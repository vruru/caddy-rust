use super::bolt::Budget;
use super::{
    actor::DatabaseOwner,
    config::Config,
    jws,
    records::{DbAccount, DbNonce},
    resources::{Leased, Meter, Resources, Scope},
    store::Database,
};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

pub struct Controller {
    pub(crate) config: Arc<Config>,
    pub(super) pki: crate::local_pki::LocalPki,
    pub(super) database: Arc<DatabaseOwner>,
    pub(super) resources: Arc<Resources>,
}
impl Controller {
    pub(super) fn new(
        config: Arc<Config>,
        pki: crate::local_pki::LocalPki,
        database: Arc<DatabaseOwner>,
        resources: Arc<Resources>,
    ) -> Self {
        Self {
            config,
            pki,
            database,
            resources,
        }
    }
    pub(crate) fn matches(&self, path: &str) -> bool {
        let mut decoded = percent_encoding::percent_decode_str(path);
        self.config
            .path_prefix
            .bytes()
            .all(|byte| decoded.next() == Some(byte))
    }
    pub(crate) async fn handle(
        self: &Arc<Self>,
        request: &mut http::Request<crate::http_runtime::Body>,
        authority: &str,
        cancel: CancellationToken,
    ) -> Result<http::Response<crate::http_runtime::Body>> {
        let scope = match self.resources.scope(cancel, false) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(crate::http_runtime::simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Bytes::from_static(b"ACME service unavailable"),
                ));
            }
        };
        let result = self.handle_scoped(request, authority, scope.clone()).await;
        if result.is_err() && scope.resource_failure() {
            return Ok(crate::http_runtime::simple(
                StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from_static(b"ACME resource capacity exceeded"),
            ));
        }
        result
    }
    async fn handle_scoped(
        self: &Arc<Self>,
        request: &mut http::Request<crate::http_runtime::Body>,
        authority: &str,
        scope: Arc<Scope>,
    ) -> Result<http::Response<crate::http_runtime::Body>> {
        scope.reserve(authority.len() + request.uri().path().len() + 1024)?;
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let authority = authority.to_owned();
        let content_type = request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        scope.reserve(content_type.len())?;
        let content_type = content_type.to_vec();
        let mut input =
            std::mem::replace(request.body_mut(), crate::http_runtime::full(Bytes::new()));
        let mut body = Vec::new();
        loop {
            let remaining = scope.remaining()?;
            let frame = tokio::select! {biased;
            _ = self.resources.cancel.cancelled()=>{scope.check()?;return Err(anyhow!("ACME services stopped"));},
            _ = scope.cancel.cancelled()=>{scope.check()?;return Err(anyhow!("ACME request cancelled"));},
            _ = tokio::time::sleep(remaining)=>{scope.check()?;return Err(anyhow!("ACME request deadline exceeded"));},
            frame=input.frame()=>frame};
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|_| anyhow!("ACME request body unavailable"))?;
            if let Ok(data) = frame.into_data() {
                ensure!(
                    body.len()
                        .checked_add(data.len())
                        .is_some_and(|n| n <= 512 * 1024),
                    "ACME request exceeds bounds"
                );
                if body.len() + data.len() > body.capacity() {
                    let target = (body.len() + data.len())
                        .max(body.capacity().saturating_mul(2))
                        .max(4096)
                        .min(512 * 1024);
                    scope.reserve(target)?;
                    body.try_reserve_exact(target - body.len())
                        .map_err(|_| anyhow!("ACME request allocation failed"))?;
                }
                body.extend_from_slice(&data);
            }
        }
        drop(input);
        let config = self.config.clone();
        let mut retained = self
            .database
            .call(scope.clone(), move |database, meter| {
                process(
                    database,
                    meter,
                    &config,
                    method,
                    &authority,
                    &path,
                    &content_type,
                    &body,
                )
            })
            .await?;
        let external_work = retained.value.action.is_some();
        if external_work {
            let permit = match self.resources.network.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    return Ok(crate::http_runtime::simple(
                        StatusCode::SERVICE_UNAVAILABLE,
                        Bytes::from_static(b"ACME challenge capacity exceeded"),
                    ));
                }
            };
            scope.reserve(std::mem::size_of::<ActionJob>() + 4096)?;
            let job = ActionJob {
                controller: self.clone(),
                response: retained,
                _permit: permit,
                scope: scope.clone(),
            };
            retained = self
                .resources
                .owned(job.execute())?
                .await
                .map_err(|_| anyhow!("ACME validation worker unavailable"))??;
        }
        // The actor has retired its snapshots, parse trees, crypto state and input
        // before the output owner may reduce its temporary byte reservation.
        // Network/TLS clients can still be retiring actual connection futures.
        // Conservatively keep that operation's whole prepaid peak until every
        // response/transport/crypto owner has retired; do not infer retirement
        // merely from receiving its database result.
        if !external_work {
            let retained_bytes = retained.value.retained_bytes();
            scope.retain(retained_bytes)?;
        }
        let mut response = http::Response::new(crate::http_runtime::full(Bytes::new()));
        *response.status_mut() = StatusCode::from_u16(retained.value.status)?;
        let headers = response.headers_mut();
        let content_type = if retained.value.problem {
            "application/problem+json"
        } else {
            retained.value.content_type
        };
        if !content_type.is_empty() {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static(content_type),
            );
        }
        for method in retained.value.allow {
            headers.append(http::header::ALLOW, HeaderValue::from_static(method));
        }
        // These read-only HEAD routes build the same finite representation as
        // GET; no request-method template, stream drain or second execution is
        // involved. Only a nonempty known representation supplies its length.
        if request.method() == Method::HEAD && !retained.value.body.is_empty() {
            headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from(retained.value.body.len()),
            );
        }
        if let Some(nonce) = &retained.value.nonce {
            headers.insert("Replay-Nonce", HeaderValue::from_str(nonce)?);
            headers.insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
        }
        if let Some(location) = &retained.value.location {
            headers.insert(http::header::LOCATION, HeaderValue::from_str(location)?);
        }
        if !retained.value.index.is_empty() {
            headers.insert(
                http::header::LINK,
                HeaderValue::from_str(&retained.value.index)?,
            );
        }
        // Bytes::from_owner keeps data and the exact scope until the transport's
        // final raw byte owner retires, including after the render future ends.
        *response.body_mut() = crate::http_runtime::full(Bytes::from_owner(retained));
        Ok(response)
    }
}
struct ActionJob {
    controller: Arc<Controller>,
    response: Leased<ResponseData>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    scope: Arc<Scope>,
}
impl ActionJob {
    async fn execute(mut self) -> Result<Leased<ResponseData>> {
        let credit = self.scope.clone();
        let result=async {
            let action=self.response.value.action.take().expect("action checked");
            match action {
                super::orders::Action::Validate{authorization,challenge,key_authorization}=>{
                    let outcome=super::validate::validate(self.controller.resources.clone(),self.scope.clone(),self.controller.config.clone(),&challenge,&key_authorization).await?;
                    self.scope.check()?;let scope=self.scope.clone();let controller=self.controller.clone();let response=self.response;
                    let output=controller.database.call(scope,move|database,meter|{
                        let mut response=response.value;
                        let current=database.transaction(meter,|tx|{
                            let mut current=tx.get::<super::records::DbChallenge>(b"acme_challenges",challenge.id.as_bytes())?.ok_or(super::store::Error::Record("challenge disappeared"))?;
                            let mut authz=tx.get::<super::records::DbAuthz>(b"acme_authzs",authorization.id.as_bytes())?.ok_or(super::store::Error::Record("authorization disappeared"))?;
                            if current.status=="pending"&&current.token==challenge.token&&matches!(authz.status.as_str(),"pending"|"valid") {
                                match outcome {
                                    super::validate::Validation::Valid=>{current.status="valid".into();current.error=serde_json::Value::Null;current.validated_at=now().map_err(|_|super::store::Error::Record("clock unavailable"))?;}
                                    super::validate::Validation::Failed{fatal,kind,detail}=>{
                                        if fatal {current.status="invalid".into();}
                                        let detail=super::problems::metadata(kind).map_or(detail,|(detail,_)|detail);
                                        current.error=serde_json::json!({"type":format!("urn:ietf:params:acme:error:{kind}"),"detail":detail});
                                    }
                                }
                                tx.put(b"acme_challenges",current.id.as_bytes(),&current)?;
                                super::orders::authorize_state(tx,&mut authz,time::OffsetDateTime::now_utc())?;
                            }Ok(current)
                        })?;
                        let directory=response.index.strip_prefix('<').and_then(|s|s.split_once('>')).map(|(s,_)|s).ok_or_else(||anyhow!("ACME directory binding unavailable"))?;
                        let base=directory.strip_suffix("/directory").ok_or_else(||anyhow!("ACME directory binding unavailable"))?;
                        meter.charge(base.len()+4096)?;response.body=json(&super::views::challenge(&current,&authorization.id,base),meter)?;Ok(response)
                    }).await?;Ok(output)
                }
                super::orders::Action::Finalize{order,csr,profile}=>{
                    let options=crate::local_pki::InternalIssuerOptions{lifetime:self.controller.config.lifetime,sign_with_root:self.controller.config.sign_with_root};
                    let issued=self.controller.pki.issue_acme_retained(&self.controller.config.ca,csr,options,profile,self.scope.cancel.clone()).await;
                    let controller=self.controller.clone();let response=self.response;let scope=self.scope.clone();
                    let authority=self.controller.config.ca.clone();
                    controller.database.call(scope,move|database,meter|super::finalize::publish(database,meter,order,issued,response.value,&authority)).await
                }
            }
        }.await;
        result.map_err(|error| crate::cert_cpu::retained_error(error, credit))
    }
}
pub(super) struct ResponseData {
    pub status: u16,
    pub body: Vec<u8>,
    pub nonce: Option<String>,
    pub location: Option<String>,
    pub index: String,
    pub problem: bool,
    pub content_type: &'static str,
    pub allow: &'static [&'static str],
    pub action: Option<super::orders::Action>,
}
impl ResponseData {
    fn retained_bytes(&self) -> usize {
        self.body.capacity()
            + 2 * (self.nonce.as_ref().map_or(0, String::capacity)
                + self.location.as_ref().map_or(0, String::capacity)
                + self.index.capacity())
            + std::mem::size_of::<Self>()
            + 2048
    }
}
impl AsRef<[u8]> for Leased<ResponseData> {
    fn as_ref(&self) -> &[u8] {
        &self.value.body
    }
}
struct Output<'a> {
    bytes: Vec<u8>,
    meter: &'a mut Meter,
}
impl Write for Output<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let fail = || io::Error::other("ACME response capacity exceeded");
        self.meter
            .work(bytes.len().div_ceil(64).max(1))
            .map_err(|_| fail())?;
        let size = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= 4 * 1024 * 1024)
            .ok_or_else(fail)?;
        if size > self.bytes.capacity() {
            let target = size
                .max(self.bytes.capacity().saturating_mul(2))
                .max(256)
                .min(4 * 1024 * 1024);
            self.meter.charge(target).map_err(|_| fail())?;
            self.bytes
                .try_reserve_exact(target - self.bytes.len())
                .map_err(|_| fail())?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn json(value: &impl Serialize, meter: &mut Meter) -> Result<Vec<u8>> {
    let mut output = Output {
        bytes: Vec::new(),
        meter,
    };
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    Ok(output.bytes)
}
#[derive(Serialize)]
struct Problem<'a> {
    #[serde(rename = "type")]
    kind: String,
    detail: &'a str,
}
pub(super) fn problem(
    response: &mut ResponseData,
    meter: &mut Meter,
    kind: &str,
    status: u16,
    detail: &str,
) -> Result<()> {
    let detail = super::problems::metadata(kind).map_or(detail, |(detail, _)| detail);
    response.status = status;
    response.problem = true;
    response.body = json(
        &Problem {
            kind: format!("urn:ietf:params:acme:error:{kind}"),
            detail,
        },
        meter,
    )?;
    Ok(())
}
pub(super) fn random_id() -> Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = String::with_capacity(32);
    for _ in 0..8 {
        let mut bytes = [0u8; 64];
        getrandom::fill(&mut bytes)?;
        for byte in bytes {
            if byte < 248 {
                out.push(ALPHABET[(byte % 62) as usize] as char);
                if out.len() == 32 {
                    return Ok(out);
                }
            }
        }
    }
    Err(anyhow!("ACME random source unavailable"))
}
pub(super) fn now() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)?
        .format(&time::format_description::well_known::Rfc3339)?)
}
fn escaped_path(raw: &[u8]) -> String {
    String::from_utf8(crate::go_url_compat::template_encode_path_bytes(raw))
        .expect("ASCII URL path escape")
}
fn link_authority(raw: &str) -> String {
    // NewLinker normalizes only a bare multi-colon configured fallback. The
    // already validated request Host remains authoritative when present.
    let normalized;
    let raw = if !raw.starts_with('[') && raw.bytes().filter(|b| *b == b':').count() > 1 {
        let (host, port) = raw.rsplit_once(':').expect("multiple colons");
        if host.parse::<std::net::IpAddr>().is_ok() {
            normalized = format!("[{host}]:{port}");
            normalized.as_str()
        } else if raw.parse::<std::net::Ipv6Addr>().is_ok() {
            normalized = format!("[{raw}]");
            normalized.as_str()
        } else {
            raw
        }
    } else {
        raw
    };
    String::from_utf8(crate::go_url_compat::template_encode_host_bytes(
        raw.as_bytes(),
    ))
    .expect("ASCII URL host escape")
}
fn zero() -> String {
    "0001-01-01T00:00:00Z".into()
}
fn nullable_string<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> std::result::Result<String, D::Error> {
    Ok(Option::<String>::deserialize(de)?.unwrap_or_default())
}
fn nullable_bool<'de, D: serde::Deserializer<'de>>(de: D) -> std::result::Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(de)?.unwrap_or_default())
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct NewAccountRequest {
    contact: Option<Vec<String>>,
    #[serde(rename = "onlyReturnExisting", deserialize_with = "nullable_bool")]
    only_existing: bool,
    #[serde(rename = "termsOfServiceAgreed", deserialize_with = "nullable_bool")]
    _terms: bool,
    // The pinned Caddy provisioner has RequireEAB=false: validate the wire
    // shape, then ignore optional EAB exactly as Smallstep does in that mode.
    #[serde(rename = "externalAccountBinding")]
    _external_binding: Option<ExternalBinding>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct ExternalBinding {
    #[serde(rename = "protected", deserialize_with = "nullable_string")]
    _protected: String,
    #[serde(rename = "payload", deserialize_with = "nullable_string")]
    _payload: String,
    #[serde(rename = "signature", deserialize_with = "nullable_string")]
    _signature: String,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct UpdateAccountRequest {
    contact: Option<Vec<String>>,
    #[serde(deserialize_with = "nullable_string")]
    status: String,
}
#[derive(Serialize)]
struct AccountView<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact: Option<&'a Vec<String>>,
    orders: String,
}
pub(super) fn account_view(account: &DbAccount, base: &str, meter: &mut Meter) -> Result<Vec<u8>> {
    json(
        &AccountView {
            status: &account.status,
            contact: account.contact.as_ref().filter(|v| !v.is_empty()),
            orders: format!("{base}/account/{}/orders", account.id),
        },
        meter,
    )
}
fn process(
    db: &mut Database,
    meter: &mut Meter,
    config: &Config,
    method: Method,
    authority: &str,
    path: &str,
    content_type: &[u8],
    body: &[u8],
) -> Result<ResponseData> {
    meter.charge(
        body.len()
            .checked_mul(64)
            .and_then(|n| n.checked_add(65536 + authority.len() * 8 + path.len() * 8))
            .ok_or_else(|| anyhow!("ACME request capacity"))?,
    )?;
    let authority = if authority.is_empty() {
        &config.host
    } else {
        authority
    };
    let authority = link_authority(authority);
    let mut response = ResponseData {
        status: 200,
        body: Vec::new(),
        nonce: None,
        location: None,
        index: String::new(),
        problem: false,
        content_type: "application/json",
        allow: &[],
        action: None,
    };
    if authority.is_empty() {
        problem(
            &mut response,
            meter,
            "malformed",
            400,
            "ACME request authority missing",
        )?;
        return Ok(response);
    }
    let root = config.path_prefix.trim_matches('/');
    let prefix = if root.is_empty() {
        "/".into()
    } else {
        format!("/{root}/")
    };
    let base = format!(
        "https://{authority}{}",
        escaped_path(format!("{prefix}{}", config.ca).as_bytes())
    );
    // Chi keeps static route components escaped, but explicitly unescapes the
    // dynamic provisioner name. Preserve that distinction and raw byte identity.
    let candidate = path
        .strip_prefix(&escaped_path(prefix.as_bytes()))
        .and_then(|suffix| suffix.split_once('/'));
    let (name, endpoint) = match candidate {
        Some(candidate) => candidate,
        None => {
            response.status = 404;
            response.content_type = "text/plain; charset=utf-8";
            meter.charge(32)?;
            response.body = b"404 page not found\n".to_vec();
            return Ok(response);
        }
    };
    let parts = endpoint.split('/').collect::<Vec<_>>();
    let registered = matches!(
        endpoint,
        "directory" | "new-nonce" | "new-account" | "new-order" | "revoke-cert" | "key-change"
    ) || (parts.len() == 2
        && matches!(parts[0], "account" | "order" | "authz" | "certificate"))
        || (parts.len() == 3
            && ((parts[0] == "account" && parts[2] == "orders")
                || (parts[0] == "order" && parts[2] == "finalize")
                || parts[0] == "challenge"));
    if !registered {
        response.status = 404;
        response.content_type = "text/plain; charset=utf-8";
        meter.charge(32)?;
        response.body = b"404 page not found\n".to_vec();
        return Ok(response);
    }
    // Route and method matching precede provisioner lookup in the pinned
    // handler. In particular an unknown provisioner cannot turn a 405 into 404.
    let read_only = matches!(endpoint, "directory" | "new-nonce");
    let permitted = if read_only {
        method == Method::GET || method == Method::HEAD
    } else {
        method == Method::POST
    };
    if !permitted {
        response.status = 405;
        response.content_type = "";
        response.allow = if read_only {
            &["GET", "HEAD"]
        } else {
            &["POST"]
        };
        return Ok(response);
    }
    let name = crate::go_url_compat::template_decode_bytes(name.as_bytes())
        .map_err(|_| anyhow!("invalid escaped provisioner name"))?;
    if name != config.ca.as_bytes() {
        #[derive(Serialize)]
        struct NotFound<'a> {
            #[serde(rename = "type")]
            kind: &'a str,
            detail: &'a str,
            message: String,
        }
        // The route key remains raw bytes. Only the JSON diagnostic performs
        // encoding/json's specified invalid-UTF8 replacement for a Go string.
        let diagnostic = String::from_utf8_lossy(&name);
        response.status = 404;
        response.body = json(
            &NotFound {
                kind: "notFound",
                detail: "resource not found",
                message: format!("provisioner {diagnostic} not found"),
            },
            meter,
        )?;
        return Ok(response);
    }
    if endpoint == "directory" {
        response.body = json(
            &serde_json::json!({"newNonce":format!("{base}/new-nonce"),"newAccount":format!("{base}/new-account"),"newOrder":format!("{base}/new-order"),"revokeCert":format!("{base}/revoke-cert"),"keyChange":format!("{base}/key-change")}),
            meter,
        )?;
        return Ok(response);
    }
    let nonce = URL_SAFE_NO_PAD.encode(random_id()?.as_bytes());
    let record = DbNonce {
        id: nonce.clone(),
        created_at: now()?,
        deleted_at: zero(),
        unknown: BTreeMap::new(),
    };
    db.transaction(meter, |tx| tx.put(b"nonces", nonce.as_bytes(), &record))?;
    response.nonce = Some(nonce);
    response.index = format!("<{base}/directory>;rel=\"index\"");
    if endpoint == "new-nonce" {
        response.content_type = "";
        response.status = if method == Method::HEAD { 200 } else { 204 };
        return Ok(response);
    }
    let certificate_type = endpoint.starts_with("certificate/")
        && matches!(
            content_type,
            b"application/pkix-cert" | b"application/pkcs7-mime"
        );
    if content_type != b"application/jose+json" && !certificate_type {
        problem(
            &mut response,
            meter,
            "malformed",
            400,
            "expected application/jose+json content type",
        )?;
        return Ok(response);
    }
    let signed = match jws::parse(body, meter) {
        Ok(s) => s,
        Err(jws::Error::Resource(e)) => return Err(e.into()),
        Err(e) => {
            problem(
                &mut response,
                meter,
                if matches!(e, jws::Error::BadAlgorithm) {
                    "badSignatureAlgorithm"
                } else {
                    "malformed"
                },
                400,
                "invalid JWS request",
            )?;
            return Ok(response);
        }
    };
    let embedded = if let Some(raw) = signed.header.jwk.as_deref() {
        match jws::VerificationKey::from_jwk(raw, meter) {
            Ok(key) => Some(key),
            Err(jws::Error::Resource(e)) => return Err(e.into()),
            Err(_) => {
                problem(&mut response, meter, "malformed", 400, "invalid JWK")?;
                return Ok(response);
            }
        }
    } else {
        None
    };
    let consumed = db.transaction(meter, |tx| {
        tx.consume_nonce(
            signed
                .header
                .nonce
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        )
    })?;
    if !consumed {
        problem(
            &mut response,
            meter,
            "badNonce",
            400,
            "unacceptable anti-replay nonce",
        )?;
        return Ok(response);
    }
    let decoded = crate::go_url_compat::template_decode_bytes(path.as_bytes())
        .map_err(|_| anyhow!("invalid ACME request path"))?;
    if signed
        .validate_binding(&format!("https://{authority}{}", escaped_path(&decoded)))
        .is_err()
    {
        problem(
            &mut response,
            meter,
            "malformed",
            400,
            "invalid JWS protected URL or key binding",
        )?;
        return Ok(response);
    }
    let account = if let Some(key) = &embedded {
        db.transaction(meter, |tx| {
            let Some(id) = tx.index(b"acme_keyID_accountID_index", key.thumbprint().as_bytes())?
            else {
                return Ok(None);
            };
            tx.get::<DbAccount>(b"acme_accounts", id.as_bytes())
        })?
    } else {
        let kid = signed.header.kid.as_deref().unwrap_or_default();
        // Go path.Base cleans dot/empty path segments before the account
        // lookup. The full stored Location is still compared afterward.
        let capacity = kid.len() / 2 + 1;
        meter.charge(
            capacity
                .checked_mul(std::mem::size_of::<&str>())
                .ok_or_else(|| anyhow!("account path size"))?,
        )?;
        let mut components = Vec::new();
        components
            .try_reserve_exact(capacity)
            .map_err(|_| anyhow!("account path allocation"))?;
        for component in kid.split('/') {
            match component {
                "" | "." => {}
                ".." if components.last().is_some_and(|last| *last != "..") => {
                    components.pop();
                }
                ".." if kid.starts_with('/') => {}
                _ => components.push(component),
            }
        }
        let id = components
            .last()
            .copied()
            .unwrap_or(if kid.starts_with('/') { "/" } else { "." });
        let account = db.transaction(meter, |tx| {
            tx.get::<DbAccount>(b"acme_accounts", id.as_bytes())
        })?;
        match account {
            Some(account) => {
                let location = format!(
                    "{}{}",
                    if account.location_prefix.is_empty() {
                        format!("{base}/account/")
                    } else {
                        account.location_prefix.clone()
                    },
                    account.id
                );
                if location != kid {
                    problem(
                        &mut response,
                        meter,
                        "unauthorized",
                        401,
                        "account location mismatch",
                    )?;
                    return Ok(response);
                }
                Some(account)
            }
            None => None,
        }
    };
    if account.as_ref().is_some_and(|a| a.status != "valid")
        && !(endpoint == "revoke-cert" && signed.header.jwk.is_some())
    {
        problem(
            &mut response,
            meter,
            "unauthorized",
            401,
            "account is not active",
        )?;
        return Ok(response);
    }
    if signed.header.kid.is_some()
        && account.as_ref().is_some_and(|account| {
            if account.provisioner_id.is_empty() {
                account.provisioner_name != config.ca
            } else {
                account.provisioner_id != format!("acme/{}", config.ca)
            }
        })
    {
        problem(
            &mut response,
            meter,
            "unauthorized",
            401,
            "account belongs to another provisioner",
        )?;
        return Ok(response);
    }
    let key = if let Some(key) = embedded {
        key
    } else {
        let Some(account) = &account else {
            problem(
                &mut response,
                meter,
                "accountDoesNotExist",
                400,
                "account does not exist",
            )?;
            return Ok(response);
        };
        let raw = serde_json::value::to_raw_value(&account.key)?;
        jws::VerificationKey::from_jwk(&raw, meter)?
    };
    if let Err(error) = key.verify(&signed, meter) {
        if let jws::Error::Resource(e) = error {
            return Err(e.into());
        }
        problem(
            &mut response,
            meter,
            "malformed",
            400,
            "JWS verification failed",
        )?;
        return Ok(response);
    }
    if endpoint == "revoke-cert" {
        super::revoke::process(db, meter, &signed, &key, account.as_ref(), &mut response)?;
        return Ok(response);
    }
    if endpoint == "new-account" {
        if signed.header.jwk.is_none() {
            problem(
                &mut response,
                meter,
                "malformed",
                400,
                "JWK required for new account",
            )?;
            return Ok(response);
        }
        let request: NewAccountRequest = match serde_json::from_slice(&signed.payload) {
            Ok(r) => r,
            Err(_) => {
                problem(
                    &mut response,
                    meter,
                    "malformed",
                    400,
                    "invalid account request",
                )?;
                return Ok(response);
            }
        };
        if request.contact.as_ref().is_some_and(|v| {
            v.iter().any(String::is_empty) || (request.only_existing && !v.is_empty())
        }) {
            problem(
                &mut response,
                meter,
                "malformed",
                400,
                "invalid account contacts",
            )?;
            return Ok(response);
        }
        let account = if let Some(account) = account {
            account
        } else {
            if request.only_existing {
                problem(
                    &mut response,
                    meter,
                    "accountDoesNotExist",
                    400,
                    "account does not exist",
                )?;
                return Ok(response);
            }
            let mut key_value: serde_json::Value =
                serde_json::from_str(signed.header.jwk.as_ref().expect("checked").get())?;
            key_value
                .as_object_mut()
                .ok_or_else(|| anyhow!("invalid account JWK"))?
                .insert(
                    "kid".into(),
                    serde_json::Value::String(key.thumbprint().into()),
                );
            let account = DbAccount {
                id: random_id()?,
                key: key_value,
                contact: request.contact,
                status: "valid".into(),
                location_prefix: format!("{base}/account/"),
                provisioner_id: String::new(),
                provisioner_name: config.ca.clone(),
                created_at: now()?,
                deactivated_at: zero(),
                unknown: BTreeMap::new(),
            };
            db.transaction(meter, |tx| {
                tx.put(b"acme_accounts", account.id.as_bytes(), &account)?;
                tx.put_raw(
                    b"acme_keyID_accountID_index",
                    key.thumbprint().as_bytes(),
                    account.id.as_bytes(),
                )?;
                Ok(())
            })?;
            response.status = 201;
            account
        };
        response.location = Some(format!("{base}/account/{}", account.id));
        response.body = account_view(&account, &base, meter)?;
        return Ok(response);
    }
    let Some(mut account) = account else {
        problem(
            &mut response,
            meter,
            "accountDoesNotExist",
            400,
            "account does not exist",
        )?;
        return Ok(response);
    };
    if signed.header.kid.as_deref().is_none_or(str::is_empty) {
        problem(&mut response, meter, "malformed", 400, "key ID required")?;
        return Ok(response);
    }
    if endpoint == "key-change" {
        super::key_change::process(db, meter, &signed, &account, &key, &base, &mut response)?;
        return Ok(response);
    }
    if endpoint == format!("account/{}", account.id) {
        if !signed.payload.is_empty() {
            let request: UpdateAccountRequest = match serde_json::from_slice(&signed.payload) {
                Ok(r) => r,
                Err(_) => {
                    problem(
                        &mut response,
                        meter,
                        "malformed",
                        400,
                        "invalid account update",
                    )?;
                    return Ok(response);
                }
            };
            let has_contacts = request.contact.as_ref().is_some_and(|v| !v.is_empty());
            if (!request.status.is_empty() && request.status != "deactivated")
                || (has_contacts && !request.status.is_empty())
                || request
                    .contact
                    .as_ref()
                    .is_some_and(|v| v.iter().any(String::is_empty))
            {
                problem(
                    &mut response,
                    meter,
                    "malformed",
                    400,
                    "invalid account update",
                )?;
                return Ok(response);
            }
            if !request.status.is_empty() {
                account.status = request.status;
                account.deactivated_at = now()?;
            } else if has_contacts {
                account.contact = request.contact;
            }
            db.transaction(meter, |tx| {
                tx.put(b"acme_accounts", account.id.as_bytes(), &account)
            })?;
        }
        response.location = Some(format!("{base}/account/{}", account.id));
        response.body = account_view(&account, &base, meter)?;
        return Ok(response);
    }
    if super::orders::process(
        db,
        meter,
        config,
        endpoint,
        &signed.payload,
        &account,
        key.thumbprint(),
        &base,
        &mut response,
    )? {
        return Ok(response);
    }
    problem(
        &mut response,
        meter,
        "malformed",
        404,
        "ACME resource not found",
    )?;
    Ok(response)
}
