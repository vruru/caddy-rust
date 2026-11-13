//! Bounded RFC 8555 client. Signing, transport and order persistence are separate.
//! No request is silently retried after an uncertain network outcome. Only an
//! explicit ACME badNonce response permits a bounded replay with a fresh nonce.

#[path = "acme_wire/signer.rs"]
mod signer;
mod network_proxy;
pub(crate) mod directory_url;
mod order_parameters;
mod chain_preference;
mod certificate_links;
mod certificate_chains;
pub(crate) use certificate_chains::Cleanup as ChainCleanup;
pub(crate) mod chain_memory;
pub(crate) mod chain_deep_shape;
pub(crate) mod chain_validation;
pub(crate) mod chain_shape;
pub(crate) use chain_memory::{Lease as ChainMemoryLease,Pools as ChainMemoryPools};
pub(crate) use chain_memory::shared as shared_chain_memory;
pub use chain_preference::{CertificateChain,ChainPreference};
pub use order_parameters::OrderParameters;
pub use network_proxy::NetworkProxy;
pub use signer::{AccountSigner, KeyType};

use anyhow::{Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::HashSet, fmt, sync::Arc, time::Duration};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_NONCES: usize = 32;

#[derive(Clone)]
pub struct WireOptions {
    pub directory: String,
    pub extra_ca_pem: Vec<Vec<u8>>,
    pub trusted_ca_origins: Vec<String>,
    /// Test-only plaintext transport is restricted to literal loopback IPs.
    pub allow_insecure_loopback: bool,
    pub request_timeout: Duration,
    /// None preserves environment proxies; Direct explicitly disables them.
    pub network_proxy:Option<NetworkProxy>,
}

#[derive(Clone, Deserialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: Option<String>,
    #[serde(rename = "renewalInfo")]
    pub renewal_info: Option<String>,
    #[serde(default)]
    pub meta: Value,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Order {
    pub status: String,
    #[serde(default)]
    pub profile: String,
    #[serde(default, rename = "notAfter")]
    pub not_after: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    #[serde(default)]
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    pub status: String,
    pub token: Option<String>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: String,
    #[serde(default)]
    pub wildcard: bool,
    #[serde(default)]
    pub challenges: Vec<Challenge>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AriWindow {
    pub start_unix: i64,
    pub end_unix: i64,
    pub refresh_after_unix: i64,
    pub certificate_id: String,
}

pub struct AccountResponse {
    pub location: String,
    pub metadata: Value,
}

pub struct Resource<T> {
    pub value: T,
    pub location: Option<String>,
    pub retry_after: Option<Duration>,
}

/// Deliberately excludes URLs, remote response bodies and signing material.
#[derive(Debug)]
pub struct ProtocolError {
    status: u16,
    kind: String,
    uncertain: bool,
    retry_after: Option<Duration>,
}
impl ProtocolError {
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn uncertain(&self) -> bool {
        self.uncertain
    }
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ACME protocol request failed (HTTP {}, {}, uncertain={})",
            self.status, self.kind, self.uncertain
        )
    }
}
impl std::error::Error for ProtocolError {}

/// Evidence only of an explicit wire cancellation branch. It does not prove
/// actual TLS worker retirement or authorize an issuer fallback.
#[derive(Debug)]
pub(crate) struct AcmeRequestCancelled {status:u16,before_send:bool,uncertain:bool}
impl fmt::Display for AcmeRequestCancelled {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{
        write!(f,"ACME protocol request failed (HTTP {}, {}, uncertain={})",self.status,
            if self.before_send{"cancelledBeforeSend"}else{"cancelled"},self.uncertain)
    }
}
impl std::error::Error for AcmeRequestCancelled {}
fn cancelled_request(error:ProtocolError)->anyhow::Error{
    let marker=AcmeRequestCancelled{status:error.status,before_send:error.kind=="cancelledBeforeSend",uncertain:error.uncertain};
    anyhow::Error::new(error).context(marker)
}

#[derive(Clone)]
pub struct AcmeWire {
    inner: Arc<WireInner>,
}
struct WireInner {
    cpu: Arc<Semaphore>,
    chain_memory:Arc<ChainMemoryPools>,
    client: reqwest::Client,
    directory_url: Url,
    directory: Directory,
    trusted: HashSet<String>,
    allow_loopback: bool,
    allowed_http_origin: Option<String>,
    nonces: Mutex<Vec<String>>,
    // Last owner: no early refund when an AccountSession outlives its manager.
    issuer_values_credit:Option<Arc<chain_memory::Lease>>,
}

pub struct AccountSession {
    wire: AcmeWire,
    signer: Arc<AccountSigner>,
    location: String,
}
impl Clone for AccountSession {
    fn clone(&self) -> Self {
        Self {
            wire: self.wire.clone(),
            signer: self.signer.clone(),
            location: self.location.clone(),
        }
    }
}

struct WireResponse {
    is_post: bool,
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
    body_memory:Option<ChainMemoryLease>,
}

impl AcmeWire {
    pub async fn connect(options: WireOptions, cancel: &CancellationToken) -> Result<Self> {
        static CPU: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
        let cpu = CPU.get_or_init(|| Arc::new(Semaphore::new(std::thread::available_parallelism().map_or(1,usize::from).min(4)))).clone();
        Self::connect_with_cpu(options,cpu,cancel).await
    }
    pub(crate) async fn connect_with_cpu(options: WireOptions, cpu: Arc<Semaphore>, cancel: &CancellationToken) -> Result<Self> {
        Self::connect_with_resources(options,cpu,shared_chain_memory(),cancel).await
    }
    pub(crate) async fn connect_with_resources(options:WireOptions,cpu:Arc<Semaphore>,chain_memory:Arc<ChainMemoryPools>,cancel:&CancellationToken)->Result<Self> {
        Self::connect_with_client_tls_scope(options,cpu,chain_memory,#[cfg(feature="native-run")] None,cancel).await
    }
    pub(crate) async fn connect_with_client_tls_scope(options:WireOptions,cpu:Arc<Semaphore>,chain_memory:Arc<ChainMemoryPools>,#[cfg(feature="native-run")] scope:Option<Arc<crate::outgoing_tls::Scope>>,cancel:&CancellationToken)->Result<Self> {
        ensure!(
            !options.request_timeout.is_zero()
                && options.request_timeout <= Duration::from_secs(3600),
            "invalid ACME request timeout"
        );
        ensure!(
            options.extra_ca_pem.len() <= 32 && options.trusted_ca_origins.len() <= 32,
            "ACME trust configuration exceeds bounds"
        );
        let directory_url = directory_url::normalize(&options.directory)?;
        let allowed_http_origin = directory_url::allowed_http_origin(&directory_url);
        let mut trusted = HashSet::from([directory_url.origin().ascii_serialization()]);
        for raw in &options.trusted_ca_origins {
            let url = Url::parse(raw).map_err(|_| anyhow!("invalid ACME trusted origin"))?;
            ensure!(
                url.path() == "/" && url.query().is_none(),
                "ACME trusted origin must be a bare origin"
            );
            validate_url(
                &url,
                &HashSet::from([url.origin().ascii_serialization()]),
                options.allow_insecure_loopback,
                allowed_http_origin.as_deref(),
            )?;
            trusted.insert(url.origin().ascii_serialization());
        }
        validate_url(&directory_url, &trusted, options.allow_insecure_loopback, allowed_http_origin.as_deref())?;
        if let Some(proxy)=&options.network_proxy {proxy.validate()?;}
        let client = crate::cert_cpu::run(cpu.clone(),cancel.clone(),move || {
        let mut builder = reqwest::Client::builder()
            .tls_crypto_provider(crate::crypto::client_provider())
            .rustls_certificate_verifier_wrapper(crate::cert_uri_san::wrap_server_verifier)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(options.request_timeout)
            .user_agent("Caddy-Rust-ACME/0.1");
        if let Some(proxy)=options.network_proxy {builder=proxy.apply(builder)?;}
        for pem in options.extra_ca_pem {
            ensure!(pem.len() <= 1024 * 1024, "ACME trust root exceeds bounds");
            builder = append_trusted_root_pem(builder, &pem)?;
        }
        #[cfg(feature="native-run")]
        if let Some(scope)=scope{builder=builder.connector_layer(scope.layer()?);}
        builder
            .build()
            .map_err(|_| anyhow!("ACME client construction failed"))
        }).await?;
        let response = send(&client, Method::GET, directory_url.clone(), None, cancel).await?;
        check_status(&response)?;
        let body=response.body;
        let directory: Directory = crate::cert_cpu::run(cpu.clone(),cancel.clone(),move || serde_json::from_slice(&body)
            .map_err(|_| anyhow!("invalid ACME directory response"))).await?;
        for endpoint in [
            &directory.new_nonce,
            &directory.new_account,
            &directory.new_order,
        ]
        .into_iter()
        .chain(directory.revoke_cert.iter())
        .chain(directory.renewal_info.iter())
        {
            validate_url(
                &Url::parse(endpoint).map_err(|_| anyhow!("invalid ACME directory endpoint"))?,
                &trusted,
                options.allow_insecure_loopback,
                allowed_http_origin.as_deref(),
            )?;
        }
        Ok(Self {
            inner: Arc::new(WireInner {
                client,
                cpu,
                chain_memory,
                directory_url,
                directory,
                trusted,
                allow_loopback: options.allow_insecure_loopback,
                allowed_http_origin,
                nonces: Mutex::new(Vec::new()),
                issuer_values_credit:None,
            }),
        })
    }

    pub(crate) fn with_issuer_values_credit(mut self,credit:Option<Arc<chain_memory::Lease>>)->Result<Self>{
        Arc::get_mut(&mut self.inner).ok_or_else(||anyhow!("ACME wire already shared"))?.issuer_values_credit=credit;
        Ok(self)
    }

    /// Original Caddy's ZeroSSL convenience registration, scoped to its fixed
    /// official API. Explicit EAB and existing accounts do not call this API.
    pub async fn zero_ssl_eab(
        &self,
        email: &str,
        cancel: &CancellationToken,
    ) -> Result<(String, String)> {
        ensure!(
            self.directory_url()
                .starts_with("https://acme.zerossl.com/"),
            "automatic EAB is only supported for ZeroSSL"
        );
        ensure!(
            !email.trim().is_empty() && email.len() <= 254,
            "email is required for ZeroSSL automatic EAB"
        );
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("email", email)
            .finish()
            .into_bytes();
        let mut response = send_with_type(
            &self.inner.client,
            Method::POST,
            Url::parse("https://api.zerossl.com/acme/eab-credentials-email")?,
            Some(form),
            "application/x-www-form-urlencoded",
            cancel,
        )
        .await?;
        let parsed = (|| {
            check_status(&response)?;
            zero_ssl_eab_response(response.status, &response.body)
        })();
        response.body.zeroize();
        parsed
    }

    pub fn directory(&self) -> &Directory {
        &self.inner.directory
    }
    pub fn directory_url(&self) -> &str {
        self.inner.directory_url.as_str()
    }

    pub fn restore(&self, signer: Arc<AccountSigner>, location: &str) -> Result<AccountSession> {
        self.endpoint(location)?;
        Ok(AccountSession {
            wire: self.clone(),
            signer,
            location: location.to_owned(),
        })
    }

    /// `only_existing` never creates a new account and must be used to recover
    /// an existing key whose local account location is missing or uncertain.
    pub async fn account(
        &self,
        signer: Arc<AccountSigner>,
        email: &str,
        agree_tos: bool,
        only_existing: bool,
        eab: Option<(&str, &str)>,
        cancel: &CancellationToken,
    ) -> Result<(AccountSession, AccountResponse)> {
        ensure!(
            email.len() <= 320 && !email.contains(['\r', '\n']),
            "invalid ACME account email"
        );
        let url = self
            .endpoint(&self.inner.directory.new_account)?
            .to_string();
        let mut payload = if only_existing {
            json!({"onlyReturnExisting":true})
        } else {
            ensure!(agree_tos, "ACME terms of service have not been accepted");
            let mut value = json!({"termsOfServiceAgreed":true});
            if !email.is_empty() {
                ensure!(email.contains('@'), "invalid ACME account email");
                value["contact"] = json!([format!("mailto:{email}")]);
            }
            value
        };
        if !only_existing && let Some((kid, secret)) = eab {
            ensure!(
                !kid.is_empty() && kid.len() <= 1024 && secret.len() <= 4096,
                "invalid external account binding"
            );
            let secret = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(secret.trim_end_matches('='))
                    .map_err(|_| anyhow!("invalid external account key"))?,
            );
            ensure!(!secret.is_empty(), "empty external account key");
            let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
                &json!({"alg":"HS256","kid":kid,"url":url}),
            )?);
            let content = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signer.jwk())?);
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret)
                .map_err(|_| anyhow!("invalid external account key"))?;
            mac.update(format!("{protected}.{content}").as_bytes());
            payload["externalAccountBinding"] = json!({"protected":protected,"payload":content,"signature":URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())});
        }
        let response = self
            .signed(&signer, None, &url, Some(&payload), cancel)
            .await?;
        let location = self
            .location(&response, &url)
            .map_err(|_| uncertain(response.status, "invalidLocation"))?
            .ok_or_else(|| uncertain(response.status, "missingLocation"))?;
        let mut metadata: Value = serde_json::from_slice(&response.body)
            .map_err(|_| uncertain(response.status, "invalidAccountJson"))?;
        if ["deactivated", "revoked"].contains(&metadata["status"].as_str().unwrap_or("")) {
            return Err(ProtocolError {
                status: response.status.as_u16(),
                kind: "accountNotActive".to_owned(),
                uncertain: false,
                retry_after: None,
            }
            .into());
        }
        if !metadata.is_object() || metadata["status"] != "valid" {
            return Err(uncertain(response.status, "invalidAccount"));
        }
        // Go decodes into the existing Account structure: an omitted contact
        // retains the request contact, while an explicit [] clears it.
        if !only_existing
            && metadata.get("contact").is_none()
            && let Some(contact) = payload.get("contact")
        {
            metadata["contact"] = contact.clone();
        }
        metadata["location"] = json!(location);
        let session = self.restore(signer, &location)?;
        Ok((session, AccountResponse { location, metadata }))
    }

    fn endpoint(&self, raw: &str) -> Result<Url> {
        let url = Url::parse(raw).map_err(|_| anyhow!("invalid ACME resource URL"))?;
        validate_url(&url, &self.inner.trusted, self.inner.allow_loopback, self.inner.allowed_http_origin.as_deref())?;
        Ok(url)
    }

    fn location(&self, response: &WireResponse, base: &str) -> Result<Option<String>> {
        let Some(raw) = response.headers.get(reqwest::header::LOCATION) else {
            return Ok(None);
        };
        let raw = raw.to_str().map_err(|_| anyhow!("invalid ACME location"))?;
        let absolute = self
            .endpoint(base)?
            .join(raw)
            .map_err(|_| anyhow!("invalid ACME relative location"))?;
        self.endpoint(absolute.as_str())?;
        Ok(Some(absolute.to_string()))
    }

    async fn nonce(&self, cancel: &CancellationToken) -> Result<String> {
        if let Some(nonce) = self.inner.nonces.lock().await.pop() {
            return Ok(nonce);
        }
        let response = send(
            &self.inner.client,
            Method::HEAD,
            self.endpoint(&self.inner.directory.new_nonce)?,
            None,
            cancel,
        )
        .await?;
        check_status(&response)?;
        parse_nonce(&response.headers)?.ok_or_else(|| anyhow!("ACME nonce missing"))
    }

    async fn signed(
        &self,
        signer: &Arc<AccountSigner>,
        kid: Option<&str>,
        raw: &str,
        payload: Option<&Value>,
        cancel: &CancellationToken,
    ) -> Result<WireResponse> {
        let url = self.endpoint(raw)?;
        self.signed_url(signer,kid,url,payload,cancel).await
    }

    // Internal transport only. Certificate delegates always pass an empty
    // POST-as-GET payload; other operations enter through endpoint() above.
    async fn signed_url(
        &self, signer:&Arc<AccountSigner>, kid:Option<&str>, url:Url,
        payload:Option<&Value>, cancel:&CancellationToken,
    )->Result<WireResponse> {
        self.signed_url_with_memory(signer,kid,url,payload,None,None,None,cancel).await
    }
    async fn signed_certificate_url(&self,signer:&Arc<AccountSigner>,kid:&str,url:Url,
        credit:ChainMemoryLease,http_slots:Arc<Semaphore>,cancel:&CancellationToken)->Result<WireResponse> {
        ensure!(credit.covers(&self.inner.chain_memory.payload,MAX_BODY),"invalid ACME certificate body admission");
        self.signed_url_with_memory(signer,Some(kid),url,None,Some(self.inner.chain_memory.clone()),Some(credit),Some(http_slots),cancel).await
    }
    async fn signed_url_with_memory(&self,signer:&Arc<AccountSigner>,kid:Option<&str>,url:Url,payload:Option<&Value>,memory:Option<Arc<ChainMemoryPools>>,
        mut first_credit:Option<ChainMemoryLease>,http_slots:Option<Arc<Semaphore>>,cancel:&CancellationToken)->Result<WireResponse> {
        if let Some(kid) = kid {
            self.endpoint(kid)?;
        }
        for attempt in 0..3 {
            let body_credit=match first_credit.take(){Some(credit)=>Some(credit),None=>memory.as_ref().map(|p|p.payload.reserve(MAX_BODY)).transpose()?};
            let nonce = self.nonce(cancel).await?;
            let mut protected = json!({"alg":signer.algorithm(),"nonce":nonce,"url":url.as_str()});
            if let Some(kid) = kid {
                protected["kid"] = json!(kid);
            } else {
                protected["jwk"] = signer.jwk();
            }
            let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
            let payload = match payload {
                Some(value) => URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?),
                None => String::new(),
            };
            let signer = signer.clone();
            let signed_bytes = format!("{protected}.{payload}");
            let signature = match crate::cert_cpu::run(self.inner.cpu.clone(),cancel.clone(),move || signer.sign(signed_bytes.as_bytes())).await {
                Err(error) if cancel.is_cancelled() => return Err(error.context(ProtocolError { status:0,kind:"cancelledBeforeSend".into(),uncertain:false,retry_after:None })),
                result => result?,
            };
            let body = serde_json::to_vec(
                &json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(signature)}),
            )?;
            let response = send_with_memory(
                &self.inner.client,
                Method::POST,
                url.clone(),
                Some(body),
                "application/jose+json",
                memory.clone(),
                body_credit,
                http_slots.clone(),
                cancel,
            )
            .await?;
            if let Ok(Some(nonce)) = parse_nonce(&response.headers) {
                let mut nonces = self.inner.nonces.lock().await;
                if nonces.len() < MAX_NONCES {
                    nonces.push(nonce);
                }
            }
            if response.status.as_u16() == 400
                && problem_type(&response.body).as_deref()
                    == Some("urn:ietf:params:acme:error:badNonce")
                && attempt < 2
            {
                continue;
            }
            check_status(&response)?;
            return Ok(response);
        }
        bail!("ACME nonce retry budget exhausted")
    }

    pub async fn renewal_info(
        &self,
        certificate_id: &str,
        cancel: &CancellationToken,
    ) -> Result<Option<AriWindow>> {
        let Some(base) = &self.inner.directory.renewal_info else {
            return Ok(None);
        };
        ensure!(
            certificate_id.len() <= 1024
                && certificate_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'),
            "invalid ARI certificate identifier"
        );
        let raw = format!("{}/{}", base.trim_end_matches('/'), certificate_id);
        let response = send(
            &self.inner.client,
            Method::GET,
            self.endpoint(&raw)?,
            None,
            cancel,
        )
        .await?;
        if response.status == StatusCode::NOT_FOUND
            || response.status == StatusCode::NOT_IMPLEMENTED
        {
            return Ok(None);
        }
        check_status(&response)?;
        let body: Value =
            serde_json::from_slice(&response.body).map_err(|_| anyhow!("invalid ARI response"))?;
        let parse = |name| -> Result<i64> {
            Ok(time::OffsetDateTime::parse(
                body["suggestedWindow"][name]
                    .as_str()
                    .ok_or_else(|| anyhow!("ARI window missing"))?,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| anyhow!("invalid ARI date"))?
            .unix_timestamp())
        };
        let start = parse("start")?;
        let end = parse("end")?;
        ensure!(end > start, "ARI renewal window is empty");
        Ok(Some(AriWindow {
            start_unix: start,
            end_unix: end,
            refresh_after_unix: time::OffsetDateTime::now_utc().unix_timestamp()
                + retry_after(&response.headers)
                    .unwrap_or(Duration::from_secs(21600))
                    .clamp(Duration::from_secs(60), Duration::from_secs(86400))
                    .as_secs() as i64,
            certificate_id: certificate_id.to_owned(),
        }))
    }
}

impl AccountSession {
    pub fn location(&self) -> &str {
        &self.location
    }
    pub fn thumbprint(&self) -> String {
        self.signer.thumbprint()
    }
    pub fn wire(&self) -> &AcmeWire {
        &self.wire
    }

    /// Resolve an uncertain newOrder using the account's advertised order list.
    /// Only pending/ready orders may be reused: processing/valid orders may
    /// already be bound to a different CSR key. Absence is not proof that an
    /// uncertain request failed, so callers must not blindly create another.
    pub async fn reconcile_order(
        &self,
        identifiers: &[Identifier],
        cancel: &CancellationToken,
    ) -> Result<Option<String>> {
        self.reconcile_order_with_parameters(identifiers, &OrderParameters::default(), cancel).await
    }

    pub async fn reconcile_order_with_parameters(
        &self,
        identifiers: &[Identifier],
        parameters: &OrderParameters,
        cancel: &CancellationToken,
    ) -> Result<Option<String>> {
        parameters.validate()?;
        let account: Resource<Value> = self
            .resource(&self.location, None, cancel)
            .await?;
        ensure!(
            account.value["status"] == "valid",
            "ACME account is not valid"
        );
        let Some(mut next) = account.value["orders"].as_str().map(str::to_owned) else {
            return Ok(None);
        };
        let mut expected = identifiers
            .iter()
            .map(|id| (id.kind.clone(), id.value.to_ascii_lowercase()))
            .collect::<Vec<_>>();
        expected.sort();
        expected.dedup();
        let mut seen = HashSet::new();
        let mut pages = HashSet::new();
        for _ in 0..16 {
            ensure!(
                pages.insert(next.clone()),
                "ACME order-list pagination loop"
            );
            let response = self
                .wire
                .signed(&self.signer, Some(&self.location), &next, None, cancel)
                .await?;
            let body: Value = serde_json::from_slice(&response.body)
                .map_err(|_| anyhow!("invalid ACME order-list response"))?;
            let orders = body["orders"]
                .as_array()
                .ok_or_else(|| anyhow!("ACME order-list entries missing"))?;
            ensure!(orders.len() <= 1024, "ACME order-list exceeds bounds");
            for entry in orders {
                let url = entry
                    .as_str()
                    .ok_or_else(|| anyhow!("invalid ACME order-list entry"))?;
                if !seen.insert(url.to_owned()) {
                    continue;
                }
                ensure!(
                    seen.len() <= 1024,
                    "ACME order reconciliation exceeds bounds"
                );
                let order = self.order(url, cancel).await?.value;
                if !["pending", "ready"].contains(&order.status.as_str()) {
                    continue;
                }
                let mut actual = order
                    .identifiers
                    .iter()
                    .map(|id| (id.kind.clone(), id.value.to_ascii_lowercase()))
                    .collect::<Vec<_>>();
                actual.sort();
                actual.dedup();
                if actual == expected && parameters.matches_observation(&order) {
                    return Ok(Some(url.to_owned()));
                }
            }
            let mut continuation = None;
            for header in response.headers.get_all(reqwest::header::LINK) {
                let header = header
                    .to_str()
                    .map_err(|_| anyhow!("invalid ACME pagination header"))?;
                for link in header.split(',') {
                    let Some((target, parameters)) = link.trim().split_once('>') else {
                        continue;
                    };
                    let Some(target) = target.strip_prefix('<') else {
                        continue;
                    };
                    if parameters
                        .split(';')
                        .map(str::trim)
                        .any(|p| p == "rel=\"next\"" || p == "rel=next")
                    {
                        let target = self
                            .wire
                            .endpoint(&next)?
                            .join(target)
                            .map_err(|_| anyhow!("invalid ACME pagination URL"))?;
                        self.wire.endpoint(target.as_str())?;
                        ensure!(
                            continuation.is_none(),
                            "ambiguous ACME pagination continuation"
                        );
                        continuation = Some(target.to_string());
                    }
                }
            }
            let Some(url) = continuation else {
                return Ok(None);
            };
            next = url;
        }
        bail!("ACME order-list pagination exceeds bounds")
    }

    pub async fn new_order(
        &self,
        identifiers: &[Identifier],
        replaces: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<Resource<Order>> {
        self.new_order_with_parameters(identifiers, replaces, &OrderParameters::default(), cancel).await
    }

    /// Validate explicit profiles against this directory before recording an
    /// irreversible order intent. An empty profile requests the CA default.
    pub fn validate_order_parameters(&self, parameters: &OrderParameters) -> Result<()> {
        parameters.validate()?;
        if !parameters.profile.is_empty() {
            ensure!(self.wire.directory().meta.get("profiles")
                .and_then(Value::as_object)
                .is_some_and(|profiles| profiles.contains_key(&parameters.profile)),
                "ACME directory does not advertise the requested profile");
        }
        Ok(())
    }

    pub async fn new_order_with_parameters(
        &self,
        identifiers: &[Identifier],
        replaces: Option<&str>,
        parameters: &OrderParameters,
        cancel: &CancellationToken,
    ) -> Result<Resource<Order>> {
        self.validate_order_parameters(parameters)?;
        ensure!(
            !identifiers.is_empty() && identifiers.len() <= 100,
            "invalid ACME identifier count"
        );
        let mut payload = json!({"identifiers":identifiers});
        parameters.write_payload(&mut payload);
        if let Some(replaces) = replaces {
            payload["replaces"] = json!(replaces);
        }
        self.resource(&self.wire.inner.directory.new_order, Some(&payload), cancel)
            .await
    }
    pub async fn order(&self, url: &str, cancel: &CancellationToken) -> Result<Resource<Order>> {
        self.resource(url, None, cancel).await
    }
    pub async fn authorization(
        &self,
        url: &str,
        cancel: &CancellationToken,
    ) -> Result<Resource<Authorization>> {
        self.resource(url, None, cancel).await
    }
    pub async fn respond(
        &self,
        url: &str,
        cancel: &CancellationToken,
    ) -> Result<Resource<Challenge>> {
        self.resource(url, Some(&json!({})), cancel).await
    }
    pub async fn finalize(
        &self,
        url: &str,
        csr: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Resource<Order>> {
        self.resource(
            url,
            Some(&json!({"csr":URL_SAFE_NO_PAD.encode(csr)})),
            cancel,
        )
        .await
    }
    pub async fn download(&self, url: &str, cancel: &CancellationToken) -> Result<Vec<u8>> {
        Ok(self
            .wire
            .signed(&self.signer, Some(&self.location), url, None, cancel)
            .await?
            .body)
    }
    pub async fn revoke(
        &self,
        certificate_der: &[u8],
        reason: u8,
        cancel: &CancellationToken,
    ) -> Result<()> {
        ensure!(
            [0, 1, 3, 4, 5].contains(&reason),
            "unsupported ACME revocation reason"
        );
        let url = self
            .wire
            .inner
            .directory
            .revoke_cert
            .as_deref()
            .ok_or_else(|| anyhow!("CA has no revocation endpoint"))?;
        self.wire
            .signed(
                &self.signer,
                Some(&self.location),
                url,
                Some(
                    &json!({"certificate":URL_SAFE_NO_PAD.encode(certificate_der),"reason":reason}),
                ),
                cancel,
            )
            .await?;
        Ok(())
    }
    async fn resource<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        payload: Option<&Value>,
        cancel: &CancellationToken,
    ) -> Result<Resource<T>> {
        let response = self
            .wire
            .signed(&self.signer, Some(&self.location), url, payload, cancel)
            .await?;
        Ok(Resource {
            value: serde_json::from_slice(&response.body)
                .map_err(|_| uncertain(response.status, "invalidResourceJson"))?,
            location: self
                .wire
                .location(&response, url)
                .map_err(|_| uncertain(response.status, "invalidLocation"))?,
            retry_after: retry_after(&response.headers),
        })
    }
}

fn validate_url(url: &Url, trusted: &HashSet<String>, allow_loopback: bool, allowed_http_origin: Option<&str>) -> Result<()> {
    let loopback = matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    ensure!(
        (url.scheme() == "https" || (url.scheme() == "http" && ((allow_loopback && loopback)
            || allowed_http_origin == Some(url.origin().ascii_serialization().as_str()))))
            && trusted.contains(&url.origin().ascii_serialization())
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "untrusted ACME endpoint"
    );
    Ok(())
}

fn parse_nonce(headers: &reqwest::header::HeaderMap) -> Result<Option<String>> {
    let Some(raw) = headers.get("Replay-Nonce") else {
        return Ok(None);
    };
    let value = raw.to_str().map_err(|_| anyhow!("invalid ACME nonce"))?;
    ensure!(
        !value.is_empty()
            && value.len() <= 1024
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid ACME nonce"
    );
    Ok(Some(value.to_owned()))
}

pub(crate) fn zero_ssl_eab_response(status: StatusCode, body: &[u8]) -> Result<(String, String)> {
    #[derive(Deserialize)]
    struct Reply {
        #[serde(default)]
        success: bool,
        #[serde(default)]
        error: Failure,
        #[serde(default)]
        eab_kid: String,
        #[serde(default)]
        eab_hmac_key: String,
    }
    impl Drop for Reply {
        fn drop(&mut self) {
            self.eab_hmac_key.zeroize();
        }
    }
    #[derive(Default, Deserialize)]
    struct Failure {
        #[serde(default)]
        code: i64,
    }
    let mut reply: Reply =
        serde_json::from_slice(body).map_err(|_| anyhow!("invalid ZeroSSL EAB response"))?;
    ensure!(
        reply.error.code == 0,
        "ZeroSSL EAB API rejected the request"
    );
    ensure!(
        status == StatusCode::OK && reply.success,
        "ZeroSSL EAB credentials request failed"
    );
    ensure!(
        !reply.eab_kid.is_empty()
            && reply.eab_kid.len() <= 1024
            && !reply.eab_hmac_key.is_empty()
            && reply.eab_hmac_key.len() <= 4096,
        "invalid ZeroSSL EAB credentials"
    );
    Ok((
        std::mem::take(&mut reply.eab_kid),
        std::mem::take(&mut reply.eab_hmac_key),
    ))
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    let seconds = value.parse::<u64>().ok().or_else(|| {
        let time =
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822)
                .ok()?;
        Some(
            (time.unix_timestamp() - time::OffsetDateTime::now_utc().unix_timestamp()).max(0)
                as u64,
        )
    })?;
    Some(Duration::from_secs(seconds.clamp(1, 604800)))
}

fn problem_type(body:&[u8])->Option<String> {
    // Error details are optional. Do not build an arbitrary JSON Value tree
    // from a certificate endpoint's untrusted error body.
    if body.len()>65536{return None}
    #[derive(Deserialize)]struct Problem {#[serde(default)] r#type:Option<String>}
    serde_json::from_slice::<Problem>(body).ok()?.r#type
}
fn problem_kind(body: &[u8]) -> String {
    let value=problem_type(body);
    let kind=value.as_deref().unwrap_or("unknown").rsplit(':').next().unwrap_or("unknown");
    if kind.len()<=64&&kind.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-'){kind.to_owned()}else{"unknown".to_owned()}
}

fn check_status(response: &WireResponse) -> Result<()> {
    if !response.status.is_success() {
        return Err(ProtocolError {
            status: response.status.as_u16(),
            kind: problem_kind(&response.body),
            // A proxy's 5xx response may hide an already accepted POST. Only
            // a structured ACME problem supplies a definitive protocol reply.
            uncertain: response.is_post
                && response.status.is_server_error()
                && !response
                    .headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| {
                        v.split(';').next().is_some_and(|v| {
                            v.trim().eq_ignore_ascii_case("application/problem+json")
                        })
                    }),
            retry_after: retry_after(&response.headers),
        }
        .into());
    }
    Ok(())
}

async fn send(
    client: &reqwest::Client,
    method: Method,
    url: Url,
    body: Option<Vec<u8>>,
    cancel: &CancellationToken,
) -> Result<WireResponse> {
    send_with_type(client, method, url, body, "application/jose+json", cancel).await
}
async fn send_with_type(
    client: &reqwest::Client,
    method: Method,
    url: Url,
    body: Option<Vec<u8>>,
    content_type: &str,
    cancel: &CancellationToken,
) -> Result<WireResponse> {
    send_with_memory(client,method,url,body,content_type,None,None,None,cancel).await
}
async fn send_with_memory(client:&reqwest::Client,method:Method,url:Url,body:Option<Vec<u8>>,content_type:&str,memory:Option<Arc<ChainMemoryPools>>,body_credit:Option<ChainMemoryLease>,http_slots:Option<Arc<Semaphore>>,cancel:&CancellationToken)->Result<WireResponse> {
    let is_post = method == Method::POST;
    if cancel.is_cancelled() {
        return Err(cancelled_request(ProtocolError {
            status: 0,
            kind: "cancelledBeforeSend".to_owned(),
            uncertain: false,
            retry_after: None,
        }));
    }
    // Certificate concurrency covers only actual HTTP send/body collection.
    // JWS signing has already finished; no HTTP slot crosses CPU or recursion.
    let _http_slot=if let Some(slots)=http_slots {
        Some(tokio::select!{biased;
            _=cancel.cancelled()=>return Err(cancelled_request(ProtocolError{status:0,kind:"cancelledBeforeSend".into(),uncertain:false,retry_after:None})),
            permit=slots.acquire_owned()=>permit.map_err(|_|anyhow!("ACME certificate HTTP scheduling stopped"))?,
        })
    }else{None};
    let mut request = client.request(method, url);
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
    }
    let mut response = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(cancelled_request(ProtocolError{status:0,kind:"cancelled".to_owned(),uncertain:is_post,retry_after:None})),
        response = request.send() => response.map_err(|error| anyhow::Error::new(error.without_url()).context(ProtocolError {status:0,kind:"transport".to_owned(),uncertain:is_post,retry_after:None}))?,
    };
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BODY as u64)
    {
        return Err(ProtocolError {
            status: response.status().as_u16(),
            kind: "bodyLimit".to_owned(),
            uncertain: is_post,
            retry_after: None,
        }
        .into());
    }
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = chain_memory::Collector::new(memory,body_credit,response.content_length().map(|n|n as usize))?;
    loop {
        let chunk = tokio::select! { biased; _=cancel.cancelled()=>return Err(cancelled_request(ProtocolError{status:status.as_u16(),kind:"cancelled".to_owned(),uncertain:is_post,retry_after:None})), chunk=response.chunk()=>chunk.map_err(|error| anyhow::Error::new(error.without_url()).context(ProtocolError{status:status.as_u16(),kind:"responseTransport".to_owned(),uncertain:is_post,retry_after:None}))? };
        let Some(chunk) = chunk else { break };
        if body.len() + chunk.len() > MAX_BODY {
            return Err(ProtocolError {
                status: status.as_u16(),
                kind: "bodyLimit".to_owned(),
                uncertain: is_post,
                retry_after: None,
            }
            .into());
        }
        body.append(&chunk)?;
    }
    let (body,body_memory)=body.into_parts();
    Ok(WireResponse {
        is_post,
        status,
        headers,
        body,
        body_memory,
    })
}

/// RFC 9773 certID: base64url(AKI) + '.' + base64url(DER INTEGER contents).
/// A leading positive-sign octet is significant and must not be stripped.
pub fn ari_certificate_id(chain_pem: &[u8]) -> Result<Option<String>> {
    Ok(ari_certificate_id_owned(chain_pem)?.map(|id|Arc::try_unwrap(id.0).ok().expect("fresh ARI owner").value))
}
#[derive(Clone)]
pub(crate) struct AriCertificateId(Arc<AriCertificateIdData>);
struct AriCertificateIdData {
    value:String,
    _memory:chain_memory::Lease,
}
impl std::ops::Deref for AriCertificateId {
    type Target=str;
    fn deref(&self)->&str{&self.0.value}
}
pub(crate) fn ari_certificate_id_owned(chain_pem: &[u8]) -> Result<Option<AriCertificateId>> {
    use x509_parser::extensions::ParsedExtension;
    let blocks = crate::cert_transient::certificate_blocks(chain_pem)?;
    let first = blocks
        .first()
        .ok_or_else(|| anyhow!("empty ARI certificate material"))?;
    ensure!(
        first.0 == "CERTIFICATE",
        "ARI material is not a certificate"
    );
    let (remaining, cert) = crate::cert_transient::parse_certificate(&first.1)?;
    ensure!(remaining.is_empty(), "trailing ARI certificate data");
    let mut aki = None;
    for extension in cert.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(value) = extension.parsed_extension() {
            ensure!(aki.is_none(), "duplicate ARI authority key identifier");
            aki = value.key_identifier.as_ref().map(|v| v.0);
        }
    }
    let Some(aki) = aki else { return Ok(None) };
    let serial = cert.raw_serial();
    let len=base64::encoded_len(aki.len(),false)
        .and_then(|n|base64::encoded_len(serial.len(),false).and_then(|m|n.checked_add(m)))
        .and_then(|n|n.checked_add(1)).ok_or(crate::cert_transient::ResourceDenied)?;
    let memory=chain_memory::shared().payload.reserve(len).map_err(|_|crate::cert_transient::ResourceDenied)?;
    let mut value=String::new();value.try_reserve_exact(len).map_err(|_|crate::cert_transient::ResourceDenied)?;
    URL_SAFE_NO_PAD.encode_string(aki,&mut value);value.push('.');URL_SAFE_NO_PAD.encode_string(serial,&mut value);
    ensure!(value.len()==len && value.capacity()==len,"unexpected ARI encoding capacity");
    Ok(Some(AriCertificateId(Arc::new(AriCertificateIdData{value,_memory:memory}))))
}

fn uncertain(status: StatusCode, kind: &str) -> anyhow::Error {
    ProtocolError {
        status: status.as_u16(),
        kind: kind.to_owned(),
        uncertain: true,
        retry_after: None,
    }
    .into()
}

/// Go ACME issuer's per-file AppendCertsFromPEM contract. Keep the original
/// client builder/provider/proxy, append only usable anchors, reject all-bad.
pub(crate) fn append_trusted_root_pem(mut builder:reqwest::ClientBuilder,pem:&[u8])->Result<reqwest::ClientBuilder> {
    let bytes=pem.len().checked_mul(8).and_then(|n|n.checked_add(65536))
        .ok_or(chain_memory::MemoryDenied)?;
    let _scratch=chain_memory::try_scratch(bytes)?;
    let certs=crate::tls_policy::source_append_certificates(pem)?;
    let mut valid=0usize;
    for cert in certs {
        if webpki::anchor_from_trusted_cert(&cert).is_err(){continue;}
        builder=builder.add_root_certificate(reqwest::Certificate::from_der(cert.as_ref())?);
        valid+=1;
    }
    ensure!(valid>0,"ACME trust root PEM contains no usable certificates");
    Ok(builder)
}
