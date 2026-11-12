//! Bounded RFC 8555 client. Signing, transport and order persistence are separate.
//! No request is silently retried after an uncertain network outcome. Only an
//! explicit ACME badNonce response permits a bounded replay with a fresh nonce.

#[path = "acme_wire/signer.rs"]
mod signer;
mod network_proxy;
mod order_parameters;
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

#[derive(Clone)]
pub struct AcmeWire {
    inner: Arc<WireInner>,
}
struct WireInner {
    cpu: Arc<Semaphore>,
    client: reqwest::Client,
    directory_url: Url,
    directory: Directory,
    trusted: HashSet<String>,
    allow_loopback: bool,
    nonces: Mutex<Vec<String>>,
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
}

impl AcmeWire {
    pub async fn connect(options: WireOptions, cancel: &CancellationToken) -> Result<Self> {
        static CPU: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
        let cpu = CPU.get_or_init(|| Arc::new(Semaphore::new(std::thread::available_parallelism().map_or(1,usize::from).min(4)))).clone();
        Self::connect_with_cpu(options,cpu,cancel).await
    }
    pub(crate) async fn connect_with_cpu(options: WireOptions, cpu: Arc<Semaphore>, cancel: &CancellationToken) -> Result<Self> {
        ensure!(
            !options.request_timeout.is_zero()
                && options.request_timeout <= Duration::from_secs(3600),
            "invalid ACME request timeout"
        );
        ensure!(
            options.extra_ca_pem.len() <= 32 && options.trusted_ca_origins.len() <= 32,
            "ACME trust configuration exceeds bounds"
        );
        let directory_url =
            Url::parse(&options.directory).map_err(|_| anyhow!("invalid ACME directory URL"))?;
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
            )?;
            trusted.insert(url.origin().ascii_serialization());
        }
        validate_url(&directory_url, &trusted, options.allow_insecure_loopback)?;
        if let Some(proxy)=&options.network_proxy {proxy.validate()?;}
        let client = crate::cert_cpu::run(cpu.clone(),cancel.clone(),move || {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(options.request_timeout)
            .user_agent("Caddy-Rust-ACME/0.1");
        if let Some(proxy)=options.network_proxy {builder=proxy.apply(builder)?;}
        for pem in options.extra_ca_pem {
            ensure!(pem.len() <= 1024 * 1024, "ACME trust root exceeds bounds");
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem)
                    .map_err(|_| anyhow!("invalid ACME trust root"))?,
            );
        }
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
            )?;
        }
        Ok(Self {
            inner: Arc::new(WireInner {
                client,
                cpu,
                directory_url,
                directory,
                trusted,
                allow_loopback: options.allow_insecure_loopback,
                nonces: Mutex::new(Vec::new()),
            }),
        })
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
        validate_url(&url, &self.inner.trusted, self.inner.allow_loopback)?;
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
        if let Some(kid) = kid {
            self.endpoint(kid)?;
        }
        for attempt in 0..3 {
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
                Err(_) if cancel.is_cancelled() => return Err(ProtocolError { status:0,kind:"cancelledBeforeSend".into(),uncertain:false,retry_after:None }.into()),
                result => result?,
            };
            let body = serde_json::to_vec(
                &json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(signature)}),
            )?;
            let response = send(
                &self.inner.client,
                Method::POST,
                url.clone(),
                Some(body),
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
                && serde_json::from_slice::<Value>(&response.body)
                    .ok()
                    .and_then(|v| v["type"].as_str().map(str::to_owned))
                    .as_deref()
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

fn validate_url(url: &Url, trusted: &HashSet<String>, allow_loopback: bool) -> Result<()> {
    let loopback = matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    ensure!(
        (url.scheme() == "https" || (allow_loopback && url.scheme() == "http" && loopback))
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

fn problem_kind(body: &[u8]) -> String {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let kind = value["type"]
        .as_str()
        .unwrap_or("unknown")
        .rsplit(':')
        .next()
        .unwrap_or("unknown");
    if kind.len() <= 64
        && kind
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        kind.to_owned()
    } else {
        "unknown".to_owned()
    }
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
    let is_post = method == Method::POST;
    if cancel.is_cancelled() {
        return Err(ProtocolError {
            status: 0,
            kind: "cancelledBeforeSend".to_owned(),
            uncertain: false,
            retry_after: None,
        }
        .into());
    }
    let mut request = client.request(method, url);
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
    }
    let mut response = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(ProtocolError{status:0,kind:"cancelled".to_owned(),uncertain:is_post,retry_after:None}.into()),
        response = request.send() => response.map_err(|_| ProtocolError {status:0,kind:"transport".to_owned(),uncertain:is_post,retry_after:None})?,
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
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! { biased; _=cancel.cancelled()=>return Err(ProtocolError{status:status.as_u16(),kind:"cancelled".to_owned(),uncertain:is_post,retry_after:None}.into()), chunk=response.chunk()=>chunk.map_err(|_| ProtocolError{status:status.as_u16(),kind:"responseTransport".to_owned(),uncertain:is_post,retry_after:None})? };
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
        body.extend_from_slice(&chunk);
    }
    Ok(WireResponse {
        is_post,
        status,
        headers,
        body,
    })
}

/// RFC 9773 certID: base64url(AKI) + '.' + base64url(DER INTEGER contents).
/// A leading positive-sign octet is significant and must not be stripped.
pub fn ari_certificate_id(chain_pem: &[u8]) -> Result<Option<String>> {
    use x509_parser::extensions::ParsedExtension;
    let blocks = crate::certmagic::pem_blocks(chain_pem, "ari-certificate")?;
    let first = blocks
        .first()
        .ok_or_else(|| anyhow!("empty ARI certificate material"))?;
    ensure!(
        first.0 == "CERTIFICATE",
        "ARI material is not a certificate"
    );
    let (remaining, cert) = x509_parser::parse_x509_certificate(&first.1)
        .map_err(|_| anyhow!("invalid ARI certificate"))?;
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
    Ok(Some(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(aki),
        URL_SAFE_NO_PAD.encode(serial)
    )))
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
