//! Configuration-time HTTP CA modules. Network, actual-byte ownership and
//! CPU decoding have separate lifetimes; handshakes only consume prepared roots.
use super::*;
use base64::Engine;
use serde_json::{Map, Value};
use std::{io::Read, pin::Pin, sync::atomic::AtomicUsize};
use tokio::sync::OwnedSemaphorePermit;
use url::Url;
const BODY: usize = 4 * 1024 * 1024;
const INPUT_CREDIT: u32 = (2 * BODY + 1024 * 1024) as u32;
const TOTAL: usize = 16 * 1024 * 1024;

enum Plan {
    Static(Value),
    Combined(Map<String, Value>, Vec<Plan>),
    Http { endpoints: Vec<Url>, tls: Tls },
}
struct Tls {
    renegotiation:native_ssl_tls::Renegotiation,
    ca: Option<Box<Plan>>,
    insecure: bool,
    name: Option<String>,
    handshake: Option<Duration>,
}
struct Prepared {
    value: Value,
    _output: Vec<OwnedSemaphorePermit>,
}
struct Download {
    bytes: Vec<u8>,
    gzip: bool,
    _input: OwnedSemaphorePermit,
}
struct BodyOutput {
    values: Vec<Value>,
    _output: OwnedSemaphorePermit,
}
struct Counts {
    raw: AtomicUsize,
    decoded: AtomicUsize,
    der: AtomicUsize,
    certificates: AtomicUsize,
    requests: AtomicUsize,
}
struct Context {
    services: Arc<CertificateServices>,
    cancel: CancellationToken,
    network: Arc<tokio::sync::Semaphore>,
    counts: Counts,
}
fn charge(counter: &AtomicUsize, n: usize, max: usize) -> Result<()> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
            v.checked_add(n).filter(|v| *v <= max)
        })
        .map(|_| ())
        .map_err(|_| crate::cert_transient::ResourceDenied.into())
}
fn http_url(raw: &str) -> Result<Url> {
    ensure!(raw.len() <= 8192, "HTTP CA URL exceeds bounds");
    let mut url = Url::parse(raw).map_err(|_| anyhow!("invalid HTTP CA source URL"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "HTTP CA URL must use HTTP(S)"
    );
    url.set_fragment(None);
    Ok(url)
}
fn plan(
    value: Value,
    depth: usize,
    nodes: &mut usize,
    endpoints: &mut usize,
    found: &mut bool,
) -> Result<Plan> {
    ensure!(depth < 8, "CA module nesting too deep");
    *nodes = nodes
        .checked_add(1)
        .ok_or(crate::cert_transient::ResourceDenied)?;
    ensure!(*nodes <= 4096, "CA module count exceeds bounds");
    match value.get("provider").and_then(Value::as_str) {
        Some("combined") => {
            let mut object = match value {
                Value::Object(v) => v,
                _ => return Err(anyhow!("CA module must be an object")),
            };
            // Move child values out; no network or certificate parsing during planning.
            crate::http_config::helpers::deny_unknown(
                &object,
                &["provider", "sources"],
                "combined CA module",
            )?;
            let children = match object.remove("sources") {
                Some(Value::Array(v)) => v,
                _ => return Err(anyhow!("combined CA sources required")),
            };
            ensure!(
                !children.is_empty() && children.len() <= 256,
                "combined CA source count exceeds bounds"
            );
            let children = children
                .into_iter()
                .map(|v| plan(v, depth + 1, nodes, endpoints, found))
                .collect::<Result<_>>()?;
            Ok(Plan::Combined(object, children))
        }
        Some("http") => {
            *found = true;
            let mut object = match value {
                Value::Object(v) => v,
                _ => return Err(anyhow!("HTTP CA module must be an object")),
            };
            crate::http_config::helpers::deny_unknown(
                &object,
                &["provider", "endpoints", "tls"],
                "HTTP CA module",
            )?;
            let values = match object.remove("endpoints") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(v)) => v,
                _ => return Err(anyhow!("HTTP CA endpoints must be an array")),
            };
            ensure!(values.len() <= 256, "HTTP CA endpoint count exceeds bounds");
            *endpoints = endpoints
                .checked_add(values.len())
                .ok_or(crate::cert_transient::ResourceDenied)?;
            ensure!(*endpoints <= 256, "HTTP CA endpoint count exceeds bounds");
            let urls = values
                .into_iter()
                .map(|v| match v {
                    Value::String(v) => http_url(&v),
                    _ => Err(anyhow!("HTTP CA endpoint must be a string")),
                })
                .collect::<Result<_>>()?;
            let mut tls = match object.remove("tls") {
                None | Some(Value::Null) => Map::new(),
                Some(Value::Object(v)) => v,
                _ => return Err(anyhow!("HTTP CA TLS options must be an object")),
            };
            crate::http_config::helpers::deny_unknown(
                &tls,
                &[
                    "ca",
                    "insecure_skip_verify",
                    "handshake_timeout",
                    "server_name",
                    "renegotiation",
                ],
                "HTTP CA TLS options",
            )?;
            let ca = tls
                .remove("ca")
                .filter(|v| !v.is_null())
                .map(|v| plan(v, depth + 1, nodes, endpoints, found).map(Box::new))
                .transpose()?;
            let insecure = match tls.remove("insecure_skip_verify") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(v)) => v,
                _ => return Err(anyhow!("HTTP CA insecure_skip_verify must be a boolean")),
            };
            let name = match tls.remove("server_name") {
                None | Some(Value::Null) => None,
                Some(Value::String(v)) if v.is_empty() => None,
                Some(Value::String(v)) => {
                    ensure!(v.len() <= 8192, "HTTP CA TLS server name exceeds bounds");
                    rustls::pki_types::ServerName::try_from(v.clone())
                        .map_err(|_| anyhow!("invalid HTTP CA TLS server name"))?;
                    Some(v)
                }
                _ => return Err(anyhow!("HTTP CA TLS server name must be a string")),
            };
            let handshake = tls
                .remove("handshake_timeout")
                .filter(|v| !v.is_null())
                .map(|v| crate::http_config::helpers::duration(&v, "HTTP CA TLS handshake timeout"))
                .transpose()?
                .filter(|v| !v.is_zero());
            let renegotiation=match tls.remove("renegotiation").filter(|v|!v.is_null()){
                None=>native_ssl_tls::Renegotiation::Never,
                Some(Value::String(v))=>native_ssl_tls::Renegotiation::parse(&v).map_err(anyhow::Error::msg)?,
                _=>return Err(anyhow!("HTTP CA TLS renegotiation must be a string")),
            };
            Ok(Plan::Http {
                endpoints: urls,
                tls: Tls {
                    renegotiation,
                    ca,
                    insecure,
                    name,
                    handshake,
                },
            })
        }
        _ => Ok(Plan::Static(value)),
    }
}
// Extract configured HTTP Basic authentication before handing the URL to the
// client; URL resolution alone preserves credentials on relative references.
// An absolute redirect without userinfo must not inherit URL Basic credentials.
// Request errors never expose userinfo. All redirects remain GET requests.
fn take_auth(url: &mut Url) -> Result<Option<http::HeaderValue>> {
    if url.username().is_empty() && url.password().is_none() {
        return Ok(None);
    }
    let mut raw = percent_encoding::percent_decode_str(url.username()).collect::<Vec<_>>();
    raw.push(b':');
    if let Some(password) = url.password() {
        raw.extend(percent_encoding::percent_decode_str(password));
    }
    let mut value = http::HeaderValue::from_str(&format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(&raw)
    ))
    .map_err(|_| anyhow!("invalid HTTP CA authentication"))?;
    value.set_sensitive(true);
    url.set_username("")
        .map_err(|_| anyhow!("invalid HTTP CA URL"))?;
    url.set_password(None)
        .map_err(|_| anyhow!("invalid HTTP CA URL"))?;
    Ok(Some(value))
}
impl Context {
    // A failing source cancels siblings, but still polls every started future to
    // completion. In particular a cert_cpu worker must join before its owner
    // task can leave CertificateServices.tasks during reload/stop.
    async fn collect<T>(
        &self,
        input: impl futures_util::Stream<Item = Result<T>>,
    ) -> Result<Vec<T>> {
        tokio::pin!(input);
        let mut values = Vec::new();
        let mut failure = None;
        while let Some(result) = input.next().await {
            match result {
                Ok(value) => values.push(value),
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                    self.cancel.cancel();
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(values),
        }
    }
    async fn download(
        self: &Arc<Self>,
        client: &reqwest::Client,
        mut url: Url,
    ) -> Result<Download> {
        let _network = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(anyhow!("HTTP CA fetch cancelled")),v=self.network.clone().acquire_owned()=>v.map_err(|_|anyhow!("HTTP CA network admission stopped"))?};
        let input = self
            .services
            .context
            .resources
            .external_bytes
            .clone()
            .try_acquire_many_owned(INPUT_CREDIT)
            .map_err(|_| crate::cert_transient::ResourceDenied)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(BODY)
            .map_err(|_| crate::cert_transient::ResourceDenied)?;
        let gzip = {
            let operation = async {
                for hop in 0..10 {
                    charge(&self.counts.requests, 1, 256)?;
                    let mut request_url = url.clone();
                    let auth = take_auth(&mut request_url)?;
                    let mut request = client
                        .get(request_url)
                        .header(http::header::USER_AGENT, "Go-http-client/1.1")
                        .header(http::header::ACCEPT_ENCODING, "gzip");
                    if let Some(auth) = &auth {
                        request = request.header(http::header::AUTHORIZATION, auth.clone());
                    }
                    let mut response = request
                        .send()
                        .await
                        .map_err(|_| anyhow!("HTTP CA source request failed"))?;
                    if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                        if let Some(location) = response.headers().get(http::header::LOCATION) {
                            ensure!(hop < 9, "HTTP CA redirect limit exceeded");
                            let location = location
                                .to_str()
                                .map_err(|_| anyhow!("invalid HTTP CA redirect location"))?;
                            ensure!(
                                location.len() <= 8192,
                                "HTTP CA redirect URL exceeds bounds"
                            );
                            let next = url
                                .join(location)
                                .map_err(|_| anyhow!("invalid HTTP CA redirect URL"))?;
                            let next = http_url(next.as_str())?;
                            ensure!(
                                url.scheme() != "https" || next.scheme() == "https",
                                "HTTP CA HTTPS redirect cannot downgrade transport"
                            );
                            url = next;
                            continue;
                        }
                    }
                    ensure!(
                        response.status().is_success(),
                        "HTTP CA source returned a non-success status"
                    );
                    ensure!(
                        response.content_length().is_none_or(|v| v <= BODY as u64),
                        "HTTP CA source body exceeds bounds"
                    );
                    let gzip = response
                        .headers()
                        .get(http::header::CONTENT_ENCODING)
                        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|_| anyhow!("HTTP CA response read failed"))?
                    {
                        ensure!(
                            chunk.len() <= BODY - bytes.len(),
                            "HTTP CA source body exceeds bounds"
                        );
                        charge(&self.counts.raw, chunk.len(), TOTAL)?;
                        bytes.extend_from_slice(&chunk);
                    }
                    return Ok(gzip);
                }
                Err(anyhow!("HTTP CA redirect limit exceeded"))
            };
            tokio::pin!(operation);
            tokio::select! {biased;_=self.cancel.cancelled()=>return Err(anyhow!("HTTP CA fetch cancelled")),v=tokio::time::timeout(Duration::from_secs(30),&mut operation)=>v.map_err(|_|anyhow!("HTTP CA source deadline exceeded"))??}
        };
        Ok(Download {
            bytes,
            gzip,
            _input: input,
        })
    }
    async fn decode(self: &Arc<Self>, download: Download) -> Result<BodyOutput> {
        let this = self.clone();
        crate::cert_cpu::run(
            self.services.context.resources.cpu.clone(),
            self.cancel.clone(),
            move || {
                let inflated = if download.gzip {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(BODY + 1)
                        .map_err(|_| crate::cert_transient::ResourceDenied)?;
                    flate2::read::MultiGzDecoder::new(download.bytes.as_slice())
                        .take((BODY + 1) as u64)
                        .read_to_end(&mut bytes)
                        .map_err(|_| anyhow!("invalid HTTP CA gzip body"))?;
                    ensure!(bytes.len() <= BODY, "HTTP CA inflated body exceeds bounds");
                    Some(bytes)
                } else {
                    None
                };
                let body = inflated.as_deref().unwrap_or(download.bytes.as_slice());
                charge(&this.counts.decoded, body.len(), TOTAL)?;
                let allowance = body
                    .len()
                    .checked_mul(6)
                    .and_then(|n| n.checked_add(65536))
                    .ok_or(crate::cert_transient::ResourceDenied)?;
                let output = this
                    .services
                    .context
                    .resources
                    .external_bytes
                    .clone()
                    .try_acquire_many_owned(
                        u32::try_from(allowance)
                            .map_err(|_| crate::cert_transient::ResourceDenied)?,
                    )
                    .map_err(|_| crate::cert_transient::ResourceDenied)?;
                let _scratch = crate::cert_transient::reserve(allowance)?;
                let mut values = Vec::new();
                for der in crate::tls_policy::source_certificates(body)? {
                    charge(&this.counts.certificates, 1, 4096)?;
                    charge(&this.counts.der, der.len(), TOTAL)?;
                    values.push(Value::String(
                        base64::engine::general_purpose::STANDARD.encode(der.as_ref()),
                    ));
                }
                Ok(BodyOutput {
                    values,
                    _output: output,
                })
            },
        )
        .await
    }
    fn resolve(
        self: Arc<Self>,
        node: Plan,
    ) -> Pin<Box<dyn Future<Output = Result<Prepared>> + Send>> {
        Box::pin(async move {
            match node {
                Plan::Static(value) => Ok(Prepared {
                    value,
                    _output: Vec::new(),
                }),
                Plan::Combined(mut object, children) => {
                    let prepared = self
                        .collect(
                            stream::iter(children)
                                .map(|v| self.clone().resolve(v))
                                .buffered(4),
                        )
                        .await?;
                    let mut values = Vec::new();
                    let mut credit = Vec::new();
                    for p in prepared {
                        values.push(p.value);
                        credit.extend(p._output);
                    }
                    object.insert("sources".into(), Value::Array(values));
                    Ok(Prepared {
                        value: Value::Object(object),
                        _output: credit,
                    })
                }
                Plan::Http { endpoints, tls } => {
                    let child = match tls.ca {
                        Some(ca) => Some(self.clone().resolve(*ca).await?),
                        None => None,
                    };
                    let cancel = self.cancel.clone();
                    let ssl_verify=self.services.ssl_verify.clone();
                    #[cfg(feature="native-run")]
                    let scope=self.services.outgoing_tls.clone();
                    let client = crate::cert_cpu::run(
                        self.services.context.resources.cpu.clone(),
                        cancel,
                        move || {
                            let mut retained = Vec::new();
                            let ca = child.map(|p| {
                                retained = p._output;
                                p.value
                            });
                            let config =
                                crate::http_runtime::ca_source_prepared_tls(ca, tls.insecure,tls.renegotiation,Some(&ssl_verify))?;
                            let mut builder = reqwest::Client::builder()
                                .use_preconfigured_tls(config.rustls)
                                .redirect(reqwest::redirect::Policy::none())
                                .connect_timeout(Duration::from_secs(10))
                                .timeout(Duration::from_secs(30))
                                .pool_max_idle_per_host(0)
                                .http2_max_header_list_size(65536);
                            if let Some(native)=config.native{builder=builder.prepared_openssl_tls(native);}
                            else {
                                #[cfg(feature="native-run")]
                                if let Some(scope)=scope{builder=builder.connector_layer(scope.layer()?);}
                            }
                            if let Some(name) = tls.name {
                                builder = builder.tls_server_name_override(name);
                            }
                            if let Some(timeout) = tls.handshake {
                                builder = builder.tls_handshake_timeout(timeout);
                            }
                            let client = builder
                                .build()
                                .map_err(|_| anyhow!("HTTP CA client preparation failed"))?;
                            drop(retained);
                            Ok(client)
                        },
                    )
                    .await?;
                    let bodies = self
                        .collect(
                            stream::iter(endpoints)
                                .map(|url| {
                                    let this = self.clone();
                                    let client = client.clone();
                                    async move {
                                        let body = this.download(&client, url).await?;
                                        this.decode(body).await
                                    }
                                })
                                .buffered(4),
                        )
                        .await?;
                    let mut values = Vec::new();
                    let mut credits = Vec::new();
                    for body in bodies {
                        values.extend(body.values);
                        credits.push(body._output);
                    }
                    let mut object = Map::new();
                    object.insert("provider".into(), Value::String("inline".into()));
                    object.insert("trusted_ca_certs".into(), Value::Array(values));
                    Ok(Prepared {
                        value: Value::Object(object),
                        _output: credits,
                    })
                }
            }
        })
    }
}
impl CertificateServices {
    #[cfg(feature = "native-run")]
    pub(crate) async fn prepare_client_pools(
        self: &Arc<Self>,
        config: crate::http_config::PreparedConfig,
        cancel: CancellationToken,
    ) -> Result<crate::http_config::PreparedConfig> {
        let config = self.prepare_managed_clients(config, cancel.clone()).await?;
        let config = self.prepare_storage_pools(config, cancel.clone()).await?;
        self.owned(cancel, move |this, token| {
            Box::pin(async move {
                let (mut config, plans, found) = crate::cert_cpu::run(
                    this.context.resources.cpu.clone(),
                    token.clone(),
                    move || {
                        let mut config = config;
                        let mut plans = Vec::new();
                        let (mut nodes, mut urls, mut found) = (0usize, 0usize, false);
                        super::ca_consumers::each_root_mut(&mut config, &mut |value| {
                            plans.push(plan(
                                std::mem::take(value),
                                0,
                                &mut nodes,
                                &mut urls,
                                &mut found,
                            )?);
                            Ok(())
                        })?;
                        Ok((config, plans, found))
                    },
                )
                .await?;
                let context = Arc::new(Context {
                    services: this.clone(),
                    cancel: token.child_token(),
                    network: this.context.resources.ca_fetch.clone(),
                    counts: Counts {
                        raw: AtomicUsize::new(0),
                        decoded: AtomicUsize::new(0),
                        der: AtomicUsize::new(0),
                        certificates: AtomicUsize::new(0),
                        requests: AtomicUsize::new(0),
                    },
                });
                let operation = context.collect(
                    stream::iter(plans)
                        .map(|v| context.clone().resolve(v))
                        .buffered(4),
                );
                tokio::pin!(operation);
                let prepared = if found {
                    tokio::select! {
                        value = &mut operation => value,
                        _ = token.cancelled() => {
                            context.cancel.cancel();
                            let _ = operation.await;
                            Err(anyhow!("HTTP CA preparation cancelled"))
                        }
                        _ = tokio::time::sleep(Duration::from_secs(120)) => {
                            context.cancel.cancel();
                            let _ = operation.await;
                            Err(anyhow!("HTTP CA preparation deadline exceeded"))
                        }
                    }?
                } else {
                    operation.await?
                };
                crate::cert_cpu::run(this.context.resources.cpu.clone(), token, move || {
                    let mut values = prepared.into_iter();
                    super::ca_consumers::each_root_mut(&mut config, &mut |value| {
                        let Prepared {
                            value: resolved,
                            _output,
                        } = values
                            .next()
                            .ok_or_else(|| anyhow!("CA consumer topology changed"))?;
                        *value = resolved;
                        drop(_output);
                        Ok(())
                    })?;
                    ensure!(values.next().is_none(), "CA consumer topology changed");
                    Ok(config)
                })
                .await
            })
        })
        .await
    }
}
