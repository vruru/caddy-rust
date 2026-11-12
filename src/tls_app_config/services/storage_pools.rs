//! Configuration-time CA storage inputs; no storage I/O in handshakes.
use super::*;
use base64::Engine;
use futures_util::TryStreamExt;
use serde_json::{Map, Value};
use std::{path::PathBuf, sync::atomic::AtomicUsize};

#[derive(Clone)]
struct Location {
    server: usize,
    policy: usize,
    path: Vec<usize>,
}
struct Request {
    location: Location,
    storage: Option<PathBuf>,
    keys: Vec<String>,
}
struct Resolved {
    location: Location,
    module: Value,
    _credit: crate::acme_wire::chain_memory::Scratch,
}
struct Totals {
    raw: AtomicUsize,
    der: AtomicUsize,
    certificates: AtomicUsize,
}
fn charge(counter: &AtomicUsize, bytes: usize, max: usize) -> Result<()> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            n.checked_add(bytes).filter(|n| *n <= max)
        })
        .map(|_| ())
        .map_err(|_| crate::cert_transient::ResourceDenied.into())
}
fn collect(
    value: &Value,
    depth: usize,
    location: &mut Location,
    out: &mut Vec<Request>,
    total_keys: &mut usize,
) -> Result<()> {
    ensure!(depth < 8, "client trust provider nesting too deep");
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("client trust provider must be an object"))?;
    match object.get("provider").and_then(Value::as_str) {
        Some("combined") => {
            crate::http_config::helpers::deny_unknown(
                object,
                &["provider", "sources"],
                "combined client trust pool",
            )?;
            let sources = object
                .get("sources")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("combined trust sources required"))?;
            ensure!(
                !sources.is_empty() && sources.len() <= 256,
                "combined trust source count exceeds bounds"
            );
            for (i, source) in sources.iter().enumerate() {
                location.path.push(i);
                collect(source, depth + 1, location, out, total_keys)?;
                location.path.pop();
            }
        }
        Some("storage") => {
            crate::http_config::helpers::deny_unknown(
                object,
                &["provider", "storage", "pem_keys"],
                "storage client trust pool",
            )?;
            let storage = super::super::pki_parse::parse_storage(
                object.get("storage"),
                "client trust storage",
            )?;
            let keys = object
                .get("pem_keys")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("client trust storage PEM keys required"))?;
            ensure!(
                !keys.is_empty() && keys.len() <= 256 && out.len() < 256,
                "client trust storage source count exceeds bounds"
            );
            *total_keys = total_keys
                .checked_add(keys.len())
                .ok_or(crate::cert_transient::ResourceDenied)?;
            ensure!(
                *total_keys <= 4096,
                "client trust storage keys exceed bounds"
            );
            let keys = keys
                .iter()
                .map(|v| {
                    let key = v
                        .as_str()
                        .ok_or_else(|| anyhow!("client trust storage key must be a string"))?;
                    ensure!(
                        !key.is_empty() && key.len() <= 4096,
                        "client trust storage key exceeds bounds"
                    );
                    Ok(key.into())
                })
                .collect::<Result<Vec<_>>>()?;
            out.push(Request {
                location: location.clone(),
                storage,
                keys,
            });
        }
        _ => {}
    }
    Ok(())
}
fn at<'a>(
    config: &'a mut crate::http_config::PreparedConfig,
    location: &Location,
) -> Result<&'a mut Value> {
    let server = config
        .servers
        .get_mut(location.server)
        .ok_or_else(|| anyhow!("client trust server location changed"))?;
    let policy = Arc::make_mut(server)
        .tls_policies
        .get_mut(location.policy)
        .ok_or_else(|| anyhow!("client trust policy location changed"))?;
    let mut value = policy
        .client_auth
        .as_mut()
        .and_then(|auth| auth.ca.as_mut())
        .ok_or_else(|| anyhow!("client trust provider location changed"))?;
    for index in &location.path {
        value = value
            .get_mut("sources")
            .and_then(Value::as_array_mut)
            .and_then(|v| v.get_mut(*index))
            .ok_or_else(|| anyhow!("client trust source location changed"))?;
    }
    Ok(value)
}
impl CertificateServices {
    #[cfg(feature = "native-run")]
    pub(crate) async fn prepare_client_pools(
        self: &Arc<Self>,
        config: crate::http_config::PreparedConfig,
        cancel: CancellationToken,
    ) -> Result<crate::http_config::PreparedConfig> {
        let config = self.prepare_pki_pools(config, cancel.clone()).await?;
        self.owned(cancel, move |this, token| {
            Box::pin(async move {
                let (config, requests) = crate::cert_cpu::run(
                    this.context.resources.cpu.clone(),
                    token.clone(),
                    move || {
                        let mut requests = Vec::new();
                        let mut total_keys = 0;
                        for (si, server) in config.servers.iter().enumerate() {
                            for (pi, policy) in server.tls_policies.iter().enumerate() {
                                if let Some(value) =
                                    policy.client_auth.as_ref().and_then(|a| a.ca.as_ref())
                                {
                                    collect(
                                        value,
                                        0,
                                        &mut Location {
                                            server: si,
                                            policy: pi,
                                            path: Vec::new(),
                                        },
                                        &mut requests,
                                        &mut total_keys,
                                    )?;
                                }
                            }
                        }
                        Ok((config, requests))
                    },
                )
                .await?;
                if requests.is_empty() {
                    return Ok(config);
                }
                let totals = Arc::new(Totals {
                    raw: AtomicUsize::new(0),
                    der: AtomicUsize::new(0),
                    certificates: AtomicUsize::new(0),
                });
                let guard = token.clone().drop_guard();
                let resolved: Vec<Resolved> = stream::iter(requests)
                    .map(|request| {
                        let this = this.clone();
                        let token = token.clone();
                        let totals = totals.clone();
                        async move {
                            let root = request
                                .storage
                                .clone()
                                .or_else(|| this.plan.storage.clone())
                                .unwrap_or_else(|| this.context.paths.default_storage.clone());
                            let store = this
                                .context
                                .resources
                                .store(root, &this.context.paths, token.clone())
                                .await?;
                            // Preserve the configured key order while independent FD
                            // reads progress concurrently. No CPU loan spans I/O.
                            let input: Vec<_> = stream::iter(request.keys.iter().cloned())
                                .map(|key| {
                                    let fs = store.fs.clone();
                                    let token = token.clone();
                                    let totals = totals.clone();
                                    async move {
                                        ensure!(
                                            !token.is_cancelled(),
                                            "client trust storage load cancelled"
                                        );
                                        let raw =
                                            fs.load_ca_input(&key).await?.ok_or_else(|| {
                                                anyhow!("client trust storage input missing")
                                            })?;
                                        charge(&totals.raw, raw.len(), 16 * 1024 * 1024)?;
                                        Ok::<_, anyhow::Error>(raw)
                                    }
                                })
                                .buffered(4)
                                .try_collect()
                                .await?;
                            let bytes = input.iter().try_fold(0usize, |n, raw| {
                                n.checked_add(raw.len())
                                    .ok_or(crate::cert_transient::ResourceDenied)
                            })?;
                            let scratch = bytes
                                .checked_mul(6)
                                .and_then(|n| n.checked_add(65536))
                                .ok_or(crate::cert_transient::ResourceDenied)?;
                            crate::cert_cpu::run(
                                this.context.resources.cpu.clone(),
                                token,
                                move || {
                                    let credit = crate::cert_transient::reserve(scratch)?;
                                    let mut output = Vec::new();
                                    for raw in &input {
                                        for der in
                                            crate::tls_policy::source_certificates(raw.as_slice())?
                                        {
                                            charge(&totals.certificates, 1, 4096)?;
                                            charge(&totals.der, der.len(), 16 * 1024 * 1024)?;
                                            output.push(Value::String(
                                                base64::engine::general_purpose::STANDARD
                                                    .encode(der.as_ref()),
                                            ));
                                        }
                                    }
                                    let mut module = Map::new();
                                    module
                                        .insert("provider".into(), Value::String("inline".into()));
                                    module.insert("trusted_ca_certs".into(), Value::Array(output));
                                    Ok(Resolved {
                                        location: request.location,
                                        module: Value::Object(module),
                                        _credit: credit,
                                    })
                                },
                            )
                            .await
                        }
                    })
                    .buffered(4)
                    .try_collect()
                    .await?;
                let result =
                    crate::cert_cpu::run(this.context.resources.cpu.clone(), token, move || {
                        let mut config = config;
                        for resolved in resolved {
                            let Resolved {
                                location,
                                module,
                                _credit,
                            } = resolved;
                            *at(&mut config, &location)? = module;
                            // The fully prepared inline value now belongs to the existing config
                            // control/output boundary. Decoder/input staging is no longer its owner.
                            drop(_credit);
                        }
                        Ok(config)
                    })
                    .await;
                drop(guard);
                result
            })
        })
        .await
    }
}
