//! Caddy's HTTP on-demand permission module. No endpoint or credentials are
//! included in errors. Permission controls cache misses and renewal, not access
//! to an already resident, valid certificate.
use crate::{cert_automation::AutomationResources, cert_cpu, http_config::helpers};
use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;
#[path = "permission/proxy.rs"]
mod proxy;
#[path = "permission/query.rs"]
mod query;
#[path = "permission/target.rs"]
mod target;

const TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermissionFailure {
    Denied(u16),
    Cancelled,
    Timeout,
    Endpoint,
    Transport,
    Capacity,
}
impl std::fmt::Display for PermissionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(status) => write!(f, "certificate permission denied (HTTP {status})"),
            Self::Cancelled => f.write_str("certificate permission check cancelled"),
            Self::Timeout => f.write_str("certificate permission check timed out"),
            Self::Endpoint => f.write_str("invalid certificate permission endpoint"),
            Self::Transport => f.write_str("certificate permission endpoint unavailable"),
            Self::Capacity => f.write_str("certificate permission capacity unavailable"),
        }
    }
}
impl std::error::Error for PermissionFailure {}

struct CachedClient {
    identity: [u8; 32],
    client: reqwest::Client,
}

pub(super) struct HttpPermission {
    endpoint: String,
    resources: Arc<AutomationResources>,
    client: Arc<Mutex<Option<CachedClient>>>,
}
impl HttpPermission {
    pub(super) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub(super) fn new(endpoint: String, resources: Arc<AutomationResources>) -> Result<Self> {
        ensure!(
            endpoint.len() <= 1024 * 1024,
            "permission endpoint limit exceeded"
        );
        Ok(Self {
            endpoint,
            resources,
            client: Arc::new(Mutex::new(None)),
        })
    }
    /// Deprecated `ask` is replaced at provisioning; the permission module's
    /// endpoint is replaced for each check, matching their distinct Go paths.
    pub(super) async fn expand_legacy(
        endpoint: String,
        resources: Arc<AutomationResources>,
        cancel: CancellationToken,
    ) -> Result<String> {
        cert_cpu::run(resources.cpu_slots(), cancel, move || {
            strict_replace(&endpoint)
        })
        .await
        .map_err(|_| PermissionFailure::Endpoint.into())
    }
    pub(super) async fn check(&self, name: String, cancel: CancellationToken) -> Result<()> {
        ensure!(
            !name.is_empty() && name.len() <= 1024,
            "invalid permission name"
        );
        let operation_cancel = cancel.child_token();
        let operation = self.check_inner(name, operation_cancel.clone());
        tokio::pin!(operation);
        tokio::select! { biased;
            _ = cancel.cancelled() => {
                operation_cancel.cancel(); let _ = operation.await;
                Err(PermissionFailure::Cancelled.into())
            },
            _ = tokio::time::sleep(TIMEOUT) => {
                operation_cancel.cancel(); let _ = operation.await;
                Err(PermissionFailure::Timeout.into())
            },
            result = &mut operation => result,
        }
    }
    async fn check_inner(&self, name: String, cancel: CancellationToken) -> Result<()> {
        let endpoint = self.endpoint.clone();
        let cache = self.client.clone();
        let target = cert_cpu::run(self.resources.cpu_slots(), cancel.clone(), move || {
            target::Target::parse(&strict_replace(&endpoint)?, &name)
        })
        .await?;
        let _network = self
            .resources
            .admit_permission(target.origin.origin().ascii_serialization(), &cancel)
            .await
            .map_err(|_| PermissionFailure::Capacity)?;
        // Root-store I/O and TLS construction are admitted only after the
        // per-permission-origin permit. A slow endpoint cannot consume the
        // independent CA network budget while merely waiting.
        let origin = target.origin.clone();
        let client = cert_cpu::run(self.resources.cpu_slots(), cancel.clone(), move || {
            permission_client(&cache, &origin)
        })
        .await?;
        let mut request = client
            .get(target.origin)
            .header(http::header::USER_AGENT, "Go-http-client/1.1")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .header(http::header::HOST, target.host)
            .build()
            .map_err(|_| PermissionFailure::Endpoint)?;
        if let Some(auth) = target.auth {
            request
                .headers_mut()
                .insert(http::header::AUTHORIZATION, auth);
        }
        let response = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(PermissionFailure::Cancelled.into()),
            response = client.execute_with_raw_target(request, target.target) =>
                response.map_err(|_| PermissionFailure::Transport)?,
        };
        let status = response.status().as_u16();
        let would_redirect = matches!(status, 301 | 302 | 303 | 307 | 308)
            && response
                .headers()
                .get(http::header::LOCATION)
                .is_some_and(|value| !value.is_empty());
        // Go closes the body immediately; do not consume an unbounded or slow body.
        drop(response);
        if (200..300).contains(&status) {
            Ok(())
        } else if would_redirect {
            Err(PermissionFailure::Transport.into())
        } else {
            Err(PermissionFailure::Denied(status).into())
        }
    }
}

fn strict_replace(input: &str) -> Result<String> {
    let failed = Cell::new(false);
    let output = helpers::replace(input, true, |name| {
        if failed.get() {
            return None;
        }
        let value = helpers::global_lookup(name)
            .or_else(|| helpers::prepare_file_lookup(name).and_then(|value| value.ok()));
        if value.as_ref().is_none_or(String::is_empty) {
            failed.set(true);
        }
        value
    })
    .map_err(|_| PermissionFailure::Endpoint)?;
    ensure!(!failed.get(), PermissionFailure::Endpoint);
    Ok(output)
}
fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var(name.to_ascii_lowercase())
                .ok()
                .filter(|s| !s.is_empty())
        })
}
fn permission_client(cache: &Mutex<Option<CachedClient>>, url: &Url) -> Result<reqwest::Client> {
    // Reload the system root inventory before consulting the cached client:
    // commit-time local trust installation must become visible to later checks.
    let mut roots = rustls_native_certs::load_native_certs().certs;
    roots.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let proxy = proxy::selected(url)?;
    let mut hash = Sha256::new();
    hash.update((roots.len() as u64).to_be_bytes());
    for cert in &roots {
        hash.update((cert.len() as u64).to_be_bytes());
        hash.update(cert.as_ref());
    }
    match &proxy {
        Some(proxy) => {
            hash.update([1]);
            hash.update(proxy.as_str().as_bytes());
        }
        None => hash.update([0]),
    }
    let identity: [u8; 32] = hash.finalize().into();
    if let Some(previous) = &*cache
        .lock()
        .map_err(|_| anyhow!(PermissionFailure::Capacity))?
        && previous.identity == identity
    {
        return Ok(previous.client.clone());
    }
    let mut trust = rustls::RootCertStore::empty();
    let _ = trust.add_parsable_certificates(roots);
    let mut tls = rustls::ClientConfig::builder_with_provider(crate::crypto::provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| PermissionFailure::Transport)?
        .with_root_certificates(trust)
        .with_no_client_auth();
    // Reqwest does not set ALPN on a preconfigured Rustls ClientConfig.
    // Go's default HTTP transport negotiates h2 and has no TLS session cache.
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls.resumption = rustls::client::Resumption::disabled();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .use_preconfigured_tls(tls)
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy) = proxy {
        builder =
            builder.proxy(reqwest::Proxy::all(proxy).map_err(|_| PermissionFailure::Transport)?);
    }
    let client = builder.build().map_err(|_| PermissionFailure::Transport)?;
    *cache
        .lock()
        .map_err(|_| anyhow!(PermissionFailure::Capacity))? = Some(CachedClient {
        identity,
        client: client.clone(),
    });
    Ok(client)
}

/// Reuse the permission transport's Go-compatible authority/path parser without
/// adding its domain argument or normalizing encoded dot/slash path segments.
pub(super) fn external_request(input: &str, replacements: &[(&str,&str)])
    -> Result<(reqwest::Request,http::uri::PathAndQuery)> {
    let target = target::Target::parse(input, "")?;
    let original_query = input.split('#').next().unwrap_or(input)
        .split_once('?').map_or("", |(_,query)| query);
    let query = query::query_with_values(original_query, replacements);
    let raw = format!("{}?{}",target.target.path(),query);
    let mut request = reqwest::Request::new(http::Method::GET, target.origin);
    request.headers_mut().insert(http::header::HOST,target.host);
    if let Some(auth)=target.auth { request.headers_mut().insert(http::header::AUTHORIZATION,auth); }
    let raw=http::uri::PathAndQuery::from_bounded_origin_form(bytes::Bytes::from(raw))?;
    Ok((request,raw))
}

/// Keep the external HTTP manager on the same Go-compatible environment proxy
/// rules as ask, including NO_PROXY and the CGI HTTP_PROXY protection.
pub(super) fn external_proxy(url: &Url) -> Result<Option<Url>> { proxy::selected(url) }
