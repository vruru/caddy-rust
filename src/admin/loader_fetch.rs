//! Bounded HTTP acquisition; client and TLS material are rebuilt every poll.
use super::super::{
    AdminError,
    loader_schema::{HttpLoader, LoaderTls},
};
use futures_util::StreamExt;
use rustls::{ClientConfig, RootCertStore, sign::CertifiedKey};
use std::{io::Read, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
const LIMIT: usize = 16 * 1024 * 1024;
fn error(category: &'static str) -> AdminError {
    AdminError::new(502, category)
}
fn read_file(path: &str) -> Result<Vec<u8>, AdminError> {
    use std::os::unix::fs::OpenOptionsExt;
    // Follow rotating secret symlinks, but never block opening a FIFO/device.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| error("config_loader_tls_file_failed"))?;
    if !f
        .metadata()
        .map_err(|_| error("config_loader_tls_file_failed"))?
        .is_file()
    {
        return Err(error("config_loader_tls_requires_regular_file"));
    }
    let mut b = Vec::new();
    f.take((LIMIT + 1) as u64)
        .read_to_end(&mut b)
        .map_err(|_| error("config_loader_tls_file_failed"))?;
    if b.len() > LIMIT {
        return Err(error("config_loader_tls_file_limit"));
    }
    Ok(b)
}
struct Identity(Arc<CertifiedKey>);
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigLoaderClientIdentity")
    }
}
impl rustls::client::ResolvesClientCert for Identity {
    fn resolve(
        &self,
        _: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.0.key.choose_scheme(schemes).map(|_| self.0.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}
fn tls(
    tls: Option<&LoaderTls>,
    identity: Option<Arc<dyn rustls::client::ResolvesClientCert>>,
) -> Result<ClientConfig, AdminError> {
    let provider = crate::crypto::provider();
    let mut roots = RootCertStore::empty();
    if let Some(tls) = tls.filter(|t| !t.root_ca_pem_files.is_empty()) {
        for path in &tls.root_ca_pem_files {
            let bytes = read_file(path)?;
            // Go AppendCertsFromPEM keeps valid entries and skips bad ones.
            for cert in rustls_pemfile::certs(&mut bytes.as_slice()).flatten() {
                let _ = roots.add(cert);
            }
        }
    } else {
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
    }
    if roots.is_empty() {
        return Err(error("config_loader_empty_root_store"));
    }
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| error("config_loader_tls_configuration_failed"))?
        .with_root_certificates(roots);
    if tls.is_some_and(|t| t.use_server_identity) {
        return Ok(builder.with_client_cert_resolver(
            identity.ok_or_else(|| error("config_loader_identity_unavailable"))?,
        ));
    }
    if let Some(t) = tls.filter(|t| {
        !t.client_certificate_file.is_empty() && !t.client_certificate_key_file.is_empty()
    }) {
        let certs = read_file(&t.client_certificate_file)?;
        let key = zeroize::Zeroizing::new(read_file(&t.client_certificate_key_file)?);
        let chain = rustls_pemfile::certs(&mut certs.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| error("config_loader_invalid_client_certificate"))?;
        let key = rustls_pemfile::private_key(&mut key.as_slice())
            .map_err(|_| error("config_loader_invalid_client_key"))?
            .ok_or_else(|| error("config_loader_invalid_client_key"))?;
        let certified = CertifiedKey::from_der(chain, key, &provider)
            .map_err(|_| error("config_loader_client_key_mismatch"))?;
        return Ok(builder.with_client_cert_resolver(Arc::new(Identity(Arc::new(certified)))));
    }
    Ok(builder.with_no_client_auth())
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
fn client(
    config: ClientConfig,
    custom_tls: bool,
    timeout: Duration,
) -> Result<reqwest::Client, AdminError> {
    let cgi = !custom_tls
        && std::env::var("REQUEST_METHOD").is_ok_and(|v| !v.is_empty())
        && env("HTTP_PROXY").is_some();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http1_only()
        .use_preconfigured_tls(config)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if cgi && attempt.url().scheme() == "http" {
                return attempt.error("config_loader_cgi_proxy_refused");
            }
            if attempt.previous().len() >= 10 {
                return attempt.error("config_loader_redirect_limit");
            }
            if attempt.url().scheme() == "http"
                && attempt
                    .previous()
                    .last()
                    .is_some_and(|u| u.scheme() == "https")
            {
                return attempt.error("config_loader_insecure_redirect");
            }
            attempt.follow()
        }));
    if !custom_tls {
        let bypass = format!(
            "localhost,127.0.0.0/8,::1,{}",
            env("NO_PROXY").unwrap_or_default()
        );
        let no_proxy = reqwest::NoProxy::from_string(&bypass);
        if let Some(proxy) = env("HTTPS_PROXY") {
            builder = builder.proxy(
                reqwest::Proxy::https(proxy)
                    .map_err(|_| error("config_loader_invalid_proxy"))?
                    .no_proxy(no_proxy.clone()),
            );
        }
        // Go's CGI guard disallows using HTTP_PROXY; do not inherit ALL_PROXY.
        if !std::env::var("REQUEST_METHOD").is_ok_and(|v| !v.is_empty())
            && let Some(proxy) = env("HTTP_PROXY")
        {
            builder = builder.proxy(
                reqwest::Proxy::http(proxy)
                    .map_err(|_| error("config_loader_invalid_proxy"))?
                    .no_proxy(no_proxy),
            );
        }
    }
    builder
        .build()
        .map_err(|_| error("config_loader_client_configuration_failed"))
}
pub(super) async fn fetch(
    loader: HttpLoader,
    identity: Option<Arc<dyn rustls::client::ResolvesClientCert>>,
    cancel: CancellationToken,
    cpu: Arc<tokio::sync::Semaphore>,
) -> Result<(Vec<u8>, Option<String>), AdminError> {
    let method = if loader.method.is_empty() {
        http::Method::GET
    } else {
        http::Method::from_bytes(loader.method.as_bytes())
            .map_err(|_| error("config_loader_invalid_method"))?
    };
    let url = url::Url::parse(&loader.url).map_err(|_| error("config_loader_invalid_url"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(error("config_loader_invalid_url"));
    }
    if loader.tls.is_none()
        && std::env::var("REQUEST_METHOD").is_ok_and(|v| !v.is_empty())
        && env("HTTP_PROXY").is_some()
        && url.scheme() == "http"
    {
        return Err(error("config_loader_cgi_proxy_refused"));
    }
    let mut headers = http::HeaderMap::new();
    for (name, values) in &loader.header {
        let name = http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| error("config_loader_invalid_header"))?;
        for value in values {
            headers.append(
                name.clone(),
                http::HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|_| error("config_loader_invalid_header"))?,
            );
        }
    }
    // net/http Request.Host is separate: Header["Host"] is not transmitted.
    for name in [
        http::header::HOST,
        http::header::CONTENT_LENGTH,
        http::header::TRANSFER_ENCODING,
        http::header::TRAILER,
    ] {
        headers.remove(name);
    }
    let auto_gzip = !headers.contains_key(http::header::ACCEPT_ENCODING)
        && !headers.contains_key(http::header::RANGE)
        && method != http::Method::HEAD;
    if auto_gzip {
        headers.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
    }
    let timeout = loader.parsed_timeout;
    let inspect_content_type = loader.adapter.is_empty();
    let permit = tokio::select! {_=cancel.cancelled()=>return Err(error("config_loader_cancelled")),p=cpu.clone().acquire_owned()=>p.map_err(|_|error("config_loader_capacity_closed"))?};
    let custom_tls = loader.tls.is_some();
    let build = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        client(tls(loader.tls.as_ref(), identity)?, custom_tls, timeout)
    });
    let client = tokio::select! {_=cancel.cancelled()=>return Err(error("config_loader_cancelled")),built=build=>built.map_err(|_|error("config_loader_tls_configuration_failed"))??};
    for attempt in 0..10 {
        let deadline = tokio::time::Instant::now() + timeout;
        let response = tokio::select! {_=cancel.cancelled()=>return Err(error("config_loader_cancelled")),r=client.request(method.clone(),url.clone()).headers(headers.clone()).send()=>r};
        match response {
            Ok(response) if (200..500).contains(&response.status().as_u16()) => {
                if response.status().as_u16() >= 400 {
                    return Err(error("config_loader_upstream_status"));
                }
                return tokio::select! {_=cancel.cancelled()=>Err(error("config_loader_cancelled")),body=tokio::time::timeout_at(deadline,body(response,auto_gzip,inspect_content_type,cancel.clone(),cpu.clone()))=>body.map_err(|_|error("config_loader_body_timeout"))?};
            }
            _ if attempt == 9 => return Err(error("config_loader_fetch_failed")),
            _ => {
                tokio::select! {_=cancel.cancelled()=>return Err(error("config_loader_cancelled")),_=tokio::time::sleep(Duration::from_millis(500))=>{}}
            }
        }
    }
    Err(error("config_loader_fetch_failed"))
}
async fn body(
    response: reqwest::Response,
    auto_gzip: bool,
    inspect_content_type: bool,
    cancel: CancellationToken,
    cpu: Arc<tokio::sync::Semaphore>,
) -> Result<(Vec<u8>, Option<String>), AdminError> {
    // Explicit adapter replaces Content-Type before MIME processing in Go.
    // Never reject an otherwise unused upstream field in that branch.
    let content = if inspect_content_type {
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|h| {
                std::str::from_utf8(h.as_bytes())
                    .map(str::to_owned)
                    .map_err(|_| error("config_loader_invalid_content_type"))
            })
            .transpose()?
    } else {
        None
    };
    let gzip = auto_gzip
        && response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_some_and(|h| h.as_bytes().eq_ignore_ascii_case(b"gzip"));
    if response.content_length().is_some_and(|n| n > LIMIT as u64) {
        return Err(error("config_loader_body_limit"));
    }
    let mut stream = response.bytes_stream();
    let mut received = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| error("config_loader_body_failed"))?;
        if chunk.len() > LIMIT.saturating_sub(received.len()) {
            return Err(error("config_loader_body_limit"));
        }
        received.extend_from_slice(&chunk);
    }
    if !gzip {
        return Ok((received, content));
    }
    let permit = tokio::select! {_=cancel.cancelled()=>return Err(error("config_loader_cancelled")),p=cpu.acquire_owned()=>p.map_err(|_|error("config_loader_capacity_closed"))?};
    let runtime = tokio::runtime::Handle::current();
    let decoded = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // This future reads only in-memory bytes; no network or reactor I/O is
        // performed by Handle::block_on on this dedicated blocking worker.
        runtime.block_on(async move {
            let mut decoder =
                async_compression::tokio::bufread::GzipDecoder::new(received.as_slice());
            decoder.multiple_members(true);
            let mut decoded = Vec::new();
            decoder
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut decoded)
                .await
                .map_err(|_| error("config_loader_body_failed"))?;
            if decoded.len() > LIMIT {
                return Err(error("config_loader_body_limit"));
            }
            Ok(decoded)
        })
    });
    let bytes = tokio::select! {_=cancel.cancelled()=>return Err(error("config_loader_cancelled")),result=decoded=>result.map_err(|_|error("config_loader_body_failed"))??};
    Ok((bytes, content))
}
