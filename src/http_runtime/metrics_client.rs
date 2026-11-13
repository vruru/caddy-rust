//! Metrics reuse the runtime resolver and native TLS roots. Only the metrics
//! transport owns cancellation; no business connector or socket is modified.
use crate::metrics::Metadata;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::{
    client::legacy::connect::{Connected, Connection},
    rt::TokioIo,
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tower_service::Service;
trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncIo for T {}
type Error = Box<dyn std::error::Error + Send + Sync>;
#[derive(Clone)]
pub(crate) struct Connector {
    inner: super::upstream_tls::FixedDialConnector,
    cancel: CancellationToken,
    tunnel: Option<Arc<str>>,
    target_tls: Option<Arc<rustls::ClientConfig>>,
    server_name: Option<rustls::pki_types::ServerName<'static>>,
    auth: Option<http::HeaderValue>,
    proxied: bool,
    credit: Arc<Metadata>,
}
pub(crate) struct Io {
    inner: TokioIo<Box<dyn AsyncIo>>,
    cancel: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    h2: bool,
    proxied: bool,
    _credit: Arc<Metadata>,
}
fn bypass(uri: &http::Uri) -> bool {
    let host = uri
        .host()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback())
    {
        return true;
    }
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let no = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    no.split(',').map(str::trim).any(|entry| {
        let Some((domain, entry_port)) = entry.rsplit_once(':') else {
            return false;
        };
        if entry_port.parse::<u16>().ok() != Some(port) {
            return false;
        }
        let domain = domain.trim_matches(['[', ']']).to_ascii_lowercase();
        if domain.starts_with('.') {
            host.ends_with(&domain)
        } else {
            host == domain || host.ends_with(&format!(".{domain}"))
        }
    })
}
fn tls(
    ca: Option<&[u8]>,
    identity: Option<(&[u8], &[u8])>,
    h2_only: bool,
) -> anyhow::Result<rustls::ClientConfig> {
    let roots = if let Some(ca) = ca {
        let mut roots = rustls::RootCertStore::empty();
        let mut valid = 0;
        for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(ca)) {
            if let Ok(cert) = cert
                && crate::cert_uri_san::add_root(&mut roots, cert)?
            {
                valid += 1;
            }
        }
        anyhow::ensure!(valid > 0, "OTLP trust roots unavailable");
        roots
    } else {
        super::upstream_tls::native_roots()?.clone()
    };
    let builder = rustls::ClientConfig::builder_with_provider(crate::crypto::client_provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let mut config = if let Some((cert, key)) = identity {
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(cert))
            .collect::<std::io::Result<Vec<_>>>()?;
        crate::cert_uri_san::check_chain(&certs)?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))?
            .ok_or_else(|| anyhow::anyhow!("OTLP client key missing"))?;
        builder.with_client_auth_cert(certs, key)?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = if h2_only {
        vec![b"h2".to_vec()]
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    Ok(crate::cert_uri_san::guarded_config(config)?)
}
impl Connector {
    pub(crate) fn with_cancel(&self, cancel: CancellationToken) -> Self {
        let mut result = self.clone();
        result.cancel = cancel;
        result
    }
    pub(crate) fn proxy_authorization(&self) -> Option<http::HeaderValue> {
        if self.proxied {
            self.auth.clone()
        } else {
            None
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        uri: http::Uri,
        ca: Option<&[u8]>,
        identity: Option<(&[u8], &[u8])>,
        timeout: Duration,
        cancel: CancellationToken,
        credit: Arc<Metadata>,
        h2_only: bool,
    ) -> anyhow::Result<Self> {
        let proxy = if bypass(&uri) {
            None
        } else {
            hyper_util::client::proxy::matcher::Matcher::from_env().intercept(&uri)
        };
        let target_tls = if uri.scheme_str() == Some("https") {
            Some(Arc::new(tls(ca, identity, h2_only)?))
        } else {
            None
        };
        let mut dial = uri.clone();
        let mut tunnel = None;
        let mut auth = None;
        let mut proxied = false;
        let mut server_name = None;
        let mut dial_tls = target_tls.clone();
        let mut tunnel_tls = None;
        if let Some(proxy) = proxy {
            dial = proxy.uri().clone();
            anyhow::ensure!(
                matches!(dial.scheme_str(), Some("http" | "https")),
                "unsupported OTLP proxy scheme"
            );
            auth = proxy.basic_auth().cloned();
            dial_tls = if dial.scheme_str() == Some("https") {
                let mut cfg = tls(ca, identity, false)?;
                cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
                Some(Arc::new(cfg))
            } else {
                None
            };
            if target_tls.is_some() || h2_only {
                let host = uri
                    .host()
                    .ok_or_else(|| anyhow::anyhow!("OTLP endpoint host missing"))?;
                let authority = format!(
                    "{host}:{}",
                    uri.port_u16()
                        .unwrap_or(if target_tls.is_some() { 443 } else { 80 })
                );
                tunnel = Some(Arc::from(authority));
                tunnel_tls = target_tls;
                server_name = Some(rustls::pki_types::ServerName::try_from(
                    host.trim_matches(['[', ']']).to_owned(),
                )?);
            } else {
                proxied = true;
            }
        }
        Ok(Self {
            inner: super::upstream_tls::PreparedTransport::metrics(dial, dial_tls, timeout),
            cancel,
            credit,
            tunnel,
            target_tls: tunnel_tls,
            server_name,
            auth,
            proxied,
        })
    }
}
impl Service<http::Uri> for Connector {
    type Response = Io;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Io, Error>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let future = self.inner.call(uri);
        let owner = self.clone();
        Box::pin(async move {
            let operation = async {
                let inner = future.await?;
                let mut h2 = inner.connected().is_negotiated_h2();
                let mut stream: Box<dyn AsyncIo> = Box::new(TokioIo::new(inner));
                if let Some(authority) = owner.tunnel.as_deref() {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request =
                        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
                    if let Some(auth) = &owner.auth {
                        request.push_str("Proxy-Authorization: ");
                        request.push_str(auth.to_str()?);
                        request.push_str("\r\n");
                    }
                    request.push_str("\r\n");
                    stream.write_all(request.as_bytes()).await?;
                    stream.flush().await?;
                    let mut headers = Vec::with_capacity(1024);
                    while !headers.ends_with(b"\r\n\r\n") {
                        if headers.len() >= 32768 {
                            return Err(
                                std::io::Error::other("OTLP proxy headers exceed limit").into()
                            );
                        }
                        let byte = stream.read_u8().await?;
                        headers.push(byte);
                    }
                    let text = std::str::from_utf8(&headers)?;
                    let status = text
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1));
                    if status != Some("200") {
                        return Err(std::io::Error::other("OTLP proxy CONNECT rejected").into());
                    }
                    h2 = false;
                    if let Some(config) = owner.target_tls.clone() {
                        let tls = tokio_rustls::TlsConnector::from(config)
                            .connect(
                                owner
                                    .server_name
                                    .clone()
                                    .expect("prepared tunnel server name"),
                                stream,
                            )
                            .await?;
                        h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                        stream = Box::new(tls);
                    }
                }
                Ok::<_, Error>(Io {
                    inner: TokioIo::new(stream),
                    cancel: Box::pin(owner.cancel.clone().cancelled_owned()),
                    h2,
                    proxied: owner.proxied,
                    _credit: owner.credit,
                })
            };
            tokio::select! {biased;_=owner.cancel.cancelled()=>Err(std::io::Error::other("metrics transport stopped").into()),result=operation=>result}
        })
    }
}
impl Io {
    fn stopped(&mut self, cx: &mut Context<'_>) -> bool {
        self.cancel.as_mut().poll(cx).is_ready()
    }
}
impl Connection for Io {
    fn connected(&self) -> Connected {
        let value = Connected::new().proxy(self.proxied);
        if self.h2 {
            value.negotiated_h2()
        } else {
            value
        }
    }
}
impl Read for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.stopped(cx) {
            return Poll::Ready(Err(std::io::Error::other("metrics transport stopped")));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl Write for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.stopped(cx) {
            return Poll::Ready(Err(std::io::Error::other("metrics transport stopped")));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.stopped(cx) {
            return Poll::Ready(Err(std::io::Error::other("metrics transport stopped")));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
