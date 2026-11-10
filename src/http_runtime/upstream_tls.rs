use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_rustls::MaybeHttpsStream;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use super::timeout_io::TimeoutIo;

use crate::http_config::types::{ProxyConfig, ProxyTls};
use anyhow::{Result, ensure};
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io::Read as _;
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
static NATIVE_ROOTS: OnceLock<rustls::RootCertStore> = OnceLock::new();
static NATIVE_LOADS: AtomicU64 = AtomicU64::new(0);
static NATIVE_ERRORS: AtomicU64 = AtomicU64::new(0);
static REJECTED_ROOTS: AtomicU64 = AtomicU64::new(0);
/// Aggregate diagnostics contain counts only, never filenames, names or material.
#[derive(Debug, Clone, Copy)]
pub struct NativeTrustDiagnostics {
    pub native_loads: u64,
    pub native_load_errors: u64,
    pub rejected_root_blocks: u64,
}
pub(super) fn diagnostics() -> NativeTrustDiagnostics {
    NativeTrustDiagnostics {
        native_loads: NATIVE_LOADS.load(Ordering::Relaxed),
        native_load_errors: NATIVE_ERRORS.load(Ordering::Relaxed),
        rejected_root_blocks: REJECTED_ROOTS.load(Ordering::Relaxed),
    }
}
fn native_roots() -> &'static rustls::RootCertStore {
    NATIVE_ROOTS.get_or_init(|| {
        NATIVE_LOADS.fetch_add(1, Ordering::Relaxed);
        let native = rustls_native_certs::load_native_certs();
        NATIVE_ERRORS.fetch_add(native.errors.len() as u64, Ordering::Relaxed);
        let mut roots = rustls::RootCertStore::empty();
        let (_, ignored) = roots.add_parsable_certificates(native.certs);
        REJECTED_ROOTS.fetch_add(ignored as u64, Ordering::Relaxed);
        roots
    })
}

/// Prepared off the reactor before a candidate generation is published.
#[derive(Clone)]
pub(super) struct PreparedTransport {
    http: HttpConnector,
    tls: Option<Arc<ClientConfig>>,
    read: Option<Duration>,
    write: Option<Duration>,
    handshake: Option<Duration>,
}
impl PreparedTransport {
    pub(super) fn prepare(config: &ProxyConfig) -> Result<Self> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(config.dial_timeout));
        http.set_nodelay(true);
        let tls = config
            .tls
            .as_ref()
            .map(|t| provision(t, config.enable_http2))
            .transpose()?
            .map(Arc::new);
        Ok(Self {
            http,
            tls,
            read: config.read_timeout,
            write: config.write_timeout,
            handshake: config.tls.as_ref().and_then(|t| t.handshake_timeout),
        })
    }
    pub(super) fn http1(&self) -> Self {
        let mut result = self.clone();
        if let Some(tls) = &result.tls {
            let mut tls = (**tls).clone();
            // Go persistConn.addTLS and Caddy's dynamic DialTLS both clear
            // NextProtos for an HTTP/1-only upgraded request. Advertising h1
            // instead breaks servers configured with an h2-only ALPN list.
            tls.alpn_protocols.clear();
            result.tls = Some(Arc::new(tls));
        }
        result
    }
    pub(super) fn connector(
        &self,
        dial: Uri,
        server_name: Option<ServerName<'static>>,
    ) -> FixedDialConnector {
        FixedDialConnector {
            http: self.http.clone(),
            tls: self.tls.clone(),
            read: self.read,
            write: self.write,
            handshake: self.handshake,
            dial,
            server_name,
        }
    }
}
fn read_material(path: &str, budget: &mut u64) -> Result<Vec<u8>> {
    let file = crate::http_config::helpers::open_regular_file(path)
        .map_err(|_| anyhow::anyhow!("upstream TLS material cannot be opened"))?;
    let mut bytes = Vec::new();
    file.take(*budget + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("upstream TLS material cannot be read"))?;
    ensure!(
        bytes.len() as u64 <= *budget,
        "upstream TLS material size limit exceeded"
    );
    *budget -= bytes.len() as u64;
    Ok(bytes)
}
fn certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(bytes))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| anyhow::anyhow!("invalid upstream TLS certificate PEM"))?;
    ensure!(
        !certs.is_empty(),
        "upstream TLS PEM contains no certificates"
    );
    Ok(certs)
}
fn provision(tls: &ProxyTls, enable_http2: bool) -> Result<ClientConfig> {
    if let Some(name) = tls
        .server_name
        .as_ref()
        .filter(|n| !n.is_empty() && !n.contains('{'))
    {
        ServerName::try_from(name.as_str())
            .map_err(|_| anyhow::anyhow!("invalid configured upstream TLS server name"))?;
    }
    ensure!(
        tls.client_certificate_file.is_some() == tls.client_certificate_key_file.is_some(),
        "client_certificate_file and client_certificate_key_file must be set together"
    );
    let mut budget = 64 * 1024 * 1024;
    let mut roots = rustls::RootCertStore::empty();
    if tls.root_ca_pool.is_empty() && tls.root_ca_pem_files.is_empty() {
        roots = native_roots().clone();
    } else {
        for encoded in &tls.root_ca_pool {
            // Go StdEncoding ignores CR/LF and does not require zero pad bits.
            let encoded = encoded
                .bytes()
                .filter(|b| !matches!(b, b'\r' | b'\n'))
                .collect::<Vec<_>>();
            let decoder = base64::engine::general_purpose::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::general_purpose::GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true),
            );
            let bytes = decoder
                .decode(encoded)
                .map_err(|_| anyhow::anyhow!("invalid upstream root CA encoding"))?;
            ensure!(
                bytes.len() as u64 <= budget,
                "upstream TLS material size limit exceeded"
            );
            budget -= bytes.len() as u64;
            roots
                .add(CertificateDer::from(bytes))
                .map_err(|_| anyhow::anyhow!("invalid upstream root CA certificate"))?;
        }
        for path in &tls.root_ca_pem_files {
            let bytes = read_material(path, &mut budget)?;
            // Go AppendCertsFromPEM skips unusable blocks but retains valid
            // anchors, including valid blocks after a malformed base64 block.
            for result in rustls_pemfile::certs(&mut std::io::Cursor::new(bytes)) {
                let valid = result
                    .ok()
                    .is_some_and(|certificate| roots.add(certificate).is_ok());
                if !valid {
                    REJECTED_ROOTS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    ensure!(
        tls.insecure_skip_verify || !roots.is_empty(),
        "upstream trust roots unavailable"
    );
    let provider = crate::crypto::provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let mut config = if let (Some(cert), Some(key)) = (
        &tls.client_certificate_file,
        &tls.client_certificate_key_file,
    ) {
        let certificates = certificates(&read_material(cert, &mut budget)?)?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(read_material(
            key,
            &mut budget,
        )?))
        .map_err(|_| anyhow::anyhow!("invalid upstream client private key PEM"))?
        .ok_or_else(|| anyhow::anyhow!("upstream client private key missing or encrypted"))?;
        builder
            .with_client_auth_cert(certificates, key)
            .map_err(|_| anyhow::anyhow!("invalid upstream client certificate/key pair"))?
    } else {
        builder.with_no_client_auth()
    };
    if tls.insecure_skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureVerifier { provider }));
    }
    // Go HTTPTransport leaves ClientSessionCache nil, so it does not resume.
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = if enable_http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        Vec::new()
    };
    Ok(config)
}
#[derive(Debug)]
struct InsecureVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}
impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(super) type TcpIo = TokioIo<TcpStream>;
pub(super) type Output = MaybeHttpsStream<TimeoutIo<TcpIo>>;

#[derive(Clone)]
pub(super) struct FixedDialConnector {
    pub(super) http: HttpConnector,
    pub(super) tls: Option<Arc<ClientConfig>>,
    pub(super) read: Option<Duration>,
    pub(super) write: Option<Duration>,
    pub(super) handshake: Option<Duration>,
    pub(super) dial: Uri,
    pub(super) server_name: Option<ServerName<'static>>,
}

impl Service<Uri> for FixedDialConnector {
    type Response = Output;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http
            .poll_ready(cx)
            .map_err(|e| Box::new(e) as Self::Error)
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let tls = self.tls.clone();
        let read = self.read;
        let write = self.write;
        let handshake = self.handshake;
        let dial = self.dial.clone();
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let tcp = http
                .call(dial.clone())
                .await
                .map_err(|e| Box::new(e) as Self::Error)?;

            let io = TimeoutIo::new(tcp, read, write);

            match tls {
                None => Ok(MaybeHttpsStream::Http(io)),
                Some(cfg) => {
                    let server_name = match server_name {
                        Some(s) => s,
                        None => {
                            let host = dial.host().ok_or("missing host in dial uri")?;
                            let host_str = host;
                            // Strip IPv6 brackets if present
                            let clean_host = host_str
                                .strip_prefix('[')
                                .and_then(|s| s.strip_suffix(']'))
                                .unwrap_or(host_str);
                            ServerName::try_from(clean_host.to_owned())
                                .map_err(|e| Box::new(e) as Self::Error)?
                        }
                    };

                    let tls_connector = TlsConnector::from(cfg);
                    let tokio_io = TokioIo::new(io);
                    let connect_future = tls_connector.connect(server_name, tokio_io);

                    let stream = match handshake {
                        Some(d) if !d.is_zero() => match timeout(d, connect_future).await {
                            Ok(result) => result.map_err(|e| Box::new(e) as Self::Error)?,
                            Err(_) => {
                                return Err(Box::new(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "TLS handshake timeout",
                                )) as Self::Error);
                            }
                        },
                        _ => connect_future
                            .await
                            .map_err(|e| Box::new(e) as Self::Error)?,
                    };

                    Ok(MaybeHttpsStream::Https(TokioIo::new(stream)))
                }
            }
        })
    }
}
