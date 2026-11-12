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
pub(super) fn native_roots() -> &'static rustls::RootCertStore {
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
    http: [HttpConnector<super::http_dial::FamilyResolver>; 3],
    tls: Option<Arc<ClientConfig>>,
    read: Option<Duration>,
    write: Option<Duration>,
    handshake: Option<Duration>,
    connect_timeout: Duration,
}
impl PreparedTransport {
    pub(super) fn prepare(config: &ProxyConfig) -> Result<Self> {
        let http = [
            super::http_dial::Family::Any,
            super::http_dial::Family::V4,
            super::http_dial::Family::V6,
        ]
        .map(|family| {
            let mut http =
                HttpConnector::new_with_resolver(super::http_dial::FamilyResolver::new(family));
            http.enforce_http(false);
            http.set_connect_timeout(Some(config.dial_timeout));
            http.set_nodelay(true);
            http
        });
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
            connect_timeout:config.dial_timeout,
        })
    }
    pub(super) fn metrics(dial:Uri,tls:Option<Arc<ClientConfig>>,timeout:Duration)->FixedDialConnector{
        let family=super::http_dial::Family::Any;
        let mut http=HttpConnector::new_with_resolver(super::http_dial::FamilyResolver::new(family));
        http.enforce_http(false);http.set_connect_timeout(Some(timeout));http.set_nodelay(true);
        FixedDialConnector{http,family,tls,read:Some(timeout),write:Some(timeout),handshake:Some(timeout),dial,server_name:None,unix_path:None,connect_timeout:timeout}
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
        family: super::http_dial::Family,
        server_name: Option<ServerName<'static>>,
        unix_path:Option<&str>,
    ) -> FixedDialConnector {
        FixedDialConnector {
            http: self.http[match family {
                super::http_dial::Family::Any => 0,
                super::http_dial::Family::V4 => 1,
                super::http_dial::Family::V6 => 2,
            }]
            .clone(),
            family,
            tls: if dial.scheme_str() == Some("https") {
                self.tls.clone()
            } else {
                None
            },
            read: self.read,
            write: self.write,
            handshake: self.handshake,
            dial,
            server_name,
            unix_path:unix_path.map(Arc::from),
            connect_timeout:self.connect_timeout,
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
/// CA provider modules share file/inline decoding with server client auth.
/// This runs only in transport provisioning, never from connector/handshake.
fn provider_roots(raw:&serde_json::Value,depth:usize,budget:&mut u64,count:&mut usize,roots:&mut rustls::RootCertStore)->Result<()>{
    use crate::http_config::helpers::{object,deny_unknown};
    ensure!(depth<8,"upstream CA provider nesting too deep");
    let obj=object(raw,"upstream CA provider")?;
    let mut add=|cert:CertificateDer<'static>|->Result<()>{
        *count=count.checked_add(1).ok_or(crate::cert_transient::ResourceDenied)?;
        ensure!(*count<=4096,"upstream CA certificate count exceeds bounds");
        roots.add(cert).map_err(|_|anyhow::anyhow!("invalid upstream root CA certificate"))?;Ok(())
    };
    match obj.get("provider").and_then(serde_json::Value::as_str){
        Some("inline")=>{
            deny_unknown(obj,&["provider","trusted_ca_certs"],"upstream inline CA pool")?;
            if let Some(value)=obj.get("trusted_ca_certs").filter(|v|!v.is_null()){
                let values=value.as_array().ok_or_else(||anyhow::anyhow!("upstream inline CA certificates must be an array"))?;
                ensure!(values.len()<=4096,"upstream inline CA count exceeds bounds");
                for value in values{
                    let value=value.as_str().ok_or_else(||anyhow::anyhow!("upstream inline CA certificate must be a string"))?;
                    let cert=crate::tls_policy::source_inline(value)?;
                    ensure!(cert.len()as u64<=*budget,"upstream TLS material size limit exceeded");*budget-=cert.len()as u64;add(cert)?;
                }
            }
        },
        Some("file")=>{
            deny_unknown(obj,&["provider","pem_files"],"upstream file CA pool")?;
            if let Some(value)=obj.get("pem_files").filter(|v|!v.is_null()){
                let files=value.as_array().ok_or_else(||anyhow::anyhow!("upstream CA files must be an array"))?;
                ensure!(files.len()<=256,"upstream CA file count exceeds bounds");
                for path in files{
                    let path=path.as_str().ok_or_else(||anyhow::anyhow!("upstream CA file must be a string"))?;
                    let bytes=read_material(path,budget)?;
                    for cert in crate::tls_policy::source_certificates(&bytes)?{add(cert)?;}
                }
            }
        },
        Some("system")=>{
            deny_unknown(obj,&["provider"],"upstream system CA pool")?;
            ensure!(depth==0,"system pool cannot export certificates to combined pool");
            *roots=native_roots().clone();
        },
        Some("combined")=>{
            deny_unknown(obj,&["provider","sources"],"upstream combined CA pool")?;
            let sources=obj.get("sources").and_then(serde_json::Value::as_array).ok_or_else(||anyhow::anyhow!("upstream combined CA sources required"))?;
            ensure!(!sources.is_empty()&&sources.len()<=256,"upstream combined CA source count exceeds bounds");
            for source in sources{provider_roots(source,depth+1,budget,count,roots)?;}
        },
        _=>anyhow::bail!("unsupported or unprepared upstream CA provider"),
    }
    Ok(())
}
fn provision(tls:&ProxyTls,enable_http2:bool)->Result<ClientConfig>{provision_inner(tls,enable_http2,false)}
fn provision_inner(tls: &ProxyTls, enable_http2: bool, allow_empty_default:bool) -> Result<ClientConfig> {
    ensure!(
        tls.client_certificate_file.is_some() == tls.client_certificate_key_file.is_some(),
        "client_certificate_file and client_certificate_key_file must be set together"
    );
    let mut budget = 64 * 1024 * 1024;
    let mut roots = rustls::RootCertStore::empty();
    if let Some(module)=&tls.ca {
        ensure!(tls.root_ca_pool.is_empty()&&tls.root_ca_pem_files.is_empty(),"conflicting upstream Root CA pool configuration");
        provider_roots(module,0,&mut budget,&mut 0,&mut roots)?;
    } else if tls.root_ca_pool.is_empty() && tls.root_ca_pem_files.is_empty() {
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
        allow_empty_default || tls.ca.is_some() || tls.insecure_skip_verify || !roots.is_empty(),
        "upstream trust roots unavailable"
    );
    let provider = if tls.curves.is_empty() {
        crate::crypto::provider()
    } else {
        let mut provider = (*crate::crypto::provider()).clone();
        let mut groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = Vec::new();
        for name in &tls.curves {
            let group = crate::tls_policy::key_exchange_group(name)?;
            if !groups.iter().any(|old|old.name() == group.name()) { groups.push(group); }
        }
        provider.kx_groups = groups;
        Arc::new(provider)
    };
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

pub(super) type Output = MaybeHttpsStream<TimeoutIo<super::http_dial_io::DialIo>>;

#[derive(Clone)]
pub(super) struct FixedDialConnector {
    pub(super) http: HttpConnector<super::http_dial::FamilyResolver>,
    family: super::http_dial::Family,
    pub(super) tls: Option<Arc<ClientConfig>>,
    pub(super) read: Option<Duration>,
    pub(super) write: Option<Duration>,
    pub(super) handshake: Option<Duration>,
    pub(super) dial: Uri,
    pub(super) server_name: Option<ServerName<'static>>,
    unix_path:Option<Arc<str>>,
    connect_timeout:Duration,
}

#[derive(Debug)]
pub(super) struct TcpDialError(Box<dyn std::error::Error + Send + Sync>);
impl std::fmt::Display for TcpDialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for TcpDialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
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
        let family = self.family;
        let server_name = self.server_name.clone();
        let unix_path=self.unix_path.clone();
        let connect_timeout=self.connect_timeout;
        Box::pin(async move {
            use super::http_dial_io::DialIo;
            let tcp=if let Some(path)=unix_path {
                #[cfg(unix)] {
                    let connect=super::http_dial::connect_unix(&path);
                    let stream=if connect_timeout.is_zero(){connect.await}else{tokio::time::timeout(connect_timeout,connect).await.map_err(|_|Box::new(TcpDialError(Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut,"Unix upstream dial timeout"))))as Self::Error)?}.map_err(|e|Box::new(TcpDialError(Box::new(e)))as Self::Error)?;
                    DialIo::Unix(TokioIo::new(stream))
                }
                #[cfg(not(unix))] {let _=path;return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Unsupported,"Unix upstreams require Unix sockets"))as Self::Error);}
            }else{
            let tcp_dial = family
                .literal_uri(&dial)
                .map_err(|e| Box::new(TcpDialError(Box::new(e))) as Self::Error)?;
            let tcp = http
                .call(tcp_dial)
                .await
                .map_err(|e| Box::new(TcpDialError(Box::new(e))) as Self::Error)?;
                DialIo::Tcp(tcp)
            };
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
                            let clean_host = super::http_dial::tls_host(host_str);
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

/// Real configuration-time HTTP CA-fetch trust uses the same prepared client
/// TLS policy as proxy traffic, with no client identity or per-port exception.
pub(crate) fn ca_source_client_tls(ca:Option<serde_json::Value>,insecure:bool)->Result<ClientConfig>{
    let options=ProxyTls{curves:Vec::new(),ca,except_ports:Vec::new(),server_name:None,insecure_skip_verify:insecure,root_ca_pem_files:Vec::new(),root_ca_pool:Vec::new(),client_certificate_file:None,client_certificate_key_file:None,handshake_timeout:None};
    provision_inner(&options,true,true)
}
