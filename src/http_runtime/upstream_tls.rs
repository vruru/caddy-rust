use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tower_service::Service;
#[path="upstream_tls/compatibility.rs"]
mod compatibility;
use compatibility::FirstAlertIo;
#[path="upstream_tls/retained.rs"]
mod retained;

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
    native: Option<Arc<native_ssl_tls::ClientConfig>>,
    fallback: Option<Arc<native_ssl_tls::ClientConfig>>,
    managed:Option<Arc<crate::tls_app_config::ManagedClientSource>>,
    client_executor:Option<Arc<super::tls_executor::TlsExecutor>>,
    http1_native: bool,
    read: Option<Duration>,
    write: Option<Duration>,
    handshake: Option<Duration>,
    connect_timeout: Duration,
}
impl PreparedTransport {
    pub(super) fn prepare(config: &ProxyConfig,resources:&Arc<super::resource_budget::Resources>) -> Result<Self> {
        let http = [
            super::http_dial::Family::Any,
            super::http_dial::Family::V4,
            super::http_dial::Family::V6,
        ]
        .map(|family| {
            let mut http =
                HttpConnector::new_with_resolver(super::http_dial::FamilyResolver::new(family));
            http.enforce_http(false);
            http.set_connect_timeout((!config.dial_timeout.is_zero()).then_some(config.dial_timeout));
            http.set_nodelay(true);
            http
        });
        let tls = config
            .tls
            .as_ref()
            .map(|t| provision_inner(t, config.enable_http2,false,Some(&resources.ssl_verify),true))
            .transpose()?;
        let (tls,native,fallback,managed)=match tls{Some(t)=>(Some(Arc::new(t.rustls)),t.native,t.fallback,t.managed),None=>(None,None,None,None)};
        let client_executor=if tls.is_some()&&native.is_none(){Some(resources.client_tls_executor()?)}else{None};
        Ok(Self {
            client_executor,
            http,
            tls,
            native,
            fallback,
            managed,
            http1_native:false,
            read: config.read_timeout,
            write: config.write_timeout,
            handshake: config.tls.as_ref().and_then(|t| t.handshake_timeout),
            connect_timeout:config.dial_timeout,
        })
    }
    pub(super) fn metrics(dial:Uri,tls:Option<Arc<ClientConfig>>,timeout:Duration)->FixedDialConnector{
        let family=super::http_dial::Family::Any;
        let mut http=HttpConnector::new_with_resolver(super::http_dial::FamilyResolver::new(family));
        http.enforce_http(false);http.set_connect_timeout((!timeout.is_zero()).then_some(timeout));http.set_nodelay(true);
        FixedDialConnector{http,family,tls,native:None,fallback:None,managed:None,client_executor:None,http1_native:false,read:Some(timeout),write:Some(timeout),handshake:Some(timeout),dial,server_name:None,unix_path:None,connect_timeout:timeout,map_owner:None}
    }
    pub(super) fn http1(&self) -> Self {
        let mut result = self.clone();
        result.http1_native=true;
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
            native: if dial.scheme_str()==Some("https"){self.native.clone()}else{None},
            fallback: if dial.scheme_str()==Some("https"){self.fallback.clone()}else{None},
            managed:if dial.scheme_str()==Some("https"){self.managed.clone()}else{None},
            client_executor:self.client_executor.clone(),
            http1_native:self.http1_native,
            read: self.read,
            write: self.write,
            handshake: self.handshake,
            dial,
            server_name,
            unix_path:unix_path.map(Arc::from),
            connect_timeout:self.connect_timeout,
            map_owner:None,
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
pub(crate) struct PreparedTls {pub(crate) rustls:ClientConfig,pub(crate) native:Option<Arc<native_ssl_tls::ClientConfig>>,fallback:Option<Arc<native_ssl_tls::ClientConfig>>,pub(crate) managed:Option<Arc<crate::tls_app_config::ManagedClientSource>>}
fn provision_inner(tls: &ProxyTls, enable_http2: bool, allow_empty_default:bool,scope:Option<&Arc<native_ssl_tls::VerificationScope>>,cbc_compat:bool) -> Result<PreparedTls> {
    ensure!(
        tls.client_certificate_file.is_some() == tls.client_certificate_key_file.is_some(),
        "client_certificate_file and client_certificate_key_file must be set together"
    );
    ensure!(tls.client_certificate_automate.is_none()||tls.managed_client.is_some(),"managed client certificate source is not prepared");
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
        crate::crypto::client_provider()
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
    let verifier:Arc<dyn ServerCertVerifier>=if tls.insecure_skip_verify||roots.is_empty(){
        Arc::new(InsecureVerifier{provider:provider.clone(),skip_chain:tls.insecure_skip_verify})
    }else{rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots),provider.clone()).build()?};
    let builder=ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?.dangerous().with_custom_certificate_verifier(verifier.clone());
    let identity=if let(Some(cert),Some(key))=(&tls.client_certificate_file,&tls.client_certificate_key_file){
        let certs=certificates(&read_material(cert,&mut budget)?)?;
        let key=rustls_pemfile::private_key(&mut std::io::Cursor::new(read_material(key,&mut budget)?))
            .map_err(|_|anyhow::anyhow!("invalid upstream client private key PEM"))?.ok_or_else(||anyhow::anyhow!("upstream client private key missing or encrypted"))?;
        Some((certs,key))
    }else{None};
    let alpn=if enable_http2{vec![b"h2".to_vec(),b"http/1.1".to_vec()]}else{Vec::new()};
    let (native,fallback)=if tls.renegotiation!=native_ssl_tls::Renegotiation::Never||cbc_compat{
        let groups=provider.kx_groups.iter().map(|g|match u16::from(g.name()){
            29=>Ok("X25519"),23=>Ok("P-256"),24=>Ok("P-384"),25=>Ok("P-521"),4588=>Ok("X25519MLKEM768"),4587=>Ok("SecP256r1MLKEM768"),4589=>Ok("SecP384r1MLKEM1024"),_=>Err(anyhow::anyhow!("TLS group is unavailable to renegotiation engine"))
        }).collect::<Result<Vec<_>>>()?.join(":");
        let identity=identity.as_ref().map(|(c,k)|(c.as_slice(),k.secret_der()));
        let config=if tls.renegotiation==native_ssl_tls::Renegotiation::Never {
            native_ssl_tls::ClientConfig::cbc_fallback(verifier,&alpn,&groups,identity)?
        } else if cbc_compat {
            native_ssl_tls::ClientConfig::go_compatible(verifier,tls.renegotiation,&alpn,&groups,identity)?
        } else {
            native_ssl_tls::ClientConfig::new(verifier,tls.renegotiation,&alpn,&groups,identity)?
        };
        let config=Arc::new(match scope{Some(scope)=>config.with_verification_scope(scope.clone()),None=>config});
        if tls.renegotiation==native_ssl_tls::Renegotiation::Never{(None,Some(config))}else{(Some(config),None)}
    }else{(None,None)};
    let mut config=match identity{Some((certs,key))=>builder.with_client_auth_cert(certs,key).map_err(|_|anyhow::anyhow!("invalid upstream client certificate/key pair"))?,None=>builder.with_no_client_auth()};
    // Go HTTPTransport leaves ClientSessionCache nil, so it does not resume.
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = if enable_http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        Vec::new()
    };
    Ok(PreparedTls{rustls:config,native,fallback,managed:tls.managed_client.clone()})
}
#[derive(Debug)]
struct InsecureVerifier {
    skip_chain:bool,
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
        if self.skip_chain{Ok(ServerCertVerified::assertion())}else{Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))}
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

type Dial=TimeoutIo<super::http_dial_io::DialIo>;
type RustlsStream=tokio_rustls::client::TlsStream<FirstAlertIo<TokioIo<Dial>>>;
pub(super) enum Output{
    Http(Dial),
    Rustls(TokioIo<RustlsStream>),
    Native(TokioIo<native_ssl_tls::OwnedClientStream<TokioIo<Dial>>>),
    ManagedNative(TokioIo<native_ssl_tls::ManagedStream<TokioIo<Dial>>>),
    ManagedRustls(TokioIo<crate::tls_app_config::BoundClientIo<RustlsStream>>),
}
fn rustls_connected(stream:&RustlsStream)->hyper_util::client::legacy::connect::Connected {
    use hyper_util::client::legacy::connect::Connection as _;
    let connected=stream.get_ref().0.inner().inner().connected();
    if stream.get_ref().1.alpn_protocol()==Some(b"h2"){connected.negotiated_h2()}else{connected}
}
impl hyper_util::client::legacy::connect::Connection for Output{
    fn connected(&self)->hyper_util::client::legacy::connect::Connected{
        match self {
            Self::Http(s)=>s.connected(),
            Self::Rustls(s)=>rustls_connected(s.inner()),
            Self::ManagedRustls(s)=>rustls_connected(s.inner().get_ref()),
            Self::Native(s)=>{
                let connected=s.inner().get_ref().inner().connected();
                if s.inner().selected_alpn_protocol()==b"h2"{connected.negotiated_h2()}else{connected}
            },
            Self::ManagedNative(s)=>{
                let connected=s.inner().get_ref().inner().connected();
                if s.inner().selected_alpn_protocol()==b"h2"{connected.negotiated_h2()}else{connected}
            },
        }
    }
}
impl hyper::rt::Read for Output{
    fn poll_read(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:hyper::rt::ReadBufCursor<'_>)->Poll<std::io::Result<()>>{match self.get_mut(){Self::Http(s)=>Pin::new(s).poll_read(cx,buf),Self::Rustls(s)=>Pin::new(s).poll_read(cx,buf),Self::Native(s)=>Pin::new(s).poll_read(cx,buf),Self::ManagedNative(s)=>Pin::new(s).poll_read(cx,buf),Self::ManagedRustls(s)=>Pin::new(s).poll_read(cx,buf)}}
}
impl hyper::rt::Write for Output{
    fn poll_write(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<std::io::Result<usize>>{match self.get_mut(){Self::Http(s)=>Pin::new(s).poll_write(cx,buf),Self::Rustls(s)=>Pin::new(s).poll_write(cx,buf),Self::Native(s)=>Pin::new(s).poll_write(cx,buf),Self::ManagedNative(s)=>Pin::new(s).poll_write(cx,buf),Self::ManagedRustls(s)=>Pin::new(s).poll_write(cx,buf)}}
    fn poll_flush(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<std::io::Result<()>>{match self.get_mut(){Self::Http(s)=>Pin::new(s).poll_flush(cx),Self::Rustls(s)=>Pin::new(s).poll_flush(cx),Self::Native(s)=>Pin::new(s).poll_flush(cx),Self::ManagedNative(s)=>Pin::new(s).poll_flush(cx),Self::ManagedRustls(s)=>Pin::new(s).poll_flush(cx)}}
    fn poll_shutdown(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<std::io::Result<()>>{match self.get_mut(){Self::Http(s)=>Pin::new(s).poll_shutdown(cx),Self::Rustls(s)=>Pin::new(s).poll_shutdown(cx),Self::Native(s)=>Pin::new(s).poll_shutdown(cx),Self::ManagedNative(s)=>Pin::new(s).poll_shutdown(cx),Self::ManagedRustls(s)=>Pin::new(s).poll_shutdown(cx)}}
    fn is_write_vectored(&self)->bool{match self{Self::Http(s)=>s.is_write_vectored(),Self::Rustls(s)=>s.is_write_vectored(),Self::Native(s)=>s.is_write_vectored(),Self::ManagedNative(s)=>s.is_write_vectored(),Self::ManagedRustls(s)=>s.is_write_vectored()}}
    fn poll_write_vectored(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[std::io::IoSlice<'_>])->Poll<std::io::Result<usize>>{match self.get_mut(){Self::Http(s)=>Pin::new(s).poll_write_vectored(cx,buf),Self::Rustls(s)=>Pin::new(s).poll_write_vectored(cx,buf),Self::Native(s)=>Pin::new(s).poll_write_vectored(cx,buf),Self::ManagedNative(s)=>Pin::new(s).poll_write_vectored(cx,buf),Self::ManagedRustls(s)=>Pin::new(s).poll_write_vectored(cx,buf)}}
}


#[derive(Clone)]
pub(super) struct FixedDialConnector {
    pub(super) http: HttpConnector<super::http_dial::FamilyResolver>,
    family: super::http_dial::Family,
    pub(super) tls: Option<Arc<ClientConfig>>,
    native:Option<Arc<native_ssl_tls::ClientConfig>>,
    fallback:Option<Arc<native_ssl_tls::ClientConfig>>,
    managed:Option<Arc<crate::tls_app_config::ManagedClientSource>>,
    client_executor:Option<Arc<super::tls_executor::TlsExecutor>>,
    http1_native:bool,
    pub(super) read: Option<Duration>,
    pub(super) write: Option<Duration>,
    pub(super) handshake: Option<Duration>,
    pub(super) dial: Uri,
    pub(super) server_name: Option<ServerName<'static>>,
    unix_path:Option<Arc<str>>,
    connect_timeout:Duration,
    map_owner:Option<Arc<super::map_runtime::DialOwner>>,
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

type ConnectError=Box<dyn std::error::Error+Send+Sync>;
fn tls_timeout()->ConnectError {
    Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut,"TLS handshake timeout"))
}
async fn within_tls<T>(deadline:Option<Instant>,future:impl Future<Output=Result<T,ConnectError>>)->Result<T,ConnectError>{
    match deadline {
        Some(at)=>{
            if Instant::now()>=at{return Err(tls_timeout());}
            timeout_at(at,future).await.map_err(|_|tls_timeout())?
        },
        None=>future.await,
    }
}
async fn dial_once(
    http:&mut HttpConnector<super::http_dial::FamilyResolver>,
    family:super::http_dial::Family,dial:&Uri,unix_path:Option<&str>,
    allowance:Option<Duration>,
)->Result<super::http_dial_io::DialIo,ConnectError>{
    use super::http_dial_io::DialIo;
    let future=async {
        if let Some(path)=unix_path {
            #[cfg(unix)] {
                let stream=super::http_dial::connect_unix(path).await?;
                Ok(DialIo::Unix(TokioIo::new(stream)))
            }
            #[cfg(not(unix))] {
                let _=path;
                Err(std::io::Error::new(std::io::ErrorKind::Unsupported,"Unix upstreams require Unix sockets").into())
            }
        } else {
            let uri=family.literal_uri(dial)?;
            Ok(DialIo::Tcp(http.call(uri).await?))
        }
    };
    let result:Result<_,ConnectError>=match allowance {
        Some(d) if d.is_zero()=>Err(std::io::Error::new(std::io::ErrorKind::TimedOut,"upstream dial timeout").into()),
        Some(d)=>match timeout(d,future).await {
            Ok(result)=>result,
            Err(_)=>Err(std::io::Error::new(std::io::ErrorKind::TimedOut,"upstream dial timeout").into()),
        },
        None=>future.await,
    };
    result.map_err(|e|Box::new(TcpDialError(e))as ConnectError)
}
async fn native_output(
    native:Arc<native_ssl_tls::ClientConfig>,
    binding:Option<Arc<crate::tls_app_config::ClientBinding>>,
    server_name:ServerName<'static>,io:Dial,http1:bool,deadline:Option<Instant>,
)->Result<Output,ConnectError>{
    within_tls(deadline,async move{
        if let Some(binding)=binding {
            let config=native_ssl_tls::ManagedClientConfig::from_shared_base(native,binding.clone())?;
            let stream=config.connect_with_alpn(server_name,TokioIo::new(io),if http1{Some(&[])}else{None}).await?;
            binding.check()?;
            Ok(Output::ManagedNative(TokioIo::new(stream)))
        } else {
            let stream=native.connect_owned_with_alpn(server_name,TokioIo::new(io),if http1{Some(&[])}else{None}).await?;
            Ok(Output::Native(TokioIo::new(stream)))
        }
    }).await
}

fn executor_error(error:anyhow::Error)->ConnectError{
    match error.downcast::<std::io::Error>(){
        Ok(error)=>Box::new(error),
        Err(error)=>error.into(),
    }
}
fn credited_native(config:Arc<native_ssl_tls::ClientConfig>,credits:Option<&Arc<native_ssl_tls::ConnectionCredits>>)->Arc<native_ssl_tls::ClientConfig>{
    match credits{
        Some(credits)=>Arc::new(config.with_connection_credits(credits.clone())),
        None=>config,
    }
}
impl Service<Uri> for FixedDialConnector {
    type Response=MapOutput;
    type Error=ConnectError;
    type Future=Pin<Box<dyn Future<Output=Result<Self::Response,Self::Error>>+Send>>;
    fn poll_ready(&mut self,cx:&mut Context<'_>)->Poll<Result<(),Self::Error>>{
        self.http.poll_ready(cx).map_err(|e|Box::new(e)as Self::Error)
    }
    fn call(&mut self, _uri: Uri) -> Self::Future {
        let (workspace,output_credit)=if let Some(owner)=&self.map_owner{
            let bytes=self.dial.authority().map_or(0,|value|value.as_str().len()).saturating_add(self.dial.scheme_str().map_or(0,str::len)).saturating_add(self.dial.path_and_query().map_or(0,|value|value.as_str().len())).saturating_add(self.unix_path.as_ref().map_or(0,|path|path.len())).saturating_add(520);
            let workspace=match owner.work_pool.reserve(bytes.saturating_mul(4).saturating_add(8192)){Ok(credit)=>credit,Err(error)=>return Box::pin(async move{Err(Box::new(std::io::Error::other(error.to_string()))as Self::Error)})};
            let output=match owner.work_pool.reserve(std::mem::size_of::<Output>().saturating_add(2048)){Ok(credit)=>Arc::new(credit),Err(error)=>return Box::pin(async move{Err(Box::new(std::io::Error::other(error.to_string()))as Self::Error)})};
            (Some(Arc::new(workspace)),Some(output))
        }else{(None,None)};
        let state=DialState{http:self.http.clone(),tls:self.tls.clone(),native:self.native.clone(),fallback:self.fallback.clone(),managed:self.managed.clone(),client_executor:self.client_executor.clone(),http1_native:self.http1_native,read:self.read,write:self.write,handshake:self.handshake,dial:self.dial.clone(),family:self.family,server_name:self.server_name.clone(),unix_path:self.unix_path.clone(),connect_timeout:self.connect_timeout,map_owner:self.map_owner.clone(),output_credit,_workspace:workspace};
        Box::pin(state.run())
    }
}

/// Real configuration-time HTTP CA-fetch trust uses the same prepared client
/// TLS policy as proxy traffic, with no client identity or per-port exception.
pub(crate) fn ca_source_client_tls(ca:Option<serde_json::Value>,insecure:bool)->Result<ClientConfig>{Ok(ca_source_prepared_tls(ca,insecure,native_ssl_tls::Renegotiation::Never,None)?.rustls)}
pub(crate) fn ca_source_prepared_tls(ca:Option<serde_json::Value>,insecure:bool,renegotiation:native_ssl_tls::Renegotiation,scope:Option<&Arc<native_ssl_tls::VerificationScope>>)->Result<PreparedTls>{
    let options=ProxyTls{client_certificate_automate:None,managed_client:None,renegotiation,curves:Vec::new(),ca,except_ports:Vec::new(),server_name:None,insecure_skip_verify:insecure,root_ca_pem_files:Vec::new(),root_ca_pool:Vec::new(),client_certificate_file:None,client_certificate_key_file:None,handshake_timeout:None};
    provision_inner(&options,true,true,scope,false)
}

impl FixedDialConnector{
    pub(super) fn with_map_owner(mut self,owner:Arc<super::map_runtime::DialOwner>,budget:super::resource_budget::BlockingBudget)->Self{
        // PreparedTransport configures exactly these TCP options. Only the
        // resolver changes for a Map-derived dial; TLS state is untouched.
        let mut http=HttpConnector::new_with_resolver(super::http_dial::FamilyResolver::with_map(self.family,budget,owner.clone()));
        http.enforce_http(false);http.set_connect_timeout((!self.connect_timeout.is_zero()).then_some(self.connect_timeout));http.set_nodelay(true);
        self.http=http;self.map_owner=Some(owner);self
    }
}
// A TLS/name-validation error may itself own the expected ServerName. Keep
// its final error value, not only successful IO, behind the same credit.
#[derive(Debug)]
struct MapDialError{inner:Box<dyn std::error::Error+Send+Sync>,_credit:Arc<native_write_policy::Lease>}
impl std::fmt::Display for MapDialError{fn fmt(&self,out:&mut std::fmt::Formatter<'_>)->std::fmt::Result{std::fmt::Display::fmt(&self.inner,out)}}
impl std::error::Error for MapDialError{fn source(&self)->Option<&(dyn std::error::Error+'static)>{Some(&*self.inner)}}
pub(super) struct MapOutput{inner:Output,_credit:Option<Arc<native_write_policy::Lease>>}
impl hyper_util::client::legacy::connect::Connection for MapOutput{fn connected(&self)->hyper_util::client::legacy::connect::Connected{hyper_util::client::legacy::connect::Connection::connected(&self.inner)}}
impl hyper::rt::Read for MapOutput{fn poll_read(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:hyper::rt::ReadBufCursor<'_>)->Poll<std::io::Result<()>>{Pin::new(&mut self.get_mut().inner).poll_read(cx,buf)}}
impl hyper::rt::Write for MapOutput{
 fn poll_write(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<std::io::Result<usize>>{Pin::new(&mut self.get_mut().inner).poll_write(cx,buf)}
 fn poll_flush(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<std::io::Result<()>>{Pin::new(&mut self.get_mut().inner).poll_flush(cx)}
 fn poll_shutdown(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<std::io::Result<()>>{Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)}
 fn is_write_vectored(&self)->bool{hyper::rt::Write::is_write_vectored(&self.inner)}
 fn poll_write_vectored(self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[std::io::IoSlice<'_>])->Poll<std::io::Result<usize>>{Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx,buf)}
}
// This single concrete input owns its real fields before all credits. Explicit
// Drop keeps that order even when its async run future is never first-polled.
struct DialState{
 http:HttpConnector<super::http_dial::FamilyResolver>,tls:Option<Arc<ClientConfig>>,native:Option<Arc<native_ssl_tls::ClientConfig>>,fallback:Option<Arc<native_ssl_tls::ClientConfig>>,managed:Option<Arc<crate::tls_app_config::ManagedClientSource>>,client_executor:Option<Arc<super::tls_executor::TlsExecutor>>,http1_native:bool,
 read:Option<Duration>,write:Option<Duration>,handshake:Option<Duration>,dial:Uri,family:super::http_dial::Family,
 server_name:Option<ServerName<'static>>,unix_path:Option<Arc<str>>,connect_timeout:Duration,
 map_owner:Option<Arc<super::map_runtime::DialOwner>>,output_credit:Option<Arc<native_write_policy::Lease>>,_workspace:Option<Arc<native_write_policy::Lease>>,
}
impl Drop for DialState{fn drop(&mut self){}}
impl DialState{
 async fn run(mut self)->Result<MapOutput,ConnectError>{
  match self.connect().await{
   Ok(inner)=>Ok(MapOutput{inner,_credit:self.output_credit.clone()}),
   Err(inner)=>match &self.output_credit{Some(credit)=>Err(Box::new(MapDialError{inner,_credit:credit.clone()})),None=>Err(inner)},
  }
 }
 async fn connect(&mut self)->Result<Output,ConnectError>{
        let mut http=self.http.clone();
        let tls=self.tls.clone();
        let native=self.native.clone();
        let fallback=self.fallback.clone();
        let managed=self.managed.clone();
        let client_executor=self.client_executor.clone();
        let http1_native=self.http1_native;
        let read=self.read;
        let write=self.write;
        let handshake=self.handshake;
        let dial=self.dial.clone();
        let family=self.family;
        let server_name=self.server_name.clone();
        let unix_path=self.unix_path.clone();
        let connect_timeout=self.connect_timeout;
        // Only mapped attempts opt into concrete shared credits. This capsule
        // follows detached TLS CPU jobs as well as their not-yet-consumed result.
        let credits=match (&self.map_owner,&self.output_credit,&self._workspace){
            (Some(owner),Some(output),Some(workspace))=>Some(owner.tls_credits(workspace.clone(),output.clone())),
            _=>None,
        };
        let map_pool=self.map_owner.as_ref().map(|owner|owner.work_pool.clone());

        // Preserve the current complete CBC/managed-client connector inside
        // this concrete owner; both dial attempts share its resolver and credit.
        async move {
            let dial_allowance=(!connect_timeout.is_zero()).then_some(connect_timeout);
            let first_dial=Instant::now();
            let tcp=dial_once(&mut http,family,&dial,unix_path.as_deref(),dial_allowance).await?;
            // Only actual dial time is deducted from the aggregate dial allowance.
            // Both TLS attempts and the compatibility redial share one TLS deadline.
            let dial_left=dial_allowance.map(|d|d.saturating_sub(first_dial.elapsed()));
            let io=TimeoutIo::new(tcp,read,write);
            let Some(cfg)=tls else{return Ok(Output::Http(io));};
            let server_name=match server_name{
                Some(s)=>s,
                None=>{
                    let host=dial.host().ok_or("missing host in dial uri")?;
                    ServerName::try_from(super::http_dial::tls_host(host).to_owned())?
                },
            };
            let deadline=handshake.filter(|d|!d.is_zero()).map(|d|{
                Instant::now().checked_add(d).ok_or_else(||std::io::Error::new(std::io::ErrorKind::InvalidInput,"TLS deadline out of range"))
            }).transpose()?;
            let binding=managed.as_ref().map(|source|source.binding());
            if let Some(native)=native{
                let native=credited_native(native,credits.as_ref());
                return native_output(native,binding,server_name,io,http1_native,deadline).await;
            }
            let cfg=if let Some(binding)=&binding{
                let mut config=(*cfg).clone();
                config.client_auth_cert_resolver=binding.clone();Arc::new(config)
            }else{cfg};
            let tls_connector=TlsConnector::from(cfg);
            let first_name=server_name.clone();
            // ClientConnection/keyshare construction is performed on first poll,
            // including when execute moves a managed handshake off the caller.
            let connect=async move{
                tls_connector.connect(first_name,FirstAlertIo::new(TokioIo::new(io))).into_fallible().await
            };
            // Keep the result envelope alive until the final stream/error has
            // been handed back to DialState. Its future owns the same capsule
            // before first poll and while another runtime is still polling it.
            let mut retained_result=None;
            let result=if let Some(executor)=client_executor{
                if let (Some(credits),Some(pool))=(&credits,&map_pool){
                    let connect=retained::RetainedTls::new(connect,credits.clone(),pool)?;
                    retained_result=Some(executor.execute(async move{Ok(connect.await)},tokio_util::sync::CancellationToken::new(),deadline).await.map_err(executor_error)?);
                    retained_result.as_mut().expect("retained TLS result").take()
                }else{
                    executor.execute(async move{Ok(connect.await)},tokio_util::sync::CancellationToken::new(),deadline).await.map_err(executor_error)?
                }
            }else{
                within_tls(deadline,async move{Ok(connect.await)}).await?
            };
            let output=match result{
                Ok(stream)=>{
                    if let Some(binding)=binding{
                        binding.check()?;
                        Ok(Output::ManagedRustls(TokioIo::new(crate::tls_app_config::BoundClientIo::new(stream,binding))))
                    }else{Ok(Output::Rustls(TokioIo::new(stream)))}
                },
                Err((error,failed_io))=>{
                    let candidate=failed_io.early_handshake_failure(&error);
                    drop(failed_io);
                    let Some(fallback)=fallback.filter(|_|candidate)else{return Err(Box::new(error)as ConnectError);};
                    // A first fatal40 is a compatibility candidate, not proof of
                    // the peer's private failure reason. The second context is
                    // TLS1.2/CBC-only with the identical native trust verifier.
                    let tcp=within_tls(deadline,dial_once(&mut http,family,&dial,unix_path.as_deref(),dial_left)).await?;
                    native_output(credited_native(fallback,credits.as_ref()),binding,server_name,TimeoutIo::new(tcp,read,write),http1_native,deadline).await
                },
            };
            // The stream/error now owns its handoff value, and DialState still
            // owns its corresponding output credit until MapOutput is built.
            drop(retained_result);
            output
        }.await
 }
}
