//! Explicit-policy OpenSSL TLS transport. The default Rustls transport is not
//! replaced. Exact-wire certificate validation remains the caller's verifier.
mod io;
mod managed_request;
mod managed_client;
pub use managed_client::{ClientCredential,ClientCertificateRequest,ClientIdentityResolver,ManagedClientConfig,ManagedStream};
mod raw;
mod server_auth;
pub use server_auth::{ServerClientAuth, signature_scheme_name};
pub mod server_engine;
mod server_io;
pub use server_io::ServerStream;
mod verify;
use foreign_types::{ForeignType, ForeignTypeRef};
pub use io::Stream;
pub use verify::VerificationScope;
/// Aggregate exact-wire certificate observation credits across all clients.
/// OpenSSL's internal state and caller-owned verifier allocations are separate.
pub fn certificate_observation_usage() -> (usize, usize) {
    raw::usage()
}

/// Exact bytes and observation credits remain one shared owner. This is a
/// parser/owner for the public SSL handshake message callback, not X509 trust.
#[derive(Clone)]
pub struct PeerCertificates(Arc<raw::Chain>);
impl PeerCertificates {
    pub fn from_handshake(message: &[u8], tls13: bool) -> stdio::Result<Self> {
        raw::Chain::parse(message, tls13).map(Self)
    }
    pub fn leaf(&self) -> &[u8] {
        self.0.leaf()
    }
    pub fn intermediates(&self) -> impl Iterator<Item = &[u8]> {
        self.0.intermediates()
    }
    pub fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        self.0.certificates()
    }
}

use openssl::{
    error::ErrorStack,
    ssl::{
        Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslSessionCacheMode,
        SslVerifyMode, SslVersion,
    },
};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    io as stdio,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncRead, AsyncWrite};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renegotiation {
    Never,
    Once,
    Freely,
}
impl Renegotiation {
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        match s {
            "" | "never" => Ok(Self::Never),
            "once" => Ok(Self::Once),
            "freely" => Ok(Self::Freely),
            _ => Err("invalid TLS renegotiation level"),
        }
    }
}
#[derive(Default)]
struct Certificates {
    initial: Option<Arc<raw::Chain>>,
    current: Option<Arc<raw::Chain>>,
}
struct Guard {
    policy: Renegotiation,
    rejected: AtomicU8,
    completed: AtomicUsize,
    finished: AtomicBool,
    verified: AtomicBool,
    verification_ready: AtomicBool,
    name: ServerName<'static>,
    verifier: Arc<dyn ServerCertVerifier>,
    certs: Mutex<Certificates>,
}
impl Guard {
    fn check(&self) -> stdio::Result<()> {
        match self.rejected.load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(stdio::Error::new(
                stdio::ErrorKind::PermissionDenied,
                "remote TLS renegotiation rejected by policy",
            )),
            2 => Err(stdio::Error::new(
                stdio::ErrorKind::InvalidData,
                "TLS peer certificate evidence rejected",
            )),
            3 => Err(stdio::Error::new(
                stdio::ErrorKind::OutOfMemory,
                "TLS certificate observation capacity exhausted",
            )),
            _ => Err(stdio::Error::other("TLS observer failed")),
        }
    }
    fn reject(&self, reason: u8) {
        let _ = self
            .rejected
            .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire);
    }
    fn certificate(&self, message: &[u8], tls13: bool) -> stdio::Result<()> {
        let next = raw::Chain::parse(message, tls13)?;
        let previous = {
            let mut state = self
                .certs
                .lock()
                .map_err(|_| stdio::Error::other("TLS observer poisoned"))?;
            if let Some(first) = &state.initial {
                if first.leaf() != next.leaf() {
                    return Err(stdio::Error::new(
                        stdio::ErrorKind::InvalidData,
                        "TLS server identity changed during renegotiation",
                    ));
                }
            }
            self.verified.store(false, Ordering::Release);
            state.current.replace(next)
        };
        drop(previous);
        Ok(())
    }
    // Called only after CPU verification has completed (or a same-leaf
    // renegotiation, where Go retains the initial trust decision).
    fn accept(&self) -> bool {
        if self.check().is_err() {
            return false;
        }
        let mut state = match self.certs.lock() {
            Ok(s) => s,
            Err(_) => {
                self.reject(4);
                return false;
            }
        };
        let Some(next) = state.current.clone() else {
            self.reject(2);
            return false;
        };
        if state.initial.is_none() {
            state.initial = Some(next)
        }
        self.verified.store(true, Ordering::Release);
        true
    }
    async fn verify_initial(&self, scope: &VerificationScope) -> stdio::Result<()> {
        let next = self
            .certs
            .lock()
            .map_err(|_| stdio::Error::other("TLS observer poisoned"))?
            .current
            .clone()
            .ok_or_else(|| stdio::Error::other("TLS certificate evidence missing"))?;
        let verifier = self.verifier.clone();
        let name = self.name.clone();
        let valid = scope
            .run(move || {
                // The raw Arc owns exact bytes and their admission credit throughout
                // real CPU execution, even when its async caller is abandoned.
                let intermediates = next
                    .intermediates()
                    .map(CertificateDer::from)
                    .collect::<Vec<_>>();
                let valid = verifier
                    .verify_server_cert(
                        &CertificateDer::from(next.leaf()),
                        &intermediates,
                        &name,
                        next.ocsp(),
                        UnixTime::now(),
                    )
                    .is_ok();
                (valid, next)
            })
            .await?;
        if !valid.0 {
            self.reject(2)
        }
        self.verification_ready.store(true, Ordering::Release);
        drop(valid);
        self.check()
    }
}
static INDEX: OnceLock<openssl::ex_data::Index<Ssl, Arc<Guard>>> = OnceLock::new();
static INDEX_INIT: Mutex<()> = Mutex::new(());
fn guard_index() -> Result<openssl::ex_data::Index<Ssl, Arc<Guard>>, ErrorStack> {
    if let Some(i) = INDEX.get() {
        return Ok(*i);
    }
    let _lock = INDEX_INIT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = INDEX.get() {
        return Ok(*i);
    }
    let i = Ssl::new_ex_index()?;
    let _ = INDEX.set(i);
    Ok(i)
}
unsafe extern "C" {
    fn SSL_CTX_set_cert_verify_callback(
        ctx: *mut openssl_sys::SSL_CTX,
        callback: Option<
            unsafe extern "C" fn(*mut openssl_sys::X509_STORE_CTX, *mut std::ffi::c_void) -> i32,
        >,
        arg: *mut std::ffi::c_void,
    );
    fn SSL_set_options(ssl: *mut openssl_sys::SSL, options: u64) -> u64;
    fn SSL_set_msg_callback(
        ssl: *mut openssl_sys::SSL,
        cb: Option<
            unsafe extern "C" fn(
                i32,
                i32,
                i32,
                *const std::ffi::c_void,
                usize,
                *mut openssl_sys::SSL,
                *mut std::ffi::c_void,
            ),
        >,
    );
    fn SSL_set_info_callback(
        ssl: *mut openssl_sys::SSL,
        cb: Option<unsafe extern "C" fn(*const openssl_sys::SSL, i32, i32)>,
    );
}
unsafe extern "C" fn observe(
    write: i32,
    _version: i32,
    kind: i32,
    ptr: *const std::ffi::c_void,
    len: usize,
    ssl: *mut openssl_sys::SSL,
    _arg: *mut std::ffi::c_void,
) {
    if kind != 22 || ptr.is_null() || len == 0 || ssl.is_null() {
        return;
    }
    if write!=0 {
        // Managed clients attest the actual sent leaf; legacy clients retain
        // their original incoming-only observer behavior.
        let ssl=unsafe{openssl::ssl::SslRef::from_ptr(ssl)};
        let bytes=unsafe{std::slice::from_raw_parts(ptr.cast::<u8>(),len)};
        managed_client::observe_sent(ssl,bytes);
        return;
    }
    let Some(index) = INDEX.get() else {
        return;
    };
    let ssl = unsafe { openssl::ssl::SslRef::from_ptr(ssl) };
    let Some(guard) = ssl.ex_data(*index) else {
        return;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let b = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
        match b[0] {
            0 => {
                let completed = guard.completed.load(Ordering::Acquire);
                if completed != 0
                    && (guard.policy == Renegotiation::Never
                        || (guard.policy == Renegotiation::Once && completed >= 2)
                        || ssl.selected_alpn_protocol() == Some(b"h2"))
                {
                    guard.reject(1);
                }
            }
            11 => {
                if let Err(e) = guard.certificate(b, ssl.version2() == Some(SslVersion::TLS1_3)) {
                    guard.reject(if e.kind() == stdio::ErrorKind::OutOfMemory {
                        3
                    } else {
                        2
                    });
                }
            }
            20 => guard.finished.store(true, Ordering::Release),
            _ => {}
        }
    }));
    if result.is_err() {
        guard.reject(4);
    }
}
unsafe extern "C" fn handshake_done(ssl: *const openssl_sys::SSL, where_: i32, _ret: i32) {
    if ssl.is_null() || where_ & 0x20 == 0 {
        return;
    }
    let Some(index) = INDEX.get() else {
        return;
    };
    let ssl = unsafe { openssl::ssl::SslRef::from_ptr(ssl.cast_mut()) };
    let Some(guard) = ssl.ex_data(*index) else {
        return;
    };
    if guard.check().is_ok()
        && guard.verified.load(Ordering::Acquire)
        && guard.finished.swap(false, Ordering::AcqRel)
    {
        let previous = guard.completed.fetch_add(1, Ordering::AcqRel);
        if guard.policy == Renegotiation::Once && previous >= 1 {
            unsafe {
                SSL_set_options(ssl.as_ptr(), SslOptions::NO_RENEGOTIATION.bits());
            }
        }
    }
}
unsafe extern "C" fn verify_chain(
    store: *mut openssl_sys::X509_STORE_CTX,
    _arg: *mut std::ffi::c_void,
) -> i32 {
    if store.is_null() {
        return 0;
    }
    let store = unsafe { openssl::x509::X509StoreContextRef::from_ptr_mut(store) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Option<bool> {
        let index = openssl::x509::X509StoreContext::ssl_idx().ok()?;
        let ssl = store.ex_data(index)?;
        let guard = ssl.ex_data(*INDEX.get()?)?;
        if guard.check().is_err() {
            return Some(false);
        }
        let leaf = ssl.peer_cert_chain()?.get(0)?;
        let key = leaf.public_key().ok()?;
        let supported = supported_public_key(&key);
        if !supported {
            guard.reject(2);
            return Some(false);
        }
        if guard.completed.load(Ordering::Acquire) == 0
            && !guard.verification_ready.load(Ordering::Acquire)
        {
            // SSL_set_retry_verify is the public SSL_ctrl macro, control 136.
            if unsafe { openssl_sys::SSL_ctrl(ssl.as_ptr(), 136, 0, std::ptr::null_mut()) } <= 0 {
                return Some(false);
            }
            return Some(true);
        }
        Some(guard.accept())
    }));
    let valid = matches!(result, Ok(Some(true)));
    store.set_error(if valid {
        openssl::x509::X509VerifyResult::OK
    } else {
        openssl::x509::X509VerifyResult::APPLICATION_VERIFICATION
    });
    i32::from(valid)
}
fn supported_public_key(key: &openssl::pkey::PKeyRef<openssl::pkey::Public>) -> bool {
    use openssl::{nid::Nid, pkey::Id};
    match key.id() {
        Id::RSA | Id::RSA_PSS => (1024..=8192).contains(&key.bits()),
        Id::EC => key.ec_key().ok().is_some_and(|k| {
            matches!(
                k.group().curve_name(),
                Some(Nid::SECP224R1 | Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1)
            )
        }),
        Id::ED25519 => true,
        _ => false,
    }
}
/// Actual pending/negotiated cipher during server ALPN selection.
pub fn pending_cipher(ssl: &openssl::ssl::SslRef) -> Option<u16> {
    unsafe extern "C" {
        fn SSL_get_pending_cipher(ssl: *const openssl_sys::SSL) -> *const openssl_sys::SSL_CIPHER;
    }
    let pointer = unsafe { SSL_get_pending_cipher(ssl.as_ptr()) };
    (!pointer.is_null()).then(|| {
        u16::from_be_bytes(
            unsafe { openssl::ssl::SslCipherRef::from_ptr(pointer.cast_mut()) }.protocol_id(),
        )
    })
}
/// Prepared on the caller's bounded provisioning CPU lane; no material I/O in
/// connect or callbacks. Credential parsing is confined to this constructor.
pub struct ClientConfig {
    context: SslContext,
    policy: Renegotiation,
    verifier: Arc<dyn ServerCertVerifier>,
    scope: Arc<VerificationScope>,
}
impl ClientConfig {
    /// The supplied hook validates exact-wire certificates, path, name and time.
    /// OpenSSL authenticates handshake signatures with the explicit scheme list.
    /// This does not add OCSP validation to the built-in native trust policy;
    /// received stapled bytes remain available from the live SSL object.
    pub fn new(
        verifier: Arc<dyn ServerCertVerifier>,
        policy: Renegotiation,
        alpn: &[Vec<u8>],
        groups: &str,
        identity: Option<(&[CertificateDer<'_>], &[u8])>,
    ) -> Result<Self, ErrorStack> {
        guard_index()?;
        let mut b = SslContextBuilder::new(SslMethod::tls_client())?;
        b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        // OpenSSL's public SSL_CTX_set_max_cert_list macro (control 51),
        // set before any connection can reassemble a Certificate message.
        unsafe {
            openssl_sys::SSL_CTX_ctrl(b.as_ptr(), 51, raw::MAX_MESSAGE as _, std::ptr::null_mut());
        }

        // Context-local level1 permits the Go-valid 1024-bit RSA case. Protocols,
        // suites/signatures and the existing native chain/name verifier stay explicit.
        b.set_security_level(1);
        b.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")?;
        b.set_sigalgs_list("ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ed25519")?;
        b.set_groups_list(groups)?;
        b.set_session_cache_mode(SslSessionCacheMode::OFF);
        b.set_options(SslOptions::NO_COMPRESSION | SslOptions::NO_TICKET);
        if policy == Renegotiation::Never {
            b.set_options(SslOptions::NO_RENEGOTIATION);
        }
        let mut wire = Vec::new();
        for protocol in alpn {
            if protocol.is_empty() || protocol.len() > 255 {
                return Err(ErrorStack::get());
            }
            wire.push(protocol.len() as u8);
            wire.extend_from_slice(protocol);
        }
        b.set_alpn_protos(&wire)?;
        if let Some((certs, key)) = identity {
            if let Some(leaf) = certs.first() {
                let leaf = openssl::x509::X509::from_der(leaf.as_ref())?;
                b.set_certificate(&leaf)?;
                for cert in &certs[1..] {
                    b.add_extra_chain_cert(openssl::x509::X509::from_der(cert.as_ref())?)?;
                }
            }
            let key = openssl::pkey::PKey::private_key_from_der(key)?;
            b.set_private_key(&key)?;
            b.check_private_key()?;
        }
        b.set_verify(SslVerifyMode::PEER);
        // Replace OpenSSL path verification entirely. A per-depth override
        // would still evaluate an untrusted chain before our native verifier,
        // including public keys outside its supported algorithm/size bounds.
        unsafe {
            SSL_CTX_set_cert_verify_callback(b.as_ptr(), Some(verify_chain), std::ptr::null_mut());
        }
        Ok(Self {
            context: b.build(),
            policy,
            verifier,
            scope: VerificationScope::new(),
        })
    }
    fn configured_connection(&self, name:ServerName<'static>, alpn:Option<&[u8]>) -> stdio::Result<(Ssl,Arc<Guard>)> {
        let mut ssl = Ssl::new(&self.context).map_err(stdio::Error::other)?;
        ssl.set_status_type(openssl::ssl::StatusType::OCSP)
            .map_err(stdio::Error::other)?;
        if let Some(alpn) = alpn {
            ssl.set_alpn_protos(alpn).map_err(stdio::Error::other)?;
        }
        if let ServerName::DnsName(dns) = &name {
            ssl.set_hostname(dns.as_ref())
                .map_err(stdio::Error::other)?;
        }
        let guard = Arc::new(Guard {
            policy: self.policy,
            rejected: AtomicU8::new(0),
            completed: AtomicUsize::new(0),
            finished: AtomicBool::new(false),
            verified: AtomicBool::new(false),
            verification_ready: AtomicBool::new(false),
            name,
            verifier: self.verifier.clone(),
            certs: Mutex::new(Certificates::default()),
        });
        ssl.set_ex_data(guard_index().map_err(stdio::Error::other)?, guard.clone());
        unsafe {
            SSL_set_msg_callback(ssl.as_ptr(), Some(observe));
            SSL_set_info_callback(ssl.as_ptr(), Some(handshake_done));
        }
        Ok((ssl,guard))
    }
    /// Bind tracked CPU work to the owning runtime/service shutdown fence.
    pub fn with_verification_scope(mut self, scope: Arc<VerificationScope>) -> Self {
        self.scope = scope;
        self
    }
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        name: ServerName<'static>,
        io: S,
    ) -> stdio::Result<Stream<S>> {
        self.connect_with_alpn(name, io, None).await
    }
    pub async fn connect_with_alpn<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        name: ServerName<'static>,
        io: S,
        alpn: Option<&[u8]>,
    ) -> stdio::Result<Stream<S>> {
        let _entry = self.scope.enter()?;
        let (ssl, guard) = self.configured_connection(name, alpn)?;
        let mut inner = tokio_openssl::SslStream::new(
            ssl,
            io::GuardedIo {
                inner: io,
                guard: guard.clone(),
            },
        )
        .map_err(stdio::Error::other)?;
        loop {
            match Pin::new(&mut inner).connect().await {
                Ok(()) => break,
                Err(error) if error.code().as_raw() == 12 => {
                    guard.verify_initial(&self.scope).await?
                }
                Err(error) => return Err(stdio::Error::other(error)),
            }
        }
        guard.check()?;
        if guard.completed.load(Ordering::Acquire) != 1 {
            return Err(stdio::Error::new(
                stdio::ErrorKind::InvalidData,
                "TLS handshake facts incomplete",
            ));
        }
        Ok(Stream { inner, guard })
    }
}

/// Actual OpenSSL negotiated group NID (or provider group identifier).
pub fn negotiated_group(ssl:&openssl::ssl::SslRef)->i64 {unsafe{openssl_sys::SSL_ctrl(ssl.as_ptr(),134,0,std::ptr::null_mut()) as i64}}
/// Actual Extended Master Secret support on this completed connection.
pub fn extended_master_secret(ssl:&openssl::ssl::SslRef)->bool{unsafe{openssl_sys::SSL_ctrl(ssl.as_ptr(),122,0,std::ptr::null_mut())==1}}

mod server_sessions;
pub use server_sessions::{ServerSessions,ServerSessionStore};

mod server_tickets;
pub use server_tickets::{ServerTickets,ServerTicketProvider,TicketKey};
