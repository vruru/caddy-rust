//! Exact-wire client-authentication adapter. OpenSSL authenticates the handshake
//! signature; the supplied native verifier alone validates path/pins/purpose.
use crate::{PeerCertificates, raw};
use foreign_types::ForeignTypeRef;
use openssl::{
    error::ErrorStack,
    ssl::{Ssl, SslContextBuilder, SslVerifyMode, SslVersion},
    x509::{X509StoreContextRef, X509VerifyResult},
};
use rustls::{
    ClientChainObservation, SignatureScheme,
    pki_types::{CertificateDer, UnixTime},
    server::danger::ClientCertVerifier,
};
use std::{
    ffi::CString,
    io,
    sync::{Arc, Mutex, OnceLock},
};
#[derive(Default)]
struct State {
    peer: Option<PeerCertificates>,
    observation: Option<ClientChainObservation>,
    error: Option<Arc<io::Error>>,
}
struct Guard {
    verifier: Option<Arc<dyn ClientCertVerifier>>,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct ServerClientAuth(Arc<Guard>);
static INDEX: OnceLock<openssl::ex_data::Index<Ssl, Arc<Guard>>> = OnceLock::new();
static INIT: Mutex<()> = Mutex::new(());
fn index() -> Result<openssl::ex_data::Index<Ssl, Arc<Guard>>, ErrorStack> {
    if let Some(v) = INDEX.get() {
        return Ok(*v);
    }
    let _lock = INIT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = INDEX.get() {
        return Ok(*v);
    }
    let value = Ssl::new_ex_index()?;
    let _ = INDEX.set(value);
    Ok(value)
}
unsafe extern "C" {
    fn X509_STORE_CTX_get0_cert(ctx: *const openssl_sys::X509_STORE_CTX) -> *mut openssl_sys::X509;
}
/// Public scheme spellings used by the complete SSL implementation. Unknown
/// native provider schemes cannot be silently advertised and then ignored.
pub fn signature_scheme_name(s: SignatureScheme) -> Option<&'static str> {
    use SignatureScheme::*;
    Some(match s {
        RSA_PKCS1_SHA256 => "rsa_pkcs1_sha256",
        RSA_PKCS1_SHA384 => "rsa_pkcs1_sha384",
        RSA_PKCS1_SHA512 => "rsa_pkcs1_sha512",
        RSA_PSS_SHA256 => "rsa_pss_rsae_sha256",
        RSA_PSS_SHA384 => "rsa_pss_rsae_sha384",
        RSA_PSS_SHA512 => "rsa_pss_rsae_sha512",
        ECDSA_NISTP256_SHA256 => "ecdsa_secp256r1_sha256",
        ECDSA_NISTP384_SHA384 => "ecdsa_secp384r1_sha384",
        ECDSA_NISTP521_SHA512 => "ecdsa_secp521r1_sha512",
        ED25519 => "ed25519",
        RSA_PKCS1_SHA1 => "RSA+SHA1",
        ECDSA_SHA1_Legacy => "ECDSA+SHA1",
        _ => return None,
    })
}
impl ServerClientAuth {
    pub fn new(verifier: Option<Arc<dyn ClientCertVerifier>>) -> Self {
        Self(Arc::new(Guard {
            verifier,
            state: Mutex::new(State::default()),
        }))
    }
    /// Provision only on the bounded CPU lane. The distinguished-name vector is
    /// bounded by its protocol u16 length before any native X509Name allocation.
    pub fn configure(&self, ctx: &mut SslContextBuilder) -> io::Result<()> {
        index().map_err(io::Error::other)?;
        unsafe {
            openssl_sys::SSL_CTX_ctrl(
                ctx.as_ptr(),
                51,
                raw::MAX_MESSAGE as _,
                std::ptr::null_mut(),
            );
        }
        let Some(verifier) = self.0.verifier.as_ref().filter(|v| v.offer_client_auth()) else {
            ctx.set_verify(SslVerifyMode::NONE);
            return Ok(());
        };
        let mut size = 0usize;
        for name in verifier.root_hint_subjects() {
            size = size
                .checked_add(2 + name.as_ref().len())
                .filter(|n| *n <= u16::MAX as usize)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TLS client authority names exceed protocol bounds",
                    )
                })?;
        }
        let mut names = openssl::stack::Stack::new().map_err(io::Error::other)?;
        for name in verifier.root_hint_subjects() {
            names
                .push(openssl::x509::X509Name::from_der(name.as_ref()).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        }
        ctx.set_client_ca_list(names);
        let schemes = verifier
            .supported_verify_schemes()
            .into_iter()
            .map(|s| {
                signature_scheme_name(s).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "native client verifier scheme unavailable to SSL",
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        if schemes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty native client signature scheme list",
            ));
        }
        let schemes = CString::new(schemes.join(":")).map_err(io::Error::other)?;
        // SSL_CTX_set1_client_sigalgs_list macro, distinct from our own server
        // certificate's signing list. No need to restrict the server key to a
        // custom client verifier's supported key types.
        if unsafe { openssl_sys::SSL_CTX_ctrl(ctx.as_ptr(), 102, 0, schemes.as_ptr() as *mut _) }
            <= 0
        {
            return Err(io::Error::other(ErrorStack::get()));
        }
        let mode = if verifier.client_auth_mandatory() {
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        } else {
            SslVerifyMode::PEER
        };
        ctx.set_verify(mode);
        unsafe {
            crate::SSL_CTX_set_cert_verify_callback(
                ctx.as_ptr(),
                Some(verify),
                std::ptr::null_mut(),
            );
        }
        Ok(())
    }
    pub fn bind(&self, ssl: &mut Ssl) -> io::Result<()> {
        ssl.set_ex_data(index().map_err(io::Error::other)?, self.0.clone());
        unsafe {
            crate::SSL_set_msg_callback(ssl.as_ptr(), Some(observe));
        }
        Ok(())
    }
    /// Only consume after the actual SSL handshake completes, including its
    /// CertificateVerify/Finished checks. This never performs a second trust walk.
    pub fn evidence(
        &self,
    ) -> io::Result<(Option<PeerCertificates>, Option<ClientChainObservation>)> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("SSL client evidence poisoned"))?;
        if let Some(error) = &state.error {
            return Err(io::Error::new(error.kind(), error.clone()));
        }
        Ok((state.peer.clone(), state.observation.clone()))
    }
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
    if write != 0 || kind != 22 || ptr.is_null() || ssl.is_null() || len == 0 {
        return;
    }
    let Some(index) = INDEX.get() else { return };
    let ssl = unsafe { openssl::ssl::SslRef::from_ptr(ssl) };
    let Some(guard) = ssl.ex_data(*index) else {
        return;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
        if bytes[0] != 11 {
            return Ok(());
        }
        let tls13 = ssl.version2() == Some(SslVersion::TLS1_3);
        let empty = if tls13 {
            bytes.get(4).is_some_and(|n| {
                let off = 5 + usize::from(*n);
                bytes.len() == off + 3
                    && bytes.get(1..4) == Some(&(bytes.len() as u32 - 4).to_be_bytes()[1..])
                    && bytes[off..] == [0, 0, 0]
            })
        } else {
            bytes == [11, 0, 0, 3, 0, 0, 0]
        };
        let peer = if empty {
            None
        } else {
            Some(PeerCertificates::from_handshake(bytes, tls13)?)
        };
        let old = {
            let mut state = guard
                .state
                .lock()
                .map_err(|_| io::Error::other("SSL client evidence poisoned"))?;
            state.observation = None;
            std::mem::replace(&mut state.peer, peer)
        };
        drop(old);
        Ok::<(), io::Error>(())
    }));
    let error = match result {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e,
        Err(_) => io::Error::other("SSL client observation failed"),
    };
    if let Ok(mut state) = guard.state.lock() {
        state.error.get_or_insert_with(|| Arc::new(error));
    }
}
unsafe extern "C" fn verify(
    store: *mut openssl_sys::X509_STORE_CTX,
    _arg: *mut std::ffi::c_void,
) -> i32 {
    if store.is_null() {
        return 0;
    }
    let store = unsafe { X509StoreContextRef::from_ptr_mut(store) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Option<bool> {
        let ssl = store.ex_data(openssl::x509::X509StoreContext::ssl_idx().ok()?)?;
        let guard = ssl.ex_data(*INDEX.get()?)?;
        let verifier = guard.verifier.as_ref()?;
        let pointer = unsafe { X509_STORE_CTX_get0_cert(store.as_ptr()) };
        if pointer.is_null() {
            return Some(false);
        }
        let leaf = unsafe { openssl::x509::X509Ref::from_ptr(pointer) };
        let key = leaf.public_key().ok()?;
        if !crate::supported_public_key(&key) {
            return Some(false);
        }
        let peer = {
            let state = guard.state.lock().ok()?;
            if state.error.is_some() {
                return Some(false);
            }
            state.peer.clone()?
        };
        let chain = peer
            .intermediates()
            .map(CertificateDer::from)
            .collect::<Vec<_>>();
        let verified = verifier
            .verify_client_cert(&CertificateDer::from(peer.leaf()), &chain, UnixTime::now())
            .ok()?;
        let mut state = guard.state.lock().ok()?;
        state.observation = Some(verified.observation().clone());
        Some(true)
    }));
    let valid = matches!(result, Ok(Some(true)));
    store.set_error(if valid {
        X509VerifyResult::OK
    } else {
        X509VerifyResult::APPLICATION_VERIFICATION
    });
    i32::from(valid)
}
