//! Complete SSL session serialization, behind the host's existing authorized
//! bounded cache. No implicit SSL internal cache or implicit ticket keys.
use openssl::ssl::{SslContextBuilder, SslOptions, SslSession, SslSessionCacheMode};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;
const MAX_SESSION: usize = 16 * 1024;
const STAGING: usize = 4 * 1024 * 1024;
static USED: AtomicUsize = AtomicUsize::new(0);
struct Loan;
impl Loan {
    fn reserve() -> Option<Self> {
        USED.try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
            v.checked_add(MAX_SESSION * 2 + 256)
                .filter(|v| *v <= STAGING)
        })
        .ok()?;
        Some(Self)
    }
}
impl Drop for Loan {
    fn drop(&mut self) {
        USED.fetch_sub(MAX_SESSION * 2 + 256, Ordering::AcqRel);
    }
}
/// The host authorizes each lookup against this handshake's actual selected
/// chain/name. Returned secrets must have been created by this SSL bridge.
pub trait ServerSessionStore: Send + Sync {
    fn put(&self, key: Vec<u8>, value: Zeroizing<Vec<u8>>) -> bool;
    fn get(&self, key: &[u8]) -> Option<Zeroizing<Vec<u8>>>;
}
#[derive(Clone)]
pub struct ServerSessions {
    store: Arc<dyn ServerSessionStore>,
    group: Arc<AtomicI64>,
}
impl ServerSessions {
    pub fn new(store: Arc<dyn ServerSessionStore>) -> Self {
        Self {
            store,
            group: Arc::new(AtomicI64::new(0)),
        }
    }
    pub fn resumed_group(&self) -> Option<i64> {
        let v = self.group.load(Ordering::Acquire);
        (v != 0).then_some(v)
    }
    pub fn configure(
        &self,
        ctx: &mut SslContextBuilder,
        binding: &[u8; 32],
        admitted: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> io::Result<()> {
        ctx.set_options(SslOptions::NO_TICKET);
        ctx.set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
        ctx.set_session_id_context(binding)
            .map_err(io::Error::other)?;
        let save = self.store.clone();
        let save_gate = admitted.clone();
        ctx.set_new_session_callback(move |ssl, session| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if !save_gate() {
                    return;
                }
                let Some(_loan) = Loan::reserve() else { return };
                // Public i2d reports size before any Rust output allocation. The SSL session
                // contains no client certificate in this no-client-auth cache path.
                let Some(encoded) = serialize(&session) else {
                    return;
                };
                let mut value = Zeroizing::new(Vec::with_capacity(encoded.len() + 8));
                value.extend_from_slice(&crate::negotiated_group(ssl).to_be_bytes());
                value.extend_from_slice(&encoded);
                if session.id().len() > 32 || session.id().is_empty() {
                    return;
                }
                let _ = save.put(session.id().to_vec(), value);
            }));
        });
        let load = self.store.clone();
        let group = self.group.clone();
        // Every returned object is newly decoded from DER into this callback's
        // context, with a strict shared session-id-context and the current cipher
        // list. No foreign live SSL_SESSION object is transferred between contexts.
        unsafe {
            ctx.set_get_session_callback(move |_ssl, id| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if !admitted() || id.len() > 32 {
                        return None;
                    }
                    let _loan = Loan::reserve()?;
                    let bytes = load.get(id)?;
                    if bytes.len() < 8 || bytes.len() > MAX_SESSION + 8 {
                        return None;
                    }
                    let observed = i64::from_be_bytes(bytes[..8].try_into().ok()?);
                    let session = SslSession::from_der(&bytes[8..]).ok()?;
                    if session.id() != id {
                        return None;
                    }
                    group.store(observed, Ordering::Release);
                    Some(session)
                }))
                .ok()
                .flatten()
            });
        }
        Ok(())
    }
}
fn serialize(session: &openssl::ssl::SslSessionRef) -> Option<Zeroizing<Vec<u8>>> {
    use foreign_types::ForeignTypeRef;
    let size = unsafe { openssl_sys::i2d_SSL_SESSION(session.as_ptr(), std::ptr::null_mut()) };
    let size = usize::try_from(size)
        .ok()
        .filter(|n| *n > 0 && *n <= MAX_SESSION)?;
    let mut bytes = Zeroizing::new(vec![0u8; size]);
    let mut ptr = bytes.as_mut_ptr();
    let written = unsafe { openssl_sys::i2d_SSL_SESSION(session.as_ptr(), &mut ptr) };
    (usize::try_from(written).ok() == Some(size)).then_some(bytes)
}
