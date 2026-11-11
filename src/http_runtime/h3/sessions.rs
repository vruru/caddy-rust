//! QUIC resumption is bound to the certificate selected by the real TLS hello.
use crate::{
    http_runtime::{
        connection_identity::chain_hash,
        connection_sessions::{OwnerCheck, SessionCache},
    },
    leaf_guard::LeafState,
    stek::TicketRuntime,
    tls_resolver::CertificateSelection,
};
use rustls::server::{NoServerSessionStorage, ProducesTickets, StoresServerSessions};
use std::{
    fmt,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use zeroize::Zeroizing;

#[cfg(feature = "native-run")]
use crate::stek::ticket::ConnectionTickets;
#[cfg(feature = "native-run")]
use sha2::{Digest, Sha256};

const ATTEMPTS: u8 = 5;
const MAX_SESSION: usize = 4096;

pub(super) struct Identity {
    sni: Box<str>,
    chain: [u8; 32],
    policy: [u8; 32],
    leaf: Arc<LeafState>,
}
impl Identity {
    fn live(&self, now: i64) -> bool {
        self.leaf.admission().allow_certificate && now < self.leaf.not_after()
    }
    fn matches(&self, current: &Self, now: i64) -> bool {
        self.sni == current.sni
            && self.chain == current.chain
            && self.policy == current.policy
            && Arc::ptr_eq(&self.leaf, &current.leaf)
            && self.live(now)
    }
}
fn now() -> Option<i64> {
    i64::try_from(rustls::pki_types::UnixTime::now().as_secs()).ok()
}

pub(super) struct Selected {
    pub(super) certificate: CertificateSelection,
    pub(super) raw_sni: Arc<str>,
    identity: Arc<Identity>,
}
impl Selected {
    pub(super) fn leaf(&self) -> &Arc<LeafState> {
        &self.identity.leaf
    }
}

/// One owned selection per actual QUIC handshake. The preflight observer
/// never owns this slot. HRR can only reuse the exact pinned certificate.
#[derive(Default)]
pub(super) struct SelectionSlot {
    selected: OnceLock<Selected>,
    poisoned: AtomicBool,
}
impl SelectionSlot {
    pub(super) fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }
    pub(super) fn current(&self) -> Option<&Selected> {
        if self.poisoned.load(Ordering::Acquire) {
            return None;
        }
        let selected = self.selected.get()?;
        selected.identity.live(now()?).then_some(selected)
    }
    pub(super) fn select(
        &self,
        sni: &str,
        raw_sni: &str,
        policy: [u8; 32],
        resolve: impl FnOnce() -> Option<CertificateSelection>,
    ) -> Option<&Selected> {
        if self.poisoned.load(Ordering::Acquire) {
            return None;
        }
        if let Some(known) = self.selected.get() {
            if known.identity.sni.as_ref() != sni || known.raw_sni.as_ref() != raw_sni {
                self.poison();
                return None;
            }
        } else {
            let certificate = resolve()?;
            let identity = Arc::new(Identity {
                sni: sni.into(),
                chain: chain_hash(&certificate.key),
                policy,
                leaf: certificate.leaf_state.clone()?,
            });
            if self
                .selected
                .set(Selected {
                    certificate,
                    raw_sni: Arc::from(raw_sni),
                    identity,
                })
                .is_err()
            {
                self.poison();
                return None;
            }
        }
        self.current()
    }
}

pub(super) type Shared = SessionCache<Identity>;
struct Stateful {
    cache: Arc<Shared>,
    slot: Arc<SelectionSlot>,
    attempts: AtomicU8,
}
impl fmt::Debug for Stateful {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicStatefulSessions")
            .finish_non_exhaustive()
    }
}
impl Stateful {
    fn lookup(&self, key: &[u8], consume: bool) -> Option<Vec<u8>> {
        let current = &self.slot.current()?.identity;
        let at = now()?;
        self.attempts
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < ATTEMPTS).then_some(n + 1)
            })
            .ok()?;
        self.cache
            .lookup(key, consume, |old| {
                if old.matches(current, at) {
                    OwnerCheck::Accept(())
                } else {
                    OwnerCheck::Reject
                }
            })
            .map(|(secret, ())| secret)
    }
}
impl StoresServerSessions for Stateful {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let value = Zeroizing::new(value);
        let Some(current) = self.slot.current().filter(|_| value.len() <= MAX_SESSION) else {
            return false;
        };
        // Rustls emits NST only after checking the client's Finished. The
        // certificate key is not retained by the cache, only its binding.
        self.cache.remember(key, value, current.identity.clone())
    }
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.lookup(key, false)
    }
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.lookup(key, true)
    }
    fn can_cache(&self) -> bool {
        true
    }
}

#[cfg(feature = "native-run")]
struct Rotating {
    tickets: ConnectionTickets,
    slot: Arc<SelectionSlot>,
}
#[cfg(feature = "native-run")]
impl fmt::Debug for Rotating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicRotatingTickets")
            .finish_non_exhaustive()
    }
}
#[cfg(feature = "native-run")]
impl Rotating {
    fn bind(&self) -> Option<&Identity> {
        let selected = &self.slot.current()?.identity;
        self.tickets
            .select(
                &selected.sni,
                rustls::ProtocolVersion::TLSv1_3,
                selected.chain,
                selected.leaf.clone(),
                selected.leaf.not_after(),
            )
            .then_some(selected)
    }
}
#[cfg(feature = "native-run")]
impl ProducesTickets for Rotating {
    fn enabled(&self) -> bool {
        self.tickets.enabled()
    }
    fn lifetime(&self) -> u32 {
        let Some(selected) = self.slot.current() else {
            return 0;
        };
        let Some(at) = now() else {
            return 0;
        };
        let remaining = selected.identity.leaf.not_after().saturating_sub(at);
        u32::try_from(remaining.max(0))
            .unwrap_or(u32::MAX)
            .min(self.tickets.lifetime())
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.bind()?;
        self.tickets.encrypt(plain)
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.bind()?;
        self.tickets.decrypt(cipher)
    }
}

#[derive(Debug)]
struct NoTickets;
impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

pub(super) fn configure(
    config: &mut rustls::ServerConfig,
    runtime: &TicketRuntime,
    cache: &Arc<Shared>,
    slot: Arc<SelectionSlot>,
    policy: &super::PolicyScope,
) {
    config.max_early_data_size = 0;
    config.max_tls13_tickets = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    if policy.client_auth {
        return;
    }
    match runtime {
        TicketRuntime::RuntimeDefault => {
            config.send_tls13_tickets = 1;
            config.session_storage = Arc::new(Stateful {
                cache: cache.clone(),
                slot,
                attempts: AtomicU8::new(0),
            });
        }
        #[cfg(feature = "native-run")]
        TicketRuntime::Disabled => {}
        #[cfg(feature = "native-run")]
        TicketRuntime::Rotating { owner, realm, .. } => {
            let mut hash = Sha256::new();
            hash.update(b"caddy-rust/stek/quic/h3/unauthenticated/v2");
            hash.update(realm);
            hash.update(policy.digest);
            let rotating = Rotating {
                tickets: ConnectionTickets::new(owner.clone(), hash.finalize().into()),
                slot,
            };
            if rotating.enabled() {
                config.send_tls13_tickets = 1;
                config.ticketer = Arc::new(rotating);
            }
        }
    }
}
