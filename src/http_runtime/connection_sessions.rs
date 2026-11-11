use super::TlsIdentity;
use crate::stek::{TicketRuntime, ticket::ConnectionTickets};
#[cfg(feature = "native-run")]
use rustls::server::NoServerSessionStorage;
use rustls::server::StoresServerSessions;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const CACHE_CAPACITY: usize = 256;
const SESSION_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The TLS config passed here is cloned per ordinary TCP handshake. Rotating
/// and disabled configurations never fall through to the session-ID cache.
pub(super) fn configure(
    config: &mut rustls::ServerConfig,
    runtime: &TicketRuntime,
    sessions: &Arc<SharedSessions>,
    state: &Arc<HandshakeState>,
    client_auth_configured: bool,
    policy_identity: [u8; 32],
) -> Option<Arc<ConnectionTickets>> {
    if client_auth_configured {
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_tls13_tickets = 0;
        config.max_early_data_size = 0;
        return None;
    }
    #[cfg(not(feature = "native-run"))]
    let _ = policy_identity;
    match runtime {
        TicketRuntime::RuntimeDefault => {
            config.send_tls13_tickets = 1;
            config.max_tls13_tickets = 0;
            config.max_early_data_size = 0;
            config.session_storage =
                Arc::new(PerConnectionSessions::new(sessions.clone(), state.clone()));
            None
        }
        #[cfg(feature = "native-run")]
        TicketRuntime::Disabled => {
            config.session_storage = Arc::new(NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            config.max_tls13_tickets = 0;
            config.max_early_data_size = 0;
            None
        }
        #[cfg(feature = "native-run")]
        TicketRuntime::Rotating { owner, realm, .. } => {
            use sha2::{Digest, Sha256};
            let mut bound = Sha256::new();
            bound.update(b"caddy-connection-ticket-policy-v1");
            bound.update(realm);
            bound.update(policy_identity);
            let tickets = Arc::new(ConnectionTickets::new(
                owner.clone(),
                bound.finalize().into(),
            ));
            config.ticketer = tickets.clone();
            config.session_storage = Arc::new(NoServerSessionStorage {});
            config.send_tls13_tickets = 1;
            config.max_tls13_tickets = 0;
            config.max_early_data_size = 0;
            Some(tickets)
        }
    }
}

pub(super) struct HandshakeState {
    pub session_name: Arc<str>,
    pub identity: OnceLock<Arc<TlsIdentity>>,
    pub selected_chain: OnceLock<[u8; 32]>,
    resumed: Mutex<Option<Arc<TlsIdentity>>>,
}

impl HandshakeState {
    pub(super) fn new(session_name: Arc<str>) -> Self {
        Self {
            session_name,
            identity: OnceLock::new(),
            selected_chain: OnceLock::new(),
            resumed: Mutex::new(None),
        }
    }

    pub(super) fn resumed(&self) -> Option<Arc<TlsIdentity>> {
        let guard = self.resumed.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    }
}

impl fmt::Debug for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeState")
            .field("identity", &self.identity.get().map(|_| "..."))
            .finish_non_exhaustive()
    }
}

struct Entry<Owner> {
    secret: Zeroizing<Vec<u8>>,
    owner: Arc<Owner>,
    inserted: Instant,
}

impl<Owner> Entry<Owner> {
    fn expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.inserted) >= SESSION_LIFETIME
    }
}

pub(super) enum OwnerCheck<T> {
    Pending,
    Reject,
    Accept(T),
}

struct Cache<Owner> {
    entries: HashMap<Vec<u8>, Entry<Owner>>,
    order: VecDeque<Vec<u8>>,
}

impl<Owner> fmt::Debug for Cache<Owner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cache")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

pub(super) struct SessionCache<Owner> {
    state: Mutex<Cache<Owner>>,
}

impl<Owner> SessionCache<Owner> {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(Cache {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub(super) fn remember(
        &self,
        key: Vec<u8>,
        value: Zeroizing<Vec<u8>>,
        owner: Arc<Owner>,
    ) -> bool {
        let mut abandoned: Vec<Entry<Owner>> = Vec::with_capacity(2);
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        // Insertion order is also age order, including replacement. Retire
        // stale secrets during activity without a task per server/connection;
        // zeroize their bytes only after releasing the cache mutex.
        while let Some(oldest) = guard.order.front() {
            if guard
                .entries
                .get(oldest)
                .is_some_and(|entry| !entry.expired_at(now))
            {
                break;
            }
            let oldest = guard.order.pop_front().expect("front checked");
            if let Some(removed) = guard.entries.remove(&oldest) {
                abandoned.push(removed);
            }
        }

        if guard.entries.contains_key(&key) {
            guard.order.retain(|k| k != &key);
        }

        let entry = Entry {
            secret: value,
            owner,
            inserted: now,
        };

        if let Some(replaced) = guard.entries.insert(key.clone(), entry) {
            abandoned.push(replaced);
        }
        guard.order.push_back(key);

        while guard.order.len() > CACHE_CAPACITY {
            if let Some(evict_key) = guard.order.pop_front()
                && let Some(removed) = guard.entries.remove(&evict_key)
            {
                abandoned.push(removed);
            }
        }

        drop(guard);

        for e in abandoned.drain(..) {
            drop(e);
        }

        true
    }

    pub(super) fn lookup<T>(
        &self,
        key: &[u8],
        consume: bool,
        check: impl FnOnce(&Owner) -> OwnerCheck<T>,
    ) -> Option<(Vec<u8>, T)> {
        let (result, discarded) = {
            let mut cache = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let entry = cache.entries.get(key)?;
            let check = if entry.expired_at(Instant::now()) {
                OwnerCheck::Reject
            } else {
                check(entry.owner.as_ref())
            };
            match check {
                OwnerCheck::Pending => {
                    return None;
                }
                OwnerCheck::Reject => {
                    cache.order.retain(|k| k.as_slice() != key);
                    (None, cache.entries.remove(key))
                }
                OwnerCheck::Accept(t) => {
                    let value = entry.secret.to_vec();
                    let discarded = if consume {
                        cache.order.retain(|k| k.as_slice() != key);
                        cache.entries.remove(key)
                    } else {
                        None
                    };
                    (Some((value, t)), discarded)
                }
            }
        };
        drop(discarded);
        result
    }
}

impl<Owner> fmt::Debug for SessionCache<Owner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSessions")
            .field(
                "state",
                &self.state.lock().unwrap_or_else(|e| e.into_inner()),
            )
            .finish_non_exhaustive()
    }
}

pub(super) type SharedSessions = SessionCache<HandshakeState>;

pub(super) struct PerConnectionSessions {
    shared: Arc<SharedSessions>,
    handshake: Arc<HandshakeState>,
}

impl PerConnectionSessions {
    pub(super) fn new(shared: Arc<SharedSessions>, handshake: Arc<HandshakeState>) -> Self {
        Self { shared, handshake }
    }
    fn lookup(&self, key: &[u8], consume: bool) -> Option<Vec<u8>> {
        // rustls 0.23.46 calls the version-aware resolver before consulting
        // session storage. An absent actual selection must never use a hint.
        let current_chain = self.handshake.selected_chain.get()?;
        let (value, identity) =
            self.shared
                .lookup(key, consume, |owner| match owner.identity.get() {
                    None => OwnerCheck::Pending,
                    Some(identity) => {
                        if identity.session_name() == self.handshake.session_name.as_ref()
                            && identity.resumable_for(current_chain)
                        {
                            OwnerCheck::Accept(identity.clone())
                        } else {
                            OwnerCheck::Reject
                        }
                    }
                })?;
        *self
            .handshake
            .resumed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(identity);
        Some(value)
    }
}

impl fmt::Debug for PerConnectionSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PerConnectionSessions")
            .field("shared", &self.shared)
            .field("handshake", &self.handshake)
            .finish_non_exhaustive()
    }
}

impl StoresServerSessions for PerConnectionSessions {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.shared
            .remember(key, Zeroizing::new(value), Arc::clone(&self.handshake))
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
