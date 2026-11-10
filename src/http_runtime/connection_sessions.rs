use super::TlsIdentity;
use rustls::server::StoresServerSessions;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

const CACHE_CAPACITY: usize = 256;

pub(super) struct HandshakeState {
    pub identity: OnceLock<Arc<TlsIdentity>>,
    pub selected_chain: OnceLock<[u8; 32]>,
    resumed: Mutex<Option<Arc<TlsIdentity>>>,
}

impl HandshakeState {
    pub(super) fn new() -> Self {
        Self {
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

struct Entry {
    secret: Zeroizing<Vec<u8>>,
    owner: Arc<HandshakeState>,
}

struct Cache {
    entries: HashMap<Vec<u8>, Entry>,
    order: VecDeque<Vec<u8>>,
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cache")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

pub(super) struct SharedSessions {
    state: Mutex<Cache>,
}

impl SharedSessions {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(Cache {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }
}

impl fmt::Debug for SharedSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSessions")
            .field(
                "state",
                &self.state.lock().unwrap_or_else(|e| e.into_inner()),
            )
            .finish_non_exhaustive()
    }
}

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
        let (result, discarded) = {
            let mut cache = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            let entry = cache.entries.get(key)?;
            // An unfinished handshake has not established an identity yet.
            // Leave its entry intact and safely fall back to a full handshake.
            let identity = entry.owner.identity.get()?.clone();
            if !identity.resumable_for(current_chain) {
                cache.order.retain(|k| k.as_slice() != key);
                (None, cache.entries.remove(key))
            } else {
                let value = entry.secret.to_vec();
                let discarded = if consume {
                    cache.order.retain(|k| k.as_slice() != key);
                    cache.entries.remove(key)
                } else {
                    None
                };
                (Some((value, identity)), discarded)
            }
        };
        drop(discarded);
        let (value, identity) = result?;
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
        let mut abandoned: Vec<Entry> = Vec::with_capacity(2);
        let mut guard = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());

        if guard.entries.contains_key(&key) {
            guard.order.retain(|k| k != &key);
        }

        let entry = Entry {
            secret: Zeroizing::new(value),
            owner: Arc::clone(&self.handshake),
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
