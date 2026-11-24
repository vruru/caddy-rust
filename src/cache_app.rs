//! Native, bounded app-owned OTTER-compatible HTTP representation storage.
//! Entries own copied bytes only; no request/generation guards or replay spools.
#[path = "cache_app/config.rs"]
mod config;
use bytes::Bytes;
pub use config::Config;
use http::{HeaderMap, StatusCode};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const RETAINED_BYTES: usize = 128 * 1024 * 1024;
static BYTE_BUDGET: std::sync::OnceLock<Arc<AtomicUsize>> = std::sync::OnceLock::new();
static FLIGHT_KEYS: AtomicUsize = AtomicUsize::new(0);
static FLIGHT_WAITERS: std::sync::OnceLock<Arc<AtomicUsize>> = std::sync::OnceLock::new();
pub struct Runtime {
    pub config: Arc<Config>,
    pub(crate) store: Arc<Store>,
}
impl Runtime {
    pub(crate) fn log(&self, level: u8, event: &str) {
        if level >= self.config.log_level {
            eprintln!("cache: {event}");
        }
    }
    pub fn new(config: Arc<Config>, previous: Option<&Arc<Runtime>>) -> Arc<Self> {
        let store = previous
            .filter(|p| p.config.capacity == config.capacity)
            .map(|p| p.store.clone())
            .unwrap_or_else(|| {
                Arc::new(Store {
                    capacity: config.capacity,
                    flights: Mutex::new(HashMap::new()),
                    waiters: FLIGHT_WAITERS
                        .get_or_init(|| Arc::new(AtomicUsize::new(0)))
                        .clone(),
                    state: Mutex::new(State {
                        entries: VecDeque::new(),
                        index: HashMap::new(),
                        collect_cursor: 0,
                    }),
                    bytes: BYTE_BUDGET
                        .get_or_init(|| Arc::new(AtomicUsize::new(0)))
                        .clone(),
                })
            });
        Arc::new(Self { config, store })
    }
}
pub(crate) struct Charge {
    used: Arc<AtomicUsize>,
    held: usize,
}
impl Charge {
    pub(crate) fn grow(&mut self, n: usize) -> bool {
        if self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(n).filter(|v| *v <= RETAINED_BYTES)
            })
            .is_err()
        {
            return false;
        }
        self.held += n;
        true
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        self.used.fetch_sub(self.held, Ordering::AcqRel);
    }
}
pub(crate) struct Entry {
    pub key: String,
    pub vary: Vec<(http::HeaderName, Vec<Vec<u8>>)>,
    pub headers: HeaderMap,
    pub status: StatusCode,
    pub chunks: Vec<Bytes>,
    pub length: usize,
    pub inserted: Instant,
    pub lifetime: Duration,
    pub initial_age: u64,
    pub charge: Charge,
    pub touched: AtomicBool,
}
pub(crate) struct Store {
    capacity: usize,
    state: Mutex<State>,
    bytes: Arc<AtomicUsize>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    waiters: Arc<AtomicUsize>,
}
struct State {
    entries: VecDeque<Arc<Entry>>,
    index: HashMap<String, Vec<Weak<Entry>>>,
    collect_cursor: usize,
}
impl State {
    fn unindex(&mut self, e: &Arc<Entry>) {
        if let Some(items) = self.index.get_mut(&e.key) {
            items.retain(|w| w.as_ptr() != Arc::as_ptr(e));
            if items.is_empty() {
                self.index.remove(&e.key);
            }
        }
    }
    fn collect(&mut self, retired: &mut Vec<Arc<Entry>>) {
        // At most sixteen entries are visited per request without disturbing
        // recency order; payloads drop only after the state lock is released.
        let mut remaining = self.entries.len().min(16);
        while remaining > 0 && !self.entries.is_empty() {
            remaining -= 1;
            if self.collect_cursor >= self.entries.len() {
                self.collect_cursor = 0;
            }
            let idx = self.collect_cursor;
            let expired_or_stale = {
                let e = &self.entries[idx];
                let registered = self
                    .index
                    .get(&e.key)
                    .is_some_and(|v| v.iter().any(|w| w.as_ptr() == Arc::as_ptr(e)));
                e.inserted.elapsed() >= e.lifetime || !registered
            };
            if expired_or_stale {
                if let Some(e) = self.entries.remove(idx) {
                    self.unindex(&e);
                    retired.push(e);
                }
            } else {
                self.collect_cursor += 1;
            }
        }
    }
}
impl Store {
    fn evict_for(&self, needed: usize) -> bool {
        if needed > RETAINED_BYTES {
            return false;
        }
        loop {
            if self.bytes.load(Ordering::Acquire).saturating_add(needed) <= RETAINED_BYTES {
                return true;
            }
            let mut retired = Vec::new();
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let mut reclaimed = 0usize;
                let total = state.entries.len();
                for _ in 0..total {
                    let Some(e) = state.entries.pop_front() else {
                        break;
                    };
                    let registered = state
                        .index
                        .get(&e.key)
                        .is_some_and(|v| v.iter().any(|w| w.as_ptr() == Arc::as_ptr(&e)));
                    if e.inserted.elapsed() >= e.lifetime || !registered {
                        state.unindex(&e);
                        reclaimed = reclaimed.saturating_add(e.charge.held);
                        retired.push(e);
                    } else {
                        state.entries.push_back(e);
                    }
                }
                if reclaimed < needed {
                    let live = state.entries.len();
                    let mut scanned = 0usize;
                    while reclaimed < needed && scanned < live {
                        let Some(e) = state.entries.pop_front() else {
                            break;
                        };
                        scanned += 1;
                        if e.touched.swap(false, Ordering::AcqRel) && !state.entries.is_empty() {
                            state.entries.push_back(e);
                            continue;
                        }
                        state.unindex(&e);
                        reclaimed = reclaimed.saturating_add(e.charge.held);
                        retired.push(e);
                    }
                    while reclaimed < needed {
                        let Some(e) = state.entries.pop_front() else {
                            break;
                        };
                        state.unindex(&e);
                        reclaimed = reclaimed.saturating_add(e.charge.held);
                        retired.push(e);
                    }
                }
            }
            if retired.is_empty() {
                return self.bytes.load(Ordering::Acquire).saturating_add(needed) <= RETAINED_BYTES;
            }
            drop(retired);
        }
    }
    pub(crate) fn reserve(&self, n: usize) -> Option<Charge> {
        let mut c = Charge {
            used: self.bytes.clone(),
            held: 0,
        };
        if self.grow(&mut c, n) {
            Some(c)
        } else {
            None
        }
    }
    pub(crate) fn grow(&self, charge: &mut Charge, n: usize) -> bool {
        if charge.grow(n) {
            return true;
        }
        self.evict_for(n) && charge.grow(n)
    }
    pub(crate) fn lookup(&self, key: &str, headers: &HeaderMap) -> Option<Arc<Entry>> {
        let mut retired = Vec::new();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.collect(&mut retired);
        let found = state
            .index
            .get(key)?
            .iter()
            .rev()
            .filter_map(Weak::upgrade)
            .find(|e| {
                e.inserted.elapsed() < e.lifetime
                    && e.vary.iter().all(|(n, v)| {
                        headers
                            .get_all(n)
                            .iter()
                            .map(|h| h.as_bytes())
                            .eq(v.iter().map(Vec::as_slice))
                    })
            });
        if let Some(entry) = &found {
            entry.touched.store(true, Ordering::Relaxed);
        }
        found
    }
    pub(crate) fn insert(&self, entry: Entry) {
        if self.capacity < 2 {
            return;
        }
        let mut retired = Vec::new();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.collect(&mut retired);
        let replaced = {
            let variants = state.index.entry(entry.key.clone()).or_default();
            let before = variants.len();
            let mut stale_ptrs = Vec::new();
            variants.retain(|w| match w.upgrade() {
                Some(e) if e.vary != entry.vary && e.inserted.elapsed() < e.lifetime => true,
                Some(e) => {
                    stale_ptrs.push(Arc::as_ptr(&e));
                    false
                }
                None => false,
            });
            if before != variants.len() && !stale_ptrs.is_empty() {
                stale_ptrs
            } else {
                Vec::new()
            }
        };
        if !replaced.is_empty() {
            let mut keep = VecDeque::with_capacity(state.entries.len());
            while let Some(e) = state.entries.pop_front() {
                if replaced.contains(&Arc::as_ptr(&e)) {
                    retired.push(e);
                } else {
                    keep.push_back(e);
                }
            }
            state.entries = keep;
        }
        while state.entries.len() >= self.capacity / 2 {
            if let Some(e) = state.entries.pop_front() {
                state.unindex(&e);
                retired.push(e);
            }
        }
        let entry = Arc::new(entry);
        state
            .index
            .entry(entry.key.clone())
            .or_default()
            .push(Arc::downgrade(&entry));
        state.entries.push_back(entry);
    }
}

// A flight retains only bounded synchronization metadata. Its leader lease is
// owned by the request/capture, never by a cached Entry.
pub(crate) enum FlightDecision {
    Leader(FlightLease),
    Wait(FlightWaiter),
}
struct Flight {
    done: tokio::sync::watch::Sender<bool>,
    waiters: AtomicUsize,
    _charge: Charge,
}
impl Drop for Flight {
    fn drop(&mut self) {
        FLIGHT_KEYS.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(crate) struct FlightLease {
    store: Weak<Store>,
    key: String,
    flight: Arc<Flight>,
}
pub(crate) struct FlightWaiter {
    receiver: tokio::sync::watch::Receiver<bool>,
    flight: Arc<Flight>,
    total: Arc<AtomicUsize>,
    _charge: Charge,
}
impl FlightWaiter {
    pub(crate) async fn wait(&mut self) {
        let _ = self.receiver.wait_for(|done| *done).await;
    }
}
impl Drop for FlightWaiter {
    fn drop(&mut self) {
        self.flight.waiters.fetch_sub(1, Ordering::AcqRel);
        self.total.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Drop for FlightLease {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            let mut flights = store.flights.lock().unwrap_or_else(|e| e.into_inner());
            if flights
                .get(&self.key)
                .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
            {
                flights.remove(&self.key);
            }
        }
        self.flight.done.send_replace(true);
    }
}
impl Store {
    pub(crate) fn flight(self: &Arc<Self>, key: &str) -> Option<FlightDecision> {
        let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(flight) = flights.get(key) {
            let charge = self.reserve(512)?;
            if flight
                .waiters
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < 32).then_some(n + 1)
                })
                .is_err()
            {
                return None;
            }
            if self
                .waiters
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < 512).then_some(n + 1)
                })
                .is_err()
            {
                flight.waiters.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            return Some(FlightDecision::Wait(FlightWaiter {
                receiver: flight.done.subscribe(),
                flight: flight.clone(),
                total: self.waiters.clone(),
                _charge: charge,
            }));
        }
        if flights.len() >= 128 {
            return None;
        }
        let charge = self.reserve(key.len().saturating_mul(2).saturating_add(2048))?;
        if FLIGHT_KEYS
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 128).then_some(n + 1)
            })
            .is_err()
        {
            return None;
        }
        let (done, _) = tokio::sync::watch::channel(false);
        let flight = Arc::new(Flight {
            done,
            waiters: AtomicUsize::new(0),
            _charge: charge,
        });
        flights.insert(key.into(), flight.clone());
        Some(FlightDecision::Leader(FlightLease {
            store: Arc::downgrade(self),
            key: key.into(),
            flight,
        }))
    }
}
