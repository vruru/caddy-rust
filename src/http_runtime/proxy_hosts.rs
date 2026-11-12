//! proxy_hosts.rs: HostState plus a bounded passive-health failure ledger.
//! Architecture 21183d32 / boundary 796c8ac7. This module does not change the
//! selection strategy (12) or the lease algorithm.
//!
//! Lock order: the only allowed nesting is PassiveOwner.touched -> HostState.ledger.
//! It is never reversed. No await or IO happens while a lock is held. Nothing here spawns tasks.
//! PassiveOwner::cancel costs O(touched + runs). Run it in an owned, bounded worker or
//! cleanup task, never while holding the root publication lock.
//! Interface notes and minimal fixes (at most 5 lines):
//! 1. new() -> Arc<Self> cannot report counter exhaustion, so owner identity is the Arc<()> address. Buckets clone it to pin the address.
//! 2. Concurrent record() calls may arrive with non-monotonic `now`, so runs are inserted sorted by `until`. FIFO stays exact and only equal expiries merge.
//! 3. touched cleanup must not remove an entry whose ledger insert is still in flight, so an `inflight` counter was added.
//! 4. record() on a canceled owner, or with duration == 0, returns Ok without recording. That generation is already void or passive health is disabled.

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Runtime-wide run budget: Semaphore::new(RUN_BUDGET), shared by every HostState.
pub const RUN_BUDGET: usize = 65_536;
pub const MAX_RUNS_PER_BUCKET: usize = RUN_BUDGET;
pub const TOUCHED_CAP: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerFullKind {
    Budget,
    BucketRuns,
    Touched,
    Counter,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerFull {
    pub kind: LedgerFullKind,
}

const fn full(kind: LedgerFullKind) -> LedgerFull {
    LedgerFull { kind }
}

impl fmt::Display for LedgerFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            LedgerFullKind::Budget => "global failure-run budget exhausted",
            LedgerFullKind::BucketRuns => "per-owner bucket run cap reached",
            LedgerFullKind::Touched => "passive owner touched-host cap reached",
            LedgerFullKind::Counter => "failure counter overflow",
            LedgerFullKind::Deadline => "failure expiry instant overflow",
        };
        write!(f, "passive failure ledger full: {what}")
    }
}

impl Error for LedgerFull {}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Allocation address of the host's Arc. The Weak in touched keeps that allocation
/// alive, so the address cannot be reused while the entry exists.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct HostKey(usize);

impl HostKey {
    fn of(host: &Arc<HostState>) -> Self {
        Self(Arc::as_ptr(host).addr())
    }
}

/// Address of the owner's Arc<()>. Every bucket holds a clone (`_pin`), so the
/// address cannot be reused while any bucket for that owner exists.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct OwnerKey(usize);

struct Run {
    until: Instant,
    count: u64,
    _credit: OwnedSemaphorePermit,
}

struct Bucket {
    _pin: Arc<()>,
    count: u64,
    runs: VecDeque<Run>,
}

impl Bucket {
    /// Pops runs in order while until <= now. Dropping each Run returns its credit (RAII).
    fn expire(&mut self, now: Instant) -> (u64, usize) {
        let (mut fails, mut runs) = (0u64, 0usize);
        while self.runs.front().is_some_and(|r| r.until <= now) {
            if let Some(r) = self.runs.pop_front() {
                fails = fails.saturating_add(r.count);
                runs = runs.saturating_add(1);
            }
        }
        self.count = self.count.saturating_sub(fails);
        (fails, runs)
    }
}

#[derive(Default)]
struct LedgerInner {
    buckets: HashMap<OwnerKey, Bucket>,
    total: u64,
    runs: usize,
}

impl LedgerInner {
    fn subtract(&mut self, fails: u64, runs: usize) {
        self.total = self.total.saturating_sub(fails);
        self.runs = self.runs.saturating_sub(runs);
    }

    fn expire_all(&mut self, now: Instant) {
        let (mut fails, mut runs) = (0u64, 0usize);
        self.buckets.retain(|_, b| {
            let (f, r) = b.expire(now);
            fails = fails.saturating_add(f);
            runs = runs.saturating_add(r);
            !b.runs.is_empty()
        });
        self.subtract(fails, runs);
    }
}

struct FailLedger {
    budget: Arc<Semaphore>,
    inner: Mutex<LedgerInner>,
}

impl FailLedger {
    fn insert(&self, owner: &PassiveOwner, until: Instant, now: Instant) -> Result<(), LedgerFull> {
        let mut guard = lock(&self.inner);
        // Second cancel check, done under the ledger lock so it is serialized with cancel's remove_owner.
        if owner.canceled.load(Ordering::Acquire) {
            return Ok(());
        }
        let inner = &mut *guard;
        inner.expire_all(now);
        let key = owner.key();
        let total = inner
            .total
            .checked_add(1)
            .ok_or(full(LedgerFullKind::Counter))?;
        let mut slot = 0usize;
        if let Some(b) = inner.buckets.get_mut(&key) {
            let bucket_count = b
                .count
                .checked_add(1)
                .ok_or(full(LedgerFullKind::Counter))?;
            slot = b.runs.partition_point(|r| r.until < until);
            if let Some(r) = b.runs.get_mut(slot).filter(|r| r.until == until) {
                // Exactly equal expiry: merge the count. No new credit is used.
                r.count = r
                    .count
                    .checked_add(1)
                    .ok_or(full(LedgerFullKind::Counter))?;
                b.count = bucket_count;
                inner.total = total;
                return Ok(());
            }
            if b.runs.len() >= MAX_RUNS_PER_BUCKET {
                return Err(full(LedgerFullKind::BucketRuns));
            }
        }
        let runs = inner
            .runs
            .checked_add(1)
            .ok_or(full(LedgerFullKind::Counter))?;
        let credit = Arc::clone(&self.budget)
            .try_acquire_owned()
            .map_err(|_| full(LedgerFullKind::Budget))?;
        let b = inner.buckets.entry(key).or_insert_with(|| Bucket {
            _pin: Arc::clone(&owner.ident),
            count: 0,
            runs: VecDeque::new(),
        });
        b.count = b.count.saturating_add(1); // overflow already checked above
        let at = slot.min(b.runs.len());
        b.runs.insert(
            at,
            Run {
                until,
                count: 1,
                _credit: credit,
            },
        );
        inner.total = total;
        inner.runs = runs;
        Ok(())
    }

    /// Returns the bucket so the caller drops it, and its credits, after this lock is released.
    fn remove_owner(&self, key: OwnerKey) -> Option<Bucket> {
        let mut g = lock(&self.inner);
        let bucket = g.buckets.remove(&key)?;
        g.subtract(bucket.count, bucket.runs.len());
        Some(bucket)
    }

    fn has_live_bucket(&self, key: OwnerKey, now: Instant) -> bool {
        let mut g = lock(&self.inner);
        let Some(b) = g.buckets.get_mut(&key) else {
            return false;
        };
        let (fails, runs) = b.expire(now);
        let empty = b.runs.is_empty();
        if empty {
            g.buckets.remove(&key);
        }
        g.subtract(fails, runs);
        !empty
    }
}

/// Replaces the old Host. `running` is reused unchanged by the existing RequestLease (CAS reserve).
/// Dropping a HostState drops all of its buckets, which returns their credits.
pub struct HostState {
    pub running: AtomicU64,
    ledger: FailLedger,
}

impl HostState {
    pub fn new(budget: Arc<Semaphore>) -> Self {
        Self {
            running: AtomicU64::new(0),
            ledger: FailLedger {
                budget,
                inner: Mutex::new(LedgerInner::default()),
            },
        }
    }

    /// Synchronously and lazily removes expired runs, returns their credits exactly,
    /// and returns the current failure count.
    pub fn fails(&self, now: Instant) -> u64 {
        let mut g = lock(&self.ledger.inner);
        g.expire_all(now);
        g.total
    }

    /// Cost estimate (runs + buckets). PreparedSelection.needs_worker uses it to move
    /// expensive ledgers onto the existing bounded blocking lane.
    pub fn work_units(&self) -> usize {
        let g = lock(&self.ledger.inner);
        g.runs.saturating_add(g.buckets.len())
    }
}

struct InflightGuard<'a>(&'a AtomicU64);

impl<'a> InflightGuard<'a> {
    fn enter(counter: &'a AtomicU64) -> Result<Self, LedgerFull> {
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .map_err(|_| full(LedgerFullKind::Counter))?;
        Ok(Self(counter))
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// One per handler generation. Dropping it without cancel() leaves its runs to expire naturally.
pub struct PassiveOwner {
    ident: Arc<()>,
    duration: Duration,
    canceled: AtomicBool,
    inflight: AtomicU64,
    touched: Mutex<HashMap<HostKey, Weak<HostState>>>,
}

impl PassiveOwner {
    pub fn new(duration: Duration) -> Arc<Self> {
        Arc::new(Self {
            ident: Arc::new(()),
            duration,
            canceled: AtomicBool::new(false),
            inflight: AtomicU64::new(0),
            touched: Mutex::new(HashMap::new()),
        })
    }

    fn key(&self) -> OwnerKey {
        OwnerKey(Arc::as_ptr(&self.ident).addr())
    }

    pub fn record(&self, host: &Arc<HostState>, now: Instant) -> Result<(), LedgerFull> {
        if self.duration.is_zero() || self.canceled.load(Ordering::Acquire) {
            return Ok(());
        }
        let until = now
            .checked_add(self.duration)
            .ok_or(full(LedgerFullKind::Deadline))?;
        // Register in touched and release that lock, then take the ledger lock.
        // `_inflight` is decremented only after the ledger lock is released.
        let _inflight = self.register(host, now)?;
        host.ledger.insert(self, until, now)
    }

    fn register(
        &self,
        host: &Arc<HostState>,
        now: Instant,
    ) -> Result<InflightGuard<'_>, LedgerFull> {
        let key = HostKey::of(host);
        let mut map = lock(&self.touched);
        // Incremented while holding the touched lock. prune uses this to see in-flight inserts by others.
        let guard = InflightGuard::enter(&self.inflight)?;
        if !map.contains_key(&key) {
            if map.len() >= TOUCHED_CAP {
                self.prune(&mut map, now);
            }
            if map.len() >= TOUCHED_CAP {
                return Err(full(LedgerFullKind::Touched));
            }
            map.insert(key, Arc::downgrade(host));
        }
        Ok(guard)
    }

    /// Called with the touched lock held. Lock order is touched -> ledger, never reversed.
    /// Dead Weak entries are always removed. A "no bucket for this owner" entry is removed
    /// only when no other record is between registering and inserting, otherwise cancel could miss a bucket.
    fn prune(&self, map: &mut HashMap<HostKey, Weak<HostState>>, now: Instant) {
        let others_inflight = self.inflight.load(Ordering::Acquire) > 1;
        let owner = self.key();
        map.retain(|_, weak| match weak.upgrade() {
            None => false,
            Some(h) => others_inflight || h.ledger.has_live_bucket(owner, now),
        });
    }

    /// Sets canceled first, then takes a snapshot of touched and releases that lock,
    /// then removes only this owner's bucket from each host. Buckets are dropped outside
    /// the ledger lock, which returns their credits exactly.
    pub(super) fn mark_cancelled(&self) {
        self.canceled.store(true, Ordering::Release);
    }
    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        let snapshot = std::mem::take(&mut *lock(&self.touched));
        let owner = self.key();
        for weak in snapshot.into_values() {
            if let Some(host) = weak.upgrade() {
                let bucket = host.ledger.remove_owner(owner);
                drop(bucket);
            }
        }
    }
}
