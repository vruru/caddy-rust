//! One independently scheduled key-ring owner per process-wide standard ring
//! or actual distributed storage namespace. No locks or I/O in ticket reads.
use super::config::{Provider, Settings};
use super::go_gob::{self, Persisted};
use super::{ring, ticket::KeySet};
use crate::certstore::FsStore;
use anyhow::{Result, anyhow, ensure};
use arc_swap::ArcSwapOption;
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

const STEK_FILE: &str = "stek/stek.bin";
const STEK_LOCK: &str = "stek_check";
const MIN_BACKOFF: Duration = Duration::from_millis(20);
const MAX_BACKOFF: Duration = Duration::from_secs(8);
const CLOCK_RECHECK: Duration = Duration::from_secs(3600);

struct Published {
    epoch: u64,
    settings: Settings,
    ring: Option<Arc<Persisted>>,
    ticket_keys: Option<KeySet>,
}
impl Published {
    fn new(epoch: u64, settings: Settings, ring: Option<Persisted>) -> Self {
        // Build key schedules before publication; a handshake never waits for
        // another handshake or for a key schedule to be prepared.
        let ticket_keys = ring.as_ref().and_then(KeySet::derive);
        Self {
            epoch,
            settings,
            ring: ring.map(Arc::new),
            ticket_keys,
        }
    }
}

pub struct Owner {
    store: Option<FsStore>,
    // Held by actual rotation I/O or a prepared publication permit. No global
    // lock is held while waiting here or during any disk operation.
    operation: Arc<Mutex<()>>,
    published: ArcSwapOption<Published>,
    changed: Notify,
    worker_epoch: AtomicU64,
}

pub struct Activation {
    owner: Arc<Owner>,
    _gate: OwnedMutexGuard<()>,
    next: Arc<Published>,
}
impl Activation {
    pub(crate) fn generation(&self) -> u64 {
        self.next.epoch
    }

    /// Synchronous publication only; external operations are finished before
    /// reserve returns. Dropping this permit leaves the old ring untouched.
    /// The root transaction has at most one ticket owner: commit or drop this
    /// permit before joining any superseded worker.
    pub fn commit(self) {
        self.owner.published.store(Some(self.next.clone()));
        self.owner.changed.notify_waiters();
    }
}

impl Owner {
    pub fn standard() -> Arc<Self> {
        Self::new(None)
    }
    pub fn distributed(store: FsStore) -> Arc<Self> {
        Self::new(Some(store))
    }
    fn new(store: Option<FsStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            operation: Arc::new(Mutex::new(())),
            published: ArcSwapOption::empty(),
            changed: Notify::new(),
            worker_epoch: AtomicU64::new(0),
        })
    }

    pub async fn reserve(
        self: &Arc<Self>,
        epoch: u64,
        settings: Settings,
        cancel: CancellationToken,
    ) -> Result<Activation> {
        self.reserve_inner(epoch, settings, cancel, true).await
    }

    /// A known predecessor may be restored without reading disk. A
    /// distributed owner first serves Full; its committed worker reads the
    /// actual current shared state under the original storage lease.
    #[cfg(feature = "native-run")]
    pub(crate) async fn reserve_restore(
        self: &Arc<Self>,
        epoch: u64,
        settings: Settings,
        cancel: CancellationToken,
    ) -> Result<Activation> {
        self.reserve_inner(epoch, settings, cancel, false).await
    }

    async fn reserve_inner(
        self: &Arc<Self>,
        epoch: u64,
        settings: Settings,
        cancel: CancellationToken,
        read_distributed: bool,
    ) -> Result<Activation> {
        ensure!(
            matches!(settings.provider(), Provider::Distributed { .. }) == self.store.is_some(),
            "session ticket storage mode changed"
        );
        let gate = tokio::time::timeout(io_limit(&settings), self.enter(&cancel))
            .await
            .map_err(|_| anyhow!("session ticket owner is busy"))??;
        let current = self.published.load_full();
        ensure!(
            epoch > 0 && current.as_ref().is_none_or(|current| current.epoch < epoch),
            "session ticket generation is stale"
        );
        let at = SystemTime::now();
        let ring = if self.store.is_some() && !read_distributed {
            None
        } else if let Some(store) = &self.store {
            let current = with_deadline(&cancel, io_limit(&settings), |_| async {
                read_shared(store).await
            })
            .await?;
            // Read-only candidate. A missing/overdue ring is initialized or
            // rotated under the original lock by the committed generation.
            current
                .as_ref()
                .map(|old| ring::bounded_view(old, &settings, false))
                .transpose()?
        } else {
            let previous = current
                .as_ref()
                .and_then(|published| published.ring.as_deref());
            let adjusted = previous
                .map(|old| ring::bounded_view(old, &settings, true))
                .transpose()?;
            Some(if adjusted.as_ref().is_none_or(|ring| ring.next <= at) {
                ring::rotate(previous, &settings, at)?
            } else {
                adjusted.ok_or_else(|| anyhow!("session ticket state unavailable"))?
            })
        };
        ensure!(!cancel.is_cancelled(), "session ticket operation cancelled");
        Ok(Activation {
            owner: self.clone(),
            _gate: gate,
            next: Arc::new(Published::new(epoch, settings, ring)),
        })
    }

    async fn enter(&self, cancel: &CancellationToken) -> Result<OwnedMutexGuard<()>> {
        tokio::select! { biased;
            _=cancel.cancelled()=>Err(anyhow!("session ticket operation cancelled")),
            gate=self.operation.clone().lock_owned()=>Ok(gate),
        }
    }

    /// The generation's caller owns and joins this future. A later
    /// activation immediately wakes it; it cannot persist after that commit.
    pub async fn run(self: &Arc<Self>, epoch: u64, cancel: CancellationToken) {
        if cancel.is_cancelled()
            || !self
                .published
                .load()
                .as_ref()
                .is_some_and(|current| current.epoch == epoch)
            || self.worker_epoch.fetch_max(epoch, Ordering::AcqRel) >= epoch
        {
            return;
        }
        let mut failures = 0_u32;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let Some(current) = self
                .published
                .load_full()
                .filter(|current| current.epoch == epoch)
            else {
                return;
            };
            if cancel.is_cancelled() {
                return;
            }
            let now = SystemTime::now();
            let until_due = current
                .ring
                .as_ref()
                .and_then(|ring| ring.next.duration_since(now).ok())
                .unwrap_or_default();
            if failures > 0 || until_due > Duration::ZERO {
                let delay = if failures > 0 {
                    MIN_BACKOFF
                        .saturating_mul(1 << failures.min(8))
                        .min(MAX_BACKOFF)
                } else {
                    until_due.min(CLOCK_RECHECK)
                };
                tokio::select! { biased;
                    _=cancel.cancelled()=>return,
                    _=&mut changed=>continue,
                    _=tokio::time::sleep(delay)=>{}
                }
            }
            if failures == 0
                && current
                    .ring
                    .as_ref()
                    .is_some_and(|ring| ring.next > SystemTime::now())
            {
                continue;
            }
            match self.refresh_owned(epoch, &cancel).await {
                Ok(false) => return,
                Ok(true) => failures = 0,
                Err(_) if cancel.is_cancelled() => return,
                Err(_) => {
                    failures = failures.saturating_add(1);
                    // Report one event per failing streak; logging cannot expose
                    // paths, time fields, or ticket key bytes.
                    if failures == 1 {
                        eprintln!("tls event=stek_rotation_failed");
                    }
                }
            }
        }
    }

    async fn refresh_owned(
        self: &Arc<Self>,
        epoch: u64,
        cancel: &CancellationToken,
    ) -> Result<bool> {
        // The running task owns the per-owner gate through all store I/O,
        // including an operation that has already entered the blocking pool.
        // Dropping its waiter cancels it, but does not release the gate early.
        let child = cancel.child_token();
        let _guard = child.clone().drop_guard();
        let owner = self.clone();
        tokio::spawn(async move { owner.refresh(epoch, &child).await })
            .await
            .map_err(|_| anyhow!("session ticket rotation worker failed"))?
    }

    async fn refresh(&self, epoch: u64, cancel: &CancellationToken) -> Result<bool> {
        let _gate = self.enter(cancel).await?;
        let Some(current) = self
            .published
            .load_full()
            .filter(|current| current.epoch == epoch)
        else {
            return Ok(false);
        };
        let now = SystemTime::now();
        if current.ring.as_ref().is_some_and(|ring| ring.next > now) {
            return Ok(true);
        }
        let settings = &current.settings;
        let ring = if let Some(store) = &self.store {
            with_deadline(cancel, io_limit(settings), |child| async move {
                let lease = store.lock(STEK_LOCK, child.clone()).await?;
                let operation = async {
                    let state = read_shared(store).await?;
                    ensure!(!child.is_cancelled(), "session ticket operation cancelled");
                    lease.check().await?;
                    let now = SystemTime::now();
                    if let Some(state) = &state
                        && state.next > now
                    {
                        return ring::bounded_view(state, settings, false);
                    }
                    let next = ring::rotate(state.as_ref(), settings, now)?;
                    let bytes = go_gob::encode(&next)?;
                    ensure!(!child.is_cancelled(), "session ticket operation cancelled");
                    store.store_fenced(STEK_FILE, &bytes, &lease).await?;
                    Ok(next)
                }
                .await;
                let release = lease.release().await;
                let value = operation?;
                release?;
                Ok(value)
            })
            .await?
        } else {
            ring::rotate(current.ring.as_deref(), settings, now)?
        };
        ensure!(!cancel.is_cancelled(), "session ticket operation cancelled");
        self.published.store(Some(Arc::new(Published::new(
            epoch,
            settings.clone(),
            Some(ring),
        ))));
        Ok(true)
    }

    pub(super) fn with_ticket_keys<T>(&self, f: impl FnOnce(&KeySet) -> Option<T>) -> Option<T> {
        let current = self.published.load_full()?;
        let ring = current.ring.as_ref()?;
        if !ring::allowed_at(ring, &current.settings, SystemTime::now()) {
            return None;
        }
        f(current.ticket_keys.as_ref()?)
    }

    /// Whether handshakes can currently use a ring. A missing or stale ring
    /// must fall back to a complete TLS handshake.
    pub fn available(&self) -> bool {
        self.with_ticket_keys(|_| Some(())).is_some()
    }
}

async fn read_shared(store: &FsStore) -> Result<Option<Persisted>> {
    store
        .load(STEK_FILE)
        .await?
        .map(|bytes| go_gob::decode(&bytes))
        .transpose()
}

fn io_limit(settings: &Settings) -> Duration {
    (settings.rotation_interval() / 2).clamp(Duration::from_millis(250), Duration::from_secs(30))
}

async fn with_deadline<T, F, Fut>(cancel: &CancellationToken, timeout: Duration, f: F) -> Result<T>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let child = cancel.child_token();
    let _guard = child.clone().drop_guard();
    let operation = f(child.clone());
    tokio::pin!(operation);
    tokio::select! { biased;
        _=cancel.cancelled()=>{
            child.cancel();
            let _=operation.await;
            Err(anyhow!("session ticket operation cancelled"))
        },
        _=tokio::time::sleep(timeout)=>{
            child.cancel();
            let _=operation.await;
            Err(anyhow!("session ticket storage operation timed out"))
        },
        result=&mut operation=>result
    }
}
