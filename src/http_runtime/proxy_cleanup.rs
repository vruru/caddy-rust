//! Bounded asynchronous reclamation of retired `PassiveOwner` ledgers.
//!
//! Invariants
//! - At most `MAX_GENERATIONS` reservations exist (current + staged + queued + working).
//!   Each queued/working job owns its reservation's permit until `cancel()` finished, so
//!   the queue (same capacity) cannot be full; `Full`/`Closed` are still handled.
//! - One lazily started, tracked async worker; `cancel()` (pure CPU, up to 65536 hosts)
//!   runs on a private `BlockingBudget(1, 0)`: never on the reactor, never under control.
//! - Owners must be exclusive to one generation (fresh `PassiveOwner`s per stage).
//!
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::runtime::Handle;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::task::TaskTracker;

use super::proxy_hosts::PassiveOwner;
// Adjust to the real path of the existing budget type.
use super::resource_budget::BlockingBudget;

/// Upper bound for current + staged + queued + working generations.
const MAX_GENERATIONS: usize = 64;
/// Irrelevant with 0 waiters (the single worker never contends); non-zero to be safe.
const BUDGET_WAIT: Duration = Duration::from_secs(1);
const CLOSED: &str = "passive owner cleanup is closed";

type Owners = Arc<[Arc<PassiveOwner>]>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Idempotent: a second `cancel()` on an owner finds an empty `touched` map.
fn cancel_all(owners: &[Arc<PassiveOwner>]) {
    for owner in owners {
        owner.cancel();
    }
}

/// Dedup by pointer (client maps may be shared across listeners). Duplicates would only
/// cost an extra no-op `cancel()`, so this is an optimisation, not a correctness need.
pub(super) fn dedup_owners<'a, I>(owners: I) -> Owners
where
    I: IntoIterator<Item = &'a Arc<PassiveOwner>>,
{
    let mut seen = HashSet::new();
    owners
        .into_iter()
        .filter(|o| seen.insert(Arc::as_ptr(*o) as usize))
        .cloned()
        .collect()
}

/// A retired generation's owners plus the permit that bounds outstanding work.
struct Job {
    owners: Owners,
    _permit: OwnedSemaphorePermit,
}

pub(super) struct Coordinator {
    slots: Arc<Semaphore>,
    /// `None` after `close()`. Also guards lazy worker start (no spawn after close).
    tx: Mutex<Option<mpsc::Sender<Job>>>,
    /// Taken exactly once by the first `reserve()`.
    rx: Mutex<Option<mpsc::Receiver<Job>>>,
    budget: Arc<BlockingBudget>,
    tasks: TaskTracker,
}

impl Coordinator {
    pub(super) fn new() -> Result<Arc<Self>> {
        let budget = Arc::new(BlockingBudget::new(1, 0, BUDGET_WAIT)?);
        let (tx, rx) = mpsc::channel(MAX_GENERATIONS);
        Ok(Arc::new(Self {
            slots: Arc::new(Semaphore::new(MAX_GENERATIONS)),
            tx: Mutex::new(Some(tx)),
            rx: Mutex::new(Some(rx)),
            budget,
            tasks: TaskTracker::new(),
        }))
    }

    /// Reserve a cleanup slot for a staged generation. `Ok(None)` when there is nothing
    /// to clean. Awaits (back-pressure) while 64 generations are outstanding; fails fast
    /// once closed. Cancel-safe: dropping the future releases everything.
    pub(super) async fn reserve(self: &Arc<Self>, owners: Owners) -> Result<Option<Reservation>> {
        if owners.is_empty() {
            return Ok(None);
        }
        let handle = Handle::try_current().map_err(|e| anyhow!("{CLOSED}: no runtime: {e}"))?;
        self.ensure_worker(&handle)?;
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| anyhow!(CLOSED))?;
        Ok(Some(Reservation {
            owners,
            permit: Mutex::new(Some(permit)),
            handle,
        }))
    }

    fn ensure_worker(&self, handle: &Handle) -> Result<()> {
        // Held across the spawn: either the worker is tracked before `close()` closes
        // the tracker, or we observe the close and refuse.
        let tx = lock(&self.tx);
        if tx.is_none() {
            return Err(anyhow!(CLOSED));
        }
        if let Some(rx) = lock(&self.rx).take() {
            let worker = worker(rx, Arc::clone(&self.budget), self.tasks.clone());
            self.tasks.spawn_on(worker, handle);
        }
        Ok(())
    }

    /// Never drops a job. Normal path: the queue cannot be full (permit invariant).
    /// Fallback (queue full/closed, or retire after close): a tracked blocking task that
    /// keeps the permit, so the total stays <= MAX_GENERATIONS.
    fn enqueue(&self, job: Job, handle: &Handle) {
        let job = {
            let tx = lock(&self.tx);
            match tx.as_ref() {
                None => job,
                Some(tx) => match tx.try_send(job) {
                    Ok(()) => return,
                    Err(TrySendError::Full(job) | TrySendError::Closed(job)) => job,
                },
            }
        };
        // `let job = job` forces capture of the whole job (edition-2021 closures would
        // otherwise capture only `job.owners` and release the permit early).
        self.tasks.spawn_blocking_on(
            move || {
                let job = job;
                cancel_all(&job.owners);
            },
            handle,
        );
    }

    /// Rejects new reservations, lets the worker drain everything already queued, then
    /// exit. Call after the current generation has been retired.
    pub(super) fn close(&self) {
        self.slots.close();
        drop(lock(&self.tx).take());
        self.tasks.close();
    }

    /// Waits for the worker, all fallback tasks and the budget's blocking threads to
    /// actually finish. Must be called after `close()`.
    pub(super) async fn wait(&self) {
        self.tasks.wait().await;
        // No budget runs can start any more: the only caller (the worker) has exited.
        let budget_tasks = self.budget.tasks();
        budget_tasks.close();
        budget_tasks.wait().await;
    }
}

/// Sequential: at most one `cancel()` batch in flight; exits once the sender is dropped
/// (close or coordinator drop) and the queue is drained.
async fn worker(mut rx: mpsc::Receiver<Job>, budget: Arc<BlockingBudget>, tasks: TaskTracker) {
    while let Some(job) = rx.recv().await {
        let owners = Arc::clone(&job.owners);
        if budget.run(move || cancel_all(&owners)).await.is_err() {
            // The closure may not have run (or only partially): rerun on a tracked
            // blocking thread. This worker is still alive, so the tracker is non-empty
            // and the spawn cannot race `wait()`.
            let owners = Arc::clone(&job.owners);
            let _ = tasks.spawn_blocking(move || cancel_all(&owners)).await;
        }
        drop(job); // releases the generation slot only after cleanup completed
    }
}

/// Held by a staged/published generation. Dropping it without `retire` (rollback
/// candidate that was never published) only releases the slot: it has no records.
pub(super) struct Reservation {
    owners: Owners,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    handle: Handle,
}

impl Reservation {
    /// Synchronous, O(owners), no blocking: instantly disables counting and hands full
    /// cleanup to the worker. Effective exactly once; later calls are no-ops.
    pub(super) fn retire(&self, coordinator: &Arc<Coordinator>) {
        let Some(permit) = lock(&self.permit).take() else {
            return;
        };
        for owner in self.owners.iter() {
            owner.mark_cancelled();
        }
        let job = Job {
            owners: Arc::clone(&self.owners),
            _permit: permit,
        };
        coordinator.enqueue(job, &self.handle);
    }
}
