//! ACME-only admission, owned byte credits and bounded CPU work. These slots
//! never consume a normal template root/CPU permit. Owners have no strong edge
//! back to a controller, database registry or configuration generation.
use super::bolt::{self, Budget};
use anyhow::{Result, anyhow};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const HEADER: usize = 4096;
pub(super) struct Resources {
    pub cpu: Arc<Semaphore>,
    pub network: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
    admission: Mutex<bool>,
    counts: Arc<Counts>,
}
#[derive(Default)]
struct Counts {
    scopes: AtomicUsize,
    bytes: AtomicUsize,
    changed: tokio::sync::Notify,
}
impl Resources {
    pub fn new(memory: Arc<Semaphore>) -> Arc<Self> {
        let concurrency = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(8);
        Arc::new(Self {
            cpu: Arc::new(Semaphore::new(concurrency)),
            network: Arc::new(Semaphore::new(concurrency)),
            memory,
            requests: Arc::new(Semaphore::new(64)),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            admission: Mutex::new(false),
            counts: Arc::new(Counts::default()),
        })
    }
    pub fn scope(&self, cancel: CancellationToken, persistent: bool) -> Result<Arc<Scope>> {
        let gate = self
            .admission
            .lock()
            .map_err(|_| anyhow!("ACME admission unavailable"))?;
        if *gate || self.cancel.is_cancelled() || cancel.is_cancelled() {
            return Err(anyhow!("ACME services stopped"));
        }
        let admission = if persistent {
            None
        } else {
            Some(
                self.requests
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| anyhow!("ACME request capacity exceeded"))?,
            )
        };
        let loan = self
            .memory
            .clone()
            .try_acquire_many_owned(HEADER as u32)
            .map_err(|_| anyhow!("ACME memory capacity exceeded"))?;
        self.counts.scopes.fetch_add(1, Ordering::Relaxed);
        self.counts.bytes.fetch_add(HEADER, Ordering::Relaxed);
        Ok(Arc::new(Scope {
            loan: Mutex::new(Some(loan)),
            memory: self.memory.clone(),
            admission,
            root_cancel: self.cancel.clone(),
            cancel,
            deadline: Instant::now() + Duration::from_secs(30),
            work: AtomicU64::new(0),
            failure: AtomicU8::new(0),
            counts: self.counts.clone(),
        }))
    }
    pub async fn shutdown(&self) -> Result<()> {
        {
            let mut gate = self
                .admission
                .lock()
                .map_err(|_| anyhow!("ACME admission unavailable"))?;
            // Publish closed admission before releasing the gate. Cancellation
            // and tracker completion can invoke arbitrary registered wakers.
            *gate = true;
        }
        self.cancel.cancel();
        self.tasks.close();
        tokio::time::timeout(Duration::from_secs(45), self.tasks.wait())
            .await
            .map_err(|_| anyhow!("ACME owned workers remain supervised"))?;
        Ok(())
    }
    pub fn diagnostics(&self) -> (usize, usize) {
        (
            self.counts.scopes.load(Ordering::Acquire),
            self.counts.bytes.load(Ordering::Acquire),
        )
    }
    pub async fn wait_for_retirement(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let notified = self.counts.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.diagnostics() == (0, 0) {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| anyhow!("ACME output owners remain supervised"))?;
        }
    }
    pub fn owned<F, T>(&self, future: F) -> Result<tokio::task::JoinHandle<T>>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Obtain the actual runtime before admission. A missing or already
        // shut-down runtime must never drop the caller's future under our gate.
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow!("ACME task runtime unavailable"))?;
        let gate = self
            .admission
            .lock()
            .map_err(|_| anyhow!("ACME admission unavailable"))?;
        if *gate || self.cancel.is_cancelled() {
            drop(gate);
            return Err(anyhow!("ACME services stopped"));
        }
        // tokio-util0.7.20 TrackedFuture stores its future before its token.
        // Construct admission under the gate, then spawn outside it: a closed
        // runtime may synchronously destroy the unpolled payload. The token
        // keeps shutdown waiting until that real destruction has completed.
        let task = self.tasks.track_future(future);
        drop(gate);
        Ok(runtime.spawn(task))
    }
}

pub(super) struct Scope {
    loan: Mutex<Option<OwnedSemaphorePermit>>,
    memory: Arc<Semaphore>,
    admission: Option<OwnedSemaphorePermit>,
    root_cancel: CancellationToken,
    pub cancel: CancellationToken,
    deadline: Instant,
    work: AtomicU64,
    failure: AtomicU8,
    counts: Arc<Counts>,
}
impl Scope {
    pub fn reject_capacity(&self) -> bolt::Error {
        self.failure
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .ok();
        bolt::Error::Limit
    }
    pub fn remaining(&self) -> bolt::Result<Duration> {
        self.check()?;
        Ok(self.deadline.saturating_duration_since(Instant::now()))
    }
    fn fail<T>(&self, kind: u8, error: bolt::Error) -> bolt::Result<T> {
        self.failure
            .compare_exchange(0, kind, Ordering::AcqRel, Ordering::Acquire)
            .ok();
        Err(error)
    }
    pub fn check(&self) -> bolt::Result<()> {
        if self.failure.load(Ordering::Acquire) == 1 {
            return Err(bolt::Error::Limit);
        }
        if self.cancel.is_cancelled() || self.root_cancel.is_cancelled() {
            return self.fail(2, bolt::Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return self.fail(2, bolt::Error::Timeout);
        }
        Ok(())
    }
    pub fn resource_failure(&self) -> bool {
        self.failure.load(Ordering::Acquire) != 0
    }
    pub fn reserve(&self, bytes: usize) -> bolt::Result<()> {
        self.check()?;
        if bytes == 0 {
            return Ok(());
        }
        let n = match u32::try_from(bytes) {
            Ok(n) => n,
            Err(_) => return self.fail(1, bolt::Error::Limit),
        };
        let mut loan = self
            .loan
            .lock()
            .map_err(|_| bolt::Error::Corrupt("ACME byte account unavailable"))?;
        let current = loan.as_ref().map_or(0, OwnedSemaphorePermit::num_permits);
        if current
            .checked_add(bytes)
            .is_none_or(|n| n > 192 * 1024 * 1024)
        {
            return self.fail(1, bolt::Error::Limit);
        }
        // try_acquire does not queue or run a host callback under this lock.
        let extra = match self.memory.clone().try_acquire_many_owned(n) {
            Ok(p) => p,
            Err(_) => return self.fail(1, bolt::Error::Limit),
        };
        if let Some(loan) = loan.as_mut() {
            loan.merge(extra);
        } else {
            *loan = Some(extra);
        }
        self.counts.bytes.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }
    pub fn work(&self, units: usize) -> bolt::Result<()> {
        self.check()?;
        let result = self
            .work
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(units as u64)
                    .filter(|new| *new <= 32_000_000)
            });
        if result.is_err() {
            return self.fail(1, bolt::Error::Limit);
        }
        Ok(())
    }
    /// Only after the closed producer's entire transient workspace has retired.
    /// Remaining value/header capacities plus the owner header stay charged.
    pub fn retain(&self, bytes: usize) -> bolt::Result<()> {
        let keep = bytes.checked_add(HEADER).ok_or(bolt::Error::Limit)?;
        let mut loan = self
            .loan
            .lock()
            .map_err(|_| bolt::Error::Corrupt("ACME byte account unavailable"))?;
        let current = loan.as_ref().map_or(0, OwnedSemaphorePermit::num_permits);
        if keep > current {
            return Err(bolt::Error::Corrupt("ACME output exceeds prepaid owner"));
        }
        let refund = loan.as_mut().and_then(|p| p.split(current - keep));
        drop(loan);
        self.counts
            .bytes
            .fetch_sub(current - keep, Ordering::Relaxed);
        drop(refund);
        Ok(())
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let permits = self
            .loan
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let bytes = permits
            .as_ref()
            .map_or(0, OwnedSemaphorePermit::num_permits);
        drop(permits);
        self.counts.bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.counts.scopes.fetch_sub(1, Ordering::Release);
        self.counts.changed.notify_waiters();
    }
}
impl crate::cert_cpu::MaterialOwner for Scope {
    fn reserve(&self, bytes: usize) -> Result<()> {
        Scope::reserve(self, bytes).map_err(Into::into)
    }
}
pub(super) struct Meter(pub Arc<Scope>);
impl Budget for Meter {
    fn charge(&mut self, bytes: usize) -> bolt::Result<()> {
        self.0.reserve(bytes)
    }
    fn work(&mut self, units: usize) -> bolt::Result<()> {
        self.0.work(units)
    }
}
/// Generic only within this closed controller. Data ALWAYS retires first.
pub(super) struct Leased<T> {
    pub value: T,
    pub scope: Arc<Scope>,
}
