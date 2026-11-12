use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
/// Credits stay with their allocation owner. Growth never waits on a request.
pub(super) struct Lease {
    pool: Arc<Semaphore>,
    held: AtomicUsize,
}
impl Lease {
    pub fn new(pool: Arc<Semaphore>, bytes: usize) -> Option<Self> {
        let lease = Self {
            pool,
            held: AtomicUsize::new(0),
        };
        lease.grow(bytes).then_some(lease)
    }
    pub fn grow(&self, bytes: usize) -> bool {
        let Ok(count) = u32::try_from(bytes) else {
            return false;
        };
        let Ok(permit) = self.pool.clone().try_acquire_many_owned(count) else {
            return false;
        };
        permit.forget();
        self.held.fetch_add(bytes, Ordering::Relaxed);
        true
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.pool.add_permits(self.held.load(Ordering::Relaxed));
    }
}

/// Constructor and native transport metadata share the same real lifetime.
/// Extra TLS parsing credits are separate from the mandatory 8 MiB headroom.
#[derive(Debug)]
pub(crate) struct Metadata {
    extra: std::sync::Mutex<Vec<tokio::sync::OwnedSemaphorePermit>>,
    _base: tokio::sync::OwnedSemaphorePermit,
}
impl Metadata {
    pub(super) fn new(base: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            _base: base,
            extra: Default::default(),
        }
    }
    pub(super) fn pay(&self, process: &super::Process, bytes: u32) -> anyhow::Result<()> {
        let credit = process
            .pay_labels(bytes)
            .ok_or_else(|| anyhow::anyhow!("metrics TLS metadata unavailable"))?;
        self.extra
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(credit);
        Ok(())
    }
}
