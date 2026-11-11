//! Keep slow client-side buffering, actual upstream sockets, and target
//! occupancy separate. A single target cannot reserve all network slots.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::task::TaskTracker;

const MAX_TARGETS: usize = 1024;
pub(super) const MEMORY_UNIT: u64 = 4096;

pub(in crate::http_runtime) struct Admission {
    limit_per_target: usize,
    targets: Mutex<HashMap<String, Weak<Semaphore>>>,
    pub(super) prefix_memory: Arc<Semaphore>,
    pub(super) diagnostic_slots: Arc<Semaphore>,
    pub(in crate::http_runtime) diagnostics: TaskTracker,
}

impl Admission {
    pub(in crate::http_runtime) fn new(capacity: usize) -> Self {
        Self {
            limit_per_target: (capacity * 3 / 4).max(1),
            targets: Mutex::new(HashMap::new()),
            // 16 MiB of process-wide logical prefix allocation.
            prefix_memory: Arc::new(Semaphore::new(4096)),
            diagnostic_slots: Arc::new(Semaphore::new((capacity / 4).clamp(1, 16))),
            diagnostics: TaskTracker::new(),
        }
    }

    pub(super) fn try_target(&self, key: String) -> Option<OwnedSemaphorePermit> {
        let mut targets = self
            .targets
            .lock()
            .expect("FastCGI target map not poisoned");
        let current = if let Some(current) = targets.get(&key).and_then(Weak::upgrade) {
            current
        } else {
            if targets.len() >= MAX_TARGETS {
                targets.retain(|_, existing| existing.strong_count() != 0);
                if targets.len() >= MAX_TARGETS {
                    return None;
                }
            }
            let current = Arc::new(Semaphore::new(self.limit_per_target));
            targets.insert(key, Arc::downgrade(&current));
            current
        };
        // This does not await, and no external work holds the map lock.
        current.try_acquire_owned().ok()
    }
}
