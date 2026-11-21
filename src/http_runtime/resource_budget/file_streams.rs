use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

use super::{BudgetError, BudgetSnapshot};

pub(crate) struct FileStreams {
    pub(super) shared: Arc<Admission>,
    wait: Duration,
}

pub(crate) struct Admission {
    state: Mutex<BudgetSnapshot>,
    ready: Notify,
}

pub(crate) struct Permit(Arc<Admission>);
struct WaitPermit(Arc<Admission>);

impl FileStreams {
    pub(super) fn new(limit: usize, waiting: usize, wait: Duration) -> Self {
        Self {
            shared: Admission::new(limit, waiting),
            wait,
        }
    }

    pub(crate) async fn acquire(&self) -> Result<Permit, BudgetError> {
        let queued = {
            let mut state = self.shared.lock();
            if state.waiting == 0 && state.running < state.running_limit {
                state.running += 1;
                return Ok(Permit(self.shared.clone()));
            }
            if state.waiting >= state.waiting_limit {
                state.rejected = state.rejected.saturating_add(1);
                return Err(BudgetError::Overloaded);
            }
            state.waiting += 1;
            WaitPermit(self.shared.clone())
        };
        let enter = self.enter();
        let result = if self.wait.is_zero() {
            Ok(enter.await)
        } else {
            tokio::time::timeout(self.wait, enter).await
        };
        drop(queued);
        result.map_err(|_| {
            let mut state = self.shared.lock();
            state.rejected = state.rejected.saturating_add(1);
            BudgetError::Overloaded
        })
    }

    async fn enter(&self) -> Permit {
        loop {
            let ready = self.shared.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            {
                let mut state = self.shared.lock();
                if state.running < state.running_limit {
                    state.running += 1;
                    return Permit(self.shared.clone());
                }
            }
            ready.await;
        }
    }

    pub(super) fn snapshot(&self) -> BudgetSnapshot {
        self.shared.snapshot()
    }
}

impl Admission {
    pub(super) fn new(limit: usize, waiting: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(BudgetSnapshot {
                running_limit: limit,
                waiting_limit: waiting,
                running: 0,
                waiting: 0,
                rejected: 0,
            }),
            ready: Notify::new(),
        })
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<Permit> {
        let mut state = self.lock();
        if state.running >= state.running_limit {
            state.rejected = state.rejected.saturating_add(1);
            return None;
        }
        state.running += 1;
        Some(Permit(self.clone()))
    }

    pub(super) fn update(&self, sample: usize, reliable: bool, allow_waiting: bool) {
        let wake = {
            let mut state = self.lock();
            // Missing observations may shrink the budget conservatively.
            let limit = if reliable {
                sample
            } else {
                state.running_limit.min(sample)
            };
            let grow = limit > state.running_limit;
            state.running_limit = limit;
            if allow_waiting {
                state.waiting_limit = limit;
            }
            grow && state.waiting != 0 && state.running < limit
        };
        if wake {
            self.ready.notify_waiters();
        }
    }

    pub(super) fn snapshot(&self) -> BudgetSnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BudgetSnapshot> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let wake = {
            let mut state = self.0.lock();
            state.running -= 1;
            state.waiting != 0 && state.running < state.running_limit
        };
        if wake {
            self.0.ready.notify_one();
        }
    }
}

impl Drop for WaitPermit {
    fn drop(&mut self) {
        let wake = {
            let mut state = self.0.lock();
            state.waiting -= 1;
            state.waiting != 0 && state.running < state.running_limit
        };
        if wake {
            self.0.ready.notify_one();
        }
    }
}
