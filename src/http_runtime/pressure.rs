//! FIFO cancellation candidates; real resource owners alone release permits.
use std::collections::BTreeMap;
use std::sync::Weak;
use std::sync::{Arc, Mutex};

pub(super) trait Victim: Send + Sync {
    fn try_cancel(&self) -> bool;
    fn completion(&self) -> Option<Arc<Completion>> {
        None
    }
}

struct State {
    next: u64,
    entries: BTreeMap<u64, Weak<dyn Victim>>,
}

pub(super) struct Registry {
    state: Mutex<State>,
}

impl Registry {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                next: 0,
                entries: BTreeMap::new(),
            }),
        })
    }

    pub(super) fn register(
        self: &Arc<Self>,
        victim: &Arc<dyn Victim>,
    ) -> anyhow::Result<Registration> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Registry mutex poisoned"))?;
        let id = guard
            .next
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Registry id overflow"))?;
        guard.next = id;
        guard.entries.insert(id, Arc::downgrade(victim));
        drop(guard);
        Ok(Registration {
            registry: self.clone(),
            id,
        })
    }

    pub(super) fn evict_oldest(&self) -> bool {
        self.evict_if(|_| Some(())).is_some()
    }
    pub(super) fn evict_oldest_with_completion(&self) -> Option<Arc<Completion>> {
        self.evict_if(|victim| victim.completion())
    }
    fn evict_if<T>(&self, prepare: impl Fn(&dyn Victim) -> Option<T>) -> Option<T> {
        loop {
            let (_, weak) = self.state.lock().ok()?.entries.pop_first()?;
            // Acquire any needed completion capability before cancellation.
            // No cancellation or callback runs while holding this registry.
            if let Some(victim) = weak.upgrade()
                && let Some(ready) = prepare(victim.as_ref())
                && victim.try_cancel()
            {
                return Some(ready);
            }
        }
    }
}

pub(super) struct Registration {
    registry: Arc<Registry>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut guard = self
            .registry
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard.entries.remove(&self.id);
    }
}

/// Only the real resource owner marks completion after dropping its resources.
pub(super) struct Completion {
    sender: tokio::sync::watch::Sender<bool>,
}
impl Completion {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            sender: tokio::sync::watch::channel(false).0,
        })
    }
    pub(super) fn finish(&self) {
        self.sender.send_replace(true);
    }
    pub(super) async fn wait(&self) -> anyhow::Result<()> {
        let mut receiver = self.sender.subscribe();
        loop {
            if *receiver.borrow_and_update() {
                return Ok(());
            }
            receiver
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("Resource completion unavailable"))?;
        }
    }
}
