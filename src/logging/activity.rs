//! A plan's accepted work stays live until the last real operation releases it.
//! Waiting, timing out or dropping a delivery ticket cannot release this token.
use anyhow::{Result, anyhow, ensure};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
pub(super) struct Activity {
    state: Mutex<State>,
    changed: watch::Sender<usize>,
    limit: usize,
}
struct State {
    open: bool,
    active: usize,
}
pub(super) struct Token {
    owner: Arc<Activity>,
}
impl Activity {
    pub(super) fn new(limit: usize) -> Result<Arc<Self>> {
        ensure!(limit > 0, "invalid logging activity limit");
        let (changed, _) = watch::channel(0);
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                open: true,
                active: 0,
            }),
            changed,
            limit,
        }))
    }
    /// The caller creates this token under the same short admission fence used to
    /// obtain the plan's immutable data. All fanout jobs clone the returned Arc.
    pub(super) fn begin(self: &Arc<Self>) -> Result<Arc<Token>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(state.open, "logging plan is closed");
        ensure!(
            state.active < self.limit,
            "logging plan work limit exceeded"
        );
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| anyhow!("logging activity count overflow"))?;
        self.changed.send_replace(state.active);
        Ok(Arc::new(Token {
            owner: self.clone(),
        }))
    }
    pub(super) fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.open = false;
        self.changed.send_replace(state.active);
    }
    pub(super) fn active(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).active
    }
    /// This is only a wait. It never owns cleanup or changes operation lifetime.
    pub(super) async fn drained(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            if *changed.borrow_and_update() == 0 {
                return;
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
}
impl Drop for Token {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.active > 0 {
            state.active -= 1;
        }
        self.owner.changed.send_replace(state.active);
    }
}
