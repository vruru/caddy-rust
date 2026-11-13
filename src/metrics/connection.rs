//! Independent observability connection metadata and abandonment owner.
//! No labels, generation reserve or certificate credits are borrowed.
use crate::outgoing_tls::{Resources, ScopeFactory};
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
pub(super) struct Connections {
    state: Mutex<State>,
    bytes: Arc<tokio::sync::Semaphore>,
}
impl Default for Connections {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            bytes: Arc::new(tokio::sync::Semaphore::new(8 << 20)),
        }
    }
}
#[derive(Default)]
struct State {
    closed: bool,
    owner: Option<Arc<Resources>>,
}
impl Connections {
    pub(super) fn factory(&self) -> Result<ScopeFactory> {
        let existing = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("observability connection state failed"))?;
            anyhow::ensure!(!state.closed, "observability connections stopped");
            state.owner.clone()
        };
        let owner = match existing {
            Some(owner) => owner,
            None => {
                // Construct outside the fence: a losing candidate's Drop may
                // cancel and wake. It has not constructed an executor/runtime.
                let candidate = Arc::new(
                    Resources::independent(self.bytes.clone())
                        .context("observability connection metadata admission refused")?,
                );
                let winner = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("observability connection state failed"))?;
                    anyhow::ensure!(!state.closed, "observability connections stopped");
                    if let Some(owner) = &state.owner {
                        owner.clone()
                    } else {
                        state.owner = Some(candidate.clone());
                        candidate.clone()
                    }
                };
                drop(candidate);
                winner
            }
        };
        // Runtime construction is synchronous, on the configuration CPU lane,
        // with no Process state lock held. close fences its own executor setup.
        owner
            .factory()
            .context("observability connection runtime preparation failed")
    }
    fn fence(&self) -> Option<Arc<Resources>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.owner.clone()
    }
    pub(super) fn close(&self) {
        if let Some(owner) = self.fence() {
            owner.close();
        }
    }
    pub(super) async fn shutdown(&self) -> Result<()> {
        if let Some(owner) = self.fence() {
            owner.shutdown().await?;
        }
        Ok(())
    }
}
// The last external Process drops State.owner. Internal connection IO retains
// only Master, so this independently closes it and breaks idle-runtime cycles.
