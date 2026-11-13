//! Root-owned, bounded database identities shared across configuration generations.
//! Only weak database owners are cached: the last real handler/command retires
//! the descriptor. An async gate is per path, never global across disk waits.
use super::{
    actor::DatabaseOwner,
    resources::{Resources, Scope},
};
use anyhow::{Result, anyhow, ensure};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

pub(super) struct Registry {
    slots: Mutex<Vec<Arc<Slot>>>,
    resources: Arc<Resources>,
}
struct Slot {
    path: PathBuf,
    authority: String,
    owner: AsyncMutex<Weak<DatabaseOwner>>,
    // Slot/key storage is charged until this actual metadata owner retires.
    _credit: Arc<Scope>,
}
impl Registry {
    pub fn new(resources: Arc<Resources>) -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            resources,
        }
    }
    pub fn clear(&self) {
        let old = {
            let mut slots = self
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *slots)
        };
        drop(old);
    }
    pub async fn open(
        &self,
        path: &Path,
        authority: &str,
        cancel: CancellationToken,
    ) -> Result<Arc<DatabaseOwner>> {
        ensure!(path.is_absolute(), "ACME database path must be absolute");
        let slot = {
            let mut slots = self
                .slots
                .lock()
                .map_err(|_| anyhow!("ACME database registry unavailable"))?;
            if let Some(slot) = slots.iter().find(|slot| slot.path == path) {
                ensure!(
                    slot.authority == authority,
                    "ACME authority storage identity collision"
                );
                slot.clone()
            } else {
                ensure!(slots.len() < 64, "ACME database identity capacity exceeded");
                let credit = self.resources.scope(cancel.clone(), true)?;
                use std::os::unix::ffi::OsStrExt;
                let bytes = path
                    .as_os_str()
                    .as_bytes()
                    .len()
                    .checked_add(authority.len())
                    .and_then(|n| {
                        n.checked_add(
                            std::mem::size_of::<Slot>() + std::mem::size_of::<Arc<Slot>>() + 128,
                        )
                    })
                    .ok_or_else(|| anyhow!("ACME registry capacity exceeded"))?;
                credit.reserve(bytes)?;
                slots
                    .try_reserve_exact(1)
                    .map_err(|_| anyhow!("ACME registry allocation failed"))?;
                let slot = Arc::new(Slot {
                    path: path.to_path_buf(),
                    authority: authority.to_owned(),
                    owner: AsyncMutex::new(Weak::new()),
                    _credit: credit,
                });
                slots.push(slot.clone());
                slot
            }
        };
        let mut owner = tokio::select! {biased;
            _=cancel.cancelled()=>return Err(anyhow!("ACME preparation cancelled")),
            _=self.resources.cancel.cancelled()=>return Err(anyhow!("ACME services stopped")),
            guard=slot.owner.lock()=>guard,
        };
        if let Some(owner) = owner.upgrade() {
            return Ok(owner);
        }
        let opened = DatabaseOwner::open(slot.path.clone(), self.resources.clone(), cancel).await?;
        *owner = Arc::downgrade(&opened);
        Ok(opened)
    }
}
