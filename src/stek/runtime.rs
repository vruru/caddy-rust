#[cfg(feature = "native-run")]
use super::{Activation, Owner, Settings};
#[cfg(feature = "native-run")]
use crate::certstore::FsStore;
#[cfg(feature = "native-run")]
use anyhow::{Result, anyhow, ensure};
#[cfg(feature = "native-run")]
use sha2::{Digest, Sha256};
#[cfg(feature = "native-run")]
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex, Weak},
};
#[cfg(feature = "native-run")]
use tokio_util::sync::CancellationToken;

#[cfg(feature = "native-run")]
const OWNER_LIMIT: usize = 256;
#[cfg(feature = "native-run")]
type StorageIdentity = (u64, u64);

/// TLS application state; one mode is pinned by each HTTP generation.
#[derive(Clone, Default)]
pub(crate) enum TicketRuntime {
    #[default]
    RuntimeDefault,
    #[cfg(feature = "native-run")]
    Disabled,
    #[cfg(feature = "native-run")]
    Rotating {
        owner: Arc<Owner>,
        settings: Settings,
        realm: [u8; 32],
    },
}
#[cfg(feature = "native-run")]
impl TicketRuntime {
    pub(crate) async fn reserve(
        &self,
        generation: u64,
        restore_only: bool,
        cancel: CancellationToken,
    ) -> Result<Option<Activation>> {
        let Self::Rotating {
            owner, settings, ..
        } = self
        else {
            return Ok(None);
        };
        let activation = if restore_only {
            owner
                .reserve_restore(generation, settings.clone(), cancel)
                .await?
        } else {
            owner.reserve(generation, settings.clone(), cancel).await?
        };
        Ok(Some(activation))
    }
}

#[cfg(feature = "native-run")]
pub(crate) struct TicketOwners {
    standard: Arc<Owner>,
    distributed: Mutex<HashMap<StorageIdentity, Weak<Owner>>>,
}
#[cfg(feature = "native-run")]
impl TicketOwners {
    pub(crate) fn new() -> Self {
        Self {
            standard: Owner::standard(),
            distributed: Mutex::new(HashMap::new()),
        }
    }
    pub(crate) fn standard(&self, settings: Settings) -> TicketRuntime {
        TicketRuntime::Rotating {
            owner: self.standard.clone(),
            settings,
            realm: realm(None),
        }
    }

    /// Both the checked storage identity and the canonical configured
    /// namespace come from the same verified StorePool entry. The local
    /// descriptor identity deduplicates owners; it is not a cross-host ID.
    pub(crate) fn distributed(
        &self,
        store: &FsStore,
        namespace: &Path,
        settings: Settings,
    ) -> Result<TicketRuntime> {
        let identity = store.root_identity();
        let mut owners = self
            .distributed
            .lock()
            .map_err(|_| anyhow!("session ticket owner pool unavailable"))?;
        owners.retain(|_, owner| owner.strong_count() > 0);
        let owner = if let Some(owner) = owners.get(&identity).and_then(Weak::upgrade) {
            owner
        } else {
            ensure!(
                owners.len() < OWNER_LIMIT,
                "session ticket owner pool limit exceeded"
            );
            let owner = Owner::distributed(store.clone());
            owners.insert(identity, Arc::downgrade(&owner));
            owner
        };
        Ok(TicketRuntime::Rotating {
            owner,
            settings,
            realm: realm(Some(namespace)),
        })
    }
}

/// A matching path never grants resumption by itself: a second process also
/// needs the authenticated matching seed from the explicitly shared store.
#[cfg(feature = "native-run")]
fn realm(namespace: Option<&Path>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"caddy-rust/stek/tcp/unauthenticated-https/v1");
    if let Some(namespace) = namespace {
        let bytes = namespace.as_os_str().as_encoded_bytes();
        hash.update([1]);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    } else {
        hash.update([0]);
    }
    hash.finalize().into()
}
