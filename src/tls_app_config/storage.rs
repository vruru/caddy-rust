use crate::cert_status::OcspResources;
#[cfg(feature = "native-run")]
use crate::stek::TicketOwners;
use crate::{cert_automation::AutomationResources, certstore::FsStore};
use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct CertificatePaths {
    pub default_storage: PathBuf,
    pub state_root: PathBuf,
    /// Captured once for this transaction, never read from a later cwd.
    pub cwd: PathBuf,
}

pub(super) struct Store {
    pub fs: FsStore,
    #[cfg(feature = "native-run")]
    pub(super) root: PathBuf,
    state: PathBuf,
}

/// Root shares one resource object across policies and configuration generations.
/// Storage and issuance pools are bounded independently of the runtime CPU count.
pub struct CertificateResources {
    pub(crate) acme_server:Arc<crate::acme_server::Shared>,
    stores: Mutex<HashMap<PathBuf, Arc<Store>>>,
    #[cfg(feature = "native-run")]
    pub(super) ticket_owners: TicketOwners,
    pub(super) resident_cache: Arc<super::resident_cache::ResidentCache>,
    pub(super) issuance: Arc<AutomationResources>,
    pub(super) ocsp: Arc<OcspResources>,
    pub(super) pki: Arc<crate::local_pki::LocalPkiResources>,
    pub(super) io: Arc<Semaphore>,
    pub(super) cpu: Arc<Semaphore>,
    pub(super) revoked: Notify,
    /// Bytes reserved before receiving/parsing manager material, shared across reloads.
    pub(super) external_bytes: Arc<Semaphore>,
    /// HTTP CA preparation network admission, shared across all generations.
    #[cfg(feature = "native-run")]
    pub(super) ca_fetch: Arc<Semaphore>,
}
impl CertificateResources {
    pub fn new() -> Result<Self> {
        let issuance = Arc::new(AutomationResources::new(10, 2)?);
        let ocsp = Arc::new(OcspResources::with_cpu(8, 2, issuance.cpu_slots())?);
        Self::with_shared(issuance, ocsp)
    }
    pub fn with_shared(
        issuance: Arc<AutomationResources>,
        ocsp: Arc<OcspResources>,
    ) -> Result<Self> {
        Ok(Self {
            acme_server:crate::acme_server::Shared::new(),
            stores: Mutex::new(HashMap::new()),
            #[cfg(feature = "native-run")]
            ticket_owners: TicketOwners::new(),
            resident_cache: Arc::new(super::resident_cache::ResidentCache::new()),
            cpu: issuance.cpu_slots(),
            issuance,
            ocsp,
            pki: Arc::new(crate::local_pki::LocalPkiResources::new(
                std::thread::available_parallelism()
                    .map_or(1, usize::from)
                    .min(4),
            )?),
            io: Arc::new(Semaphore::new(8)),
            revoked: Notify::new(),
            external_bytes: Arc::new(Semaphore::new(256 * 1024 * 1024)),
            #[cfg(feature = "native-run")]
            ca_fetch: Arc::new(Semaphore::new(4)),
        })
    }
    pub(super) async fn store(
        self: &Arc<Self>,
        root: PathBuf,
        paths: &CertificatePaths,
        cancel: CancellationToken,
    ) -> Result<Arc<Store>> {
        let root = absolute(&paths.cwd, &root);
        let state = paths.state_root.clone();
        let this = self.clone();
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(anyhow!("certificate storage cancelled")),
            permit = self.io.clone().acquire_owned() => permit.map_err(|_| anyhow!("certificate storage stopped"))?,
        };
        let worker_cancel = cancel.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            ensure!(
                !worker_cancel.is_cancelled(),
                "certificate storage cancelled"
            );
            let predicted = canonical_destination(&root)?;
            let key = Sha256::digest(predicted.as_os_str().as_encoded_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let state = canonical_destination(&state.join("certificate-stores").join(key))?;
            let existing = {
                let stores = this
                    .stores
                    .lock()
                    .map_err(|_| anyhow!("certificate storage pool unavailable"))?;
                let existing = stores.get(&predicted).cloned();
                ensure!(
                    existing.is_some() || stores.len() < 256,
                    "certificate storage pool limit exceeded"
                );
                existing
            };
            if let Some(store) = existing {
                let metadata = std::fs::metadata(&predicted)
                    .map_err(|_| anyhow!("certificate storage root changed"))?;
                ensure!(
                    metadata.is_dir()
                        && (metadata.dev(), metadata.ino()) == store.fs.root_identity(),
                    "certificate storage root changed"
                );
                ensure!(
                    store.state == state,
                    "certificate storage state root changed"
                );
                let metadata = std::fs::metadata(&state)
                    .map_err(|_| anyhow!("certificate storage state root changed"))?;
                ensure!(
                    metadata.is_dir()
                        && (metadata.dev(), metadata.ino()) == store.fs.state_identity(),
                    "certificate storage state root changed"
                );
                return Ok(store);
            }
            let fs = FsStore::open(predicted.clone(), state.clone())?;
            let actual = std::fs::canonicalize(&predicted)
                .map_err(|_| anyhow!("certificate storage root unavailable"))?;
            ensure!(
                actual == predicted,
                "certificate storage root changed during preparation"
            );
            let metadata = std::fs::metadata(&actual)
                .map_err(|_| anyhow!("certificate storage root unavailable"))?;
            ensure!(
                (metadata.dev(), metadata.ino()) == fs.root_identity(),
                "certificate storage root changed during preparation"
            );
            let state_metadata = std::fs::metadata(&state)
                .map_err(|_| anyhow!("certificate storage state root unavailable"))?;
            ensure!(
                (state_metadata.dev(), state_metadata.ino()) == fs.state_identity(),
                "certificate storage state root changed during preparation"
            );
            let store = Arc::new(Store {
                fs,
                #[cfg(feature = "native-run")]
                root: actual.clone(),
                state,
            });
            let mut stores = this
                .stores
                .lock()
                .map_err(|_| anyhow!("certificate storage pool unavailable"))?;
            if let Some(existing) = stores.get(&actual) {
                ensure!(
                    existing.fs.root_identity() == store.fs.root_identity(),
                    "certificate storage root changed during preparation"
                );
                ensure!(
                    existing.state == store.state
                        && existing.fs.state_identity() == store.fs.state_identity(),
                    "certificate storage state root changed during preparation"
                );
                return Ok(existing.clone());
            }
            ensure!(
                stores.len() < 256,
                "certificate storage pool limit exceeded"
            );
            stores.insert(actual, store.clone());
            Ok(store)
        });
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                let _ = worker.await;
                Err(anyhow!("certificate storage cancelled"))
            }
            result = &mut worker => result.map_err(|_| anyhow!("certificate storage worker failed"))?,
        }
    }
}

pub(super) fn absolute(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    }
}

fn canonical_destination(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "certificate storage root must be absolute"
    );
    let mut ancestor = path.to_owned();
    let mut suffix = Vec::new();
    loop {
        match std::fs::canonicalize(&ancestor) {
            Ok(mut base) => {
                for component in suffix.into_iter().rev() {
                    base.push(component);
                }
                let mut normalized = PathBuf::new();
                for component in base.components() {
                    match component {
                        Component::ParentDir => {
                            ensure!(normalized.pop(), "invalid certificate storage root");
                        }
                        Component::CurDir => {}
                        _ => normalized.push(component.as_os_str()),
                    }
                }
                return Ok(normalized);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or_else(|| anyhow!("invalid certificate storage root"))?
                    .to_owned();
                suffix.push(name);
                ensure!(
                    ancestor.pop() && suffix.len() <= 64,
                    "invalid certificate storage root"
                );
            }
            Err(_) => return Err(anyhow!("certificate storage root unavailable")),
        }
    }
}
