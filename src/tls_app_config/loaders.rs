use super::{material::Material, model::ManualSource, services::PrepareContext, storage::absolute};
use anyhow::{Result, anyhow, ensure};
use futures_util::{StreamExt, stream};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const MAX_MATERIAL: usize = 12 * 1024 * 1024;
#[path = "loaders/manual_pem.rs"]
mod manual_pem;

#[derive(Default)]
struct MaterialBudget {
    bytes: AtomicUsize,
    count: AtomicUsize,
    visited: AtomicUsize,
}
impl MaterialBudget {
    fn reserve(&self, material: &Material) -> Result<()> {
        let bytes = material
            .certificate
            .len()
            .checked_add(material.key.len())
            .ok_or_else(|| anyhow!("configured certificate size overflow"))?;
        self.count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count
                    .checked_add(1)
                    .filter(|next| *next <= crate::tls_resolver::MAX_CERTIFICATES)
            })
            .map_err(|_| anyhow!("configured certificate capacity exceeded"))?;
        self.bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= 64 * 1024 * 1024)
            })
            .map_err(|_| anyhow!("configured certificate memory budget exceeded"))?;
        Ok(())
    }
}
fn material(
    certificate: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    tags: Vec<String>,
    budget: &MaterialBudget,
) -> Result<Material> {
    // A certificate input may itself be a combined bundle containing a key.
    let certificate = Zeroizing::new(certificate);
    ensure!(
        certificate.len() <= MAX_MATERIAL && key.len() <= MAX_MATERIAL,
        "configured certificate input exceeds size limit"
    );
    let (certificate, key) = manual_pem::pair(&certificate, &key)?;
    prepared_material(certificate, key, tags, budget)
}
fn prepared_material(
    certificate: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    tags: Vec<String>,
    budget: &MaterialBudget,
) -> Result<Material> {
    let mut material = Material::from_pem(certificate, key)?;
    material.tags = tags;
    budget.reserve(&material)?;
    Ok(material)
}

pub(super) async fn blocking<T: Send + 'static>(
    slots: Arc<Semaphore>,
    cancel: CancellationToken,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    crate::cert_cpu::run(slots, cancel, operation).await
}

async fn loading<T: Send + 'static>(
    io: Arc<Semaphore>,
    cpu: Arc<Semaphore>,
    cancel: CancellationToken,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(anyhow!("certificate loading cancelled")),
        permit = cpu.acquire_owned() => permit.map_err(|_| anyhow!("certificate CPU operations stopped"))?,
    };
    blocking(io, cancel, move || {
        let _permit = permit;
        operation()
    })
    .await
}

pub(super) async fn load_manual(
    sources: &[ManualSource],
    storage_root: &Path,
    context: &PrepareContext,
    cancel: CancellationToken,
) -> Result<Vec<Material>> {
    let store_needed = sources
        .iter()
        .any(|source| matches!(source, ManualSource::Storage { .. }));
    let store = if store_needed {
        Some(
            context
                .resources
                .store(storage_root.to_owned(), &context.paths, cancel.clone())
                .await?,
        )
    } else {
        None
    };
    let budget = Arc::new(MaterialBudget::default());
    let work = cancel.child_token();
    let mut pending = stream::iter(sources.iter().cloned().enumerate())
        .map(|(index, source)| {
            let store = store.clone();
            let cwd = context.paths.cwd.clone();
            let io = context.resources.io.clone();
            let cpu = context.resources.cpu.clone();
            let token = work.clone();
            let budget = budget.clone();
            let operation = async move {
                ensure!(!token.is_cancelled(), "certificate loading cancelled");
                match source {
                    ManualSource::Pem {
                        certificate,
                        key,
                        tags,
                    } => {
                        loading(io, cpu, token, move || {
                            Ok(vec![material(certificate, key, tags, &budget)?])
                        })
                        .await
                    }
                    ManualSource::Files {
                        certificate,
                        key,
                        tags,
                    } => {
                        loading(io, cpu, token, move || {
                            let certificate = read(&absolute(&cwd, &certificate))?;
                            let key = Zeroizing::new(read(&absolute(&cwd, &key))?);
                            manual_pem::file_key(&key)?;
                            Ok(vec![material(certificate, key, tags, &budget)?])
                        })
                        .await
                    }
                    ManualSource::Storage {
                        certificate,
                        key,
                        tags,
                    } => {
                        let fs = &store
                            .ok_or_else(|| anyhow!("certificate storage unavailable"))?
                            .fs;
                        let certificate = fs
                            .load(&certificate)
                            .await?
                            .ok_or_else(|| anyhow!("configured storage certificate missing"))?;
                        ensure!(!token.is_cancelled(), "certificate loading cancelled");
                        let key = fs
                            .load(&key)
                            .await?
                            .ok_or_else(|| anyhow!("configured storage private key missing"))?;
                        loading(io, cpu, token, move || {
                            manual_pem::file_key(&key)?;
                            Ok(vec![material(certificate.to_vec(), key, tags, &budget)?])
                        })
                        .await
                    }
                    ManualSource::Folder(path) => {
                        let walking = token.clone();
                        loading(io, cpu, token, move || {
                            let path = absolute(&cwd, &path);
                            let mut files = Vec::new();
                            collect(&path, 0, &mut files, &walking, &budget)?;
                            files.sort();
                            files
                                .into_iter()
                                .map(|path| {
                                    ensure!(
                                        !walking.is_cancelled(),
                                        "certificate loading cancelled"
                                    );
                                    let bundle = Zeroizing::new(read(&path)?);
                                    let (certificate, key) = manual_pem::bundle(&bundle)?;
                                    prepared_material(certificate, key, Vec::new(), &budget)
                                })
                                .collect()
                        })
                        .await
                    }
                }
            };
            async move { (index, operation.await) }
        })
        .buffer_unordered(8);
    let mut results = Vec::new();
    let mut first_error = None;
    while let Some((index, result)) = pending.next().await {
        match result {
            Ok(material) if first_error.is_none() => results.push((index, material)),
            Ok(_) => {}
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                    work.cancel();
                }
            }
        }
    }
    // All admitted blocking workers are drained even when an early source
    // fails. No queued input can start another read after cancellation.
    if let Some(error) = first_error {
        return Err(error);
    }
    results.sort_by_key(|(index, _)| *index);
    Ok(results
        .into_iter()
        .flat_map(|(_, material)| material)
        .collect())
}

pub(super) fn read(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| anyhow!("configured certificate file unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow!("configured certificate metadata unavailable"))?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_MATERIAL as u64,
        "configured certificate file exceeds size limit"
    );
    let size = usize::try_from(metadata.len())
        .map_err(|_| anyhow!("configured certificate size overflow"))?;
    let mut bytes = Zeroizing::new(vec![0; size]);
    file.read_exact(&mut bytes)
        .map_err(|_| anyhow!("configured certificate file read failed"))?;
    let mut extra = Zeroizing::new([0u8; 1]);
    ensure!(
        file.read(&mut *extra)
            .map_err(|_| anyhow!("configured certificate file read failed"))?
            == 0,
        "configured certificate changed during read"
    );
    Ok(std::mem::take(&mut *bytes))
}
/// Root-file bytes stay admitted through their actual constructor/manager
/// owner. The data-first tuple also preserves that order if its caller stops
/// while the file worker is still running or leaves its result unconsumed.
pub(super) fn read_root_input(
    path: &Path,
) -> Result<(Vec<u8>, crate::acme_wire::chain_memory::Scratch)> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| anyhow!("configured certificate file unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow!("configured certificate metadata unavailable"))?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_MATERIAL as u64,
        "configured certificate file exceeds size limit"
    );
    let size = usize::try_from(metadata.len())
        .map_err(|_| anyhow!("configured certificate size overflow"))?;
    let amount = size
        .checked_add(std::mem::size_of::<Vec<u8>>())
        .and_then(|n| n.checked_add(std::mem::size_of::<crate::acme_wire::chain_memory::Scratch>()))
        .and_then(|n| n.checked_add(64))
        .ok_or(crate::cert_transient::ResourceDenied)?;
    let memory = crate::cert_transient::reserve(amount)?;
    let mut bytes = Zeroizing::new(vec![0; size]);
    file.read_exact(&mut bytes)
        .map_err(|_| anyhow!("configured certificate file read failed"))?;
    let mut extra = Zeroizing::new([0u8; 1]);
    ensure!(
        file.read(&mut *extra)
            .map_err(|_| anyhow!("configured certificate file read failed"))?
            == 0,
        "configured certificate changed during read"
    );
    Ok((std::mem::take(&mut *bytes), memory))
}
fn collect(
    path: &Path,
    depth: usize,
    output: &mut Vec<PathBuf>,
    cancel: &CancellationToken,
    budget: &MaterialBudget,
) -> Result<()> {
    ensure!(!cancel.is_cancelled(), "certificate loading cancelled");
    ensure!(
        depth < 64,
        "configured certificate folder nesting limit exceeded"
    );
    for entry in
        std::fs::read_dir(path).map_err(|_| anyhow!("configured certificate folder unavailable"))?
    {
        let entry =
            entry.map_err(|_| anyhow!("configured certificate folder entry unavailable"))?;
        ensure!(!cancel.is_cancelled(), "certificate loading cancelled");
        budget
            .visited
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1).filter(|next| *next <= 65_536)
            })
            .map_err(|_| anyhow!("configured certificate folder traversal capacity exceeded"))?;
        let kind = entry
            .file_type()
            .map_err(|_| anyhow!("configured certificate folder metadata unavailable"))?;
        ensure!(
            !kind.is_symlink(),
            "configured certificate folder symlinks require confined loader support"
        );
        if kind.is_dir() {
            collect(&entry.path(), depth + 1, output, cancel, budget)?;
        } else if entry
            .path()
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pem"))
        {
            ensure!(
                output.len() < crate::tls_resolver::MAX_CERTIFICATES,
                "configured certificate folder capacity exceeded"
            );
            output.push(entry.path());
        }
    }
    Ok(())
}
