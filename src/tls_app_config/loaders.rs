use super::{
    manual_values::{self, Kind, ScratchBudget, Sources},
    material::Material,
    services::PrepareContext,
};
use anyhow::{Result, anyhow, ensure};
use futures_util::{StreamExt, stream};
use std::{
    io::Read,
    path::Path,
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
    certificate: &[u8],
    key: &[u8],
    tags: Arc<crate::certificate_tags::CertificateTags>,
    budget: &MaterialBudget,
) -> Result<Material> {
    ensure!(
        certificate.len() <= MAX_MATERIAL && key.len() <= MAX_MATERIAL,
        "configured certificate input exceeds size limit"
    );
    let (certificate, key) = manual_pem::pair(certificate, key)?;
    prepared_material(certificate, key, tags, budget)
}
fn prepared_material(
    certificate: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    tags: Arc<crate::certificate_tags::CertificateTags>,
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

struct PathsCredit {
    _memory: ScratchBudget,
}
struct OwnedPaths {
    files: std::vec::IntoIter<manual_values::PathValue>,
    credit: Arc<PathsCredit>,
}
impl OwnedPaths {
    fn next(&mut self) -> Option<OwnedPathItem> {
        self.files.next().map(|path| OwnedPathItem {
            path,
            _credit: self.credit.clone(),
        })
    }
}
struct OwnedPathItem {
    path: manual_values::PathValue,
    _credit: Arc<PathsCredit>,
}
impl OwnedPathItem {
    // A consuming method forces closure capture of the whole envelope. Field
    // capture of path.path alone would strand the credit in an aborted waiter.
    fn read(self) -> Result<crate::cert_transient::Bytes> {
        read_owned(&self.path)
    }
}
fn read_owned(path: &Path) -> Result<crate::cert_transient::Bytes> {
    use crate::cert_transient::{Bytes, Lifetime};
    let mut file = crate::http_config::helpers::open_regular_file(path)
        .map_err(|_| anyhow!("configured certificate file unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow!("configured certificate metadata unavailable"))?;
    ensure!(
        metadata.len() <= MAX_MATERIAL as u64,
        "configured certificate file exceeds size limit"
    );
    let mut bytes = Bytes::allocate(usize::try_from(metadata.len())?, Some(Lifetime::Temporary))?;
    file.read_exact(bytes.as_mut_slice())
        .map_err(|_| anyhow!("configured certificate file read failed"))?;
    let mut extra = Zeroizing::new([0u8; 1]);
    ensure!(
        file.read(&mut *extra)? == 0,
        "configured certificate changed during read"
    );
    Ok(bytes)
}
pub(super) async fn load_manual(
    sources: &Sources,
    storage_root: &Path,
    context: &PrepareContext,
    cancel: CancellationToken,
) -> Result<Vec<Material>> {
    let store = if sources.iter().any(|s| s.kind() == Kind::Storage) {
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
            let cwd = manual_values::cwd(&context.paths.cwd);
            let io = context.resources.io.clone();
            let cpu = context.resources.cpu.clone();
            let token = work.clone();
            let budget = budget.clone();
            let operation = async move {
                let cwd = cwd?;
                ensure!(!token.is_cancelled(), "certificate loading cancelled");
                let prepared = source.get()?;
                match prepared.kind() {
                    Kind::Pem => {
                        blocking(cpu, token, move || {
                            Ok(vec![material(
                                prepared.certificate(),
                                prepared.key(),
                                prepared.tags.clone(),
                                &budget,
                            )?])
                        })
                        .await
                    }
                    Kind::Files => {
                        prepared.check_format()?;
                        let input = prepared.clone();
                        let reading = token.clone();
                        let (certificate, key) = blocking(io, reading, move || {
                            let certificate_path =
                                manual_values::path(input.certificate(), &cwd.path)?;
                            let key_path = manual_values::path(input.key(), &cwd.path)?;
                            Ok((
                                read_owned(&certificate_path.path)?,
                                read_owned(&key_path.path)?,
                            ))
                        })
                        .await?;
                        blocking(cpu, token, move || {
                            manual_pem::file_key(&key)?;
                            Ok(vec![material(
                                &certificate,
                                &key,
                                prepared.tags.clone(),
                                &budget,
                            )?])
                        })
                        .await
                    }
                    Kind::Storage => {
                        prepared.check_format()?;
                        let fs = &store
                            .ok_or_else(|| anyhow!("certificate storage unavailable"))?
                            .fs;
                        let certificate_key =
                            std::str::from_utf8(prepared.certificate()).map_err(|_| {
                                anyhow!("manual storage key contains unsupported non-UTF8 bytes")
                            })?;
                        let key_key = std::str::from_utf8(prepared.key()).map_err(|_| {
                            anyhow!("manual storage key contains unsupported non-UTF8 bytes")
                        })?;
                        let certificate = fs
                            .load_ca_input(certificate_key)
                            .await?
                            .ok_or_else(|| anyhow!("configured storage certificate missing"))?;
                        ensure!(!token.is_cancelled(), "certificate loading cancelled");
                        let key = fs
                            .load_ca_input(key_key)
                            .await?
                            .ok_or_else(|| anyhow!("configured storage private key missing"))?;
                        blocking(cpu, token, move || {
                            manual_pem::file_key(&key)?;
                            Ok(vec![material(
                                &certificate,
                                &key,
                                prepared.tags.clone(),
                                &budget,
                            )?])
                        })
                        .await
                    }
                    Kind::Folder => {
                        let walking = token.clone();
                        let collecting = budget.clone();
                        let input = prepared.clone();
                        let paths = blocking(io.clone(), token.clone(), move || {
                            let path = manual_values::path(input.certificate(), &cwd.path)?;
                            let mut files = Vec::new();
                            let mut memory = ScratchBudget::new();
                            let mut used = 0usize;
                            collect(
                                &path.path,
                                0,
                                &mut files,
                                &walking,
                                &collecting,
                                &mut memory,
                                &mut used,
                            )?;
                            files.sort_by(|a, b| a.as_path().cmp(b.as_path()));
                            memory.grow(
                                used.checked_add(
                                    files.capacity() * 2 * std::mem::size_of::<manual_values::PathValue>()
                                        + std::mem::size_of::<PathsCredit>()
                                        + 256,
                                )
                                .ok_or(crate::cert_transient::ResourceDenied)?,
                            )?;
                            Ok(OwnedPaths {
                                files: files.into_iter(),
                                credit: Arc::new(PathsCredit { _memory: memory }),
                            })
                        })
                        .await?;
                        let mut paths = paths;
                        let mut result = Vec::new();
                        while let Some(path) = paths.next() {
                            let bytes =
                                blocking(io.clone(), token.clone(), move || path.read()).await?;
                            let budget = budget.clone();
                            result.push(
                                blocking(cpu.clone(), token.clone(), move || {
                                    let (certificate, key) = manual_pem::bundle(&bytes)?;
                                    prepared_material(
                                        certificate,
                                        key,
                                        crate::certificate_tags::CertificateTags::empty(),
                                        &budget,
                                    )
                                })
                                .await?,
                            );
                        }
                        Ok(result)
                    }
                }
            };
            async move { (index, operation.await) }
        })
        .buffer_unordered(8);
    let mut results = Vec::new();
    let mut error = None;
    while let Some((index, result)) = pending.next().await {
        match result {
            Ok(value) if error.is_none() => results.push((index, value)),
            Ok(_) => {}
            Err(e) => {
                if error.is_none() {
                    error = Some(e);
                    work.cancel();
                }
            }
        }
    }
    if let Some(error) = error {
        return Err(error);
    }
    results.sort_by_key(|(index, _)| *index);
    Ok(results.into_iter().flat_map(|(_, value)| value).collect())
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
    output: &mut Vec<manual_values::PathValue>,
    cancel: &CancellationToken,
    budget: &MaterialBudget,
    memory: &mut ScratchBudget,
    used: &mut usize,
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
        let _entry_memory = crate::cert_transient::reserve(
            path.as_os_str()
                .len()
                .checked_add(512)
                .and_then(|n| n.checked_mul(4))
                .ok_or(crate::cert_transient::ResourceDenied)?,
        )?;
        let kind = entry
            .file_type()
            .map_err(|_| anyhow!("configured certificate folder metadata unavailable"))?;
        ensure!(
            !kind.is_symlink(),
            "configured certificate folder symlinks require confined loader support"
        );
        use std::os::unix::ffi::OsStringExt;
        let name = Zeroizing::new(entry.file_name().into_vec());
        let entry_path = manual_values::path(&name, path)?;
        if kind.is_dir() {
            collect(&entry_path.path, depth + 1, output, cancel, budget, memory, used)?;
        } else if entry_path
            .path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pem"))
        {
            ensure!(
                output.len() < crate::tls_resolver::MAX_CERTIFICATES,
                "configured certificate folder capacity exceeded"
            );
            let cap = if output.len() == output.capacity() {
                output.capacity().saturating_mul(2).max(4)
            } else {
                output.capacity()
            };
            *used = used
                .checked_add(entry_path.path.capacity())
                .ok_or(crate::cert_transient::ResourceDenied)?;
            memory.grow(
                used.checked_add(cap * 2 * std::mem::size_of::<manual_values::PathValue>() + 1024)
                    .ok_or(crate::cert_transient::ResourceDenied)?,
            )?;
            if output.len() == output.capacity() {
                output.try_reserve_exact(cap - output.len())?;
            }
            output.push(entry_path.path);
        }
    }
    Ok(())
}
