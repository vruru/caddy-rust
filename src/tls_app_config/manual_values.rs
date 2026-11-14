//! Closed generation-owned manual loader values. Raw JSON remains untouched.
use super::{
    services::PrepareContext,
    subject_values::environment::{self, ProviderValue},
};
use crate::{
    acme_wire::chain_memory::{self, Lease, Pool, Scratch},
    cert_transient::{self, ResourceDenied},
    certificate_tags::CertificateTags,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
const FIELD: usize = 1 << 20;
const MATERIAL: usize = 12 << 20;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Files,
    Pem,
    Folder,
    Storage,
}
pub(super) struct ScratchBudget {
    credits: [Option<Scratch>; 64],
    count: usize,
    bytes: usize,
}
impl ScratchBudget {
    pub(super) fn new() -> Self {
        Self {
            credits: std::array::from_fn(|_| None),
            count: 0,
            bytes: 0,
        }
    }
    pub(super) fn grow(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.bytes {
            let bytes = bytes
                .max(1024)
                .checked_next_power_of_two()
                .ok_or(ResourceDenied)?;
            ensure!(self.count < self.credits.len(), ResourceDenied);
            self.credits[self.count] = Some(cert_transient::reserve(bytes - self.bytes)?);
            self.count += 1;
            self.bytes = bytes;
        }
        Ok(())
    }
}
struct Raw {
    kind: Kind,
    certificate: Zeroizing<String>,
    key: Zeroizing<String>,
    format: Zeroizing<String>,
    tags: Arc<CertificateTags>,
    _memory: Lease,
}
pub(super) struct Input {
    raw: Arc<Raw>,
    ready: OnceCell<Arc<Prepared>>,
}
struct OwnedField {
    bytes: Zeroizing<Vec<u8>>,
    _memory: Lease,
}
pub(super) struct Prepared {
    raw: Arc<Raw>,
    certificate: Option<OwnedField>,
    key: Option<OwnedField>,
    format: Option<OwnedField>,
    pub(super) tags: Arc<CertificateTags>,
    _memory: Lease,
}
impl Prepared {
    pub(super) fn kind(&self) -> Kind {
        self.raw.kind
    }
    pub(super) fn certificate(&self) -> &[u8] {
        self.certificate
            .as_ref()
            .map_or(self.raw.certificate.as_bytes(), |v| &v.bytes)
    }
    pub(super) fn key(&self) -> &[u8] {
        self.key
            .as_ref()
            .map_or(self.raw.key.as_bytes(), |v| &v.bytes)
    }
    pub(super) fn format(&self) -> &[u8] {
        self.format
            .as_ref()
            .map_or(self.raw.format.as_bytes(), |v| &v.bytes)
    }
    pub(super) fn check_format(&self) -> Result<()> {
        ensure!(
            matches!(self.format(), b"" | b"pem"),
            "unsupported configured certificate format"
        );
        Ok(())
    }
}
fn text(value: &str) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::new());
    out.try_reserve_exact(value.len())?;
    out.push_str(value);
    Ok(out)
}
impl Input {
    pub(super) fn new(
        kind: Kind,
        certificate: &str,
        key: &str,
        format: &str,
        tags: &[Value],
    ) -> Result<Arc<Self>> {
        ensure!(
            certificate.len() <= MATERIAL && key.len() <= MATERIAL && format.len() <= MATERIAL,
            "manual configured input exceeds limit"
        );
        ensure!(
            tags.iter().all(Value::is_string),
            "manual certificate tag must be string"
        );
        let pool = chain_memory::shared().payload.clone();
        let bytes = certificate
            .len()
            .checked_add(key.len())
            .and_then(|n| n.checked_add(format.len()))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Raw>() + std::mem::size_of::<Self>() + 256)
            })
            .ok_or(ResourceDenied)?;
        let memory = pool.reserve(bytes)?;
        let certificate = text(certificate)?;
        let key = text(key)?;
        let format = text(format)?;
        ensure!(
            certificate.capacity()
                + key.capacity()
                + format.capacity()
                + std::mem::size_of::<Raw>()
                + std::mem::size_of::<Self>()
                + 128
                <= memory.bytes(),
            ResourceDenied
        );
        let tags = CertificateTags::copy(
            tags.len(),
            tags.iter().map(|v| v.as_str().expect("checked tag type")),
            &pool,
        )?;
        Ok(Arc::new(Self {
            raw: Arc::new(Raw {
                kind,
                certificate,
                key,
                format,
                tags,
                _memory: memory,
            }),
            ready: OnceCell::new(),
        }))
    }
    pub(super) fn kind(&self) -> Kind {
        self.raw.kind
    }
    pub(super) fn get(&self) -> Result<Arc<Prepared>> {
        self.ready
            .get()
            .cloned()
            .ok_or_else(|| anyhow!("manual certificate values are not prepared"))
    }
    async fn prepare(
        self: &Arc<Self>,
        context: &PrepareContext,
        cancel: CancellationToken,
    ) -> Result<()> {
        self.ready
            .get_or_try_init(|| async {
                let this = self.clone();
                let pool = context.resources.issuer_values.clone();
                let cwd = cwd(&context.paths.cwd)?;
                crate::cert_cpu::run(context.resources.io.clone(), cancel.clone(), move || {
                    this.build(&pool, &cwd.path, &cancel)
                })
                .await
            })
            .await?;
        Ok(())
    }
    fn build(
        &self,
        pool: &Arc<Pool>,
        cwd: &Path,
        cancel: &CancellationToken,
    ) -> Result<Arc<Prepared>> {
        let memory = pool.reserve(std::mem::size_of::<Prepared>() + 128)?;
        // Go provisions tags before certificate/key/format for each pair.
        let tags = prepare_tags(&self.raw.tags, pool, cwd, cancel)?;
        let certificate = field(&self.raw.certificate, pool, cwd, cancel)?;
        let key = field(&self.raw.key, pool, cwd, cancel)?;
        let format = field(&self.raw.format, pool, cwd, cancel)?;
        ensure!(!cancel.is_cancelled(), "manual value preparation cancelled");
        Ok(Arc::new(Prepared {
            raw: self.raw.clone(),
            certificate,
            key,
            format,
            tags,
            _memory: memory,
        }))
    }
}
struct Expansion {
    bytes: Zeroizing<Vec<u8>>,
    _memory: ScratchBudget,
}
fn expand(raw: &str, cwd: &Path, cancel: &CancellationToken) -> Result<Expansion> {
    let mut memory = ScratchBudget::new();
    let bytes = crate::http_config::helpers::replace_secret_bytes_accounted(
        raw,
        false,
        MATERIAL,
        MATERIAL,
        |name| lookup(name, cwd, cancel),
        |capacity| memory.grow(capacity),
    )?;
    ensure!(!cancel.is_cancelled(), "manual value preparation cancelled");
    Ok(Expansion {
        bytes,
        _memory: memory,
    })
}

fn field(
    raw: &str,
    pool: &Arc<Pool>,
    cwd: &Path,
    cancel: &CancellationToken,
) -> Result<Option<OwnedField>> {
    if !raw.contains(['{', '}']) {
        return Ok(None);
    }
    let value = expand(raw, cwd, cancel)?;
    if value.bytes.as_slice() == raw.as_bytes() {
        return Ok(None);
    }
    let memory = pool.reserve(value.bytes.capacity() + std::mem::size_of::<OwnedField>() + 64)?;
    Ok(Some(OwnedField {
        bytes: value.bytes,
        _memory: memory,
    }))
}
fn prepare_tags(
    raw: &Arc<CertificateTags>,
    pool: &Arc<Pool>,
    cwd: &Path,
    cancel: &CancellationToken,
) -> Result<Arc<CertificateTags>> {
    if !raw.iter().any(|v| v.contains(['{', '}'])) {
        return Ok(raw.clone());
    }
    let mut memory = ScratchBudget::new();
    let mut owned = Zeroizing::new(Vec::new());
    let mut bytes = raw
        .len()
        .checked_mul(std::mem::size_of::<String>() * 2)
        .and_then(|n| n.checked_add(256))
        .ok_or(ResourceDenied)?;
    memory.grow(bytes)?;
    owned.try_reserve_exact(raw.len())?;
    let mut changed = false;
    for value in raw.iter() {
        let expanded = expand(value, cwd, cancel)?;
        changed |= expanded.bytes.as_slice() != value.as_bytes();
        ensure!(
            std::str::from_utf8(&expanded.bytes).is_ok(),
            "manual certificate tag contains unsupported non-UTF8 bytes"
        );
        bytes = bytes
            .checked_add(expanded.bytes.capacity())
            .ok_or(ResourceDenied)?;
        memory.grow(bytes)?;
        let mut data = expanded.bytes;
        let string = String::from_utf8(std::mem::take(&mut *data)).map_err(|e| {
            let _wipe = Zeroizing::new(e.into_bytes());
            anyhow!("invalid configured tag")
        })?;
        owned.push(string);
    }
    if !changed {
        return Ok(raw.clone());
    }
    CertificateTags::adopt(owned, pool)
}
fn lookup(name: &str, cwd: &Path, cancel: &CancellationToken) -> Result<Option<ProviderValue>> {
    ensure!(!cancel.is_cancelled(), "manual value preparation cancelled");
    if let Some(key) = name.strip_prefix("env.") {
        return environment::bounded_bytes(key).map(Some);
    }
    if let Some(path) = name.strip_prefix("file.") { return lookup_file(path, cwd); }
    lookup_global(name)
}
pub(super) fn lookup_file(path:&str,cwd:&Path)->Result<Option<ProviderValue>> {
        use std::io::Read;
        let _path_memory = cert_transient::reserve(
            path.len()
                .checked_add(cwd.as_os_str().len())
                .and_then(|n| n.checked_mul(4))
                .and_then(|n| n.checked_add(256))
                .ok_or(ResourceDenied)?,
        )?;
        let path = super::storage::absolute(cwd, Path::new(path));
        let Ok(mut file) = crate::http_config::helpers::open_regular_file(path) else {
            return ProviderValue::empty().map(Some);
        };
        let memory = cert_transient::reserve(FIELD)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(FIELD)?;
        bytes.resize(FIELD, 0);
        let mut len = 0;
        while len < FIELD {
            match file.read(&mut bytes[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return ProviderValue::empty().map(Some),
            }
        }
        if len > 0 && bytes[len - 1] == b'\n' {
            len -= 1
        }
        if len > 0 && bytes[len - 1] == b'\r' {
            len -= 1
        }
        bytes.truncate(len);
        Ok(Some(ProviderValue { bytes, memory }))
}
pub(super) fn lookup_global(name:&str)->Result<Option<ProviderValue>> {
    let memory = cert_transient::reserve(FIELD)?;
    let Some(value) = crate::http_config::helpers::global_lookup(name) else {
        return Ok(None);
    };
    let mut value = Zeroizing::new(value);
    ensure!(
        value.capacity() <= FIELD,
        "manual global value exceeds limit"
    );
    let bytes = Zeroizing::new(std::mem::take(&mut *value).into_bytes());
    Ok(Some(ProviderValue { bytes, memory }))
}
struct List {
    values: Vec<Arc<Input>>,
    _memory: Option<Lease>,
}
#[derive(Clone)]
pub(super) struct Sources(Arc<List>);
impl Default for Sources {
    fn default() -> Self {
        static EMPTY: OnceLock<Arc<List>> = OnceLock::new();
        Self(
            EMPTY
                .get_or_init(|| {
                    Arc::new(List {
                        values: Vec::new(),
                        _memory: None,
                    })
                })
                .clone(),
        )
    }
}
impl Sources {
    pub(super) fn iter(&self) -> std::slice::Iter<'_, Arc<Input>> {
        self.0.values.iter()
    }
    pub(super) fn len(&self) -> usize {
        self.0.values.len()
    }
}
pub(super) struct Builder {
    values: Vec<Arc<Input>>,
    memory: Lease,
}
impl Builder {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            values: Vec::new(),
            memory: chain_memory::shared().payload.reserve(0)?,
        })
    }
    pub(super) fn push(&mut self, value: Arc<Input>) -> Result<()> {
        ensure!(
            self.values.len() < crate::tls_resolver::MAX_CERTIFICATES,
            "manual source count exceeds limit"
        );
        if self.values.len() == self.values.capacity() {
            let cap = self.values.capacity().saturating_mul(2).max(4);
            self.memory
                .resize(cap * std::mem::size_of::<Arc<Input>>() * 2 + 256)?;
            self.values.try_reserve_exact(cap - self.values.len())?;
        }
        self.values.push(value);
        Ok(())
    }
    pub(super) fn finish(mut self) -> Result<Sources> {
        if self.values.is_empty() {
            return Ok(Sources::default());
        }
        self.memory
            .resize(self.values.capacity() * std::mem::size_of::<Arc<Input>>() + 256)?;
        Ok(Sources(Arc::new(List {
            values: self.values,
            _memory: Some(self.memory),
        })))
    }
}
pub(super) async fn prepare_all(
    sources: &Sources,
    context: &PrepareContext,
    cancel: CancellationToken,
) -> Result<()> {
    for (index, source) in sources.iter().enumerate() {
        source.prepare(context, cancel.clone()).await?;
        if index.is_multiple_of(32) {
            tokio::task::yield_now().await
        }
    }
    Ok(())
}
/// Owned path bytes use the same wipe-before-credit-drop order as values.
/// No Clone implementation permits an unadmitted deep path copy.
pub(super) struct PathValue(PathBuf);
impl std::ops::Deref for PathValue {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}
impl Drop for PathValue {
    fn drop(&mut self) {
        use std::os::unix::ffi::OsStringExt;
        let path = std::mem::take(&mut self.0);
        let _wipe = Zeroizing::new(path.into_os_string().into_vec());
    }
}
pub(super) struct OwnedPath {
    pub(super) path: PathValue,
    _memory: Scratch,
}
pub(super) fn path(bytes: &[u8], cwd: &Path) -> Result<OwnedPath> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    ensure!(!bytes.is_empty(), "configured certificate path is empty");
    let absolute = Path::new(std::ffi::OsStr::from_bytes(bytes)).is_absolute();
    let prefix = if absolute {
        &[][..]
    } else {
        cwd.as_os_str().as_bytes()
    };
    let separator = !prefix.is_empty() && !prefix.ends_with(b"/");
    let length = prefix
        .len()
        .checked_add(usize::from(separator))
        .and_then(|n| n.checked_add(bytes.len()))
        .ok_or(ResourceDenied)?;
    let allowance = length
        .checked_mul(2)
        .and_then(|n| n.checked_add(std::mem::size_of::<OwnedPath>() + 256))
        .ok_or(ResourceDenied)?;
    let memory = cert_transient::reserve(allowance)?;
    let mut value = Zeroizing::new(Vec::new());
    value.try_reserve_exact(length)?;
    ensure!(value.capacity() <= allowance, ResourceDenied);
    value.extend_from_slice(prefix);
    if separator {
        value.push(b'/')
    }
    value.extend_from_slice(bytes);
    let path = PathValue(PathBuf::from(std::ffi::OsString::from_vec(std::mem::take(
        &mut *value,
    ))));
    Ok(OwnedPath {
        path,
        _memory: memory,
    })
}
/// The copied path and Arc/control bytes retain their own admission through
/// actual I/O worker destruction, including a true abort of its waiter.
pub(super) fn cwd(path: &Path) -> Result<Arc<OwnedPath>> {
    let allowance = path
        .as_os_str()
        .len()
        .checked_add(std::mem::size_of::<OwnedPath>() + 128)
        .ok_or(ResourceDenied)?;
    let memory = cert_transient::reserve(allowance)?;
    let path = PathValue(path.to_path_buf());
    ensure!(
        path.capacity() + std::mem::size_of::<OwnedPath>() + 64 <= allowance,
        ResourceDenied
    );
    Ok(Arc::new(OwnedPath {
        path,
        _memory: memory,
    }))
}
