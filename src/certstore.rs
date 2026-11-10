//! CertMagic FileStorage persistence with explicit native crash recovery.
//!
//! Key/crt/metadata are individually atomic files, not an atomic group. The
//! separate private state directory records staged generations and original
//! bytes. Run `recover` before handing the store back to original Caddy. The
//! old Go stale-lock protocol cannot provide distributed fencing; operate one
//! active issuer implementation at a time, including during rollback.

#[path = "certstore/io.rs"]
mod io;
#[path = "certstore/lease.rs"]
mod lease;
pub use lease::StorageLease;

use anyhow::{Result, anyhow, bail, ensure};
use io::Root;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Default)]
pub struct RecoveryReport {
    pub recovered: usize,
    pub issues: Vec<RecoveryIssue>,
}
enum RecoveryOutcome {
    Recovered,
    Unchanged,
    Issue(RecoveryIssue),
}
#[derive(Clone, Serialize)]
pub struct RecoveryIssue {
    pub transaction_key: String,
    pub scope: Option<RecoveryScope>,
    pub class: RecoveryClass,
    pub blocker: RecoveryBlocker,
}
#[derive(Clone, Serialize)]
pub struct RecoveryScope {
    pub kind: RecoveryKind,
    pub scope_id: String,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    Account,
    Certificate,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryClass {
    Quarantined,
    InvalidJournal,
    InvalidMaterial,
    ScopeChanged,
    Busy,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryBlocker {
    Journal,
    Quarantine,
}
#[derive(Debug)]
struct ScopedFault(RecoveryClass);
impl std::fmt::Display for ScopedFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scoped storage transaction requires recovery")
    }
}
impl std::error::Error for ScopedFault {}
fn scoped_fault(class: RecoveryClass) -> anyhow::Error {
    anyhow::Error::new(ScopedFault(class))
}

#[derive(Clone)]
pub struct FsStore {
    core: Arc<Core>,
    scope: Option<Arc<GroupGuard>>,
}
// Filesystem gate must close before the in-process mutex is released. Every
// blocking I/O retains this entire guard, even after its async caller is dropped.
struct GroupGuard {
    filesystem: Arc<lease::NativeGate>,
    _local: OwnedMutexGuard<()>,
    lost: CancellationToken,
    ended: CancellationToken,
    transaction_key: String,
    material_base: String,
}
impl GroupGuard {
    fn verify(&self) -> Result<()> {
        ensure!(
            !self.lost.is_cancelled() && !self.ended.is_cancelled(),
            "storage transaction lease lost or ended"
        );
        self.filesystem.verify()
    }
}

struct Core {
    data: Root,
    state: Root,
    id: String,
    gate: Arc<Semaphore>,
    groups: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
}

/// These values intentionally do not implement Debug.
#[derive(Clone)]
pub struct StoredAccount {
    pub metadata: Value,
    pub private_key_pem: Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
pub struct CertificateBundle {
    pub chain_pem: Vec<u8>,
    pub private_key_pem: Zeroizing<Vec<u8>>,
    pub metadata: Value,
}

#[derive(Serialize, Deserialize)]
struct StoreIdentity {
    version: u32,
    id: String,
    data_dev: u64,
    data_ino: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Staging,
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Account,
    Certificate,
}

#[derive(Serialize, Deserialize, Clone)]
struct TxPart {
    suffix: String,
    old_hash: Option<String>,
    new_hash: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Transaction {
    version: u32,
    store_id: String,
    data_dev: u64,
    data_ino: u64,
    id: String,
    kind: Kind,
    issuer: String,
    name: String,
    lock_name: String,
    lease_owner: String,
    phase: Phase,
    parts: Vec<TxPart>,
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// CertMagic StorageKeys.Safe, a single path component. A slash is removed.
pub fn safe(input: &str) -> String {
    input
        .to_lowercase()
        .trim()
        .replace(' ', "_")
        .replace('+', "_plus_")
        .replace('*', "wildcard_")
        .replace(':', "-")
        .replace("..", "")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '-'))
        .collect()
}

pub fn issuer_key(directory: &str) -> Result<String> {
    let url = url::Url::parse(directory).map_err(|_| anyhow!("invalid ACME directory URL"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "invalid ACME directory URL"
    );
    let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let path = url
        .path()
        .replace(['/', '\\'], "-")
        .trim_matches('-')
        .to_owned();
    let raw = if path.is_empty() {
        host.to_owned()
    } else {
        format!("{host}-{path}")
    };
    let result = safe(&raw);
    ensure!(!result.is_empty(), "empty ACME issuer key");
    Ok(result)
}

/// Caddy sorts SANs without deduplication and truncates to 1024 bytes including
/// the suffix. For a cut UTF-8 character we stop at its boundary; Safe removes
/// that non-ASCII character either way, preserving the FileStorage path.
pub fn names_key(names: &[String]) -> Result<String> {
    ensure!(
        !names.is_empty()
            && names.len() <= 1024
            && names
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 4096 && !s.contains('\0')),
        "invalid certificate names"
    );
    let mut names = names.to_vec();
    names.sort();
    let mut result = names.join(",");
    if result.len() > 1024 {
        let mut cut = 1018;
        while !result.is_char_boundary(cut) {
            cut -= 1;
        }
        result.truncate(cut);
        result.push_str("_trunc");
    }
    Ok(result)
}

/// Caddy locks registration by the primary contact, not the account filename.
pub fn account_primary(metadata: &Value) -> Result<&str> {
    let object = metadata
        .as_object()
        .ok_or_else(|| anyhow!("account metadata must be an object"))?;
    let contact = match object.get("contact") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => a.first(),
        _ => bail!("invalid account contact shape"),
    };
    let primary = match contact {
        None => "",
        Some(Value::String(s)) => s.split_once(':').map(|(_, v)| v).unwrap_or(s),
        _ => bail!("invalid account contact"),
    };
    Ok(primary)
}

pub fn account_lock_name(metadata: &Value) -> Result<String> {
    let primary = account_primary(metadata)?;
    Ok(if primary.is_empty() {
        "register_acme_account".to_owned()
    } else {
        format!("register_acme_account_{primary}")
    })
}

fn account_path(issuer: &str, email: &str) -> Result<String> {
    let issuer = safe(issuer);
    ensure!(!issuer.is_empty(), "invalid issuer storage key");
    let email = if email.is_empty() { "default" } else { email };
    let lower = email.to_lowercase();
    let username = match lower.find('@') {
        None => lower.as_str(),
        Some(0) => &lower[1..],
        Some(n) => &lower[..n],
    };
    let user = safe(email);
    let file = safe(username);
    ensure!(
        !user.is_empty() && !file.is_empty(),
        "invalid account storage key"
    );
    Ok(format!("acme/{issuer}/users/{user}/{file}"))
}

fn cert_path(issuer: &str, name: &str) -> Result<String> {
    let issuer = safe(issuer);
    let name = safe(name);
    ensure!(
        !issuer.is_empty() && !name.is_empty(),
        "invalid certificate storage key"
    );
    Ok(format!("certificates/{issuer}/{name}/{name}"))
}

impl FsStore {
    pub fn open(root: PathBuf, state_root: PathBuf) -> Result<Self> {
        ensure!(
            root.is_absolute()
                && state_root.is_absolute()
                && !root.starts_with(&state_root)
                && !state_root.starts_with(&root),
            "storage roots must be separate, non-nested absolute directories"
        );
        let data = Root::open(&root, false)?;
        let state = Root::open(&state_root, true)?;
        ensure!(
            data.dev != state.dev || data.ino != state.ino,
            "storage roots must be distinct"
        );
        let id = match state.exclusive("store-id.json", 0o600)? {
            Some(mut file) => {
                let id = io::random_id()?;
                let identity = StoreIdentity {
                    version: 1,
                    id: id.clone(),
                    data_dev: data.dev,
                    data_ino: data.ino,
                };
                file.write_all(&serde_json::to_vec(&identity)?)
                    .map_err(|_| anyhow!("store identity write failed"))?;
                file.sync_all()
                    .map_err(|_| anyhow!("store identity synchronization failed"))?;
                id
            }
            None => {
                let mut parsed = None;
                for _ in 0..8 {
                    if let Some(bytes) = state.load("store-id.json", true)?
                        && !bytes.is_empty()
                    {
                        parsed = Some(
                            serde_json::from_slice::<StoreIdentity>(&bytes)
                                .map_err(|_| anyhow!("invalid store identity"))?,
                        );
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                let identity =
                    parsed.ok_or_else(|| anyhow!("store identity initialization incomplete"))?;
                ensure!(
                    identity.version == 1
                        && is_hex(&identity.id, 32)
                        && identity.data_dev == data.dev
                        && identity.data_ino == data.ino,
                    "store identity does not match storage root; explicit state migration required"
                );
                identity.id
            }
        };
        Ok(Self {
            scope: None,
            core: Arc::new(Core {
                data,
                state,
                id,
                gate: Arc::new(Semaphore::new(32)),
                groups: Mutex::new(HashMap::new()),
            }),
        })
    }

    async fn blocking<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Core>) -> Result<T> + Send + 'static,
    {
        let permit = self
            .core
            .gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("storage worker pool closed"))?;
        let core = self.core.clone();
        let scope = self.scope.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if let Some(group) = &scope {
                group.verify()?;
            }
            let result = operation(core);
            if let Some(group) = &scope {
                group.verify()?;
            }
            result
        })
        .await
        .map_err(|_| anyhow!("storage worker task failed"))?
    }

    async fn group(&self, key: &str) -> Result<OwnedMutexGuard<()>> {
        let lock = {
            let mut map = self
                .core
                .groups
                .lock()
                .map_err(|_| anyhow!("storage group state unavailable"))?;
            map.retain(|_, v| v.strong_count() > 0);
            if let Some(lock) = map.get(key).and_then(Weak::upgrade) {
                lock
            } else {
                ensure!(map.len() < 16_384, "storage group capacity reached");
                let lock = Arc::new(AsyncMutex::new(()));
                map.insert(key.to_owned(), Arc::downgrade(&lock));
                lock
            }
        };
        Ok(lock.lock_owned().await)
    }

    async fn scoped(&self, key: &str, base: &str, lease: &StorageLease) -> Result<Self> {
        self.scoped_until(
            key,
            base,
            lease,
            CancellationToken::new(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(120),
        )
        .await
    }
    async fn scoped_until(
        &self,
        key: &str,
        base: &str,
        lease: &StorageLease,
        cancel: CancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<Self> {
        ensure!(
            self.scope.is_none(),
            "nested storage transaction scope refused"
        );
        lease.check().await?;
        let lost = lease.lost();
        let local = tokio::select! {biased;
            _=cancel.cancelled()=>bail!("storage recovery cancelled"),
            _=lost.cancelled()=>bail!("storage transaction lease lost"),
            _=tokio::time::sleep_until(deadline)=>return Err(anyhow::Error::new(lease::GateBusy)),
            result=self.group(key)=>result?,
        };
        // Cancelling a waiter must never cancel the held issuance lease itself.
        let waiting = lost.child_token();
        let gate = lease::transaction_gate(self.core.clone(), key, waiting.clone(), deadline);
        tokio::pin!(gate);
        let filesystem = tokio::select! {biased;
            _=cancel.cancelled()=>{
                waiting.cancel(); let _=gate.await; bail!("storage recovery cancelled")
            },
            result=&mut gate=>result?,
        };
        let scope = Arc::new(GroupGuard {
            filesystem,
            _local: local,
            lost,
            ended: lease.ended(),
            transaction_key: key.to_owned(),
            material_base: base.to_owned(),
        });
        scope.verify()?;
        Ok(Self {
            core: self.core.clone(),
            scope: Some(scope),
        })
    }
    fn check_group_material(&self, key: &str) -> Result<()> {
        let scope = self
            .scope
            .as_ref()
            .ok_or_else(|| anyhow!("group mutation requires transaction scope"))?;
        ensure!(
            key.strip_prefix(&scope.material_base)
                .is_some_and(|s| matches!(s, ".key" | ".crt" | ".json")),
            "group mutation outside transaction scope"
        );
        Ok(())
    }
    fn check_group_state(&self, key: &str) -> Result<()> {
        let scope = self
            .scope
            .as_ref()
            .ok_or_else(|| anyhow!("journal mutation requires transaction scope"))?;
        let prefix = scope
            .transaction_key
            .strip_suffix(".json")
            .ok_or_else(|| anyhow!("invalid transaction scope"))?;
        ensure!(
            key == scope.transaction_key
                || key == format!("{prefix}.quarantine")
                || key.starts_with(&format!("{prefix}/")),
            "journal mutation outside transaction scope"
        );
        Ok(())
    }

    pub async fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let key = key.to_owned();
        self.blocking(move |c| c.data.load(&key, key.ends_with(".key")))
            .await
    }
    async fn read_group(
        &self,
        keys: Vec<String>,
        transaction_key: String,
    ) -> Result<Vec<Option<Zeroizing<Vec<u8>>>>> {
        self.blocking(move |c| {
            let before = keys
                .iter()
                .map(|k| c.data.signature(k))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                !pending_core(&c, &transaction_key)?,
                "storage transaction recovery required"
            );
            let pinned = keys
                .iter()
                .map(|k| c.data.load_pinned(k, k.ends_with(".key")))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                pinned
                    .iter()
                    .zip(&before)
                    .all(|(value, signature)| value.as_ref().map(io::PinnedRead::signature)
                        == signature.as_ref()),
                "storage generation changed during grouped read"
            );
            ensure!(
                !pending_core(&c, &transaction_key)?,
                "storage transaction recovery required"
            );
            let after = keys
                .iter()
                .map(|k| c.data.signature(k))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                before == after,
                "storage generation changed during grouped read"
            );
            for value in pinned.iter().flatten() {
                value.verify()?;
            }
            Ok(pinned
                .into_iter()
                .map(|value| value.map(io::PinnedRead::into_bytes))
                .collect())
        })
        .await
    }
    pub async fn store(&self, key: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            key != "locks" && !key.starts_with("locks/"),
            "lock files require the lease API"
        );
        ensure!(
            !group_path(key),
            "account and certificate material require the transaction API"
        );
        let key = key.to_owned();
        let bytes = Zeroizing::new(bytes.to_vec());
        self.blocking(move |c| c.data.store(&key, &bytes)).await
    }
    pub async fn delete(&self, key: &str) -> Result<()> {
        ensure!(
            key != "locks" && !key.starts_with("locks/"),
            "lock files require the lease API"
        );
        ensure!(
            !group_path(key),
            "account and certificate material require the transaction API"
        );
        let key = key.to_owned();
        self.blocking(move |c| c.data.delete_tree(&key)).await
    }
    pub async fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        let prefix = prefix.to_owned();
        self.blocking(move |c| c.data.list(&prefix, recursive))
            .await
    }
    pub async fn lock(&self, name: &str, cancel: CancellationToken) -> Result<StorageLease> {
        lease::acquire(self.core.clone(), name, cancel).await
    }

    pub async fn journal_load(&self, job_id: &str) -> Result<Option<Value>> {
        let key = job_key(job_id)?;
        self.blocking(move |c| {
            c.state
                .load(&key, true)?
                .map(|v| {
                    serde_json::from_slice(&v).map_err(|_| anyhow!("invalid job journal JSON"))
                })
                .transpose()
        })
        .await
    }
    /// Create an unleased bootstrap record once. Live ACME jobs and every
    /// update require journal_store_fenced; this helper cannot overwrite them.
    pub async fn journal_store(&self, job_id: &str, value: &Value) -> Result<()> {
        ensure!(
            value.get("lease_name").is_none(),
            "live job requires a storage lease"
        );
        let key = job_key(job_id)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(value).map_err(|_| anyhow!("job journal encoding failed"))?,
        );
        self.blocking(move |c| {
            let mut file = c
                .state
                .exclusive(&key, 0o600)?
                .ok_or_else(|| anyhow!("job journal already exists"))?;
            file.write_all(&bytes)
                .map_err(|_| anyhow!("job bootstrap write failed"))?;
            file.sync_all()
                .map_err(|_| anyhow!("job bootstrap synchronization failed"))
        })
        .await
    }

    async fn fenced<T, F>(&self, lease: &StorageLease, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Core>) -> Result<T> + Send + 'static,
    {
        ensure!(
            lease.belongs(&self.core, lease.name()),
            "lease belongs to another store"
        );
        let lost = lease.lost();
        let permit = tokio::select! {biased;_=lost.cancelled()=>bail!("lease lost while waiting for storage worker"),permit=self.core.gate.clone().acquire_owned()=>permit.map_err(|_|anyhow!("storage worker pool closed"))?};
        let core = self.core.clone();
        let scope = self.scope.clone();
        lease
            .mutate(move || {
                let _permit = permit;
                if let Some(group) = &scope {
                    group.verify()?;
                }
                let result = operation(core);
                if let Some(group) = &scope {
                    group.verify()?;
                }
                result
            })
            .await
    }

    /// All live ACME job writes must use this method. The payload's lease_name
    /// binds a persistent job identifier to one lease scope. Native flock is
    /// retained until each blocking mutation completes, even on async drop.
    pub async fn journal_store_fenced(
        &self,
        job_id: &str,
        value: &Value,
        lease: &StorageLease,
    ) -> Result<()> {
        ensure!(
            value.get("lease_name").and_then(Value::as_str) == Some(lease.name()),
            "journal lease scope mismatch"
        );
        let key = job_key(job_id)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(value).map_err(|_| anyhow!("job journal encoding failed"))?,
        );
        let name = lease.name().to_owned();
        self.fenced(lease, move |c| {
            if let Some(existing) = c.state.load(&key, true)? {
                let old: Value = serde_json::from_slice(&existing)
                    .map_err(|_| anyhow!("invalid job journal JSON"))?;
                ensure!(
                    old.get("lease_name").and_then(Value::as_str) == Some(name.as_str()),
                    "existing journal lease scope mismatch"
                );
            }
            c.state.store(&key, &bytes)
        })
        .await
    }

    pub async fn store_fenced(&self, key: &str, bytes: &[u8], lease: &StorageLease) -> Result<()> {
        ensure!(
            key != "locks" && !key.starts_with("locks/"),
            "lock files require the lease API"
        );
        ensure!(
            !group_path(key),
            "account and certificate material require the transaction API"
        );
        let key = key.to_owned();
        let bytes = Zeroizing::new(bytes.to_vec());
        self.fenced(lease, move |c| c.data.store(&key, &bytes))
            .await
    }
    pub async fn delete_fenced(&self, key: &str, lease: &StorageLease) -> Result<()> {
        ensure!(
            key != "locks" && !key.starts_with("locks/"),
            "lock files require the lease API"
        );
        ensure!(
            !group_path(key),
            "account and certificate material require the transaction API"
        );
        let key = key.to_owned();
        self.fenced(lease, move |c| c.data.delete_tree(&key)).await
    }

    async fn write_group_part(&self, key: &str, bytes: &[u8], lease: &StorageLease) -> Result<()> {
        self.check_group_material(key)?;
        let key = key.to_owned();
        let bytes = Zeroizing::new(bytes.to_vec());
        self.fenced(lease, move |c| c.data.store(&key, &bytes))
            .await
    }
    async fn delete_group_part(&self, key: &str, lease: &StorageLease) -> Result<()> {
        self.check_group_material(key)?;
        let key = key.to_owned();
        self.fenced(lease, move |c| c.data.delete(&key)).await
    }
    async fn pending(&self, kind: Kind, issuer: &str, name: &str) -> Result<bool> {
        let key = self.tx_key(kind, issuer, name)?;
        self.blocking(move |c| pending_core(&c, &key)).await
    }
    fn tx_key(&self, kind: Kind, issuer: &str, name: &str) -> Result<String> {
        let target = match kind {
            Kind::Account => account_path(issuer, name)?,
            Kind::Certificate => cert_path(issuer, name)?,
        };
        let identity = serde_json::json!([
            self.core.id,
            match kind {
                Kind::Account => "account",
                Kind::Certificate => "certificate",
            },
            target
        ]);
        Ok(format!(
            "transactions/{}.json",
            hash(identity.to_string().as_bytes())
        ))
    }

    /// Follow Caddy's directory-mtime ordering, ignoring terminal artifacts
    /// such as .DS_Store. A corrupt newest account is an error, never a reason
    /// to silently create a replacement account.
    pub async fn most_recent_account_email(&self, issuer: &str) -> Result<Option<String>> {
        let issuer_safe = safe(issuer);
        ensure!(!issuer_safe.is_empty(), "invalid issuer storage key");
        let prefix = format!("acme/{issuer_safe}/users");
        let mut candidates = self
            .blocking(move |c| {
                let mut found = Vec::new();
                for key in c.data.list(&prefix, false)? {
                    if let Some((false, modified, _)) = c.data.stat(&key)? {
                        found.push((modified, key));
                    }
                }
                Ok(found)
            })
            .await?;
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let Some((_, key)) = candidates.first() else {
            return Ok(None);
        };
        let directory = key
            .rsplit('/')
            .next()
            .ok_or_else(|| anyhow!("invalid account directory"))?;
        let lookup = if directory == "default" {
            ""
        } else {
            directory
        };
        let account = self
            .load_account(issuer, lookup)
            .await?
            .ok_or_else(|| anyhow!("account directory contains no complete account"))?;
        let primary = account
            .metadata
            .get("contact")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(|s| s.split_once(':').map(|(_, v)| v).unwrap_or(s))
            .filter(|s| !s.is_empty());
        if let Some(primary) = primary {
            ensure!(
                safe(primary) == directory,
                "account contact does not match storage directory"
            );
            Ok(Some(primary.to_owned()))
        } else {
            Ok(Some(lookup.to_owned()))
        }
    }

    /// Recover the original registration lock scope without reading a partial
    /// account pair. Pending journals are validated before their scope is used.
    pub async fn account_registration_lock_name(
        &self,
        issuer: &str,
        email: &str,
    ) -> Result<String> {
        let key = self.tx_key(Kind::Account, issuer, email)?;
        let quarantine = key
            .strip_suffix(".json")
            .ok_or_else(|| anyhow!("invalid transaction key"))?
            .to_owned()
            + ".quarantine";
        ensure!(
            self.state_load(&quarantine).await?.is_none(),
            "quarantined storage transaction requires operator review"
        );
        if let Some(bytes) = self.state_load(&key).await? {
            let tx: Transaction = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow!("invalid storage transaction journal"))?;
            self.validate_transaction(&key, &tx)?;
            ensure!(
                matches!(tx.kind, Kind::Account)
                    && account_path(&tx.issuer, &tx.name)? == account_path(issuer, email)?,
                "account registration journal scope mismatch"
            );
            return Ok(tx.lock_name);
        }
        match self.load_account(issuer, email).await? {
            Some(account) => account_lock_name(&account.metadata),
            None => account_lock_name(&serde_json::json!({
                "contact": if email.is_empty() { Vec::<String>::new() }
                           else { vec![format!("mailto:{email}")] }
            })),
        }
    }

    pub async fn load_account(&self, issuer: &str, email: &str) -> Result<Option<StoredAccount>> {
        let base = account_path(issuer, email)?;
        let mut values = self
            .read_group(
                vec![format!("{base}.key"), format!("{base}.json")],
                self.tx_key(Kind::Account, issuer, email)?,
            )
            .await?;
        let meta = values
            .pop()
            .ok_or_else(|| anyhow!("incomplete grouped read"))?;
        let key = values
            .pop()
            .ok_or_else(|| anyhow!("incomplete grouped read"))?;
        match (key, meta) {
            (None, None) => Ok(None),
            (Some(key), Some(meta)) => {
                let metadata = serde_json::from_slice(&meta)
                    .map_err(|_| anyhow!("invalid account metadata JSON"))?;
                validate_account(&metadata, &key)?;
                Ok(Some(StoredAccount {
                    metadata,
                    private_key_pem: key,
                }))
            }
            _ => bail!("partial account material; recovery required, registration refused"),
        }
    }

    pub async fn save_account(
        &self,
        issuer: &str,
        email: &str,
        account: &StoredAccount,
        lease: &StorageLease,
    ) -> Result<()> {
        validate_account(&account.metadata, &account.private_key_pem)?;
        let expected = account_lock_name(&account.metadata)?;
        ensure!(
            lease.belongs(&self.core, &expected),
            "account lease scope mismatch"
        );
        let base = account_path(issuer, email)?;
        ensure!(
            base == account_path(issuer, account_primary(&account.metadata)?)?,
            "account contact/storage path mismatch"
        );
        self.commit(
            Kind::Account,
            issuer,
            email,
            &base,
            &[
                ("key", Zeroizing::new(account.private_key_pem.to_vec())),
                (
                    "json",
                    Zeroizing::new(serde_json::to_vec(&account.metadata)?),
                ),
            ],
            lease,
        )
        .await
    }

    pub async fn load_certificate(
        &self,
        issuer: &str,
        name: &str,
    ) -> Result<Option<CertificateBundle>> {
        let base = cert_path(issuer, name)?;
        let mut values = self
            .read_group(
                vec![
                    format!("{base}.key"),
                    format!("{base}.crt"),
                    format!("{base}.json"),
                ],
                self.tx_key(Kind::Certificate, issuer, name)?,
            )
            .await?;
        let meta = values
            .pop()
            .ok_or_else(|| anyhow!("incomplete grouped read"))?;
        let crt = values
            .pop()
            .ok_or_else(|| anyhow!("incomplete grouped read"))?;
        let key = values
            .pop()
            .ok_or_else(|| anyhow!("incomplete grouped read"))?;
        match (key, crt, meta) {
            (None, None, None) => Ok(None),
            (Some(key), Some(crt), Some(meta)) => {
                let metadata = serde_json::from_slice(&meta)
                    .map_err(|_| anyhow!("invalid certificate metadata JSON"))?;
                validate_certificate(&crt, &key, &metadata)?;
                ensure!(
                    safe(&names_key(&metadata_names(&metadata)?)?) == safe(name),
                    "certificate metadata storage name mismatch"
                );
                Ok(Some(CertificateBundle {
                    chain_pem: crt.to_vec(),
                    private_key_pem: key,
                    metadata,
                }))
            }
            _ => bail!("partial certificate material; recovery required, reissuance refused"),
        }
    }

    pub async fn save_certificate(
        &self,
        issuer: &str,
        name: &str,
        bundle: &CertificateBundle,
        lease: &StorageLease,
    ) -> Result<()> {
        validate_certificate(&bundle.chain_pem, &bundle.private_key_pem, &bundle.metadata)?;
        let blocks = crate::certmagic::pem_blocks(&bundle.chain_pem, "certificate-candidate")?;
        let (_, leaf) = x509_parser::parse_x509_certificate(&blocks[0].1)
            .map_err(|_| anyhow!("invalid leaf certificate"))?;
        ensure!(
            leaf.validity().is_valid(),
            "new certificate is not currently valid"
        );
        let sans = metadata_names(&bundle.metadata)?;
        ensure!(
            safe(&names_key(&sans)?) == safe(name),
            "certificate metadata storage name mismatch"
        );
        let expected = format!("issue_cert_{}", sans[0]);
        ensure!(
            lease.belongs(&self.core, &expected),
            "certificate lease scope mismatch"
        );
        let base = cert_path(issuer, name)?;
        self.commit(
            Kind::Certificate,
            issuer,
            name,
            &base,
            &[
                ("key", Zeroizing::new(bundle.private_key_pem.to_vec())),
                ("crt", Zeroizing::new(bundle.chain_pem.clone())),
                (
                    "json",
                    Zeroizing::new(serde_json::to_vec(&bundle.metadata)?),
                ),
            ],
            lease,
        )
        .await
    }

    async fn commit(
        &self,
        kind: Kind,
        issuer: &str,
        name: &str,
        base: &str,
        values: &[(&str, Zeroizing<Vec<u8>>)],
        lease: &StorageLease,
    ) -> Result<()> {
        let key = self.tx_key(kind, issuer, name)?;
        let scoped = self.scoped(&key, base, lease).await?;
        scoped
            .commit_scoped(kind, issuer, name, base, values, lease)
            .await
    }
    async fn commit_scoped(
        &self,
        kind: Kind,
        issuer: &str,
        name: &str,
        base: &str,
        values: &[(&str, Zeroizing<Vec<u8>>)],
        lease: &StorageLease,
    ) -> Result<()> {
        let tx_key = self.tx_key(kind, issuer, name)?;
        lease.check().await?;
        ensure!(
            !self.pending(kind, issuer, name).await?,
            "storage transaction recovery required"
        );
        let mut old = Vec::new();
        let mut parts = Vec::new();
        for (suffix, new) in values {
            let value = self.load(&format!("{base}.{suffix}")).await?;
            parts.push(TxPart {
                suffix: suffix.to_string(),
                old_hash: value.as_ref().map(|v| hash(v)),
                new_hash: hash(new),
            });
            old.push(value);
        }
        ensure!(
            old.iter().all(Option::is_none) || old.iter().all(Option::is_some),
            "partial existing material; transaction refused"
        );
        // Validate complete old material as well, so a corrupt old generation is
        // never silently replaced and later reported as merely missing.
        match kind {
            Kind::Account => {
                if let [Some(key), Some(meta)] = old.as_slice() {
                    validate_account(
                        &serde_json::from_slice(meta)
                            .map_err(|_| anyhow!("invalid old account metadata"))?,
                        key,
                    )?;
                }
            }
            Kind::Certificate => {
                if let [Some(key), Some(crt), Some(meta)] = old.as_slice() {
                    validate_certificate(
                        crt,
                        key,
                        &serde_json::from_slice(meta)
                            .map_err(|_| anyhow!("invalid old certificate metadata"))?,
                    )?;
                }
            }
        }
        if old.iter().zip(values).all(|(old, (suffix, new))| {
            old.as_ref().is_some_and(|old| {
                if *suffix == "json" {
                    serde_json::from_slice::<Value>(old).ok()
                        == serde_json::from_slice::<Value>(new).ok()
                } else {
                    old.as_slice() == new.as_slice()
                }
            })
        }) {
            return Ok(());
        }
        let mut tx = Transaction {
            version: 1,
            store_id: self.core.id.clone(),
            data_dev: self.core.data.dev,
            data_ino: self.core.data.ino,
            id: io::random_id()?,
            kind,
            issuer: issuer.to_owned(),
            name: name.to_owned(),
            lock_name: lease.name().to_owned(),
            lease_owner: lease.owner().to_owned(),
            phase: Phase::Staging,
            parts,
        };
        self.write_transaction(&tx_key, &tx, lease).await?;
        for ((suffix, new), old) in values.iter().zip(&old) {
            lease.check().await?;
            self.state_store(&staged_key(&tx_key, &tx.id, suffix, "new")?, new, lease)
                .await?;
            if let Some(old) = old {
                self.state_store(&staged_key(&tx_key, &tx.id, suffix, "old")?, old, lease)
                    .await?;
            }
        }
        lease.check().await?;
        tx.phase = Phase::Prepared;
        self.write_transaction(&tx_key, &tx, lease).await?;
        for (suffix, new) in values {
            lease.check().await?;
            self.write_group_part(&format!("{base}.{suffix}"), new, lease)
                .await?;
        }
        lease.check().await?;
        tx.phase = Phase::Committed;
        self.write_transaction(&tx_key, &tx, lease).await?;
        self.cleanup_transaction(&tx_key, &tx, lease).await
    }

    async fn state_store(&self, key: &str, bytes: &[u8], lease: &StorageLease) -> Result<()> {
        self.check_group_state(key)?;
        let key = key.to_owned();
        let bytes = Zeroizing::new(bytes.to_vec());
        self.fenced(lease, move |c| c.state.store(&key, &bytes))
            .await
    }
    async fn state_load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let key = key.to_owned();
        self.blocking(move |c| c.state.load(&key, true)).await
    }
    async fn state_delete(&self, key: &str, lease: &StorageLease) -> Result<()> {
        self.check_group_state(key)?;
        let key = key.to_owned();
        self.fenced(lease, move |c| c.state.delete(&key)).await
    }
    async fn write_transaction(
        &self,
        key: &str,
        tx: &Transaction,
        lease: &StorageLease,
    ) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(tx)?);
        self.state_store(key, &bytes, lease).await
    }

    /// Strict compatibility entry point: every unresolved scope is an error.
    pub async fn recover(&self, cancel: CancellationToken) -> Result<()> {
        let report = self
            .recover_report_with_wait(cancel, std::time::Duration::from_secs(120))
            .await?;
        ensure!(
            report.issues.is_empty(),
            "storage recovery has unresolved transaction scopes"
        );
        Ok(())
    }

    /// Observe isolated journal faults without treating unrelated groups as
    /// healthy or missing. Unknown IO, root identity, cancellation and worker
    /// failures remain global errors. Callers MUST retain each blocker and still
    /// enforce deterministic scoped recovery before reading/issuing that group.
    pub async fn recover_report(&self, cancel: CancellationToken) -> Result<RecoveryReport> {
        self.recover_report_with_wait(cancel, std::time::Duration::from_secs(2))
            .await
    }
    async fn recover_report_with_wait(
        &self,
        cancel: CancellationToken,
        lock_wait: std::time::Duration,
    ) -> Result<RecoveryReport> {
        self.verify_roots().await?;
        let entries = self
            .blocking(|c| c.state.list("transactions", true))
            .await?;
        let quarantined = entries
            .iter()
            .filter(|k| k.ends_with(".quarantine"))
            .cloned()
            .collect::<Vec<_>>();
        let mut report = RecoveryReport::default();
        let work_cancel = cancel.child_token();
        for key in &quarantined {
            if cancel.is_cancelled() {
                bail!("storage recovery cancelled");
            }
            let canonical = key
                .strip_suffix(".quarantine")
                .ok_or_else(|| anyhow!("invalid quarantine path"))?
                .to_owned()
                + ".json";
            let bytes = self
                .state_load(key)
                .await?
                .ok_or_else(|| anyhow!("quarantine changed during scan"))?;
            let scope = serde_json::from_slice::<Transaction>(&bytes)
                .ok()
                .and_then(|tx| self.verified_scope(&canonical, &tx).ok());
            report.issues.push(
                self.recovery_issue(&canonical, scope, RecoveryClass::Quarantined)
                    .await?,
            );
        }
        let mut tasks = tokio::task::JoinSet::new();
        let mut failure = None;
        for key in entries.into_iter().filter(|k| k.ends_with(".json")) {
            if cancel.is_cancelled() {
                failure = Some(anyhow!("storage recovery cancelled"));
                break;
            }
            if quarantined.contains(&key.replace(".json", ".quarantine")) {
                continue;
            }
            let store = self.clone();
            let token = work_cancel.child_token();
            tasks.spawn(async move { store.recover_one_report(key, token, lock_wait).await });
            if tasks.len() >= 8 {
                match tasks.join_next().await {
                    Some(Ok(Ok(RecoveryOutcome::Issue(issue)))) => report.issues.push(issue),
                    Some(Ok(Ok(RecoveryOutcome::Recovered))) => report.recovered += 1,
                    Some(Ok(Ok(RecoveryOutcome::Unchanged))) => {}
                    Some(Ok(Err(error))) => {
                        failure = Some(error);
                        break;
                    }
                    Some(Err(_)) => {
                        failure = Some(anyhow!("storage recovery worker failed"));
                        break;
                    }
                    None => {}
                }
            }
        }
        if failure.is_some() {
            work_cancel.cancel();
        }
        // Do not abort blocking I/O or leave detached writers after a global
        // fault. Stop spawning and drain all accepted scopes instead.
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(RecoveryOutcome::Issue(issue))) => report.issues.push(issue),
                Ok(Ok(RecoveryOutcome::Recovered)) => report.recovered += 1,
                Ok(Ok(RecoveryOutcome::Unchanged)) => {}
                Ok(Err(error)) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(anyhow!("storage recovery worker failed"));
                    }
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if cancel.is_cancelled() {
            bail!("storage recovery cancelled");
        }
        self.verify_roots().await?;
        Ok(report)
    }
    fn verified_scope(&self, key: &str, tx: &Transaction) -> Result<RecoveryScope> {
        self.validate_transaction(key, tx)?;
        Ok(RecoveryScope {
            kind: match tx.kind {
                Kind::Account => RecoveryKind::Account,
                Kind::Certificate => RecoveryKind::Certificate,
            },
            scope_id: hash(key.as_bytes()),
        })
    }
    async fn recovery_issue(
        &self,
        key: &str,
        scope: Option<RecoveryScope>,
        class: RecoveryClass,
    ) -> Result<RecoveryIssue> {
        let check = key.to_owned();
        let blocker = self
            .blocking(move |c| {
                let quarantine = check.replace(".json", ".quarantine");
                if c.state.stat(&quarantine)?.is_some() {
                    return Ok(RecoveryBlocker::Quarantine);
                }
                if c.state.stat(&check)?.is_some() {
                    return Ok(RecoveryBlocker::Journal);
                }
                bail!("recovery blocker disappeared; global revalidation required")
            })
            .await?;
        Ok(RecoveryIssue {
            transaction_key: key.to_owned(),
            scope,
            class,
            blocker,
        })
    }
    async fn recover_one_report(
        &self,
        key: String,
        cancel: CancellationToken,
        lock_wait: std::time::Duration,
    ) -> Result<RecoveryOutcome> {
        let deadline = tokio::time::Instant::now() + lock_wait;
        let Some(bytes) = self.state_load(&key).await? else {
            let quarantine = key
                .strip_suffix(".json")
                .ok_or_else(|| anyhow!("invalid transaction key"))?
                .to_owned()
                + ".quarantine";
            if self.state_load(&quarantine).await?.is_some() {
                return Ok(RecoveryOutcome::Issue(
                    self.recovery_issue(&key, None, RecoveryClass::Quarantined)
                        .await?,
                ));
            }
            return Ok(RecoveryOutcome::Unchanged);
        };
        let tx = match serde_json::from_slice::<Transaction>(&bytes) {
            Ok(tx) => tx,
            Err(_) => {
                return Ok(RecoveryOutcome::Issue(
                    self.recovery_issue(&key, None, RecoveryClass::InvalidJournal)
                        .await?,
                ));
            }
        };
        let scope = match self.verified_scope(&key, &tx) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(RecoveryOutcome::Issue(
                    self.recovery_issue(&key, None, RecoveryClass::InvalidJournal)
                        .await?,
                ));
            }
        };
        let waiting = cancel.child_token();
        let acquire = self.lock(&tx.lock_name, waiting.clone());
        tokio::pin!(acquire);
        let lease = tokio::select! {
            result=&mut acquire=>result?,
            _=tokio::time::sleep_until(deadline)=>{
                waiting.cancel();
                match acquire.await {
                    Ok(lease)=>{lease.release().await?;},
                    Err(error) if error.is::<lease::AcquisitionCancelled>()=>{},
                    Err(error)=>return Err(error),
                }
                if cancel.is_cancelled(){bail!("storage recovery cancelled");}
                return Ok(RecoveryOutcome::Issue(self.recovery_issue(&key,Some(scope),RecoveryClass::Busy).await?));
            }
        };
        let result = self
            .recover_transaction_until(&key, &tx, &lease, cancel.clone(), deadline)
            .await;
        let released = lease.release().await;
        if let Err(error) = result {
            if error.is::<lease::GateBusy>() {
                released?;
                return Ok(RecoveryOutcome::Issue(
                    self.recovery_issue(&key, Some(scope), RecoveryClass::Busy)
                        .await?,
                ));
            }
            if let Some(fault) = error.downcast_ref::<ScopedFault>() {
                released?;
                let scope = if matches!(
                    fault.0,
                    RecoveryClass::InvalidJournal | RecoveryClass::ScopeChanged
                ) {
                    None
                } else {
                    Some(scope)
                };
                return Ok(RecoveryOutcome::Issue(
                    self.recovery_issue(&key, scope, fault.0).await?,
                ));
            }
            return Err(error);
        }
        released?;
        Ok(RecoveryOutcome::Recovered)
    }
    async fn verify_roots(&self) -> Result<()> {
        self.blocking(|c| {
            for (root, private) in [(&c.data, false), (&c.state, true)] {
                let st = rustix::fs::fstat(&*root.fd)
                    .map_err(|_| anyhow!("storage root metadata unavailable"))?;
                ensure!(
                    rustix::fs::FileType::from_raw_mode(st.st_mode)
                        == rustix::fs::FileType::Directory
                        && st.st_uid == root.uid
                        && st.st_mode & 0o022 == 0
                        && (!private || st.st_mode & 0o077 == 0)
                        && io::device_id(&st) == root.dev
                        && st.st_ino == root.ino,
                    "unsafe or changed storage root"
                );
            }
            let bytes = c
                .state
                .load("store-id.json", true)?
                .ok_or_else(|| anyhow!("store identity missing"))?;
            let identity: StoreIdentity =
                serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid store identity"))?;
            ensure!(
                identity.version == 1
                    && identity.id == c.id
                    && identity.data_dev == c.data.dev
                    && identity.data_ino == c.data.ino,
                "changed store identity"
            );
            Ok(())
        })
        .await
    }

    /// Recover only this certificate group after the caller has acquired a new
    /// issuance lease. Unlike recover(), this never tries to acquire that lease
    /// again, and does not wait on unrelated domains or registration jobs.
    pub async fn recover_certificate_with_lease(
        &self,
        issuer: &str,
        name: &str,
        lease: &StorageLease,
    ) -> Result<()> {
        self.recover_group_with_lease(Kind::Certificate, issuer, name, lease)
            .await
    }

    pub async fn recover_account_with_lease(
        &self,
        issuer: &str,
        email: &str,
        lease: &StorageLease,
    ) -> Result<()> {
        self.recover_group_with_lease(Kind::Account, issuer, email, lease)
            .await
    }

    async fn recover_group_with_lease(
        &self,
        kind: Kind,
        issuer: &str,
        name: &str,
        lease: &StorageLease,
    ) -> Result<()> {
        ensure!(
            lease.belongs(&self.core, lease.name()),
            "recovery lease belongs to another store"
        );
        lease.check().await?;
        let key = self.tx_key(kind, issuer, name)?;
        let quarantine = key
            .strip_suffix(".json")
            .ok_or_else(|| anyhow!("invalid transaction key"))?
            .to_owned()
            + ".quarantine";
        ensure!(
            self.state_load(&quarantine).await?.is_none(),
            "quarantined storage transaction requires operator review"
        );
        let Some(bytes) = self.state_load(&key).await? else {
            return Ok(());
        };
        let tx: Transaction = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("invalid storage transaction journal"))?;
        self.validate_transaction(&key, &tx)?;
        ensure!(
            lease.belongs(&self.core, &tx.lock_name),
            "recovery lease scope mismatch"
        );
        self.recover_transaction(&key, &tx, lease).await
    }

    fn validate_transaction(&self, key: &str, tx: &Transaction) -> Result<()> {
        ensure!(
            tx.version == 1
                && tx.store_id == self.core.id
                && tx.data_dev == self.core.data.dev
                && tx.data_ino == self.core.data.ino
                && is_hex(&tx.id, 32)
                && key == self.tx_key(tx.kind, &tx.issuer, &tx.name)?,
            "transaction does not match this store"
        );
        let suffixes = match tx.kind {
            Kind::Account => vec!["key", "json"],
            Kind::Certificate => vec!["key", "crt", "json"],
        };
        ensure!(
            tx.parts.len() == suffixes.len()
                && tx.parts.iter().zip(suffixes).all(|(p, s)| p.suffix == s
                    && is_hex(&p.new_hash, 64)
                    && p.old_hash.as_ref().is_none_or(|s| is_hex(s, 64))),
            "invalid transaction part manifest"
        );
        ensure!(
            tx.parts.iter().all(|p| p.old_hash.is_some())
                || tx.parts.iter().all(|p| p.old_hash.is_none()),
            "invalid old transaction generation"
        );
        ensure!(
            !tx.lock_name.is_empty() && tx.lock_name.len() <= 2048 && is_hex(&tx.lease_owner, 32),
            "invalid transaction lease metadata"
        );
        match tx.kind {
            Kind::Account => {
                account_path(&tx.issuer, &tx.name)?;
                ensure!(
                    tx.lock_name == "register_acme_account"
                        || tx.lock_name.starts_with("register_acme_account_"),
                    "invalid account transaction lock"
                );
            }
            Kind::Certificate => {
                cert_path(&tx.issuer, &tx.name)?;
                ensure!(
                    tx.lock_name.starts_with("issue_cert_"),
                    "invalid certificate transaction lock"
                );
            }
        }
        Ok(())
    }

    async fn recover_transaction(
        &self,
        key: &str,
        tx: &Transaction,
        lease: &StorageLease,
    ) -> Result<()> {
        self.recover_transaction_until(
            key,
            tx,
            lease,
            CancellationToken::new(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(120),
        )
        .await
    }
    async fn recover_transaction_until(
        &self,
        key: &str,
        tx: &Transaction,
        lease: &StorageLease,
        cancel: CancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let base = match tx.kind {
            Kind::Account => account_path(&tx.issuer, &tx.name)?,
            Kind::Certificate => cert_path(&tx.issuer, &tx.name)?,
        };
        let scoped = self
            .scoped_until(key, &base, lease, cancel, deadline)
            .await?;
        scoped.recover_transaction_scoped(key, tx, lease).await
    }
    async fn recover_transaction_scoped(
        &self,
        key: &str,
        _previous: &Transaction,
        lease: &StorageLease,
    ) -> Result<()> {
        self.check_group_state(key)?;
        if self
            .state_load(&key.replace(".json", ".quarantine"))
            .await?
            .is_some()
        {
            return Err(scoped_fault(RecoveryClass::Quarantined));
        }
        lease.check().await?;
        // Re-read after obtaining the lease: the prior active owner may have
        // completed and removed this journal while recovery was waiting.
        let Some(latest) = self.state_load(key).await? else {
            return Ok(());
        };
        let latest: Transaction = serde_json::from_slice(&latest)
            .map_err(|_| scoped_fault(RecoveryClass::InvalidJournal))?;
        self.validate_transaction(key, &latest)
            .map_err(|_| scoped_fault(RecoveryClass::ScopeChanged))?;

        let tx = &latest;
        if !lease.belongs(&self.core, &tx.lock_name) {
            return Err(scoped_fault(RecoveryClass::ScopeChanged));
        }
        ensure!(
            lease.owner() != tx.lease_owner,
            "recovery requires a newly acquired lease"
        );
        let base = match tx.kind {
            Kind::Account => account_path(&tx.issuer, &tx.name)?,
            Kind::Certificate => cert_path(&tx.issuer, &tx.name)?,
        };
        let mut target = Vec::new();
        for p in &tx.parts {
            let bytes = self.load(&format!("{base}.{}", p.suffix)).await?;
            target.push(bytes.as_ref().map(|b| hash(b)));
        }
        let belongs = target
            .iter()
            .zip(&tx.parts)
            .all(|(h, p)| h == &p.old_hash || h.as_deref() == Some(p.new_hash.as_str()));
        if !belongs {
            self.quarantine(key, lease).await?;
            return Err(scoped_fault(RecoveryClass::Quarantined));
        }
        let all_new = target
            .iter()
            .zip(&tx.parts)
            .all(|(h, p)| h.as_deref() == Some(p.new_hash.as_str()));
        if tx.phase == Phase::Committed && !all_new {
            self.quarantine(key, lease).await?;
            return Err(scoped_fault(RecoveryClass::Quarantined));
        }
        let all_old = target.iter().zip(&tx.parts).all(|(h, p)| h == &p.old_hash);
        if tx.phase == Phase::RolledBack && !all_old {
            self.quarantine(key, lease).await?;
            return Err(scoped_fault(RecoveryClass::Quarantined));
        }
        if matches!(tx.phase, Phase::Committed | Phase::RolledBack) {
            return self.cleanup_transaction(key, tx, lease).await;
        }
        if tx.phase == Phase::Staging {
            if !all_old {
                self.quarantine(key, lease).await?;
                return Err(scoped_fault(RecoveryClass::Quarantined));
            }
            let mut terminal = tx.clone();
            terminal.phase = Phase::RolledBack;
            return self.cleanup_transaction(key, &terminal, lease).await;
        }
        let mut new = Vec::new();
        let mut old = Vec::new();
        for p in &tx.parts {
            let bytes = self
                .state_load(&staged_key(key, &tx.id, &p.suffix, "new")?)
                .await?
                .ok_or_else(|| scoped_fault(RecoveryClass::InvalidMaterial))?;
            if hash(&bytes) != p.new_hash {
                return Err(scoped_fault(RecoveryClass::InvalidMaterial));
            }
            new.push(bytes);
            let bytes = self
                .state_load(&staged_key(key, &tx.id, &p.suffix, "old")?)
                .await?;
            if bytes.as_ref().map(|b| hash(b)) != p.old_hash {
                return Err(scoped_fault(RecoveryClass::InvalidMaterial));
            }
            old.push(bytes);
        }
        let validation = (|| -> Result<()> {
            match tx.kind {
                Kind::Account => {
                    let metadata: Value = serde_json::from_slice(&new[1])?;
                    if all_new {
                        validate_account(&metadata, &new[0])?;
                    }
                    ensure!(
                        account_path(&tx.issuer, account_primary(&metadata)?)? == base,
                        "transaction account path mismatch"
                    );
                    ensure!(
                        account_lock_name(&serde_json::from_slice(&new[1])?)? == tx.lock_name,
                        "transaction account lock mismatch"
                    );
                }
                Kind::Certificate => {
                    let metadata: Value = serde_json::from_slice(&new[2])?;
                    if all_new {
                        validate_certificate(&new[1], &new[0], &metadata)?;
                    }
                    let sans = metadata_names(&metadata)?;
                    ensure!(
                        safe(&names_key(&sans)?) == safe(&tx.name)
                            && tx.lock_name == format!("issue_cert_{}", sans[0]),
                        "transaction certificate scope mismatch"
                    );
                }
            }
            Ok(())
        })();
        if validation.is_err() {
            return Err(scoped_fault(RecoveryClass::InvalidMaterial));
        }
        if !all_new {
            for ((p, old), current) in tx.parts.iter().zip(old).zip(&target) {
                if current == &p.old_hash {
                    continue;
                }
                lease.check().await?;
                let target = format!("{base}.{}", p.suffix);
                match old {
                    Some(bytes) => self.write_group_part(&target, &bytes, lease).await?,
                    None => self.delete_group_part(&target, lease).await?,
                }
            }
        }
        let mut terminal = tx.clone();
        terminal.phase = if all_new {
            Phase::Committed
        } else {
            Phase::RolledBack
        };
        self.cleanup_transaction(key, &terminal, lease).await
    }

    async fn quarantine(&self, key: &str, lease: &StorageLease) -> Result<()> {
        let new = key
            .strip_suffix(".json")
            .ok_or_else(|| anyhow!("invalid transaction key"))?
            .to_owned()
            + ".quarantine";
        ensure!(
            self.state_load(&new).await?.is_none(),
            "transaction already quarantined"
        );
        self.check_group_state(key)?;
        self.check_group_state(&new)?;
        let key = key.to_owned();
        self.fenced(lease, move |c| c.state.rename_new(&key, &new))
            .await
    }

    async fn cleanup_transaction(
        &self,
        key: &str,
        tx: &Transaction,
        lease: &StorageLease,
    ) -> Result<()> {
        // Persist a terminal cleanup-only state before deleting private copies.
        // Recovery of that state verifies the published generation, but does
        // not require candidate/backup copies already removed by prior cleanup.
        ensure!(
            matches!(tx.phase, Phase::Committed | Phase::RolledBack),
            "transaction is not ready for cleanup"
        );
        lease.check().await?;
        self.write_transaction(key, tx, lease).await?;
        for p in &tx.parts {
            let base = match tx.kind {
                Kind::Account => account_path(&tx.issuer, &tx.name)?,
                Kind::Certificate => cert_path(&tx.issuer, &tx.name)?,
            };
            let material_key = format!("{base}.{}", p.suffix);
            self.fenced(lease, move |c| c.data.clean_temps_for_key(&material_key))
                .await?;
            for direction in ["new", "old"] {
                lease.check().await?;
                let temporary_key = staged_key(key, &tx.id, &p.suffix, direction)?;
                self.fenced(lease, move |c| c.state.clean_temps_for_key(&temporary_key))
                    .await?;
                self.state_delete(&staged_key(key, &tx.id, &p.suffix, direction)?, lease)
                    .await?;
            }
        }
        if tx.phase == Phase::RolledBack && tx.parts.iter().all(|p| p.old_hash.is_none()) {
            let base = match tx.kind {
                Kind::Account => account_path(&tx.issuer, &tx.name)?,
                Kind::Certificate => cert_path(&tx.issuer, &tx.name)?,
            };
            let directory = base
                .rsplit_once('/')
                .ok_or_else(|| anyhow!("invalid material directory"))?
                .0
                .to_owned();
            self.fenced(lease, move |c| c.data.remove_empty_directory(&directory))
                .await?;
        }
        let directory = key
            .strip_suffix(".json")
            .ok_or_else(|| anyhow!("invalid transaction key"))?
            .to_owned();
        self.fenced(lease, move |c| c.state.remove_empty_directory(&directory))
            .await?;
        let temporary_key = key.to_owned();
        self.fenced(lease, move |c| c.state.clean_temps_for_key(&temporary_key))
            .await?;
        lease.check().await?;
        self.state_delete(key, lease).await?;
        Ok(())
    }
}

fn job_key(id: &str) -> Result<String> {
    ensure!(
        !id.is_empty()
            && id.len() <= 200
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            && !id.contains(".."),
        "invalid job identifier"
    );
    Ok(format!("jobs/{id}.json"))
}
fn staged_key(key: &str, id: &str, suffix: &str, direction: &str) -> Result<String> {
    ensure!(
        is_hex(id, 32)
            && matches!(suffix, "key" | "crt" | "json")
            && matches!(direction, "new" | "old"),
        "invalid transaction stage"
    );
    let name = key
        .strip_prefix("transactions/")
        .and_then(|s| s.strip_suffix(".json"))
        .filter(|s| is_hex(s, 64))
        .ok_or_else(|| anyhow!("invalid transaction key"))?;
    Ok(format!("transactions/{name}/{id}.{suffix}.{direction}"))
}

fn metadata_names(metadata: &Value) -> Result<Vec<String>> {
    let values = metadata
        .get("sans")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("certificate metadata requires SAN list"))?;
    ensure!(
        !values.is_empty() && values.len() <= 1024,
        "invalid certificate SAN list"
    );
    values
        .iter()
        .map(|v| {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("invalid certificate SAN"))?;
            ensure!(!s.is_empty() && s.len() <= 4096, "invalid certificate SAN");
            Ok(s.to_owned())
        })
        .collect()
}

fn validate_account(metadata: &Value, key: &[u8]) -> Result<()> {
    crate::certmagic::signing_key(key, "account-candidate")?;
    let object = metadata
        .as_object()
        .ok_or_else(|| anyhow!("account metadata must be an object"))?;
    if let Some(status) = object.get("status") {
        ensure!(
            status.is_null()
                || status
                    .as_str()
                    .is_some_and(|s| matches!(s, "" | "valid" | "deactivated" | "revoked")),
            "invalid account status"
        );
    }
    if let Some(contact) = object.get("contact") {
        ensure!(
            contact.is_null()
                || contact.as_array().is_some_and(|a| a.len() <= 1024
                    && a.iter()
                        .all(|s| s.as_str().is_some_and(|s| s.len() <= 4096))),
            "invalid account contact"
        );
    }
    for field in ["location", "orders"] {
        if let Some(value) = object.get(field) {
            ensure!(
                value.is_null() || value.as_str().is_some_and(|s| s.len() <= 8192),
                "invalid account URL metadata"
            );
        }
    }
    if let Some(v) = object.get("termsOfServiceAgreed") {
        ensure!(
            v.is_null() || v.is_boolean(),
            "invalid account agreement metadata"
        );
    }
    Ok(())
}

fn validate_certificate(crt: &[u8], key: &[u8], metadata: &Value) -> Result<()> {
    ensure!(
        crt.len() <= 4 * 1024 * 1024 && key.len() <= 128 * 1024,
        "certificate material size limit exceeded"
    );
    let blocks = crate::certmagic::pem_blocks(crt, "certificate-candidate")?;
    let mut chain = Vec::new();
    for (tag, der) in &blocks {
        ensure!(tag == "CERTIFICATE", "unexpected certificate PEM label");
        let (rest, _) = x509_parser::parse_x509_certificate(der)
            .map_err(|_| anyhow!("invalid certificate DER"))?;
        ensure!(rest.is_empty(), "trailing certificate DER");
        chain.push(rustls::pki_types::CertificateDer::from(der.to_vec()));
    }
    let signer = crate::certmagic::signing_key(key, "certificate-candidate")?;
    let certified = rustls::sign::CertifiedKey::new(chain, signer);
    certified
        .keys_match()
        .map_err(|_| anyhow!("certificate and private key do not match"))?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&blocks[0].1)
        .map_err(|_| anyhow!("invalid leaf certificate"))?;
    ensure!(
        leaf.validity().not_before <= leaf.validity().not_after,
        "invalid certificate validity interval"
    );
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| anyhow!("invalid certificate SAN"))?
        .ok_or_else(|| anyhow!("certificate has no SAN"))?;
    let actual: Vec<String> = san
        .value
        .general_names
        .iter()
        .filter_map(|g| match g {
            x509_parser::extensions::GeneralName::DNSName(s) => {
                Some(s.trim_end_matches('.').to_ascii_lowercase())
            }
            x509_parser::extensions::GeneralName::IPAddress(b) => match b.len() {
                4 => Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
                16 => {
                    let a: [u8; 16] = (*b).try_into().ok()?;
                    Some(std::net::Ipv6Addr::from(a).to_string())
                }
                _ => None,
            },
            _ => None,
        })
        .collect();
    for name in metadata_names(metadata)? {
        let normalized = name
            .parse::<std::net::IpAddr>()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| name.trim_end_matches('.').to_ascii_lowercase());
        ensure!(
            actual.contains(&normalized),
            "certificate metadata SAN not present in leaf"
        );
    }
    Ok(())
}

fn group_path(key: &str) -> bool {
    matches!(key, "acme" | "certificates")
        || key.starts_with("acme/")
        || key.starts_with("certificates/")
}
fn pending_core(core: &Core, key: &str) -> Result<bool> {
    Ok(core.state.load(key, true)?.is_some()
        || core
            .state
            .load(&key.replace(".json", ".quarantine"), true)?
            .is_some())
}
