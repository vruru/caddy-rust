//! CertMagic-compatible leases. Stale unlink remains non-atomic with original
//! Go writers; inode/token checks detect loss, they cannot create a fencing ABI.
use super::{Core, io};
use anyhow::{Result, anyhow, bail, ensure};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;

#[derive(Serialize, Deserialize)]
struct LockMeta {
    #[serde(default, deserialize_with = "zero_time")]
    created: String,
    #[serde(default, deserialize_with = "zero_time")]
    updated: String,
    #[serde(default)]
    rust_owner: Option<String>,
}

fn zero_time<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

struct Inner {
    core: Arc<Core>,
    name: String,
    key: String,
    file: Mutex<File>,
    dev: u64,
    ino: u64,
    created: String,
    owner: String,
    stop: CancellationToken,
    lost: CancellationToken,
    released: AtomicBool,
    gate: Arc<NativeGate>,
    mutation: Mutex<()>,
    cancel: CancellationToken,
}

#[derive(Debug)]
pub(super) struct AcquisitionCancelled;
impl std::fmt::Display for AcquisitionCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("storage lease acquisition cancelled")
    }
}
impl std::error::Error for AcquisitionCancelled {}
#[derive(Debug)]
pub(super) struct GateBusy;
impl std::fmt::Display for GateBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("storage group acquisition deadline exceeded")
    }
}
impl std::error::Error for GateBusy {}
fn cancelled() -> anyhow::Error {
    anyhow::Error::new(AcquisitionCancelled)
}

pub(super) struct NativeGate {
    core: Arc<Core>,
    key: String,
    file: Mutex<Option<File>>,
    dev: u64,
    ino: u64,
}

impl NativeGate {
    pub(super) fn verify(&self) -> Result<()> {
        let guard = self
            .file
            .lock()
            .map_err(|_| anyhow!("native gate state unavailable"))?;
        let file = guard
            .as_ref()
            .ok_or_else(|| anyhow!("native gate released"))?;
        let (parent, name) = self
            .core
            .state
            .parent(&self.key, false)?
            .ok_or_else(|| anyhow!("native gate missing"))?;
        let st = fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| anyhow!("native gate missing"))?;
        io::validate_file(&st, self.core.state.uid, true)?;
        let held = fs::fstat(file).map_err(|_| anyhow!("native gate metadata unavailable"))?;
        ensure!(
            io::device_id(&st) == self.dev
                && st.st_ino == self.ino
                && io::device_id(&held) == self.dev
                && held.st_ino == self.ino,
            "native gate replaced"
        );
        Ok(())
    }
    fn close(&self) -> Result<()> {
        let mut guard = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Closing the last open file description releases flock even when the
        // CertMagic owner check failed. Gate files themselves are never unlinked.
        drop(guard.take());
        Ok(())
    }
}

async fn native_gate(
    core: Arc<Core>,
    key: String,
    cancel: CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<Arc<NativeGate>> {
    let c = core.clone();
    let k = key.clone();
    let file = tokio::task::spawn_blocking(move || c.state.gate(&k))
        .await
        .map_err(|_| anyhow!("native gate open task failed"))??;
    let st = fs::fstat(&file).map_err(|_| anyhow!("native gate metadata unavailable"))?;
    let gate = Arc::new(NativeGate {
        core,
        key,
        file: Mutex::new(Some(file)),
        dev: io::device_id(&st),
        ino: st.st_ino,
    });
    loop {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow::Error::new(GateBusy));
        }
        let work = gate.clone();
        let acquired = tokio::task::spawn_blocking(move || -> Result<bool> {
            let guard = work
                .file
                .lock()
                .map_err(|_| anyhow!("native gate state unavailable"))?;
            let file = guard
                .as_ref()
                .ok_or_else(|| anyhow!("native gate released"))?;
            match fs::flock(file, fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => Ok(true),
                Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
                Err(_) => bail!("native gate locking unsupported or failed"),
            }
        })
        .await
        .map_err(|_| anyhow!("native gate acquisition task failed"))??;
        if acquired {
            gate.verify()?;
            return Ok(gate);
        }
        tokio::select! {biased;_=cancel.cancelled()=>return Err(cancelled()),_=tokio::time::sleep(Duration::from_millis(100))=>{}}
    }
}

/// Drop cancels heartbeats and schedules ownership-checked release. Normal
/// completion should await `release`; without a runtime the file ages stale.
pub struct StorageLease {
    inner: Arc<Inner>,
}

fn stamp() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| anyhow!("lock clock formatting failed"))
}

fn stale(meta: &LockMeta) -> Result<bool> {
    let reference = if meta.updated.is_empty() || meta.updated.starts_with("0001-01-01") {
        &meta.created
    } else {
        &meta.updated
    };
    if reference.is_empty() || reference.starts_with("0001-01-01") {
        return Ok(true);
    }
    let reference = OffsetDateTime::parse(reference, &Rfc3339)
        .map_err(|_| anyhow!("invalid lock timestamp"))?;
    Ok(OffsetDateTime::now_utc() - reference > time::Duration::seconds(10))
}

// Move the whole guard into the blocking task, including while it is queued.
// A dropped async waiter must not hide an I/O error or a worker panic.
struct LostOnFailure(Option<CancellationToken>);
impl LostOnFailure {
    fn new(token: &CancellationToken) -> Self {
        Self(Some(token.clone()))
    }
    fn fire(&mut self) {
        if let Some(token) = self.0.take() {
            token.cancel();
        }
    }
    fn settle<T>(&mut self, result: &Result<T>) {
        if result.is_ok() {
            self.0 = None;
        } else {
            self.fire();
        }
    }
}
impl Drop for LostOnFailure {
    fn drop(&mut self) {
        self.fire();
    }
}

impl StorageLease {
    pub fn name(&self) -> &str {
        &self.inner.name
    }
    pub fn lost(&self) -> CancellationToken {
        self.inner.lost.clone()
    }
    pub(super) fn ended(&self) -> CancellationToken {
        self.inner.stop.clone()
    }
    pub(super) fn owner(&self) -> &str {
        &self.inner.owner
    }
    pub(super) fn belongs(&self, core: &Arc<Core>, name: &str) -> bool {
        Arc::ptr_eq(core, &self.inner.core) && self.inner.name == name
    }
    /// A blocking mutation retains the native gate even if its async caller is
    /// dropped. Release waits for this critical section before closing flock.
    pub(super) async fn mutate<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let guard = LostOnFailure::new(&self.inner.lost);
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let _mutation = inner
                .mutation
                .lock()
                .map_err(|_| anyhow!("lease mutation state unavailable"))?;
            // Rebind after acquiring the mutex: unwind cancels before unlock.
            let mut guard = guard;
            let result = (|| {
                inner.verify(false)?;
                let value = operation()?;
                inner.verify(false)?;
                Ok(value)
            })();
            // Cancel before releasing the mutation mutex so a queued writer
            // cannot pass verification between this failure and cancellation.
            guard.settle(&result);
            result
        })
        .await
        .map_err(|_| {
            self.inner.lost.cancel();
            anyhow!("fenced mutation task failed")
        })?
    }
    pub async fn check(&self) -> Result<()> {
        let guard = LostOnFailure::new(&self.inner.lost);
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = guard;
            let result = inner.verify(false);
            guard.settle(&result);
            result
        })
        .await
        .map_err(|_| {
            self.inner.lost.cancel();
            anyhow!("lease check task failed")
        })?
    }
    pub async fn release(self) -> Result<()> {
        self.inner.stop.cancel();
        if self.inner.released.swap(true, Ordering::AcqRel) {
            bail!("lease already released");
        }
        let guard = LostOnFailure::new(&self.inner.lost);
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = guard;
            let result = inner.remove();
            guard.settle(&result);
            result
        })
        .await
        .map_err(|_| {
            self.inner.lost.cancel();
            anyhow!("lease release task failed")
        })?
    }
}

impl Drop for StorageLease {
    fn drop(&mut self) {
        self.inner.stop.cancel();
        if self.inner.released.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = self.inner.clone();
            runtime.spawn_blocking(move || {
                let _ = inner.remove();
            });
        }
    }
}

impl Inner {
    fn identity(&self, file: &File) -> Result<()> {
        let (parent, name) = self
            .core
            .data
            .parent(&self.key, false)?
            .ok_or_else(|| anyhow!("lease lost"))?;
        let st = fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| anyhow!("lease lost"))?;
        io::validate_file(&st, self.core.data.uid, false)?;
        let actual = fs::fstat(file).map_err(|_| anyhow!("lease metadata unavailable"))?;
        ensure!(
            io::device_id(&st) == self.dev
                && st.st_ino == self.ino
                && io::device_id(&actual) == self.dev
                && actual.st_ino == self.ino,
            "lease lost"
        );
        Ok(())
    }

    fn read_meta(&self, file: &mut File) -> Result<LockMeta> {
        file.seek(SeekFrom::Start(0))
            .map_err(|_| anyhow!("lease read failed"))?;
        let mut bytes = Vec::new();
        (&*file)
            .take(2049)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow!("lease read failed"))?;
        ensure!(bytes.len() <= 2048, "lease metadata size limit exceeded");
        let meta: LockMeta = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("lease metadata changed or invalid"))?;
        ensure!(
            meta.created == self.created && meta.rust_owner.as_deref() == Some(self.owner.as_str()),
            "lease lost"
        );
        Ok(meta)
    }

    fn verify(&self, refresh: bool) -> Result<()> {
        ensure!(
            !self.released.load(Ordering::Acquire)
                && !self.lost.is_cancelled()
                && !self.cancel.is_cancelled(),
            "lease lost"
        );
        self.gate.verify()?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow!("lease state unavailable"))?;
        self.identity(&file)?;
        let mut meta = self.read_meta(&mut file)?;
        ensure!(!stale(&meta)?, "lease freshness expired");
        if refresh {
            meta.updated = stamp()?;
            let mut bytes =
                serde_json::to_vec(&meta).map_err(|_| anyhow!("lease metadata encoding failed"))?;
            bytes.push(b'\n');
            file.set_len(0)
                .map_err(|_| anyhow!("lease heartbeat failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| anyhow!("lease heartbeat failed"))?;
            file.write_all(&bytes)
                .map_err(|_| anyhow!("lease heartbeat failed"))?;
            file.sync_all()
                .map_err(|_| anyhow!("lease heartbeat synchronization failed"))?;
            self.identity(&file)?;
        }
        Ok(())
    }

    fn remove(&self) -> Result<()> {
        // A panic in a fenced operation poisons this mutex, but cleanup must
        // still wait for that operation to finish and release the native gate.
        let mutation = self.mutation.lock();
        let poisoned = mutation.is_err();
        let _mutation = mutation.unwrap_or_else(std::sync::PoisonError::into_inner);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let mut file = self
                .file
                .lock()
                .map_err(|_| anyhow!("lease state unavailable"))?;
            self.identity(&file)?;
            self.read_meta(&mut file)?;
            self.core.data.delete(&self.key)
        }));
        // Close the native gate even if cleanup panics. Detached operations
        // have already finished because the mutation mutex is still held.
        let unlocked = self.gate.close();
        let result = match outcome {
            Ok(outcome) => (|| {
                outcome?;
                unlocked?;
                ensure!(!poisoned, "lease mutation state poisoned during release");
                Ok(())
            })(),
            Err(panic) => {
                self.lost.cancel();
                std::panic::resume_unwind(panic)
            }
        };
        if result.is_err() {
            self.lost.cancel();
        }
        result
    }
}

// An O_EXCL file is ours only while its held descriptor still matches the
// directory entry. Never remove a replacement written by another Go process.
fn discard_initializing_lock(core: &Core, key: &str, file: &File) -> Result<()> {
    let held = fs::fstat(file).map_err(|_| anyhow!("failed lock identity unavailable"))?;
    let Some((parent, name)) = core.data.parent(key, false)? else {
        return Ok(());
    };
    let actual = match fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(_) => bail!("failed lock cleanup metadata unavailable"),
    };
    ensure!(
        io::device_id(&actual) == io::device_id(&held) && actual.st_ino == held.st_ino,
        "failed lock replaced during initialization"
    );
    fs::unlinkat(&parent, &name, AtFlags::empty())
        .map_err(|_| anyhow!("failed lock cleanup unavailable"))?;
    fs::fsync(&parent).map_err(|_| anyhow!("failed lock cleanup synchronization failed"))?;
    Ok(())
}

pub(super) async fn acquire(
    core: Arc<Core>,
    name: &str,
    cancel: CancellationToken,
) -> Result<StorageLease> {
    ensure!(!name.is_empty() && name.len() <= 2048, "invalid lock name");
    let safe = super::safe(name);
    ensure!(
        !safe.is_empty() && safe.len() <= 240,
        "invalid lock storage component"
    );
    let key = format!("locks/{safe}.lock");
    let owner = io::random_id()?;
    let start = tokio::time::Instant::now();
    let gate = native_gate(
        core.clone(),
        format!("leases/{}.gate", super::hash(safe.as_bytes())),
        cancel.clone(),
        start + Duration::from_secs(120),
    )
    .await?;
    let mut empty_count = 0;
    loop {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        ensure!(
            start.elapsed() < Duration::from_secs(120),
            "lock acquisition deadline exceeded"
        );
        let operation_core = core.clone();
        let operation_key = key.clone();
        let operation_owner = owner.clone();
        let operation_name = name.to_owned();
        let operation_gate = gate.clone();
        let operation_cancel = cancel.clone();
        let created = tokio::task::spawn_blocking(move || -> Result<Option<Arc<Inner>>> {
            let Some(mut file) = operation_core.data.exclusive(&operation_key, 0o644)? else {
                return Ok(None);
            };
            let initialized = (|| -> Result<_> {
                let created = stamp()?;
                let meta = LockMeta {
                    created: created.clone(),
                    updated: created.clone(),
                    rust_owner: Some(operation_owner.clone()),
                };
                let mut bytes =
                    serde_json::to_vec(&meta).map_err(|_| anyhow!("lock encoding failed"))?;
                bytes.push(b'\n');
                file.write_all(&bytes)
                    .map_err(|_| anyhow!("lock initialization failed"))?;
                file.sync_all()
                    .map_err(|_| anyhow!("lock synchronization failed"))?;
                let st = fs::fstat(&file).map_err(|_| anyhow!("lock metadata unavailable"))?;
                Ok((created, st))
            })();
            let (created, st) = match initialized {
                Ok(value) => value,
                Err(error) => {
                    discard_initializing_lock(&operation_core, &operation_key, &file)?;
                    return Err(error);
                }
            };
            Ok(Some(Arc::new(Inner {
                core: operation_core,
                name: operation_name,
                key: operation_key,
                file: Mutex::new(file),
                dev: io::device_id(&st),
                ino: st.st_ino,
                created,
                owner: operation_owner,
                stop: CancellationToken::new(),
                lost: CancellationToken::new(),
                released: AtomicBool::new(false),
                gate: operation_gate,
                mutation: Mutex::new(()),
                cancel: operation_cancel,
            })))
        })
        .await
        .map_err(|_| anyhow!("lock acquisition task failed"))??;
        if let Some(inner) = created {
            let heartbeat = inner.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval_at(
                    tokio::time::Instant::now() + Duration::from_secs(5),
                    Duration::from_secs(5),
                );
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! { biased; _ = heartbeat.stop.cancelled() => break, _ = heartbeat.cancel.cancelled()=>{heartbeat.lost.cancel();break;}, _ = tick.tick() => {} }
                    let work = heartbeat.clone();
                    if !matches!(
                        tokio::task::spawn_blocking(move || work.verify(true)).await,
                        Ok(Ok(()))
                    ) {
                        heartbeat.lost.cancel();
                        break;
                    }
                }
            });
            let lease = StorageLease { inner };
            if cancel.is_cancelled() {
                let _ = lease.release().await;
                return Err(cancelled());
            }
            return Ok(lease);
        }
        let operation_core = core.clone();
        let operation_key = key.clone();
        let state = tokio::task::spawn_blocking(move || -> Result<bool> {
            let Some((parent, file_name)) = operation_core.data.parent(&operation_key, false)?
            else {
                return Ok(false);
            };
            let fd = match fs::openat(
                &parent,
                &file_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => return Ok(false),
                Err(_) => bail!("existing lock unavailable"),
            };
            let st = fs::fstat(&fd).map_err(|_| anyhow!("existing lock metadata unavailable"))?;
            io::validate_file(&st, operation_core.data.uid, false)?;
            ensure!(
                st.st_size >= 0 && st.st_size <= 2048,
                "existing lock size limit exceeded"
            );
            let mut bytes = Vec::new();
            File::from(fd)
                .take(2049)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow!("existing lock read failed"))?;
            if bytes.iter().all(u8::is_ascii_whitespace) {
                return Ok(true);
            }
            let meta: LockMeta = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow!("existing lock metadata invalid"))?;
            if stale(&meta)? {
                // The original Go stale unlink protocol has a race here too.
                // Recheck inode and exact bytes to detect ordinary replacement.
                let now = fs::statat(&parent, &file_name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| anyhow!("existing lock changed"))?;
                if now.st_ino == st.st_ino && now.st_dev == st.st_dev {
                    let latest = operation_core.data.load(&operation_key, false)?;
                    if latest.as_deref().map(Vec::as_slice) == Some(bytes.as_slice()) {
                        operation_core.data.delete(&operation_key)?;
                    }
                }
            }
            Ok(false)
        })
        .await
        .map_err(|_| anyhow!("lock inspection task failed"))??;
        let delay = if state {
            empty_count += 1;
            if empty_count >= 8 {
                let operation_core = core.clone();
                let operation_key = key.clone();
                tokio::task::spawn_blocking(move || -> Result<()> {
                    if operation_core
                        .data
                        .load(&operation_key, false)?
                        .is_some_and(|b| b.iter().all(u8::is_ascii_whitespace))
                    {
                        operation_core.data.delete(&operation_key)?;
                    }
                    Ok(())
                })
                .await
                .map_err(|_| anyhow!("empty lock recovery task failed"))??;
                empty_count = 0;
            }
            Duration::from_millis(250)
        } else {
            empty_count = 0;
            Duration::from_secs(1)
        };
        tokio::select! { biased; _=cancel.cancelled()=>return Err(cancelled()),_=tokio::time::sleep(delay)=>{} }
    }
}

/// A fresh open file description per canonical transaction group acquisition.
/// The file is never unlinked and LOCK_NB waits never orphan a blocking waiter.
pub(super) async fn transaction_gate(
    core: Arc<Core>,
    key: &str,
    cancel: CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<Arc<NativeGate>> {
    native_gate(
        core,
        format!("groups/{}.gate", super::hash(key.as_bytes())),
        cancel,
        deadline,
    )
    .await
}
