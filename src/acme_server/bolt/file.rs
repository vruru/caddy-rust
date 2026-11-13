//! Same-descriptor cooperative locking and checked positional reads. A foreign
//! truncate can produce an I/O/corruption error, never an mmap SIGBUS.

use super::{Budget, Error, Result};
use std::{
    fs::{File, TryLockError},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct LockedFile {
    file: File,
    path: PathBuf,
    identity: (u64, u64),
    parent: Option<File>,
    writable: bool,
    failed: bool,
}

impl LockedFile {
    pub fn retained_bytes(&self) -> usize {
        self.path.capacity() + std::mem::size_of::<Self>()
    }
    pub fn open(
        path: &Path,
        writable: bool,
        timeout: Duration,
        budget: &mut impl Budget,
    ) -> Result<Self> {
        budget.work(1)?;
        budget.charge(path.as_os_str().as_encoded_bytes().len())?;
        let mut saved = PathBuf::new();
        saved
            .try_reserve_exact(path.as_os_str().as_encoded_bytes().len())
            .map_err(|_| Error::Limit)?;
        saved.push(path);
        use rustix::fs::{Mode, OFlags, open};
        let flags = OFlags::CLOEXEC
            | OFlags::NONBLOCK
            | if writable {
                OFlags::RDWR
            } else {
                OFlags::RDONLY
            };
        let (fd, created) = if writable {
            match open(
                path,
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => (fd, true),
                Err(rustix::io::Errno::EXIST) => (
                    open(path, flags, Mode::empty()).map_err(|e| Error::Io(e.into()))?,
                    false,
                ),
                Err(e) => return Err(Error::Io(e.into())),
            }
        } else {
            (
                open(path, flags, Mode::empty()).map_err(|e| Error::Io(e.into()))?,
                false,
            )
        };
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(Error::Corrupt("database is not a regular file"));
        }
        let parent = if created || (writable && metadata.len() == 0) {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            Some(File::from(
                open(
                    parent,
                    OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::RDONLY,
                    Mode::empty(),
                )
                .map_err(|e| Error::Io(e.into()))?,
            ))
        } else {
            None
        };
        let deadline = Instant::now().checked_add(timeout).ok_or(Error::Limit)?;
        loop {
            budget.work(1)?;
            match if writable {
                file.try_lock()
            } else {
                file.try_lock_shared()
            } {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(Error::Timeout);
                    }
                    std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
                }
                Err(TryLockError::Error(e)) => return Err(e.into()),
            }
        }
        budget.work(1)?;
        let this = Self {
            file,
            path: saved,
            identity: (metadata.dev(), metadata.ino()),
            parent,
            writable,
            failed: false,
        };
        // A waiter can acquire an old inode after somebody renamed the path.
        // Never treat that descriptor as the currently published database.
        this.check_identity()?;
        Ok(this)
    }

    fn check_identity(&self) -> Result<()> {
        let fd = self.file.metadata()?;
        let path = std::fs::metadata(&self.path)?;
        if !path.is_file()
            || fd.nlink() == 0
            || (fd.dev(), fd.ino()) != self.identity
            || (path.dev(), path.ino()) != self.identity
        {
            return Err(Error::Corrupt("database file identity changed"));
        }
        Ok(())
    }

    pub fn initialize(&mut self, page_size: usize, budget: &mut impl Budget) -> Result<()> {
        use std::os::unix::fs::FileExt;
        budget.work(1)?;
        self.check_identity()?;
        if !self.writable || self.failed || self.file.metadata()?.len() != 0 {
            return Err(Error::Corrupt("database is not empty"));
        }
        let mut meta = super::Meta {
            page_size,
            root: 3,
            sequence: 0,
            freelist: 2,
            high_water: 4,
            txid: 0,
            slot: 0,
        };
        let first = super::meta::encode(&meta)?;
        meta.txid = 1;
        meta.slot = 1;
        let second = super::meta::encode(&meta)?;
        let size = page_size.checked_mul(2).ok_or(Error::Limit)?;
        budget.charge(size)?;
        let mut data = Vec::new();
        data.try_reserve_exact(size).map_err(|_| Error::Limit)?;
        data.resize(size, 0);
        data[0..8].copy_from_slice(&2u64.to_le_bytes());
        data[8..10].copy_from_slice(&16u16.to_le_bytes());
        data[page_size..page_size + 8].copy_from_slice(&3u64.to_le_bytes());
        data[page_size + 8..page_size + 10].copy_from_slice(&2u16.to_le_bytes());
        budget.work(0)?;
        self.failed = true;
        self.file.set_len((page_size * 4) as u64)?;
        self.file.write_all_at(&data, (page_size * 2) as u64)?;
        self.file.sync_all()?;
        budget.work(0)?;
        self.file.write_all_at(&first, 0)?;
        self.file.sync_all()?;
        budget.work(0)?;
        self.file.write_all_at(&second, page_size as u64)?;
        self.file.sync_all()?;
        if let Some(parent) = &self.parent {
            parent.sync_all()?;
        }
        self.check_identity()?;
        self.parent = None;
        self.failed = false;
        let _ = budget.work(0);
        Ok(())
    }

    pub fn snapshot(&self, max_bytes: usize, budget: &mut impl Budget) -> Result<Vec<u8>> {
        if self.failed {
            return Err(Error::Corrupt("database requires recovery"));
        }
        self.snapshot_bytes(max_bytes, budget)
    }
    /// A failed publication has an uncertain old/new commit outcome. Keep the
    /// SAME exclusively locked descriptor, re-read its real bytes under a NEW
    /// operation budget, and fully check its committed tree before reusing it.
    /// Refusal/cancellation/corruption keeps the handle poisoned; never create
    /// an empty replacement or follow a renamed path during recovery.
    pub fn recover_if_needed(&mut self, max_bytes: usize, budget: &mut impl Budget) -> Result<()> {
        if !self.failed {
            return Ok(());
        }
        if !self.writable {
            return Err(Error::Corrupt("read-only poisoned database"));
        }
        let bytes = self.snapshot_bytes(max_bytes, budget)?;
        drop(super::parse(&bytes, budget)?);
        budget.work(1)?;
        self.check_identity()?;
        self.failed = false;
        Ok(())
    }
    fn snapshot_bytes(&self, max_bytes: usize, budget: &mut impl Budget) -> Result<Vec<u8>> {
        self.check_identity()?;
        budget.work(1)?;
        let len = usize::try_from(self.file.metadata()?.len()).map_err(|_| Error::Limit)?;
        if len > max_bytes {
            return Err(Error::Limit);
        }
        budget.charge(len)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| Error::Limit)?;
        bytes.resize(len, 0);
        let mut offset = 0;
        while offset < len {
            budget.work(1)?;
            let chunk = (len - offset).min(64 * 1024);
            #[cfg(unix)]
            let result = {
                use std::os::unix::fs::FileExt;
                self.file
                    .read_at(&mut bytes[offset..offset + chunk], offset as u64)
            };
            #[cfg(not(unix))]
            compile_error!("ACME Bolt locking/positional I/O requires the audited Unix backend");
            match result {
                Ok(0) => return Err(Error::Corrupt("file shortened during snapshot")),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        if self.file.metadata()?.len() != len as u64 {
            return Err(Error::Corrupt("file length changed during snapshot"));
        }
        self.check_identity()?;
        budget.work(1)?;
        Ok(bytes)
    }

    /// The original descriptor remains exclusively locked throughout all data
    /// and metadata writes. Failure after the first write poisons this handle;
    /// callers must recover/reopen and validate before accepting further writes.
    /// A successful return follows BOTH syncs, never just an in-memory update.
    pub fn commit(
        &mut self,
        expected: &[u8],
        plan: &super::encode::Plan,
        budget: &mut impl Budget,
    ) -> Result<()> {
        use std::os::unix::fs::FileExt;
        budget.work(1)?;
        if !self.writable || self.failed {
            return Err(Error::Corrupt("database is not writable"));
        }
        self.check_identity()?;
        if super::meta::select_meta(expected)? != plan.base {
            return Err(Error::Corrupt("stale transaction plan"));
        }
        if self.file.metadata()?.len() != expected.len() as u64 {
            return Err(Error::Corrupt("database length changed"));
        }
        // Match the exact captured image on the SAME FD. Advisory locking cannot
        // prevent a malicious unrelated writer, but no mapped access is involved.
        let mut scratch = [0u8; 4096];
        let mut offset = 0;
        while offset < expected.len() {
            budget.work(1)?;
            let n = (expected.len() - offset).min(scratch.len());
            self.file.read_exact_at(&mut scratch[..n], offset as u64)?;
            if scratch[..n] != expected[offset..offset + n] {
                return Err(Error::Corrupt("database image changed"));
            }
            offset += n;
        }
        let required = plan
            .meta
            .high_water
            .checked_mul(plan.meta.page_size as u64)
            .ok_or(Error::Limit)?;
        // All page ranges and the complete future tree are checked before I/O.
        // Preview is operation-owned; it is explicitly dropped before writes.
        drop(plan.preview(expected, budget)?);
        budget.work(0)?;
        self.failed = true;
        if required > expected.len() as u64 {
            self.file.set_len(required)?;
        }
        for page in &plan.pages {
            budget.work(page.bytes.len().div_ceil(64).max(1))?;
            let at = page
                .id
                .checked_mul(plan.meta.page_size as u64)
                .ok_or(Error::Limit)?;
            self.file.write_all_at(&page.bytes, at)?;
        }
        budget.work(0)?;
        self.file.sync_all()?;
        budget.work(0)?;
        self.check_identity()?;
        self.file.write_all_at(
            &plan.metadata,
            (plan.meta.slot * plan.meta.page_size) as u64,
        )?;
        budget.work(0)?;
        self.file.sync_all()?;
        self.check_identity()?;
        // Once durability succeeded, cancellation cannot turn this into a
        // claimed rollback. The accepted transaction is complete.
        self.failed = false;
        // Observability/checkpoint only: a late cancellation cannot undo a
        // completed fsync. No further allocation or database mutation follows.
        let _ = budget.work(0);
        Ok(())
    }
}
