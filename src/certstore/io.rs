//! FD-relative storage operations. Errors deliberately omit paths and payloads.
use anyhow::{Result, anyhow, bail, ensure};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
    sync::Arc,
};
use zeroize::Zeroizing;

pub(super) const MAX_FILE: usize = 12 * 1024 * 1024;
const MAX_LIST: usize = 50_000;

// dev_t is signed 32-bit on macOS and unsigned 64-bit on Linux. Treat it as
// an opaque identity within the current host; state migration is explicit.
#[allow(clippy::unnecessary_cast)]
pub(super) fn device_id(st: &fs::Stat) -> u64 {
    st.st_dev as u64
}

#[derive(Clone)]
pub(super) struct Root {
    pub fd: Arc<OwnedFd>,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
}

#[derive(PartialEq, Eq)]
pub(super) struct Signature {
    dev: u64,
    ino: u64,
    size: u64,
    modified: i128,
    changed: i128,
}
impl Signature {
    fn from_stat(st: &fs::Stat) -> Self {
        Self {
            dev: device_id(st),
            ino: st.st_ino,
            size: st.st_size as u64,
            modified: st.st_mtime as i128 * 1_000_000_000 + st.st_mtime_nsec as i128,
            changed: st.st_ctime as i128 * 1_000_000_000 + st.st_ctime_nsec as i128,
        }
    }
}

/// Retain the actual read inode until every member of a group is verified.
/// Published files use atomic replacement; retaining their descriptors prevents
/// unlinked inode numbers being reused during a grouped snapshot check.
pub(super) struct PinnedRead {
    file: File,
    bytes:crate::cert_transient::Bytes,
    signature: Signature,
    uid: u32,
    private: bool,
}
impl PinnedRead {
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
    pub fn verify(&self) -> Result<()> {
        let current = fs::fstat(&self.file).map_err(|_| anyhow!("file metadata unavailable"))?;
        validate_file(&current, self.uid, self.private)?;
        ensure!(
            self.signature == Signature::from_stat(&current),
            "storage generation changed during grouped read"
        );
        Ok(())
    }
    pub fn into_bytes(self) -> Result<Zeroizing<Vec<u8>>> {
        self.bytes.into_untracked()
    }
    pub fn into_owned_bytes(self)->crate::cert_transient::Bytes {self.bytes}
}

pub(super) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| anyhow!("secure random source unavailable"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub(super) fn components(key: &str) -> Result<Vec<&str>> {
    ensure!(
        !key.is_empty() && key.len() <= 4096 && !key.contains('\0'),
        "invalid storage key"
    );
    let parts: Vec<_> = key.split('/').collect();
    ensure!(
        parts.len() <= 64
            && parts
                .iter()
                .all(|s| !s.is_empty() && *s != "." && *s != ".." && s.len() <= 255),
        "invalid storage key"
    );
    Ok(parts)
}

fn cstr(name: &str) -> Result<CString> {
    CString::new(name).map_err(|_| anyhow!("invalid storage component"))
}

fn validate_dir(fd: &OwnedFd, uid: u32, final_owned: bool, private: bool) -> Result<()> {
    let st = fs::fstat(fd).map_err(|_| anyhow!("directory metadata unavailable"))?;
    ensure!(
        FileType::from_raw_mode(st.st_mode) == FileType::Directory
            && (st.st_uid == uid || (!final_owned && st.st_uid == 0))
            && st.st_mode & 0o022 == 0
            && (!private || st.st_mode & 0o077 == 0),
        "unsafe storage directory"
    );
    Ok(())
}

pub(super) fn directory(
    parent: &OwnedFd,
    name: &str,
    uid: u32,
    create: bool,
) -> Result<Option<OwnedFd>> {
    Ok(directory_at(parent, name, uid, create, false)?.map(|(fd, _)| fd))
}

/// A shared mount or sticky directory is a traversal boundary, never a store.
/// The caller must require an immediately following private, user-owned anchor.
/// All paths below an admitted Root continue through strict `directory` above.
fn directory_at(
    parent: &OwnedFd,
    name: &str,
    uid: u32,
    create: bool,
    allow_mount_ancestor: bool,
) -> Result<Option<(OwnedFd, bool)>> {
    let name = cstr(name)?;
    if create {
        match fs::mkdirat(parent, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                fs::fsync(parent).map_err(|_| anyhow!("directory synchronization failed"))?;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => bail!("directory creation failed"),
        }
    }
    let fd = match fs::openat(
        parent,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
        Err(_) => bail!("storage directory unavailable or symlink"),
    };
    let mount_ancestor = if let Err(error) = validate_dir(&fd, uid, false, false) {
        if !allow_mount_ancestor { return Err(error); }
        let st=fs::fstat(&fd).map_err(|_|anyhow!("mount ancestor metadata unavailable"))?;
        let parent_st=fs::fstat(parent).map_err(|_|anyhow!("mount parent metadata unavailable"))?;
        ensure!(crate::storage_boundary::shared_mount_root(&parent_st,&st)
            || crate::storage_boundary::sticky_parent(&st,uid),
            "unsafe storage ancestor");
        true
    } else { false };
    Ok(Some((fd, mount_ancestor)))
}

impl Root {
    pub fn signature(&self, key: &str) -> Result<Option<Signature>> {
        let Some((parent, name)) = self.parent(key, false)? else {
            return Ok(None);
        };
        let st = match fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => bail!("storage metadata unavailable"),
        };
        validate_file(&st, self.uid, key.ends_with(".key"))?;
        ensure!(
            st.st_size >= 0 && st.st_size as u64 <= MAX_FILE as u64,
            "storage value size limit exceeded"
        );
        Ok(Some(Signature::from_stat(&st)))
    }
    pub fn stat(&self, key: &str) -> Result<Option<(bool, i128, u64)>> {
        let Some((parent, name)) = self.parent(key, false)? else {
            return Ok(None);
        };
        let st = match fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => bail!("storage metadata unavailable"),
        };
        let terminal = match FileType::from_raw_mode(st.st_mode) {
            FileType::Directory => {
                let fd = fs::openat(
                    &parent,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| anyhow!("storage directory unavailable"))?;
                validate_dir(&fd, self.uid, false, false)?;
                false
            }
            FileType::RegularFile => {
                validate_file(&st, self.uid, key.ends_with(".key"))?;
                true
            }
            _ => bail!("unsupported storage entry type"),
        };
        ensure!(st.st_size >= 0, "invalid storage file size");
        Ok(Some((
            terminal,
            st.st_mtime as i128 * 1_000_000_000 + st.st_mtime_nsec as i128,
            st.st_size as u64,
        )))
    }
    pub fn open(path: &Path, private: bool) -> Result<Self> {
        ensure!(path.is_absolute(), "storage root must be absolute");
        let normalized=crate::storage_boundary::system_absolute(path).map_err(|_|anyhow!("storage system directory unavailable"))?;
        let path=normalized.as_ref();
        let uid = rustix::process::geteuid().as_raw();
        let mut fd = fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| anyhow!("storage root unavailable"))?;
        let mut count = 0usize;
        let mut private_anchor_required=false;
        let mut components=path.components().peekable();
        while let Some(component)=components.next() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    count += 1;
                    ensure!(count <= 64, "storage root too deep");
                    let name = name
                        .to_str()
                        .ok_or_else(|| anyhow!("storage component is not UTF-8"))?;
                    let (next,mount_ancestor)=directory_at(&fd,name,uid,true,
                        components.peek().is_some() && !private_anchor_required)?
                        .ok_or_else(||anyhow!("storage root unavailable"))?;
                    if private_anchor_required {
                        let st=fs::fstat(&next).map_err(|_|anyhow!("private anchor metadata unavailable"))?;
                        ensure!(crate::storage_boundary::private_anchor(&st,uid),"mount requires a private user-owned anchor");
                    }
                    private_anchor_required=mount_ancestor;
                    fd=next;
                }
                _ => bail!("invalid storage root"),
            }
        }
        ensure!(!private_anchor_required,"mount root requires a private storage anchor");
        ensure!(count > 0, "filesystem root cannot be a store");
        validate_dir(&fd, uid, true, private)?;
        ensure_local(&fd)?;
        let st = fs::fstat(&fd).map_err(|_| anyhow!("storage root metadata unavailable"))?;
        Ok(Self {
            fd: Arc::new(fd),
            uid,
            dev: device_id(&st),
            ino: st.st_ino,
        })
    }

    pub fn parent(&self, key: &str, create: bool) -> Result<Option<(OwnedFd, CString)>> {
        let parts = components(key)?;
        let mut fd = fs::openat(
            &*self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| anyhow!("storage root unavailable"))?;
        for part in &parts[..parts.len() - 1] {
            match directory(&fd, part, self.uid, create)? {
                Some(next) => fd = next,
                None => return Ok(None),
            }
        }
        Ok(Some((fd, cstr(parts[parts.len() - 1])?)))
    }

    pub fn exclusive(&self, key: &str, mode: u32) -> Result<Option<File>> {
        let mode = match mode {
            0o600 => Mode::from_raw_mode(0o600),
            0o644 => Mode::from_raw_mode(0o644),
            _ => bail!("unsupported private storage mode"),
        };
        let (parent, name) = self
            .parent(key, true)?
            .ok_or_else(|| anyhow!("storage parent unavailable"))?;
        let fd = match fs::openat(
            &parent,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::EXIST) => return Ok(None),
            Err(_) => bail!("exclusive storage file creation failed"),
        };
        fs::fsync(&parent).map_err(|_| anyhow!("storage directory synchronization failed"))?;
        Ok(Some(File::from(fd)))
    }

    /// Persistent native gate files must never be replaced or unlinked.
    pub fn gate(&self, key: &str) -> Result<File> {
        let (parent, name) = self
            .parent(key, true)?
            .ok_or_else(|| anyhow!("gate parent unavailable"))?;
        let fd = fs::openat(
            &parent,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| anyhow!("native gate unavailable"))?;
        let st = fs::fstat(&fd).map_err(|_| anyhow!("native gate metadata unavailable"))?;
        validate_file(&st, self.uid, true)?;
        fs::fsync(&parent).map_err(|_| anyhow!("native gate directory synchronization failed"))?;
        Ok(File::from(fd))
    }

    pub fn load(&self, key: &str, private: bool) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.load_pinned(key, private)
            .and_then(|value| value.map(PinnedRead::into_bytes).transpose())
    }

    pub fn load_pinned(&self, key: &str, private: bool) -> Result<Option<PinnedRead>> {
        self.load_pinned_with_credit(key,private,None)
    }
    pub fn load_owned(&self,key:&str,private:bool,lifetime:crate::cert_transient::Lifetime)->Result<Option<crate::cert_transient::Bytes>> {
        self.load_pinned_with_credit(key,private,Some(lifetime)).map(|value|value.map(PinnedRead::into_owned_bytes))
    }
    pub fn load_pinned_owned(&self,key:&str,private:bool,lifetime:crate::cert_transient::Lifetime)->Result<Option<PinnedRead>> {
        self.load_pinned_with_credit(key,private,Some(lifetime))
    }
    fn load_pinned_with_credit(&self, key:&str,private:bool,lifetime:Option<crate::cert_transient::Lifetime>)->Result<Option<PinnedRead>> {
        self.load_pinned_bounded(key,private,lifetime,MAX_FILE)
    }
    fn load_pinned_bounded(&self,key:&str,private:bool,lifetime:Option<crate::cert_transient::Lifetime>,maximum:usize)->Result<Option<PinnedRead>> {
        let Some((parent, name)) = self.parent(key, false)? else {
            return Ok(None);
        };
        let fd = match fs::openat(
            &parent,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => bail!("storage file unavailable or symlink"),
        };
        let st = fs::fstat(&fd).map_err(|_| anyhow!("file metadata unavailable"))?;
        validate_file(&st, self.uid, private)?;
        ensure!(
            st.st_size >= 0 && st.st_size as u64 <= maximum.min(MAX_FILE) as u64,
            "storage file size limit exceeded"
        );
        let file = File::from(fd);
        // Never grow a private-key buffer: realloc would leave its previous
        // allocation outside Zeroizing ownership. Read exactly the bounded size.
        // Admit the opened FD's actual bounded size before allocating. The
        // payload itself retains credit through an unconsumed worker result.
        let mut bytes=crate::cert_transient::Bytes::allocate(st.st_size as usize,lifetime)?;
        let mut reader = &file;
        reader.read_exact(bytes.as_mut_slice()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                anyhow!("storage file changed during read")
            } else {
                anyhow!("storage read failed")
            }
        })?;
        let mut probe = Zeroizing::new([0u8; 1]);
        loop {
            match reader.read(probe.as_mut()) {
                Ok(0) => break,
                Ok(_) => bail!("storage file changed during read"),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => bail!("storage read failed"),
            }
        }
        let after = fs::fstat(&file).map_err(|_| anyhow!("file metadata unavailable"))?;
        ensure!(
            bytes.len() as u64 == st.st_size as u64
                && st.st_ino == after.st_ino
                && st.st_dev == after.st_dev
                && st.st_size == after.st_size
                && st.st_mtime == after.st_mtime
                && st.st_mtime_nsec == after.st_mtime_nsec,
            "storage file changed during read"
        );
        // Single-key callers may legitimately read the old inode while a new
        // value is renamed into place. Preserve that content-snapshot behavior;
        // grouped callers additionally verify ctime, permissions and path identity.
        Ok(Some(PinnedRead {
            file,
            bytes,
            signature: Signature::from_stat(&st),
            uid: self.uid,
            private,
        }))
    }

    pub fn store(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.store_atomic(key, bytes, false).map(|_| ())
    }

    /// Publish a complete, synchronized value without replacing an existing
    /// inode. A losing publisher removes only its own temporary file.
    pub fn store_new(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.store_atomic(key, bytes, true)
    }

    fn store_atomic(&self, key: &str, bytes: &[u8], no_replace: bool) -> Result<bool> {
        self.store_atomic_receipted(key,bytes,no_replace,None)
    }
    fn store_atomic_receipted(&self,key:&str,bytes:&[u8],no_replace:bool,mut receipt:Option<&mut StoreReceipt>)->Result<bool>{
        ensure!(bytes.len() <= MAX_FILE, "storage value size limit exceeded");
        let (parent, name) = self
            .parent(key, true)?
            .ok_or_else(|| anyhow!("storage parent unavailable"))?;
        match fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => validate_file(&st, self.uid, true)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(_) => bail!("storage target metadata unavailable"),
        }
        let temp = cstr(&format!(
            ".rust-cm-{}-{}.tmp",
            super::hash(name.to_bytes()),
            random_id()?
        ))?;
        // Allocate opt-in receipt text BEFORE creating anything on disk.
        let mut receipt_temp=receipt.as_ref().map(|_|temp.clone());
        let fd = fs::openat(
            &parent,
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| anyhow!("temporary storage file creation failed"))?;
        // The fd is ours before any write/sync can fail. Only this opt-in check
        // retains the exact temporary component; normal writers do not clone it.
        let mut opened=Some(File::from(fd));
        if let Some(receipt)=receipt.as_deref_mut(){
            // Retain both name and actual fd with no allocation after create.
            receipt.temporary=receipt_temp.take();
            // Retain the actual inode, not only a guess based on its name.
            // Keeping this fd open also prevents unlink/reuse of the inode id.
            receipt.file=opened.take();
            let st=fs::fstat(receipt.file.as_ref().expect("owned check fd"))
                .map_err(|_|anyhow!("storage check inode metadata unavailable"))?;
            receipt.identity=Some(CheckIdentity::from_stat(&st));
        }
        let mut operation = || -> Result<bool> {
            {
                let file=receipt.as_deref().and_then(|r|r.file.as_ref()).or(opened.as_ref())
                    .expect("owned atomic storage fd");
                let mut writer=file;
                writer.write_all(bytes).map_err(|_|anyhow!("storage write failed"))?;
                file.sync_all().map_err(|_|anyhow!("storage file synchronization failed"))?;
            }
            if no_replace {
                match fs::renameat_with(&parent, &temp, &parent, &name, fs::RenameFlags::NOREPLACE) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::EXIST) => return Ok(false),
                    Err(_) => bail!("storage no-replace publication failed"),
                }
            } else {
                fs::renameat(&parent, &temp, &parent, &name)
                    .map_err(|_| anyhow!("storage atomic replacement failed"))?;
            }
            // rename has physically succeeded. Record ownership BEFORE fsync:
            // Err from the subsequent sync must not hide a published test key.
            if let Some(receipt)=receipt.as_deref_mut(){receipt.published=true;receipt.temporary=None;}
            fs::fsync(&parent).map_err(|_| anyhow!("storage directory synchronization failed"))?;
            Ok(true)
        };
        match operation() {
            Ok(true) => Ok(true),
            // The dedicated checker must verify the retained inode before
            // unlinking. Do not run the ordinary name-only cleanup first.
            Ok(false) if receipt.is_some()=>Ok(false),
            Err(error) if receipt.is_some()=>Err(error),
            Ok(false) => {
                match fs::unlinkat(&parent, &temp, AtFlags::empty()) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                    Err(_) => bail!("storage temporary cleanup failed"),
                }
                if let Some(receipt)=receipt.as_deref_mut(){receipt.temporary=None;}
                fs::fsync(&parent).map_err(|_| anyhow!("storage directory synchronization failed"))?;
                Ok(false)
            }
            Err(error) => {
                // Preserve the operation's first failure even if cleanup fails.
                // Successful publication already removed temp; NOENT is benign.
                if matches!(fs::unlinkat(&parent,&temp,AtFlags::empty()),Ok(())|Err(rustix::io::Errno::NOENT)){
                    if let Some(receipt)=receipt.as_deref_mut(){receipt.temporary=None;}
                }
                Err(error)
            }
        }
    }

    pub fn delete(&self, key: &str) -> Result<()> {
        let Some((parent, name)) = self.parent(key, false)? else {
            return Ok(());
        };
        match fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => validate_file(&st, self.uid, false)?,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => bail!("storage target metadata unavailable"),
        }
        match fs::unlinkat(&parent, &name, AtFlags::empty()) {
            Ok(()) => {}
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => bail!("storage deletion failed"),
        }
        fs::fsync(&parent).map_err(|_| anyhow!("storage directory synchronization failed"))?;
        Ok(())
    }

    /// Atomically preserve a private journal without replacing prior evidence.
    /// Both names remain relative to already verified directory descriptors.
    pub fn rename_new(&self, from: &str, to: &str) -> Result<()> {
        let (parent, name) = self
            .parent(from, false)?
            .ok_or_else(|| anyhow!("journal source missing"))?;
        let (destination, new_name) = self
            .parent(to, false)?
            .ok_or_else(|| anyhow!("journal destination unavailable"))?;
        let st = fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| anyhow!("journal source metadata unavailable"))?;
        validate_file(&st, self.uid, true)?;
        fs::renameat_with(
            &parent,
            &name,
            &destination,
            &new_name,
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| anyhow!("journal no-replace move failed"))?;
        fs::fsync(&parent)
            .map_err(|_| anyhow!("journal source directory synchronization failed"))?;
        fs::fsync(&destination)
            .map_err(|_| anyhow!("journal destination directory synchronization failed"))?;
        Ok(())
    }

    pub fn remove_empty_directory(&self, key: &str) -> Result<()> {
        let Some((parent, name)) = self.parent(key, false)? else {
            return Ok(());
        };
        let st = match fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => bail!("cleanup directory unavailable"),
        };
        ensure!(
            FileType::from_raw_mode(st.st_mode) == FileType::Directory
                && st.st_uid == self.uid
                && st.st_mode & 0o022 == 0,
            "unsafe cleanup directory"
        );
        match fs::unlinkat(&parent, &name, AtFlags::REMOVEDIR) {
            Ok(()) => {}
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => bail!("transaction cleanup directory not empty"),
        }
        fs::fsync(&parent).map_err(|_| anyhow!("cleanup directory synchronization failed"))?;
        Ok(())
    }

    /// A process killed between temp creation and rename cannot run cleanup.
    /// The destination hash tags each temp, so recovery removes only files for
    /// this exact destination, never another domain's concurrent atomic write.
    pub fn clean_temps_for_key(&self, key: &str) -> Result<()> {
        let Some((parent, name)) = self.parent(key, false)? else {
            return Ok(());
        };
        let prefix = format!(".rust-cm-{}-", super::hash(name.to_bytes()));
        let dir = Dir::read_from(&parent)
            .map_err(|_| anyhow!("atomic temporary file enumeration failed"))?;
        let mut count = 0;
        let path = key.rsplit_once('/').map(|(p, _)| p);
        for entry in dir {
            let entry = entry.map_err(|_| anyhow!("atomic temporary file enumeration failed"))?;
            count += 1;
            ensure!(
                count <= MAX_LIST,
                "atomic temporary enumeration limit exceeded"
            );
            let Some(candidate) = entry.file_name().to_str().ok() else {
                continue;
            };
            let Some(token) = candidate
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_suffix(".tmp"))
            else {
                continue;
            };
            if !super::is_hex(token, 32) {
                continue;
            }
            let key = path
                .map(|p| format!("{p}/{candidate}"))
                .unwrap_or_else(|| candidate.to_owned());
            // Validate private ownership and no-follow framing before unlink.
            self.load(&key, true)?;
            self.delete(&key)?;
        }
        Ok(())
    }

    pub fn delete_tree(&self, key: &str) -> Result<()> {
        match self.stat(key)? {
            None => Ok(()),
            Some((true, _, _)) => self.delete(key),
            Some((false, _, _)) => {
                // Preflight a bounded, no-follow tree before deleting anything.
                // Concurrent changes yield an explicit error, never traversal
                // outside the root or an unbounded retry loop.
                let mut entries = self.list(key, true)?;
                entries
                    .sort_by_key(|s| std::cmp::Reverse(s.bytes().filter(|b| *b == b'/').count()));
                for entry in entries {
                    match self.stat(&entry)? {
                        None => {}
                        Some((true, _, _)) => self.delete(&entry)?,
                        Some((false, _, _)) => self.remove_empty_directory(&entry)?,
                    }
                }
                self.remove_empty_directory(key)
            }
        }
    }

    pub fn list(&self, prefix: &str, recursive: bool) -> Result<Vec<String>> {
        let mut fd = fs::openat(
            &*self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| anyhow!("storage root unavailable"))?;
        if !prefix.is_empty() {
            for part in components(prefix)? {
                match directory(&fd, part, self.uid, false)? {
                    Some(next) => fd = next,
                    None => return Ok(Vec::new()),
                }
            }
        }
        let mut result = Vec::new();
        self.walk(&fd, prefix, recursive, &mut result, 0)?;
        result.sort();
        Ok(result)
    }

    fn walk(
        &self,
        fd: &OwnedFd,
        prefix: &str,
        recursive: bool,
        result: &mut Vec<String>,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth <= 64, "storage enumeration depth limit exceeded");
        let dir = Dir::read_from(fd).map_err(|_| anyhow!("storage enumeration failed"))?;
        for entry in dir {
            let entry = entry.map_err(|_| anyhow!("storage enumeration failed"))?;
            let raw = entry.file_name();
            if raw.to_bytes() == b"." || raw.to_bytes() == b".." {
                continue;
            }
            let name = raw.to_str().map_err(|_| anyhow!("non-UTF-8 storage key"))?;
            let st = match fs::statat(fd, raw, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => st,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(_) => bail!("storage entry metadata unavailable"),
            };
            ensure!(
                result.len() < MAX_LIST,
                "storage enumeration entry limit exceeded"
            );
            let key = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            match FileType::from_raw_mode(st.st_mode) {
                FileType::Directory => {
                    let child = directory(fd, name, self.uid, false)?
                        .ok_or_else(|| anyhow!("storage directory disappeared"))?;
                    result.push(key.clone());
                    if recursive {
                        self.walk(&child, &key, true, result, depth + 1)?;
                    }
                }
                FileType::RegularFile => {
                    validate_file(&st, self.uid, false)?;
                    result.push(key);
                }
                _ => bail!("unsupported storage entry type"),
            }
        }
        Ok(())
    }
}

pub(super) fn validate_file(st: &fs::Stat, uid: u32, private: bool) -> Result<()> {
    ensure!(
        FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
            && st.st_uid == uid
            && st.st_nlink == 1
            && st.st_mode & 0o022 == 0
            && (!private || st.st_mode & 0o077 == 0),
        "unsafe storage file"
    );
    Ok(())
}

fn ensure_local(fd: &OwnedFd) -> Result<()> {
    let info = fs::fstatfs(fd).map_err(|_| anyhow!("filesystem type unavailable"))?;
    #[cfg(target_os = "linux")]
    {
        // NFS, CIFS/SMB, 9p, Ceph, AFS, Lustre and FUSE may expose remote or
        // non-local locking semantics. This implementation requires local FS.
        let kind = info.f_type as u64;
        ensure!(
            !matches!(
                kind,
                0x6969
                    | 0xff534d42
                    | 0xfe534d42
                    | 0x01021997
                    | 0x00c36400
                    | 0x5346414f
                    | 0x0bd00bd0
                    | 0x65735546
            ),
            "remote filesystem is unsupported for native certificate fencing"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let name: Vec<u8> = info
            .f_fstypename
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as u8)
            .collect();
        ensure!(
            info.f_flags & 0x1000 != 0
                && !matches!(name.as_slice(), b"nfs" | b"smbfs" | b"afpfs" | b"webdav"),
            "remote filesystem is unsupported for native certificate fencing"
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = info;
        bail!("filesystem fencing unsupported on this platform");
    }
    Ok(())
}


pub(super) const STORAGE_CHECK_BYTES:usize=10*1024;
/// Both 10KiB buffers plus bounded single-component paths/receipt and worker
/// bookkeeping. The dedicated caller acquires this before any producer.
pub(super) const STORAGE_CHECK_CREDIT:usize=32*1024;
#[derive(Clone,Copy,PartialEq,Eq)]
struct CheckIdentity{dev:u64,ino:u64}
impl CheckIdentity{fn from_stat(st:&fs::Stat)->Self{Self{dev:device_id(st),ino:st.st_ino}}}
#[derive(Default)]
struct StoreReceipt{
    temporary:Option<CString>,published:bool,identity:Option<CheckIdentity>,
    // Last actual descriptor prevents inode-number reuse until cleanup ends.
    file:Option<File>,
}
#[derive(Debug)]
struct CheckFailure{primary:anyhow::Error,cleanup:anyhow::Error}
impl std::fmt::Display for CheckFailure{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        write!(f,"{}; storage check cleanup also failed: {}",self.primary,self.cleanup)
    }
}
impl std::error::Error for CheckFailure{
    fn source(&self)->Option<&(dyn std::error::Error+'static)>{Some(self.primary.as_ref())}
}
impl Root{
    /// Only the prepaid FsStore worker calls this; no buffers or relative names
    /// escape its small Result. A receipt owns only our EXCL temp and the target
    /// after successful rename, never the target of a no-replace collision.
    pub(super) fn check_read_write(&self,cancel:&tokio_util::sync::CancellationToken)->Result<()>{
        let key=format!("rw_test_{}",random_id()?);
        let mut receipt=StoreReceipt::default();
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<()>{
            ensure!(!cancel.is_cancelled(),"storage check cancelled");
            let mut expected=crate::cert_transient::Bytes::allocate(STORAGE_CHECK_BYTES,None)?;
            getrandom::fill(expected.as_mut_slice()).map_err(|_|anyhow!("storage check entropy unavailable"))?;
            ensure!(self.store_atomic_receipted(&key,expected.as_slice(),true,Some(&mut receipt))?,"storage check key collision");
            ensure!(!cancel.is_cancelled(),"storage check cancelled");
            let loaded=self.load_pinned_bounded(&key,true,None,STORAGE_CHECK_BYTES)?
                .ok_or_else(||anyhow!("storage check value disappeared"))?;
            let identity=receipt.identity.ok_or_else(||anyhow!("storage check inode receipt missing"))?;
            ensure!(CheckIdentity{dev:loaded.signature.dev,ino:loaded.signature.ino}==identity,
                "storage check read inode changed");
            ensure!(loaded.bytes.as_slice()==expected.as_slice(),"storage check loaded different bytes");
            loaded.verify()?;
            ensure!(!cancel.is_cancelled(),"storage check cancelled");
            Ok(())
        }));
        let result=match result{Ok(result)=>result,Err(payload)=>{
            // Preserve bounded diagnostics, then destroy arbitrary payloads on
            // this real worker while its permit/credit are still retained.
            let evidence=CheckPanic::from_payload(&*payload);drop(payload);Err(evidence.into())
        }};
        // Cleanup is not gated by a cancelled token. Keep the first failure and
        // expose secondary cleanup failure without stringifying its cause.
        let cleanup=self.cleanup_check_receipt(&key,&mut receipt);
        match(result,cleanup){
            (Ok(()),Ok(()))=>Ok(()),
            (Err(error),Ok(()))=>Err(error),
            (Ok(()),Err(error))=>Err(error.context("storage check cleanup failed")),
            (Err(primary),Err(cleanup))=>Err(CheckFailure{primary,cleanup}.into()),
        }
    }
    fn cleanup_check_receipt(&self,key:&str,receipt:&mut StoreReceipt)->Result<()>{
        let mut failure=None;
        let identity=match receipt.identity{
            Some(identity)=>identity,
            None=>match receipt.file.as_ref(){
                Some(file)=>CheckIdentity::from_stat(&fs::fstat(file)
                    .map_err(|_|anyhow!("storage check cleanup inode unavailable"))?),
                None=>return Ok(()), // creation never succeeded; own no name
            }
        };
        if receipt.published{
            match self.delete_check_inode(key,identity){Ok(())=>receipt.published=false,Err(error)=>failure=Some(error)}
        }
        if let Some(temp)=receipt.temporary.as_ref(){
            let deletion=temp.to_str().map_err(|_|anyhow!("invalid storage check temporary component"))
                .and_then(|name|self.delete_check_inode(name,identity));
            match deletion{Ok(())=>receipt.temporary=None,Err(error)=>{
                failure=Some(match failure{None=>error,Some(primary)=>CheckFailure{primary,cleanup:error}.into()});
            }}
        }
        failure.map_or(Ok(()),Err)
    }
    fn delete_check_inode(&self,key:&str,expected:CheckIdentity)->Result<()>{
        let Some((parent,name))=self.parent(key,false)?else{return Ok(())};
        let st=match fs::statat(&parent,&name,AtFlags::SYMLINK_NOFOLLOW){
            Ok(st)=>st,Err(rustix::io::Errno::NOENT)=>return Ok(()),
            Err(_)=>bail!("storage check cleanup metadata unavailable"),
        };
        validate_file(&st,self.uid,true)?;
        ensure!(CheckIdentity::from_stat(&st)==expected,"storage check cleanup inode changed");
        match fs::unlinkat(&parent,&name,AtFlags::empty()){
            Ok(())|Err(rustix::io::Errno::NOENT)=>{},Err(_)=>bail!("storage check deletion failed"),
        }
        fs::fsync(&parent).map_err(|_|anyhow!("storage check deletion synchronization failed"))?;Ok(())
    }
}
#[derive(Debug)]
struct CheckPanic{kind:&'static str,bytes:Option<usize>,digest:Option<[u8;32]>}
impl CheckPanic{
    fn from_payload(payload:&(dyn std::any::Any+Send))->Self{
        use sha2::{Digest,Sha256};
        let text=payload.downcast_ref::<String>().map(String::as_bytes)
            .or_else(||payload.downcast_ref::<&'static str>().map(|s|s.as_bytes()));
        Self{kind:if text.is_some(){"text"}else{"opaque"},bytes:text.map(<[u8]>::len),
            digest:text.map(|text|Sha256::digest(text).into())}
    }
}
impl std::fmt::Display for CheckPanic{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        write!(f,"storage check worker panicked ({}, bytes={:?}, sha256={:02x?})",self.kind,self.bytes,self.digest)
    }
}
impl std::error::Error for CheckPanic{}
