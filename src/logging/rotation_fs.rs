//! Own the configured rolling log directory and serialize native writers for a
//! pathname. All archive mutations are relative to that retained directory FD.
use super::{
    file_open,
    writer_spec::{FileSpec, unix_mode},
};
use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Gid, Mode, OFlags, RenameFlags, Stat, Uid},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

const MB: i64 = 1 << 20;
pub(super) const MAX_NAME_ATTEMPTS: u32 = 10_000;
const SAFE_FLAGS: OFlags = OFlags::CLOEXEC
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

pub(super) struct Paths {
    pub directory: File,
    _gate: File,
    pub active_name: String,
    pub prefix: String,
    pub extension: String,
    pub temporary_prefix: String,
    pub owner: u32,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    active: Option<(u64, u64)>,
    pending: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    dev: u64,
    ino: u64,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    gid: u32,
    pub links: u64,
    pub modified: i128,
    changed: i128,
}
impl Identity {
    fn from_stat(stat: Stat) -> io::Result<Self> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self {
            // macOS dev_t is signed; only equality matters for this identifier.
            #[allow(clippy::unnecessary_cast)]
            dev: stat.st_dev as u64,
            ino: stat.st_ino,
            size: u64::try_from(stat.st_size).map_err(|_| io::ErrorKind::InvalidData)?,
            #[allow(clippy::unnecessary_cast)]
            mode: (stat.st_mode & 0o777) as u32,
            uid: stat.st_uid,
            gid: stat.st_gid,
            #[allow(clippy::unnecessary_cast)]
            links: stat.st_nlink as u64,
            modified: stat.st_mtime as i128 * 1_000_000_000 + stat.st_mtime_nsec as i128,
            changed: stat.st_ctime as i128 * 1_000_000_000 + stat.st_ctime_nsec as i128,
        })
    }
    pub(super) fn for_file(file: &File) -> io::Result<Self> {
        Self::from_stat(fs::fstat(file)?)
    }
    fn key(self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}
impl Paths {
    pub(super) fn open(spec: &FileSpec) -> io::Result<Arc<Self>> {
        if spec.filename.ends_with('/') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        file_open::prepare_directory(spec).map_err(io::Error::other)?;
        let path = Path::new(&spec.filename);
        let active_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(io::ErrorKind::InvalidInput)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory: File = fs::open(
            parent,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
            Mode::empty(),
        )?
        .into();
        let dir_stat = fs::fstat(&directory)?;
        let owner = geteuid().as_raw();
        if (dir_stat.st_uid != owner && dir_stat.st_uid != 0)
            || (dir_stat.st_mode & 0o022 != 0 && dir_stat.st_mode & 0o1000 == 0)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let (prefix, extension) = active_name
            .rfind('.')
            .map_or((active_name, ""), |index| active_name.split_at(index));
        let hash = Sha256::digest(active_name.as_bytes());
        let base = format!(".caddy-log-{}", hex(&hash[..16]));
        let gate_name = format!("{base}.gate");
        let gate: File = fs::openat(
            &directory,
            gate_name.as_str(),
            SAFE_FLAGS | OFlags::CREATE | OFlags::RDWR,
            Mode::RUSR | Mode::WUSR,
        )?
        .into();
        let gate_id = Identity::for_file(&gate)?;
        if gate_id.uid != owner || gate_id.mode != 0o600 || gate_id.links != 1 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        fs::flock(&gate, FlockOperation::NonBlockingLockExclusive)?;
        // Do not unlink the persistent gate: a late opener might still hold
        // its old inode. Old Go instances do not honor this native gate.
        let paths = Arc::new(Self {
            directory,
            _gate: gate,
            active_name: active_name.into(),
            prefix: format!("{prefix}-"),
            extension: extension.into(),
            temporary_prefix: format!("{base}.tmp-"),
            owner,
            state: Mutex::new(State::default()),
        });
        let mode = if spec.mode == 0 {
            0o600
        } else {
            unix_mode(spec.mode) & 0o777
        };
        let preflight: File = fs::openat(
            &paths.directory,
            active_name,
            SAFE_FLAGS | OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE,
            mode_bits(mode),
        )?
        .into();
        let identity = Identity::for_file(&preflight)?;
        if identity.links != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if spec.mode != 0 && identity.mode != mode {
            fs::fchmod(&preflight, mode_bits(mode))?;
        }
        paths.set_active(Some(identity));
        Ok(paths)
    }
    pub(super) fn stat(&self, name: &str) -> io::Result<Identity> {
        Identity::from_stat(fs::statat(
            &self.directory,
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )?)
    }
    pub(super) fn occupied(&self, name: &str) -> io::Result<bool> {
        match fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    pub(super) fn move_exclusive(&self, from: &str, to: &str) -> io::Result<()> {
        fs::renameat_with(
            &self.directory,
            from,
            &self.directory,
            to,
            RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }
    pub(super) fn append(&self) -> io::Result<(File, Identity)> {
        let file: File = fs::openat(
            &self.directory,
            self.active_name.as_str(),
            SAFE_FLAGS | OFlags::WRONLY | OFlags::APPEND,
            Mode::empty(),
        )?
        .into();
        let identity = Identity::for_file(&file)?;
        if identity.links != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.set_active(Some(identity));
        Ok((file, identity))
    }
    pub(super) fn create(&self, name: &str) -> io::Result<(File, Identity)> {
        let file: File = fs::openat(
            &self.directory,
            name,
            SAFE_FLAGS | OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )?
        .into();
        let identity = Identity::for_file(&file)?;
        Ok((file, identity))
    }
    pub(super) fn read(&self, name: &str) -> io::Result<(File, Identity)> {
        let file: File = fs::openat(
            &self.directory,
            name,
            SAFE_FLAGS | OFlags::RDONLY,
            Mode::empty(),
        )?
        .into();
        let identity = Identity::for_file(&file)?;
        if identity.links != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok((file, identity))
    }
    pub(super) fn temp(&self) -> io::Result<(String, File, Identity)> {
        let mut random = File::open("/dev/urandom")?;
        for _ in 0..8 {
            let mut bytes = [0; 16];
            random.read_exact(&mut bytes)?;
            let name = format!("{}{}", self.temporary_prefix, hex(&bytes));
            match self.create(&name) {
                Ok((file, identity)) => return Ok((name, file, identity)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::ErrorKind::AlreadyExists.into())
    }
    pub(super) fn is_temp_name(&self, name: &str) -> bool {
        name.strip_prefix(&self.temporary_prefix)
            .is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    }
    pub(super) fn remove_created(&self, name: &str, expected: Identity) -> io::Result<()> {
        let current = self.stat(name)?;
        if current.key() != expected.key() || current.links != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        fs::unlinkat(&self.directory, name, AtFlags::empty())?;
        Ok(())
    }
    pub(super) fn remove_archive(&self, name: &str, expected: Identity) -> io::Result<()> {
        let current = self.stat(name)?;
        if current != expected || !self.archivable(name, current) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        fs::unlinkat(&self.directory, name, AtFlags::empty())?;
        Ok(())
    }
    pub(super) fn archivable(&self, name: &str, identity: Identity) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        identity.uid == self.owner
            && identity.links == 1
            && state.active != Some(identity.key())
            && state.pending.as_deref() != Some(name)
    }
    pub(super) fn set_active(&self, identity: Option<Identity>) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active = identity.map(Identity::key);
    }
    pub(super) fn transition(&self, name: String) -> Transition<'_> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending = Some(name);
        Transition(Some(self))
    }
    pub(super) fn clear_transition(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending = None;
    }
    pub(super) fn matches_inode(&self, name: &str, expected: Identity) -> io::Result<bool> {
        self.stat(name).map(|found| found.key() == expected.key())
    }
    pub(super) fn mode_for(spec: &FileSpec, old: Option<Identity>) -> u32 {
        if spec.mode == 0 {
            old.map_or(0o640, |id| id.mode)
        } else {
            unix_mode(spec.mode) & 0o777
        }
    }
    pub(super) fn max_bytes(spec: &FileSpec) -> i64 {
        spec.size_mb.wrapping_mul(MB)
    }
}
pub(super) struct Transition<'a>(Option<&'a Paths>);
impl Transition<'_> {
    pub(super) fn defer(mut self) {
        self.0.take();
    }
}
impl Drop for Transition<'_> {
    fn drop(&mut self) {
        if let Some(paths) = self.0 {
            paths.clear_transition();
        }
    }
}
pub(super) fn attributes(file: &File, previous: Option<Identity>, mode: u32) -> io::Result<()> {
    let current = Identity::for_file(file)?;
    if let Some(previous) = previous
        && (previous.uid != current.uid || previous.gid != current.gid)
        && fs::fchown(
            file,
            Some(Uid::from_raw(previous.uid)),
            Some(Gid::from_raw(previous.gid)),
        )
        .is_err()
    {
        warning(b"timberjack: ownership could not be copied; kept private file permissions\n");
        return Ok(());
    }
    fs::fchmod(file, mode_bits(mode))?;
    Ok(())
}
pub(super) fn warning(message: &[u8]) {
    let _ = io::stderr().lock().write_all(message);
}
fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        result.push(char::from(ALPHABET[usize::from(byte & 15)]));
    }
    result
}

#[allow(clippy::unnecessary_cast)]
fn mode_bits(mode: u32) -> Mode {
    Mode::from_raw_mode(mode as _)
}
