use super::AdminError;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::{Component, Path},
};

pub(super) struct Parent {
    pub fd: OwnedFd,
    pub name: CString,
    pub uid: u32,
}
fn error() -> AdminError {
    AdminError::new(500, "admin_file_operation_failed")
}
pub(super) fn random() -> Result<String, AdminError> {
    let mut b = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut b)
        .map_err(|_| error())?;
    Ok(b.iter().map(|b| format!("{b:02x}")).collect())
}
pub(super) fn parent(path: &Path, create: bool) -> Result<Parent, AdminError> {
    resolve_parent(path, create)?.ok_or_else(error)
}
fn resolve_parent(path: &Path, create: bool) -> Result<Option<Parent>, AdminError> {
    if !path.is_absolute() {
        return Err(AdminError::new(400, "admin_path_must_be_absolute"));
    }
    let normalized=crate::storage_boundary::system_absolute(path).map_err(|_|error())?;
    let path=normalized.as_ref();
    let parts = path
        .components()
        .filter_map(|c| match c {
            Component::RootDir => None,
            c => Some(c),
        })
        .collect::<Vec<_>>();
    if parts.is_empty()||parts.len()>64||!parts.iter().all(|c|matches!(c,Component::Normal(s)if s.as_bytes().len()<=255&&!s.as_bytes().contains(&0))){return Err(AdminError::new(400,"invalid_admin_path"));}
    let uid = rustix::process::geteuid().as_raw();
    let mut fd = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| error())?;
    let mut sticky_parent = false;
    let mut mount_anchor_required=false;
    for (i, component) in parts[..parts.len() - 1].iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(error());
        };
        if create {
            match fs::mkdirat(&fd, *name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(error()),
            }
        }
        let next = match fs::openat(
            &fd,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(_) => return Err(AdminError::new(400, "unsafe_admin_parent_directory")),
        };
        let st = fs::fstat(&next).map_err(|_| error())?;
        let final_parent = i + 1 == parts.len() - 1;
        if st.st_uid != uid && st.st_uid != 0 {
            return Err(AdminError::new(400, "foreign_admin_parent_directory"));
        }
        if mount_anchor_required && !crate::storage_boundary::private_anchor(&st,uid) {
            return Err(AdminError::new(400,"mount_requires_private_admin_anchor"));
        }
        let writable = st.st_mode & 0o022 != 0;
        let shared_mount=if writable && !final_parent && !sticky_parent && !mount_anchor_required {
            let parent_st=fs::fstat(&fd).map_err(|_|error())?;
            crate::storage_boundary::shared_mount_root(&parent_st,&st)
        }else{false};
        if writable && !(st.st_mode & 0o1000 != 0 && !final_parent && !sticky_parent || shared_mount) {
            return Err(AdminError::new(400, "writable_admin_parent_directory"));
        }
        if sticky_parent && writable {
            return Err(AdminError::new(400, "unsafe_directory_under_sticky_parent"));
        }
        sticky_parent = writable && !shared_mount;
        mount_anchor_required=shared_mount;
        fd = next;
    }
    let st = fs::fstat(&fd).map_err(|_| error())?;
    if st.st_uid != uid || st.st_mode & 0o022 != 0 {
        return Err(AdminError::new(
            400,
            "admin_parent_must_be_owned_and_private",
        ));
    }
    let Component::Normal(name) = parts[parts.len() - 1] else {
        return Err(error());
    };
    Ok(Some(Parent {
        fd,
        name: CString::new(name.as_bytes()).map_err(|_| error())?,
        uid,
    }))
}
pub(super) fn read(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, AdminError> {
    let Some(cap) = resolve_parent(path, false)? else {
        return Ok(None);
    };
    let fd = match fs::openat(
        &cap.fd,
        &cap.name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(error()),
    };
    let st = fs::fstat(&fd).map_err(|_| error())?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || st.st_uid != cap.uid
        || st.st_nlink != 1
        || st.st_mode & 0o077 != 0
        || st.st_size < 0
        || st.st_size as u64 > limit as u64
    {
        return Err(AdminError::new(400, "unsafe_or_oversized_admin_file"));
    }
    let file = File::from(fd);
    let mut out = Vec::new();
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| error())?;
    let after = fs::fstat(&file).map_err(|_| error())?;
    if out.len() > limit
        || st.st_size != after.st_size
        || st.st_mtime != after.st_mtime
        || st.st_mtime_nsec != after.st_mtime_nsec
        || out.len() as u64 != st.st_size as u64
    {
        return Err(error());
    }
    Ok(Some(out))
}
pub(super) fn save(path: &Path, value: &serde_json::Value) -> Result<(), AdminError> {
    let cap = parent(path, true)?;
    match fs::statat(&cap.fd, &cap.name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                || st.st_uid != cap.uid
                || st.st_nlink != 1
                || st.st_mode & 0o077 != 0
            {
                return Err(error());
            }
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(error()),
    }
    let name = CString::new(format!(".caddy-admin-{}.tmp", random()?)).map_err(|_| error())?;
    let fd = fs::openat(
        &cap.fd,
        &name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| error())?;
    let outcome = (|| {
        let mut file = File::from(fd);
        let bytes = crate::admin_json::encoded(value).map_err(|_| error())?;
        file.write_all(&bytes).map_err(|_| error())?;
        file.sync_all().map_err(|_| error())?;
        fs::renameat(&cap.fd, &name, &cap.fd, &cap.name).map_err(|_| error())?;
        fs::fsync(&cap.fd).map_err(|_| error())?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::unlinkat(&cap.fd, &name, AtFlags::empty());
    }
    outcome
}
pub(super) fn resume(
    path: &Path,
    fallback: &serde_json::Value,
) -> Result<serde_json::Value, AdminError> {
    match read(path, 100 * 1024 * 1024)? {
        None => Ok(fallback.clone()),
        Some(bytes) => crate::admin_json::decoded(&bytes)
            .map_err(|_| AdminError::new(400, "corrupt_autosave_configuration")),
    }
}
pub(super) fn basename_hash(name: &OsStr) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(name.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
