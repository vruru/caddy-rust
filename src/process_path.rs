//! Resolve startup-selected application roots, never an API-supplied file path.
//!
//! A protected, current-user-owned directory alias is process configuration.
//! Capture its target once; the existing store/admin descriptor walks still
//! validate the resulting physical path and never follow its child symlinks.
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use std::{
    collections::VecDeque,
    ffi::OsString,
    io,
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::{Component, Path, PathBuf},
};

const DEPTH: usize = 64;
const PATH_BYTES: usize = 16 << 10;
const LINKS: usize = 40;
struct Frame {
    fd: OwnedFd,
    stat: Stat,
    private_next: bool,
    name: Option<OsString>,
}
enum Part {
    Name(OsString),
    Parent,
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unsafe process application root",
    )
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid process application root",
    )
}
fn errno(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}
fn parts(path: &Path) -> io::Result<VecDeque<Part>> {
    if path.as_os_str().as_bytes().len() > PATH_BYTES {
        return Err(invalid());
    }
    path.components()
        .filter_map(|p| match p {
            Component::RootDir | Component::CurDir => None,
            Component::Normal(name) => Some(
                if name.as_bytes().len() <= 255 && !name.as_bytes().contains(&0) {
                    Ok(Part::Name(name.to_owned()))
                } else {
                    Err(invalid())
                },
            ),
            Component::ParentDir => Some(Ok(Part::Parent)),
            _ => Some(Err(invalid())),
        })
        .collect()
}
fn unchanged(frames: &[Frame]) -> io::Result<()> {
    for pair in frames.windows(2) {
        let seen = fs::statat(
            &pair[0].fd,
            pair[1].name.as_ref().expect("directory component"),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(errno)?;
        if !same(&seen, &pair[1].stat) {
            return Err(denied());
        }
    }
    Ok(())
}
/// This is only for trusted process-selected XDG/HOME/cwd application roots.
/// It does not authorize a request path, create a directory, weaken NOFOLLOW,
/// or replace the actual store's ownership, inode and private-anchor checks.
pub fn resolve_application_root(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let normalized = crate::storage_boundary::system_absolute(path)?;
    let mut pending = parts(&normalized)?;
    let uid = rustix::process::geteuid().as_raw();
    let fd = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    let stat = fs::fstat(&fd).map_err(errno)?;
    let mut frames = vec![Frame {
        fd,
        stat,
        private_next: false,
        name: None,
    }];
    let mut output = PathBuf::from("/");
    let mut links = 0;
    let mut steps = 0;
    while let Some(part) = pending.pop_front() {
        steps += 1;
        if steps > 8192 {
            return Err(invalid());
        }
        let name = match part {
            Part::Parent => {
                if frames.len() > 1 {
                    frames.pop();
                    output.pop();
                }
                continue;
            }
            Part::Name(name) => name,
        };
        if frames.len() > DEPTH {
            return Err(invalid());
        }
        let parent = frames.last().expect("root frame");
        let seen = match fs::statat(&parent.fd, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => {
                unchanged(&frames)?;
                output.push(name);
                for part in pending {
                    let Part::Name(name) = part else {
                        return Err(invalid());
                    };
                    output.push(name);
                }
                if output.components().count() > DEPTH + 1
                    || output.as_os_str().as_bytes().len() > PATH_BYTES
                {
                    return Err(invalid());
                }
                return Ok(output);
            }
            Err(e) => return Err(errno(e)),
        };
        if FileType::from_raw_mode(seen.st_mode) == FileType::Symlink {
            links += 1;
            let current_parent = fs::fstat(&parent.fd).map_err(errno)?;
            // Keep the existing protected macOS /var, /tmp and /etc rule
            // when an owned alias target reaches one of those first entries.
            let link_path = output.join(&name);
            let system_target = crate::storage_boundary::system_absolute(&link_path)?;
            let system_alias = system_target.as_ref() != link_path;
            if links > LINKS
                || seen.st_uid != uid && !system_alias
                || !same(&parent.stat, &current_parent)
                || current_parent.st_mode & 0o022 != 0
                || parent.private_next
            {
                return Err(denied());
            }
            let target = fs::readlinkat(&parent.fd, &name, Vec::new()).map_err(errno)?;
            let after = fs::statat(&parent.fd, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(errno)?;
            let confirm = fs::readlinkat(&parent.fd, &name, Vec::new()).map_err(errno)?;
            if !same(&seen, &after)
                || seen.st_mtime != after.st_mtime
                || seen.st_mtime_nsec != after.st_mtime_nsec
                || seen.st_size != after.st_size
                || target != confirm
            {
                return Err(denied());
            }
            unchanged(&frames)?;
            let read_target = Path::new(std::ffi::OsStr::from_bytes(target.as_bytes()));
            let target = if system_alias {
                system_target.as_ref()
            } else {
                read_target
            };
            let mut target_parts = parts(target)?;
            if target.is_absolute() {
                frames.truncate(1);
                output = PathBuf::from("/");
            }
            target_parts.append(&mut pending);
            if target_parts.len() > 128 {
                return Err(invalid());
            }
            pending = target_parts;
            continue;
        }
        if FileType::from_raw_mode(seen.st_mode) != FileType::Directory {
            return Err(denied());
        }
        let fd = fs::openat(
            &parent.fd,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        let stat = fs::fstat(&fd).map_err(errno)?;
        if !same(&seen, &stat) || stat.st_uid != uid && stat.st_uid != 0 {
            return Err(denied());
        }
        if parent.private_next && !crate::storage_boundary::private_anchor(&stat, uid) {
            return Err(denied());
        }
        let writable = stat.st_mode & 0o022 != 0;
        let shared = writable
            && !parent.private_next
            && crate::storage_boundary::shared_mount_root(&parent.stat, &stat);
        let sticky =
            writable && !parent.private_next && crate::storage_boundary::sticky_parent(&stat, uid);
        if writable && !(shared || sticky) {
            return Err(denied());
        }
        output.push(&name);
        frames.push(Frame {
            fd,
            stat,
            private_next: writable,
            name: Some(name),
        });
    }
    unchanged(&frames)?;
    Ok(output)
}
