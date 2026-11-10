//! Darwin exposes SO_ACCEPTCONN in proc_pidfdinfo, not getsockopt.
//! Prefix layouts follow public SDK sys/proc_info.h (proc_fileinfo,
//! vinfo_stat, socket_info); the kernel returns the complete extensible record.
use super::{AdminError, invalid};
use std::os::fd::{AsRawFd, OwnedFd};
#[repr(C)]
#[derive(Clone, Copy)]
struct FileInfo {
    flags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guard: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Stat {
    dev: u32,
    mode: u16,
    nlink: u16,
    ino: u64,
    uid: u32,
    gid: u32,
    atime: i64,
    atimensec: i64,
    mtime: i64,
    mtimensec: i64,
    ctime: i64,
    ctimensec: i64,
    birthtime: i64,
    birthtimensec: i64,
    size: i64,
    blocks: i64,
    blksize: i32,
    flags: u32,
    generation: u32,
    rdev: u32,
    spare: [i64; 2],
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Prefix {
    file: FileInfo,
    stat: Stat,
    socket: u64,
    pcb: u64,
    kind: i32,
    protocol: i32,
    family: i32,
    options: i16,
}
pub(super) fn info(fd: &OwnedFd) -> Result<(u64, bool, i32), AdminError> {
    let mut bytes = [0u64; 512];
    let len = unsafe {
        libc::proc_pidfdinfo(
            libc::getpid(),
            fd.as_raw_fd(),
            3,
            bytes.as_mut_ptr().cast(),
            std::mem::size_of_val(&bytes) as i32,
        )
    };
    if len < std::mem::size_of::<Prefix>() as i32 {
        return Err(invalid("admin_inherited_socket_info_unavailable"));
    }
    let prefix = unsafe { std::ptr::read(bytes.as_ptr().cast::<Prefix>()) };
    if prefix.socket == 0 {
        return Err(invalid("admin_inherited_socket_identity_unavailable"));
    }
    Ok((
        prefix.socket,
        prefix.options & libc::SO_ACCEPTCONN as i16 != 0,
        prefix.protocol,
    ))
}
