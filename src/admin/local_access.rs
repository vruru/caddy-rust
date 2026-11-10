//! Recheck the kernel's connection credentials when Unix permissions tighten.
use super::AdminError;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const TIGHTENED: u64 = 1 << 63;
const CLOSED: u64 = 1 << 62;
const FENCED: u64 = 1 << 61;
const FLAGS: u64 = TIGHTENED | CLOSED | FENCED;

pub(super) struct AdmissionState {
    uid: u32,
    packed: AtomicU64,
}
fn pack(mode: u32, gid: u32) -> u64 {
    (u64::from(gid) << 16) | u64::from(mode & 0o7777)
}
impl AdmissionState {
    pub fn new(uid: u32, gid: u32, mode: u32) -> Self {
        Self {
            uid,
            packed: AtomicU64::new(pack(mode, gid)),
        }
    }
    pub fn restrict(&self, mode: u32, gid: u32) {
        let _ = self
            .packed
            .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                let previous = (old & 0o7777) as u32;
                let narrowed = if (old >> 16) as u32 == gid {
                    previous & mode
                } else {
                    previous & mode & 0o700
                };
                let changed = narrowed != previous || (old >> 16) as u32 != gid;
                Some((old & FLAGS) | if changed { TIGHTENED } else { 0 } | pack(narrowed, gid))
            });
    }
    pub fn publish_mode(&self, mode: u32) {
        let _ = self
            .packed
            .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                if old & (CLOSED | FENCED) != 0 {
                    None
                } else {
                    Some((old & !0o7777) | u64::from(mode & 0o7777))
                }
            });
    }
    pub fn enforce(&self) {
        self.packed.fetch_or(TIGHTENED, Ordering::AcqRel);
    }
    pub fn fence(&self) {
        self.packed.fetch_or(FENCED | TIGHTENED, Ordering::AcqRel);
    }
    pub fn revoke(&self) {
        self.packed.fetch_or(CLOSED, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub(super) struct LocalAdmission {
    state: Option<Arc<AdmissionState>>,
    uid: u32,
    gid: u32,
    // Positive membership hints. Only Linux SO_PEERGROUPS is authoritative
    // for absence; macOS may resolve additional memberships outside xucred.
    groups: Option<Arc<[u32]>>,
}
fn credential_error() -> AdminError {
    AdminError::new(500, "admin_peer_credentials_unavailable")
}
fn revoked() -> AdminError {
    AdminError::new(403, "local_admin_authorization_revoked")
}
impl LocalAdmission {
    pub fn tcp() -> Self {
        Self {
            state: None,
            uid: 0,
            gid: 0,
            groups: None,
        }
    }
    pub fn for_unix(
        stream: &tokio::net::UnixStream,
        state: Option<Arc<AdmissionState>>,
    ) -> Result<Self, AdminError> {
        let Some(state) = state else {
            return Ok(Self::tcp());
        };
        let peer = stream.peer_cred().map_err(|_| credential_error())?;
        Ok(Self {
            state: Some(state),
            uid: peer.uid(),
            gid: peer.gid(),
            groups: peer_groups(stream)?,
        })
    }
    pub fn check(&self) -> Result<(), AdminError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let value = state.packed.load(Ordering::Acquire);
        if value & (CLOSED | FENCED) != 0 {
            return Err(revoked());
        }
        if value & TIGHTENED == 0 || self.uid == 0 {
            return Ok(());
        }
        let mode = (value & 0o7777) as u32;
        let gid = (value >> 16) as u32;
        let allowed = if self.uid == state.uid {
            mode & 0o200 != 0
        } else if self.gid == gid || self.groups.as_ref().is_some_and(|g| g.contains(&gid)) {
            mode & 0o020 != 0
        } else {
            // Without a complete group snapshot this peer might belong to the
            // owning group. Unix then uses group bits, never the wider other bits.
            mode & 0o002 != 0
                && ((cfg!(target_os = "linux") && self.groups.is_some()) || mode & 0o020 != 0)
        };
        if allowed { Ok(()) } else { Err(revoked()) }
    }
}

#[cfg(target_os = "linux")]
fn peer_groups(stream: &tokio::net::UnixStream) -> Result<Option<Arc<[u32]>>, AdminError> {
    fn read(fd: std::os::fd::RawFd, groups: &mut [u32], length: &mut libc::socklen_t) -> i32 {
        // Kernel writes at most the supplied byte length into an aligned gid buffer.
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERGROUPS,
                groups.as_mut_ptr().cast(),
                length,
            )
        }
    }
    fn valid_length(length: libc::socklen_t, capacity: usize) -> Result<usize, AdminError> {
        let length = length as usize;
        if !length.is_multiple_of(4) || length > capacity * 4 {
            return Err(credential_error());
        }
        Ok(length / 4)
    }
    let mut small = [0u32; 64];
    let mut length = std::mem::size_of_val(&small) as libc::socklen_t;
    if read(stream.as_raw_fd(), &mut small, &mut length) == 0 {
        return Ok(Some(Arc::from(
            &small[..valid_length(length, small.len())?],
        )));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOPROTOOPT) | Some(libc::EINVAL) | Some(libc::ENOSYS) => Ok(None),
        Some(libc::ERANGE) => {
            let count = valid_length(length, 65_536)?;
            if count <= small.len() {
                return Err(credential_error());
            }
            let mut groups = vec![0u32; count];
            let mut actual = length;
            if read(stream.as_raw_fd(), &mut groups, &mut actual) != 0 {
                return Err(credential_error());
            }
            groups.truncate(valid_length(actual, groups.len())?);
            Ok(Some(Arc::from(groups)))
        }
        _ => Err(credential_error()),
    }
}

#[cfg(target_os = "macos")]
fn peer_groups(stream: &tokio::net::UnixStream) -> Result<Option<Arc<[u32]>>, AdminError> {
    let mut peer = std::mem::MaybeUninit::<libc::xucred>::zeroed();
    let mut length = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    // SOL_LOCAL is 0 on Darwin; LOCAL_PEERCRED returns a versioned xucred.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            0,
            libc::LOCAL_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::xucred>()
    {
        return Err(credential_error());
    }
    // The complete initialized, size-checked structure is now safe to inspect.
    let peer = unsafe { peer.assume_init() };
    if peer.cr_version != 0
        || peer.cr_ngroups < 0
        || peer.cr_ngroups as usize > peer.cr_groups.len()
    {
        return Err(credential_error());
    }
    let count = peer.cr_ngroups as usize;
    // Known positive memberships remain useful even for a full fixed array.
    // Absence is never authoritative: XNU may ask its external group resolver.

    Ok(Some(Arc::from(&peer.cr_groups[..count])))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_groups(_: &tokio::net::UnixStream) -> Result<Option<Arc<[u32]>>, AdminError> {
    Ok(None)
}
