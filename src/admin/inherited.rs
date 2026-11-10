//! Initial-configuration inherited descriptors are anchored before Tokio starts.
//! Runtime fd numbers are never lazily captured: they may belong to the reactor.
use super::AdminError;
use std::{
    collections::BTreeMap,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Mutex, OnceLock},
};
#[cfg(target_os = "macos")]
#[path = "inherited_darwin.rs"]
mod darwin;
fn invalid(category: &'static str) -> AdminError {
    AdminError::new(400, category)
}
struct Anchor {
    fd: OwnedFd,
    dev: u64,
    ino: u64,
}
#[derive(Default)]
struct Registry {
    initialized: bool,
    entries: BTreeMap<i32, Anchor>,
}
static ANCHORS: OnceLock<Mutex<Registry>> = OnceLock::new();
fn anchors() -> &'static Mutex<Registry> {
    ANCHORS.get_or_init(|| Mutex::new(Registry::default()))
}
pub(super) fn number(raw: &str) -> Result<i32, AdminError> {
    let text = raw
        .strip_prefix("fd/")
        .ok_or_else(|| invalid("invalid_admin_inherited_descriptor"))?;
    if text.is_empty() || text.starts_with(['-', '+']) {
        return Err(invalid("invalid_admin_inherited_descriptor"));
    }
    let (radix, digits, prefix) =
        if let Some(s) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (16, s, true)
        } else if let Some(s) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
            (8, s, true)
        } else if let Some(s) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
            (2, s, true)
        } else if text.len() > 1 && text.starts_with('0') {
            (8, &text[1..], true)
        } else {
            (10, text, false)
        };
    let digits = if prefix {
        digits.strip_prefix('_').unwrap_or(digits)
    } else {
        digits
    };
    if digits.is_empty() || digits.ends_with('_') || digits.contains("__") {
        return Err(invalid("invalid_admin_inherited_descriptor"));
    }
    if digits.starts_with('_') || digits.chars().any(|c| c != '_' && !c.is_digit(radix)) {
        return Err(invalid("invalid_admin_inherited_descriptor"));
    }
    i32::from_str_radix(&digits.replace('_', ""), radix)
        .map_err(|_| invalid("invalid_admin_inherited_descriptor"))
}
fn duplicate(raw: i32) -> Result<OwnedFd, AdminError> {
    // fcntl validates the integer before Rust assumes ownership of its new fd.
    let fd = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(invalid("admin_inherited_descriptor_unavailable"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn identity(fd: &OwnedFd) -> Result<(u64, u64), AdminError> {
    #[cfg(target_os = "macos")]
    {
        darwin::info(fd).map(|(key, _, _)| (0, key))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let stat =
            rustix::fs::fstat(fd).map_err(|_| invalid("invalid_admin_inherited_descriptor"))?;
        Ok((stat.st_dev as u64, stat.st_ino))
    }
}
fn validate(fd: &OwnedFd) -> Result<(), AdminError> {
    fn option(fd: i32, opt: i32) -> Result<i32, AdminError> {
        let mut value = 0i32;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&mut value as *mut i32).cast(),
                &mut len,
            )
        };
        if rc != 0 || len as usize != std::mem::size_of::<i32>() {
            return Err(invalid("admin_inherited_not_socket"));
        }
        Ok(value)
    }
    #[cfg(target_os = "macos")]
    let listening = darwin::info(fd)?.1;
    #[cfg(not(target_os = "macos"))]
    let listening = option(fd.as_raw_fd(), libc::SO_ACCEPTCONN)? == 1;
    if option(fd.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM || !listening {
        return Err(invalid("admin_inherited_requires_stream_listener"));
    }
    let socket = socket2::SockRef::from(fd);
    let addr = socket
        .local_addr()
        .map_err(|_| invalid("admin_inherited_invalid_address"))?;
    if !matches!(
        addr.family() as i32,
        libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX
    ) {
        return Err(invalid("admin_inherited_unsupported_family"));
    }
    #[cfg(target_os = "macos")]
    if matches!(addr.family() as i32, libc::AF_INET | libc::AF_INET6)
        && darwin::info(fd)?.2 != libc::IPPROTO_TCP
    {
        return Err(invalid("admin_inherited_requires_tcp"));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if matches!(addr.family() as i32, libc::AF_INET | libc::AF_INET6)
        && !matches!(
            option(fd.as_raw_fd(), libc::SO_PROTOCOL)?,
            libc::IPPROTO_TCP | 262
        )
    {
        return Err(invalid("admin_inherited_requires_tcp"));
    }
    Ok(())
}
/// Must run before creating Tokio; only declared admin descriptors are captured.
/// Original descriptors remain open and keep their existing FD_CLOEXEC value.
/// Activation sets O_NONBLOCK on their shared open-file description, as Go does.
/// Successful capture is once per process; failures do not freeze the registry.
pub fn capture(config: &serde_json::Value) -> Result<(), AdminError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(invalid("admin_inherited_capture_requires_pre_runtime"));
    }
    let policy = super::policy::LocalPolicy::parse(config)?;
    let mut refs = Vec::new();
    if !policy.disabled && policy.listen.starts_with("fd/") {
        refs.push(number(&policy.listen)?);
    }
    if let Some(remote) = &policy.remote
        && remote.listen.starts_with("fd/")
    {
        refs.push(number(&remote.listen)?);
    }
    let mut registry = anchors()
        .lock()
        .map_err(|_| invalid("admin_inherited_registry_failed"))?;
    if registry.initialized {
        return Err(invalid("admin_inherited_capture_repeated"));
    }
    // Validate every original integer before a dup can occupy a missing slot.
    for n in &refs {
        if unsafe { libc::fcntl(*n, libc::F_GETFD) } < 0 {
            return Err(invalid("admin_inherited_descriptor_unavailable"));
        }
    }
    let entries = &mut registry.entries;
    let mut pending = Vec::new();
    let mut seen = Vec::new();
    for n in refs {
        let fd = duplicate(n)?;
        validate(&fd)?;
        let (dev, ino) = identity(&fd)?;
        if seen.contains(&(dev, ino)) {
            return Err(invalid("admin_inherited_socket_used_twice"));
        }
        seen.push((dev, ino));
        if let Some(old) = entries.get(&n) {
            if (old.dev, old.ino) != (dev, ino) {
                return Err(invalid("admin_inherited_descriptor_replaced"));
            }
        } else {
            pending.push((n, Anchor { fd, dev, ino }));
        }
    }
    entries.extend(pending);
    registry.initialized = true;
    Ok(())
}
pub(super) struct Captured {
    pub socket: socket2::Socket,
}
pub(super) fn get(raw: &str) -> Result<Captured, AdminError> {
    let n = number(raw)?;
    let entries = anchors()
        .lock()
        .map_err(|_| invalid("admin_inherited_registry_failed"))?;
    let anchor = entries
        .entries
        .get(&n)
        .ok_or_else(|| invalid("admin_inherited_descriptor_not_anchored"))?;
    let fd = duplicate(anchor.fd.as_raw_fd())?;
    validate(&fd)?;
    Ok(Captured {
        socket: socket2::Socket::from(fd),
    })
}
pub(super) fn key(raw: &str) -> Option<(u64, u64)> {
    let n = number(raw).ok()?;
    let entries = anchors().lock().ok()?;
    let a = entries.entries.get(&n)?;
    Some((a.dev, a.ino))
}
