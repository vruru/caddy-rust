// Copyright 2022 The Go Authors. All rights reserved.
// Startup policy follows Go 1.27.3 syscall/rlimit{,_darwin}.go, BSD-3-Clause.
//! Process-only open-file startup policy. Call before creating worker runtimes.
use std::io;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileLimitReport {
    pub before_soft: u64,
    pub after_soft: u64,
    pub hard: u64,
    pub attempted: bool,
    pub set_error_code: Option<i32>,
}
#[cfg(unix)]
fn current() -> io::Result<libc::rlimit> {
    let mut limit = std::mem::MaybeUninit::uninit();
    // On success getrlimit initializes the complete caller-owned structure.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { limit.assume_init() })
}
#[cfg(target_os = "macos")]
fn platform_limit(requested: libc::rlim_t) -> libc::rlim_t {
    let mut maximum = 0u32;
    let mut size = std::mem::size_of_val(&maximum);
    // Read only. No sysctl or system-wide resource setting is modified.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut maximum as *mut u32).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 && size == std::mem::size_of_val(&maximum) {
        requested.min(maximum.into())
    } else {
        requested
    }
}
#[cfg(all(unix, not(target_os = "macos")))]
fn platform_limit(requested: libc::rlim_t) -> libc::rlim_t {
    requested
}
/// Raise this process's soft NOFILE limit within its inherited hard limit.
/// An explicit equal soft/hard limit is respected. Failed set attempts are
/// reported while preserving the observed limit for honest admission budgets.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
pub fn prepare_open_file_limit() -> io::Result<FileLimitReport> {
    let before = current()?;
    let mut attempted = false;
    let mut set_error_code = None;
    if before.rlim_max > 0 && before.rlim_cur < before.rlim_max - 1 {
        let desired = platform_limit(before.rlim_max - 1);
        // Never lower an already higher soft limit, even if a platform's
        // current global ceiling differs from an earlier process setting.
        if desired > before.rlim_cur {
            attempted = true;
            let next = libc::rlimit {
                rlim_cur: desired,
                rlim_max: before.rlim_max,
            };
            // Only this process's soft limit changes, never its hard limit.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } != 0 {
                set_error_code = io::Error::last_os_error().raw_os_error();
            }
        }
    }
    let after = current()?;
    Ok(FileLimitReport {
        before_soft: before.rlim_cur as u64,
        after_soft: after.rlim_cur as u64,
        hard: after.rlim_max as u64,
        attempted,
        set_error_code,
    })
}
#[cfg(not(unix))]
pub fn prepare_open_file_limit() -> io::Result<FileLimitReport> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix open-file limits unavailable",
    ))
}
