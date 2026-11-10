//! Shared process-local descriptor limit observation; never changes OS limits.
pub(super) fn descriptor_limit() -> Option<usize> {
    #[cfg(unix)]
    {
        let mut value = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // getrlimit initializes the supplied structure on success.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, value.as_mut_ptr()) } == 0 {
            let value = unsafe { value.assume_init() };
            if value.rlim_cur != libc::RLIM_INFINITY {
                return Some(usize::try_from(value.rlim_cur).unwrap_or(usize::MAX));
            }
        } else {
            eprintln!("HTTP descriptor limit unavailable; using operation budget fallback");
        }
    }
    None
}
