// facts.rs
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn values() -> Vec<(&'static str, f64)> {
    let mut out = Vec::with_capacity(10);

    // 1. process_cpu_seconds_total (utime + stime from getrusage SELF)
    if let Some(cpu) = get_process_cpu_seconds() {
        out.push(("process_cpu_seconds_total", cpu));
    }

    // 2. process_max_fds (RLIMIT_NOFILE)
    if let Some(max_fds) = get_max_fds() {
        out.push(("process_max_fds", max_fds));
    }

    // 3. process_virtual_memory_max_bytes (RLIMIT_AS)
    if let Some(vm_max) = get_virtual_memory_max_bytes() {
        out.push(("process_virtual_memory_max_bytes", vm_max));
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(start_time) = get_linux_start_time() {
            out.push(("process_start_time_seconds", start_time));
        }

        if let Some(vm_bytes) = get_linux_vm_bytes() {
            out.push(("process_virtual_memory_bytes", vm_bytes));
        }

        if let Some(rss_bytes) = get_linux_rss_bytes() {
            out.push(("process_resident_memory_bytes", rss_bytes));
        }

        if let Some(fd_count) = get_linux_fd_count() {
            out.push(("process_open_fds", fd_count));
        }
        if let Some((received, sent)) = get_linux_network_bytes() {
            out.push(("process_network_receive_bytes_total", received));
            out.push(("process_network_transmit_bytes_total", sent));
        }
    }

    #[cfg(target_os = "macos")]
    macos_values(&mut out);
    out
}

// FFI Safety: libc::getrusage is a standard POSIX syscall. We use RUSAGE_SELF.
// The struct is fully initialized by the kernel. No aliasing issues with raw pointers to local stack vars.
#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn get_process_cpu_seconds() -> Option<f64> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_process_cpu_seconds() -> Option<f64> {
    // SAFETY: rusage contains integer/timeval fields; all-zero is valid,
    // including libc's platform-specific reserved fields.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };

    // Safety: usage is a valid pointer to an initialized struct of the correct type.
    let res = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if res != 0 {
        return None;
    }

    // utime and stime are timevals.
    let secs = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let secs = secs + usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
    Some(secs)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_max_fds() -> Option<f64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Safety: limit is a valid pointer to an initialized struct.
    let res = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if res != 0 {
        return None;
    }
    Some(limit.rlim_cur as f64)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_virtual_memory_max_bytes() -> Option<f64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Safety: limit is a valid pointer to an initialized struct.
    let res = unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) };
    if res != 0 {
        return None;
    }
    Some(limit.rlim_cur as f64)
}

#[cfg(target_os = "linux")]
fn get_sysconf_clk_tck() -> Option<f64> {
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    // Safety: sysconf is standard POSIX.
    if clk_tck > 0 {
        Some(clk_tck as f64)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn get_sysconf_pagesize() -> Option<f64> {
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    // Safety: sysconf is standard POSIX.
    if pagesize > 0 {
        Some(pagesize as f64)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn get_linux_start_time() -> Option<f64> {
    // 1. Read /proc/self/stat
    let stat_str = read_proc_self_stat()?;
    // Find last ')'
    let idx = stat_str.rfind(')')?;
    let rest = stat_str.get(idx + 1..)?; // Skip ') '

    // Fields after comm:
    // 0: state, 1: ppid, ...
    // Indices in rest split by space:
    // 0=state, 1=ppid, 2=pgrp, 3=session, 4=tty_nr, 5=tpgid,
    // 6=flags, 7=minflt, 8=cminflt, 9=majflt, 10=cmajflt,
    // 11=utime, 12=stime, 13=cutime, 14=cstime, 15=priority,
    // 16=nice, 17=num_threads, 18=itrealvalue, 19=starttime

    let iter = rest.split_whitespace();
    // We need index 19 (0-based)
    let mut start_ticks_str = None;
    for (i, field) in iter.enumerate() {
        if i == 19 {
            start_ticks_str = Some(field);
            break;
        }
    }

    let start_ticks: f64 = start_ticks_str?.parse().ok()?;
    let hz = get_sysconf_clk_tck()?;

    // 2. Read /proc/stat for btime
    let btime = get_btime()?;

    Some(btime + start_ticks / hz)
}

#[cfg(target_os = "linux")]
fn get_linux_vm_bytes() -> Option<f64> {
    let stat_str = read_proc_self_stat()?;
    let idx = stat_str.rfind(')')?;
    let rest = stat_str.get(idx + 1..)?;

    // vsize is index 20 in rest
    let iter = rest.split_whitespace();
    let mut vsize_str = None;
    for (i, field) in iter.enumerate() {
        if i == 20 {
            vsize_str = Some(field);
            break;
        }
    }

    let vsize: f64 = vsize_str?.parse().ok()?;
    Some(vsize)
}

#[cfg(target_os = "linux")]
fn get_linux_rss_bytes() -> Option<f64> {
    let stat_str = read_proc_self_stat()?;
    let idx = stat_str.rfind(')')?;
    let rest = stat_str.get(idx + 1..)?;

    // rss is index 21 in rest
    let iter = rest.split_whitespace();
    let mut rss_pages_str = None;
    for (i, field) in iter.enumerate() {
        if i == 21 {
            rss_pages_str = Some(field);
            break;
        }
    }

    let rss_pages: f64 = rss_pages_str?.parse().ok()?;
    let page_size = get_sysconf_pagesize()?;
    Some(rss_pages * page_size)
}

#[cfg(target_os = "linux")]
fn get_linux_fd_count() -> Option<f64> {
    let mut count: u64 = 0;
    let path = std::path::Path::new("/proc/self/fd");
    let entries = std::fs::read_dir(path).ok()?;
    {
        for entry in entries {
            entry.ok()?;
            count = count.saturating_add(1);
        }
    }
    Some(count as f64)
}

#[cfg(target_os = "linux")]
fn read_proc_self_stat() -> Option<String> {
    let file = File::open("/proc/self/stat").ok()?;
    const LIMIT: usize = 64 * 1024;
    let mut buffer = Vec::with_capacity(4096);
    // Read at most LIMIT + 1 to check overflow
    if file
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut buffer)
        .is_err()
    {
        return None;
    }
    if buffer.len() > LIMIT {
        return None;
    }
    String::from_utf8(buffer).ok()
}

#[cfg(target_os = "linux")]
fn get_btime() -> Option<f64> {
    let file = File::open("/proc/stat").ok()?;
    const LIMIT: usize = 2 * 1024 * 1024; // 2MiB
    let mut buffer = Vec::with_capacity(4096);
    if file
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut buffer)
        .is_err()
    {
        return None;
    }
    if buffer.len() > LIMIT {
        return None;
    }
    let content = String::from_utf8(buffer).ok()?;

    for line in content.lines() {
        if line.starts_with("btime ") {
            let rest = line.trim_start_matches("btime ");
            if let Some(val_str) = rest.split_whitespace().next() {
                return val_str.parse().ok();
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn values() -> Vec<(&'static str, f64)> {
    Vec::new()
}

#[cfg(target_os = "macos")]
fn macos_values(out: &mut Vec<(&'static str, f64)>) {
    use std::mem::{MaybeUninit, size_of};
    // SDK libproc.h / sys/proc_info.h and libc expose the same native layout.
    let pid = unsafe { libc::getpid() };
    let mut task = MaybeUninit::<libc::proc_taskinfo>::zeroed();
    let count = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            task.as_mut_ptr().cast(),
            size_of::<libc::proc_taskinfo>() as i32,
        )
    };
    if count == size_of::<libc::proc_taskinfo>() as i32 {
        let task = unsafe { task.assume_init() };
        out.push((
            "process_resident_memory_bytes",
            task.pti_resident_size as f64,
        ));
        out.push(("process_virtual_memory_bytes", task.pti_virtual_size as f64));
    }
    let mut bsd = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let count = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            bsd.as_mut_ptr().cast(),
            size_of::<libc::proc_bsdinfo>() as i32,
        )
    };
    if count == size_of::<libc::proc_bsdinfo>() as i32 {
        let bsd = unsafe { bsd.assume_init() };
        out.push((
            "process_start_time_seconds",
            bsd.pbi_start_tvsec as f64 + bsd.pbi_start_tvusec as f64 / 1e6,
        ));
    }
    if let Some(count) = macos_fds(pid) {
        out.push(("process_open_fds", count as f64));
    }
}
#[cfg(target_os = "macos")]
fn macos_fds(pid: i32) -> Option<usize> {
    const MAX: usize = 8 << 20;
    let hint =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if hint <= 0 {
        return None;
    }
    let mut capacity = (hint as usize).checked_add(4096)?.min(MAX);
    for _ in 0..3 {
        let mut buffer = Vec::<std::mem::MaybeUninit<libc::proc_fdinfo>>::new();
        buffer
            .try_reserve_exact(capacity / std::mem::size_of::<libc::proc_fdinfo>())
            .ok()?;
        let length = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                buffer.as_mut_ptr().cast(),
                capacity as i32,
            )
        };
        if length <= 0 {
            return None;
        }
        let length = length as usize;
        if length < capacity && length.is_multiple_of(std::mem::size_of::<libc::proc_fdinfo>()) {
            return Some(length / std::mem::size_of::<libc::proc_fdinfo>());
        }
        if capacity == MAX {
            return None;
        }
        capacity = capacity.saturating_mul(2).min(MAX);
    }
    None
}

// Linux exposes these in the process network namespace, as procfs.Proc.Netstat
// used by Prometheus' process collector does; these are not per-socket counters.
#[cfg(target_os = "linux")]
fn get_linux_network_bytes() -> Option<(f64, f64)> {
    let file = File::open("/proc/self/net/netstat").ok()?;
    let mut bytes = Vec::with_capacity(4096);
    file.take((2 << 20) + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 2 << 20 {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let mut lines = text.lines();
    while let Some(names) = lines.next() {
        let values = lines.next()?;
        let mut names = names.split_whitespace();
        let mut values = values.split_whitespace();
        if names.next() != Some("IpExt:") || values.next() != Some("IpExt:") {
            continue;
        }
        let mut input = None;
        let mut output = None;
        for (name, value) in names.zip(values) {
            match name {
                "InOctets" => input = Some(value.parse::<u64>().ok()? as f64),
                "OutOctets" => output = Some(value.parse::<u64>().ok()? as f64),
                _ => {}
            }
        }
        return Some((input.unwrap_or(0.), output.unwrap_or(0.)));
    }
    None
}
