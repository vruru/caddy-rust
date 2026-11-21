//! Linux memory headroom for open static-file responses.

#[cfg(target_os = "linux")]
pub(super) fn memory_headroom() -> Option<usize> {
    use std::{fs, io::ErrorKind, path::Path};

    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let mut available = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?
        .split_ascii_whitespace()
        .next()?
        .parse::<usize>()
        .ok()?
        .saturating_mul(1024);

    let membership = fs::read_to_string("/proc/self/cgroup").ok()?;
    if membership.lines().any(|line| {
        line.split(':')
            .nth(1)
            .is_some_and(|controllers| controllers.split(',').any(|name| name == "memory"))
    }) {
        // A legacy memory hierarchy may be mounted outside the standard v2 root.
        return None;
    }
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))?;
    let root = Path::new("/sys/fs/cgroup");
    let group = root.join(relative);
    if !group.is_dir() || !root.join("cgroup.controllers").is_file() {
        return None;
    }
    for ancestor in group.ancestors().take_while(|dir| dir.starts_with(root)) {
        for name in ["memory.high", "memory.max"] {
            let limit = match fs::read_to_string(ancestor.join(name)) {
                Ok(value) if value.trim() == "max" => continue,
                Ok(value) => value.trim().parse::<usize>().ok()?,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(_) => return None,
            };
            let current = fs::read_to_string(ancestor.join("memory.current"))
                .ok()?
                .trim()
                .parse::<usize>()
                .ok()?;
            available = available.min(limit.saturating_sub(current));
        }
    }
    Some(available)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn memory_headroom() -> Option<usize> {
    None
}
