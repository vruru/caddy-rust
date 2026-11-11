//! Caddy file writer's pre-open phase, executed only on its owned I/O worker.
//! Writer keys retain the original filename; directory cleaning does not change
//! the filename passed to open (important for symlinks and `a/../b` paths).
use super::writer_spec::{FileSpec, parse_mode, unix_mode};
use anyhow::{Result, anyhow, bail};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
};
pub(super) fn prepare_directory(spec: &FileSpec) -> Result<PathBuf> {
    let directory = parent_dir(&spec.filename);
    let normalized = super::config::simple_lower(spec.dir_mode.trim());
    let dir_mode = match normalized.as_str() {
        "" | "0" => 0o700,
        "inherit" => inherit(&directory)?,
        // Match Go .Perm() (which deliberately discards special bits), then
        // ensure owner-write. The configured zero value is not replaced here.
        "from_file" => normalize(spec.mode & 0o777) | 0o200,
        _ => parse_mode(&spec.dir_mode)?,
    };
    mkdir_all(&directory, dir_mode)?;
    Ok(directory)
}
pub(super) fn prepare_plain(spec: &FileSpec) -> Result<File> {
    prepare_directory(spec)?;
    let mode = if spec.mode == 0 { 0o600 } else { spec.mode };
    let mut options = OpenOptions::new();
    options.write(true).append(true).create(true);
    #[cfg(unix)]
    options.mode(unix_mode(mode));
    let file = options
        .open(&spec.filename)
        .map_err(|e| anyhow!("log file open failed: {}", e.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("log file stat failed: {}", e.kind()))?;
    #[cfg(unix)]
    if spec.mode != 0 && (metadata.permissions().mode() & 0o777) != (spec.mode & 0o777) {
        fs::set_permissions(
            &spec.filename,
            fs::Permissions::from_mode(unix_mode(spec.mode)),
        )
        .map_err(|e| anyhow!("log file chmod failed: {}", e.kind()))?;
    }
    #[cfg(not(unix))]
    let _ = (mode, metadata);
    Ok(file)
}
fn mkdir_all(directory: &Path, mode: u32) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(unix_mode(mode));
    #[cfg(not(unix))]
    let _ = mode;
    builder
        .create(directory)
        .map_err(|e| anyhow!("log directory creation failed: {}", e.kind()))
}
fn normalize(mut mode: u32) -> u32 {
    if mode & 0o400 != 0 {
        mode |= 0o100;
    }
    if mode & 0o40 != 0 {
        mode |= 0o10;
    }
    if mode & 0o4 != 0 {
        mode |= 0o1;
    }
    mode
}
fn inherit(directory: &Path) -> Result<u32> {
    if fs::metadata(directory).is_ok_and(|m| m.is_dir()) {
        return Ok(0o700);
    }
    let mut current = directory.to_path_buf();
    loop {
        let next = current
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if next == current {
            break;
        }
        if let Ok(metadata) = fs::metadata(next) {
            if !metadata.is_dir() {
                bail!("log directory ancestor is not a directory");
            }
            #[cfg(unix)]
            return Ok(normalize(metadata.permissions().mode() & 0o777));
            #[cfg(not(unix))]
            return Ok(0o700);
        }
        current = next.to_path_buf();
    }
    Ok(0o700)
}
pub(super) fn parent_dir(filename: &str) -> PathBuf {
    let directory = filename.rfind('/').map_or(".", |i| &filename[..=i]);
    clean(Path::new(directory))
}
fn clean(path: &Path) -> PathBuf {
    let absolute = path.is_absolute();
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::Normal(s) => parts.push(s),
            Component::ParentDir => {
                if parts
                    .last()
                    .is_some_and(|s| *s != std::ffi::OsStr::new(".."))
                {
                    parts.pop();
                } else if !absolute {
                    parts.push(std::ffi::OsStr::new(".."));
                }
            }
            _ => {}
        }
    }
    let mut result = if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for part in parts {
        result.push(part);
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    result
}
