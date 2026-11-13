// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

fn has_meta(pattern: &str) -> bool {
    pattern.contains(['*', '?', '[', '\\'])
}

fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    }
}

fn clean_glob_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    if path == "/" {
        return "/".to_string();
    }
    path[..path.len() - 1].to_string()
}

fn match_name(pattern:&str,name:&[u8])->Result<bool>{
    crate::go_path_glob::go_path_glob_bytes(pattern,name).ok_or_else(||anyhow::anyhow!("syntax error in glob pattern"))
}
fn validate_pattern(pattern:&str)->Result<()>{
    if crate::go_path_glob::compile_go_path_glob(pattern).is_none(){bail!("syntax error in glob pattern");}Ok(())
}

pub(super) fn glob(pattern: &Path, max_matches: usize) -> Result<Vec<PathBuf>> {
    let pattern_str = pattern
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("pattern must be valid UTF-8"))?;

    if !pattern.is_absolute() {
        bail!("glob pattern must be absolute");
    }
    if pattern_str.matches('*').count() > 1
        || pattern_str.matches('?').count() > 1
        || (pattern_str.contains('[') && pattern_str.contains(']'))
    {
        bail!("Glob pattern may only contain one wildcard (*), but has others: {pattern_str}");
    }
    let mut remaining = max_matches.saturating_mul(64).saturating_add(1024);
    glob_with_limit(pattern_str, 0, max_matches, &mut remaining)
}

fn glob_with_limit(
    pattern: &str,
    depth: usize,
    max_matches: usize,
    remaining: &mut usize,
) -> Result<Vec<PathBuf>> {
    const MAX_DEPTH: usize = 256;
    if depth >= MAX_DEPTH {
        bail!("glob recursion depth exceeded");
    }

    validate_pattern(pattern)?;

    if !has_meta(pattern) {
        let path = Path::new(pattern);
        match fs::symlink_metadata(path) {
            Ok(_) => {
                if max_matches == 0 {
                    bail!("max matches exceeded");
                }
                return Ok(vec![path.to_path_buf()]);
            }
            Err(_) => return Ok(vec![]),
        }
    }

    let (dir, file) = split_path(pattern);
    let dir_cleaned = clean_glob_path(dir);

    if !has_meta(&dir_cleaned) {
        return glob_dir(&dir_cleaned, file, max_matches, remaining);
    }

    if dir_cleaned == pattern {
        bail!("syntax error: infinite recursion");
    }

    let dirs = glob_with_limit(&dir_cleaned, depth + 1, max_matches, remaining)?;

    let mut matches = Vec::new();

    for d in dirs {
        let d_str = d
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("path not UTF-8"))?;

        let m = glob_dir(d_str, file, max_matches, remaining)?;

        for p in m {
            if matches.len() >= max_matches {
                bail!("max matches exceeded");
            }
            matches.push(p);
        }
    }

    Ok(matches)
}

fn glob_dir(
    dir: &str,
    pattern: &str,
    max_matches: usize,
    remaining: &mut usize,
) -> Result<Vec<PathBuf>> {
    let dir_path = Path::new(dir);

    let meta = match fs::metadata(dir_path) {
        Ok(m) => m,
        Err(_) => return Ok(vec![]), // Ignore I/O error
    };

    if !meta.is_dir() {
        return Ok(vec![]);
    }

    let mut read_dir = match fs::read_dir(dir_path) {
        Ok(rd) => rd,
        Err(_) => return Ok(vec![]), // Ignore I/O error
    };

    let mut names = Vec::new();
    for entry in read_dir.by_ref() {
        if *remaining == 0 {
            bail!("glob directory scan limit exceeded");
        }
        *remaining -= 1;
        if let Ok(entry) = entry {
            names.push(entry.file_name());
        }
    }

    names.sort();

    let mut matches = Vec::new();

    for name in names {
        use std::os::unix::ffi::OsStrExt;
        if match_name(pattern, name.as_bytes())? {
            if name.to_str().is_none() {
                bail!("non-UTF8 import paths are unsupported");
            }
            let joined = lexical_absolute(&dir_path.join(&name), Path::new("/"))?;

            if matches.len() >= max_matches {
                bail!("max matches exceeded");
            }
            matches.push(joined);
        }
    }

    Ok(matches)
}
pub(super) fn lexical_absolute(path: &Path, cwd: &Path) -> Result<PathBuf> {
    use std::path::Component;
    if !cwd.is_absolute() {
        bail!("Caddyfile working directory must be absolute");
    }
    let combined = if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    };
    let mut result = PathBuf::from("/");
    for part in combined.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(name) => result.push(name),
            Component::Prefix(_) => bail!("unsupported import path prefix"),
        }
    }
    Ok(result)
}
pub(crate) fn read_source(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::{fs::OpenOptions, io::Read};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        bail!("import source must be a regular file");
    }
    let limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("import byte limit overflow"))?;
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("import source byte limit exceeded");
    }
    Ok(bytes)
}
pub(super) fn same_directory(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.is_dir() && b.is_dir() && a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}
