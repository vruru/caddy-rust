// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::budget::{Budget, add, mul};
use anyhow::{Result, anyhow};
use serde_json::Value;
use std::path::Path;
pub(super) fn apply(
    handler: &mut Value,
    files: &[String],
    cwd: &Path,
    budget: &mut Budget,
) -> Result<()> {
    let map = handler
        .as_object_mut()
        .ok_or_else(|| anyhow!("file_server handler must be an object"))?;
    let hide = map
        .entry("hide")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow!("file_server hide must be an array"))?;
    for file in files {
        budget.work(file.len() as u64 + 1)?;
        budget.materialize(file.len() as u64 + 128)?;
        let file = clean(file);
        if hidden(&file, hide, cwd, budget)? {
            continue;
        }
        hide.push(Value::String(if file.contains('/') {
            file
        } else {
            format!("./{file}")
        }));
    }
    if hide.is_empty() {
        map.remove("hide");
    }
    Ok(())
}
fn hidden(file: &str, patterns: &[Value], cwd: &Path, budget: &mut Budget) -> Result<bool> {
    if patterns.is_empty() {
        return Ok(false);
    }
    let absolute = if file.starts_with('/') {
        file.to_owned()
    } else {
        let cwd = cwd.to_str().ok_or_else(|| {
            anyhow!("non-UTF8 working directory cannot be used to finalize Caddyfile hiding")
        })?;
        clean(&format!("{cwd}/{file}"))
    };
    for pattern in patterns {
        let pattern = pattern
            .as_str()
            .ok_or_else(|| anyhow!("file_server hide pattern must be a string"))?;
        // Regex/path matching work is prepaid for every source-controlled
        // comparison; no hidden N x M sweep runs outside the shared ledger.
        budget.work(mul(
            add(pattern.len() as u64, 1)?,
            add(absolute.len() as u64, 1)?,
        )?)?;
        if !pattern.contains('/') {
            if absolute
                .split('/')
                .any(|part| crate::http_runtime::go_path_glob(pattern, part))
            {
                return Ok(true);
            }
        } else if absolute
            .strip_prefix(pattern)
            .is_some_and(|tail| tail.starts_with('/'))
        {
            return Ok(true);
        }
        if crate::http_runtime::go_path_glob(pattern, &absolute) {
            return Ok(true);
        }
    }
    Ok(false)
}
fn clean(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|s| *s != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(part);
                }
            }
            _ => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}
