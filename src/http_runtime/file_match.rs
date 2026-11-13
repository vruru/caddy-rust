use super::{
    go_path_glob,
    request::{
        Context, budget_failure, clean_path, descriptor_exhausted, failure, file_io_failure,
        file_split, safe_join,
    },
};
use crate::{http_config::helpers::replace, http_config::types::FileMatchPolicy};
use anyhow::Result;
use http::StatusCode;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const ENTRY_LIMIT: usize = 100_000;
const MATCH_LIMIT: usize = 10_000;

struct Candidate {
    path: PathBuf,
    relative: String,
    remainder: String,
    directory: bool,
}

fn candidate(path: PathBuf, root: &Path, remainder: &str, directory: bool) -> Candidate {
    let relative = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
    let mut relative = format!("/{}", relative.trim_start_matches('/'));
    if directory && !relative.ends_with('/') {
        relative.push('/');
    }
    Candidate {
        path,
        relative,
        remainder: remainder.to_owned(),
        directory,
    }
}

fn has_glob(component: &str) -> bool {
    !cfg!(windows)
        && component
            .bytes()
            .any(|b| matches!(b, b'[' | b'?' | b'*' | b'\\'))
}

fn expand_globs(root: &Path, before: &str, remaining: &mut usize) -> io::Result<Vec<PathBuf>> {
    let mut parents = vec![root.to_path_buf()];
    for component in before
        .trim_matches('/')
        .split('/')
        .filter(|c| !c.is_empty())
    {
        if !has_glob(component) {
            for path in &mut parents {
                path.push(component);
            }
            continue;
        }
        let mut results = Vec::new();
        for path in parents {
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(e) if descriptor_exhausted(&e) => return Err(e),
                Err(_) => continue,
            };
            for entry in entries {
                *remaining = remaining
                    .checked_sub(1)
                    .ok_or_else(|| io::Error::other("file glob scan budget exceeded"))?;
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) if descriptor_exhausted(&e) => return Err(e),
                    Err(_) => continue,
                };
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| go_path_glob(component, name))
                {
                    if results.len() >= MATCH_LIMIT {
                        return Err(io::Error::other("file glob result budget exceeded"));
                    }
                    results.push(entry.path());
                }
            }
        }
        results.sort_unstable();
        parents = results;
    }
    let mut present = Vec::with_capacity(parents.len());
    for path in parents {
        match fs::metadata(&path) {
            Ok(_) => present.push(path),
            Err(error) if descriptor_exhausted(&error) => return Err(error),
            Err(_) => {}
        }
    }
    Ok(present)
}

fn escaped_lookup(value: String) -> String {
    if cfg!(windows) || !has_glob(&value) {
        return value;
    }
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '[' | '?' | '*' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn publish(ctx: &mut Context, candidate: Candidate, directory: bool) {
    ctx.values
        .insert("http.matchers.file.relative".into(), candidate.relative);
    let mut absolute = candidate
        .path
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    if candidate.directory && !absolute.ends_with('/') {
        absolute.push('/');
    }
    ctx.values
        .insert("http.matchers.file.absolute".into(), absolute);
    ctx.values
        .insert("http.matchers.file.remainder".into(), candidate.remainder);
    ctx.values.insert(
        "http.matchers.file.type".into(),
        if directory { "directory" } else { "file" }.into(),
    );
}

pub(super) async fn matches(
    ctx: &mut Context,
    root: Option<&str>,
    patterns: &[String],
    splits: &[String],
    policy: FileMatchPolicy,
) -> Result<bool> {
    let root = PathBuf::from(ctx.expand_text_resolved(root.unwrap_or("{http.vars.root}"),true).await?);
    let first = matches!(policy, FileMatchPolicy::First | FileMatchPolicy::Fallback);
    let mut work = Vec::with_capacity(patterns.len());
    let mut input_bytes = 0usize;
    for raw in patterns {
        let status = first
            .then(|| {
                raw.strip_prefix('=')
                    .and_then(|value| value.parse::<u16>().ok())
                    .and_then(|value| StatusCode::from_u16(value).ok())
            })
            .flatten();
        let expanded = if status.is_some() {
            String::new()
        } else {
            let view=ctx.lookup_view();let lookup=EscapedLookup{view};
            let value=super::replacer_async::expand(raw,true,&lookup,view.pool()).await?;
            view.retain_text(value.clone())?;view.reserve_text_copy(value.len().saturating_mul(8).saturating_add(8192))?;
            let value=String::from_utf8(value.to_vec())?;
            input_bytes = input_bytes.saturating_add(value.len());
            if input_bytes > 1 << 20 {
                return Err(failure(StatusCode::SERVICE_UNAVAILABLE));
            }
            clean_path(&value, true)
        };
        let (before, remainder) = file_split(expanded.trim_end_matches('/'), splits);
        // Preserve safe_join's established lexical check for the entire path.
        let _ = safe_join(&root, before)?;
        work.push((
            before.to_owned(),
            remainder.to_owned(),
            raw.ends_with('/'),
            status,
        ));
        if status.is_some() {
            break;
        }
    }
    let selected = ctx
        .resources
        .metadata
        .run(super::map_runtime::text_job(ctx.text_owner(),move || {
            let mut winner: Option<(Candidate, fs::Metadata)> = None;
            let mut remaining = ENTRY_LIMIT;
            let count = work.len();
            for (i, (before, remainder, directory, status)) in work.into_iter().enumerate() {
                if let Some(status) = status {
                    return Ok(Err(status));
                }
                let choices = expand_globs(&root, &before, &mut remaining)?;
                for path in choices {
                    let current = candidate(path, &root, &remainder, directory);
                    if policy == FileMatchPolicy::Fallback && i + 1 == count {
                        return Ok(Ok(Some((current, false))));
                    }
                    let info = match fs::metadata(&current.path) {
                        Ok(info) => info,
                        Err(e) if descriptor_exhausted(&e) => return Err(e),
                        Err(_) => continue,
                    };
                    if first {
                        if info.is_dir() == directory {
                            return Ok(Ok(Some((current, info.is_dir()))));
                        }
                        continue;
                    }
                    let replace = match policy {
                        FileMatchPolicy::Largest => {
                            info.len() > winner.as_ref().map_or(0, |(_, v)| v.len())
                        }
                        FileMatchPolicy::Smallest => winner
                            .as_ref()
                            .is_none_or(|(_, v)| v.len() == 0 || info.len() < v.len()),
                        FileMatchPolicy::Newest => winner
                            .as_ref()
                            .is_none_or(|(_, v)| info.modified().ok() > v.modified().ok()),
                        _ => false,
                    };
                    if replace {
                        winner = Some((current, info));
                    }
                }
            }
            Ok::<_, io::Error>(Ok(
                winner.map(|(candidate, info)| (candidate, info.is_dir()))
            ))
        })?)
        .await
        .map_err(|e| budget_failure(ctx, e))?.into_context(ctx)?
        .map_err(|e| file_io_failure(ctx, &e))?;
    let Some((candidate, is_dir)) = selected.map_err(failure)? else {
        return Ok(false);
    };
    publish(ctx, candidate, is_dir);
    Ok(true)
}

struct EscapedLookup<'a>{view:super::request::ReplacerView<'a>}
impl super::replacer_async::Lookup for EscapedLookup<'_>{
 fn lookup<'a>(&'a self,name:&'a str)->impl std::future::Future<Output=Result<Option<bytes::Bytes>>>+Send+'a{
  async move{
   let Some(value)=self.view.lookup_resolved(name).await?else{return Ok(None)};
   let Ok(value)=std::str::from_utf8(&value)else{return Ok(None)};
   let credit=self.view.pool().reserve(value.len().saturating_mul(10)+1024)?;
   Ok(Some(super::map_runtime::owned(escaped_lookup(value.to_owned()).into_bytes(),credit)))
  }
 }
}
