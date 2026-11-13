//! Byte-oriented URI modifiers, ported from Caddy v2.11.7 (Apache-2.0).
//! A component is never parsed as an absolute URL. All operations have an
//! admitted workspace and a separate output limit before buffer growth.
use crate::go_regexp::{GoRegexp, ReplaceBudget, Replacement};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
pub(super) const CAP: usize = 4 << 20;
pub(super) fn uri_bytes(uri: &http::Uri) -> usize {
    uri.scheme_str()
        .map_or(0, str::len)
        .saturating_add(uri.authority().map_or(0, |a| a.as_str().len()))
        .saturating_add(uri.path_and_query().map_or(0, |p| p.as_str().len()))
        .saturating_add(8)
}

pub(super) fn clean(input: &[u8], merge: bool) -> Vec<u8> {
    if input.is_empty() {
        return b".".to_vec();
    }
    let rooted = input[0] == b'/';
    let trailing = input.ends_with(b"/");
    // Empty components are concrete stack entries when repeated slashes are
    // significant. This avoids a sentinel colliding with a real request byte.
    let mut parts: Vec<&[u8]> = Vec::with_capacity(input.len() / 2 + 1);
    let mut at = usize::from(rooted);
    while at < input.len() {
        let end = memchr::memchr(b'/', &input[at..]).map_or(input.len(), |n| at + n);
        let p = &input[at..end];
        if p == b"." || (p.is_empty() && merge) {
        } else if p == b".." {
            if parts.last().is_some_and(|p| *p != b"..") {
                parts.pop();
            } else if !rooted {
                parts.push(p);
            }
        } else {
            parts.push(p);
        }
        at = end + 1;
    }
    let mut out = Vec::with_capacity(input.len() + 1);
    if rooted {
        out.push(b'/');
    }
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(p);
    }
    if out.is_empty() && parts.is_empty() {
        out.push(b'.');
    }
    if trailing && (out != b"/" || !parts.is_empty()) {
        out.push(b'/');
    }
    out
}
fn width(input: &[u8]) -> usize {
    let n = match input[0] {
        0..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 1,
    };
    if input.len() >= n && std::str::from_utf8(&input[..n]).is_ok() {
        n
    } else {
        1
    }
}
pub(super) fn replace(input: &[u8], find: &[u8], with: &[u8], limit: i64) -> Result<Vec<u8>> {
    let limit = if limit <= 0 {
        usize::MAX
    } else {
        usize::try_from(limit).unwrap_or(usize::MAX)
    };
    let count = if find.is_empty() {
        let (mut at, mut n) = (0, 1);
        while at < input.len() && n < limit {
            at += width(&input[at..]);
            n += 1;
        }
        n.min(limit)
    } else {
        memchr::memmem::Finder::new(find)
            .find_iter(input)
            .take(limit)
            .count()
    };
    let size = input
        .len()
        .checked_sub(
            count
                .checked_mul(find.len())
                .ok_or_else(|| anyhow::anyhow!("rewrite size overflow"))?,
        )
        .and_then(|n| count.checked_mul(with.len()).and_then(|m| n.checked_add(m)))
        .filter(|n| *n <= CAP)
        .ok_or_else(|| anyhow::anyhow!("rewrite output limit exceeded"))?;
    let mut out = Vec::with_capacity(size);
    let (mut at, mut n) = (0, 0);
    if find.is_empty() {
        while n < count {
            out.extend_from_slice(with);
            n += 1;
            if at < input.len() {
                let w = width(&input[at..]);
                out.extend_from_slice(&input[at..at + w]);
                at += w;
            }
        }
    } else {
        for found in memchr::memmem::Finder::new(find)
            .find_iter(input)
            .take(count)
        {
            out.extend_from_slice(&input[at..found]);
            out.extend_from_slice(with);
            at = found + find.len();
        }
    }
    out.extend_from_slice(&input[at..]);
    Ok(out)
}
pub(super) fn escape_query(input: &[u8]) -> Result<Vec<u8>> {
    let size = input
        .iter()
        .try_fold(0usize, |n, b| {
            n.checked_add(if b.is_ascii_alphanumeric() || b"-_.~ ".contains(b) {
                1
            } else {
                3
            })
        })
        .filter(|n| *n <= CAP)
        .ok_or_else(|| anyhow::anyhow!("query output limit exceeded"))?;
    let mut out = Vec::with_capacity(size);
    for b in input {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(b) {
            out.push(*b);
        } else if *b == b' ' {
            out.push(b'+');
        } else {
            out.extend_from_slice(&[
                b'%',
                b"0123456789ABCDEF"[usize::from(b >> 4)],
                b"0123456789ABCDEF"[usize::from(b & 15)],
            ]);
        }
    }
    Ok(out)
}
fn decode(b: &[u8]) -> Result<Vec<u8>> {
    super::http_redirect::url::template_decode_bytes(b)
        .map_err(|_| anyhow::anyhow!("invalid escaped path"))
}
fn encode(b: &[u8]) -> Vec<u8> {
    super::http_redirect::url::template_encode_path_bytes(b)
}
fn encoded_len(path: &[u8]) -> usize {
    path.iter()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(b) {
                1
            } else {
                3
            }
        })
        .sum()
}
fn canonical_eq(path: &[u8], raw: &[u8]) -> bool {
    if path == b"*" {
        return raw == b"*";
    }
    let mut at = 0;
    for b in path {
        if b.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(b) {
            if raw.get(at) != Some(b) {
                return false;
            }
            at += 1;
        } else {
            let encoded = [
                b'%',
                b"0123456789ABCDEF"[(b >> 4) as usize],
                b"0123456789ABCDEF"[(b & 15) as usize],
            ];
            if raw.get(at..at + 3) != Some(&encoded) {
                return false;
            }
            at += 3;
        }
    }
    at == raw.len()
}
fn decoded_eq(raw: &[u8], path: &[u8]) -> bool {
    let (mut at, mut n) = (0, 0);
    while at < raw.len() {
        let b = if raw[at] == b'%' {
            if at + 2 >= raw.len() {
                return false;
            }
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            let (Some(a), Some(b)) = (digit(raw[at + 1]), digit(raw[at + 2])) else {
                return false;
            };
            at += 3;
            a * 16 + b
        } else {
            let b = raw[at];
            at += 1;
            b
        };
        if path.get(n) != Some(&b) {
            return false;
        }
        n += 1;
    }
    n == path.len()
}
#[derive(Clone)]
pub(super) struct State {
    pub path: Vec<u8>,
    pub raw_path: Vec<u8>,
    pub query: Vec<u8>,
    pub fragment: Vec<u8>,
    pub force_query: bool,
}
impl State {
    pub fn read(uri: &http::Uri) -> Result<Self> {
        let raw = uri.path_and_query().map_or("", |p| p.raw_path()).as_bytes();
        let path = decode(raw)?;
        let raw_path = if canonical_eq(&path, raw) {
            Vec::new()
        } else {
            raw.to_vec()
        };
        Ok(Self {
            path,
            raw_path,
            query: uri.query().unwrap_or_default().as_bytes().to_vec(),
            fragment: Vec::new(),
            force_query: uri.query() == Some(""),
        })
    }
    fn raw_valid(&self) -> bool {
        !self.raw_path.is_empty()
            && self
                .raw_path
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@!'()*[]%".contains(b))
            && decoded_eq(&self.raw_path, &self.path)
    }
    fn escaped_len(&self) -> usize {
        if self.raw_valid() {
            self.raw_path.len()
        } else if self.path == b"*" {
            1
        } else {
            encoded_len(&self.path)
        }
    }
    pub fn escaped(&self) -> Vec<u8> {
        if self.raw_valid() {
            self.raw_path.clone()
        } else if self.path == b"*" {
            b"*".to_vec()
        } else {
            encode(&self.path)
        }
    }
    pub fn target_bytes(&self, request_uri: bool) -> Result<Vec<u8>> {
        let path_size = self.escaped_len();
        let size = path_size.max(usize::from(request_uri))
            + if self.force_query || !self.query.is_empty() {
                1 + self.query.len()
            } else {
                0
            };
        ensure!(size <= CAP, "rewritten URI exceeds limit");
        let escaped = self.escaped();
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&escaped);
        if request_uri && out.is_empty() {
            out.push(b'/');
        }
        if self.force_query || !self.query.is_empty() {
            out.push(b'?');
            out.extend_from_slice(&self.query);
        }
        Ok(out)
    }
    // Mechanical HTTP URI storage remains valid UTF-8. Logical Go-string query
    // bytes live separately in State; illegal wire octets are percent encoded.
    pub fn target(&self, request_uri: bool) -> Result<String> {
        let mut out = self.escaped();
        if request_uri && out.is_empty() {
            out.push(b'/');
        }
        if self.force_query || !self.query.is_empty() {
            out.push(b'?');
            let mut input = &self.query[..];
            while !input.is_empty() {
                let valid = match std::str::from_utf8(input) {
                    Ok(_) => input.len(),
                    Err(e) => e.valid_up_to(),
                };
                for &b in &input[..valid] {
                    if b < 128 && !matches!(b,0x21|0x24..=0x3b|0x3d|0x3f..=0x7e) {
                        out.extend_from_slice(&[
                            b'%',
                            b"0123456789ABCDEF"[(b >> 4) as usize],
                            b"0123456789ABCDEF"[(b & 15) as usize],
                        ]);
                    } else {
                        out.push(b);
                    }
                }
                input = &input[valid..];
                if let Some((&b, rest)) = input.split_first() {
                    out.extend_from_slice(&[
                        b'%',
                        b"0123456789ABCDEF"[(b >> 4) as usize],
                        b"0123456789ABCDEF"[(b & 15) as usize],
                    ]);
                    input = rest;
                }
            }
        }
        ensure!(out.len() <= CAP, "rewritten URI exceeds limit");
        Ok(String::from_utf8(out)?)
    }
    pub fn bytes(&self) -> usize {
        self.path.len() + self.raw_path.len() + self.query.len() + self.fragment.len()
    }
    pub fn change(&mut self, mut f: impl FnMut(&[u8]) -> Result<Vec<u8>>) -> Result<()> {
        let raw = f(&self.escaped())?;
        let path = match decode(&raw) {
            Ok(p) if !p.is_empty() => p,
            _ => f(&self.path)?,
        };
        self.raw_path = if canonical_eq(&path, &raw) {
            Vec::new()
        } else {
            raw
        };
        self.path = path;
        Ok(())
    }
    fn canonicalize(&mut self) -> Result<()> {
        let mut path = self.path.clone();
        if !path.starts_with(b"/") {
            path.insert(0, b'/');
        }
        let path = decode(&clean(&encode(&path), false))?;
        if !self.raw_path.is_empty() {
            if !self.raw_path.starts_with(b"/") {
                self.raw_path.insert(0, b'/');
            }
            if !decode(&self.raw_path).is_ok_and(|p| p == path) || self.raw_path == encode(&path) {
                self.raw_path.clear();
            }
        }
        self.path = path;
        Ok(())
    }
    pub fn strip(&mut self, pattern: &[u8], suffix: bool) -> Result<()> {
        let mut prefix = Vec::new();
        let pattern = if !suffix && !pattern.starts_with(b"/") {
            prefix.push(b'/');
            prefix.extend_from_slice(pattern);
            &prefix[..]
        } else {
            pattern
        };
        let merge = !pattern.windows(2).any(|p| p == b"//");
        let mut stripped = false;
        self.change(|path| {
            let path = clean(path, merge);
            let trimmed = trim(&path, pattern, suffix);
            stripped |= trimmed.len() != path.len();
            Ok(trimmed.to_vec())
        })?;
        if stripped {
            self.canonicalize()?;
        }
        Ok(())
    }
}
fn equal_byte(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}
fn trim<'a>(path: &'a [u8], pattern: &[u8], suffix: bool) -> &'a [u8] {
    if suffix {
        let (mut i, mut j) = (path.len(), pattern.len());
        while i > 0 && j > 0 {
            let mut step = 1;
            let mut b = path[i - 1];
            if i >= 3 && path[i - 3] == b'%' && !(j >= 3 && pattern[j - 3] == b'%') {
                let Ok(v) = decode(&path[i - 3..i]) else {
                    return path;
                };
                b = v[0];
                step = 3;
            }
            if !equal_byte(b, pattern[j - 1]) {
                return path;
            }
            i -= step;
            j -= 1;
        }
        if j == 0 { &path[..i] } else { path }
    } else {
        let (mut i, mut j) = (0, 0);
        while i < path.len() && j < pattern.len() {
            let mut step = 1;
            let mut b = path[i];
            if b == b'%' && pattern[j] != b'%' && i + 3 <= path.len() {
                let Ok(v) = decode(&path[i..i + 3]) else {
                    return path;
                };
                b = v[0];
                step = 3;
            }
            if !equal_byte(b, pattern[j]) {
                return path;
            }
            i += step;
            j += 1;
        }
        if j == pattern.len() { &path[i..] } else { path }
    }
}
pub(super) fn regex(regex: &GoRegexp, input: &[u8], replacement: &[u8]) -> Result<Vec<u8>> {
    let replacement = Replacement::compile_bytes(regex, replacement.to_vec(), CAP)?;
    let mut budget = ReplaceBudget::new(
        regex
            .search_memory()
            .saturating_add(input.len().saturating_mul(32))
            .saturating_add(CAP),
        Some(Instant::now() + Duration::from_millis(150)),
    );
    Ok(regex.replace_all(input, &replacement, CAP, false, &mut budget)?)
}
pub(super) struct Query {
    pub rename: Vec<(Vec<u8>, Vec<u8>)>,
    pub set: Vec<(Vec<u8>, Vec<u8>)>,
    pub add: Vec<(Vec<u8>, Vec<u8>)>,
    pub replace: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Arc<GoRegexp>>)>,
    pub delete: Vec<Vec<u8>>,
}
pub(super) fn query(input: &[u8], ops: Query) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(150);
    let mut values = BTreeMap::<Vec<u8>, Vec<Vec<u8>>>::new();
    let mut total = 0usize;
    let check = |n: usize| -> Result<usize> {
        ensure!(n <= CAP, "query component limit exceeded");
        ensure!(
            Instant::now() < deadline,
            "query rewrite work limit exceeded"
        );
        Ok(n)
    };
    for part in input.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
        if let Some((k, v)) = super::query_match::query_pair(part) {
            let new_key = !values.contains_key(k.as_ref());
            total = check(total + v.len() + if new_key { k.len() } else { 0 })?;
            values
                .entry(k.into_owned())
                .or_default()
                .push(v.into_owned());
        }
    }
    for (k, v) in ops.rename {
        if k.is_empty() || v.is_empty() || k == v {
            continue;
        }
        if let Some(old) = values.remove(&k) {
            total -= k.len();
            if let Some(previous) = values.remove(&v) {
                total -= v.len() + previous.iter().map(Vec::len).sum::<usize>();
            }
            total = check(total + v.len())?;
            values.insert(v, old);
        }
    }
    for (k, v) in ops.set {
        if !k.is_empty() {
            if let Some(old) = values.remove(&k) {
                total -= k.len() + old.iter().map(Vec::len).sum::<usize>();
            }
            total = check(total + k.len() + v.len())?;
            values.insert(k, vec![v]);
        }
    }
    for (k, v) in ops.add {
        if !k.is_empty() {
            total = check(total + v.len() + if values.contains_key(&k) { 0 } else { k.len() })?;
            values.entry(k).or_default().push(v);
        }
    }
    let mut work = 64usize << 20;
    for (k, search, with, re) in ops.replace {
        let compiled = if let Some(re) = &re {
            Some(Replacement::compile_bytes(re, with.clone(), CAP)?)
        } else {
            None
        };
        for (key, vals) in &mut values {
            if k == b"*" || *key == k {
                for value in vals {
                    work = work
                        .checked_sub(value.len() + 1)
                        .ok_or_else(|| anyhow::anyhow!("query rewrite work limit exceeded"))?;
                    check(total)?;
                    let next = if let (Some(re), Some(compiled)) = (&re, &compiled) {
                        let mut budget = ReplaceBudget::new(
                            re.search_memory() + value.len() * 32 + CAP,
                            Some(deadline),
                        );
                        re.replace_all(value, compiled, CAP, false, &mut budget)?
                    } else {
                        replace(value, &search, &with, -1)?
                    };
                    total = check(total - value.len() + next.len())?;
                    *value = next;
                }
            }
        }
    }
    for k in ops.delete {
        check(total)?;
        if !k.is_empty() {
            values.remove(&k);
        }
    }
    let mut size = 0usize;
    for (k, vs) in &values {
        let key = escape_query(k)?;
        for v in vs {
            let value = escape_query(v)?;
            size = size
                .checked_add(key.len() + value.len() + 2)
                .filter(|n| *n <= CAP + 1)
                .ok_or_else(|| anyhow::anyhow!("query output limit exceeded"))?;
        }
    }
    let mut out = Vec::with_capacity(size.saturating_sub(1));
    for (k, vs) in values {
        let key = escape_query(&k)?;
        for v in vs {
            if !out.is_empty() {
                out.push(b'&');
            }
            out.extend_from_slice(&key);
            out.push(b'=');
            out.extend_from_slice(&escape_query(&v)?);
        }
    }
    Ok(out)
}
