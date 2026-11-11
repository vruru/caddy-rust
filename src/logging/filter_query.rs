// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
// URL semantics derived from Go net/url, Copyright The Go Authors, BSD-3-Clause.
//! Query filtering uses Go URL parsing/serialization, not browser URL resolution.
//! Relative/opaque URLs and escaped raw paths retain their original semantics.
use super::{
    bounded::Buffer,
    filter_cookie::{self, Action, ActionKind},
    types::FieldValue,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
pub(super) struct Query {
    actions: Vec<Action>,
    max_params: Option<i64>,
    strict_colons: bool,
}
impl Query {
    pub(super) fn from_module(name: &str, mut fields: Map<String, Value>) -> Option<Result<Self>> {
        if name != "query" {
            return None;
        }
        Some((|| {
            crate::http_config::helpers::deny_unknown(
                &fields,
                &["actions"],
                "/logging/filter/query",
            )?;
            Ok(Self {
                actions: filter_cookie::actions(fields.remove("actions"), "parameter")?,
                max_params: filter_cookie::godebug_i64("urlmaxqueryparams"),
                strict_colons: filter_cookie::godebug_value("urlstrictcolons").as_deref()
                    != Some("0"),
            })
        })())
    }
    pub(super) fn apply(&self, value: &FieldValue, limit: usize) -> Result<Option<FieldValue>> {
        Ok(match value {
            FieldValue::String(s) => Some(FieldValue::RawString(self.string(s.as_bytes(), limit)?)),
            FieldValue::RawString(s) => Some(FieldValue::RawString(self.string(s, limit)?)),
            FieldValue::StringArray(values) => {
                let overhead = values
                    .len()
                    .checked_mul(std::mem::size_of::<Vec<u8>>())
                    .filter(|n| *n <= limit)
                    .ok_or(super::bounded::ByteLimit(
                        "log query array byte limit exceeded",
                    ))?;
                let mut remaining = limit - overhead;
                let mut output = Vec::new();
                output
                    .try_reserve_exact(values.len())
                    .map_err(|_| anyhow!("log query array allocation failed"))?;
                for value in values {
                    let s = self.string(value, remaining)?;
                    remaining -= s.len();
                    output.push(s);
                }
                Some(FieldValue::StringArray(output))
            }
            _ => None,
        })
    }
    fn string(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let Some(parts) = Parts::parse(input, self.strict_colons, limit)? else {
            let mut out = Buffer::new(limit);
            out.bytes(input)?;
            return Ok(out.into_vec());
        };
        let mut values: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
        let mut used = 0usize;
        let count = parts
            .query
            .iter()
            .filter(|b| **b == b'&')
            .count()
            .saturating_add(1);
        let allowed = self
            .max_params
            .map_or(count <= 10000, |n| n == 0 || (n > 0 && count < n as usize));
        if allowed {
            for pair in parts
                .query
                .split(|b| *b == b'&')
                .filter(|p| !p.is_empty() && !p.contains(&b';'))
            {
                let (key, value) = cut(pair, b'=');
                if !valid_escapes(key) || !valid_escapes(value) {
                    continue;
                }
                let size = key
                    .len()
                    .checked_add(value.len())
                    .and_then(|n| n.checked_add(128))
                    .ok_or_else(|| anyhow!("log query workspace size overflow"))?;
                ensure!(
                    used.checked_add(size).is_some_and(|n| n <= limit),
                    super::bounded::ByteLimit("log query workspace byte limit exceeded")
                );
                let k = decode(key, Mode::Query, limit)?;
                let v = decode(value, Mode::Query, limit)?;
                // BTree node/key/value-vector overhead is charged conservatively before
                // either decode/allocation. Duplicate query values remain in input order.
                used += size;
                let slot = values.entry(k).or_default();
                slot.try_reserve(1)
                    .map_err(|_| anyhow!("log query value allocation failed"))?;
                slot.push(v);
            }
        }
        for action in &self.actions {
            match action.kind {
                ActionKind::Delete => {
                    values.remove(action.name.as_bytes());
                }
                ActionKind::Replace | ActionKind::Hash => {
                    if let Some(items) = values.get_mut(action.name.as_bytes()) {
                        for item in items {
                            let new_len = match action.kind {
                                ActionKind::Replace => action.value.len(),
                                _ => 8,
                            };
                            used = used.checked_add(new_len).filter(|n| *n <= limit).ok_or(
                                super::bounded::ByteLimit(
                                    "log query replacement workspace byte limit exceeded",
                                ),
                            )?;
                            *item = match action.kind {
                                ActionKind::Replace => {
                                    let mut out = Buffer::new(new_len);
                                    out.bytes(action.value.as_bytes())?;
                                    out.into_vec()
                                }
                                _ => filter_cookie::hash(item).to_vec(),
                            };
                        }
                    }
                }
            }
        }
        let mut query = Buffer::new(limit);
        for (key, items) in values {
            for value in items {
                if !query.as_slice().is_empty() {
                    query.byte(b'&')?;
                }
                escaped(&mut query, &key, Mode::Query)?;
                query.byte(b'=')?;
                escaped(&mut query, &value, Mode::Query)?;
            }
        }
        parts.render(query.as_slice(), limit)
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Path,
    Host,
    Zone,
    User,
    Query,
    Fragment,
}
struct Parts<'a> {
    scheme: &'a [u8],
    opaque: Option<&'a [u8]>,
    user: Option<(&'a [u8], Option<&'a [u8]>)>,
    host: Vec<u8>,
    path: &'a [u8],
    query: &'a [u8],
    fragment: &'a [u8],
    force_query: bool,
    omit_host: bool,
}
impl<'a> Parts<'a> {
    fn parse(input: &'a [u8], strict: bool, limit: usize) -> Result<Option<Self>> {
        let (body, fragment) = cut(input, b'#');
        if body.iter().any(|b| *b < 0x20 || *b == 0x7f) {
            return Ok(None);
        }
        let mut scheme = &b""[..];
        let mut rest = body;
        for (i, b) in body.iter().enumerate() {
            if b.is_ascii_alphabetic() {
                continue;
            }
            if b.is_ascii_digit() || b"+-.".contains(b) {
                if i == 0 {
                    break;
                }
                continue;
            }
            if *b == b':' {
                if i == 0 {
                    return Ok(None);
                }
                scheme = &body[..i];
                rest = &body[i + 1..];
            }
            break;
        }
        let force_query =
            rest.last() == Some(&b'?') && rest.iter().filter(|b| **b == b'?').count() == 1;
        let query;
        if force_query {
            rest = &rest[..rest.len() - 1];
            query = &b""[..];
        } else {
            (rest, query) = cut(rest, b'?');
        }
        if !valid_escapes(fragment) {
            return Ok(None);
        }
        let mut parts = Self {
            scheme,
            opaque: None,
            user: None,
            host: Vec::new(),
            path: &[],
            query,
            fragment,
            force_query,
            omit_host: false,
        };
        if !rest.starts_with(b"/") {
            if !scheme.is_empty() {
                parts.opaque = Some(rest);
                return Ok(Some(parts));
            }
            if rest
                .split(|b| *b == b'/')
                .next()
                .is_some_and(|s| s.contains(&b':'))
            {
                return Ok(None);
            }
        }
        if (!scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
            let (authority, path) = split_at(rest.get(2..).unwrap_or_default(), b'/');
            rest = path;
            let mut host = authority;
            if let Some(at) = authority.iter().rposition(|b| *b == b'@') {
                host = &authority[at + 1..];
                let user = &authority[..at];
                if user
                    .iter()
                    .any(|b| !b.is_ascii_alphanumeric() && !b"-._:~!$&'()*+,;=%@".contains(b))
                {
                    return Ok(None);
                }
                let (username, password) = if let Some(colon) = user.iter().position(|b| *b == b':')
                {
                    (&user[..colon], Some(&user[colon + 1..]))
                } else {
                    (user, None)
                };
                if !valid_escapes(username) || password.is_some_and(|p| !valid_escapes(p)) {
                    return Ok(None);
                }
                parts.user = Some((username, password));
            }
            let Some(decoded) = parse_host(host, scheme, strict, limit)? else {
                return Ok(None);
            };
            parts.host = decoded;
        } else if !scheme.is_empty() && rest.starts_with(b"/") {
            parts.omit_host = true;
        }
        if !valid_escapes(rest) {
            return Ok(None);
        }
        parts.path = rest;
        Ok(Some(parts))
    }
    fn render(&self, query: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Buffer::new(limit);
        if !self.scheme.is_empty() {
            for b in self.scheme {
                out.byte(b.to_ascii_lowercase())?;
            }
            out.byte(b':')?;
        }
        if let Some(opaque) = self.opaque.filter(|s| !s.is_empty()) {
            out.bytes(opaque)?;
        } else {
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && !(self.omit_host && self.host.is_empty() && self.user.is_none())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    out.bytes(b"//")?;
                }
                if let Some((user, password)) = self.user {
                    escape_decoded(&mut out, user, Mode::User)?;
                    if let Some(password) = password {
                        out.byte(b':')?;
                        escape_decoded(&mut out, password, Mode::User)?;
                    }
                    out.byte(b'@')?;
                }
                escaped(&mut out, &self.host, Mode::Host)?;
            }
            let mut path = Buffer::new(out.remaining());
            escaped_raw(&mut path, self.path, Mode::Path)?;
            let mut path = path.as_slice();
            if self.omit_host
                && self.host.is_empty()
                && self.user.is_none()
                && path.starts_with(b"//")
            {
                out.bytes(b"%2F")?;
                path = &path[1..];
            }
            if !path.is_empty() && path[0] != b'/' && !self.host.is_empty() {
                out.byte(b'/')?;
            }
            if out.as_slice().is_empty()
                && path
                    .split(|b| *b == b'/')
                    .next()
                    .is_some_and(|p| p.contains(&b':'))
            {
                out.bytes(b"./")?;
            }
            out.bytes(path)?;
        }
        if self.force_query || !query.is_empty() {
            out.byte(b'?')?;
            out.bytes(query)?;
        }
        if !self.fragment.is_empty() {
            out.byte(b'#')?;
            escaped_raw(&mut out, self.fragment, Mode::Fragment)?;
        }
        Ok(out.into_vec())
    }
}
fn parse_host(raw: &[u8], scheme: &[u8], strict: bool, limit: usize) -> Result<Option<Vec<u8>>> {
    let open = raw.iter().rposition(|b| *b == b'[');
    if open.is_some_and(|i| i > 0) {
        return Ok(None);
    }
    if open == Some(0) {
        let Some(end) = raw.iter().rposition(|b| *b == b']') else {
            return Ok(None);
        };
        let port = &raw[end + 1..];
        if !optional_port(port) {
            return Ok(None);
        }
        let hostname = &raw[1..end];
        let mut output = Buffer::new(limit);
        output.byte(b'[')?;
        if let Some(zone) = hostname.windows(3).position(|s| s == b"%25") {
            if !valid_host(hostname.get(..zone).unwrap_or_default(), Mode::Host)
                || !valid_host(&hostname[zone..], Mode::Zone)
            {
                return Ok(None);
            }
            decoded_into(&mut output, &hostname[..zone], Mode::Host)?;
            decoded_into(&mut output, &hostname[zone..], Mode::Zone)?;
        } else {
            if !valid_host(hostname, Mode::Host) {
                return Ok(None);
            }
            decoded_into(&mut output, hostname, Mode::Host)?;
        }
        let text = &output.as_slice()[1..];
        let ip = text.split(|b| *b == b'%').next().unwrap_or_default();
        if std::str::from_utf8(ip)
            .ok()
            .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok())
            .is_none()
        {
            return Ok(None);
        }
        if text.iter().position(|b| *b == b'%') == Some(text.len().saturating_sub(1)) {
            return Ok(None);
        }
        output.byte(b']')?;
        if !valid_host(port, Mode::Host) {
            return Ok(None);
        }
        decoded_into(&mut output, port, Mode::Host)?;
        return Ok(Some(output.into_vec()));
    }
    if let Some(first) = raw.iter().position(|b| *b == b':') {
        let last = raw.iter().rposition(|b| *b == b':').unwrap_or(first);
        let i = if strict
            && (scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"https"))
        {
            first
        } else {
            last
        };
        if !optional_port(&raw[i..]) {
            return Ok(None);
        }
    }
    if !valid_host(raw, Mode::Host) {
        return Ok(None);
    }
    Ok(Some(decode(raw, Mode::Host, limit)?))
}
fn optional_port(port: &[u8]) -> bool {
    port.is_empty() || port[0] == b':' && port[1..].iter().all(u8::is_ascii_digit)
}
fn cut(input: &[u8], byte: u8) -> (&[u8], &[u8]) {
    input
        .iter()
        .position(|b| *b == byte)
        .map_or((input, &[]), |i| (&input[..i], &input[i + 1..]))
}
fn split_at(input: &[u8], byte: u8) -> (&[u8], &[u8]) {
    input
        .iter()
        .position(|b| *b == byte)
        .map_or((input, &[]), |i| (&input[..i], &input[i..]))
}
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
fn valid_escapes(input: &[u8]) -> bool {
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            if i + 2 >= input.len() || hex(input[i + 1]).is_none() || hex(input[i + 2]).is_none() {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}
fn valid_host(input: &[u8], mode: Mode) -> bool {
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' {
            if i + 2 >= input.len() {
                return false;
            }
            let (Some(a), Some(b)) = (hex(input[i + 1]), hex(input[i + 2])) else {
                return false;
            };
            let n = a * 16 + b;
            if matches!(mode, Mode::Host) && n < 128 && &input[i..i + 3] != b"%25" {
                return false;
            }
            if matches!(mode, Mode::Zone)
                && n != b' '
                && &input[i..i + 3] != b"%25"
                && should_escape(n, Mode::Host)
            {
                return false;
            }
            i += 3;
        } else {
            if b < 128 && should_escape(b, mode) {
                return false;
            }
            i += 1;
        }
    }
    true
}
fn decode(input: &[u8], mode: Mode, limit: usize) -> Result<Vec<u8>> {
    let mut out = Buffer::new(limit);
    decoded_into(&mut out, input, mode)?;
    Ok(out.into_vec())
}
fn decoded_into(out: &mut Buffer, input: &[u8], mode: Mode) -> Result<()> {
    let mut i = 0;
    while i < input.len() {
        let byte = if input[i] == b'%' {
            let n = hex(input[i + 1]).ok_or_else(|| anyhow!("URL percent invariant"))? * 16
                + hex(input[i + 2]).ok_or_else(|| anyhow!("URL percent invariant"))?;
            i += 3;
            n
        } else {
            let b = input[i];
            i += 1;
            if b == b'+' && matches!(mode, Mode::Query) {
                b' '
            } else {
                b
            }
        };
        out.byte(byte)?;
    }
    Ok(())
}
fn should_escape(b: u8, mode: Mode) -> bool {
    if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone) && b"!$&'()*+,;=:[]<>\"".contains(&b) {
        return false;
    }
    if b"$&+,/:;=?@".contains(&b) {
        return match mode {
            Mode::Path => b == b'?',
            Mode::User => b"@/?:".contains(&b),
            Mode::Query => true,
            Mode::Fragment => false,
            _ => true,
        };
    }
    if matches!(mode, Mode::Fragment) && b"!()*".contains(&b) {
        return false;
    }
    true
}
fn escaped(out: &mut Buffer, input: &[u8], mode: Mode) -> Result<()> {
    for b in input {
        escape_byte(out, *b, mode)?;
    }
    Ok(())
}
fn escape_byte(out: &mut Buffer, b: u8, mode: Mode) -> Result<()> {
    if !should_escape(b, mode) {
        out.byte(b)
    } else if b == b' ' && matches!(mode, Mode::Query) {
        out.byte(b'+')
    } else {
        const H: &[u8; 16] = b"0123456789ABCDEF";
        out.bytes(&[b'%', H[(b >> 4) as usize], H[(b & 15) as usize]])
    }
}
fn escape_decoded(out: &mut Buffer, input: &[u8], mode: Mode) -> Result<()> {
    let mut i = 0;
    while i < input.len() {
        let b = if input[i] == b'%' {
            let n = hex(input[i + 1]).unwrap() * 16 + hex(input[i + 2]).unwrap();
            i += 3;
            n
        } else {
            let n = input[i];
            i += 1;
            n
        };
        escape_byte(out, b, mode)?;
    }
    Ok(())
}
fn escaped_raw(out: &mut Buffer, input: &[u8], mode: Mode) -> Result<()> {
    if input
        .iter()
        .all(|b| b"!$&'()*+,;=:@[]%".contains(b) || !should_escape(*b, mode))
    {
        out.bytes(input)
    } else {
        escape_decoded(out, input, mode)
    }
}
