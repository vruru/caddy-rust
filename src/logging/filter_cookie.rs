// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
// Cookie parsing follows Go's net/http (Copyright The Go Authors, BSD-3-Clause).
//! Cookie filters operate only on Caddy's special string-array marshaler.
//! Set-Cookie keeps the original attribute suffix, including invalid attributes.
use super::{bounded::Buffer, config, types::FieldValue};
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(super) enum ActionKind {
    Replace,
    Hash,
    Delete,
}
pub(super) struct Action {
    pub kind: ActionKind,
    pub name: String,
    pub value: String,
}
pub(super) fn actions(value: Option<Value>, name_key: &str) -> Result<Vec<Action>> {
    let values = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        _ => bail!("log filter actions must be an array"),
    };
    let mut output = Vec::new();
    output
        .try_reserve_exact(values.len())
        .map_err(|_| anyhow!("log filter action allocation failed"))?;
    for value in values {
        let mut map = match value {
            Value::Object(map) => map,
            Value::Null => Map::new(),
            _ => bail!("log filter action must be an object"),
        };
        crate::http_config::helpers::deny_unknown(
            &map,
            &["type", name_key, "value"],
            "/logging/filter/actions",
        )?;
        let kind = match config::string(map.remove("type"))?.as_str() {
            "replace" => ActionKind::Replace,
            "hash" => ActionKind::Hash,
            "delete" => ActionKind::Delete,
            _ => bail!("invalid log filter action type"),
        };
        output.push(Action {
            kind,
            name: config::string(map.remove(name_key))?,
            value: config::string(map.remove("value"))?,
        });
    }
    Ok(output)
}
pub(super) enum Cookie {
    Request {
        actions: Vec<Action>,
        max_count: i64,
    },
    Response {
        actions: Vec<Action>,
    },
}
impl Cookie {
    pub(super) fn from_module(name: &str, mut fields: Map<String, Value>) -> Option<Result<Self>> {
        if !matches!(name, "cookie" | "set_cookie") {
            return None;
        }
        Some((|| {
            crate::http_config::helpers::deny_unknown(&fields, &["actions"], "/logging/filter")?;
            let actions = actions(fields.remove("actions"), "name")?;
            Ok(if name == "cookie" {
                Self::Request {
                    actions,
                    max_count: godebug_i64("httpcookiemaxnum").unwrap_or(3000),
                }
            } else {
                Self::Response { actions }
            })
        })())
    }
    pub(super) fn apply(&self, value: &FieldValue, limit: usize) -> Result<Option<FieldValue>> {
        let FieldValue::StringArray(lines) = value else {
            return Ok(None);
        };
        Ok(Some(FieldValue::StringArray(match self {
            Self::Request { actions, max_count } => request(lines, actions, *max_count, limit)?,
            Self::Response { actions } => response(lines, actions, limit)?,
        })))
    }
}
pub(super) fn godebug_value(key: &str) -> Option<String> {
    let raw = std::env::var_os("GODEBUG")?;
    let value = raw
        .as_encoded_bytes()
        .split(|b| *b == b',')
        .rev()
        .find_map(|entry| {
            let equal = entry.iter().position(|b| *b == b'=')?;
            (entry[..equal] == *key.as_bytes()).then_some(&entry[equal + 1..])
        })?;
    std::str::from_utf8(value).ok().map(str::to_owned)
}
pub(super) fn godebug_i64(key: &str) -> Option<i64> {
    // The rightmost setting wins even when malformed; malformed uses default.
    godebug_value(key).and_then(|value| value.parse().ok())
}
pub(super) fn hash(value: &[u8]) -> [u8; 8] {
    let digest = Sha256::digest(value);
    let mut bytes = [0; 8];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in digest[..4].iter().enumerate() {
        bytes[i * 2] = HEX[(b >> 4) as usize];
        bytes[i * 2 + 1] = HEX[(b & 15) as usize];
    }
    bytes
}
fn request(
    lines: &[Vec<u8>],
    actions: &[Action],
    max_count: i64,
    limit: usize,
) -> Result<Vec<Vec<u8>>> {
    let count = lines
        .iter()
        .try_fold(0usize, |n, line| {
            n.checked_add(line.iter().filter(|b| **b == b';').count())?
                .checked_add(1)
        })
        .ok_or_else(|| anyhow!("log cookie count overflow"))?;
    if max_count != 0 && (max_count < 0 || count > max_count as usize) {
        return Ok(Vec::new());
    }
    let overhead = std::mem::size_of::<Vec<u8>>();
    // Empty output allocates no array storage. The first surviving cookie needs
    // one Vec slot; no collection of all parsed cookies is ever allocated.
    let mut output = Buffer::new(limit.saturating_sub(overhead));
    let mut any = false;
    for line in lines {
        for part in trim_ascii(line).split(|b| *b == b';') {
            let part = trim_ascii(part);
            if part.is_empty() {
                continue;
            }
            let eq = part.iter().position(|b| *b == b'=');
            let (name, value) = eq.map_or((part, &b""[..]), |i| (&part[..i], &part[i + 1..]));
            let name = trim_ascii(name);
            if !token(name) {
                continue;
            }
            let Some((value, quoted)) = parse_value(value) else {
                continue;
            };
            let action = actions.iter().find(|a| a.name.as_bytes() == name);
            if action.is_some_and(|a| matches!(a.kind, ActionKind::Delete)) {
                continue;
            }
            ensure!(
                limit >= overhead,
                super::bounded::ByteLimit("log filtered cookie byte limit exceeded")
            );
            if any {
                output.bytes(b"; ")?;
            }
            any = true;
            output.bytes(name)?;
            output.byte(b'=')?;
            let hashed;
            let replacement = match action {
                Some(Action {
                    kind: ActionKind::Replace,
                    value,
                    ..
                }) => value.as_bytes(),
                Some(Action {
                    kind: ActionKind::Hash,
                    ..
                }) => {
                    hashed = hash(value);
                    &hashed
                }
                _ => value,
            };
            let quote = quoted
                || replacement
                    .iter()
                    .any(|b| valid_value(*b) && matches!(*b, b' ' | b','));
            if quote {
                output.byte(b'"')?;
            }
            for byte in replacement.iter().copied().filter(|b| valid_value(*b)) {
                output.byte(byte)?;
            }
            if quote {
                output.byte(b'"')?;
            }
        }
    }
    if !any {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(1)
        .map_err(|_| anyhow!("log cookie array allocation failed"))?;
    values.push(output.into_vec());
    Ok(values)
}
fn response(lines: &[Vec<u8>], actions: &[Action], limit: usize) -> Result<Vec<Vec<u8>>> {
    let kept = lines
        .iter()
        .filter(|line| {
            let parsed = parse_set_cookie(line);
            !parsed
                .as_ref()
                .and_then(|(name, _, _)| actions.iter().find(|a| a.name.as_bytes() == *name))
                .is_some_and(|a| matches!(a.kind, ActionKind::Delete))
        })
        .count();
    let overhead = kept
        .checked_mul(std::mem::size_of::<Vec<u8>>())
        .filter(|n| *n <= limit)
        .ok_or(super::bounded::ByteLimit(
            "log cookie array byte limit exceeded",
        ))?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(kept)
        .map_err(|_| anyhow!("log cookie array allocation failed"))?;
    let mut remaining = limit - overhead;
    for line in lines {
        let parsed = parse_set_cookie(line);
        let action = parsed
            .as_ref()
            .and_then(|(name, _, _)| actions.iter().find(|a| a.name.as_bytes() == *name));
        if action.is_some_and(|a| matches!(a.kind, ActionKind::Delete)) {
            continue;
        }

        let mut output = Buffer::new(remaining);
        if let (Some((name, value, quoted)), Some(action)) = (parsed, action) {
            let head_end = line.iter().position(|b| *b == b';').unwrap_or(line.len());
            let head = &line[..head_end];
            let eq = head
                .iter()
                .position(|b| *b == b'=')
                .ok_or_else(|| anyhow!("log cookie parse invariant"))?;
            // ParseSetCookie trims ASCII whitespace; the source replacement uses
            // Unicode TrimSpace for the raw first segment and value edges.
            if trim_unicode(&head[..eq]) != name {
                output.bytes(line)?;
            } else {
                let raw = &head[eq + 1..];
                let trimmed = trim_unicode(raw);
                let leading = unicode_start(raw);
                let trailing = unicode_end(raw);
                output.bytes(&line[..eq + 1])?;
                output.bytes(&raw[..leading])?;
                let quotes = quoted
                    && trimmed.len() >= 2
                    && trimmed.first() == Some(&b'"')
                    && trimmed.last() == Some(&b'"');
                if quotes {
                    output.byte(b'"')?;
                }
                match action.kind {
                    ActionKind::Replace => output.bytes(action.value.as_bytes())?,
                    ActionKind::Hash => output.bytes(&hash(value))?,
                    ActionKind::Delete => unreachable!(),
                }
                if quotes {
                    output.byte(b'"')?;
                }
                output.bytes(&raw[raw.len() - trailing..])?;
                output.bytes(&line[head_end..])?;
            }
        } else {
            output.bytes(line)?;
        }
        let bytes = output.into_vec();
        remaining -= bytes.len();
        values.push(bytes);
    }
    Ok(values)
}
fn parse_set_cookie(line: &[u8]) -> Option<(&[u8], &[u8], bool)> {
    let line = trim_ascii(line);
    let head = trim_ascii(line.split(|b| *b == b';').next()?);
    let eq = head.iter().position(|b| *b == b'=')?;
    let name = trim_ascii(&head[..eq]);
    if !token(name) {
        return None;
    }
    let (value, quoted) = parse_value(&head[eq + 1..])?;
    Some((name, value, quoted))
}
fn parse_value(mut value: &[u8]) -> Option<(&[u8], bool)> {
    let quoted = value.len() > 1 && value.first() == Some(&b'"') && value.last() == Some(&b'"');
    if quoted {
        value = &value[1..value.len() - 1];
    }
    value
        .iter()
        .all(|b| valid_value(*b))
        .then_some((value, quoted))
}
fn valid_value(b: u8) -> bool {
    (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b';' | b'\\')
}
fn token(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}
fn trim_ascii(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && matches!(value[start], b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(value[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &value[start..end]
}
fn unicode_start(value: &[u8]) -> usize {
    let Ok(s) = std::str::from_utf8(value) else {
        return 0;
    };
    s.len() - s.trim_start_matches(char::is_whitespace).len()
}
fn unicode_end(value: &[u8]) -> usize {
    let Ok(s) = std::str::from_utf8(value) else {
        return 0;
    };
    s.len() - s.trim_end_matches(char::is_whitespace).len()
}
fn trim_unicode(value: &[u8]) -> &[u8] {
    let start = unicode_start(value);
    let end = value.len() - unicode_end(value);
    if start >= end {
        &value[..0]
    } else {
        &value[start..end]
    }
}
