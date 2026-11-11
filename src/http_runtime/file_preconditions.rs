//! Conditional file representation requests, including precompressed sidecars.
//! Behavioral reference: Go 1.27.3 net/http/fs.go, BSD-3-Clause.
use http::{HeaderMap, Method, StatusCode, header};
use std::time::SystemTime;

pub(super) fn evaluate(
    headers: &HeaderMap,
    method: &Method,
    etag: &[u8],
    modified: SystemTime,
    useful: bool,
) -> Option<StatusCode> {
    let safe = matches!(*method, Method::GET | Method::HEAD);
    if let Some(tags) = nonempty(headers, header::IF_MATCH) {
        if !includes(tags, etag, true) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if useful
        && date(headers, header::IF_UNMODIFIED_SINCE)
            .is_some_and(|t| super::files::seconds(modified) > super::files::seconds(t))
    {
        return Some(StatusCode::PRECONDITION_FAILED);
    }
    let not_modified = if let Some(tags) = nonempty(headers, header::IF_NONE_MATCH) {
        includes(tags, etag, false)
    } else {
        safe && useful
            && date(headers, header::IF_MODIFIED_SINCE)
                .is_some_and(|t| super::files::seconds(modified) <= super::files::seconds(t))
    };
    not_modified.then_some(if safe {
        StatusCode::NOT_MODIFIED
    } else {
        StatusCode::PRECONDITION_FAILED
    })
}

pub(super) fn range_allowed(
    headers: &HeaderMap,
    method: &Method,
    etag: &[u8],
    modified: SystemTime,
    useful: bool,
) -> bool {
    let Some(value) = nonempty(headers, header::IF_RANGE) else {
        return true;
    };
    if !matches!(*method, Method::GET | Method::HEAD) {
        return true;
    }
    if let Some((tag, _)) = scan(value) {
        return tag.first() == Some(&b'"') && tag == etag;
    }
    useful
        && date(headers, header::IF_RANGE)
            .is_some_and(|t| super::files::seconds(modified) == super::files::seconds(t))
}

fn date(headers: &HeaderMap, name: http::HeaderName) -> Option<SystemTime> {
    httpdate::parse_http_date(headers.get(name)?.to_str().ok()?).ok()
}

fn nonempty(headers: &HeaderMap, name: http::HeaderName) -> Option<&[u8]> {
    let value = headers.get(name)?.as_bytes();
    (!value.is_empty()).then_some(value)
}

fn includes(mut list: &[u8], current: &[u8], strong: bool) -> bool {
    loop {
        list = trim_space(list);
        match list.first() {
            Some(b'*') => return true,
            Some(b',') => list = &list[1..],
            _ => {
                let Some((tag, rest)) = scan(list) else {
                    return false;
                };
                let hit = if strong {
                    tag.first() == Some(&b'"') && tag == current
                } else {
                    strip_weak(tag) == strip_weak(current)
                };
                if hit {
                    return true;
                }
                list = rest;
            }
        }
    }
}

fn strip_weak(tag: &[u8]) -> &[u8] {
    tag.strip_prefix(b"W/").unwrap_or(tag)
}

fn scan(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let raw = trim_space(raw);
    let begin = usize::from(raw.starts_with(b"W/")) * 2;
    if raw.get(begin) != Some(&b'"') {
        return None;
    }
    for (i, &c) in raw.iter().enumerate().skip(begin + 1) {
        match c {
            b'"' => return Some(raw.split_at(i + 1)),
            0x21 | 0x23..=0x7e | 0x80..=0xff => {}
            _ => return None,
        }
    }
    None
}

fn trim_space(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        bytes = &bytes[1..];
    }
    bytes
}
