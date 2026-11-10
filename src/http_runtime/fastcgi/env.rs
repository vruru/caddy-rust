// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Unix CGI environment semantics. Filesystem canonicalization, when enabled,
//! belongs to the caller's bounded metadata worker before environment building.
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub struct SplitPath(Vec<Vec<u8>>);

impl SplitPath {
    pub fn new(patterns: &[String]) -> io::Result<Self> {
        if patterns.iter().any(|pattern| !pattern.is_ascii()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FastCGI split path must be ASCII",
            ));
        }
        Ok(Self(
            patterns
                .iter()
                .map(|pattern| pattern.to_ascii_lowercase().into_bytes())
                .collect(),
        ))
    }
    fn position(&self, path: &[u8]) -> Option<usize> {
        if self.0.is_empty() {
            return Some(0);
        }
        self.0
            .iter()
            .filter(|pattern| !pattern.is_empty())
            .find_map(|pattern| {
                path.windows(pattern.len())
                    .position(|slice| slice.eq_ignore_ascii_case(pattern))
                    .map(|position| position + pattern.len())
            })
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a [u8],
    pub original_uri: &'a [u8],
    pub query: &'a [u8],
    pub host: &'a [u8],
    pub protocol: &'a str,
    pub software: &'a str,
    pub remote: SocketAddr,
    pub local: SocketAddr,
    pub tls: Option<(&'a str, &'a str)>,
    pub authenticated_user: &'a [u8],
    pub remainder: &'a [u8],
    pub headers: &'a http::HeaderMap,
    pub content_length: Option<u64>,
}

#[derive(Debug)]
pub enum Error {
    InvalidPath,
    LengthRequired,
}

/// The root is a trusted absolute Unix path; the untrusted request can only
/// supply a lexical path beneath it. Never resolve script paths or open files.
fn sanitized_path(root: &Path, path: &[u8]) -> Vec<u8> {
    let mut parts = Vec::new();
    for part in path.split(|byte| *byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let mut output = PathBuf::from(root);
    for part in parts {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            output.push(std::ffi::OsStr::from_bytes(part));
        }
        #[cfg(not(unix))]
        output.push(String::from_utf8_lossy(part).as_ref());
    }
    let mut output = output.into_os_string().as_encoded_bytes().to_vec();
    if path.len() > 1 && path.ends_with(b"/") {
        output.push(b'/');
    }
    output
}

fn host_port(host: &[u8]) -> (&[u8], Option<&[u8]>) {
    if host.starts_with(b"[") {
        if let Some(end) = host.iter().position(|b| *b == b']')
            && let Some(port) = host.get(end + 1..).and_then(|rest| rest.strip_prefix(b":"))
            && !port.contains(&b':')
        {
            return (&host[1..end], Some(port));
        }
    } else if let Some(colon) = host.iter().position(|b| *b == b':')
        && !host[colon + 1..].contains(&b':')
    {
        return (&host[..colon], Some(&host[colon + 1..]));
    }
    (host, None)
}

pub fn build(
    root: &Path,
    split: &SplitPath,
    request: &Request<'_>,
    overrides: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    if request.path.contains(&0)
        || !root.is_absolute()
        || root.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(Error::InvalidPath);
    }
    let (script, mut info) = split
        .position(request.path)
        .map_or((request.path, &b""[..]), |n| request.path.split_at(n));
    if info.is_empty() {
        info = request.remainder;
    }
    if info.contains(&0) {
        return Err(Error::InvalidPath);
    }
    let script_file = sanitized_path(root, script);
    let mut script_name = script.to_vec();
    if !script.is_empty() && !script.starts_with(b"/") {
        script_name.insert(0, b'/');
    }
    let secure = request.tls.is_some();
    let (host, port) = host_port(request.host);
    let remote_ip = request.remote.ip().to_string();
    let remote_port = request.remote.port().to_string();
    let local_ip = request.local.ip().to_string();
    let mut values: BTreeMap<String, Vec<u8>> = [
        ("AUTH_TYPE", &b""[..]),
        (
            "CONTENT_TYPE",
            request
                .headers
                .get(http::header::CONTENT_TYPE)
                .map_or(b"", http::HeaderValue::as_bytes),
        ),
        ("GATEWAY_INTERFACE", b"CGI/1.1"),
        ("PATH_INFO", info),
        ("QUERY_STRING", request.query),
        ("REMOTE_ADDR", remote_ip.as_bytes()),
        ("REMOTE_HOST", remote_ip.as_bytes()),
        ("REMOTE_PORT", remote_port.as_bytes()),
        ("REMOTE_IDENT", b""),
        ("REMOTE_USER", request.authenticated_user),
        ("REQUEST_SCHEME", if secure { b"https" } else { b"http" }),
        ("SERVER_NAME", host),
        ("SERVER_PROTOCOL", request.protocol.as_bytes()),
        ("SERVER_SOFTWARE", request.software.as_bytes()),
        ("DOCUMENT_ROOT", root.as_os_str().as_encoded_bytes()),
        ("DOCUMENT_URI", script),
        ("HTTP_HOST", request.host),
        ("REQUEST_URI", request.original_uri),
        ("SCRIPT_FILENAME", &script_file),
        ("SCRIPT_NAME", &script_name),
        ("SERVER_ADDR", local_ip.as_bytes()),
        (
            "SERVER_PORT",
            port.filter(|p| !p.is_empty())
                .unwrap_or(if secure { b"443" } else { b"80" }),
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_vec()))
    .collect();
    if !info.is_empty() {
        values.insert("PATH_TRANSLATED".into(), sanitized_path(root, info));
    }
    if let Some((version, cipher)) = request.tls {
        values.insert("HTTPS".into(), b"on".to_vec());
        if !version.is_empty() {
            values.insert("SSL_PROTOCOL".into(), version.as_bytes().to_vec());
        }
        if !cipher.is_empty() {
            values.insert("SSL_CIPHER".into(), cipher.as_bytes().to_vec());
        }
    }
    values.extend(
        overrides
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    for name in request.headers.keys() {
        if name.as_str() == "proxy" {
            continue;
        }
        let key = format!(
            "HTTP_{}",
            name.as_str().replace('-', "_").to_ascii_uppercase()
        );
        let mut joined = Vec::new();
        for (i, value) in request.headers.get_all(name).iter().enumerate() {
            if i > 0 {
                joined.extend_from_slice(b", ");
            }
            joined.extend_from_slice(value.as_bytes());
        }
        values.insert(key, joined);
    }
    let bodyless = matches!(request.method, "HEAD" | "OPTIONS");
    let length = if bodyless {
        0
    } else {
        request.content_length.ok_or(Error::LengthRequired)?
    };
    let mut method = request.method.to_ascii_uppercase();
    if method.is_empty() || method == "GET" && request.method != "GET" {
        method = "POST".into();
    }
    values.insert("REQUEST_METHOD".into(), method.into_bytes());
    values.insert("CONTENT_LENGTH".into(), length.to_string().into_bytes());
    if !matches!(request.method, "GET" | "HEAD" | "OPTIONS") {
        let actual = request
            .headers
            .get(http::header::CONTENT_TYPE)
            .map(http::HeaderValue::as_bytes)
            .filter(|v| !v.is_empty())
            .unwrap_or(b"application/x-www-form-urlencoded");
        values.insert("CONTENT_TYPE".into(), actual.to_vec());
    }
    Ok(values)
}
