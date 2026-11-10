// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Address-only adaptation; no name resolution or socket operations.
use super::{
    address::split_host_port,
    budget::{Budget, add, mul},
};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

#[derive(Default)]
struct Parsed {
    network: String,
    scheme: String,
    host: String,
    port: String,
}
fn join_host(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn split_network(input: &str) -> Result<(String, String, String)> {
    let (network, address) = match input.split_once('/') {
        Some((network, address)) => (super::address::go_lower(network.trim()), address),
        None => (String::new(), input),
    };
    if network.starts_with("unix") || network.starts_with("fd") {
        return Ok((network, address.to_owned(), String::new()));
    }
    let (host, port, error) = split_host_port(address);
    if error.is_none() {
        return Ok((network, host, port));
    }
    let retry = join_host(address.trim_matches(['[', ']']), "0");
    let (host, _, error) = split_host_port(&retry);
    if error.is_some() {
        bail!("invalid network address");
    }
    Ok((network, host, String::new()))
}
// URL component validation derives from Go net/url (Go Authors, BSD-3-Clause).
fn host_allowed(b: u8) -> bool {
    b >= 128 || b.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:\"[]<>".contains(&b)
}
fn unescape(input: &str, mode: u8) -> Result<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                bail!("invalid URL escape");
            }
            let nibble = |b: u8| -> Result<u8> {
                match b {
                    b'0'..=b'9' => Ok(b - b'0'),
                    b'a'..=b'f' => Ok(b - b'a' + 10),
                    b'A'..=b'F' => Ok(b - b'A' + 10),
                    _ => bail!("invalid URL escape"),
                }
            };
            let v = nibble(bytes[i + 1])? * 16 + nibble(bytes[i + 2])?;
            if mode == 0 && v < 128 && v != b'%' {
                bail!("invalid URL host escape");
            }
            if mode == 1 && v != b'%' && v != b' ' && (v >= 128 || !host_allowed(v)) {
                bail!("invalid URL zone escape");
            }
            out.push(v);
            i += 3;
        } else {
            if mode != 2 && !host_allowed(bytes[i]) {
                bail!("invalid URL host");
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    // Go strings may contain invalid UTF-8; encoding/json replaces each
    // invalid byte individually rather than an entire truncated sequence.
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_slice();
    loop {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                result.push_str(valid);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                result.push_str(std::str::from_utf8(&rest[..valid]).unwrap());
                result.push(char::REPLACEMENT_CHARACTER);
                rest = &rest[valid + 1..];
            }
        }
    }
    Ok(result)
}

fn parsed(input: &str) -> Result<Parsed> {
    let mut p = Parsed::default();
    if let Some((scheme, rest)) = input.split_once("://") {
        if input.bytes().any(|b| b < b' ' || b == 127) {
            bail!("invalid URL control byte");
        }
        if input.contains('{') {
            bail!("placeholders are not allowed when an upstream address contains a scheme");
        }
        if scheme.is_empty()
            || !scheme.as_bytes()[0].is_ascii_alphabetic()
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            bail!("invalid URL scheme");
        }
        p.scheme = scheme.to_ascii_lowercase();
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let suffix = &rest[end..];
        if suffix.starts_with('/')
            || suffix
                .strip_prefix('?')
                .is_some_and(|s| !s.split('#').next().unwrap_or("").is_empty())
            || suffix.split_once('#').is_some_and(|(_, s)| !s.is_empty())
        {
            bail!("proxy upstream URL must contain only scheme, host and port");
        }
        let authority = &rest[..end];
        let hostport = if let Some((user, host)) = authority.rsplit_once('@') {
            if !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&b))
            {
                bail!("invalid URL userinfo");
            }
            unescape(user, 2)?;
            host
        } else {
            authority
        };
        if hostport.rfind('[').is_some_and(|i| i > 0) {
            bail!("invalid URL IP literal");
        }
        if matches!(p.scheme.as_str(), "http" | "https")
            && !hostport.starts_with('[')
            && hostport.bytes().filter(|b| *b == b':').count() > 1
        {
            bail!("invalid URL port");
        }
        let (host, port) = if let Some(host) = hostport.strip_prefix('[') {
            let end = host
                .rfind(']')
                .ok_or_else(|| anyhow!("missing URL host bracket"))?;
            let tail = &host[end + 1..];
            if !tail.is_empty() && !tail.starts_with(':') {
                bail!("invalid URL port");
            }
            (&host[..end], tail.strip_prefix(':').unwrap_or(""))
        } else if let Some((host, port)) = hostport.rsplit_once(':') {
            (host, port)
        } else {
            (hostport, "")
        };
        if !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
            if !port.contains('-') {
                bail!("invalid URL port");
            }
            let range = input.rsplit_once(':').unwrap().1;
            if range.bytes().filter(|b| *b == b'-').count() != 1 {
                bail!("invalid URL port range");
            }
            // Caddy retries url.Parse after ReplaceAll over the entire URL,
            // not merely the final port field. Keep that observable rewrite.
            let retry = input.replace(range, "0");
            let mut parsed = parsed(&retry)?;
            parsed.port = range.to_owned();
            return Ok(parsed);
        }
        p.host = if hostport.starts_with('[') {
            if let Some((prefix, zone)) = host.split_once("%25") {
                format!(
                    "{}{}",
                    unescape(prefix, 0)?,
                    unescape(&format!("%25{zone}"), 1)?
                )
            } else {
                unescape(host, 0)?
            }
        } else {
            unescape(host, 0)?
        };
        p.port = port.to_owned();
        if hostport.starts_with('[') {
            let (addr, zone) = p
                .host
                .split_once('%')
                .map_or((p.host.as_str(), None), |(a, z)| (a, Some(z)));
            if zone == Some("") || addr.parse::<std::net::Ipv6Addr>().is_err() {
                bail!("invalid URL IP host");
            }
        }
        if (p.scheme == "http" || p.scheme == "h2c") && p.port == "443"
            || p.scheme == "https" && p.port == "80"
        {
            bail!("conflicting upstream scheme and port");
        }
        if p.port.is_empty() {
            p.port = match p.scheme.as_str() {
                "http" | "h2c" => "80",
                "https" => "443",
                _ => "",
            }
            .to_owned();
        }
    } else {
        let (network, host, port) = split_network(input).unwrap_or_else(|_| {
            (
                input
                    .split_once('/')
                    .map_or(String::new(), |(n, _)| super::address::go_lower(n.trim())),
                input.to_owned(),
                String::new(),
            )
        });
        p.network = network;
        p.host = host;
        p.port = port;
        if p.port.is_empty()
            && !p.host.contains('{')
            && !p.network.starts_with("unix")
            && !p.network.starts_with("fd")
        {
            p.port = "80".into();
        }
    }
    if p.network == "unix+h2c" {
        p.network = "unix".into();
        p.scheme = "h2c".into();
    }
    Ok(p)
}
impl Parsed {
    fn dial(&self) -> String {
        if !self.network.is_empty() {
            let address = if (self.port.is_empty() && !self.host.is_empty())
                || self.network.starts_with("unix")
                || self.network.starts_with("fd")
            {
                self.host.clone()
            } else if !self.port.is_empty() {
                join_host(&self.host, &self.port)
            } else {
                String::new()
            };
            return format!("{}/{address}", self.network);
        }
        if self.port.is_empty() && self.host.contains('{') {
            return self.host.clone();
        }
        join_host(&self.host, &self.port)
    }
}
pub(super) fn append(
    input: &str,
    common: &mut String,
    upstreams: &mut Vec<Value>,
    budget: &mut Budget,
) -> Result<()> {
    budget.work(mul(input.len() as u64 + 1, 8)?)?;
    // Parsing/canonicalization produces a bounded number of address copies.
    budget.materialize(mul(add(input.len() as u64, 128)?, 12)?)?;
    let p = parsed(input)?;
    match p.scheme.as_str() {
        "ws" | "wss" => bail!("websocket URL schemes are browser-only; use http or https"),
        "" | "http" | "https" | "h2c" => {}
        _ => bail!("unsupported upstream URL scheme"),
    }
    if !common.is_empty() && *common != p.scheme {
        bail!("all proxy upstreams must use the same scheme");
    }
    *common = p.scheme.clone();
    let dial = p.dial();
    if p.port.contains('{') && p.port.contains('}') {
        upstreams.push(json!({"dial":dial}));
        return Ok(());
    }
    let (network, host, port) = split_network(&dial)?;
    if network.starts_with("unix") {
        if let Some((_, mode)) = host.split_once('|') {
            if mode.is_empty() || !mode.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                bail!("invalid unix permission bits");
            }
            let mode = u32::from_str_radix(mode, 8)?;
            if mode & 0o200 == 0 {
                bail!("unix socket owner write permission required");
            }
        }
        upstreams.push(json!({"dial":dial}));
        return Ok(());
    }
    if network.starts_with("fd") {
        upstreams.push(json!({"dial":dial}));
        return Ok(());
    }
    let (start, end) = port.split_once('-').unwrap_or((&port, &port));
    let port_number = |s: &str| -> Result<u16> {
        if s.is_empty() {
            return Ok(0);
        }
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            bail!("invalid upstream port");
        }
        Ok(s.parse::<u16>()?)
    };
    if !port.is_empty() && (start.is_empty() || end.is_empty()) {
        bail!("invalid upstream port");
    }
    let start = port_number(start)?;
    let end = port_number(end)?;
    if end < start {
        bail!("end port must not be less than start port");
    }
    let count = u64::from(end) - u64::from(start) + 1;
    if count > 65535 {
        bail!("upstream port range exceeds 65535 ports");
    }
    if !p.port.contains('-') {
        upstreams.push(json!({"dial":dial}));
        return Ok(());
    }
    budget.work(count)?;
    budget.materialize(mul(count, add(host.len() as u64, 384)?)?)?;
    upstreams.extend((start..=end).map(|port| json!({"dial":join_host(&host,&port.to_string())})));
    Ok(())
}
