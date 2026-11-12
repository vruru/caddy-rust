//! Byte-preserving Go 1.27 crypto/x509 hostname matching (BSD-3-Clause).
//! Derived from https://github.com/golang/go/blob/go1.27.3/src/crypto/x509/verify.go.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
fn split(host: &[u8]) -> Vec<Vec<u8>> {
    host.strip_suffix(b".")
        .unwrap_or(host)
        .split(|b| *b == b'.')
        .map(|p| p.to_ascii_lowercase())
        .collect()
}
fn valid(host: &[u8], pattern: bool) -> bool {
    let host = if pattern {
        host
    } else {
        host.strip_suffix(b".").unwrap_or(host)
    };
    !host.is_empty()
        && host != b"*"
        && host.split(|b| *b == b'.').enumerate().all(|(i, p)| {
            !p.is_empty()
                && (pattern && i == 0 && p == b"*"
                    || p.iter().enumerate().all(|(j, b)| {
                        b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-' && j != 0
                    }))
        })
}
fn matches(pattern: &[u8], parts: &[Vec<u8>]) -> bool {
    let lower = pattern.to_ascii_lowercase();
    let p: Vec<_> = lower.split(|b| *b == b'.').collect();
    !pattern.is_empty()
        && !parts.is_empty()
        && p.len() == parts.len()
        && p.iter()
            .zip(parts)
            .enumerate()
            .all(|(i, (a, b))| i == 0 && *a == b"*" || *a == b.as_slice())
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(IpAddr::V6(v), IpAddr::V4),
        v => v,
    }
}
fn ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
        16 => Some(normalize(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).ok()?,
        )))),
        _ => None,
    }
}
fn parse_ip(host: &[u8], zone: bool) -> Option<IpAddr> {
    let s = std::str::from_utf8(host).ok()?;
    let s = if zone && s.contains(':') {
        if let Some((address, zone)) = s.split_once('%') {
            if zone.is_empty() {
                return None;
            }
            address
        } else {
            s
        }
    } else {
        s
    };
    s.parse().ok().map(normalize)
}
fn append(out: &mut Vec<u8>, text: &[u8]) {
    out.extend_from_slice(text)
}
pub(super) fn verify(
    host: &[u8],
    common: &[u8],
    dns: &[Vec<u8>],
    ips: &[Vec<u8>],
    has_san: bool,
) -> Result<(), (Vec<u8>, Vec<u8>)> {
    let candidate = if host.len() >= 3 && host.starts_with(b"[") && host.ends_with(b"]") {
        &host[1..host.len() - 1]
    } else {
        host
    };
    let error_host = if let Some(address) = parse_ip(candidate, true) {
        if ips.iter().any(|bytes| ip(bytes) == Some(address)) {
            return Ok(());
        }
        address.to_string().into_bytes()
    } else {
        let lower = host.to_ascii_lowercase();
        let parts = split(&lower);
        let valid = valid(&lower, false);
        for pattern in dns {
            if if valid && self::valid(pattern, true) {
                matches(pattern, &parts)
            } else {
                !matches!(pattern.as_slice(), b"" | b".")
                    && !matches!(lower.as_slice(), b"" | b".")
                    && pattern.eq_ignore_ascii_case(&lower)
            } {
                return Ok(());
            }
        }
        host.to_vec()
    };
    if !has_san && matches(common, &split(&error_host)) {
        return Err((
            b"x509: certificate relies on legacy Common Name field, use SANs instead".to_vec(),
            error_host,
        ));
    }
    let mut names = Vec::new();
    let is_ip = parse_ip(&error_host, false).is_some();
    let count = if is_ip { ips.len() } else { dns.len() };
    let mut message = Vec::new();
    if is_ip && ips.is_empty() {
        append(&mut message, b"x509: cannot validate certificate for ");
        append(&mut message, &error_host);
        append(&mut message, b" because it doesn't contain any IP SANs");
    } else if count >= 100 {
        append(
            &mut message,
            format!(
                "x509: certificate is valid for {count} {}, but none matched ",
                if is_ip { "IP SANs" } else { "names" }
            )
            .as_bytes(),
        );
        append(&mut message, &error_host);
    } else {
        if is_ip {
            for address in ips {
                if !names.is_empty() {
                    append(&mut names, b", ");
                }
                if let Some(address) = ip(address) {
                    append(&mut names, address.to_string().as_bytes());
                }
            }
        } else {
            for (index, name) in dns.iter().enumerate() {
                if index > 0 {
                    append(&mut names, b", ");
                }
                append(&mut names, name);
            }
        }
        if names.is_empty() {
            append(
                &mut message,
                b"x509: certificate is not valid for any names, but wanted to match ",
            );
        } else {
            append(&mut message, b"x509: certificate is valid for ");
            append(&mut message, &names);
            append(&mut message, b", not ");
        }
        append(&mut message, &error_host);
    }
    Err((message, error_host))
}
