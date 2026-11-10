// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Pinned CertMagic/Caddy subject classification for configuration adaptation.
use std::net::{IpAddr, Ipv4Addr};
pub(super) fn qualifies(s: &str) -> bool {
    !s.trim().is_empty()
        && !s.starts_with('.')
        && !s.ends_with('.')
        && (!s.contains('*') || s.starts_with("*.") || s == "*")
        && !s.contains([
            '(', ')', '[', ']', '{', '}', '<', '>', ' ', '\t', '\n', '"', '\\', '!', '@', '#', '$',
            '%', '^', '&', '|', ';', '\'', '+', '=',
        ])
}
fn host_only(s: &str) -> String {
    let (h, _, error) = super::address::split_host_port(s);
    if error.is_none() {
        h
    } else if s.starts_with('[') && s.ends_with(']') && s.len() > 1 {
        s[1..s.len() - 1].into()
    } else {
        s.into()
    }
}
pub(super) fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}
fn private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 127
        || a == 0 && b == 0
        || a == 10
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && b == 168
        || a == 169 && b == 254
}
pub(super) fn internal(s: &str) -> bool {
    let host = host_only(s);
    let lower = super::address::go_lower(host.strip_suffix('.').unwrap_or(&host));
    if lower == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa"]
            .iter()
            .any(|end| lower.ends_with(end))
    {
        return true;
    }
    // CertMagic isInternalIP calls hostOnly a second time after the
    // first host normalization (observable for nested bracket input).
    match host_only(&lower).parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => private_v4(v),
        Ok(IpAddr::V6(v)) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return private_v4(v4);
            }
            let n = u128::from(v);
            n >> (128 - 7) == 0 || n >> (128 - 10) == 0b1111111010 || n >> (128 - 7) == 0b1111110
        }
        _ => false,
    }
}
pub(super) fn public_implicit(s: &str, on_demand: bool) -> bool {
    !is_ip(s) && !internal(s) && (s.matches("*.").count() < 2 || on_demand)
}
pub(super) fn public_certmagic(s: &str) -> bool {
    qualifies(s)
        && !internal(s)
        && (!s.contains('*')
            || s.matches('*').count() == 1
                && s.matches('.').count() > 1
                && s.len() > 2
                && s.starts_with("*."))
}
pub(super) fn tailscale(s: &str) -> bool {
    super::address::go_lower(s).ends_with(".ts.net")
}
pub(super) fn wildcard(subject: &str, pattern: &str) -> bool {
    let subject = super::address::go_lower(&host_only(subject));
    let pattern = super::address::go_lower(pattern);
    if subject == pattern {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }
    // The original replaces every preceding nonempty label cumulatively.
    // Compare that candidate without rebuilding a joined string at each
    // position: the prefix must already be stars and the remaining suffix
    // must equal the original. This keeps the exact behavior linear.
    let mut last_mismatch = None;
    let mut a = subject.split('.');
    let mut b = pattern.split('.');
    let mut index = 0;
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) => {
                if x != y {
                    last_mismatch = Some(index);
                }
                index += 1;
            }
            (None, None) => break,
            _ => return false,
        }
    }
    for (i, (original, reference)) in subject.split('.').zip(pattern.split('.')).enumerate() {
        if original.is_empty() {
            if !reference.is_empty() {
                return false;
            }
            continue;
        }
        if reference != "*" {
            return false;
        }
        if last_mismatch.is_none_or(|last| last <= i) {
            return true;
        }
    }
    false
}
