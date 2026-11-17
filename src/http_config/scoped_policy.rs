//! Immutable exact-Host trusted-proxy scopes. Unknown authorities trust nothing.
use anyhow::{Result, ensure};
use ipnet::IpNet;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

use super::helpers::object;

const MAX_HOSTS: usize = 256;
const MAX_CIDRS_PER_HOST: usize = 10_000;
const MAX_CIDRS_TOTAL: usize = MAX_HOSTS * MAX_CIDRS_PER_HOST;
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Clone, Default)]
pub(crate) struct ScopedPolicy {
    ranges: HashMap<String, Vec<IpNet>>,
}

pub(crate) fn parse(value: &Value, path: &str) -> Result<ScopedPolicy> {
    let normalized = crate::module_json::inline(value, "source", false)?;
    let module = object(&normalized, path)?;
    ensure!(
        module.get("source").and_then(Value::as_str) == Some("scoped_policy"),
        "unsupported trusted proxy source at {path}"
    );

    // Inline modules pass through Go's sorted map encoding before typed field
    // decoding. Repeated folded map fields merge; null resets the map. DNS map
    // keys themselves are never case folded.
    let mut hosts = BTreeMap::new();
    for (name, value) in module {
        if matches!(name.as_str(), "source" | "@id") {
            continue;
        }
        ensure!(
            is_hosts_field(name),
            "unknown configuration field at {path}"
        );
        if value.is_null() {
            hosts.clear();
        } else {
            for (key, value) in object(value, path)? {
                // Typed-decoding errors survive a subsequent folded field
                // overwriting the same key; semantic CIDR validation does not.
                if !value.is_null() {
                    let entries = value
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("CIDR array required at {path}"))?;
                    ensure!(
                        entries.iter().all(|v| v.is_null() || v.is_string()),
                        "CIDR string required at {path}"
                    );
                }
                hosts.insert(key.as_str(), value);
            }
        }
    }
    ensure!(
        hosts.len() <= MAX_HOSTS,
        "scoped_policy host limit exceeded at {path}"
    );

    // Check every scope's shape and bounds before parsing any CIDR.
    let mut total = 0usize;
    for (host, value) in &hosts {
        ensure!(valid_hostname(host), "invalid scoped_policy host at {path}");
        let count = if value.is_null() {
            0
        } else {
            value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("CIDR array required at {path}"))?
                .len()
        };
        ensure!(
            count <= MAX_CIDRS_PER_HOST,
            "scoped_policy per-host CIDR limit exceeded at {path}"
        );
        total += count;
        ensure!(
            total <= MAX_CIDRS_TOTAL,
            "scoped_policy total CIDR limit exceeded at {path}"
        );
    }

    let mut ranges = HashMap::new();
    ranges
        .try_reserve(hosts.len())
        .map_err(|_| anyhow::anyhow!("scoped_policy allocation unavailable at {path}"))?;
    for (host, value) in hosts {
        let list = value.as_array().map(Vec::as_slice).unwrap_or(&[]);
        let mut seen = HashSet::new();
        seen.try_reserve(list.len())
            .map_err(|_| anyhow::anyhow!("scoped_policy allocation unavailable at {path}"))?;
        let mut out = Vec::new();
        out.try_reserve_exact(list.len())
            .map_err(|_| anyhow::anyhow!("scoped_policy allocation unavailable at {path}"))?;
        for value in list {
            // Go decodes null into a slice string's empty zero value, which
            // fails prefix parsing just like an explicit empty string.
            let cidr = if value.is_null() {
                ""
            } else {
                value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("CIDR string required at {path}"))?
            };
            let prefix = parse_canonical_prefix(cidr, path)?;
            if seen.insert(prefix) {
                out.push(prefix);
            }
        }
        ranges.insert(host.to_owned(), out);
    }
    Ok(ScopedPolicy { ranges })
}

fn is_hosts_field(name: &str) -> bool {
    // The only non-ASCII member of these ASCII letters' Go SimpleFold sets.
    name.chars()
        .map(|ch| match ch {
            '\u{017f}' => 's',
            _ => ch.to_ascii_lowercase(),
        })
        .eq("hosts".chars())
}

fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return false;
    }
    let mut count = 0;
    let mut final_label = "";
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > MAX_LABEL_LEN
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
        count += 1;
        final_label = label;
    }
    count >= 2 && !final_label.bytes().all(|b| b.is_ascii_digit())
}

fn parse_canonical_prefix(cidr: &str, path: &str) -> Result<IpNet> {
    let prefix = cidr
        .parse::<IpNet>()
        .map_err(|_| anyhow::anyhow!("invalid scoped_policy CIDR at {path}"))?;
    ensure!(
        prefix.trunc() == prefix && prefix.to_string() == cidr,
        "non-canonical scoped_policy CIDR at {path}"
    );
    ensure!(
        !matches!(prefix.addr(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()),
        "IPv4-mapped scoped_policy CIDR not allowed at {path}"
    );
    ensure!(
        prefix.prefix_len() > 0,
        "zero-length scoped_policy CIDR not allowed at {path}"
    );
    Ok(prefix)
}

impl ScopedPolicy {
    /// Select one immutable scope, shared by direct-peer and forwarded-IP trust
    /// checks. The lookup allocates nothing and performs no external I/O.
    pub(crate) fn ranges_for(&self, host: &str) -> &[IpNet] {
        if host.is_empty() || host.len() > MAX_HOST_LEN + 7 || host.starts_with('[') {
            return &[];
        }
        let host = if let Some((host, port)) = host.rsplit_once(':') {
            if !valid_port(port) {
                return &[];
            }
            host
        } else {
            host
        };
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return &[];
        }
        let mut key = [0u8; MAX_HOST_LEN];
        for (index, byte) in host.bytes().enumerate() {
            if byte >= 0x7f || byte <= b' ' {
                return &[];
            }
            key[index] = byte.to_ascii_lowercase();
        }
        // Every written byte was checked as ASCII before conversion.
        let Ok(key) = std::str::from_utf8(&key[..host.len()]) else {
            return &[];
        };
        self.ranges.get(key).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn valid_port(port: &str) -> bool {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let number = port.bytes().fold(0u32, |n, b| n * 10 + u32::from(b - b'0'));
    (1..=65535).contains(&number)
}
