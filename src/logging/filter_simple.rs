// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
//! The non-URL/non-regexp field filters. Views preserve large borrowed objects;
//! renaming a key does not clone the complete object or event for each writer.
use super::{bounded::Buffer, config, net_address, types::FieldValue};
use anyhow::{Result, ensure};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, net::IpAddr};
pub(super) struct View<'a> {
    pub key: &'a str,
    pub value: Cow<'a, FieldValue>,
}
pub(super) enum Simple {
    Delete,
    Hash,
    Replace(String),
    Rename(String),
    IpMask { v4: Option<u8>, v6: Option<u8> },
}
impl Simple {
    /// None means this is a different filter family, not successful provisioning.
    pub(super) fn from_module(name: &str, mut fields: Map<String, Value>) -> Option<Result<Self>> {
        if !matches!(name, "delete" | "hash" | "replace" | "rename" | "ip_mask") {
            return None;
        }
        Some((|| {
            let allowed: &[&str] = match name {
                "replace" => &["value"],
                "rename" => &["name"],
                "ip_mask" => &["ipv4_cidr", "ipv6_cidr"],
                _ => &[],
            };
            crate::http_config::helpers::deny_unknown(&fields, allowed, "/logging/filter")?;
            Ok(match name {
                "delete" => Self::Delete,
                "hash" => Self::Hash,
                "replace" => Self::Replace(config::string(fields.remove("value"))?),
                "rename" => Self::Rename(config::string(fields.remove("name"))?),
                _ => {
                    let v4 = config::integer(fields.remove("ipv4_cidr"))?;
                    let v6 = config::integer(fields.remove("ipv6_cidr"))?;
                    Self::IpMask {
                        v4: if (1..=32).contains(&v4) {
                            Some(v4 as u8)
                        } else {
                            None
                        },
                        v6: if (1..=128).contains(&v6) {
                            Some(v6 as u8)
                        } else {
                            None
                        },
                    }
                }
            })
        })())
    }
    pub(super) fn apply<'a>(
        &'a self,
        mut field: View<'a>,
        limit: usize,
    ) -> Result<Option<View<'a>>> {
        match self {
            Self::Delete => return Ok(None),
            Self::Rename(name) => field.key = name,
            Self::Replace(value) => {
                ensure!(
                    value.len() <= limit,
                    super::bounded::ByteLimit("log replacement byte limit exceeded")
                );
                field.value = Cow::Owned(FieldValue::String(value.clone()));
            }
            Self::Hash | Self::IpMask { .. } => {
                if let Some(value) = self.transform(&field.value, limit)? {
                    field.value = Cow::Owned(value);
                }
            }
        }
        Ok(Some(field))
    }
    fn transform(&self, value: &FieldValue, limit: usize) -> Result<Option<FieldValue>> {
        Ok(match value {
            FieldValue::String(s) => Some(FieldValue::RawString(self.string(s.as_bytes(), limit)?)),
            FieldValue::RawString(s) => Some(FieldValue::RawString(self.string(s, limit)?)),
            FieldValue::StringArray(values) => {
                // Charge array storage before reserving; count the transformed
                // strings cumulatively, not independently against the full cap.
                let overhead = values
                    .len()
                    .checked_mul(std::mem::size_of::<Vec<u8>>())
                    .filter(|n| *n <= limit)
                    .ok_or(super::bounded::ByteLimit(
                        "log filtered array byte limit exceeded",
                    ))?;
                let mut remaining = limit - overhead;
                let mut output = Vec::with_capacity(values.len());
                for value in values {
                    let bytes = self.string(value, remaining)?;
                    remaining -= bytes.len();
                    output.push(bytes);
                }
                Some(FieldValue::StringArray(output))
            }
            // Go mutates Field.String for other types, but their encoder reads
            // Integer/Interface instead. A generic ArrayMarshaler is not the
            // special internal.LoggableStringArray and must remain untouched.
            _ => None,
        })
    }
    fn string(&self, value: &[u8], limit: usize) -> Result<Vec<u8>> {
        match self {
            Self::Hash => {
                ensure!(
                    limit >= 8,
                    super::bounded::ByteLimit("log hash byte limit exceeded")
                );
                let digest = Sha256::digest(value);
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut out = Vec::with_capacity(8);
                for byte in &digest[..4] {
                    out.push(HEX[(byte >> 4) as usize]);
                    out.push(HEX[(byte & 15) as usize]);
                }
                Ok(out)
            }
            Self::IpMask { v4, v6 } => mask(value, *v4, *v6, limit),
            _ => unreachable!("only string-transforming filter variants call string"),
        }
    }
}
fn mask(value: &[u8], v4: Option<u8>, v6: Option<u8>, limit: usize) -> Result<Vec<u8>> {
    let mut output = Buffer::new(limit);
    for (i, value) in value.split(|b| *b == b',').enumerate() {
        if i > 0 {
            output.bytes(b", ")?;
        }
        let value = trim_space(value);
        let Ok(text) = std::str::from_utf8(value) else {
            output.bytes(value)?;
            continue;
        };
        let (host, port) = net_address::split_host_port(text).unwrap_or((text, ""));
        let Ok(ip) = host.parse::<IpAddr>() else {
            output.bytes(value)?;
            continue;
        };
        let mapped = match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(ip) => ip.to_ipv4_mapped(),
        };
        let masked = if let Some(ip) = mapped {
            v4.map(|p| std::net::Ipv4Addr::from(u32::from(ip) & (u32::MAX << (32 - p))).to_string())
        } else if let IpAddr::V6(ip) = ip {
            v6.map(|p| {
                std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << (128 - p))).to_string()
            })
        } else {
            None
        };
        let host = masked.as_deref().unwrap_or("<nil>");
        if port.is_empty() {
            output.bytes(host.as_bytes())?;
        } else {
            let bytes = host
                .len()
                .checked_add(port.len())
                .and_then(|n| n.checked_add(if host.contains(':') { 3 } else { 1 }))
                .ok_or_else(|| anyhow::anyhow!("log masked address size overflow"))?;
            ensure!(
                bytes <= output.remaining(),
                super::bounded::ByteLimit("log masked address byte limit exceeded")
            );
            if host.contains(':') {
                output.byte(b'[')?;
                output.bytes(host.as_bytes())?;
                output.byte(b']')?;
            } else {
                output.bytes(host.as_bytes())?;
            }
            output.byte(b':')?;
            output.bytes(port.as_bytes())?;
        }
    }
    Ok(output.into_vec())
}
/// Unicode White_Space byte sequences as used by Go strings.TrimSpace. Matching
/// exact UTF-8 sequences preserves invalid bytes instead of lossy replacement.
fn space_prefix(input: &[u8]) -> usize {
    if matches!(input.first(), Some(b'\t'..=b'\r' | b' ')) {
        return 1;
    }
    if input.starts_with(&[0xc2, 0x85]) || input.starts_with(&[0xc2, 0xa0]) {
        return 2;
    }
    if input.starts_with(&[0xe1, 0x9a, 0x80])
        || input.starts_with(&[0xe2, 0x81, 0x9f])
        || input.starts_with(&[0xe3, 0x80, 0x80])
    {
        return 3;
    }
    if input.starts_with(&[0xe2, 0x80])
        && input
            .get(2)
            .is_some_and(|b| matches!(*b, 0x80..=0x8a | 0xa8 | 0xa9 | 0xaf))
    {
        return 3;
    }
    0
}
pub(crate) fn trim_space(mut input: &[u8]) -> &[u8] {
    loop {
        let n = space_prefix(input);
        if n == 0 {
            break;
        }
        input = &input[n..];
    }
    loop {
        let mut found = 0;
        for n in 1..=3 {
            if input.len() >= n && space_prefix(&input[input.len() - n..]) == n {
                found = n;
                break;
            }
        }
        if found == 0 {
            break;
        }
        input = &input[..input.len() - found];
    }
    input
}
