// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
// ParseBytes behavior derives from go-humanize (MIT), copyright
// (c) 2005-2008 Dustin Sallings. See THIRD-PARTY-NOTICES.
//! Configuration-only body/timeout directives. Their runtime enforcement is
//! handled separately by the HTTP implementation.
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};
pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Option<Value>> {
    if !matches!(name, "request_body" | "timeouts") {
        return Ok(None);
    }
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut map = Map::new();
    map.insert("handler".into(), name.into());
    while d.next_block(0) {
        match (name, d.val()) {
            ("request_body", "max_size") | ("timeouts", "max_write_chunk") => {
                let key = d.val().to_owned();
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                let value = parse_size(&args[0])? as i64;
                if value == 0 {
                    map.remove(&key);
                } else {
                    map.insert(key, value.into());
                }
            }
            ("request_body", "set") => {
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                if args[0].is_empty() {
                    map.remove("set");
                } else {
                    map.insert("set".into(), args[0].clone().into());
                }
            }
            ("timeouts", "read_timeout" | "write_timeout") => {
                let key = d.val().to_owned();
                let args = d.remaining_args();
                if !(1..=2).contains(&args.len()) {
                    return Err(d.arg_err());
                }
                // The original directive uses time.ParseDuration, deliberately
                // excluding Caddy's additional 'd' unit.
                if args[0].contains('d') {
                    bail!("invalid timeout duration");
                }
                let duration = crate::duration::parse_str(&args[0])?;
                if duration == 0 {
                    map.remove(&key);
                } else {
                    map.insert(key.clone(), duration.into());
                }
                if args.len() == 2 {
                    let rate = args[1]
                        .parse::<i64>()
                        .map_err(|_| anyhow!("invalid timeout minimum rate"))?;
                    let rate_key = if key == "read_timeout" {
                        "read_min_rate"
                    } else {
                        "write_min_rate"
                    };
                    if rate == 0 {
                        map.remove(rate_key);
                    } else {
                        map.insert(rate_key.into(), rate.into());
                    }
                }
            }
            (_, key) => bail!("unrecognized {name} subdirective {key}"),
        }
    }
    super::module_value::normalize(Value::Object(map)).map(Some)
}
/// Follows go-humanize v1.1.0 ParseBytes: commas, decimal fractions, SI/IEC
/// aliases, whole integer checked multiplication before float fallback.
pub(super) fn parse_size(input: &str) -> Result<u64> {
    let end = input
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b'.' || *b == b',')
        .count();
    let number = input[..end].replace(',', "");
    let float = number
        .parse::<f64>()
        .map_err(|_| anyhow!("invalid byte size"))?;
    if !float.is_finite() {
        bail!("invalid byte size");
    }
    let unit = super::address::go_lower(input[end..].trim());
    let multiplier = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "m" | "mb" => 1_000_000,
        "g" | "gb" => 1_000_000_000,
        "t" | "tb" => 1_000_000_000_000,
        "p" | "pb" => 1_000_000_000_000_000,
        "e" | "eb" => 1_000_000_000_000_000_000,
        "ki" | "kib" => 1 << 10,
        "mi" | "mib" => 1 << 20,
        "gi" | "gib" => 1 << 30,
        "ti" | "tib" => 1 << 40,
        "pi" | "pib" => 1 << 50,
        "ei" | "eib" => 1 << 60,
        _ => bail!("unrecognized byte size unit"),
    };
    if !number.contains('.')
        && let Ok(integer) = number.parse::<u64>()
    {
        return integer
            .checked_mul(multiplier)
            .ok_or_else(|| anyhow!("byte size overflow"));
    }
    let bytes = float * multiplier as f64;
    if bytes >= u64::MAX as f64 {
        bail!("byte size overflow");
    }
    Ok(bytes as u64)
}
