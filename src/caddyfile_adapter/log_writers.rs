// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Writer configuration adaptation only; this module never creates log files
//! or opens network connections.
use super::{
    budget::Budget,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
fn mode(input: &str) -> Result<u32> {
    // Go fmt's zero-padded %04s accepts the empty string as mode 0000.
    let padded = format!("{input:0>4}");
    if !padded.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        bail!("invalid octal file mode");
    }
    Ok(u32::from_str_radix(&padded, 8)?)
}
fn one(d: &mut Dispenser) -> Result<String> {
    d.all_args(1)
        .map(|a| a[0].clone())
        .ok_or_else(|| d.arg_err())
}
pub(super) fn parse(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut m = Map::new();
    m.insert("output".into(), name.into());
    if !matches!(name, "file" | "net") {
        bail!("module caddy.logging.writers.{name} not registered");
    }
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    set_str(
        &mut m,
        if name == "file" {
            "filename"
        } else {
            "address"
        },
        d.val(),
    );
    if d.next_arg() {
        return Err(d.arg_err());
    }
    while d.next_block(0) {
        let k = d.val().to_owned();
        match (name, k.as_str()) {
            ("net", "dial_timeout") => {
                let v = one(&mut d)?;
                set_i64(&mut m, &k, crate::duration::parse_str(&v)?);
            }
            ("net", "soft_start") => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert(k, true.into());
            }
            ("file", "mode") => {
                let v = mode(&one(&mut d)?)?;
                if v == 0 {
                    m.remove("mode");
                } else {
                    m.insert("mode".into(), format!("{v:04o}").into());
                }
            }
            ("file", "dir_mode") => {
                let v = one(&mut d)?.trim().to_owned();
                if !matches!(
                    super::address::go_lower(&v).as_str(),
                    "inherit" | "from_file"
                ) {
                    mode(&v)?;
                }
                set_str(&mut m, &k, &v);
            }
            ("file", "roll_disabled" | "roll_uncompressed") => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert(
                    if k == "roll_disabled" {
                        "roll"
                    } else {
                        "roll_gzip"
                    }
                    .into(),
                    false.into(),
                );
            }
            ("file", "roll_size") => {
                let n = super::handler_limits::parse_size(&one(&mut d)?)?;
                set_i64(
                    &mut m,
                    "roll_size_mb",
                    (n as f64 / 1_048_576.0).ceil() as i64,
                );
            }
            ("file", "roll_compression") => {
                let v = super::address::go_lower(one(&mut d)?.trim());
                if !matches!(v.as_str(), "none" | "gzip" | "zstd") {
                    return Err(d.error("roll_compression must be none, gzip or zstd"));
                }
                set_str(&mut m, &k, &v);
            }
            ("file", "roll_local_time") => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert(k, true.into());
            }
            ("file", "roll_keep") => {
                set_i64(&mut m, &k, one(&mut d)?.parse::<i64>()?);
            }
            ("file", "roll_keep_for") => {
                let n = crate::duration::parse_str(&one(&mut d)?)?;
                if n < 0 {
                    return Err(d.error("negative roll_keep_for duration"));
                }
                set_i64(
                    &mut m,
                    "roll_keep_days",
                    (n as f64 / 3_600_000_000_000.0 / 24.0).ceil() as i64,
                );
            }
            ("file", "roll_interval") => {
                set_i64(&mut m, &k, crate::duration::parse_str(&one(&mut d)?)?);
            }
            ("file", "roll_minutes" | "roll_at") => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.arg_err());
                }
                let mut values = Vec::<Value>::new();
                for a in args {
                    for v in a.split(',') {
                        let v = v.trim();
                        if v.is_empty() {
                            return Err(d.error("empty roll schedule value"));
                        }
                        values.push(if k == "roll_minutes" {
                            v.parse::<i64>()?.into()
                        } else {
                            v.into()
                        });
                    }
                }
                m.insert(k, values.into());
            }
            ("file", "backup_time_format") => {
                set_str(&mut m, &k, &one(&mut d)?);
            }
            _ => return Err(d.error(format!("unrecognized {name} writer subdirective {k}"))),
        }
    }
    let v = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &v)?;
    Ok(v)
}
