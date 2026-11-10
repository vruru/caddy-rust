// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Translate PKI configuration without loading keys or modifying trust stores.
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
pub(super) fn parse(tokens: &[Token]) -> Result<Map<String, Value>> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut authorities = Map::new();
    while d.next_block(0) {
        if d.val() != "ca" {
            bail!("unrecognized pki option {}", d.val());
        }
        let mut id = String::new();
        if d.next_arg() {
            id = d.val().to_owned();
            if d.next_arg() {
                return Err(d.arg_err());
            }
        }
        if id.is_empty() {
            id = "local".into();
        }
        let mut config = Map::new();
        let nesting = d.nesting();
        while d.next_block(nesting) {
            match d.val() {
                "name" | "root_cn" | "intermediate_cn" => {
                    let key = match d.val() {
                        "root_cn" => "root_common_name",
                        "intermediate_cn" => "intermediate_common_name",
                        _ => "name",
                    };
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    set_string(&mut config, key, d.val());
                }
                "intermediate_lifetime" | "maintenance_interval" => {
                    let key = d.val().to_owned();
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    let duration = crate::duration::parse_str(d.val())?;
                    if duration == 0 {
                        config.remove(&key);
                    } else {
                        config.insert(key, duration.into());
                    }
                }
                "renewal_window_ratio" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    let Some(ratio) = crate::caddyfile_parser::scalar::parse_float(d.val()) else {
                        return Err(d.error("invalid PKI renewal ratio"));
                    };
                    if !ratio.is_finite() || ratio <= 0.0 || ratio > 1.0 {
                        bail!("PKI renewal ratio must be finite and in (0,1]");
                    }
                    // Go serializes this sole integral ratio as 1. Keep the
                    // returned Value canonical too, without touching i64 durations.
                    config.insert(
                        "renewal_window_ratio".into(),
                        if ratio == 1.0 {
                            1u64.into()
                        } else {
                            ratio.into()
                        },
                    );
                }
                "root" | "intermediate" => {
                    let section = d.val().to_owned();
                    keypair(&mut d, &mut config, &section)?;
                }
                name => bail!("unrecognized pki ca option {name}"),
            }
        }
        authorities.insert(id, Value::Object(config));
    }
    Ok(authorities)
}
fn keypair(d: &mut Dispenser, config: &mut Map<String, Value>, section: &str) -> Result<()> {
    let value = config
        .entry(section)
        .or_insert_with(|| Value::Object(Map::new()));
    let pair = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("PKI keypair must be an object"))?;
    let nesting = d.nesting();
    while d.next_block(nesting) {
        let field = match d.val() {
            "cert" => "certificate",
            "key" => "private_key",
            "format" => "format",
            name => bail!("unrecognized pki ca {section} option {name}"),
        };
        if !d.next_arg() {
            return Err(d.arg_err());
        }
        set_string(pair, field, d.val());
    }
    Ok(())
}
fn set_string(map: &mut Map<String, Value>, key: &str, value: &str) {
    if value.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.into(), value.into());
    }
}
