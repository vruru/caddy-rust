// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
use crate::{caddyfile_lexer::Token, caddyfile_parser::dispenser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Option<Value>> {
    let mut d = Dispenser::new(tokens.to_vec());
    let result = match name {
        "host" | "path" | "method" => {
            let mut initialized = false;
            let mut values = Vec::new();
            while d.next() {
                let args = d.remaining_args();
                if !args.is_empty() {
                    initialized = true;
                }
                values.extend(args);
                if d.next_block(0) {
                    return Err(d.error(format!(
                        "malformed {name} matcher: blocks are not supported"
                    )));
                }
            }
            if initialized {
                serde_json::to_value(values)?
            } else {
                Value::Null
            }
        }
        "query" => {
            let mut map = Map::new();
            while d.next() {
                for query in d.remaining_args() {
                    if query.is_empty() {
                        continue;
                    }
                    let Some((before, after)) = query.split_once('=') else {
                        return Err(d.error(format!(
                            "malformed query matcher token: {}; must be in param=val format",
                            d.val()
                        )));
                    };
                    append(&mut map, before.to_string(), after.to_string())?;
                }
                if d.next_block(0) {
                    return Err(d.error("malformed query matcher: blocks are not supported"));
                }
            }
            Value::Object(map)
        }
        "header" => {
            let mut map = Map::new();
            while d.next() {
                let Some(fields) = d.args(1) else {
                    return Err(d.error("malformed header matcher: expected field"));
                };
                let field = &fields[0];
                if let Some(key) = field.strip_prefix('!') {
                    if key.is_empty() {
                        return Err(d.error(
                            "malformed header matcher: must have field name following ! character",
                        ));
                    }
                    map.insert(key.to_string(), Value::Null);
                    if d.next_arg() {
                        return Err(d.error("malformed header matcher: null matching headers cannot have a field value"));
                    }
                } else {
                    if !d.next_arg() {
                        return Err(
                            d.error("malformed header matcher: expected both field and value")
                        );
                    }
                    append(&mut map, canonical_header(field), d.val().to_string())?;
                }
                if d.next_block(0) {
                    return Err(d.error("malformed header matcher: blocks are not supported"));
                }
            }
            Value::Object(map)
        }
        "protocol" => {
            let mut protocol = String::new();
            while d.next() {
                let Some(args) = d.args(1) else {
                    return Err(d.error("expected exactly one protocol"));
                };
                protocol = args[0].clone();
            }
            Value::String(protocol)
        }
        "tls" => {
            let mut map = Map::new();
            while d.next() {
                if d.next_arg() {
                    if d.val() == "early_data" {
                        map.insert("handshake_complete".into(), Value::Bool(false));
                    } else {
                        return Err(d.error(format!("unrecognized option '{}'", d.val())));
                    }
                }
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                if d.next_block(0) {
                    return Err(d.error("malformed tls matcher: blocks are not supported yet"));
                }
            }
            Value::Object(map)
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}
fn append(map: &mut Map<String, Value>, key: String, value: String) -> Result<()> {
    let target = map.entry(key).or_insert(Value::Null);
    if target.is_null() {
        *target = Value::Array(Vec::new());
    }
    target
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid matcher map value"))?
        .push(Value::String(value));
    Ok(())
}
fn canonical_header(field: &str) -> String {
    if !field
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return field.to_string();
    }
    let mut upper = true;
    field
        .bytes()
        .map(|b| {
            let out = if upper {
                b.to_ascii_uppercase()
            } else {
                b.to_ascii_lowercase()
            };
            upper = b == b'-';
            char::from(out)
        })
        .collect()
}
