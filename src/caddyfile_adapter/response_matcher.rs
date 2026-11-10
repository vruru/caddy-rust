// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
/// Shared representation of Caddy response status/header matchers. Cursor
/// consumption deliberately follows ParseNamedResponseMatcher, including its
/// distinction between a nil header slice and a slice of strings.
pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let depth = d.nesting();
    let mut headers = Map::new();
    let mut statuses = Vec::new();
    while d.next_arg() || d.next_block(depth) {
        match d.val() {
            "header" => {
                let incoming = super::matcher_atoms::parse("header", &d.next_segment())?;
                let Some(Value::Object(incoming)) = incoming else {
                    bail!("invalid header matcher representation");
                };
                for (key, value) in incoming {
                    match value {
                        Value::Null => {
                            headers.insert(key, Value::Null);
                        }
                        Value::Array(mut values) => {
                            let entry = headers.entry(key).or_insert(Value::Null);
                            if entry.is_null() {
                                *entry = Value::Array(Vec::new());
                            }
                            entry
                                .as_array_mut()
                                .ok_or_else(|| anyhow::anyhow!("invalid header matcher values"))?
                                .append(&mut values);
                        }
                        _ => bail!("invalid header matcher value"),
                    }
                }
            }
            "status" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.arg_err());
                }
                for arg in args {
                    let arg = if arg.len() == 3 && arg.ends_with("xx") {
                        &arg[..1]
                    } else {
                        &arg
                    };
                    statuses.push(Value::from(arg.parse::<isize>()?));
                }
            }
            name => bail!("unrecognized response matcher {name}"),
        }
    }
    let mut object = Map::new();
    if !headers.is_empty() {
        object.insert("headers".into(), Value::Object(headers));
    }
    if !statuses.is_empty() {
        object.insert("status_code".into(), Value::Array(statuses));
    }
    Ok(Value::Object(object))
}
