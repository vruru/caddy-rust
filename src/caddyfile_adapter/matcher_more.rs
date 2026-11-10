// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::Dispenser;
use serde_json::{Value, json};

pub(super) fn parse(
    name: &str,
    tokens: &[Token],
    context_name: &str,
) -> anyhow::Result<Option<Value>> {
    let mut d = Dispenser::new(tokens.to_vec());

    match name {
        "remote_ip" | "client_ip" => {
            let mut ranges: Vec<String> = Vec::new();
            while d.next() {
                while d.next_arg() {
                    let val = d.val();
                    if val == "forwarded" && name == "remote_ip" {
                        return Err(d.error("the 'forwarded' option is no longer supported; use the 'client_ip' matcher instead"));
                    }
                    if val == "private_ranges" {
                        ranges.extend(
                            [
                                "192.168.0.0/16",
                                "172.16.0.0/12",
                                "10.0.0.0/8",
                                "127.0.0.1/8",
                                "fd00::/8",
                                "::1",
                            ]
                            .into_iter()
                            .map(str::to_owned),
                        );
                    } else {
                        ranges.push(val.to_owned());
                    }
                }
                if d.next_block(0) {
                    return Err(d.error(format!(
                        "malformed {name} matcher: blocks are not supported"
                    )));
                }
            }
            if ranges.is_empty() {
                Ok(Some(json!({})))
            } else {
                Ok(Some(json!({ "ranges": ranges })))
            }
        }
        "vars" => {
            let mut map: std::collections::BTreeMap<String, Vec<String>> = Default::default();
            while d.next() {
                let Some(fields) = d.args(1) else {
                    return Err(d.error("malformed vars matcher: expected field name"));
                };
                let vals = d.remaining_args();
                if vals.is_empty() {
                    return Err(d.error(
                        "malformed vars matcher: expected at least one value to match against",
                    ));
                }
                map.entry(fields[0].clone()).or_default().extend(vals);
                if d.next_block(0) {
                    return Err(d.error("malformed vars matcher: blocks are not supported"));
                }
            }
            Ok(Some(serde_json::to_value(map)?))
        }
        "expression" => {
            d.next();

            if d.count_remaining_args() > 1 {
                // Return JSON string. Name is empty.
                let raw_args = d.remaining_args_raw();
                let expr = raw_args.join(" ");
                return Ok(Some(Value::String(expr)));
            }

            if !d.next_arg() {
                return Err(d.arg_err());
            }

            let expr = d.val().to_string();

            if context_name.is_empty() {
                Ok(Some(Value::String(expr)))
            } else {
                Ok(Some(json!({
                    "expr": expr,
                    "name": context_name
                })))
            }
        }
        _ => Ok(None),
    }
}
