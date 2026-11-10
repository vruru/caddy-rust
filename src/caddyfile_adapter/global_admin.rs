// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut map = Map::new();
    let mut listen = String::new();
    let mut disabled = false;
    if d.next_arg() {
        listen = d.val().to_owned();
        if listen == "off" {
            disabled = true;
            if d.next() {
                bail!("No more option is allowed after turning off admin config");
            }
        } else if d.next_arg() {
            return Err(d.arg_err());
        }
    }
    while d.next_block(0) {
        match d.val() {
            "enforce_origin" => {
                map.insert("enforce_origin".into(), true.into());
            }
            "origins" => {
                let origins = d.remaining_args();
                if origins.is_empty() {
                    map.remove("origins");
                } else {
                    map.insert(
                        "origins".into(),
                        Value::Array(origins.into_iter().map(Value::String).collect()),
                    );
                }
            }
            name => bail!("unrecognized admin parameter {name}"),
        }
    }
    if disabled {
        map.insert("disabled".into(), true.into());
    } else {
        if listen.is_empty() {
            listen = "localhost:2019".into();
        }
        map.insert("listen".into(), listen.into());
    }
    Ok(Value::Object(map))
}
