// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};
pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut metrics = Map::new();
    while d.next_block(0) {
        match d.val() {
            "per_host" | "observe_catchall_hosts" | "otlp" => {
                metrics.insert(d.val().to_owned(), true.into());
            }
            _ => return Err(d.error(format!("unrecognized servers option '{}'", d.val()))),
        }
    }
    Ok(Value::Object(metrics))
}
