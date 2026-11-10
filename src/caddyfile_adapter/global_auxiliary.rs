// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! The fixed standard-module inventory has no events.handlers.* or caddy.fs.*
//! provider. Preserve their exact configuration namespaces and fail explicitly.
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

pub(super) fn events(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    if d.next_block(0) {
        if d.val() != "on" || !d.next_arg() || !d.next_arg() {
            return Err(d.arg_err());
        }
        return Err(missing(&d, "events.handlers", d.val()));
    }
    Ok(Value::Object(Map::new()))
}

pub(super) fn filesystem(tokens: &[Token]) -> Result<()> {
    let mut d = Dispenser::new(tokens.to_vec());
    if d.next() {
        if d.args(1).is_none() || !d.next_arg() {
            return Err(d.arg_err());
        }
        return Err(missing(&d, "caddy.fs", d.val()));
    }
    Ok(())
}
fn missing(d: &Dispenser, namespace: &str, name: &str) -> anyhow::Error {
    d.error(format!(
        "getting module named '{namespace}.{name}': module not registered: {namespace}.{name}"
    ))
}
