// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

pub(super) fn invoke(tokens: &[Token]) -> Result<(String, Value)> {
    let mut h = Dispenser::new(tokens.to_vec());
    h.next();
    if !h.next_arg() {
        return Err(h.arg_err());
    }
    let name = h.val().to_owned();
    if h.next() || h.next_block(0) {
        return Err(h.arg_err());
    }
    let mut handler = Map::new();
    handler.insert("handler".into(), "invoke".into());
    if !name.is_empty() {
        handler.insert("name".into(), name.clone().into());
    }
    Ok((name, Value::Object(handler)))
}
