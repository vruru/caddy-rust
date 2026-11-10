// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(super) fn parse(name: &str, tokens: &[Token], context_name: &str) -> Result<Option<Value>> {
    match name {
        "path_regexp" => path(tokens, context_name).map(Some),
        "header_regexp" | "vars_regexp" => fields(name, tokens, context_name).map(Some),
        _ => Ok(None),
    }
}

fn path(tokens: &[Token], context_name: &str) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    let mut pattern = String::new();
    let mut name = String::new();
    while d.next() {
        if !pattern.is_empty() {
            return Err(d.error("regular expression can only be used once per named matcher"));
        }
        let args = d.remaining_args();
        match args.len() {
            1 => pattern = args[0].clone(),
            2 => {
                name = args[0].clone();
                pattern = args[1].clone();
            }
            _ => return Err(d.arg_err()),
        }
        if name.is_empty() {
            name = context_name.to_owned();
        }
        if d.next_block(0) {
            return Err(d.error("malformed path_regexp matcher: blocks are not supported"));
        }
    }
    Ok(regexp(name, pattern))
}

fn fields(kind: &str, tokens: &[Token], context_name: &str) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    let mut result = BTreeMap::new();
    while d.next() {
        let Some(first) = d.args(2) else {
            return Err(d.arg_err());
        };
        let (mut name, field, pattern) = match d.args(1) {
            Some(third) => (first[0].clone(), first[1].clone(), third[0].clone()),
            None => (String::new(), first[0].clone(), first[1].clone()),
        };
        if name.is_empty() {
            name = context_name.to_owned();
        }
        if kind == "header_regexp" && result.contains_key(&field) {
            return Err(d.error(format!("header_regexp matcher can only be used once per named matcher, per header field: {field}")));
        }
        result.insert(field, regexp(name, pattern));
        if d.next_block(0) {
            return Err(d.error(format!(
                "malformed {kind} matcher: blocks are not supported"
            )));
        }
    }
    Ok(serde_json::to_value(result)?)
}

fn regexp(name: String, pattern: String) -> Value {
    let mut value = Map::new();
    if !name.is_empty() {
        value.insert("name".into(), name.into());
    }
    value.insert("pattern".into(), pattern.into());
    value.into()
}
