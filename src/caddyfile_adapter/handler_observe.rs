// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Option<Value>> {
    if !["metrics", "log_skip", "skip_log", "log_name", "log_append"].contains(&name) {
        return Ok(None);
    }
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut value = Map::new();
    match name {
        "metrics" => {
            if !d.remaining_args().is_empty() {
                return Err(d.arg_err());
            }
            value.insert("handler".into(), "metrics".into());
            while d.next_block(0) {
                if d.val() == "disable_openmetrics" {
                    value.insert("disable_openmetrics".into(), true.into());
                } else {
                    bail!("unrecognized metrics subdirective {}", d.val());
                }
            }
        }
        "log_skip" | "skip_log" => {
            if d.next_arg() {
                return Err(d.arg_err());
            }
            if d.next_block(0) {
                bail!("log_skip directive does not accept blocks");
            }
            value.insert("handler".into(), "vars".into());
            value.insert("log_skip".into(), true.into());
        }
        "log_name" => {
            value.insert("handler".into(), "vars".into());
            let names = d.remaining_args();
            value.insert(
                "access_logger_names".into(),
                if names.is_empty() {
                    Value::Null
                } else {
                    json!(names)
                },
            );
        }
        "log_append" => {
            if !d.next_arg() {
                return Err(d.arg_err());
            }
            let mut key = d.val().to_owned();
            if !d.next_arg() {
                return Err(d.arg_err());
            }
            let val = d.val();
            if key.starts_with('<') && key.len() > 1 {
                key.remove(0);
                value.insert("early".into(), true.into());
            }
            value.insert("handler".into(), "log_append".into());
            if !key.is_empty() {
                value.insert("key".into(), key.into());
            }
            if !val.is_empty() {
                value.insert("value".into(), val.into());
            }
        }
        _ => unreachable!(),
    }
    super::module_value::normalize(Value::Object(value)).map(Some)
}
