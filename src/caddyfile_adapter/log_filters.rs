// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Caddyfile filter objects. Regexp compilation belongs to Provision, including
//! merged multi_regexp values; adaptation only enforces the original bounds.
use super::{
    budget::Budget,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
fn arg(d: &mut Dispenser) -> Result<String> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(d.val().into())
}
pub(super) fn operation(pattern: &str, replacement: &str) -> Result<Value> {
    if pattern.is_empty() {
        bail!("regexp pattern cannot be empty");
    }
    if pattern.len() > 1000 {
        bail!("regexp pattern too long (maximum 1000 characters)");
    }
    let mut m = Map::new();
    set_str(&mut m, "regexp", pattern);
    set_str(&mut m, "value", replacement);
    Ok(m.into())
}
pub(super) fn parse(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    let mut m = Map::new();
    m.insert("filter".into(), name.into());
    match name {
        "delete" | "hash" => {}
        "replace" | "rename" => {
            d.next();
            if d.next_arg() {
                set_str(
                    &mut m,
                    if name == "replace" { "value" } else { "name" },
                    d.val(),
                );
            }
        }
        "regexp" => {
            d.next();
            if d.next_arg() {
                set_str(&mut m, "regexp", d.val());
            }
            if d.next_arg() {
                set_str(&mut m, "value", d.val());
            }
        }
        "ip_mask" => {
            d.next();
            let a = d.remaining_args();
            if a.len() > 2 {
                return Err(d.arg_err());
            }
            for (key, value) in ["ipv4_cidr", "ipv6_cidr"].into_iter().zip(a) {
                set_i64(&mut m, key, value.parse::<i64>()?);
            }
            while d.next_block(0) {
                let k = d.val().to_owned();
                let key = match k.as_str() {
                    "ipv4" => "ipv4_cidr",
                    "ipv6" => "ipv6_cidr",
                    _ => return Err(d.error(format!("unrecognized ip_mask subdirective {k}"))),
                };
                set_i64(&mut m, key, arg(&mut d)?.parse::<i64>()?);
            }
        }
        "query" | "cookie" | "set_cookie" => {
            d.next();
            let mut actions = Vec::new();
            while d.next_block(0) {
                let k = d.val().to_owned();
                if !matches!(k.as_str(), "replace" | "delete" | "hash") {
                    return Err(d.error(format!("unrecognized filter action {k}")));
                }
                let mut action = Map::new();
                action.insert("type".into(), k.clone().into());
                action.insert(
                    if name == "query" { "parameter" } else { "name" }.into(),
                    arg(&mut d)?.into(),
                );
                if k == "replace" {
                    set_str(&mut action, "value", &arg(&mut d)?);
                }
                actions.push(Value::Object(action));
            }
            m.insert(
                "actions".into(),
                if actions.is_empty() {
                    Value::Null
                } else {
                    actions.into()
                },
            );
        }
        "multi_regexp" => {
            d.next();
            let mut ops = Vec::new();
            while d.next_block(0) {
                if d.val() != "regexp" {
                    return Err(d.error(format!(
                        "unrecognized multi_regexp subdirective {}",
                        d.val()
                    )));
                }
                if ops.len() >= 50 {
                    return Err(d.error("too many regexp operations (maximum 50 allowed)"));
                }
                let pattern = arg(&mut d)?;
                if pattern.len() > 1000 {
                    return Err(d.error("regexp pattern too long"));
                }
                if pattern.is_empty() {
                    return Err(d.error("regexp pattern cannot be empty"));
                }
                let replacement = arg(&mut d)?;
                ops.push(operation(&pattern, &replacement)?);
            }
            if ops.is_empty() {
                return Err(d.error("multi_regexp filter requires at least one regexp operation"));
            }
            m.insert("operations".into(), ops.into());
        }
        _ => bail!("module caddy.logging.encoders.filter.{name} not registered"),
    }
    let v = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &v)?;
    Ok(v)
}
