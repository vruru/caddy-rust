// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! ACME-server Caddyfile configuration only: provisioning/signing is separate.
use super::{
    budget::Budget,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};
fn arg(d: &mut Dispenser) -> Result<String> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(d.val().into())
}
fn append(m: &mut Map<String, Value>, key: &str, values: Vec<String>) {
    if !values.is_empty() {
        m.entry(key)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .extend(values.into_iter().map(Value::String));
    }
}
pub(super) fn parse(tokens: &[Token], budget: &mut Budget) -> Result<(Value, Option<String>)> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    if d.next_arg() {
        return Err(d.arg_err());
    }
    let mut m = Map::new();
    m.insert("handler".into(), "acme_server".into());
    let mut ca = None;
    while d.next_block(0) {
        let k = d.val().to_owned();
        match k.as_str() {
            "ca" => {
                let a = d.all_args(1).ok_or_else(|| d.arg_err())?;
                set_str(&mut m, &k, &a[0]);
                ca = Some(a[0].clone());
            }
            "lifetime" => set_i64(&mut m, &k, crate::duration::parse_str(&arg(&mut d)?)?),
            "resolvers" => {
                let a = d.remaining_args();
                if a.is_empty() {
                    return Err(d.error("must specify at least one resolver address"));
                }
                m.insert(k, a.into_iter().map(Value::String).collect());
            }
            "challenges" => append(&mut m, &k, d.remaining_args()),
            "allow_wildcard_names" => {
                m.entry("policy")
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .unwrap()
                    .insert(k, true.into());
            }
            "allow" | "deny" => {
                let mut rule = Map::new();
                let nest = d.nesting();
                while d.next_block(nest) {
                    if d.count_remaining_args() == 0 {
                        return Err(d.arg_err());
                    }
                    let name = d.val().to_owned();
                    if !matches!(name.as_str(), "domains" | "ip_ranges") {
                        return Err(d.error(format!("unrecognized '{k}' subdirective: {name}")));
                    }
                    append(&mut rule, &name, d.remaining_args());
                }
                m.entry("policy")
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .unwrap()
                    .insert(k, rule.into());
            }
            "sign_with_root" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                m.insert(k, true.into());
            }
            _ => return Err(d.error(format!("unrecognized ACME server directive: {k}"))),
        }
    }
    let value = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &value)?;
    Ok((value, ca))
}
