// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::Budget,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
fn arg(d: &mut Dispenser) -> Result<String> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(d.val().into())
}
pub(super) fn policy(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    budget.nested(|b| policy_at(name, tokens, b))
}
fn policy_at(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    let mut m = Map::new();
    m.insert("policy".into(), name.into());
    if name != "cookie" {
        d.next();
    }
    match name {
        "random" | "least_conn" | "round_robin" | "first" | "ip_hash" | "client_ip_hash"
        | "uri_hash" => {
            if d.next_arg() {
                return Err(d.arg_err());
            }
        }
        "weighted_round_robin" => {
            let a = d.remaining_args();
            if a.is_empty() {
                return Err(d.arg_err());
            }
            let mut w = Vec::new();
            for a in a {
                let n = a.parse::<i64>()?;
                if n < 0 {
                    bail!("weight must be non-negative");
                }
                w.push(Value::from(n));
            }
            m.insert("weights".into(), w.into());
        }
        "random_choose" => {
            set_i64(&mut m, "choose", arg(&mut d)?.parse::<i64>()?);
        }
        "query" | "header" => {
            set_str(
                &mut m,
                if name == "query" { "key" } else { "field" },
                &arg(&mut d)?,
            );
            fallbacks(&mut m, &mut d, budget, false)?;
        }
        "cookie" => {
            let a = d.remaining_args();
            match a.as_slice() {
                [_] => {}
                [_, n] => set_str(&mut m, "name", n),
                [_, n, s] => {
                    set_str(&mut m, "name", n);
                    set_str(&mut m, "secret", s);
                }
                _ => return Err(d.arg_err()),
            }
            fallbacks(&mut m, &mut d, budget, true)?;
        }
        _ => bail!("module http.reverse_proxy.selection_policies.{name} not registered"),
    }
    let v = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &v)?;
    Ok(v)
}
fn fallbacks(
    m: &mut Map<String, Value>,
    d: &mut Dispenser,
    b: &mut Budget,
    cookie: bool,
) -> Result<()> {
    while d.next_block(0) {
        match d.val() {
            "fallback" => {
                let name = arg(d)?;
                if m.contains_key("fallback") {
                    return Err(d.error("fallback selection policy already specified"));
                }
                let v = policy(&name, &d.next_segment(), b)?;
                m.insert("fallback".into(), v);
            }
            "max_age" if cookie => {
                let v = arg(d)?;
                if m.contains_key("max_age") {
                    return Err(d.error("cookie max_age already specified"));
                }
                let n = crate::duration::parse_str(&v)?;
                if n <= 0 {
                    return Err(d.error("max_age must be positive"));
                }
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                set_i64(m, "max_age", n);
            }
            _ => return Err(d.error(format!("unrecognized option {}", d.val()))),
        }
    }
    Ok(())
}
pub(super) fn dynamic(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    budget.nested(|b| dynamic_at(name, tokens, b))
}
fn dynamic_at(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut m = Map::new();
    m.insert("source".into(), name.into());
    match name {
        "multi" => {
            if d.next_arg() {
                return Err(d.arg_err());
            }
            let mut sources = Vec::new();
            while d.next_block(0) {
                let name = d.val().to_owned();
                sources.push(dynamic(&name, &d.next_segment(), budget)?);
            }
            if !sources.is_empty() {
                m.insert("sources".into(), sources.into());
            }
        }
        "srv" | "a" => {
            let a = d.remaining_args();
            if a.len() > if name == "srv" { 1 } else { 2 } {
                return Err(d.arg_err());
            }
            if let Some(v) = a.first() {
                set_str(&mut m, "name", v);
            }
            if let Some(v) = a.get(1) {
                set_str(&mut m, "port", v);
            }
            while d.next_block(0) {
                let k = d.val().to_owned();
                match k.as_str() {
                    "name" | "port" | "service" | "proto"
                        if k == "name"
                            || name == "a" && k == "port"
                            || name == "srv" && matches!(k.as_str(), "service" | "proto") =>
                    {
                        let v = arg(&mut d)?;
                        if m.contains_key(&k) {
                            return Err(d.error(format!("{name} {k} has already been specified")));
                        }
                        set_str(&mut m, &k, &v);
                    }
                    "refresh" | "dial_timeout" | "dial_fallback_delay" => {
                        set_i64(&mut m, &k, crate::duration::parse_str(&arg(&mut d)?)?);
                    }
                    "grace_period" if name == "srv" => {
                        set_i64(&mut m, &k, crate::duration::parse_str(&arg(&mut d)?)?);
                    }
                    "resolvers" => {
                        let a = d.remaining_args();
                        if a.is_empty() {
                            return Err(d.arg_err());
                        }
                        m.insert("resolver".into(), json!({"addresses":a}));
                    }
                    "versions" if name == "a" => {
                        let a = d.remaining_args();
                        if a.is_empty() {
                            return Err(d.arg_err());
                        }
                        let versions = m
                            .entry("versions")
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .unwrap();
                        for a in a {
                            if !matches!(a.as_str(), "ipv4" | "ipv6") {
                                return Err(d.error(format!("unsupported version {a}")));
                            }
                            versions.insert(a, true.into());
                        }
                    }
                    _ => return Err(d.error(format!("unrecognized {name} option {k}"))),
                }
            }
        }
        _ => bail!("module http.reverse_proxy.upstreams.{name} not registered"),
    }
    let v = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &v)?;
    Ok(v)
}
