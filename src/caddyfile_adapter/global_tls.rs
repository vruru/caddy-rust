// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value, json};

pub(super) fn on_demand(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    if d.next_arg() {
        return Err(d.arg_err());
    }
    let mut permission = None;
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val() {
            "ask" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if permission.is_some() {
                    return Err(
                        d.error("on-demand TLS permission module (or 'ask') already specified")
                    );
                }
                permission = Some(super::module_value::normalize(
                    json!({"module":"http","endpoint":d.val()}),
                )?);
            }
            "permission" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if permission.is_some() {
                    return Err(
                        d.error("on-demand TLS permission module (or 'ask') already specified")
                    );
                }
                let name = d.val().to_owned();
                if name != "http" {
                    return Err(d.error(format!("getting module named 'tls.permission.{name}': module not registered: tls.permission.{name}")));
                }
                let mut module = Dispenser::new(d.next_segment());
                module.next();
                let args = module.all_args(1).ok_or_else(|| module.arg_err())?;
                permission = Some(super::module_value::normalize(
                    json!({"module":"http","endpoint":args[0]}),
                )?);
            }
            "interval" | "burst" => return Err(d.error(format!(
                "the on_demand_tls '{}' option is no longer supported, remove it from your config",
                d.val()
            ))),
            _ => return Err(d.error(format!("unrecognized parameter '{}'", d.val()))),
        }
    }
    let permission = permission
        .ok_or_else(|| d.error("expected at least one config parameter for on_demand_tls"))?;
    Ok(Value::Object(Map::from_iter([(
        "permission".into(),
        permission,
    )])))
}

pub(super) fn ech(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let names = d.remaining_args();
    if names.is_empty() {
        return Err(d.arg_err());
    }
    let nesting = d.nesting();
    if d.next_block(nesting) {
        if d.val() != "dns" {
            return Err(d.error(format!("ech: unrecognized subdirective '{}'", d.val())));
        }
        // Match the original whole-token step, including its line-boundary
        // behavior. This fixed standard module set has no DNS providers.
        if !d.next() {
            return Err(d.arg_err());
        }
        let name = d.val();
        return Err(d.error(format!("getting module named 'dns.providers.{name}': module not registered: dns.providers.{name}")));
    }
    Ok(
        json!({"configs":names.into_iter().map(|name|json!({"public_name":name})).collect::<Vec<_>>()}),
    )
}
