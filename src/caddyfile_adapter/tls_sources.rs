// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::Budget,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};

pub(super) fn manager(name: &str, tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut fields = Map::new();
    match name {
        "tailscale" => {
            if d.next_arg() {
                return Err(d.arg_err());
            }
        }
        "http" => {
            if !d.next_arg() {
                return Err(d.arg_err());
            }
            set_str(&mut fields, "url", d.val());
            if d.next_arg() {
                return Err(d.arg_err());
            }
            if d.next_block(0) {
                return Err(d.error("block not allowed here"));
            }
        }
        _ => {
            return Err(d.error(format!(
                "getting module named 'tls.get_certificate.{name}': module not registered"
            )));
        }
    }
    fields.insert("via".into(), name.into());
    Ok(Value::Object(fields))
}

pub(super) fn storage(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    if !d.next() {
        return Err(d.error("expected tokens"));
    }
    if d.val() != "file_system" {
        return Err(d.error(format!(
            "getting module named 'caddy.storage.{}': module not registered: caddy.storage.{}",
            d.val(),
            d.val()
        )));
    }
    let mut root = String::new();
    if d.next_arg() {
        root = d.val().to_owned();
    }
    if d.next_arg() {
        return Err(d.arg_err());
    }
    while d.next_block(0) {
        if d.val() != "root" {
            return Err(d.error(format!("unrecognized parameter '{}'", d.val())));
        }
        if !d.next_arg() {
            return Err(d.arg_err());
        }
        if !root.is_empty() {
            return Err(d.error("root already set"));
        }
        root = d.val().to_owned();
        if d.next_arg() {
            return Err(d.arg_err());
        }
    }
    if root.is_empty() {
        return Err(d.error("missing root path (to use default, omit storage config entirely)"));
    }
    Ok(serde_json::json!({"module":"file_system","root":root}))
}

pub(super) fn pool(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    pool_at(name, tokens, 0, budget)
}

// Nested combined pools and HTTP pool CA sources share one bounded stack.
// The caller reserves the complete input-token expansion before entering.
fn pool_at(name: &str, tokens: &[Token], depth: usize, budget: &mut Budget) -> Result<Value> {
    if depth >= 64 {
        bail!("Caddyfile certificate pool nesting limit exceeded");
    }
    let reservation = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut fields = Map::new();
    match name {
        "inline" | "file" | "pki_root" | "pki_intermediate" => {
            if name == "inline" && d.count_remaining_args() > 0 {
                return Err(d.arg_err());
            }
            let mut values = if name == "inline" {
                Vec::new()
            } else {
                d.remaining_args()
            };
            let (sub, key, error) = match name {
                "inline" => ("trust_der", "trusted_ca_certs", "no certificates specified"),
                "file" => ("pem_file", "pem_files", "no certificates specified"),
                _ => ("authority", "authority", "no authorities specified"),
            };
            let nesting = if matches!(name, "inline" | "file") {
                0
            } else {
                d.nesting()
            };
            while d.next_block(nesting) {
                if d.val() != sub {
                    return Err(d.error(format!("unrecognized directive: {}", d.val())));
                }
                values.extend(d.remaining_args());
            }
            if values.is_empty() {
                return Err(d.error(error));
            }
            fields.insert(key.into(), strings(values));
        }
        "system" => {
            if d.count_remaining_args() > 0 {
                return Err(d.arg_err());
            }
            if d.next_block(0) {
                return Err(d.error("system trust pool does not support any configuration"));
            }
        }
        "storage" => {
            let mut keys = d.remaining_args();
            let nesting = d.nesting();
            while d.next_block(nesting) {
                match d.val() {
                    "storage" => {
                        if fields.contains_key("storage") {
                            return Err(d.error("storage module already set"));
                        }
                        if !d.next_arg() {
                            return Err(d.arg_err());
                        }
                        let value = storage(&d.next_segment())?;
                        fields.insert("storage".into(), super::module_value::normalize(value)?);
                    }
                    "keys" => keys.extend(d.remaining_args()),
                    _ => return Err(d.error(format!("unrecognized directive: {}", d.val()))),
                }
            }
            if !keys.is_empty() {
                fields.insert("pem_keys".into(), strings(keys));
            }
        }
        "http" => {
            let mut endpoints = d.remaining_args();
            let nesting = d.nesting();
            while d.next_block(nesting) {
                match d.val() {
                    "endpoints" => {
                        if d.count_remaining_args() == 0 {
                            return Err(d.arg_err());
                        }
                        endpoints.extend(d.remaining_args());
                    }
                    "tls" => {
                        if fields.contains_key("tls") {
                            return Err(d.error("tls block already defined"));
                        }
                        fields.insert("tls".into(), pool_tls(&mut d, depth, budget)?);
                    }
                    _ => return Err(d.error(format!("unrecognized directive: {}", d.val()))),
                }
            }
            if !endpoints.is_empty() {
                fields.insert("endpoints".into(), strings(endpoints));
            }
        }
        "combined" => {
            if d.count_remaining_args() > 0 {
                return Err(d.arg_err());
            }
            let nesting = d.nesting();
            let mut sources = Vec::new();
            while d.next_block(nesting) {
                if d.val() != "source" {
                    return Err(d.error(format!("unrecognized directive: {}", d.val())));
                }
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let name = d.val().to_owned();
                let value = pool_at(&name, &d.next_segment(), depth + 1, budget)?;
                sources.push(super::module_value::normalize(value)?);
            }
            if sources.is_empty() {
                return Err(d.error("no sources specified"));
            }
            fields.insert("sources".into(), Value::Array(sources));
        }
        _ => {
            return Err(d.error(format!(
                "getting module named 'tls.ca_pool.source.{name}': module not registered"
            )));
        }
    }
    fields.insert("provider".into(), name.into());
    budget.finish_map(reservation, &fields)?;
    Ok(Value::Object(fields))
}
fn strings(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}
fn pool_tls(d: &mut Dispenser, depth: usize, budget: &mut Budget) -> Result<Value> {
    let mut fields = Map::new();
    let nesting = d.nesting();
    while d.next_block(nesting) {
        match d.val() {
            "ca" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let name = d.val().to_owned();
                let value = pool_at(&name, &d.next_segment(), depth + 1, budget)?;
                fields.insert("ca".into(), super::module_value::normalize(value)?);
            }
            "insecure_skip_verify" => {
                fields.insert("insecure_skip_verify".into(), true.into());
            }
            "handshake_timeout" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let duration = crate::duration::parse_str(d.val())?;
                set_i64(&mut fields, "handshake_timeout", duration);
            }
            "server_name" | "renegotiation" => {
                let field = d.val().to_owned();
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let value = d.val();
                if field == "renegotiation" && !["never", "once", "freely"].contains(&value) {
                    return Err(d.error("unrecognized renegotiation level: "));
                }
                set_str(&mut fields, &field, value);
            }
            _ => return Err(d.error(format!("unrecognized directive: {}", d.val()))),
        }
    }
    Ok(Value::Object(fields))
}
