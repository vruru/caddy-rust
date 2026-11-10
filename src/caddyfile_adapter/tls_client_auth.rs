// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{budget::Budget, tls_issuers::set_str, tls_pem, tls_sources};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};
use std::path::Path;

pub(super) fn parse(tokens: &[Token], cwd: &Path, budget: &mut Budget) -> Result<Value> {
    let reservation = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    while d.next_arg() {}
    let nesting = d.nesting();
    let mut fields = Map::new();
    let mut roots = Vec::<String>::new();
    let mut leaves = Vec::<String>::new();
    let mut verifiers = Vec::new();
    while d.next_block(nesting) {
        match d.val() {
            "mode" => {
                if d.count_remaining_args() > 1 || !d.next_arg() {
                    return Err(d.arg_err());
                }
                set_str(&mut fields, "mode", d.val());
            }
            "trusted_ca_cert" | "trusted_ca_cert_file" => {
                let file = d.val() == "trusted_ca_cert_file";
                if fields.contains_key("ca") {
                    return Err(d.error("cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'"));
                }
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if file {
                    roots.extend(
                        tls_pem::read_certificates(d.val(), cwd, budget)
                            .map_err(|e| d.error(e.to_string()))?,
                    );
                } else {
                    roots.push(d.val().to_owned());
                }
            }
            "trusted_leaf_cert" | "trusted_leaf_cert_file" => {
                let file = d.val() == "trusted_leaf_cert_file";
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if file {
                    leaves.extend(
                        tls_pem::read_certificates(d.val(), cwd, budget)
                            .map_err(|e| d.error(e.to_string()))?,
                    );
                } else {
                    leaves.push(d.val().to_owned());
                }
            }
            "trust_pool" => {
                if !roots.is_empty() {
                    return Err(d.error("cannot specify both 'trust_pool' and 'trusted_ca_cert' or 'trusted_ca_cert_file'"));
                }
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let name = d.val().to_owned();
                let value = tls_sources::pool(&name, &d.next_segment(), budget)?;
                fields.insert("ca".into(), super::module_value::normalize(value)?);
            }
            "verifier" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let name = d.val().to_owned();
                if name != "leaf" {
                    return Err(d.error(format!("getting module named 'tls.client_auth.verifier.{name}': module not registered: tls.client_auth.verifier.{name}")));
                }
                verifiers.push(leaf_verifier(&d.next_segment(), budget)?);
            }
            _ => return Err(d.error(format!("unknown subdirective for client_auth: {}", d.val()))),
        }
    }
    // File bytes are separately prepaid by read_certificates; their output can
    // exceed the token-only leaf reservation and is measured before wrapping.
    let external = !roots.is_empty() || !leaves.is_empty();
    if !roots.is_empty() {
        // This module contains only string fields/lists, so it already has
        // the normalized JSON shape without another encode/decode or clone.
        fields.insert(
            "ca".into(),
            Value::Object(Map::from_iter([
                ("provider".into(), "inline".into()),
                ("trusted_ca_certs".into(), strings(roots)),
            ])),
        );
    }
    if !leaves.is_empty() {
        fields.insert("trusted_leaf_certs".into(), strings(leaves));
    }
    if !verifiers.is_empty() {
        fields.insert("verifiers".into(), Value::Array(verifiers));
    }
    if external {
        let cost = budget.measure_map(&fields)?;
        budget.copies(cost, 1, 0)?;
    } else {
        budget.finish_map(reservation, &fields)?;
    }
    Ok(Value::Object(fields))
}
fn strings(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}
fn leaf_verifier(tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    let reservation = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next_arg();
    let mut loaders = Vec::new();
    // The original one-line form selects a loader only with at least two
    // remaining arguments. A lone argument is deliberately not reinterpreted.
    if d.count_remaining_args() > 1 {
        d.next_arg();
        let name = d.val().to_owned();
        loaders.push(leaf_loader(&name, &d.next_segment())?);
    } else {
        let nesting = d.nesting();
        while d.next_block(nesting) {
            let name = d.val().to_owned();
            loaders.push(leaf_loader(&name, &d.next_segment())?);
        }
    }
    let mut fields = Map::new();
    fields.insert("verifier".into(), "leaf".into());
    if !loaders.is_empty() {
        fields.insert("leaf_certs_loaders".into(), Value::Array(loaders));
    }
    budget.finish_map(reservation, &fields)?;
    super::module_value::normalize(Value::Object(fields))
}
fn leaf_loader(name: &str, tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next_arg();
    let key = match name {
        "file" => "files",
        "folder" => "folders",
        "pem" => "certificates",
        "storage" => return Err(d.error("module tls.leaf_cert_loader.storage is not a Caddyfile unmarshaler")),
        _ => return Err(d.error(format!("getting module named 'tls.leaf_cert_loader.{name}': module not registered: tls.leaf_cert_loader.{name}"))),
    };
    let values = d.remaining_args();
    let mut fields = Map::new();
    fields.insert("loader".into(), name.into());
    if !values.is_empty() {
        fields.insert(key.into(), strings(values));
    }
    super::module_value::normalize(Value::Object(fields))
}
