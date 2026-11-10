// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, Reservation, add, mul},
    globals::Options,
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

pub(super) fn parse(
    tokens: &[Token],
    budget: &mut Budget,
    reservation: Reservation,
    options: &Options,
) -> Result<Value> {
    // An additional real scan identifies output-matrix amplification before
    // allocating padded rows. Pay its complete token/metadata copies first.
    budget.tokens(tokens, 8)?;
    let mut scan = Dispenser::new(tokens.to_vec());
    scan.next();
    while scan.next_arg() {}
    let mut rows = 0u64;
    while scan.next_block(0) {
        rows = add(rows, 1)?;
        while scan.next_arg() {}
    }
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let source = d.val().to_owned();
    let destinations = d.remaining_args();
    if destinations.is_empty() {
        return Err(d.error("missing destination argument(s)"));
    }
    for destination in &destinations {
        budget.work(mul(add(destination.len() as u64, 1)?, 40)?)?;
        if let Some(shorthand) = super::shorthands::destination_conflict(destination) {
            return Err(d.error(format!(
                "destination {shorthand} conflicts with a Caddyfile placeholder shorthand"
            )));
        }
    }
    let cells = mul(destinations.len() as u64, rows)?;
    budget.work(mul(cells, 128)?)?;
    let reservation = budget.extend_reservation(reservation, mul(cells, 256)?)?;
    let mut defaults: Vec<String> = Vec::new();
    let mut mappings = Vec::new();
    let mut unsupported = None;
    while d.next_block(0) {
        if d.val() == "default" {
            if !defaults.is_empty() {
                return Err(d.error("defaults already defined"));
            }
            defaults = d.remaining_args();
            defaults.resize(defaults.len().max(destinations.len()), String::new());
            continue;
        }
        let input = d.val().to_owned();
        let mut outputs = Vec::new();
        while d.next_arg() {
            let value = match d.scalar_val() {
                Ok(value) => value.unwrap_or(Value::Null),
                Err(error) => {
                    let Some(number) = crate::caddyfile_parser::scalar::parse_float(d.val())
                        .filter(|n| !n.is_finite())
                    else {
                        return Err(error);
                    };
                    // The original JSONModuleObject converts a non-finite
                    // output into one warning and a null handler, after all
                    // Caddyfile parsing and its errors have completed.
                    unsupported.get_or_insert(if number.is_nan() {
                        "json: unsupported value: NaN"
                    } else if number.is_sign_negative() {
                        "json: unsupported value: -Inf"
                    } else {
                        "json: unsupported value: +Inf"
                    });
                    Value::Null
                }
            };
            outputs.push(if value.as_str() == Some("-") {
                Value::Null
            } else {
                value
            });
        }
        if outputs.len() > destinations.len() {
            return Err(d.error("too many outputs"));
        }
        outputs.resize(destinations.len(), Value::Null);
        let mut mapping = Map::new();
        if let Some(regex) = input.strip_prefix('~') {
            if !regex.is_empty() {
                mapping.insert("input_regexp".into(), regex.into());
            }
        } else if !input.is_empty() {
            mapping.insert("input".into(), input.into());
        }
        mapping.insert("outputs".into(), Value::Array(outputs));
        mappings.push(Value::Object(mapping));
    }
    let value = if let Some(message) = unsupported {
        options.warn("", 0, "map", message, budget)?;
        Value::Null
    } else {
        let mut handler = Map::new();
        handler.insert("handler".into(), "map".into());
        if !source.is_empty() {
            handler.insert("source".into(), source.into());
        }
        handler.insert("destinations".into(), destinations.into());
        if !mappings.is_empty() {
            handler.insert("mappings".into(), Value::Array(mappings));
        }
        if !defaults.is_empty() {
            handler.insert("defaults".into(), defaults.into());
        }
        super::module_value::normalize(Value::Object(handler))?
    };
    budget.finish_value(reservation, &value)?;
    Ok(value)
}
