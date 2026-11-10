// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{budget::Budget, globals::Options, tls_issuers::set_str};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
fn arg(d: &mut Dispenser) -> Result<String> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(d.val().into())
}
/// None represents a nil JSONModuleObject result, not a literal JSON null.
/// The caller decides whether its RawMessage field is omitted or retains null.
pub(super) fn parse(
    name: &str,
    tokens: &[Token],
    budget: &mut Budget,
    options: &Options,
    global: bool,
) -> Result<Option<Value>> {
    budget.nested(|b| parse_at(name, tokens, b, options, global, true))
}
fn parse_at(
    name: &str,
    tokens: &[Token],
    budget: &mut Budget,
    options: &Options,
    global: bool,
    report_warning: bool,
) -> Result<Option<Value>> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut m = Map::new();
    m.insert("format".into(), name.into());
    let mut fields = Map::new();
    let mut regexps = BTreeMap::<String, Vec<Value>>::new();
    let mut unsupported = None;
    match name {
        "json" | "console" => {
            if d.next_arg() {
                return Err(d.arg_err());
            }
            while d.next_block(0) {
                let k = d.val().to_owned();
                if k == "time_local" {
                    if d.next_arg() {
                        return Err(d.arg_err());
                    }
                    m.insert(k, true.into());
                    continue;
                }
                let a = d.all_args(1).ok_or_else(|| d.arg_err())?;
                match k.as_str() {
                    "message_key" | "level_key" | "time_key" | "name_key" | "caller_key"
                    | "stacktrace_key" | "line_ending" => {
                        m.insert(k, a[0].clone().into());
                    }
                    "time_format" | "duration_format" | "level_format" => {
                        set_str(&mut m, &k, &a[0])
                    }
                    _ => return Err(d.error(format!("unrecognized encoder subdirective {k}"))),
                }
            }
        }
        "journald" | "append" | "filter" => {
            if name == "journald" && d.next_arg() {
                return Err(d.arg_err());
            }
            while d.next_block(0) {
                match d.val() {
                    "wrap" => {
                        let name = arg(&mut d)?;
                        let nested = d.next_segment();
                        // Nested modules pass nil warnings to JSONModuleObject in
                        // Go: serialization failures omit that module but are not
                        // returned as adapter warnings for the outer encoder.
                        let v = budget
                            .nested(|b| parse_at(&name, &nested, b, options, false, false))?;
                        if let Some(v) = v {
                            m.insert("wrap".into(), v);
                        } else {
                            m.remove("wrap");
                        }
                    }
                    "fields" if name != "journald" => {
                        let nesting = d.nesting();
                        while d.next_block(nesting) {
                            field(
                                name,
                                &mut d,
                                &mut fields,
                                &mut regexps,
                                &mut unsupported,
                                budget,
                            )?;
                        }
                    }
                    _ if name != "journald" => field(
                        name,
                        &mut d,
                        &mut fields,
                        &mut regexps,
                        &mut unsupported,
                        budget,
                    )?,
                    _ => {
                        return Err(
                            d.error(format!("unrecognized journald subdirective {}", d.val()))
                        );
                    }
                }
            }
            // Deliberately preserve the original asymmetric duplicate rule: a regexp
            // after a non-regexp overwrites it at finalization; the reverse order errors.
            for (key, mut values) in regexps {
                let value = if values.len() == 1 {
                    values.pop().unwrap()
                } else {
                    let mut operations = Vec::new();
                    for v in values {
                        if operations.len() >= 50 {
                            bail!("cannot add operation: maximum 50 operations allowed");
                        }
                        let cost = budget.measure(&v)?;
                        budget.copies(cost, 1, 2)?;
                        let pattern = v.get("regexp").and_then(Value::as_str).unwrap_or("");
                        let replacement = v.get("value").and_then(Value::as_str).unwrap_or("");
                        operations.push(super::log_filters::operation(pattern, replacement)?);
                    }
                    serde_json::json!({"filter":"multi_regexp","operations":operations})
                };
                fields.insert(key, value);
            }
            if !fields.is_empty() {
                m.insert("fields".into(), fields.into());
            }
        }
        _ => bail!("module caddy.logging.encoders.{name} not registered"),
    }
    if let Some(message) = unsupported {
        let token = tokens.first().ok_or_else(|| d.arg_err())?;
        if global {
            return Err(d.error(format!(
                "warnings found in parsing global log options: {message}"
            )));
        }
        if report_warning {
            options.warn(&token.file, token.line, "log", message, budget)?;
        }
        budget.finish_value(r, &Value::Null)?;
        return Ok(None);
    }
    let v = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &v)?;
    Ok(Some(v))
}
fn field(
    kind: &str,
    d: &mut Dispenser,
    fields: &mut Map<String, Value>,
    regexps: &mut BTreeMap<String, Vec<Value>>,
    unsupported: &mut Option<&'static str>,
    budget: &mut Budget,
) -> Result<()> {
    let key = d.val().to_owned();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    if kind == "append" {
        let value = match d.scalar_val() {
            Ok(v) => v.unwrap_or(Value::Null),
            Err(error) => {
                let Some(n) = crate::caddyfile_parser::scalar::parse_float(d.val())
                    .filter(|v| !v.is_finite())
                else {
                    return Err(error);
                };
                unsupported.get_or_insert(if n.is_nan() {
                    "json: unsupported value: NaN"
                } else if n.is_sign_negative() {
                    "json: unsupported value: -Inf"
                } else {
                    "json: unsupported value: +Inf"
                });
                Value::Null
            }
        };
        fields.insert(key, value);
        if d.next_arg() {
            return Err(d.arg_err());
        }
    } else {
        let filter = d.val().to_owned();
        let value = super::log_filters::parse(&filter, &d.next_segment(), budget)?;
        if filter == "regexp" {
            regexps.entry(key).or_default().push(value);
            return Ok(());
        }
        if regexps.contains_key(&key) {
            return Err(d.error(format!(
                "cannot mix regexp filters with other filter types for field {key}"
            )));
        }
        if fields.contains_key(&key) {
            return Err(d.error(format!("field {key} already has a filter")));
        }
        fields.insert(key, value);
    }
    Ok(())
}
