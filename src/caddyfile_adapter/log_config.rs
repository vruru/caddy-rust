// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, Cost},
    globals::Options,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
pub(super) struct Entry {
    pub name: String,
    pub log: Option<Map<String, Value>>,
    pub hostnames: Vec<String>,
    pub no_hostname: bool,
    pub cost: Cost,
}
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
pub(super) fn parse(
    tokens: &[Token],
    global_names: Option<&mut BTreeSet<String>>,
    counter: &mut usize,
    budget: &mut Budget,
    options: &Options,
) -> Result<Entry> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let global = global_names.is_some();
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut name = if d.next_arg() {
        let n = d.val().to_owned();
        if d.next_arg() {
            return Err(d.arg_err());
        }
        n
    } else if global {
        "default".into()
    } else {
        String::new()
    };
    if let Some(names) = global_names
        && !names.insert(name.clone())
    {
        return Err(d.error(format!("duplicate global log option for: {name}")));
    }
    let mut fields = Map::new();
    let mut hostnames = Vec::new();
    let mut no_hostname = false;
    let mut seen = BTreeSet::new();
    while d.next_block(0) {
        let k = d.val().to_owned();
        if matches!(
            k.as_str(),
            "output" | "sampling" | "core" | "format" | "level" | "no_hostname"
        ) && !seen.insert(k.clone())
        {
            return Err(d.error(format!(
                "'{k}' subdirective specified more than once in the same log block"
            )));
        }
        match k.as_str() {
            "hostnames" => {
                if global {
                    return Err(d.error("hostnames is not allowed in the log global options"));
                }
                let a = d.remaining_args();
                if a.is_empty() {
                    return Err(d.arg_err());
                }
                hostnames.extend(a);
            }
            "output" => {
                let name = arg(&mut d)?;
                let value = if matches!(name.as_str(), "stdout" | "stderr" | "discard") {
                    serde_json::json!({"output":name})
                } else {
                    super::log_writers::parse(&name, &d.next_segment(), budget)?
                };
                fields.insert("writer".into(), value);
            }
            "format" => {
                let name = arg(&mut d)?;
                if let Some(value) =
                    super::log_encoders::parse(&name, &d.next_segment(), budget, options, global)?
                {
                    fields.insert("encoder".into(), value);
                } else {
                    fields.remove("encoder");
                }
            }
            "core" => {
                let name = arg(&mut d)?;
                let _segment = d.next_segment();
                if name != "mock" {
                    bail!("module caddy.logging.cores.{name} not registered");
                }
                fields.insert("core".into(), serde_json::json!({"module":"mock"}));
            }
            "sampling" => {
                let mut s = Dispenser::new(d.next_segment());
                while s.next_arg() {}
                let mut sampling = Map::new();
                let mut seen = BTreeSet::new();
                let nesting = s.nesting();
                while s.next_block(nesting) {
                    let k = s.val().to_owned();
                    if !seen.insert(k.clone()) {
                        return Err(s.error(format!(
                            "'{k}' specified more than once in the same sampling block"
                        )));
                    }
                    match k.as_str() {
                        "interval" => set_i64(
                            &mut sampling,
                            &k,
                            crate::duration::parse_str(&arg(&mut s)?)?,
                        ),
                        "first" | "thereafter" => {
                            set_i64(&mut sampling, &k, arg(&mut s)?.parse::<i64>()?)
                        }
                        _ => return Err(s.error(format!("unrecognized sampling subdirective {k}"))),
                    }
                }
                fields.insert("sampling".into(), sampling.into());
            }
            "level" => {
                set_str(&mut fields, "level", &arg(&mut d)?);
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            "include" | "exclude" => {
                if !global {
                    return Err(d.error(format!("{k} is not allowed in the log directive")));
                }
                append(&mut fields, &k, d.remaining_args());
            }
            "no_hostname" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                no_hostname = true;
            }
            _ => return Err(d.error(format!("unrecognized log subdirective {k}"))),
        }
    }
    // Equality with a zero CustomLog precedes automatic Include mutation.
    let empty = fields.is_empty();
    if !global {
        if name.is_empty() && !empty {
            name = format!("log{counter}");
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| d.error("log counter overflow"))?;
        }
        if !name.is_empty() {
            fields.insert(
                "include".into(),
                vec![Value::String(format!("http.log.access.{name}"))].into(),
            );
        }
    }
    let cost = budget.finish_map(r, &fields)?;
    Ok(Entry {
        name,
        log: if empty { None } else { Some(fields) },
        hostnames,
        no_hostname,
        cost,
    })
}
