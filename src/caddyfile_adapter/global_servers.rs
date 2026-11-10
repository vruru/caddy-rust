// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Global server configuration adaptation; module provisioning is separate.
use super::{
    budget::{Budget, Cost, add, mul},
    tls_issuers::set_i64,
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
pub(super) struct Settings {
    pub listener: String,
    name: String,
    fields: Map<String, Value>,
    cost: Cost,
    metrics: Option<Value>,
    credentials: bool,
    trace: bool,
}
fn arg(d: &mut Dispenser) -> Result<String> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(d.val().into())
}
fn no_args(d: &mut Dispenser) -> Result<()> {
    if d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(())
}
fn array(m: &mut Map<String, Value>, key: &str, a: Vec<String>) {
    if !a.is_empty() {
        m.insert(key.into(), a.into_iter().map(Value::String).collect());
    } else {
        m.remove(key);
    }
}
fn append(m: &mut Map<String, Value>, key: &str, a: Vec<String>) {
    if !a.is_empty() {
        m.entry(key)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .extend(a.into_iter().map(Value::String));
    }
}
pub(super) fn parse(tokens: &[Token], budget: &mut Budget) -> Result<Settings> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut listener = String::new();
    if d.next_arg() {
        listener = d.val().into();
        no_args(&mut d)?;
    }
    let mut name = String::new();
    let mut m = Map::new();
    let mut metrics = None;
    let mut credentials = false;
    let mut trace = false;
    while d.next_block(0) {
        let k = d.val().to_owned();
        match k.as_str() {
            "name" => {
                if listener.is_empty() {
                    return Err(
                        d.error("cannot set a name for a server without a listener address")
                    );
                }
                name = arg(&mut d)?;
            }
            "listener_wrappers" | "packet_conn_wrappers" => {
                let nest = d.nesting();
                while d.next_block(nest) {
                    let n = d.val().to_owned();
                    if k == "packet_conn_wrappers" {
                        bail!("module caddy.packetconns.{n} not registered");
                    }
                    let value = wrapper(&n, &d.next_segment(), budget)?;
                    m.entry(k.clone())
                        .or_insert_with(|| Value::Array(Vec::new()))
                        .as_array_mut()
                        .unwrap()
                        .push(value);
                }
            }
            "timeouts" => {
                let nest = d.nesting();
                while d.next_block(nest) {
                    let n = d.val().to_owned();
                    match n.as_str() {
                        "read_body_idle" | "write_idle" => {
                            let a = d.remaining_args();
                            if !(1..=2).contains(&a.len()) {
                                return Err(d.arg_err());
                            }
                            let prefix = if n == "read_body_idle" {
                                "read"
                            } else {
                                "write"
                            };
                            set_i64(
                                &mut m,
                                &format!("{prefix}_idle_timeout"),
                                crate::duration::parse_str(&a[0])?,
                            );
                            if let Some(rate) = a.get(1) {
                                set_i64(
                                    &mut m,
                                    &format!("{prefix}_min_rate"),
                                    rate.parse::<i64>()?,
                                );
                            }
                        }
                        "write_max_chunk" => {
                            let a = d.all_args(1).ok_or_else(|| d.arg_err())?;
                            let v = super::handler_limits::parse_size(&a[0])?;
                            set_i64(&mut m, "max_write_chunk", v as i64);
                        }
                        "read_body" | "read_header" | "write" | "idle" => {
                            let key = match n.as_str() {
                                "read_body" => "read_timeout",
                                "read_header" => "read_header_timeout",
                                "write" => "write_timeout",
                                _ => "idle_timeout",
                            };
                            set_i64(&mut m, key, crate::duration::parse_str(&arg(&mut d)?)?);
                        }
                        _ => return Err(d.error(format!("unrecognized timeouts option '{n}'"))),
                    }
                }
            }
            "keepalive_interval" | "keepalive_idle" => {
                set_i64(&mut m, &k, crate::duration::parse_str(&arg(&mut d)?)?)
            }
            "keepalive_count" => set_i64(&mut m, &k, arg(&mut d)?.parse::<i32>()? as i64),
            "max_header_size" => {
                let a = d.all_args(1).ok_or_else(|| d.arg_err())?;
                set_i64(
                    &mut m,
                    "max_header_bytes",
                    super::handler_limits::parse_size(&a[0])? as i64,
                );
            }
            "enable_full_duplex" | "trusted_proxies_unix" => {
                no_args(&mut d)?;
                m.insert(k, true.into());
            }
            "expected_underscore_headers" | "expected_dot_headers" => {
                let a = d.remaining_args();
                if a.is_empty() {
                    return Err(d.arg_err());
                }
                array(&mut m, &k, a);
            }
            "log_credentials" => {
                no_args(&mut d)?;
                credentials = true;
            }
            "trace" => {
                no_args(&mut d)?;
                trace = true;
            }
            "protocols" | "client_ip_headers" => {
                let values = d.remaining_args();
                let entry = m
                    .entry(k.clone())
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .unwrap();
                for value in values {
                    if k == "protocols" && !matches!(value.as_str(), "h1" | "h2" | "h2c" | "h3") {
                        return Err(d.error(format!(
                            "unknown protocol '{value}': expected h1, h2, h2c, or h3"
                        )));
                    }
                    if entry.iter().any(|v| v.as_str() == Some(value.as_str())) {
                        return Err(d.error(format!("{k} {value} specified more than once")));
                    }
                    entry.push(value.into());
                }
                if entry.is_empty() {
                    m.remove(&k);
                }
                let nest = d.nesting();
                if d.next_block(nest) {
                    return Err(d.arg_err());
                }
            }
            "strict_sni_host" => {
                let enabled = if d.next_arg() {
                    match d.val() {
                        "on" => true,
                        "insecure_off" => false,
                        _ => {
                            return Err(d.error("strict_sni_host only supports on or insecure_off"));
                        }
                    }
                } else {
                    true
                };
                m.insert("strict_sni_host".into(), enabled.into());
            }
            "trusted_proxies" => {
                let n = arg(&mut d)?;
                if n != "static" {
                    bail!("module http.ip_sources.{n} not registered");
                }
                let mut sub = Dispenser::new(d.next_segment());
                sub.next();
                let mut ranges = Vec::new();
                for a in sub.remaining_args() {
                    if a == "private_ranges" {
                        ranges.extend(
                            [
                                "192.168.0.0/16",
                                "172.16.0.0/12",
                                "10.0.0.0/8",
                                "127.0.0.1/8",
                                "fd00::/8",
                                "::1",
                            ]
                            .into_iter()
                            .map(str::to_owned),
                        );
                    } else {
                        ranges.push(a);
                    }
                }
                let mut source = Map::new();
                source.insert("source".into(), "static".into());
                array(&mut source, "ranges", ranges);
                m.insert("trusted_proxies".into(), source.into());
            }
            "trusted_proxies_strict" => {
                no_args(&mut d)?;
                m.insert(k, 1.into());
            }
            "metrics" => {
                let mut metric = Map::new();
                let nest = d.nesting();
                while d.next_block(nest) {
                    if d.val() != "per_host" {
                        return Err(d.error(format!("unrecognized metrics option '{}'", d.val())));
                    }
                    metric.insert("per_host".into(), true.into());
                }
                metrics = Some(Value::Object(metric));
            }
            "0rtt" => {
                if arg(&mut d)? != "off" {
                    return Err(d.error("0rtt only supports off"));
                }
                m.insert("allow_0rtt".into(), false.into());
            }
            _ => return Err(d.error(format!("unrecognized servers option '{k}'"))),
        }
    }
    let cost = budget.finish_map(r, &m)?;
    Ok(Settings {
        listener,
        name,
        fields: m,
        cost,
        metrics,
        credentials,
        trace,
    })
}
fn wrapper(name: &str, tokens: &[Token], budget: &mut Budget) -> Result<Value> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut m = Map::new();
    m.insert("wrapper".into(), name.into());
    match name {
        "tls" | "http_redirect" => {}
        "proxy_protocol" => {
            let mut d = Dispenser::new(tokens.to_vec());
            d.next();
            no_args(&mut d)?;
            while d.next_block(0) {
                let k = d.val().to_owned();
                match k.as_str() {
                    "timeout" => set_i64(&mut m, &k, crate::duration::parse_str(&arg(&mut d)?)?),
                    "allow" | "deny" => append(&mut m, &k, d.remaining_args()),
                    "fallback_policy" => {
                        let policy = arg(&mut d)?.to_uppercase();
                        if !matches!(
                            policy.as_str(),
                            "IGNORE" | "USE" | "REJECT" | "REQUIRE" | "SKIP"
                        ) {
                            return Err(d.error("invalid proxy protocol fallback policy"));
                        }
                        if policy == "IGNORE" {
                            m.remove(&k);
                        } else {
                            m.insert(k, policy.into());
                        }
                    }
                    _ => return Err(d.arg_err()),
                }
            }
        }
        _ => bail!("module caddy.listeners.{name} not registered"),
    }
    let v = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &v)?;
    Ok(v)
}
pub(super) fn apply(
    servers: &mut Map<String, Value>,
    options: &[Settings],
    budget: &mut Budget,
) -> Result<Option<Value>> {
    let mut entries = Vec::new();
    let mut listeners = BTreeSet::new();
    let mut names = BTreeSet::new();
    for entry in options {
        budget.work(entry.listener.len() as u64 + entry.name.len() as u64 + 1)?;
        budget.materialize(add(
            entry.listener.len() as u64,
            entry.name.len() as u64 + 128,
        )?)?;
        let logarithm = 65 - (entries.len() as u64 + 1).leading_zeros() as u64;
        budget.work(mul(
            add(entry.listener.len() as u64, entry.name.len() as u64 + 1)?,
            logarithm,
        )?)?;
        if !listeners.insert(entry.listener.as_str()) {
            bail!(
                "cannot have 'servers' global options with duplicate listener addresses: {}",
                entry.listener
            );
        }
        if !entry.name.is_empty() && !names.insert(entry.name.as_str()) {
            bail!("cannot use duplicate server name '{}'", entry.name);
        }
        entries.push(entry);
    }
    budget.materialize(mul(entries.len() as u64, 16)?)?;
    let n = entries.len() as u64;
    let logarithm = 64 - n.max(1).leading_zeros() as u64;
    budget.work(mul(mul(n, logarithm + 1)?, 64)?)?;
    super::pdqsort::sort_by(&mut entries, |a, b| a.listener.len() > b.listener.len());
    let mut replacements = BTreeMap::new();
    for (key, server) in servers.iter_mut() {
        let s = server.as_object_mut().unwrap();
        let mut selected = None;
        for entry in &entries {
            let listeners = s
                .get("listen")
                .and_then(Value::as_array)
                .map_or(0, Vec::len) as u64;
            budget.work(mul(entry.listener.len() as u64 + 1, listeners + 1)?)?;
            if entry.listener.is_empty()
                || s.get("listen")
                    .and_then(Value::as_array)
                    .is_some_and(|list| {
                        list.iter()
                            .any(|v| v.as_str() == Some(entry.listener.as_str()))
                    })
            {
                selected = Some(*entry);
                break;
            }
        }
        if let Some(entry) = selected {
            budget.copies(entry.cost, 1, 2)?;
            s.extend(entry.fields.clone());
            for (k, enabled) in [
                ("should_log_credentials", entry.credentials),
                ("trace", entry.trace),
            ] {
                if enabled {
                    budget.materialize(128)?;
                    s.entry("logs")
                        .or_insert_with(|| Value::Object(Map::new()))
                        .as_object_mut()
                        .unwrap()
                        .insert(k.into(), true.into());
                }
            }
            if !entry.name.is_empty() {
                budget.materialize(key.len() as u64 + entry.name.len() as u64 + 128)?;
                replacements.insert(key.clone(), entry.name.clone());
            }
            if let Some(m) = &entry.metrics {
                budget.materialize(192)?;
                s.insert("metrics".into(), m.clone());
            }
        }
    }
    // Go iterates this replacement map without an order guarantee. Deterministic
    // key ordering is one permitted order, including the original self-name removal.
    for (old, new) in replacements {
        if let Some(value) = servers.remove(&old) {
            servers.insert(new.clone(), value);
        } else {
            servers.insert(new.clone(), Value::Null);
        }
        if old == new {
            servers.remove(&old);
        }
    }
    let mut metric = None;
    for server in servers.values_mut() {
        let Some(server) = server.as_object_mut() else {
            bail!("server name replacements produced a null server");
        };
        if let Some(m) = server.remove("metrics") {
            let per_host = m.get("per_host").and_then(Value::as_bool).unwrap_or(false);
            let target = metric.get_or_insert_with(Map::new);
            if per_host {
                target.insert("per_host".into(), true.into());
            }
        }
    }
    Ok(metric.map(Value::Object))
}
