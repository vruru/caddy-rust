// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, add, mul},
    global_atoms::Atom,
    globals::Options,
    listeners::{self, Pairing},
    site::Site,
    tls_connections::{self, Connection},
};
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

pub(super) struct ServerTls {
    pub connections: Vec<Connection>,
    pub skip: Vec<String>,
}
fn option<'a>(options: &'a Options, name: &str) -> &'a str {
    match options.atoms.get(name) {
        Some(Atom::String(s)) => s,
        _ => "",
    }
}
fn set_string(
    fields: &mut Map<String, Value>,
    name: &str,
    value: &str,
    budget: &mut Budget,
) -> Result<()> {
    budget.materialize(value.len() as u64 + 96)?;
    if value.is_empty() {
        fields.remove(name);
    } else {
        fields.insert(name.into(), value.into());
    }
    Ok(())
}
pub(super) fn hosts(site: &Site, keys: &[usize], budget: &mut Budget) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for &index in keys {
        let host = &site.keys[index].host;
        budget.work(mul(host.len() as u64 + 1, 64)?)?;
        if host.is_empty() {
            return Ok(Vec::new());
        }
        budget.materialize(mul(host.len() as u64 + 96, 2)?)?;
        if seen.insert(host.as_str()) {
            result.push(host.clone());
        }
    }
    Ok(result)
}
fn names(connection: &Connection, budget: &mut Budget) -> Result<Option<Vec<String>>> {
    budget.copies(connection.cost()?, 1, 0)?;
    let fields = connection.fields();
    let Some(values) = fields
        .get("match")
        .and_then(|v| v.get("sni"))
        .and_then(Value::as_array)
    else {
        return Ok(None);
    };
    Ok(Some(
        values
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_owned())
            .collect(),
    ))
}
fn sort_names(names: &mut [String], budget: &mut Budget) -> Result<()> {
    let text = names
        .iter()
        .try_fold(1u64, |n, s| add(n, s.len() as u64 + 1))?;
    let log = 64 - (names.len() as u64).max(1).leading_zeros() as u64;
    budget.work(mul(text, log + 1)?)?;
    names.sort();
    Ok(())
}
fn set_names(cp: &Connection, names: &[String], budget: &mut Budget) -> Result<()> {
    let text = names
        .iter()
        .try_fold(128u64, |n, s| add(n, s.len() as u64 + 96))?;
    budget.materialize(text)?;
    cp.change(budget, |fields, _| {
        fields.insert("match".into(), json!({"sni":names}));
        Ok(())
    })
}
pub(super) fn build(
    pair: &Pairing,
    sites: &[Site],
    options: &Options,
    budget: &mut Budget,
) -> Result<ServerTls> {
    let default = option(options, "default_sni");
    let fallback = option(options, "fallback_sni");
    let http = options.integer("http_port", 80).to_string();
    let https = options.integer("https_port", 443).to_string();
    let mut skip = Vec::new();
    let mut skip_seen = BTreeSet::new();
    let mut connections = Vec::new();
    let mut empty = Vec::new();
    let mut has_catchall = false;
    let mut qualifies = false;
    let mut automatic = !options.strings("auto_https").iter().any(|s| s == "off");
    for entry in &pair.sites {
        let site = &sites[entry.site];
        let mut names = hosts(site, &entry.keys, budget)?;
        if !site.tls.connections.is_empty() {
            for cp in &site.tls.connections {
                // hosts is a shared local slice across all CPs of this block;
                // appending the empty SNI in one iteration affects the next.
                for name in &names {
                    budget.work(name.len() as u64 + 1)?;
                    let field = if name == default {
                        Some(("default_sni", default))
                    } else if name == fallback {
                        Some(("fallback_sni", fallback))
                    } else {
                        None
                    };
                    if let Some((field, value)) = field {
                        budget.materialize(96)?;
                        names.push(String::new());
                        cp.change(budget, |fields, budget| {
                            set_string(fields, field, value, budget)
                        })?;
                        break;
                    }
                }
                if names.is_empty() {
                    cp.change(budget, |fields, budget| {
                        set_string(fields, "default_sni", default, budget)?;
                        set_string(fields, "fallback_sni", fallback, budget)
                    })?;
                } else {
                    sort_names(&mut names, budget)?;
                    set_names(cp, &names, budget)?;
                }
                budget.materialize(64)?;
                if !tls_connections::settings_empty(cp)
                    || (site.tls.force_automate && !names.is_empty())
                {
                    connections.push(cp.clone());
                    has_catchall = names.is_empty();
                } else if !names.is_empty() {
                    empty.push(cp.clone());
                }
            }
        } else {
            names.retain(|s| !s.is_empty() && !s.contains('*'));
            if !names.is_empty() {
                sort_names(&mut names, budget)?;
                let cp = Connection::new(Map::new(), budget)?;
                set_names(&cp, &names, budget)?;
                empty.push(cp);
            }
        }
        for &index in &entry.keys {
            let address = &site.keys[index];
            budget.work(mul(address.host.len() as u64 + 1, 64)?)?;
            if listeners::uses_other_port(&pair.listeners, &http)
                && address.scheme == "http"
                && !address.host.is_empty()
            {
                budget.materialize(mul(address.host.len() as u64 + 96, 2)?)?;
                if skip_seen.insert(address.host.as_str()) {
                    skip.push(address.host.clone());
                }
            }
            let enabled = !site.tls.connections.is_empty()
                || (!address.host.is_empty() && !skip_seen.contains(address.host.as_str()));
            qualifies |= address.scheme == "https"
                || (address.scheme != "http" && address.port != http && enabled);
            automatic &=
                address.port == https || (address.port != http && !address.host.is_empty());
        }
    }
    let mut protocol = None;
    for entry in &pair.sites {
        for &index in &entry.keys {
            let addr = &sites[entry.site].keys[index];
            let next = if addr.scheme == "http" || addr.port == http {
                Some(false)
            } else if addr.scheme == "https" || addr.port == https || !connections.is_empty() {
                Some(true)
            } else if addr.host.is_empty() {
                Some(false)
            } else {
                None
            };
            if let Some(next) = next {
                if protocol.is_some_and(|old| old != next) {
                    bail!("server cannot natively multiplex HTTP and HTTPS");
                }
                if !next && !connections.is_empty() {
                    bail!("server is HTTP, but attempts to configure TLS connection policies");
                }
                protocol = Some(next);
            }
        }
    }
    // Match first covering client-auth wildcard, then insert shields backwards.
    let mut wildcards = Vec::new();
    let mut shields = Vec::<Vec<String>>::new();
    budget.materialize(mul(connections.len() as u64, 128)?)?;
    for cp in &connections {
        let ns = if cp.fields().contains_key("client_authentication") {
            names(cp, budget)?
                .unwrap_or_default()
                .into_iter()
                .filter(|s| s.contains('*'))
                .collect()
        } else {
            Vec::new()
        };
        wildcards.push(ns);
        shields.push(Vec::new());
    }
    for cp in &empty {
        for name in names(cp, budget)?.unwrap_or_default() {
            'cover: for (i, patterns) in wildcards.iter().enumerate() {
                for pattern in patterns {
                    budget.work(mul(name.len() as u64 + 1, pattern.len() as u64 + 1)?)?;
                    if super::subjects::wildcard(&name, pattern) {
                        budget.materialize(name.len() as u64 + 96)?;
                        shields[i].push(name);
                        break 'cover;
                    }
                }
            }
        }
    }
    for (i, mut names) in shields.into_iter().enumerate().rev() {
        if names.is_empty() {
            continue;
        }
        sort_names(&mut names, budget)?;
        names.dedup();
        let cp = connections[i].shallow_copy(budget)?;
        cp.change(budget, |fields, _| {
            fields.remove("client_authentication");
            Ok(())
        })?;
        set_names(&cp, &names, budget)?;
        connections.insert(i, cp);
    }
    if qualifies
        && !has_catchall
        && (!connections.is_empty() || !automatic || !default.is_empty() || !fallback.is_empty())
    {
        let mut fields = Map::new();
        set_string(&mut fields, "default_sni", default, budget)?;
        set_string(&mut fields, "fallback_sni", fallback, budget)?;
        connections.push(Connection::new(fields, budget)?);
    }
    Ok(ServerTls {
        connections: tls_connections::consolidate(connections, budget)?,
        skip,
    })
}
