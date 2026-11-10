// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    Warning,
    address::Address,
    budget::{Budget, add, mul},
    globals::Options,
    listeners::{self, Pairing},
    route_build,
    route_build::Counter,
    routes::Route,
    site,
};
use crate::caddyfile_parser::ServerBlock;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub(super) fn setup(
    mut blocks: Vec<ServerBlock>,
    budget: &mut Budget,
    warnings: &mut Vec<Warning>,
    cwd: &std::path::Path,
) -> Result<Value> {
    for block in &blocks {
        for (j, key) in block.keys.iter().enumerate() {
            if j == 0 && key.text.starts_with('@') {
                bail!(
                    "{}:{}: cannot define a matcher outside a site block",
                    key.file,
                    key.line
                );
            }
            if super::order::REGISTERED_DIRECTIVES.contains(&key.text.as_str()) {
                bail!(
                    "{}:{}: known directive parsed as site address; directives must appear in a site block",
                    key.file,
                    key.line
                );
            }
        }
    }
    let mut options = Options::new();
    if blocks.first().is_some_and(|b| b.keys.is_empty()) {
        let global = blocks.remove(0);
        options.parse(&global.segments, budget)?;
    }
    let (blocks, named) = super::named_routes::extract(blocks, &options, budget, cwd)?;
    let mut sites = Vec::new();
    let mut counter = Counter::default();
    let mut state = site::State::default();
    for mut block in blocks {
        if block.keys.is_empty() {
            bail!("global configuration must be the first block");
        }
        for segment in &mut block.segments {
            super::shorthands::apply(segment, budget)?;
        }
        let keys = block
            .keys
            .into_iter()
            .map(|k| {
                budget.work(mul(k.text.len() as u64 + 1, 32)?)?;
                budget.materialize(add(mul(k.text.len() as u64, 32)?, 512)?)?;
                Address::parse(&k.text).map(|a| a.normalized())
            })
            .collect::<Result<Vec<_>>>()?;
        sites.push(site::parse(
            keys,
            &block.segments,
            &options,
            budget,
            &mut counter,
            cwd,
            &mut state,
        )?);
    }
    let mut pairings = listeners::pairings(&sites, &options, budget)?;
    let mut staged_servers = Vec::new();
    for pair in &mut pairings {
        staged_servers.push(server(
            pair,
            &mut sites,
            &options,
            &named,
            budget,
            &mut counter,
        )?);
    }
    // The original server map holds pointers to CPs shared by split site
    // blocks. Encode only after all pairings have performed their mutations.
    let mut servers = Map::new();
    for (i, (mut server, connections)) in staged_servers.into_iter().enumerate() {
        if !connections.is_empty() {
            let values = connections
                .iter()
                .map(|cp| cp.render(budget).map(Value::Object))
                .collect::<Result<Vec<_>>>()?;
            server.insert("tls_connection_policies".into(), Value::Array(values));
        }
        servers.insert(format!("srv{i}"), Value::Object(server));
    }
    let server_metrics = super::global_servers::apply(&mut servers, &options.servers, budget)?;
    // No parsed option may disappear simply because the next adapter family
    // is still pending. This gate is removed only with its physical assembly.
    for name in options.atoms.keys() {
        if ![
            "debug",
            "http_port",
            "https_port",
            "grace_period",
            "shutdown_delay",
            "persist_config",
            "auto_https",
            "skip_install_trust",
            "storage_check",
            "storage_clean_interval",
            "renew_interval",
            "ocsp_interval",
            "tls_resolvers",
            "tls_automate_names",
            "local_certs",
            "key_type",
            "ocsp_stapling",
            "renewal_window_ratio",
            "email",
            "acme_ca",
            "acme_ca_root",
            "acme_dns",
            "cert_lifetime",
            "default_sni",
            "fallback_sni",
        ]
        .contains(&name.as_str())
        {
            bail!(
                "Caddyfile option {name} was parsed but its application assembly is not implemented"
            );
        }
    }
    let mut config = Map::new();
    options.top(&mut config, budget)?;
    if let Some(logging) = super::log_assembly::top(&pairings, &sites, &options, budget)? {
        config.insert("logging".into(), logging);
    } else {
        config.remove("logging");
    }
    let mut apps = Map::new();
    if let Some(events) = &options.events {
        let cost = budget.measure(events)?;
        budget.copies(cost, 1, 2)?;
        apps.insert("events".into(), events.clone());
    }
    if !servers.is_empty() {
        if let Some(metrics) = &options.metrics {
            let cost = budget.measure(metrics)?;
            budget.copies(cost, 1, 2)?;
        }
        let mut http = options.http(servers);
        if let Some(mut metric) = server_metrics {
            if http
                .get("metrics")
                .and_then(|m| m.get("per_host"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                metric
                    .as_object_mut()
                    .unwrap()
                    .insert("per_host".into(), true.into());
            }
            http.insert("metrics".into(), metric);
        }
        apps.insert("http".into(), Value::Object(http));
    }
    let tls = super::tls_defaults::build(&sites, &pairings, &options, budget)?;
    if let Some(tls) = super::tls_settings::apply(tls, &options, budget)? {
        apps.insert("tls".into(), tls);
    }
    if let Some(pki) = options.pki_app(budget, &pairings, &sites)? {
        apps.insert("pki".into(), pki);
    }
    if !apps.is_empty() {
        config.insert("apps".into(), Value::Object(apps));
    }
    warnings.append(options.diagnostics.get_mut());
    Ok(Value::Object(config))
}
fn server(
    pair: &mut Pairing,
    sites: &mut [site::Site],
    options: &Options,
    named: &super::named_routes::NamedRoutes,
    budget: &mut Budget,
    counter: &mut Counter,
) -> Result<(Map<String, Value>, Vec<super::tls_connections::Connection>)> {
    let mut server = Map::new();
    let key_count = pair
        .sites
        .iter()
        .try_fold(0u64, |n, entry| add(n, entry.keys.len() as u64))?;
    let key_logarithm = 64 - key_count.max(1).leading_zeros() as u64;
    for entry in &pair.sites {
        for &key in &entry.keys {
            let address = &sites[entry.site].keys[key];
            let text = add(
                address.original.len() as u64,
                add(address.host.len() as u64, address.path.len() as u64)?,
            )?;
            budget.work(mul(text + 1, mul(key_logarithm + 1, 8)?)?)?;
            budget.materialize(128)?;
        }
    }
    for (address, protocols) in &pair.listeners {
        budget.materialize(add(mul(address.len() as u64, 2)?, 256)?)?;
        for protocol in protocols {
            budget.materialize(add(mul(protocol.len() as u64, 2)?, 128)?)?;
        }
    }
    if !pair.listeners.is_empty() {
        server.insert(
            "listen".into(),
            Value::Array(
                pair.listeners
                    .iter()
                    .map(|(a, _)| Value::String(a.clone()))
                    .collect(),
            ),
        );
    }
    if pair
        .listeners
        .iter()
        .any(|(_, p)| p.iter().any(|p| !p.is_empty()))
    {
        server.insert(
            "listen_protocols".into(),
            Value::Array(
                pair.listeners
                    .iter()
                    .map(|(_, p)| {
                        if p.iter().all(String::is_empty) {
                            Value::Null
                        } else {
                            json!(p)
                        }
                    })
                    .collect(),
            ),
        );
    }
    if let Some(auto) = options.auto_https() {
        server.insert("automatic_https".into(), auto);
    }
    let mut seen = BTreeMap::new();
    for r in &pair.sites {
        for &k in &r.keys {
            let key = &sites[r.site].keys[k].original;
            if let Some(previous) = seen.insert(key, r.site)
                && previous != r.site
            {
                bail!("ambiguous site definition: {key}");
            }
        }
    }
    // This mutates the pairing itself, as Go's slice sort does; TLS and
    // logging assembly later observe this same ordered block list.
    let n = pair.sites.len() as u64;
    let logarithm = 64 - n.max(1).leading_zeros() as u64;
    budget.work(mul(mul(n, logarithm + 1)?, 64)?)?;
    budget.materialize(mul(n, 128)?)?;
    let mut ranked = Vec::new();
    for entry in std::mem::take(&mut pair.sites) {
        let mut size = 0;
        for &key in &entry.keys {
            let address = &sites[entry.site].keys[key];
            size = add(
                size,
                add(address.host.len() as u64, address.path.len() as u64 + 16)?,
            )?;
        }
        budget.work(mul(size, 8)?)?;
        let score = specificity(&sites[entry.site], &entry.keys);
        ranked.push((entry, score));
    }
    super::stable_sort::stable_sort(&mut ranked, |(_, a), (_, b)| {
        if !a.0 {
            return false;
        }
        if !b.0 {
            return true;
        }
        if a.1 != b.1 {
            return a.1;
        }
        if a.2 == b.2 {
            return a.3 > b.3;
        }
        a.2 > b.2
    });
    pair.sites = ranked.into_iter().map(|(entry, _)| entry).collect();
    if let Some(logging) = super::log_assembly::server(pair, sites, budget)? {
        server.insert("logs".into(), logging);
    }
    let tls = super::tls_server::build(pair, sites, options, budget)?;
    if !tls.skip.is_empty() {
        let auto = server.entry("automatic_https").or_insert_with(|| json!({}));
        auto.as_object_mut()
            .unwrap()
            .insert("skip".into(), json!(tls.skip));
    }
    if let Some(routes) = super::named_routes::attach(pair, sites, named, budget)? {
        server.insert("named_routes".into(), Value::Object(routes));
    }
    let mut routes = Vec::new();
    let mut errors: Option<Vec<Route>> = None;
    let single_site = pair.sites.len() == 1;
    for r in &pair.sites {
        sort_error_pile(&mut sites[r.site], budget)?;
        let site = &sites[r.site];
        let matches = site_matchers(site, &r.keys, budget)?;
        let error_matches = if site.errors.is_empty() {
            None
        } else {
            Some(clone_matchers(&matches, budget)?)
        };
        budget.copies(site.cost, 3, 9)?;
        let children =
            route_build::build(site.values.clone(), counter, Some(&options.order), budget)?;
        append_site_routes(&mut routes, matches, children, single_site);
        if let (Some(matches), Some(cost)) = (error_matches, site.errors_cost) {
            budget.copies(cost, 3, 9)?;
            let children = site.errors.iter().map(|e| e.route.clone()).collect();
            append_site_routes(
                errors.get_or_insert_with(Vec::new),
                matches,
                children,
                single_site,
            );
        }
    }
    let routes = route_build::consolidate(routes);
    if !routes.is_empty() {
        server.insert("routes".into(), serde_json::to_value(routes)?);
    }
    if let Some(errors) = errors {
        let mut config = Map::new();
        if !errors.is_empty() {
            config.insert("routes".into(), serde_json::to_value(errors)?);
        }
        server.insert("errors".into(), Value::Object(config));
    }
    Ok((server, tls.connections))
}

fn append_site_routes(
    list: &mut Vec<Route>,
    matchers: Vec<Map<String, Value>>,
    mut children: Vec<Route>,
    single_site: bool,
) {
    let host = children
        .iter()
        .any(|r| r.matchers.iter().any(|m| m.contains_key("host")));
    if matchers.is_empty() && single_site && !host {
        list.append(&mut children);
    } else if !matchers.is_empty() || !children.is_empty() {
        let handlers = if children.is_empty() {
            Vec::new()
        } else {
            vec![json!({"handler":"subroute","routes":children})]
        };
        list.push(Route {
            matchers,
            handlers,
            terminal: true,
            ..Default::default()
        });
    }
}
fn sort_error_pile(site: &mut site::Site, budget: &mut Budget) -> Result<()> {
    let n = site.errors.len() as u64;
    if n == 0 {
        return Ok(());
    }
    let log = (u64::BITS - n.leading_zeros() + 1) as u64;
    budget.work(mul(mul(n, log)?, mul(log, 4)?)?)?;
    // Literal non-strict Go comparator. The shared pile is sorted again for
    // every pairing; first server output is already an independent route list.
    super::stable_sort::stable_sort(&mut site.errors, |a, b| a.matched() || !b.matched());
    Ok(())
}
fn clone_matchers(
    matchers: &[Map<String, Value>],
    budget: &mut Budget,
) -> Result<Vec<Map<String, Value>>> {
    for matcher in matchers {
        let cost = budget.measure_map(matcher)?;
        budget.copies(cost, 1, 9)?;
    }
    Ok(matchers.to_vec())
}

fn specificity(site: &site::Site, keys: &[usize]) -> (bool, bool, usize, usize) {
    fn score(s: &str) -> usize {
        let mut n = s.len().saturating_sub(s.matches('*').count());
        let mut rest = s;
        while let Some(start) = rest.find('{') {
            let Some(end) = rest[start..].find('}') else {
                break;
            };
            n = n.saturating_sub(end + 1);
            rest = &rest[start + end + 1..];
        }
        n
    }
    let host = keys
        .iter()
        .map(|k| score(&site.keys[*k].host))
        .max()
        .unwrap_or(0);
    let wildcard = keys
        .iter()
        .any(|k| site.keys[*k].host.is_empty() || site.keys[*k].host.contains('*'));
    let mut path = "";
    let mut path_score = 0;
    for k in keys {
        let candidate = site.keys[*k].path.as_str();
        let candidate_score = score(candidate);
        if candidate_score > path_score {
            path = candidate;
            path_score = candidate_score;
        }
    }
    (host > 0, !wildcard, host, path.len())
}
fn site_matchers(
    site: &site::Site,
    keys: &[usize],
    budget: &mut Budget,
) -> Result<Vec<Map<String, Value>>> {
    let logarithm = 64 - (keys.len() as u64).max(1).leading_zeros() as u64;
    for &key in keys {
        let address = &site.keys[key];
        let bytes = add(address.host.len() as u64, address.path.len() as u64)?;
        budget.work(mul(bytes + 1, mul(logarithm + 1, 8)?)?)?;
        budget.materialize(mul(add(bytes, 128)?, 4)?)?;
    }
    let mut groups: Vec<(&str, Vec<&str>, BTreeSet<&str>)> = Vec::new();
    let mut indices = BTreeMap::new();
    let mut catchall = false;
    for k in keys {
        let addr = &site.keys[*k];
        let index = *indices.entry(addr.path.as_str()).or_insert_with(|| {
            groups.push((addr.path.as_str(), Vec::new(), BTreeSet::new()));
            groups.len() - 1
        });
        if addr.host.is_empty() && !catchall {
            groups[index].1.clear();
            groups[index].2.clear();
            catchall = true;
        }
        if !catchall && groups[index].2.insert(addr.host.as_str()) {
            groups[index].1.push(addr.host.as_str());
        }
    }
    Ok(groups
        .into_iter()
        .filter_map(|(path, hosts, _)| {
            let mut map = Map::new();
            if !hosts.is_empty() {
                map.insert("host".into(), json!(hosts));
            }
            if !path.is_empty() {
                map.insert("path".into(), json!([path]));
            }
            if map.is_empty() { None } else { Some(map) }
        })
        .collect())
}
