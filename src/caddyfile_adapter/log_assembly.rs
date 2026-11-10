// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, Cost, add},
    globals::Options,
    listeners::Pairing,
    site::Site,
};
use anyhow::Result;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
fn hosts(site: &Site, keys: &[usize], budget: &mut Budget) -> Result<(bool, Vec<String>)> {
    let mut catch = false;
    let mut result = BTreeSet::new();
    for &key in keys {
        let a = &site.keys[key];
        budget.work(a.host.len() as u64 + 1)?;
        if a.host.is_empty() {
            catch = true;
            continue;
        }
        budget.materialize(a.host.len() as u64 + a.port.len() as u64 + 128)?;
        result.insert(if !a.port.is_empty() && a.port != "80" && a.port != "443" {
            super::proxy_addresses::join_host(&a.host, &a.port)
        } else {
            a.host.clone()
        });
    }
    Ok((catch, result.into_iter().collect()))
}
pub(super) fn server(pair: &Pairing, sites: &[Site], budget: &mut Budget) -> Result<Option<Value>> {
    if !pair.sites.iter().any(|p| !sites[p.site].logs.is_empty()) {
        return Ok(None);
    }
    let mut m = Map::new();
    let mut names = BTreeMap::<String, Vec<String>>::new();
    let mut skips = Vec::new();
    for p in &pair.sites {
        let site = &sites[p.site];
        let (catch, hosts) = hosts(site, &p.keys, budget)?;
        for log in &site.logs {
            budget.work(1)?;
            if log.no_hostname {
                continue;
            }
            if catch && log.hostnames.is_empty() {
                budget.materialize(log.name.len() as u64 + 64)?;
                if log.name.is_empty() {
                    m.remove("default_logger_name");
                } else {
                    m.insert("default_logger_name".into(), log.name.clone().into());
                }
            } else {
                let sources = if log.hostnames.is_empty() {
                    &hosts
                } else {
                    &log.hostnames
                };
                for source in sources {
                    budget.work(source.len() as u64 + 1)?;
                    budget
                        .materialize(add(add(source.len() as u64, log.name.len() as u64)?, 160)?)?;
                    let key = if log.hostnames.is_empty() {
                        let (host, _, error) = super::address::split_host_port(source);
                        if error.is_some() {
                            source.clone()
                        } else {
                            host
                        }
                    } else {
                        source.clone()
                    };
                    let comparisons = 65 - (names.len() as u64 + 1).leading_zeros() as u64;
                    budget.work(super::budget::mul(key.len() as u64 + 1, comparisons)?)?;
                    names.entry(key).or_default().push(log.name.clone());
                }
            }
        }
        if site.logs.is_empty() {
            if catch {
                m.insert("skip_unmapped_hosts".into(), true.into());
            }
            for host in hosts {
                budget.materialize(host.len() as u64 + 64)?;
                skips.push(Value::String(host));
            }
        }
    }
    if !names.is_empty() {
        let mut values = Map::new();
        for (k, v) in names {
            let value = v.into_iter().map(Value::String).collect();
            values.insert(k, value);
        }
        m.insert("logger_names".into(), values.into());
    }
    if !skips.is_empty() {
        let logarithm = 64 - (skips.len() as u64).max(1).leading_zeros() as u64;
        let bytes = skips.iter().try_fold(0u64, |sum, v| {
            add(sum, v.as_str().map_or(1, |s| s.len() as u64 + 1))
        })?;
        budget.work(super::budget::mul(bytes, logarithm + 1)?)?;
        skips.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        m.insert("skip_hosts".into(), skips.into());
    }
    Ok(Some(m.into()))
}
pub(super) fn top(
    pairings: &[Pairing],
    sites: &[Site],
    options: &Options,
    budget: &mut Budget,
) -> Result<Option<Value>> {
    let mut logs = Vec::<(&str, Option<&Map<String, Value>>, Cost)>::new();
    let mut has_default = false;
    for e in &options.logs {
        if !e.name.is_empty() {
            has_default |= e.name == "default";
            budget.materialize(64)?;
            logs.push((&e.name, e.log.as_ref(), e.cost));
        }
    }
    let debug = options.atoms.contains_key("debug");
    let synthetic = serde_json::json!({"level":"DEBUG"});
    if debug && !has_default {
        budget.materialize(192)?;
        logs.push((
            "default",
            synthetic.as_object(),
            budget.measure(&synthetic)?,
        ));
    }
    for p in pairings {
        for s in &p.sites {
            for e in &sites[s.site].logs {
                if !e.name.is_empty() {
                    budget.materialize(e.name.len() as u64 + 64)?;
                    logs.push((&e.name, e.log.as_ref(), e.cost));
                }
            }
        }
    }
    let mut rendered = Map::new();
    for (name, log, cost) in &logs {
        if *name == "default"
            && let Some(log) = log
        {
            rendered.insert("default".into(), copy(log, *cost, debug, budget)?);
            break;
        }
    }
    let mut excludes = BTreeSet::new();
    if let Some(existing) = rendered
        .get("default")
        .and_then(|v| v.get("exclude"))
        .and_then(Value::as_array)
    {
        for v in existing {
            if let Some(s) = v.as_str() {
                budget.materialize(s.len() as u64 + 64)?;
                excludes.insert(s.to_owned());
            }
        }
    }
    let mut deduplicate_excludes = false;
    for (name, log, cost) in logs {
        if name == "default" {
            continue;
        }
        let Some(log) = log else { continue };
        budget.materialize(name.len() as u64 + 64)?;
        rendered.insert(name.into(), copy(log, cost, debug, budget)?);
        if let Some(includes) = log
            .get("include")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty())
        {
            deduplicate_excludes = true;
            for value in includes {
                if let Some(value) = value.as_str() {
                    budget.work(value.len() as u64 + 32)?;
                    budget.materialize(value.len() as u64 + 64)?;
                    excludes.insert(value.to_owned());
                }
            }
        }
    }
    if deduplicate_excludes && !excludes.is_empty() {
        let default = rendered
            .entry("default")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .unwrap();
        default.insert(
            "exclude".into(),
            excludes.into_iter().map(Value::String).collect(),
        );
    }
    if rendered.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::json!({"logs":rendered})))
}
fn copy(
    fields: &Map<String, Value>,
    cost: Cost,
    debug: bool,
    budget: &mut Budget,
) -> Result<Value> {
    budget.copies(cost, 1, 3)?;
    let mut m = fields.clone();
    if debug && !m.contains_key("level") {
        budget.materialize(128)?;
        m.insert("level".into(), "DEBUG".into());
    }
    Ok(m.into())
}
