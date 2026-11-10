// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, Cost, add, mul},
    globals::Options,
    listeners::Pairing,
    route_build::Counter,
    routes::Route,
    site,
};
use crate::caddyfile_parser::ServerBlock;
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
};

#[derive(Default)]
pub(super) struct Invokes {
    order: Vec<String>,
    seen: BTreeSet<String>,
}
fn lookup_work(name: &str, count: usize) -> Result<u64> {
    let logarithm = u64::BITS as u64 - (count as u64).max(1).leading_zeros() as u64;
    mul(add(name.len() as u64, 1)?, logarithm + 2)
}
impl Invokes {
    pub(super) fn record(&mut self, name: &str, budget: &mut Budget) -> Result<()> {
        budget.work(lookup_work(name, self.seen.len())?)?;
        if self.seen.contains(name) {
            return Ok(());
        }
        budget.materialize(add(mul(name.len() as u64, 2)?, 192)?)?;
        self.seen.insert(name.to_owned());
        self.order.push(name.to_owned());
        Ok(())
    }
    pub(super) fn into_vec(self) -> Vec<String> {
        self.order
    }
    fn len(&self) -> u64 {
        self.order.len() as u64
    }
}
struct NamedRoute {
    value: Value,
    cost: Cost,
    invokes: Vec<String>,
}
#[derive(Default)]
pub(super) struct NamedRoutes {
    routes: BTreeMap<String, NamedRoute>,
    edges: u64,
}
pub(super) fn extract(
    blocks: Vec<ServerBlock>,
    options: &Options,
    budget: &mut Budget,
    cwd: &Path,
) -> Result<(Vec<ServerBlock>, NamedRoutes)> {
    budget.work(blocks.len() as u64)?;
    if !blocks.iter().any(|b| b.is_named_route) {
        return Ok((blocks, NamedRoutes::default()));
    }
    budget.materialize(mul(
        blocks.len() as u64,
        std::mem::size_of::<ServerBlock>() as u64,
    )?)?;
    let mut regular = Vec::with_capacity(blocks.len());
    let mut named = NamedRoutes::default();
    let mut counter = Counter::default();
    let mut tags = BTreeMap::new();
    for mut block in blocks {
        if !block.is_named_route {
            regular.push(block);
            continue;
        }
        if block.segments.is_empty() {
            continue;
        }
        for segment in &mut block.segments {
            super::shorthands::apply(segment, budget)?;
        }
        let whole = if block.segments.len() == 1 {
            block.segments.pop().unwrap()
        } else {
            let n = block.segments.iter().try_fold(0usize, |n, s| {
                n.checked_add(s.len())
                    .ok_or_else(|| anyhow!("Caddyfile named-route token overflow"))
            })?;
            budget.work(n as u64)?;
            budget.materialize(mul(
                n as u64,
                std::mem::size_of::<crate::caddyfile_lexer::Token>() as u64,
            )?)?;
            let mut whole = Vec::with_capacity(n);
            for segment in block.segments {
                whole.extend(segment);
            }
            whole
        };
        let mut invokes = Invokes::default();
        let routes = site::named_route_body(
            &whole,
            options,
            budget,
            &mut counter,
            cwd,
            &mut invokes,
            &mut tags,
        )?;
        let route = simplify(routes, budget)?;
        let key = block
            .keys
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("internal: named route without key"))?
            .text;
        budget.work(lookup_work(&key, named.routes.len())?)?;
        if named.routes.contains_key(&key) {
            bail!("cannot have duplicate named_routes: {key}");
        }
        let (value, cost) = site::serialize_route(&route, budget)?;
        budget.materialize(add(key.len() as u64, 128)?)?;
        named.edges = add(named.edges, invokes.len())?;
        named.routes.insert(
            key,
            NamedRoute {
                value,
                cost,
                invokes: invokes.into_vec(),
            },
        );
    }
    Ok((regular, named))
}
fn simplify(mut routes: Vec<Route>, budget: &mut Budget) -> Result<Route> {
    if routes.len() == 1 && routes[0].matchers.is_empty() {
        // The original deliberately retains only the first handler, even if
        // route consolidation collected multiple handlers into that route.
        let first = routes
            .pop()
            .unwrap()
            .handlers
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("internal: single named-route route without handlers"))?;
        return Ok(Route {
            handlers: vec![first],
            ..Default::default()
        });
    }
    Ok(Route {
        handlers: vec![site::subroute_handler(routes, budget)?],
        ..Default::default()
    })
}
pub(super) fn attach(
    pair: &Pairing,
    sites: &[site::Site],
    named: &NamedRoutes,
    budget: &mut Budget,
) -> Result<Option<Map<String, Value>>> {
    let roots = pair
        .sites
        .iter()
        .try_fold(0u64, |n, e| add(n, sites[e.site].invokes.len() as u64))?;
    if roots == 0 {
        return Ok(None);
    }
    let pops = add(roots, named.edges)?;
    let logarithm = u64::BITS as u64 - (named.routes.len() as u64).max(1).leading_zeros() as u64;
    budget.work(mul(pops, mul(logarithm + 1, 8)?)?)?;
    budget.materialize(add(
        mul(add(pops, 1)?, 64)?,
        mul(named.routes.len() as u64, 128)?,
    )?)?;
    let mut attached: BTreeMap<&str, &NamedRoute> = BTreeMap::new();
    let mut queue = VecDeque::new();
    for entry in &pair.sites {
        for root in &sites[entry.site].invokes {
            queue.clear();
            queue.push_back(root.as_str());
            while let Some(name) = queue.pop_front() {
                budget.work(lookup_work(name, named.routes.len())?)?;
                if attached.contains_key(name) {
                    continue;
                }
                let route = named.routes.get(name).ok_or_else(|| {
                    anyhow!("cannot invoke named route '{name}', which was not defined")
                })?;
                attached.insert(name, route);
                queue.extend(route.invokes.iter().map(String::as_str));
            }
        }
    }
    // All value copies are prepaid before any materialized server entry.
    for (name, route) in &attached {
        budget.copies(route.cost, 3, 9)?;
        budget.materialize(add(name.len() as u64, 128)?)?;
    }
    Ok(Some(
        attached
            .into_iter()
            .map(|(name, r)| (name.to_owned(), r.value.clone()))
            .collect(),
    ))
}
