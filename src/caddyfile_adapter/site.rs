// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, Cost, Reservation},
    builtin_state::{self, Bind},
    globals::Options,
    named_matchers::{self, Definitions},
    route_build::{self, Counter},
    routes::{Route, RouteKind, RouteValue},
};
use crate::{
    caddyfile_lexer::Token,
    caddyfile_parser::{Dispenser, Segment},
};
use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
/// This bound covers the fixed leaf parsers' copied dispensers, JSON
/// normalization buffers and bounded per-token object/string expansion. It is
/// deliberately cumulative, not a retained-allocation/RSS measurement.
pub(super) fn reserve_helper(tokens: &[Token], budget: &mut Budget) -> Result<Reservation> {
    budget.tokens(tokens, 8)?;
    let mut bytes = 1024u64;
    for token in tokens {
        budget.work(token.text.len() as u64)?;
        bytes = bytes
            .checked_add(
                (token.text.len() as u64)
                    .checked_mul(64)
                    .and_then(|n| n.checked_add(2048))
                    .ok_or_else(|| anyhow!("Caddyfile helper estimate overflow"))?,
            )
            .ok_or_else(|| anyhow!("Caddyfile helper estimate overflow"))?;
    }
    budget.reserve_value(bytes)
}
pub(super) struct Site {
    pub keys: Vec<super::address::Address>,
    pub binds: Vec<Bind>,
    pub values: Vec<RouteValue>,
    pub cost: Cost,
    pub tls: super::tls_site::SiteTls,
}
struct Scope {
    defs: Definitions,
    costs: BTreeMap<String, Cost>,
    files: Arc<Vec<String>>,
    cwd: Arc<PathBuf>,
}
impl Scope {
    fn new(files: Vec<String>, cwd: &Path) -> Self {
        Self {
            defs: Definitions::new(),
            costs: BTreeMap::new(),
            files: Arc::new(files),
            cwd: Arc::new(cwd.to_owned()),
        }
    }
    fn copied(&self, budget: &mut Budget) -> Result<Self> {
        debug_assert!(self.defs.keys().eq(self.costs.keys()));
        // Each of the two maps owns its own key String. Charge each copy
        // explicitly; matcher payload is copied only by defs.clone().
        for name in self.defs.keys() {
            budget.work(name.len() as u64 + 1)?;
            budget.materialize(name.len() as u64 + 96)?;
        }
        for (name, cost) in &self.costs {
            budget.work(name.len() as u64 + 1)?;
            budget.materialize(name.len() as u64 + 96)?;
            budget.copies(*cost, 1, 0)?;
        }
        Ok(Self {
            defs: self.defs.clone(),
            costs: self.costs.clone(),
            files: self.files.clone(),
            cwd: self.cwd.clone(),
        })
    }
    fn pre_extract(&self, tokens: &[Token], budget: &mut Budget) -> Result<()> {
        // Use the same line/import metadata semantics as the owned Dispenser.
        budget.tokens(tokens, 1)?;
        let mut d = Dispenser::new(tokens.to_vec());
        d.next();
        if tokens
            .first()
            .is_some_and(|t| matches!(t.text.as_str(), "root" | "rewrite"))
            && d.count_remaining_args() == 1
        {
            return Ok(());
        }
        if d.next_arg()
            && let Some(cost) = self.costs.get(d.val())
        {
            budget.copies(*cost, 1, 4)?;
        }
        Ok(())
    }
}
pub(super) fn parse(
    keys: Vec<super::address::Address>,
    segments: &[Segment],
    options: &Options,
    budget: &mut Budget,
    counter: &mut Counter,
    cwd: &Path,
    tags: &mut BTreeMap<String, String>,
) -> Result<Site> {
    let tls = super::tls_site::parse(segments, tags, options, cwd, budget)?;
    let mut file_set = BTreeSet::new();
    for segment in segments {
        for token in segment {
            budget.work(1)?;
            file_set.insert(token.file.as_str());
        }
    }
    for file in &file_set {
        budget.materialize(file.len() as u64 + 64)?;
    }
    let mut scope = Scope::new(file_set.into_iter().map(str::to_owned).collect(), cwd);
    let mut binds = Vec::new();
    let values = parse_segments(
        segments,
        &mut scope,
        options,
        budget,
        counter,
        Some(&mut binds),
    )?;
    let count = values
        .iter()
        .map(|v| match &v.value {
            RouteKind::Route(_) => 1,
        })
        .sum::<usize>();
    budget.materialize(
        (count as u64)
            .checked_mul(std::mem::size_of::<&Route>() as u64)
            .ok_or_else(|| anyhow!("Caddyfile route reference overflow"))?,
    )?;
    let references = values
        .iter()
        .flat_map(|v| match &v.value {
            RouteKind::Route(r) => std::slice::from_ref(r),
        })
        .collect::<Vec<_>>();
    let bound = route_bound(references.iter().copied(), budget, 0)?;
    let reservation = budget.reserve_value(bound)?;
    let value = serde_json::to_value(&references)?;
    let cost = budget.finish_value(reservation, &value)?;
    Ok(Site {
        keys,
        binds,
        values,
        cost,
        tls,
    })
}
fn route_bound<'a>(
    routes: impl IntoIterator<Item = &'a Route>,
    budget: &mut Budget,
    extra: usize,
) -> Result<u64> {
    let mut bytes = 64u64;
    for route in routes {
        bytes = bytes
            .checked_add(512 + route.group.len() as u64)
            .ok_or_else(|| anyhow!("Caddyfile route size overflow"))?;
        for matcher in &route.matchers {
            let cost = budget.measure_map(matcher)?;
            budget.copies(cost, 0, 3 + extra)?;
            bytes = bytes
                .checked_add(cost.bytes)
                .ok_or_else(|| anyhow!("Caddyfile route size overflow"))?;
        }
        for h in &route.handlers {
            let cost = budget.measure(h)?;
            budget.copies(cost, 0, 3 + extra)?;
            bytes = bytes
                .checked_add(cost.bytes)
                .ok_or_else(|| anyhow!("Caddyfile route size overflow"))?;
        }
    }
    Ok(bytes)
}
fn parse_segments(
    segments: &[Segment],
    scope: &mut Scope,
    options: &Options,
    budget: &mut Budget,
    counter: &mut Counter,
    mut binds: Option<&mut Vec<Bind>>,
) -> Result<Vec<RouteValue>> {
    for seg in segments {
        if let Some(first) = seg.first()
            && first.text.starts_with('@')
        {
            let cost = named_matchers::parse_definition(seg, &mut scope.defs, budget)?;
            scope.costs.insert(first.text.clone(), cost);
        }
    }
    let mut result = Vec::new();
    for seg in segments {
        let Some(first) = seg.first() else { continue };
        let name = first.text.as_str();
        if name.starts_with('@') {
            continue;
        }
        if !super::order::REGISTERED_DIRECTIVES.contains(&name) {
            bail!(
                "{}:{}: unrecognized directive: {name}",
                first.file,
                first.line
            );
        }
        if name == "tls" {
            if binds.is_none() {
                bail!(
                    "tls directive returned something other than an HTTP route; only handler directives can be used in routes"
                );
            }
            continue;
        }
        if name == "try_files" {
            result.extend(super::handler_try_files::parse(seg, budget, counter)?);
            continue;
        }
        if name == "bind" {
            let destination=binds.as_deref_mut().ok_or_else(||anyhow!("bind directive returned something other than an HTTP route; only handler directives can be used in routes"))?;
            let reservation = reserve_helper(seg, budget)?;
            destination.push(builtin_state::bind(seg, false)?);
            budget.finish_value(reservation, &Value::Null)?;
            continue;
        }
        if name == "header" || name == "request_header" {
            scope.pre_extract(seg, budget)?;
            let reservation = reserve_helper(seg, budget)?;
            let (matcher, tokens) = named_matchers::extract(seg, &scope.defs)?;
            let handlers = super::handler_headers::parse(name, &tokens)?;
            let serialized = serde_json::to_value(&handlers)?;
            budget.finish_value(reservation, &serialized)?;
            if let Some(matcher) = &matcher {
                let cost = budget.measure_map(matcher)?;
                budget.copies(cost, handlers.len() as u64, 3)?;
            }
            for handler in handlers {
                let route = Route {
                    matchers: matcher.clone().into_iter().collect(),
                    handlers: vec![handler],
                    ..Default::default()
                };
                record_route(&mut result, name, route, budget)?;
            }
            continue;
        }
        scope.pre_extract(seg, budget)?;
        let mut reservation = Some(reserve_helper(seg, budget)?);
        let route = if name == "rewrite" {
            rewrite(seg, &scope.defs, budget)?
        } else if name == "root" {
            let root = builtin_state::root(seg, &scope.defs)?;
            if let Some(handler) = root.route.handlers.first() {
                budget.finish_value(reservation.take().unwrap(), handler)?;
            }
            root.route
        } else {
            let (matcher, tokens) = named_matchers::extract(seg, &scope.defs)?;
            let handler = if name == "route" || name == "handle" || name == "handle_path" {
                let children = block_segments(&tokens, budget)?;
                let mut nested = scope.copied(budget)?;
                let values = budget.nested(|budget| {
                    parse_segments(&children, &mut nested, options, budget, counter, None)
                })?;
                let order = if name == "route" {
                    None
                } else {
                    Some(options.order.as_slice())
                };
                let mut routes = route_build::build(values, counter, order, budget)?;
                if name == "handle_path" {
                    let path = seg.get(1).map(|t| t.text.as_str()).unwrap_or("");
                    if !path.starts_with('/') {
                        bail!("handle_path path matcher must begin with '/' ");
                    }
                    let strip = path
                        .strip_suffix("/*")
                        .or_else(|| path.strip_suffix('*'))
                        .unwrap_or(path);
                    let mut handler = serde_json::Map::new();
                    handler.insert("handler".into(), "rewrite".into());
                    if !strip.is_empty() {
                        handler.insert("strip_path_prefix".into(), strip.into());
                    }
                    routes.insert(
                        0,
                        Route {
                            handlers: vec![Value::Object(handler)],
                            ..Default::default()
                        },
                    );
                }
                subroute_handler(routes, budget)?
            } else if let Some(v) = super::handler_atoms::parse(name, &tokens)? {
                v
            } else if let Some(v) = super::handler_rewrite::parse(name, &tokens)? {
                v
            } else if let Some(value) = super::handler_limits::parse(name, &tokens)? {
                value
            } else if let Some(value) = super::handler_misc::parse(name, &tokens)? {
                value
            } else if let Some(value) = super::handler_observe::parse(name, &tokens)? {
                value
            } else if name == "encode" {
                super::handler_encode::parse(&tokens)?
            } else if name == "file_server" {
                let mut value = super::handler_files::parse(&tokens)?;
                budget.finish_value(reservation.take().unwrap(), &value)?;
                super::file_finalize::apply(&mut value, &scope.files, &scope.cwd, budget)?;
                value
            } else if name == "redir" {
                super::handler_redir::parse(&tokens)?
            } else {
                bail!("Caddyfile directive {name} is registered but not implemented");
            };
            if !["route", "handle", "handle_path", "file_server"].contains(&name) {
                budget.finish_value(reservation.take().unwrap(), &handler)?;
            }
            Route {
                matchers: matcher.into_iter().collect(),
                handlers: vec![handler],
                ..Default::default()
            }
        };
        if let Some(reservation) = reservation {
            budget.finish_value(reservation, &Value::Null)?;
        }
        record_route(&mut result, name, route, budget)?;
    }
    Ok(result)
}
fn record_route(
    result: &mut Vec<RouteValue>,
    name: &str,
    route: Route,
    budget: &mut Budget,
) -> Result<()> {
    let size = route_bound(std::slice::from_ref(&route), budget, 0)?;
    // Route is retained; only its serialization is a temporary owned copy.
    let reservation = budget.reserve_value(size)?;
    let value = serde_json::to_value(&route)?;
    budget.finish_value(reservation, &value)?;
    result.push(RouteValue {
        directive: if name == "handle_path" {
            "handle".into()
        } else {
            name.into()
        },
        value: RouteKind::Route(route),
    });
    Ok(())
}
fn block_segments(tokens: &[Token], budget: &mut Budget) -> Result<Vec<Segment>> {
    budget.tokens(tokens, 3)?;
    let mut d = Dispenser::new(tokens.to_vec());
    let mut segments = Vec::new();
    while d.next() {
        if d.next_arg() {
            return Err(d.arg_err());
        }
        let depth = d.nesting();
        while d.next_block(depth) {
            segments.push(d.next_segment());
        }
    }
    Ok(segments)
}

fn rewrite(tokens: &[Token], defs: &Definitions, budget: &mut Budget) -> Result<Route> {
    budget.tokens(tokens, 2)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let count = d.count_remaining_args();
    if count == 0 || count > 2 {
        return Err(d.arg_err());
    }
    let (matcher, remaining) = if count == 1 {
        (None, tokens.to_vec())
    } else {
        named_matchers::extract(tokens, defs)?
    };
    let mut d = Dispenser::new(remaining);
    d.next();
    d.next();
    let mut handler = serde_json::Map::new();
    handler.insert("handler".into(), "rewrite".into());
    if !d.val().is_empty() {
        handler.insert("uri".into(), d.val().into());
    }
    Ok(Route {
        matchers: matcher.into_iter().collect(),
        handlers: vec![Value::Object(handler)],
        ..Default::default()
    })
}
fn subroute_handler(routes: Vec<Route>, budget: &mut Budget) -> Result<Value> {
    let bound = route_bound(&routes, budget, 1)?
        .checked_add(512)
        .ok_or_else(|| anyhow!("Caddyfile subroute overflow"))?;
    let reservation = budget.reserve_value(bound)?;
    let mut map = serde_json::Map::new();
    map.insert("handler".into(), "subroute".into());
    if !routes.is_empty() {
        map.insert("routes".into(), serde_json::to_value(routes)?);
    }
    let value = Value::Object(map);
    budget.finish_value(reservation, &value)?;
    Ok(value)
}
