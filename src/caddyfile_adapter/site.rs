// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, Cost, Reservation},
    builtin_state::{self, Bind},
    globals::Options,
    handler_errors_status,
    named_matchers::{self, Definitions},
    named_routes::Invokes,
    route_build::{self, Counter},
    routes::{ERROR_ROUTE_CLASS, ErrorRoute, Route, RouteKind, RouteValue},
};
use crate::{
    caddyfile_lexer::Token,
    caddyfile_parser::{Dispenser, Segment},
};
use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    rc::Rc,
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
#[derive(Default)]
struct Piles {
    binds: Vec<Bind>,
    errors: Vec<ErrorRoute>,
    tls: super::tls_site::SiteTls,
}
#[derive(Clone, Copy)]
enum Block {
    Route,
    Ordered,
}
pub(super) struct Site {
    pub keys: Vec<super::address::Address>,
    pub binds: Vec<Bind>,
    pub values: Vec<RouteValue>,
    pub cost: Cost,
    pub tls: super::tls_site::SiteTls,
    pub errors: Vec<ErrorRoute>,
    pub errors_cost: Option<Cost>,
    pub invokes: Vec<String>,
}
struct Scope<'state> {
    defs: Definitions,
    costs: BTreeMap<String, Cost>,
    files: Arc<Vec<String>>,
    cwd: Arc<PathBuf>,
    tags: Rc<RefCell<&'state mut BTreeMap<String, String>>>,
}
impl<'state> Scope<'state> {
    fn new(files: Vec<String>, cwd: &Path, tags: &'state mut BTreeMap<String, String>) -> Self {
        Self {
            defs: Definitions::new(),
            costs: BTreeMap::new(),
            files: Arc::new(files),
            cwd: Arc::new(cwd.to_owned()),
            tags: Rc::new(RefCell::new(tags)),
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
            tags: self.tags.clone(),
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
    let mut scope = file_scope(segments.iter().flatten(), budget, cwd, tags)?;
    let mut invokes = Invokes::default();
    let mut piles = Piles::default();
    let values = parse_segments(
        segments,
        &mut scope,
        options,
        budget,
        counter,
        Some(&mut piles),
        &mut invokes,
    )?;
    let count = values
        .iter()
        .map(|v| match &v.value {
            RouteKind::Route(_) => 1,
            RouteKind::ErrorRoute(_) | RouteKind::Binding { .. } | RouteKind::Tls { .. } => 0,
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
            RouteKind::ErrorRoute(_) | RouteKind::Binding { .. } | RouteKind::Tls { .. } => &[],
        })
        .collect::<Vec<_>>();
    let cost = pile_cost(&references, budget)?;
    let errors_cost = if piles.errors.is_empty() {
        None
    } else {
        budget.materialize(
            (piles.errors.len() as u64)
                .checked_mul(std::mem::size_of::<&Route>() as u64)
                .ok_or_else(|| anyhow!("Caddyfile route reference overflow"))?,
        )?;
        let references = piles.errors.iter().map(|e| &e.route).collect::<Vec<_>>();
        Some(pile_cost(&references, budget)?)
    };
    Ok(Site {
        keys,
        binds: piles.binds,
        values,
        cost,
        tls: piles.tls,
        errors: piles.errors,
        errors_cost,
        invokes: invokes.into_vec(),
    })
}
fn file_scope<'a, 'state>(
    tokens: impl Iterator<Item = &'a Token>,
    budget: &mut Budget,
    cwd: &Path,
    tags: &'state mut BTreeMap<String, String>,
) -> Result<Scope<'state>> {
    let mut files = BTreeSet::new();
    for token in tokens {
        budget.work(1)?;
        files.insert(token.file.as_str());
    }
    for file in &files {
        budget.materialize(file.len() as u64 + 64)?;
    }
    budget.materialize(64)?;
    Ok(Scope::new(
        files.into_iter().map(str::to_owned).collect(),
        cwd,
        tags,
    ))
}
pub(super) fn named_route_body(
    tokens: &[Token],
    options: &Options,
    budget: &mut Budget,
    counter: &mut Counter,
    cwd: &Path,
    invokes: &mut Invokes,
    tags: &mut BTreeMap<String, String>,
) -> Result<Vec<Route>> {
    let scope = file_scope(tokens.iter(), budget, cwd, tags)?;
    block_routes(
        tokens,
        Block::Ordered,
        &scope,
        options,
        budget,
        counter,
        invokes,
    )
}

fn pile_cost(references: &[&Route], budget: &mut Budget) -> Result<Cost> {
    let bound = route_bound(references.iter().copied(), budget, 0)?;
    let reservation = budget.reserve_value(bound)?;
    let value = serde_json::to_value(references)?;
    budget.finish_value(reservation, &value)
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
    scope: &mut Scope<'_>,
    options: &Options,
    budget: &mut Budget,
    counter: &mut Counter,
    mut piles: Option<&mut Piles>,
    invokes: &mut Invokes,
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
            let directive = {
                let mut tags = scope.tags.borrow_mut();
                super::tls_directive::parse(seg, &mut tags, options, &scope.cwd, budget)?
            };
            if let Some(piles) = piles.as_deref_mut() {
                piles.tls.push(directive, budget)?;
            } else {
                let count = directive.config_value_count()?;
                let bytes = super::budget::add(
                    first.file.len() as u64,
                    std::mem::size_of::<RouteValue>() as u64 + 16,
                )?;
                budget.materialize(super::budget::mul(count, bytes)?)?;
                budget.work(super::budget::mul(count, first.file.len() as u64 + 1)?)?;
                for _ in 0..count {
                    result.push(RouteValue {
                        directive: name.into(),
                        value: RouteKind::Tls {
                            file: first.file.clone(),
                            line: first.line,
                        },
                    });
                }
            }
            continue;
        }
        if name == "handle_errors" {
            let reservation = reserve_helper(seg, budget)?;
            let status = handler_errors_status::status(seg)?;
            let measured = status.expression.clone().map_or(Value::Null, Value::String);
            budget.finish_value(reservation, &measured)?;
            let children = block_routes(
                &seg[status.args..],
                Block::Ordered,
                scope,
                options,
                budget,
                counter,
                invokes,
            )?;
            let route = Route {
                matchers: status
                    .expression
                    .map(handler_errors_status::expression_matcher)
                    .into_iter()
                    .collect(),
                handlers: vec![subroute_handler(children, budget)?],
                ..Default::default()
            };
            charge_route(&route, budget)?;
            budget.materialize(first.file.len() as u64 + 64)?;
            let error = ErrorRoute {
                route,
                file: first.file.clone(),
                line: first.line,
            };
            if let Some(piles) = piles.as_deref_mut() {
                piles.errors.push(error);
            } else {
                result.push(RouteValue {
                    directive: "handle_errors".into(),
                    value: RouteKind::ErrorRoute(error),
                });
            }
            continue;
        }
        if name == "invoke" {
            scope.pre_extract(seg, budget)?;
            let reservation = reserve_helper(seg, budget)?;
            let (matcher, tokens) = named_matchers::extract(seg, &scope.defs)?;
            let (target, handler) = super::handler_invoke::invoke(&tokens)?;
            budget.finish_value(reservation, &handler)?;
            invokes.record(&target, budget)?;
            record_route(
                &mut result,
                name,
                Route {
                    matchers: matcher.into_iter().collect(),
                    handlers: vec![handler],
                    ..Default::default()
                },
                budget,
            )?;
            continue;
        }
        if name == "try_files" {
            result.extend(super::handler_try_files::parse(seg, budget, counter)?);
            continue;
        }
        if name == "bind" {
            let reservation = reserve_helper(seg, budget)?;
            let binding = builtin_state::bind(seg, false)?;
            budget.finish_value(reservation, &Value::Null)?;
            if let Some(piles) = piles.as_deref_mut() {
                piles.binds.push(binding);
            } else {
                // This config-only value is intentionally dropped by Go's
                // ordered buildSubroute, after parsing and ordering checks.
                budget.materialize(first.file.len() as u64 + 64)?;
                result.push(RouteValue {
                    directive: name.into(),
                    value: RouteKind::Binding {
                        file: first.file.clone(),
                        line: first.line,
                    },
                });
            }
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
                let block = if name == "route" {
                    Block::Route
                } else {
                    Block::Ordered
                };
                let mut routes =
                    block_routes(&tokens, block, scope, options, budget, counter, invokes)?;
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
            } else if let Some(value) = super::handler_auth_trace::parse(name, &tokens)? {
                if name == "basicauth" {
                    let message =
                        "the 'basicauth' directive is deprecated, please use 'basic_auth' instead!";
                    options.warn(&first.file, first.line, name, message, budget)?;
                }
                value
            } else if name == "map" {
                super::handler_map::parse(&tokens, budget, reservation.take().unwrap(), options)?
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
            if !["route", "handle", "handle_path", "file_server", "map"].contains(&name) {
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
fn block_routes(
    tokens: &[Token],
    block: Block,
    scope: &Scope<'_>,
    options: &Options,
    budget: &mut Budget,
    counter: &mut Counter,
    invokes: &mut Invokes,
) -> Result<Vec<Route>> {
    let children = block_segments(tokens, budget)?;
    let mut nested = scope.copied(budget)?;
    let values = budget.nested(|budget| {
        parse_segments(
            &children,
            &mut nested,
            options,
            budget,
            counter,
            None,
            invokes,
        )
    })?;
    let order = match block {
        Block::Route => {
            for value in &values {
                let invalid = match &value.value {
                    RouteKind::ErrorRoute(error) => {
                        Some((&error.file, error.line, ERROR_ROUTE_CLASS))
                    }
                    RouteKind::Binding { file, line } => Some((file, *line, "bind")),
                    RouteKind::Tls { file, line } => Some((file, *line, "tls")),
                    RouteKind::Route(_) => None,
                };
                if let Some((file, line, class)) = invalid {
                    bail!(
                        "{file}:{line}: {} directive returned something other than an HTTP route or subroute: {class} value (only handler directives can be used in routes)",
                        value.directive
                    );
                }
            }
            None
        }
        Block::Ordered => Some(options.order.as_slice()),
    };
    route_build::build(values, counter, order, budget)
}
pub(super) fn serialize_route(route: &Route, budget: &mut Budget) -> Result<(Value, Cost)> {
    let size = route_bound(std::slice::from_ref(route), budget, 0)?;
    let reservation = budget.reserve_value(size)?;
    let value = serde_json::to_value(route)?;
    let cost = budget.finish_value(reservation, &value)?;
    Ok((value, cost))
}
fn charge_route(route: &Route, budget: &mut Budget) -> Result<()> {
    serialize_route(route, budget)?;
    Ok(())
}

fn record_route(
    result: &mut Vec<RouteValue>,
    name: &str,
    route: Route,
    budget: &mut Budget,
) -> Result<()> {
    charge_route(&route, budget)?;
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
pub(super) fn subroute_handler(routes: Vec<Route>, budget: &mut Budget) -> Result<Value> {
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
