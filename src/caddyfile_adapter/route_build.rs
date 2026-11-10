// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, add, mul},
    routes::{Route, RouteKind, RouteValue},
};
use anyhow::{Result, anyhow, bail};
use std::collections::BTreeMap;
#[derive(Default)]
pub(super) struct Counter(usize);
impl Counter {
    pub(super) fn next(&mut self) -> Result<String> {
        let current = self.0;
        self.0 = self
            .0
            .checked_add(1)
            .ok_or_else(|| anyhow!("Caddyfile route group overflow"))?;
        Ok(format!("group{current}"))
    }
}
pub(super) fn build(
    mut values: Vec<RouteValue>,
    counter: &mut Counter,
    order: Option<&[String]>,
    budget: &mut Budget,
) -> Result<Vec<Route>> {
    budget.work(values.len() as u64)?;
    if let Some(order) = order {
        for v in &values {
            if !order.contains(&v.directive) {
                bail!(
                    "directive '{}' is not an ordered HTTP handler; place it within a route block or use the order global option",
                    v.directive
                );
            }
        }
        // Stable-sort scans remain bounded separately from output copies.
        let log = (usize::BITS - values.len().leading_zeros() + 1) as u64;
        budget.work(mul(mul(values.len() as u64, log)?, mul(log, 4)?)?)?;
        super::routes::sort_routes(&mut values, order);
    }
    let mut groups = BTreeMap::new();
    for name in ["handle", "rewrite", "root"] {
        let count = values
            .iter()
            .filter(|v| v.directive == name)
            .take(2)
            .count();
        if count > 1 || name == "rewrite" {
            groups.insert(name, counter.next()?);
        }
    }
    let mut routes = Vec::new();
    for mut v in values {
        match &mut v.value {
            RouteKind::Route(route) => {
                if let Some(group) = groups.get(v.directive.as_str()) {
                    budget.materialize(add(group.len() as u64, 128)?)?;
                    route.group = group.clone();
                }
            }
        }
        match v.value {
            RouteKind::Route(r) => routes.push(r),
        }
    }
    Ok(consolidate(routes))
}
pub(super) fn consolidate(routes: Vec<Route>) -> Vec<Route> {
    let mut result: Vec<Route> = Vec::with_capacity(routes.len());
    for mut route in routes {
        if let Some(last) = result.last_mut()
            && last.matchers == route.matchers
            && last.group == route.group
            && last.terminal == route.terminal
        {
            last.handlers.append(&mut route.handlers);
        } else {
            result.push(route);
        }
    }
    result
}
