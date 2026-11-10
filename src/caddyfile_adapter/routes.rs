// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

pub(super) const DEFAULT_ORDER: &[&str] = &[
    "tracing",
    "map",
    "vars",
    "fs",
    "root",
    "log_append",
    "skip_log",
    "log_skip",
    "log_name",
    "header",
    "copy_response_headers",
    "request_body",
    "timeouts",
    "redir",
    "method",
    "rewrite",
    "uri",
    "try_files",
    "basicauth",
    "basic_auth",
    "forward_auth",
    "request_header",
    "encode",
    "push",
    "intercept",
    "templates",
    "invoke",
    "handle",
    "handle_path",
    "route",
    "abort",
    "error",
    "copy_response",
    "respond",
    "metrics",
    "reverse_proxy",
    "php_fastcgi",
    "file_server",
    "acme_server",
];
#[derive(Clone, Default, Serialize)]
pub(super) struct Route {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group: String,
    #[serde(rename = "match", skip_serializing_if = "Vec::is_empty")]
    pub matchers: Vec<Map<String, Value>>,
    #[serde(rename = "handle", skip_serializing_if = "Vec::is_empty")]
    pub handlers: Vec<Value>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub terminal: bool,
}
#[derive(Clone)]
pub(super) struct RouteValue {
    pub directive: String,
    pub value: RouteKind,
}
#[derive(Clone)]
pub(super) enum RouteKind {
    Route(Route),
}
impl RouteValue {
    pub(super) fn route(&self) -> Option<&Route> {
        match &self.value {
            RouteKind::Route(r) => Some(r),
        }
    }
}
fn single_path(route: &Route) -> Option<&str> {
    if route.matchers.len() != 1 {
        return None;
    }
    let paths = route.matchers[0].get("path")?.as_array()?;
    if paths.len() != 1 {
        return None;
    }
    paths[0].as_str().filter(|s| !s.is_empty())
}
pub(super) fn sort_routes(routes: &mut [RouteValue], order: &[String]) {
    let positions: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, d)| (d.as_str(), i))
        .collect();
    // The original vars comparator returns true for equal keys. Preserve Go's
    // concrete stable-sort algorithm rather than passing a non-total ordering
    // to Rust's standard comparison sort.
    super::stable_sort::stable_sort(routes, |a, b| {
        if a.directive != b.directive {
            return positions.get(a.directive.as_str()).copied().unwrap_or(0)
                < positions.get(b.directive.as_str()).copied().unwrap_or(0);
        }
        let (Some(a_route), Some(b_route)) = (a.route(), b.route()) else {
            return false;
        };
        let sort_by_path = match (single_path(a_route), single_path(b_route)) {
            (Some(ap), Some(bp)) => {
                let at = ap.strip_suffix('*').unwrap_or(ap);
                let bt = bp.strip_suffix('*').unwrap_or(bp);
                if at == bt {
                    ap.len() < bp.len()
                } else if at.len() == bt.len() {
                    at < bt
                } else {
                    at.len() > bt.len()
                }
            }
            _ => !a_route.matchers.is_empty() && b_route.matchers.is_empty(),
        };
        if a.directive == "vars" {
            !sort_by_path
        } else {
            sort_by_path
        }
    });
}
