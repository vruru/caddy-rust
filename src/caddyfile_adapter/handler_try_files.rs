// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::Budget,
    route_build::Counter,
    routes::{Route, RouteKind, RouteValue},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
pub(super) fn parse(
    tokens: &[Token],
    budget: &mut Budget,
    counter: &mut Counter,
) -> Result<Vec<RouteValue>> {
    let reservation = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    if !d.next() {
        return Err(d.arg_err());
    }
    let files = d.remaining_args();
    if files.is_empty() {
        return Err(d.arg_err());
    }
    let mut policy = String::new();
    while d.next_block(0) {
        if d.val() == "policy" {
            if !policy.is_empty() {
                bail!("try policy already configured");
            }
            if !d.next_arg() {
                return Err(d.arg_err());
            }
            policy = d.val().to_owned();
            if ![
                "first_exist",
                "first_exist_fallback",
                "largest_size",
                "smallest_size",
                "most_recently_modified",
            ]
            .contains(&policy.as_str())
            {
                bail!("unrecognized try policy: {policy}");
            }
        }
    }
    let mut routes = Vec::new();
    let mut accumulated = Vec::new();
    for file in files {
        if let Some(index) = file.find('?') {
            if !accumulated.is_empty() {
                routes.push(make(std::mem::take(&mut accumulated), "", &policy));
            }
            routes.push(make(
                vec![file[..index].to_owned()],
                &file[index..],
                &policy,
            ));
        } else {
            accumulated.push(file);
        }
    }
    if !accumulated.is_empty() {
        routes.push(make(accumulated, "", &policy));
    }
    if routes.len() > 1 {
        let group = counter.next()?;
        for route in &mut routes {
            route.group = group.clone();
        }
    }
    let value = serde_json::to_value(&routes)?;
    budget.finish_value(reservation, &value)?;
    Ok(routes
        .into_iter()
        .map(|route| RouteValue {
            directive: "try_files".into(),
            value: RouteKind::Route(route),
        })
        .collect())
}
fn make(files: Vec<String>, query: &str, policy: &str) -> Route {
    let mut file = Map::new();
    file.insert(
        "try_files".into(),
        Value::Array(files.into_iter().map(Value::String).collect()),
    );
    if !policy.is_empty() {
        file.insert("try_policy".into(), policy.into());
    }
    let mut matcher = Map::new();
    matcher.insert("file".into(), Value::Object(file));
    let mut handler = Map::new();
    handler.insert("handler".into(), "rewrite".into());
    handler.insert(
        "uri".into(),
        format!("{{http.matchers.file.relative}}{query}").into(),
    );
    Route {
        matchers: vec![matcher],
        handlers: vec![Value::Object(handler)],
        ..Default::default()
    }
}
