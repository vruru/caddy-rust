// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{budget::Budget, globals::Options, handler_proxy::Defaults, tls_issuers::set_str};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub(super) fn forward_auth<F>(
    tokens: &[Token],
    budget: &mut Budget,
    options: &Options,
    subroute: F,
) -> Result<Value>
where
    F: FnMut(&[Token], &mut Budget) -> Result<Value>,
{
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    let mut uri = String::new();
    let mut headers = BTreeMap::new();
    while d.next() {
        while d.next_block(0) {
            if d.nesting() != 1 {
                continue;
            }
            match d.val() {
                "uri" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    if !uri.is_empty() {
                        return Err(d.error("cannot re-declare uri"));
                    }
                    uri = d.val().into();
                    d.delete_n(2);
                }
                "copy_headers" => {
                    let mut args = d.remaining_args();
                    let mut block = false;
                    let nesting = d.nesting();
                    while d.next_block(nesting) {
                        block = true;
                        args.push(d.val().to_owned());
                    }
                    d.delete_n(args.len() + 1);
                    if block {
                        d.delete_n(2);
                    }
                    for a in args {
                        if let Some((from, to)) = a.split_once('>') {
                            headers.insert(
                                from.to_owned(),
                                to.split('>').next().unwrap_or("").to_owned(),
                            );
                        } else {
                            headers.insert(a.clone(), a);
                        }
                    }
                    if headers.is_empty() {
                        return Err(d.arg_err());
                    }
                }
                _ => {}
            }
        }
    }
    if uri.is_empty() {
        return Err(d.error("the 'uri' subdirective is required"));
    }
    let mut defaults = Defaults::default();
    let mut rewrite = serde_json::Map::new();
    set_str(&mut rewrite, "method", "GET");
    set_str(&mut rewrite, "uri", &uri);
    defaults.fields.insert("rewrite".into(), rewrite.into());
    let mut request = super::handler_headers::Ops::default();
    request.apply(false, "X-Forwarded-Method", "{http.request.method}", None)?;
    request.apply(false, "X-Forwarded-Uri", "{http.request.uri}", None)?;
    defaults.request = Some(request);
    let mut routes = vec![json!({"handle":[{"handler":"vars"}]})];
    for (from, to) in headers {
        let to = super::matcher_atoms::canonical_header(&to);
        let placeholder = format!(
            "{{http.reverse_proxy.header.{}}}",
            super::matcher_atoms::canonical_header(&from)
        );
        routes.push(json!({"handle":[{"handler":"headers","request":{"delete":[to]}}]}));
        routes.push(json!({"match":[{"not":[{"vars":{placeholder.clone():[""]}}]}],"handle":[{"handler":"headers","request":{"set":{to:[placeholder]}}}]}));
    }
    defaults
        .responses
        .push(json!({"match":{"status_code":[2]},"routes":routes}));
    d.reset();
    d.next();
    let rest = d.next_segment();
    budget.finish_value(r, &Value::Null)?;
    super::handler_proxy::parse_with("reverse_proxy", &rest, budget, options, defaults, subroute)
}
pub(super) fn php_fastcgi<F>(
    tokens: &[Token],
    budget: &mut Budget,
    options: &Options,
    subroute: F,
) -> Result<Vec<super::routes::Route>>
where
    F: FnMut(&[Token], &mut Budget) -> Result<Value>,
{
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    let mut transport = serde_json::Map::new();
    transport.insert("protocol".into(), "fastcgi".into());
    let mut extensions = vec![".php".to_owned()];
    let mut index = "index.php".to_owned();
    let mut try_files = Vec::new();
    while d.next() {
        while d.next_block(0) {
            if d.nesting() != 1 {
                continue;
            }
            let k = d.val().to_owned();
            match k.as_str() {
                "root" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    set_str(&mut transport, "root", d.val());
                    d.delete_n(2);
                }
                "split" => {
                    extensions = d.remaining_args();
                    d.delete_n(extensions.len() + 1);
                    if extensions.is_empty() {
                        return Err(d.arg_err());
                    }
                }
                "env" => {
                    let a = d.remaining_args();
                    d.delete_n(a.len() + 1);
                    if a.len() != 2 {
                        return Err(d.arg_err());
                    }
                    transport
                        .entry("env")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .unwrap()
                        .insert(a[0].clone(), a[1].clone().into());
                }
                "index" => {
                    let a = d.remaining_args();
                    d.delete_n(a.len() + 1);
                    if a.len() != 1 {
                        return Err(d.arg_err());
                    }
                    index = a[0].clone();
                }
                "try_files" => {
                    try_files = d.remaining_args();
                    d.delete_n(try_files.len() + 1);
                    if try_files.is_empty() {
                        return Err(d.arg_err());
                    }
                }
                "resolve_root_symlink" | "capture_stderr" => {
                    let a = d.remaining_args();
                    d.delete_n(a.len() + 1);
                    transport.insert(k, true.into());
                }
                "dial_timeout" | "read_timeout" | "write_timeout" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    super::tls_issuers::set_i64(
                        &mut transport,
                        &k,
                        crate::duration::parse_str(d.val())?,
                    );
                    d.delete_n(2);
                }
                _ => {}
            }
        }
    }
    transport.insert("split_path".into(), serde_json::to_value(&extensions)?);
    let mut routes = Vec::new();
    if index != "off" {
        let dir_index = format!("{{http.request.uri.path}}/{index}");
        let mut policy = "first_exist_fallback";
        let dir_redir = if try_files.is_empty() {
            try_files = vec!["{http.request.uri.path}".into(), dir_index.clone(), index];
            true
        } else {
            if !try_files.last().unwrap().ends_with(".php") {
                policy = "";
            }
            try_files.contains(&dir_index)
        };
        if dir_redir {
            let mut matchers = serde_json::Map::new();
            matchers.insert("file".into(), json!({"try_files":[dir_index]}));
            matchers.insert("not".into(), json!([{"path":["*/"]}]));
            routes.push(super::routes::Route{matchers:vec![matchers],handlers:vec![json!({"handler":"static_response","status_code":308,"headers":{"Location":["{http.request.orig_uri.path}/{http.request.orig_uri.prefixed_query}"]}})],..Default::default()});
        }
        let mut file = serde_json::Map::new();
        file.insert("try_files".into(), serde_json::to_value(&try_files)?);
        file.insert("split_path".into(), serde_json::to_value(&extensions)?);
        set_str(&mut file, "try_policy", policy);
        let mut matchers = serde_json::Map::new();
        matchers.insert("file".into(), file.into());
        routes.push(super::routes::Route {
            matchers: vec![matchers],
            handlers: vec![json!({"handler":"rewrite","uri":"{http.matchers.file.relative}"})],
            ..Default::default()
        });
    }
    let mut defaults = Defaults::default();
    defaults.fields.insert("transport".into(), transport.into());
    d.reset();
    d.next();
    let rest = d.next_segment();
    budget.finish_value(r, &Value::Null)?;
    let proxy = super::handler_proxy::parse_with(
        "reverse_proxy",
        &rest,
        budget,
        options,
        defaults,
        subroute,
    )?;
    let paths = extensions
        .into_iter()
        .map(|ext| format!("*{ext}"))
        .map(Value::from)
        .collect::<Vec<_>>();
    let mut matchers = serde_json::Map::new();
    matchers.insert("path".into(), paths.into());
    routes.push(super::routes::Route {
        matchers: vec![matchers],
        handlers: vec![proxy],
        ..Default::default()
    });
    Ok(routes)
}
