// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, Cost, add, mul},
    globals::Options,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
fn arg(d: &mut Dispenser) -> Result<String> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(d.val().into())
}
fn child<'a>(m: &'a mut Map<String, Value>, k: &str) -> &'a mut Map<String, Value> {
    m.entry(k)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap()
}
fn active(m: &mut Map<String, Value>) -> &mut Map<String, Value> {
    child(child(m, "health_checks"), "active")
}
fn passive(m: &mut Map<String, Value>) -> &mut Map<String, Value> {
    child(child(m, "health_checks"), "passive")
}
fn duration(d: &mut Dispenser) -> Result<i64> {
    crate::duration::parse_str(&arg(d)?)
}
fn weak_status(m: &mut Map<String, Value>, k: &str, v: &str) {
    if v.is_empty() {
        m.remove(k);
    } else {
        m.insert(k.into(), super::handler_atoms::weak_string_to_value(v));
    }
}
fn status(v: &str) -> Result<i64> {
    Ok(if v.len() == 3 && v.ends_with("xx") {
        &v[..1]
    } else {
        v
    }
    .parse::<i64>()?)
}
fn append_array(m: &mut Map<String, Value>, key: &str, values: impl IntoIterator<Item = Value>) {
    m.entry(key)
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .unwrap()
        .extend(values)
}
pub(super) fn copy(name: &str, tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut m = Map::new();
    m.insert("handler".into(), name.into());
    let a = d.remaining_args();
    if name == "copy_response" {
        if a.len() == 1 && a[0].parse::<i64>().is_ok_and(|n| n > 0) {
            weak_status(&mut m, "status_code", &a[0]);
            return super::module_value::normalize(m.into());
        }
        while d.next_block(0) {
            if d.val() != "status" {
                return Err(d.error("unrecognized copy_response subdirective"));
            }
            weak_status(&mut m, "status_code", &arg(&mut d)?);
        }
    } else {
        if !a.is_empty() {
            return Err(d.arg_err());
        }
        while d.next_block(0) {
            let k = d.val().to_owned();
            if !matches!(k.as_str(), "include" | "exclude") {
                return Err(d.error("unrecognized copy_response_headers subdirective"));
            }
            let a = d.remaining_args();
            if !a.is_empty() {
                append_array(&mut m, &k, a.into_iter().map(Value::String));
            }
        }
    }
    super::module_value::normalize(m.into())
}
#[derive(Default)]
pub(super) struct Defaults {
    pub fields: Map<String, Value>,
    pub request: Option<super::handler_headers::Ops>,
    pub responses: Vec<Value>,
}
pub(super) fn parse<F>(
    kind: &str,
    tokens: &[Token],
    budget: &mut Budget,
    options: &Options,
    subroute: F,
) -> Result<Value>
where
    F: FnMut(&[Token], &mut Budget) -> Result<Value>,
{
    parse_with(kind, tokens, budget, options, Defaults::default(), subroute)
}
pub(super) fn parse_with<F>(
    kind: &str,
    tokens: &[Token],
    budget: &mut Budget,
    options: &Options,
    defaults: Defaults,
    mut subroute: F,
) -> Result<Value>
where
    F: FnMut(&[Token], &mut Budget) -> Result<Value>,
{
    let initial = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut m = defaults.fields;
    m.insert("handler".into(), kind.into());
    let mut scheme = String::new();
    let mut upstreams = Vec::new();
    let mut transport = None;
    let mut request = defaults.request;
    let mut response = None::<super::handler_headers::Ops>;
    let mut matchers = BTreeMap::<String, (Value, Cost)>::new();
    let mut pending = Vec::new();
    let mut responses = defaults.responses;
    if kind == "reverse_proxy" {
        for up in d.remaining_args() {
            super::proxy_addresses::append(&up, &mut scheme, &mut upstreams, budget)?;
        }
    }
    while d.next_block(0) {
        let k = d.val().to_owned();
        if k.starts_with('@') {
            if matchers.contains_key(&k) {
                return Err(d.error("duplicate response matcher"));
            }
            let segment = d.next_segment();
            let r = super::site::reserve_helper(&segment, budget)?;
            let value = super::response_matcher::parse(&segment)?;
            let cost = budget.finish_value(r, &value)?;
            matchers.insert(k, (value, cost));
            continue;
        }
        if kind == "intercept" && !matches!(k.as_str(), "replace_status" | "handle_response") {
            return Err(d.error(format!("unrecognized intercept subdirective {k}")));
        }
        match k.as_str() {
            "to" => {
                let a = d.remaining_args();
                if a.is_empty() {
                    return Err(d.arg_err());
                }
                for up in a {
                    super::proxy_addresses::append(&up, &mut scheme, &mut upstreams, budget)?;
                }
            }
            "dynamic" => {
                let name = arg(&mut d)?;
                m.insert(
                    "dynamic_upstreams".into(),
                    super::proxy_sources::dynamic(&name, &d.next_segment(), budget)?,
                );
            }
            "lb_policy" => {
                let name = arg(&mut d)?;
                let lb = child(&mut m, "load_balancing");
                if lb.contains_key("selection_policy") {
                    return Err(d.error("load balancing selection policy already specified"));
                }
                lb.insert(
                    "selection_policy".into(),
                    super::proxy_sources::policy(&name, &d.next_segment(), budget)?,
                );
            }
            "lb_retries" => {
                set_i64(
                    child(&mut m, "load_balancing"),
                    "retries",
                    arg(&mut d)?.parse::<i64>()?,
                );
            }
            "lb_try_duration" | "lb_try_interval" => {
                set_i64(
                    child(&mut m, "load_balancing"),
                    if k == "lb_try_duration" {
                        "try_duration"
                    } else {
                        "try_interval"
                    },
                    duration(&mut d)?,
                );
            }
            "lb_retry_match" => {
                let v = super::named_matchers::nested_set(&d.next_segment(), budget)?;
                append_array(child(&mut m, "load_balancing"), "retry_match", [v]);
            }
            "health_uri"
            | "health_path"
            | "health_method"
            | "health_request_body"
            | "health_body" => {
                let v = arg(&mut d)?;
                let key = match k.as_str() {
                    "health_uri" => "uri",
                    "health_path" => "path",
                    "health_method" => "method",
                    "health_request_body" => "body",
                    _ => "expect_body",
                };
                set_str(active(&mut m), key, &v);
                if k == "health_path" {
                    warn(
                        &d,
                        options,
                        budget,
                        "the 'health_path' subdirective is deprecated, please use 'health_uri' instead!",
                    )?;
                }
            }
            "health_upstream" => {
                let v = arg(&mut d)?;
                let (_, p, e) = super::address::split_host_port(&v);
                if e.is_some() {
                    return Err(d.error("health_upstream is malformed"));
                }
                p.parse::<i64>()?;
                set_str(active(&mut m), "upstream", &v);
            }
            "health_port" => {
                let v = arg(&mut d)?;
                let a = active(&mut m);
                if a.contains_key("upstream") {
                    return Err(d.error("health_port ignored when health_upstream is used"));
                }
                set_i64(a, "port", v.parse::<i64>()?);
            }
            "health_headers" => {
                let mut headers = Map::new();
                let depth = d.nesting();
                while d.next_block(depth) {
                    let key = d.val().to_owned();
                    let mut a = d.remaining_args();
                    if a.is_empty() {
                        a.push(String::new());
                    }
                    append_array(&mut headers, &key, a.into_iter().map(Value::String));
                }
                let a = active(&mut m);
                if headers.is_empty() {
                    a.remove("headers");
                } else {
                    a.insert("headers".into(), headers.into());
                }
            }
            "health_interval" | "health_timeout" => {
                set_i64(
                    active(&mut m),
                    if k == "health_interval" {
                        "interval"
                    } else {
                        "timeout"
                    },
                    duration(&mut d)?,
                );
            }
            "health_status" => {
                set_i64(active(&mut m), "expect_status", status(&arg(&mut d)?)?);
            }
            "health_follow_redirects" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                active(&mut m).insert("follow_redirects".into(), true.into());
            }
            "health_passes" | "health_fails" => {
                set_i64(
                    active(&mut m),
                    if k == "health_passes" {
                        "passes"
                    } else {
                        "fails"
                    },
                    arg(&mut d)?.parse::<i64>()?,
                );
            }
            "max_fails" | "unhealthy_request_count" => {
                set_i64(passive(&mut m), &k, arg(&mut d)?.parse::<i64>()?);
            }
            "fail_duration" | "unhealthy_latency" => {
                set_i64(passive(&mut m), &k, duration(&mut d)?);
            }
            "unhealthy_status" => {
                let a = d.remaining_args();
                if a.is_empty() {
                    return Err(d.arg_err());
                }
                for a in a {
                    append_array(passive(&mut m), "unhealthy_status", [status(&a)?.into()]);
                }
            }
            "flush_interval" | "stream_timeout" | "stream_close_delay" => {
                let v = arg(&mut d)?;
                let n = match v.parse::<i64>() {
                    Ok(n) => n,
                    Err(_) => crate::duration::parse_str(&v)?,
                };
                set_i64(&mut m, &k, n);
            }
            "request_buffers" | "response_buffers" | "stream_buffer_size" => {
                let v = arg(&mut d)?;
                let n = if v == "unlimited" {
                    -1
                } else {
                    super::handler_limits::parse_size(&v)? as i64
                };
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                set_i64(&mut m, &k, n);
            }
            "proxy_status_name" => {
                set_str(&mut m, &k, &arg(&mut d)?);
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            "trusted_proxies" => {
                for a in d.remaining_args() {
                    if a == "private_ranges" {
                        append_array(
                            &mut m,
                            "trusted_proxies",
                            [
                                "192.168.0.0/16",
                                "172.16.0.0/12",
                                "10.0.0.0/8",
                                "127.0.0.1/8",
                                "fd00::/8",
                                "::1",
                            ]
                            .into_iter()
                            .map(Value::from),
                        );
                    } else {
                        append_array(&mut m, "trusted_proxies", [a.into()]);
                    }
                }
            }
            "header_up" | "header_down" => {
                let a = d.remaining_args();
                if !(1..=3).contains(&a.len()) {
                    return Err(d.arg_err());
                }
                if k == "header_up" && a.len() == 2 {
                    let redundant = if a[0].eq_ignore_ascii_case("x-forwarded-for")
                        && [
                            "{remote}",
                            "{http.request.remote}",
                            "{remote_host}",
                            "{http.request.remote.host}",
                        ]
                        .contains(&a[1].as_str())
                    {
                        Some("X-Forwarded-For")
                    } else if a[0].eq_ignore_ascii_case("x-forwarded-proto")
                        && ["{scheme}", "{http.request.scheme}"].contains(&a[1].as_str())
                    {
                        Some("X-Forwarded-Proto")
                    } else if a[0].eq_ignore_ascii_case("x-forwarded-host")
                        && [
                            "{host}",
                            "{http.request.host}",
                            "{hostport}",
                            "{http.request.hostport}",
                        ]
                        .contains(&a[1].as_str())
                    {
                        Some("X-Forwarded-Host")
                    } else {
                        None
                    };
                    if let Some(header) = redundant {
                        warn(
                            &d,
                            options,
                            budget,
                            &format!(
                                "Unnecessary header_up {header}: the reverse proxy's default behavior is to pass headers to the upstream"
                            ),
                        )?;
                    }
                }
                let ops = if k == "header_up" {
                    request.get_or_insert_with(Default::default)
                } else {
                    response.get_or_insert_with(Default::default)
                };
                ops.apply(
                    false,
                    &a[0],
                    a.get(1).map_or("", String::as_str),
                    a.get(2).cloned(),
                )?;
            }
            "method" | "rewrite" => {
                set_str(
                    child(&mut m, "rewrite"),
                    if k == "method" { "method" } else { "uri" },
                    &arg(&mut d)?,
                );
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            "transport" => {
                let name = arg(&mut d)?;
                if m.contains_key("transport") {
                    return Err(d.error("transport already specified"));
                }
                transport = Some(super::proxy_transport::parse(
                    &name,
                    &d.next_segment(),
                    budget,
                    options,
                )?);
            }
            "handle_response" => pending.push(d.next_segment()),
            "replace_status" => {
                let a = d.remaining_args();
                if !(1..=2).contains(&a.len()) {
                    return Err(d.arg_err());
                }
                let mut response = Map::new();
                if a.len() == 2 {
                    response.insert("match".into(), matched(&a[0], &matchers, budget)?);
                }
                weak_status(&mut response, "status_code", a.last().unwrap());
                let depth = d.nesting();
                if d.next_block(depth) {
                    return Err(d.error("cannot define routes for replace_status"));
                }
                responses.push(Value::Object(response));
            }
            "verbose_logs" => {
                if m.contains_key("verbose_logs") {
                    return Err(d.error("verbose_logs already specified"));
                }
                m.insert("verbose_logs".into(), true.into());
            }
            _ => return Err(d.error(format!("unrecognized subdirective {k}"))),
        }
    }
    if !upstreams.is_empty() {
        m.insert("upstreams".into(), upstreams.into());
    }
    if let Some(request) = request {
        child(&mut m, "headers").insert("request".into(), request.value(false));
    }
    if let Some(response) = response {
        child(&mut m, "headers").insert("response".into(), response.value(false));
    }
    if matches!(scheme.as_str(), "https" | "h2c") && transport.is_none() {
        transport = Some(json!({"protocol":"http"}));
    }
    if let Some(mut t) = transport {
        if t["protocol"] == "http" {
            let object = t.as_object_mut().unwrap();
            if scheme == "https" {
                object.entry("tls").or_insert_with(|| json!({}));
            }
            if object.contains_key("tls")
                && m.get("headers")
                    .and_then(|v| v.pointer("/request/set/Host/0"))
                    .and_then(Value::as_str)
                    .is_some_and(|v| {
                        [
                            "{upstream_hostport}",
                            "{http.reverse_proxy.upstream.hostport}",
                        ]
                        .contains(&v)
                    })
            {
                warn(
                    &d,
                    options,
                    budget,
                    "Unnecessary header_up Host: the reverse proxy's default behavior is to pass the configured upstream address to the upstream when proxying to HTTPS",
                )?;
            }
            if scheme == "http" && object.contains_key("tls") {
                bail!("upstream HTTP scheme conflicts with TLS transport");
            }
            if scheme == "h2c" {
                object.insert("versions".into(), json!(["h2c", "2"]));
            }
            if object.len() > 1 {
                m.insert("transport".into(), t);
            }
        } else {
            if scheme == "https" {
                bail!("configured transport does not support HTTPS");
            }
            m.insert("transport".into(), t);
        }
    }
    for segment in pending {
        let mut h = Dispenser::new(segment.clone());
        h.next();
        let a = h.remaining_args();
        if a.len() > 1 {
            return Err(h.arg_err());
        }
        let mut response = Map::new();
        if let Some(name) = a.first() {
            response.insert("match".into(), matched(name, &matchers, budget)?);
        }
        let sub = subroute(&h.next_segment(), budget)?;
        if let Some(routes) = sub.get("routes") {
            let cost = budget.measure(routes)?;
            budget.copies(cost, 1, 2)?;
            response.insert("routes".into(), routes.clone());
        }
        responses.push(response.into());
    }
    if !responses.is_empty() {
        let mut without = Vec::new();
        let mut with = Vec::new();
        for response in responses {
            if response.get("match").is_some() {
                with.push(response);
            } else {
                without.push(response);
            }
        }
        with.append(&mut without);
        m.insert("handle_response".into(), with.into());
    }
    // Composite input and each amplifying child were prepaid before construction.
    // Charge normalization's additional owned graph and temporary encoded buffers.
    budget.finish_value(initial, &Value::Null)?;
    let raw = Value::Object(m);
    let cost = budget.measure(&raw)?;
    let reservation = budget.reserve_value(add(mul(cost.bytes, 3)?, cost.json_upper)?)?;
    let value = super::module_value::normalize(raw)?;
    budget.finish_value(reservation, &value)?;
    Ok(value)
}
fn matched(
    name: &str,
    matchers: &BTreeMap<String, (Value, Cost)>,
    budget: &mut Budget,
) -> Result<Value> {
    if !name.starts_with('@') {
        bail!("response matcher must begin with @");
    }
    let (v, cost) = matchers
        .get(name)
        .ok_or_else(|| anyhow!("no named response matcher {name}"))?;
    budget.copies(*cost, 1, 2)?;
    Ok(v.clone())
}
fn warn(d: &Dispenser, o: &Options, b: &mut Budget, message: &str) -> Result<()> {
    let t = d.token();
    o.warn(&t.file, t.line, "reverse_proxy", message, b)
}
