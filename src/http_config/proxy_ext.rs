// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
use anyhow::{Result, ensure};
use serde_json::{Map, Value, json};
use std::time::Duration;

use super::helpers::*;
use super::types::{MatcherSet, RequestRegex};

#[derive(Clone)]
pub(crate) struct ProxyExt {
    pub(crate) health: HealthCfg,
    pub(crate) retry: RetryCfg,
    pub(crate) dynamic: Option<DynamicCfg>,
    pub(crate) request_buffers: i64,
}

#[derive(Clone)]
pub(crate) struct HealthCfg {
    pub(crate) active: Option<ActiveCfg>,
    pub(crate) passive: Option<PassiveCfg>,
}

#[derive(Clone)]
pub(crate) struct ActiveCfg {
    pub(crate) uri_path_query: Option<String>,
    pub(crate) path: String,
    pub(crate) uri: String,
    pub(crate) upstream: String,
    pub(crate) port: u16,
    pub(crate) headers: Vec<(String, Vec<String>)>,
    pub(crate) method: http::Method,
    pub(crate) body: String,
    pub(crate) follow_redirects: bool,
    pub(crate) interval: Duration,
    pub(crate) timeout: i64,
    pub(crate) passes: u32,
    pub(crate) fails: u32,
    pub(crate) max_size: i64,
    pub(crate) expect_status: i64,
    pub(crate) expect_body: Option<RequestRegex>,
}

impl ActiveCfg {
    pub(crate) fn enabled(&self) -> bool {
        !self.path.is_empty() || !self.uri.is_empty() || self.port != 0
    }
}

#[derive(Clone)]
pub(crate) struct PassiveCfg {
    pub(crate) fail_duration: i64,
    pub(crate) max_fails: i64,
    pub(crate) unhealthy_request_count: i64,
    pub(crate) unhealthy_status: Vec<i64>,
    pub(crate) unhealthy_latency: i64,
}

#[derive(Clone)]
pub(crate) struct RetryCfg {
    pub(crate) retries: u32,
    pub(crate) try_duration: Duration,
    pub(crate) try_interval: Duration,
    pub(crate) retry_match: Option<Vec<MatcherSet>>,
}

#[derive(Clone)]
pub(crate) enum IpVersions {
    Any,
    V4,
    V6,
}

#[derive(Clone)]
pub(crate) struct DnsCfg {
    pub(crate) resolver_addresses: Option<Vec<String>>,
    pub(crate) dial_timeout: i64,
    pub(crate) fallback_delay: i64,
}

#[derive(Clone)]
pub(crate) enum DynamicCfg {
    A {
        name: String,
        port: String,
        refresh: i64,
        dns: DnsCfg,
        versions: IpVersions,
    },
    Srv {
        name: String,
        service: String,
        proto: String,
        refresh: i64,
        grace_period: i64,
        dns: DnsCfg,
        dial_network: String,
    },
    Multi(Vec<DynamicCfg>),
}

// ---------------------------------------------------------------------------
// helpers local to this file
// ---------------------------------------------------------------------------

fn get_i64(m: &Map<String, Value>, key: &str, path: &str) -> Result<i64> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v
            .as_number()
            .and_then(|n| n.as_i64())
            .ok_or_else(|| anyhow::anyhow!("integer required for {key} at {path}")),
    }
}

fn get_dur(m: &Map<String, Value>, key: &str, path: &str, default: Duration) -> Result<Duration> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => duration(v, path),
    }
}

fn get_signed(m: &Map<String, Value>, key: &str, path: &str, default: i64) -> Result<i64> {
    m.get(key)
        .filter(|v| !v.is_null())
        .map(|v| signed_duration(v, path))
        .transpose()
        .map(|v| v.unwrap_or(default))
}

fn get_opt_str(m: &Map<String, Value>, key: &str, path: &str) -> Result<String> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(v) => string(v, path),
    }
}

fn get_opt_string(m: &Map<String, Value>, key: &str, path: &str) -> Result<Option<String>> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => Ok(Some(string(v, path)?)),
    }
}

// ---------------------------------------------------------------------------
// parse entry
// ---------------------------------------------------------------------------

pub(crate) fn parse(
    m: &Map<String, Value>,
    path: &str,
    regex_remaining: &mut usize,
) -> Result<ProxyExt> {
    let health = parse_health_opt(m.get("health_checks"), path, regex_remaining)?;
    let retry = parse_retry_opt(m.get("load_balancing"), path, regex_remaining)?;
    let mut source_count = 0;
    let dynamic = parse_dynamic_opt(m.get("dynamic_upstreams"), path, 0, &mut source_count)?;
    let request_buffers = get_i64(m, "request_buffers", path)?;
    ensure!(
        request_buffers == -1 || request_buffers >= 0,
        "request_buffers must be -1 or >= 0 at {path}"
    );
    Ok(ProxyExt {
        health,
        retry,
        dynamic,
        request_buffers,
    })
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

fn parse_health_opt(
    value: Option<&Value>,
    path: &str,
    regex_remaining: &mut usize,
) -> Result<HealthCfg> {
    match value {
        None | Some(Value::Null) => Ok(HealthCfg {
            active: None,
            passive: None,
        }),
        Some(v) => {
            let m = object(v, path)?;
            deny_unknown(m, &["active", "passive"], path)?;
            let active =
                parse_active_opt(m.get("active"), &format!("{path}.active"), regex_remaining)?;
            let passive = parse_passive_opt(m.get("passive"), &format!("{path}.passive"))?;
            Ok(HealthCfg { active, passive })
        }
    }
}

fn parse_active_opt(
    value: Option<&Value>,
    path: &str,
    regex_remaining: &mut usize,
) -> Result<Option<ActiveCfg>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let m = object(v, path)?;
            deny_unknown(
                m,
                &[
                    "path",
                    "uri",
                    "upstream",
                    "port",
                    "headers",
                    "method",
                    "body",
                    "follow_redirects",
                    "interval",
                    "timeout",
                    "passes",
                    "fails",
                    "max_size",
                    "expect_status",
                    "expect_body",
                ],
                path,
            )?;
            let cfg = parse_active(m, path, regex_remaining)?;
            Ok(Some(cfg))
        }
    }
}

fn parse_active(
    m: &Map<String, Value>,
    path: &str,
    regex_remaining: &mut usize,
) -> Result<ActiveCfg> {
    let uri = get_opt_str(m, "uri", path)?;
    let uri_path_query = if uri.is_empty() {
        None
    } else {
        Some(
            crate::go_url_compat::health_uri_path_query(&uri)
                .map_err(|_| anyhow::anyhow!("invalid active health URI at {path}"))?,
        )
    };
    let upstream = get_opt_str(m, "upstream", path)?;
    let raw_path = get_opt_str(m, "path", path)?;
    let body = get_opt_str(m, "body", path)?;

    let port_raw = get_i64(m, "port", path)?;
    ensure!(
        (0..=65535).contains(&port_raw),
        "active port out of range at {path}"
    );
    let port = port_raw as u16;

    let enabled = !raw_path.is_empty() || !uri.is_empty() || port != 0;

    let headers = parse_headers(m, path)?;

    let method_str = get_opt_string(m, "method", path)?;
    let method = match method_str {
        Some(ref s) if !s.is_empty() => s
            .parse::<http::Method>()
            .map_err(|_| anyhow::anyhow!("invalid HTTP method at {path}"))?,
        _ => http::Method::GET,
    };

    let follow_redirects = boolean(
        m.get("follow_redirects").filter(|v| !v.is_null()),
        false,
        path,
    )?;

    let interval_raw = get_dur(m, "interval", path, Duration::from_secs(30))?;
    let interval = if interval_raw.is_zero() {
        Duration::from_secs(30)
    } else {
        interval_raw
    };

    let timeout_raw = get_signed(m, "timeout", path, 5_000_000_000)?;
    let timeout = if timeout_raw == 0 {
        5_000_000_000
    } else {
        timeout_raw
    };

    let passes = {
        let v = get_i64(m, "passes", path)?.max(1);
        let v = u32::try_from(v).map_err(|_| anyhow::anyhow!("passes out of range at {path}"))?;
        ensure!(v <= 65536, "passes exceeds 65536 at {path}");
        v
    };
    let fails = {
        let v = get_i64(m, "fails", path)?.max(1);
        let v = u32::try_from(v).map_err(|_| anyhow::anyhow!("fails out of range at {path}"))?;
        ensure!(v <= 65536, "fails exceeds 65536 at {path}");
        v
    };

    let max_size = get_i64(m, "max_size", path)?;
    let expect_status = get_i64(m, "expect_status", path)?;

    let expect_body = if enabled {
        let text = get_opt_str(m, "expect_body", path)?;
        if text.is_empty() {
            None
        } else {
            let val = json!({ "pattern": text });
            Some(super::parse_request_regexp(&val, regex_remaining)?)
        }
    } else {
        None
    };

    Ok(ActiveCfg {
        uri_path_query,
        path: raw_path,
        uri,
        upstream,
        port,
        headers,
        method,
        body,
        follow_redirects,
        interval,
        timeout,
        passes,
        fails,
        max_size,
        expect_status,
        expect_body,
    })
}

fn parse_headers(m: &Map<String, Value>, path: &str) -> Result<Vec<(String, Vec<String>)>> {
    let v = match m.get("headers") {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(v) => v,
    };
    let obj = object(v, &format!("{path}.headers"))?;
    ensure!(
        obj.len() <= 256,
        "headers field count exceeds 256 at {path}"
    );
    let mut out: Vec<(String, Vec<String>)> = Vec::with_capacity(obj.len());
    let mut total = 0usize;
    for (k, val) in obj {
        ensure!(k.len() <= 4096, "health header name too long");
        total = total
            .checked_add(k.len())
            .ok_or_else(|| anyhow::anyhow!("health header budget overflow"))?;
        if val.is_null() {
            continue;
        }
        let arr = val
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("headers.{k} must be an array at {path}"))?;
        ensure!(arr.len() <= 65536, "health header values count exceeded");
        let mut vals = Vec::with_capacity(arr.len());
        for item in arr {
            let value = string(item, path)?;
            total = total
                .checked_add(value.len())
                .ok_or_else(|| anyhow::anyhow!("health header budget overflow"))?;
            ensure!(total <= 1 << 20, "health header byte budget exceeded");
            vals.push(value);
        }
        if vals.is_empty() {
            continue;
        }
        // Go http.Header.Add canonicalizes valid MIME token names before
        // placeholder expansion; invalid names remain unchanged until send.
        let key = if http::HeaderName::from_bytes(k.as_bytes()).is_ok() {
            let mut upper = true;
            k.bytes()
                .map(|c| {
                    let c = if upper {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    };
                    upper = c == b'-';
                    char::from(c)
                })
                .collect()
        } else {
            k.clone()
        };
        if let Some((_, existing)) = out.iter_mut().find(|(name, _)| *name == key) {
            existing.extend(vals);
        } else {
            out.push((key, vals));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// passive
// ---------------------------------------------------------------------------

fn parse_passive_opt(value: Option<&Value>, path: &str) -> Result<Option<PassiveCfg>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let m = object(v, path)?;
            deny_unknown(
                m,
                &[
                    "fail_duration",
                    "max_fails",
                    "unhealthy_request_count",
                    "unhealthy_status",
                    "unhealthy_latency",
                ],
                path,
            )?;
            let fail_duration = get_signed(m, "fail_duration", path, 0)?;
            let mut max_fails = get_i64(m, "max_fails", path)?;
            if max_fails == 0 {
                max_fails = 1;
            }
            ensure!(
                max_fails <= 65536,
                "passive health max_fails limit exceeded"
            );
            let unhealthy_request_count = get_i64(m, "unhealthy_request_count", path)?;
            let unhealthy_status = {
                let raw = m.get("unhealthy_status");
                match raw {
                    None | Some(Value::Null) => vec![],
                    Some(arr) => {
                        let list = arr
                            .as_array()
                            .ok_or_else(|| anyhow::anyhow!("array required at {path}"))?;
                        ensure!(
                            list.len() <= 256,
                            "unhealthy_status entries exceed 256 at {path}"
                        );
                        let mut out = Vec::with_capacity(list.len());
                        for item in list {
                            out.push(item.as_number().and_then(|n| n.as_i64()).ok_or_else(
                                || {
                                    anyhow::anyhow!(
                                        "integer required in unhealthy_status at {path}"
                                    )
                                },
                            )?);
                        }
                        out
                    }
                }
            };
            let unhealthy_latency = get_signed(m, "unhealthy_latency", path, 0)?;
            Ok(Some(PassiveCfg {
                fail_duration,
                max_fails,
                unhealthy_request_count,
                unhealthy_status,
                unhealthy_latency,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// retry
// ---------------------------------------------------------------------------

fn parse_retry_opt(
    value: Option<&Value>,
    path: &str,
    regex_remaining: &mut usize,
) -> Result<RetryCfg> {
    match value {
        None | Some(Value::Null) => Ok(RetryCfg {
            retries: 0,
            try_duration: Duration::ZERO,
            try_interval: Duration::ZERO,
            retry_match: None,
        }),
        Some(v) => {
            let m = object(v, path)?;
            deny_unknown(
                m,
                &[
                    "selection_policy",
                    "retries",
                    "try_duration",
                    "try_interval",
                    "retry_match",
                ],
                path,
            )?;
            let retries = {
                let raw = get_i64(m, "retries", path)?;
                ensure!(
                    (0..=65536).contains(&raw),
                    "retries out of range 0..=65536 at {path}"
                );
                raw as u32
            };
            let try_duration = get_dur(m, "try_duration", path, Duration::ZERO)?;
            let mut try_interval = get_dur(m, "try_interval", path, Duration::ZERO)?;
            if try_duration > Duration::ZERO && try_interval.is_zero() {
                try_interval = Duration::from_millis(250);
            }
            let retry_match = match m.get("retry_match") {
                None | Some(Value::Null) => None,
                Some(v) => {
                    let sets = super::parse_matcher_sets(Some(v), 0, regex_remaining)?;
                    (!sets.is_empty()).then_some(sets)
                }
            };
            Ok(RetryCfg {
                retries,
                try_duration,
                try_interval,
                retry_match,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// dynamic
// ---------------------------------------------------------------------------

fn parse_dynamic_opt(
    value: Option<&Value>,
    path: &str,
    depth: usize,
    count: &mut usize,
) -> Result<Option<DynamicCfg>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            ensure!(depth <= 4, "dynamic nesting depth exceeded at {path}");
            *count = count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("dynamic source count overflow"))?;
            ensure!(*count <= 64, "dynamic source count limit exceeded");
            let m = object(v, path)?;
            let source = get_opt_str(m, "source", path)?;
            match source.as_str() {
                "a" => {
                    deny_unknown(
                        m,
                        &[
                            "source",
                            "name",
                            "port",
                            "refresh",
                            "resolver",
                            "dial_timeout",
                            "dial_fallback_delay",
                            "versions",
                        ],
                        path,
                    )?;
                    Ok(Some(parse_dynamic_a(m, path)?))
                }
                "srv" => {
                    deny_unknown(
                        m,
                        &[
                            "source",
                            "name",
                            "service",
                            "proto",
                            "refresh",
                            "grace_period",
                            "resolver",
                            "dial_timeout",
                            "dial_fallback_delay",
                            "dial_network",
                        ],
                        path,
                    )?;
                    Ok(Some(parse_dynamic_srv(m, path)?))
                }
                "multi" => {
                    deny_unknown(m, &["source", "sources"], path)?;
                    let empty = Vec::new();
                    let raw_sources = match m.get("sources").filter(|v| !v.is_null()) {
                        None => &empty,
                        Some(value) => value
                            .as_array()
                            .ok_or_else(|| anyhow::anyhow!("dynamic sources array required"))?,
                    };
                    ensure!(
                        raw_sources.len() <= 64,
                        "dynamic source count limit exceeded"
                    );
                    let mut out = Vec::with_capacity(raw_sources.len());
                    for item in raw_sources {
                        let child = parse_dynamic_opt(Some(item), path, depth + 1, count)?
                            .ok_or_else(|| anyhow::anyhow!("null dynamic child source"))?;
                        out.push(child);
                    }
                    Ok(Some(DynamicCfg::Multi(out)))
                }
                other => Err(anyhow::anyhow!(
                    "unknown dynamic source \"{other}\" at {path}"
                )),
            }
        }
    }
}

fn parse_dns(m: &Map<String, Value>, path: &str) -> Result<DnsCfg> {
    let resolver = m.get("resolver").filter(|v| !v.is_null());
    let resolver_addresses = match resolver {
        None => None,
        Some(rv) => {
            let ro = object(rv, &format!("{path}.resolver"))?;
            deny_unknown(ro, &["addresses"], &format!("{path}.resolver"))?;
            match ro.get("addresses") {
                None | Some(Value::Null) => {
                    anyhow::bail!("configured DNS resolver requires addresses")
                }
                Some(arr) => {
                    let list = arr
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("addresses array required at {path}"))?;
                    ensure!(
                        !list.is_empty() && list.len() <= 64,
                        "resolver addresses must be non-empty and <= 64 at {path}"
                    );
                    let mut out = Vec::with_capacity(list.len());
                    for item in list {
                        let s = string(item, &format!("{path}.resolver.addresses"))?;
                        ensure!(
                            s.len() <= 4096,
                            "resolver address exceeds 4096 bytes at {path}"
                        );
                        out.push(s);
                    }
                    Some(out)
                }
            }
        }
    };
    let dial_timeout = get_signed(m, "dial_timeout", path, 0)?;
    let fallback_delay = m
        .get("dial_fallback_delay")
        .filter(|v| !v.is_null())
        .map(|v| signed_duration(v, path))
        .transpose()?
        .unwrap_or(0);
    Ok(DnsCfg {
        resolver_addresses,
        dial_timeout,
        fallback_delay,
    })
}

fn parse_dynamic_a(m: &Map<String, Value>, path: &str) -> Result<DynamicCfg> {
    let name = get_opt_str(m, "name", path)?;
    ensure!(name.len() <= 4096, "name exceeds 4096 bytes at {path}");
    let port = {
        let raw = m.get("port").filter(|v| !v.is_null());
        match raw {
            None => "80".to_owned(),
            Some(v) => {
                let s = string(v, path)?;
                ensure!(s.len() <= 4096, "port string exceeds 4096 bytes at {path}");
                if s.is_empty() { "80".to_owned() } else { s }
            }
        }
    };
    let refresh_raw = get_signed(m, "refresh", path, 60_000_000_000)?;
    let refresh = if refresh_raw == 0 {
        60_000_000_000
    } else {
        refresh_raw
    };
    let dns = parse_dns(m, path)?;
    let versions = match m.get("versions").filter(|v| !v.is_null()) {
        None => IpVersions::Any,
        Some(value) => {
            let versions = object(value, path)?;
            deny_unknown(versions, &["ipv4", "ipv6"], path)?;
            let v4 = boolean(versions.get("ipv4").filter(|v| !v.is_null()), false, path)?;
            let v6 = boolean(versions.get("ipv6").filter(|v| !v.is_null()), false, path)?;
            if v4 == v6 {
                IpVersions::Any
            } else if v4 {
                IpVersions::V4
            } else {
                IpVersions::V6
            }
        }
    };
    Ok(DynamicCfg::A {
        name,
        port,
        refresh,
        dns,
        versions,
    })
}

fn parse_dynamic_srv(m: &Map<String, Value>, path: &str) -> Result<DynamicCfg> {
    let name = get_opt_str(m, "name", path)?;
    ensure!(name.len() <= 4096, "name exceeds 4096 bytes at {path}");
    let service = get_opt_str(m, "service", path)?;
    ensure!(
        service.len() <= 4096,
        "service exceeds 4096 bytes at {path}"
    );
    let proto = get_opt_str(m, "proto", path)?;
    ensure!(proto.len() <= 4096, "proto exceeds 4096 bytes at {path}");
    let refresh_raw = get_signed(m, "refresh", path, 60_000_000_000)?;
    let refresh = if refresh_raw == 0 {
        60_000_000_000
    } else {
        refresh_raw
    };
    let grace_period = get_signed(m, "grace_period", path, 0)?;
    let dns = parse_dns(m, path)?;
    let dial_network = get_opt_str(m, "dial_network", path)?;
    ensure!(
        matches!(dial_network.as_str(), "" | "tcp" | "tcp4" | "tcp6"),
        "invalid dial_network at {path}"
    );
    Ok(DynamicCfg::Srv {
        name,
        service,
        proto,
        refresh,
        grace_period,
        dns,
        dial_network,
    })
}
