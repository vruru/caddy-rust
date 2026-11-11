// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Owned root/base logging configuration. Module provisioning remains separate.
use super::{limits::RuntimeLimits, routing::Routing};
use anyhow::{Result, bail, ensure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
pub(super) struct ParsedConfig {
    pub sink: Option<BaseLog>,
    pub logs: BTreeMap<String, CustomLog>,
}
pub(super) struct CustomLog {
    pub base: BaseLog,
    pub routing: Routing,
}
pub(super) struct BaseLog {
    pub writer: Option<Value>,
    pub encoder: Option<Value>,
    pub core: Option<Value>,
    pub level: String,
    pub sampling: Option<Sampling>,
    pub with_caller: bool,
    pub with_caller_skip: i64,
    pub with_stacktrace: String,
}
pub(super) struct Sampling {
    pub interval: i64,
    pub first: i64,
    pub thereafter: i64,
}
pub(super) fn string(value: Option<Value>) -> Result<String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s),
        _ => bail!("logging string field has invalid type"),
    }
}
pub(super) fn boolean(value: Option<Value>) -> Result<bool> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(v)) => Ok(v),
        _ => bail!("logging boolean field has invalid type"),
    }
}
pub(super) fn integer(value: Option<Value>) -> Result<i64> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n
            .as_go_i64()
            .ok_or_else(|| anyhow::anyhow!("logging integer field has invalid type or overflow")),
        _ => bail!("logging integer field has invalid type"),
    }
}
pub(super) fn duration(value: Option<Value>) -> Result<i64> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::String(s)) => crate::duration::parse_str(&s),
        some => integer(some),
    }
}
pub(super) fn strings(value: Option<Value>) -> Result<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => {
            ensure!(a.len() <= 65536, "logging array limit exceeded");
            a.into_iter().map(|v| string(Some(v))).collect()
        }
        _ => bail!("logging string array has invalid type"),
    }
}
fn object(value: Value) -> Result<Map<String, Value>> {
    if let Value::Object(m) = value {
        Ok(m)
    } else {
        bail!("logging configuration object required")
    }
}
fn known(m: &Map<String, Value>, names: &[&str]) -> Result<()> {
    crate::http_config::helpers::deny_unknown(m, names, "/logging/*")
}
pub(super) fn parse(value: Option<Value>, limits: &RuntimeLimits) -> Result<ParsedConfig> {
    limits.validate()?;
    let value = value.unwrap_or(Value::Null);
    preflight(&value, limits)?;
    crate::admin_json::encoded_len_typed(&value, limits.max_config_bytes)
        .map_err(|_| anyhow::anyhow!("logging configuration byte/depth limit exceeded"))?;
    let mut m = if value.is_null() {
        Map::new()
    } else {
        object(value)?
    };
    known(&m, &["sink", "logs"])?;
    let sink = match m.remove("sink") {
        None | Some(Value::Null) => None,
        Some(v) => Some(base(object(v)?, false)?.0),
    };
    let raw = match m.remove("logs") {
        None | Some(Value::Null) => Map::new(),
        Some(v) => object(v)?,
    };
    ensure!(
        raw.len()
            .checked_add(usize::from(!raw.contains_key("default")))
            .is_some_and(|n| n <= limits.max_logs),
        "logging log count limit exceeded"
    );
    let mut logs = BTreeMap::new();
    for (name, value) in raw {
        let (fields, include, exclude) = base(object(value)?, true)?;
        // The original validator is quadratic. Bound its actual comparison work
        // before entering it; a resource failure is never silently made a rule.
        let pairs = include
            .len()
            .checked_mul(exclude.len())
            .ok_or_else(|| anyhow::anyhow!("logging routing work limit exceeded"))?;
        ensure!(
            pairs <= limits.max_routing_comparisons,
            "logging routing work limit exceeded"
        );
        let routing = Routing::new(include, exclude)?;
        logs.insert(
            name,
            CustomLog {
                base: fields,
                routing,
            },
        );
    }
    // Default logger always exists, including when it discards its writes.
    if !logs.contains_key("default") {
        let (base, include, exclude) = base(Map::new(), true)?;
        logs.insert(
            "default".into(),
            CustomLog {
                base,
                routing: Routing::new(include, exclude)?,
            },
        );
    }
    Ok(ParsedConfig { sink, logs })
}
fn base(mut m: Map<String, Value>, custom: bool) -> Result<(BaseLog, Vec<String>, Vec<String>)> {
    let mut allowed = vec![
        "writer",
        "encoder",
        "core",
        "level",
        "sampling",
        "with_caller",
        "with_caller_skip",
        "with_stacktrace",
    ];
    if custom {
        allowed.extend(["include", "exclude"]);
    }
    known(&m, &allowed)?;
    let sampling = match m.remove("sampling") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let mut s = object(v)?;
            known(&s, &["interval", "first", "thereafter"])?;
            Some(Sampling {
                // Caddy LogSampling.Interval is Go time.Duration (JSON
                // integer nanoseconds), unlike caddy.Duration on writers.
                interval: integer(s.remove("interval"))?,
                first: integer(s.remove("first"))?,
                thereafter: integer(s.remove("thereafter"))?,
            })
        }
    };
    let include = strings(m.remove("include"))?;
    let exclude = strings(m.remove("exclude"))?;
    Ok((
        BaseLog {
            writer: m.remove("writer"),
            encoder: m.remove("encoder"),
            core: m.remove("core"),
            level: string(m.remove("level"))?,
            sampling,
            with_caller: boolean(m.remove("with_caller"))?,
            with_caller_skip: integer(m.remove("with_caller_skip"))?,
            with_stacktrace: string(m.remove("with_stacktrace"))?,
        },
        include,
        exclude,
    ))
}

fn preflight(value: &Value, limits: &RuntimeLimits) -> Result<()> {
    let mut nodes = 1usize;
    let mut weight = 0usize;
    let mut pending = vec![(value, 0usize)];
    while let Some((value, depth)) = pending.pop() {
        ensure!(
            depth <= crate::admin_json::MAX_CONFIG_DEPTH,
            "logging configuration depth limit exceeded"
        );
        weight = weight
            .checked_add(128)
            .filter(|n| *n <= limits.max_config_owned_bytes)
            .ok_or_else(|| anyhow::anyhow!("logging configuration owned-byte limit exceeded"))?;
        let mut bytes = |len: usize| -> Result<()> {
            weight = weight
                .checked_add(
                    len.checked_mul(4)
                        .ok_or_else(|| anyhow::anyhow!("logging configuration size overflow"))?,
                )
                .filter(|n| *n <= limits.max_config_owned_bytes)
                .ok_or_else(|| {
                    anyhow::anyhow!("logging configuration owned-byte limit exceeded")
                })?;
            Ok(())
        };
        match value {
            Value::String(s) => bytes(s.len())?,
            Value::Array(a) => {
                nodes = nodes
                    .checked_add(a.len())
                    .filter(|n| *n <= limits.max_config_nodes)
                    .ok_or_else(|| anyhow::anyhow!("logging configuration node limit exceeded"))?;
                for v in a {
                    pending.push((v, depth + 1));
                }
            }
            Value::Object(m) => {
                nodes = nodes
                    .checked_add(m.len())
                    .filter(|n| *n <= limits.max_config_nodes)
                    .ok_or_else(|| anyhow::anyhow!("logging configuration node limit exceeded"))?;
                for (k, v) in m {
                    bytes(k.len())?;
                    pending.push((v, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Go strings.ToLower uses simple Unicode mapping; Rust expands U+0130.
pub(super) fn simple_lower(input: &str) -> String {
    input
        .chars()
        .flat_map(|c| {
            if c == '\u{130}' {
                'i'.to_lowercase()
            } else {
                c.to_lowercase()
            }
        })
        .collect()
}
