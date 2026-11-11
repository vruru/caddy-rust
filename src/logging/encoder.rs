// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
//! Prepared encoder operations preserve Caddy's value-receiver marshaler chain.
//! Nested filters are not equivalent to ordinary full-path JSON transforms.
use super::{
    bounded::Buffer,
    console_encoder::ConsoleEncoder,
    filter_cookie::Cookie,
    filter_query::Query,
    filter_simple::{Simple, View},
    json_encoder::{JsonEncoder, Sink},
    level::Level,
    module_config,
    primitives::{Common, LocalZone},
    types::{Entry, Field, FieldValue},
};
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Map, Value};
use std::{borrow::Cow, collections::BTreeMap};
enum Filter {
    Simple(Simple),
    Cookie(Cookie),
    Query(Query),
}
impl Filter {
    fn parse(value: Value, limit: usize) -> Result<Self> {
        let (name, fields) = module_config::inline(value, "filter", limit, true)?;
        if matches!(
            name.as_str(),
            "delete" | "hash" | "replace" | "rename" | "ip_mask"
        ) {
            return Ok(Self::Simple(
                Simple::from_module(&name, fields)
                    .ok_or_else(|| anyhow!("log filter module invariant"))??,
            ));
        }
        if matches!(name.as_str(), "cookie" | "set_cookie") {
            return Ok(Self::Cookie(
                Cookie::from_module(&name, fields)
                    .ok_or_else(|| anyhow!("log cookie module invariant"))??,
            ));
        }
        if name == "query" {
            return Ok(Self::Query(
                Query::from_module(&name, fields)
                    .ok_or_else(|| anyhow!("log query module invariant"))??,
            ));
        }
        bail!("unsupported native logging filter module")
    }
    fn apply<'a>(&'a self, mut view: View<'a>, limit: usize) -> Result<Option<View<'a>>> {
        match self {
            Self::Simple(f) => f.apply(view, limit),
            Self::Cookie(f) => {
                if let Some(value) = f.apply(&view.value, limit)? {
                    view.value = Cow::Owned(value);
                }
                Ok(Some(view))
            }
            Self::Query(f) => {
                if let Some(value) = f.apply(&view.value, limit)? {
                    view.value = Cow::Owned(value);
                }
                Ok(Some(view))
            }
        }
    }
}
enum AppendValue {
    Static(FieldValue),
    Placeholder(String),
}
struct FilterLayer {
    fields: BTreeMap<String, Filter>,
    max_key: usize,
}
enum Layer {
    Filter(FilterLayer),
    Append(Vec<(String, AppendValue)>),
    Journald,
}
enum Base {
    Json(JsonEncoder),
    Console(ConsoleEncoder),
}
pub(super) struct Encoder {
    layers: Vec<Layer>,
    base: Base,
    limit: usize,
}
/// Only placeholder results are copied; static configured values stay borrowed.
pub(super) struct Resolved {
    values: Vec<Vec<Option<FieldValue>>>,
}
impl Encoder {
    pub(super) fn prepare(
        mut value: Option<Value>,
        terminal: bool,
        coloring: bool,
        limit: usize,
    ) -> Result<Self> {
        let mut layers = Vec::new();
        let mut work = limit;
        let mut journal = false;
        loop {
            ensure!(layers.len() < 64, "log encoder nesting limit exceeded");
            let (name, mut fields) = if let Some(value) = value.take() {
                let size = crate::admin_json::encoded_len_typed(&value, work)
                    .map_err(|_| anyhow!("log encoder preparation byte limit exceeded"))?;
                work -= size;
                module_config::inline(value, "format", limit, !layers.is_empty())?
            } else {
                let mut fields = Map::new();
                // Caddy's root production formatter retains lower-case levels
                // when its process coloring flag is off. Explicit console and
                // wrappers' console defaults still use ConsoleEncoder colors.
                if terminal && layers.is_empty() && !coloring {
                    fields.insert("level_format".into(), Value::String("lower".into()));
                }
                (if terminal { "console" } else { "json" }.into(), fields)
            };
            match name.as_str() {
                "append" => {
                    deny(&fields, &["wrap", "fields"])?;
                    value = fields.remove("wrap");
                    let raw = match fields.remove("fields") {
                        None | Some(Value::Null) => Map::new(),
                        Some(Value::Object(map)) => map,
                        _ => bail!("log append fields must be an object"),
                    };
                    let mut appended = Vec::new();
                    appended
                        .try_reserve_exact(raw.len())
                        .map_err(|_| anyhow!("log append allocation failed"))?;
                    for (key, value) in raw {
                        let value = if let Value::String(s) = &value {
                            if s.starts_with('{')
                                && s.ends_with('}')
                                && s.bytes().filter(|b| *b == b'{').count() == 1
                            {
                                AppendValue::Placeholder(s.trim_matches(['{', '}']).into())
                            } else {
                                AppendValue::Static(FieldValue::String(s.clone()))
                            }
                        } else {
                            AppendValue::Static(any_json(value, limit)?)
                        };
                        appended.push((key, value));
                    }
                    layers.push(Layer::Append(appended));
                }
                "filter" => {
                    deny(&fields, &["wrap", "fields"])?;
                    value = fields.remove("wrap");
                    let raw = match fields.remove("fields") {
                        None | Some(Value::Null) => Map::new(),
                        Some(Value::Object(map)) => map,
                        _ => bail!("log filter fields must be an object"),
                    };
                    let mut parsed = BTreeMap::new();
                    let mut max_key = 0;
                    for (key, value) in raw {
                        max_key = max_key.max(key.len());
                        parsed.insert(key, Filter::parse(value, limit)?);
                    }
                    layers.push(Layer::Filter(FilterLayer {
                        fields: parsed,
                        max_key,
                    }));
                }
                "journald" => {
                    deny(&fields, &["wrap"])?;
                    value = fields.remove("wrap");
                    layers.push(Layer::Journald);
                    journal = true;
                }
                "json" | "console" => {
                    deny(
                        &fields,
                        &[
                            "message_key",
                            "level_key",
                            "time_key",
                            "name_key",
                            "caller_key",
                            "stacktrace_key",
                            "line_ending",
                            "time_format",
                            "time_local",
                            "duration_format",
                            "level_format",
                        ],
                    )?;
                    let mut common = Common::parse(&mut fields, name == "console")?;
                    if journal && name == "console" {
                        common.time_key.clear();
                    }
                    let base = if name == "json" {
                        Base::Json(JsonEncoder { common })
                    } else {
                        Base::Console(ConsoleEncoder {
                            wrapped: JsonEncoder { common },
                        })
                    };
                    return Ok(Self {
                        layers,
                        base,
                        limit,
                    });
                }
                _ => bail!("unsupported native logging encoder module"),
            }
            // Unspecified wrapped encoders default to JSON, then terminal adjustment.
            // Explicit null remains Some(null), causing the module loader to reject it.
        }
    }
    pub(super) fn dynamic_count(&self) -> usize {
        self.layers
            .iter()
            .map(|layer| match layer {
                Layer::Append(fields) => fields
                    .iter()
                    .filter(|(_, value)| matches!(value, AppendValue::Placeholder(_)))
                    .count(),
                _ => 0,
            })
            .sum()
    }
    /// Must run on an owned I/O preparation lane: lookup may read file providers.
    /// No placeholder or filesystem lookup occurs in the CPU encoder lane.
    pub(super) fn resolve(
        &self,
        lookup: &mut dyn FnMut(&str) -> Result<Option<FieldValue>>,
    ) -> Result<Resolved> {
        let slots = self
            .layers
            .iter()
            .map(|l| match l {
                Layer::Append(f) => f.len(),
                _ => 0,
            })
            .sum::<usize>();
        let overhead = slots
            .checked_mul(std::mem::size_of::<Option<FieldValue>>())
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| anyhow!("log resolved placeholder slot limit exceeded"))?;
        let mut remaining = self.limit - overhead;
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.layers.len())
            .map_err(|_| anyhow!("log placeholder allocation failed"))?;
        for layer in &self.layers {
            let mut items = Vec::new();
            if let Layer::Append(fields) = layer {
                items
                    .try_reserve_exact(fields.len())
                    .map_err(|_| anyhow!("log placeholder allocation failed"))?;
                for (_, value) in fields {
                    items.push(match value {
                        AppendValue::Static(_) => None,
                        AppendValue::Placeholder(key) => {
                            let value = lookup(key)?.unwrap_or(FieldValue::Null);
                            charge_value(&value, &mut remaining)?;
                            Some(value)
                        }
                    });
                }
            }
            values.push(items);
        }
        Ok(Resolved { values })
    }
    pub(super) fn encode_entry(
        &self,
        event: Entry<'_>,
        bound: &[Field],
        resolved: &Resolved,
        local: LocalZone,
        limit: usize,
    ) -> Result<Vec<u8>> {
        let limit = self.limit.min(limit);
        ensure!(
            resolved.values.len() == self.layers.len(),
            "log resolved placeholder generation mismatch"
        );
        let mut workspace = limit;
        let mut emit = |sink: &mut dyn Sink| -> Result<()> {
            for field in bound.iter().chain(&event.fields) {
                self.push(
                    0,
                    Walk {
                        start: 0,
                        prefix: Some(""),
                    },
                    View {
                        key: &field.key,
                        value: Cow::Borrowed(&field.value),
                    },
                    sink,
                    &mut workspace,
                    0,
                )?;
            }
            for (i, layer) in self.layers.iter().enumerate() {
                if let Layer::Append(fields) = layer {
                    ensure!(
                        resolved.values[i].len() == fields.len(),
                        "log resolved placeholder shape mismatch"
                    );
                    for (j, (key, value)) in fields.iter().enumerate() {
                        let value = match value {
                            AppendValue::Static(value) => value,
                            AppendValue::Placeholder(_) => resolved.values[i][j]
                                .as_ref()
                                .ok_or_else(|| anyhow!("log placeholder result missing"))?,
                        };
                        self.push(
                            i + 1,
                            Walk {
                                start: i + 1,
                                prefix: Some(""),
                            },
                            View {
                                key,
                                value: Cow::Borrowed(value),
                            },
                            sink,
                            &mut workspace,
                            0,
                        )?;
                    }
                }
            }
            Ok(())
        };
        let prefixes = self
            .layers
            .iter()
            .filter(|l| matches!(l, Layer::Journald))
            .count();
        let prefix_bytes =
            prefixes
                .checked_mul(3)
                .filter(|n| *n <= limit)
                .ok_or(super::bounded::ByteLimit(
                    "log journald prefix byte limit exceeded",
                ))?;
        let inner_limit = limit - prefix_bytes;
        let bytes = match &self.base {
            Base::Json(base) => base.encode_stream(event, inner_limit, local, &mut emit)?,
            Base::Console(base) => base.encode_stream(event, inner_limit, local, &mut emit)?,
        };
        if prefixes == 0 {
            return Ok(bytes);
        }
        let mut out = Buffer::new(limit);
        let priority = match event.level {
            Level::Debug => b"<7>",
            Level::Info => b"<6>",
            Level::Warn => b"<4>",
            Level::Error => b"<3>",
            _ => b"<2>",
        };
        for _ in 0..prefixes {
            out.bytes(priority)?;
        }
        out.bytes(&bytes)?;
        Ok(out.into_vec())
    }
    fn push<'a>(
        &'a self,
        mut i: usize,
        walk: Walk<'_>,
        mut view: View<'a>,
        sink: &mut dyn Sink,
        workspace: &mut usize,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth <= 128, "log wrapper field depth limit exceeded");
        let saved = *workspace;
        let mut source: Option<(usize, Option<String>)> = None;
        while i < self.layers.len() {
            if let Layer::Filter(filter) = &self.layers[i]
                && !matches!(*view.value, FieldValue::Namespace)
            {
                let prefix = if i == walk.start {
                    walk.prefix
                } else {
                    Some("")
                };
                let mut composite = None;
                if let Some(prefix) = prefix
                    && !prefix.is_empty()
                    && prefix
                        .len()
                        .checked_add(view.key.len())
                        .is_some_and(|n| n <= filter.max_key)
                {
                    let n = prefix.len() + view.key.len();
                    charge(n, workspace)?;
                    let mut key = String::new();
                    key.try_reserve_exact(n)
                        .map_err(|_| anyhow!("log filter key allocation failed"))?;
                    key.push_str(prefix);
                    key.push_str(view.key);
                    composite = Some(key);
                }
                let rule = prefix.and_then(|p| {
                    if p.is_empty() {
                        filter.fields.get(view.key)
                    } else {
                        composite.as_ref().and_then(|k| filter.fields.get(k))
                    }
                });
                if let Some(rule) = rule {
                    if !matches!(rule, Filter::Simple(Simple::Delete | Simple::Replace(_))) {
                        view.value = as_any(view.value, workspace)?;
                    }
                    let Some(next) = rule.apply(view, *workspace)? else {
                        *workspace = saved;
                        return Ok(());
                    };
                    if let Cow::Owned(value) = &next.value {
                        charge_value(value, workspace)?;
                    }
                    view = next;
                } else if source.is_none() && matches!(*view.value, FieldValue::Object(_)) {
                    let child = if let Some(prefix) = prefix {
                        let size = prefix
                            .len()
                            .checked_add(view.key.len())
                            .and_then(|n| n.checked_add(1))
                            .ok_or_else(|| anyhow!("log filter prefix overflow"))?;
                        if size <= filter.max_key {
                            charge(size, workspace)?;
                            let mut child = String::new();
                            child
                                .try_reserve_exact(size)
                                .map_err(|_| anyhow!("log filter prefix allocation failed"))?;
                            child.push_str(prefix);
                            child.push_str(view.key);
                            child.push('>');
                            if filter
                                .fields
                                .range::<str, _>((
                                    std::ops::Bound::Included(child.as_str()),
                                    std::ops::Bound::Unbounded,
                                ))
                                .next()
                                .is_some_and(|(key, _)| key.starts_with(&child))
                            {
                                Some(child)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    source = Some((i, child));
                }
            }
            i += 1;
        }
        if let (FieldValue::Object(fields), Some((start, prefix))) = (&*view.value, source) {
            sink.object(view.key, &mut |nested| {
                for field in fields {
                    self.push(
                        start,
                        Walk {
                            start,
                            prefix: prefix.as_deref(),
                        },
                        View {
                            key: &field.key,
                            value: Cow::Borrowed(&field.value),
                        },
                        nested,
                        workspace,
                        depth + 1,
                    )?;
                }
                Ok(())
            })?;
        } else {
            sink.add(view.key, &view.value)?;
        }
        *workspace = saved;
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct Walk<'a> {
    start: usize,
    prefix: Option<&'a str>,
}
fn deny(fields: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    crate::http_config::helpers::deny_unknown(fields, allowed, "/logging/encoder")
}
fn any_json(value: Value, limit: usize) -> Result<FieldValue> {
    Ok(match value {
        Value::Null => FieldValue::Null,
        Value::String(s) => FieldValue::String(s),
        Value::Bool(b) => FieldValue::Bool(b),
        Value::Number(n) => FieldValue::F64(
            n.as_f64()
                .ok_or_else(|| anyhow!("invalid appended log number"))?,
        ),
        other => {
            let bytes = crate::admin_json::encoded(&other)
                .map_err(|_| anyhow!("appended log JSON encoding failed"))?;
            ensure!(
                bytes.len() <= limit,
                "appended log JSON byte limit exceeded"
            );
            FieldValue::Reflected(
                crate::admin_json::decoded(&bytes)
                    .map_err(|_| anyhow!("appended log JSON normalization failed"))?,
            )
        }
    })
}
fn as_any<'a>(value: Cow<'a, FieldValue>, workspace: &mut usize) -> Result<Cow<'a, FieldValue>> {
    let normalized = match &*value {
        FieldValue::ByteString(bytes) => {
            charge(bytes.len(), workspace)?;
            Some(FieldValue::Binary(bytes.clone()))
        }
        FieldValue::Reflected(Value::String(s)) => {
            charge(s.len(), workspace)?;
            Some(FieldValue::String(s.clone()))
        }
        FieldValue::Reflected(Value::Null) => Some(FieldValue::Null),
        FieldValue::Reflected(Value::Bool(b)) => Some(FieldValue::Bool(*b)),
        FieldValue::Reflected(Value::Number(n)) => Some(FieldValue::F64(
            n.as_f64()
                .ok_or_else(|| anyhow!("invalid reflected log number"))?,
        )),
        _ => None,
    };
    Ok(normalized.map_or(value, Cow::Owned))
}
fn charge(n: usize, remaining: &mut usize) -> Result<()> {
    *remaining = remaining.checked_sub(n).ok_or(super::bounded::ByteLimit(
        "log wrapper workspace byte limit exceeded",
    ))?;
    Ok(())
}
fn charge_value(value: &FieldValue, remaining: &mut usize) -> Result<()> {
    let n = match value {
        FieldValue::String(s) | FieldValue::Error(s) => s.len(),
        FieldValue::Binary(v) | FieldValue::ByteString(v) | FieldValue::RawString(v) => v.len(),
        FieldValue::StringArray(values) => values.iter().try_fold(
            values
                .len()
                .checked_mul(std::mem::size_of::<Vec<u8>>())
                .ok_or_else(|| anyhow!("log array size overflow"))?,
            |n, v| {
                n.checked_add(v.len())
                    .ok_or_else(|| anyhow!("log array size overflow"))
            },
        )?,
        FieldValue::Reflected(value) => crate::admin_json::encoded_len_typed(value, *remaining)
            .map_err(super::bounded::reflection_error)?,
        FieldValue::Object(_) | FieldValue::Array(_) => {
            bail!("log placeholder lookup returned an unsupported owned marshaler")
        }
        _ => 0,
    };
    charge(n, remaining)
}
