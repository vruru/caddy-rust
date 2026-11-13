//! A route's immutable, provisioned handler description. Trace admission never
//! affects handler execution and never evaluates request placeholders.
use crate::{
    http_config::types::Handler,
    logging::{Event, Field, FieldValue, Level, Logging, Origin},
};
use anyhow::Result;
use serde_json::{Map, Value, json};
use std::sync::{Arc, LazyLock};
const COPY_POOL: usize = 64 << 20;
static COPIES: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(COPY_POOL));
#[derive(Clone)]
pub(crate) struct Module {
    name: Arc<str>,
    value: Arc<Value>,
    copy_bytes: usize,
}
impl Module {
    pub(crate) fn metric_name(&self)->Arc<str>{self.name.clone()}
    pub(crate) fn redirect(location: &str) -> Self {
        let value = json!({"status_code":308,"headers":{"Location":[location]},"close":true});
        Self {
            name: Arc::from("static_response"),
            copy_bytes: copy_upper(&value),
            value: Arc::new(value),
        }
    }
    pub(crate) fn prepare(raw: &Value, handler: &Handler, normalized: bool) -> Result<Self> {
        let raw = crate::module_json::inline(raw, "handler", normalized)?;
        let name = raw["handler"].as_str().unwrap_or_default();
        let mut value = reflected_fields(name, raw.as_ref());
        if name != "vars" {
            prune(&mut value, pointers(name));
        }
        match handler {
            Handler::StaticResponse { status, .. }
            | Handler::StaticError { status, .. }
            | Handler::CopyResponse(status) => weak(&mut value, "status_code", status),
            Handler::Headers { .. } => headers(&mut value),
            Handler::Map(plan) => {
                let destinations=&plan.destinations;
                if !destinations.is_empty() {
                    value.insert("destinations".into(), json!(&**destinations));
                }
            }
            Handler::Subroute { .. } => {
                routes(value.get_mut("routes"));
                if let Some(errors) = value.get_mut("errors").and_then(Value::as_object_mut) {
                    routes(errors.get_mut("routes"));
                }
            }
            Handler::Intercept(_) => responses(value.get_mut("handle_response")),
            Handler::Authentication { .. } => {
                value.remove("providers");
            }
            Handler::Templates(_) => {
                value.remove("match");
                default_string(&mut value, "file_root", "{http.vars.root}");
                if raw.get("mime_types").is_none_or(Value::is_null) {
                    value.insert(
                        "mime_types".into(),
                        json!(["text/html", "text/plain", "text/markdown"]),
                    );
                }
            }
            Handler::Encode(plan) => {
                value.remove("encodings");
                value.insert("minimum_length".into(), json!(plan.minimum_length));
                if !plan.prefer.is_empty() {
                    value.insert(
                        "prefer".into(),
                        json!(plan.prefer.iter().map(|c| c.as_str()).collect::<Vec<_>>()),
                    );
                }
                if raw.get("match").is_none_or(Value::is_null) {
                    value.insert("match".into(),json!({"headers":{"Content-Type":super::encode_response::DEFAULT_TYPES.iter().map(|v|format!("{}*",String::from_utf8_lossy(v))).collect::<Vec<_>>()}}));
                }
            }
            Handler::FileServer { .. } => {
                value.remove("precompressed");
                default_string(&mut value, "fs", "{http.vars.fs}");
                default_string(&mut value, "root", "{http.vars.root}");
                if raw.get("index_names").is_none_or(Value::is_null) {
                    value.insert("index_names".into(), json!(["index.html", "index.txt"]));
                }
                if let Some(hide) = value.get_mut("hide").and_then(Value::as_array_mut) {
                    for item in hide {
                        if let Some(path) = item
                            .as_str()
                            .filter(|s| !s.contains('{') && s.contains(std::path::MAIN_SEPARATOR))
                        {
                            let path = std::path::absolute(path)?;
                            *item =
                                json!(super::request::clean_path(&path.to_string_lossy(), true));
                        }
                    }
                }
                if let Some(status) = raw.get("status_code") {
                    let text = crate::module_json::weak_string(status)?;
                    weak(&mut value, "status_code", &text);
                }
            }
            Handler::ReverseProxy(proxy) => {
                value.remove("transport");
                value.remove("circuit_breaker");
                value.remove("dynamic_upstreams");
                let lb = value
                    .entry("load_balancing")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .expect("validated load balancing object");
                lb.remove("selection_policy");
                lb.remove("retry_match");
                prune(lb, &[]);
                durations(lb, &["try_duration", "try_interval"])?;
                if lb
                    .get("try_duration")
                    .and_then(Value::as_i64)
                    .unwrap_or_default()
                    > 0
                    && lb
                        .get("try_interval")
                        .and_then(Value::as_i64)
                        .unwrap_or_default()
                        == 0
                {
                    lb.insert("try_interval".into(), json!(250_000_000));
                }
                durations(
                    &mut value,
                    &["flush_interval", "stream_timeout", "stream_close_delay"],
                )?;
                let request_buffers = if proxy.ext.request_buffers != 0 {
                    proxy.ext.request_buffers
                } else {
                    proxy
                        .fastcgi
                        .as_ref()
                        .and_then(|config| config.request_buffer)
                        .and_then(|n| i64::try_from(n).ok())
                        .unwrap_or_default()
                };
                if request_buffers != 0 {
                    value.insert("request_buffers".into(), json!(request_buffers));
                }
                if let Some(v) = value.get_mut("headers").and_then(Value::as_object_mut) {
                    headers(v);
                }
                if let Some(v) = value
                    .get_mut("health_checks")
                    .and_then(Value::as_object_mut)
                {
                    if let Some(passive) = v.get_mut("passive").and_then(Value::as_object_mut) {
                        prune(passive, &[]);
                        durations(passive, &["fail_duration", "unhealthy_latency"])?;
                        if !passive.contains_key("max_fails") {
                            passive.insert("max_fails".into(), json!(1));
                        }
                    }
                    if let Some(active) = v.get_mut("active").and_then(Value::as_object_mut) {
                        prune(active, &[]);
                        durations(active, &["interval", "timeout"])?;
                        let enabled = active
                            .get("uri")
                            .or_else(|| active.get("path"))
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())
                            || active
                                .get("port")
                                .and_then(Value::as_i64)
                                .is_some_and(|n| n != 0);
                        if enabled {
                            default_string(active, "method", "GET");
                            if !active.contains_key("interval") {
                                active.insert("interval".into(), json!(30_000_000_000i64));
                            }
                            for key in ["passes", "fails"] {
                                if active.get(key).and_then(Value::as_i64).unwrap_or_default() < 1 {
                                    active.insert(key.into(), json!(1));
                                }
                            }
                            if let Some(headers) =
                                active.get_mut("headers").and_then(Value::as_object_mut)
                            {
                                canonical_headers(headers);
                                if headers.is_empty() {
                                    active.remove("headers");
                                }
                            }
                        }
                    }
                }
                responses(value.get_mut("handle_response"));
            }
            _ => {}
        }
        let value = Value::Object(value);
        let copy_bytes = copy_upper(&value);
        Ok(Self {
            name: Arc::from(name),
            value: Arc::new(value),
            copy_bytes,
        })
    }
    pub(super) fn emit(&self, logging: &Logging) {
        if !logging.module_enabled("http", "http.log.trace", Level::Debug) {
            return;
        }
        let Ok(credits) = u32::try_from(self.copy_bytes) else {
            return;
        };
        let Ok(_credit) = COPIES.try_acquire_many(credits) else {
            return;
        };
        let Ok(mut event) = Event::new(
            Origin::Module {
                module_id: "http".into(),
            },
            "http.log.trace",
            Level::Debug,
            self.name.as_ref(),
        ) else {
            return;
        };
        event.fields.push(Field::new(
            "module",
            FieldValue::Reflected(self.value.as_ref().clone()),
        ));
        let _ = logging.try_emit(event);
    }
}
fn reflected_fields(name: &str, raw: &Value) -> Map<String, Value> {
    let cleared: &[&str] = match name {
        "encode" => &["encodings"],
        "templates" => &["match"],
        "authentication" => &["providers"],
        "file_server" => &["precompressed"],
        "reverse_proxy" => &["transport", "circuit_breaker", "dynamic_upstreams"],
        _ => &[],
    };
    raw.as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| {
            !matches!(key.as_str(), "handler" | "@id") && !cleared.contains(&key.as_str())
        })
        .map(|(key, value)| {
            let value = match (name, key.as_str()) {
                ("subroute", "routes") => route_snapshot(value),
                ("subroute", "errors") => Value::Object(
                    value
                        .as_object()
                        .into_iter()
                        .flatten()
                        .map(|(key, value)| {
                            (
                                key.clone(),
                                if key == "routes" {
                                    route_snapshot(value)
                                } else {
                                    value.clone()
                                },
                            )
                        })
                        .collect(),
                ),
                (_, "handle_response") => Value::Array(
                    value
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|response| {
                            Value::Object(
                                response
                                    .as_object()
                                    .into_iter()
                                    .flatten()
                                    .map(|(key, value)| {
                                        (
                                            key.clone(),
                                            if key == "routes" {
                                                route_snapshot(value)
                                            } else {
                                                value.clone()
                                            },
                                        )
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
                _ => value.clone(),
            };
            (key.clone(), value)
        })
        .collect()
}
fn route_snapshot(value: &Value) -> Value {
    Value::Array(
        value
            .as_array()
            .into_iter()
            .flatten()
            .map(|route| {
                Value::Object(
                    route
                        .as_object()
                        .into_iter()
                        .flatten()
                        .filter(|(key, value)| {
                            matches!(key.as_str(), "group" | "terminal") && !empty(value)
                        })
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                )
            })
            .collect(),
    )
}
fn pointers(name: &str) -> &[&str] {
    match name {
        "headers" => &["request", "response"],
        "subroute" => &["errors"],
        "encode" => &["match"],
        "file_server" => &["browse", "canonical_uris"],
        "reverse_proxy" => &["load_balancing", "health_checks", "headers", "rewrite"],
        _ => &[],
    }
}
fn empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(false) => true,
        Value::Number(n) => n.as_f64() == Some(0.),
        Value::String(s) => s.is_empty(),
        Value::Array(v) => v.is_empty(),
        Value::Object(v) => v.is_empty(),
        _ => false,
    }
}
fn prune(value: &mut Map<String, Value>, pointers: &[&str]) {
    value.retain(|key, value| {
        !value.is_null() && (pointers.contains(&key.as_str()) || !empty(value))
    });
}
fn default_string(value: &mut Map<String, Value>, key: &str, default: &str) {
    if !value.contains_key(key) {
        value.insert(key.into(), json!(default));
    }
}
fn weak(value: &mut Map<String, Value>, key: &str, text: &str) {
    if text.is_empty() {
        value.remove(key);
        return;
    }
    let result = match text {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => text
            .parse::<i64>()
            .map_or_else(|_| json!(text), |v| json!(v)),
    };
    value.insert(key.into(), result);
}
fn durations(value: &mut Map<String, Value>, keys: &[&str]) -> Result<()> {
    for key in keys {
        if let Some(raw) = value.get(*key) {
            let nanos = crate::duration::parse_value(raw)?;
            if nanos == 0 {
                value.remove(*key);
            } else {
                value.insert((*key).into(), json!(nanos));
            }
        }
    }
    Ok(())
}
fn headers(value: &mut Map<String, Value>) {
    for key in ["request", "response"] {
        if let Some(ops) = value.get_mut(key).and_then(Value::as_object_mut) {
            prune(ops, &["require"]);
            if let Some(set) = ops.get_mut("set").and_then(Value::as_object_mut) {
                canonical_headers(set);
            }
        }
    }
}
fn canonical_headers(headers: &mut Map<String, Value>) {
    let old = std::mem::take(headers);
    for (key, items) in old {
        let key = canonical(&key);
        let entry = headers.entry(key).or_insert_with(|| json!([]));
        if let (Some(to), Some(from)) = (entry.as_array_mut(), items.as_array()) {
            to.extend(from.iter().cloned());
        }
    }
}
fn canonical(value: &str) -> String {
    let mut upper = true;
    value
        .chars()
        .map(|c| {
            let result = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == '-';
            result
        })
        .collect()
}
fn routes(value: Option<&mut Value>) {
    if let Some(list) = value.and_then(Value::as_array_mut) {
        for route in list {
            if let Some(object) = route.as_object_mut() {
                object.remove("match");
                object.remove("handle");
                prune(object, &[]);
            }
        }
    }
}
fn responses(value: Option<&mut Value>) {
    if let Some(list) = value.and_then(Value::as_array_mut) {
        for response in list {
            if let Some(object) = response.as_object_mut() {
                routes(object.get_mut("routes"));
                prune(object, &["match"]);
                if let Some(raw) = object.get("status_code")
                    && let Ok(text) = crate::module_json::weak_string(raw)
                {
                    weak(object, "status_code", &text);
                }
            }
        }
    }
}
fn copy_upper(value: &Value) -> usize {
    // Rust stable BTreeMap uses 11 entries/12 edges per node. Include first-node
    // and child-node headroom, String storage, Value vectors, and record framing.
    let mut bytes = 4096usize;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(s) => bytes = bytes.saturating_add(s.len()),
            Value::Array(v) => {
                bytes = bytes.saturating_add(v.len().saturating_mul(std::mem::size_of::<Value>()));
                pending.extend(v);
            }
            Value::Object(v) => {
                let node = 64
                    + 11 * (std::mem::size_of::<String>() + std::mem::size_of::<Value>())
                    + 12 * std::mem::size_of::<usize>();
                bytes = bytes.saturating_add((v.len().div_ceil(5) + 3).saturating_mul(node));
                for (k, v) in v {
                    bytes = bytes.saturating_add(k.len());
                    pending.push(v);
                }
            }
            _ => {}
        }
    }
    bytes
}
