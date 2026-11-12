//! Native types shared by CEL and template replacer consumers. String rendering
//! remains in Context::lookup; this projection does not stringify native values.
use super::{ConnectionSnapshot, request::Context};
use serde_json::Value as Json;
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct TimeValue {
    pub unix_seconds: i64,
    pub nanoseconds: u32,
    pub offset_seconds: i32,
    pub zone: String,
}
#[derive(Clone)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Double(f64),
    String(String),
    Json(Arc<Json>),
    Time(TimeValue),
    Duration(i64),
    Error(String),
    TlsClient {
        cache: Arc<super::client_cert_facts::Cache>,
        field: String,
    },
    Unavailable(String),
}
/// Request-owned facts needed by a blocking template worker. Retaining the
/// generation Arc does not retain the active-request BusinessGuard.
#[derive(Clone)]
pub(crate) struct Dynamic {
    started: std::time::Instant,
    generation: Arc<super::retirement::BusinessGeneration>,
    probe: bool,
}
impl Dynamic {
    pub(super) fn capture(ctx:&Context)->Self {
        Self {started:ctx.request_started,generation:ctx.business.generation().clone(),probe:ctx.probe}
    }
    pub(crate) fn get(&self,name:&str)->Option<Value> {
        if self.probe {return None}
        Some(match name {
            "http.shutting_down"=>Value::Bool(self.generation.shutting_down()),
            "http.time_until_shutdown"=>self.generation.time_until_shutdown().map_or(Value::Null,|s|crate::duration::parse_str(&s).map_or_else(|e|Value::Unavailable(e.to_string()),Value::Duration)),
            "http.request.duration"=>Value::Duration(self.started.elapsed().as_nanos().min(i64::MAX as u128) as i64),
            "http.request.duration_ms"=>Value::Double(self.started.elapsed().as_secs_f64()*1000.),
            _=>return None,
        })
    }
}
/// Resolve fresh global values on the caller's bounded blocking worker. In
/// particular, time.now is not a captured request-time value. The year/unix/ms
/// global names are Go-formatted strings, not numeric values.
pub(crate) fn global(name: &str) -> Option<Value> {
    if name == "time.now" {
        let now = chrono::Utc::now();
        let (offset_seconds, zone) = crate::http_config::helpers::local_zone_info(now.timestamp())
            .unwrap_or((0, "UTC".into()));
        return Some(Value::Time(TimeValue {
            unix_seconds: now.timestamp(),
            nanoseconds: now.timestamp_subsec_nanos(),
            offset_seconds,
            zone,
        }));
    }
    crate::http_config::helpers::global_lookup(name).map(Value::String)
}
pub(crate) fn is_global(name: &str) -> bool {
    name.starts_with("env.")
        || matches!(
            name,
            "system.hostname"
                | "system.slash"
                | "system.os"
                | "system.wd"
                | "system.arch"
                | "time.now"
                | "time.now.http"
                | "time.now.common_log"
                | "time.now.year"
                | "time.now.unix"
                | "time.now.unix_ms"
        )
}
/// Project only request-scoped values. Dynamic globals are deliberately excluded
/// so a template's input capture cannot freeze later ph(time.now) calls.
pub(super) fn request(ctx: &Context, name: &str) -> Option<Value> {
    if is_global(name) {
        return None;
    }
    if ctx.probe {
        return None;
    }
    if let Some(key) = name.strip_prefix("http.vars.") {
        if let Some(value) = ctx.typed_vars.get(key) {
            return Some(Value::Json(value.clone()));
        }
    }
    if name == "http.shutting_down" {
        return Some(Value::Bool(ctx.business.generation().shutting_down()));
    }
    if name == "http.time_until_shutdown" {
        return Some(
            ctx.business
                .generation()
                .time_until_shutdown()
                .map_or(Value::Null, |s| {
                    crate::duration::parse_str(&s)
                        .map_or_else(|e| Value::Unavailable(e.to_string()), Value::Duration)
                }),
        );
    }
    if matches!(name, "http.request.duration" | "http.request.duration_ms") {
        let duration = ctx.request_started.elapsed();
        return Some(if name.ends_with("_ms") {
            Value::Double(duration.as_secs_f64() * 1000.)
        } else {
            Value::Duration(duration.as_nanos().min(i64::MAX as u128) as i64)
        });
    }
    if let Some(field) = name.strip_prefix("http.request.tls.") {
        let field = field.to_ascii_lowercase();
        let scalar = matches!(
            field.as_str(),
            "version"
                | "cipher_suite"
                | "resumed"
                | "proto"
                | "proto_mutual"
                | "server_name"
                | "ech"
        );
        let client = matches!(
            field.as_str(),
            "client.fingerprint"
                | "client.public_key"
                | "client.public_key_sha256"
                | "client.issuer"
                | "client.serial"
                | "client.subject"
                | "client.certificate_pem"
                | "client.certificate_der_base64"
        ) || field.starts_with("client.san.");
        if !scalar && !client {
            return None;
        }
        if !ctx.tls {
            return Some(Value::Null);
        }
        let Some(snapshot) = ctx
            .req()
            .extensions()
            .get::<Arc<ConnectionSnapshot>>()
            .cloned()
        else {
            return Some(Value::Unavailable("TLS connection snapshot missing".into()));
        };
        if client {
            return Some(match ctx.req().extensions().get::<Arc<super::client_cert_facts::Cache>>() {
                Some(cache) => Value::TlsClient { cache: cache.clone(), field },
                None => Value::Unavailable("TLS client certificate cache missing".into()),
            });
        }
        let meta = match snapshot.metadata() {
            Ok(meta) => meta,
            Err(e) => return Some(Value::Unavailable(e.to_string())),
        };
        return Some(match field.as_str() {
            "version" => Value::String(match meta.version {
                0x0303 => "tls1.2".into(),
                0x0304 => "tls1.3".into(),
                n => format!("0x{n:04x}"),
            }),
            "cipher_suite" => Value::String(
                format!("{:?}", rustls::CipherSuite::from(meta.cipher_suite))
                    .replacen("TLS13_", "TLS_", 1),
            ),
            "resumed" => Value::Bool(meta.did_resume),
            "proto" => Value::String(String::from_utf8_lossy(&meta.alpn).into_owned()),
            "proto_mutual" => Value::Bool(meta.negotiated_protocol_is_mutual),
            "server_name" => Value::String(meta.server_name.to_string()),
            "ech" => Value::Bool(meta.ech_accepted),
            _ => unreachable!(),
        });
    }
    if matches!(name, "http.request.body" | "http.request.body_base64") {
        return Some(Value::Unavailable(
            "request body placeholder requires asynchronous capture".into(),
        ));
    }
    let raw = ctx.lookup(name)?;
    if name == "http.error" {
        return Some(Value::Error(raw));
    }
    if matches!(
        name,
        "http.request.port"
            | "http.request.local.port"
            | "http.request.remote.port"
            | "http.error.status_code"
            | "http.reverse_proxy.status_code"
            | "http.reverse_proxy.retries"
            | "http.reverse_proxy.upstream.requests"
            | "http.reverse_proxy.upstream.max_requests"
            | "http.reverse_proxy.upstream.fails"
    ) {
        return Some(raw.parse().map_or_else(|_| Value::String(raw), Value::Int));
    }
    if name == "http.reverse_proxy.is_transport_error" {
        return Some(Value::Bool(raw == "true"));
    }
    if matches!(
        name,
        "http.reverse_proxy.duration_ms"
            | "http.reverse_proxy.upstream.duration_ms"
            | "http.reverse_proxy.upstream.latency_ms"
    ) {
        return Some(raw.parse().map_or_else(
            |_| Value::Unavailable("invalid duration milliseconds".into()),
            Value::Double,
        ));
    }
    if matches!(
        name,
        "http.reverse_proxy.duration"
            | "http.reverse_proxy.upstream.duration"
            | "http.reverse_proxy.upstream.latency"
    ) {
        return Some(
            crate::duration::parse_str(&raw)
                .map_or_else(|e| Value::Unavailable(e.to_string()), Value::Duration),
        );
    }
    Some(Value::String(raw))
}
