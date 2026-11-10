//! Read-only configuration signals, never a runtime compatibility verdict.
use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_FIELDS: usize = 65_536;
const MAX_USES: usize = 16_384;
const FIXED: &[&str] = &[
    "apps",
    "http",
    "tls",
    "pki",
    "events",
    "admin",
    "config",
    "listen",
    "servers",
    "routes",
    "match",
    "not",
    "handle",
    "handler",
    "transport",
    "protocol",
    "protocols",
    "encodings",
    "load_balancing",
    "lb",
    "selection_policy",
    "policy",
    "trusted_proxies",
    "source",
    "automation",
    "policies",
    "issuers",
    "module",
    "certificates",
    "on_demand",
    "listener_wrappers",
    "wrapper",
    "logging",
    "logs",
    "output",
    "writer",
    "encoder",
    "format",
    "storage",
    "automatic_https",
    "disable",
    "disable_redirects",
    "disable_certificates",
    "ignore_loaded_certificates",
    "headers",
    "request",
    "response",
    "set",
    "add",
    "delete",
    "upstreams",
    "dial",
    "body",
    "uri",
    "host",
    "path",
    "method",
    "expression",
    "vars",
    "hosts",
    "ranges",
    "timeout",
    "terminal",
    "group",
    "@id",
];

#[derive(Clone)]
enum Segment {
    Key(String),
    Index(usize),
}
fn key(p: &[Segment], i: usize) -> Option<&str> {
    match p.get(i) {
        Some(Segment::Key(k)) => Some(k),
        _ => None,
    }
}
fn is_index(p: &[Segment], i: usize) -> bool {
    matches!(p.get(i), Some(Segment::Index(_)))
}
fn prefix(p: &[Segment], parts: &[&str]) -> bool {
    parts.iter().enumerate().all(|(i, s)| key(p, i) == Some(*s))
}
fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn pointer(p: &[Segment]) -> String {
    let mut result = String::new();
    for (i, part) in p.iter().enumerate() {
        let token = match part {
            Segment::Index(n) => n.to_string(),
            Segment::Key(k) => {
                let dynamic = i > 0
                    && matches!(
                        key(p, i - 1),
                        Some("servers" | "logs" | "hosts" | "vars" | "set" | "add")
                    );
                if !dynamic && FIXED.contains(&k.as_str()) {
                    k.clone()
                } else {
                    format!("key-sha256:{}", hex(k.as_bytes()))
                }
            }
        };
        result.push('/');
        result.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    result
}
fn child(p: &[Segment], name: &str) -> Vec<Segment> {
    let mut p = p.to_vec();
    p.push(Segment::Key(name.into()));
    p
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}
fn value_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
fn port(address: &str) -> Option<u16> {
    let s = address
        .strip_prefix("tcp/")
        .or_else(|| address.strip_prefix("tcp4/"))
        .or_else(|| address.strip_prefix("tcp6/"))
        .unwrap_or(address);
    if s.starts_with("unix/") || s.contains('/') {
        return None;
    }
    let (host, number) = s.rsplit_once(':')?;
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return None;
    }
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    number.parse().ok()
}

#[derive(Default)]
struct Visitor {
    fields: BTreeMap<String, &'static str>,
    modules: BTreeSet<(String, String)>,
    placeholders: BTreeSet<(String, String)>,
    servers: BTreeMap<String, Value>,
    caps: BTreeMap<&'static str, bool>,
    unknown_module_tokens: usize,
}
impl Visitor {
    fn module(&mut self, namespace: &str, name: &str, p: &[Segment]) -> Result<()> {
        if !token(name) || namespace.len() + name.len() > 200 {
            self.unknown_module_tokens += 1;
            return Ok(());
        }
        let id = format!("{namespace}{name}");
        match id.as_str() {
            "http.matchers.expression" => {
                self.caps.insert("cel_expressions", true);
            }
            "pki" | "tls.issuance.internal" => {
                self.caps.insert("internal_pki", true);
            }
            "tls.issuance.acme" => {
                self.caps.insert("explicit_acme_issuer", true);
            }
            _ => {}
        }
        self.modules.insert((id, pointer(p)));
        if self.modules.len() > MAX_USES {
            bail!("module surface exceeds bounded limit");
        }
        Ok(())
    }
    fn field_module(&mut self, v: &Value, field: &str, ns: &str, p: &[Segment]) -> Result<()> {
        if let Some(name) = v.get(field).and_then(Value::as_str) {
            self.module(ns, name, &child(p, field))?;
        }
        Ok(())
    }
    fn matcher(&mut self, v: &Value, p: &[Segment]) -> Result<()> {
        if let Some(map) = v.as_object() {
            for (name, value) in map {
                if name == "@id" {
                    continue;
                }
                let next = child(p, name);
                self.module("http.matchers.", name, &next)?;
                if name == "not"
                    && let Some(array) = value.as_array()
                {
                    for (i, item) in array.iter().enumerate() {
                        let mut nested = next.clone();
                        nested.push(Segment::Index(i));
                        self.matcher(item, &nested)?;
                    }
                }
            }
        }
        Ok(())
    }
    fn semantics(&mut self, v: &Value, p: &[Segment]) -> Result<()> {
        let n = p.len();
        if n == 1
            && key(p, 0) == Some("apps")
            && let Some(map) = v.as_object()
        {
            for app in map.keys() {
                self.module("", app, &child(p, app))?;
            }
        }
        if prefix(p, &["apps", "http"]) {
            if n >= 2 && key(p, n - 2) == Some("handle") && is_index(p, n - 1) {
                self.field_module(v, "handler", "http.handlers.", p)?;
                match v.get("handler").and_then(Value::as_str) {
                    Some("encode") => {
                        if let Some(enc) = v.get("encodings").and_then(Value::as_object) {
                            for name in enc.keys() {
                                self.module(
                                    "http.encoders.",
                                    name,
                                    &child(&child(p, "encodings"), name),
                                )?;
                            }
                        }
                    }
                    Some("reverse_proxy") => {
                        if let Some(t) = v.get("transport") {
                            self.field_module(
                                t,
                                "protocol",
                                "http.reverse_proxy.transport.",
                                &child(p, "transport"),
                            )?;
                        }
                        for lb in ["load_balancing", "lb"] {
                            if let Some(selection) =
                                v.get(lb).and_then(|v| v.get("selection_policy"))
                            {
                                self.field_module(
                                    selection,
                                    "policy",
                                    "http.reverse_proxy.selection_policies.",
                                    &child(&child(p, lb), "selection_policy"),
                                )?;
                            }
                        }
                    }
                    _ => {}
                }
            }
            if n >= 3
                && key(p, n - 3) == Some("routes")
                && is_index(p, n - 2)
                && key(p, n - 1) == Some("match")
                && let Some(a) = v.as_array()
            {
                for (i, item) in a.iter().enumerate() {
                    let mut next = p.to_vec();
                    next.push(Segment::Index(i));
                    self.matcher(item, &next)?;
                }
            }
            if n == 4 && prefix(p, &["apps", "http", "servers"]) {
                self.server(v, p)?;
            }
            if n == 6
                && prefix(p, &["apps", "http", "servers"])
                && key(p, 4) == Some("listener_wrappers")
                && is_index(p, 5)
            {
                self.field_module(v, "wrapper", "caddy.listeners.", p)?;
            }
        }
        if n == 3
            && prefix(p, &["apps", "tls", "certificates"])
            && let Some(m) = v.as_object()
        {
            for loader in m.keys() {
                self.module("tls.certificates.", loader, &child(p, loader))?;
            }
        }
        if n == 5 && prefix(p, &["apps", "tls", "automation", "policies"]) && is_index(p, 4) {
            if v.get("on_demand").and_then(Value::as_bool) == Some(true) {
                self.caps.insert("on_demand_tls", true);
            }
            self.caps.insert("tls_automation_configuration", true);
        }
        if n == 3
            && prefix(p, &["apps", "tls", "automation"])
            && v.get("on_demand").is_some_and(Value::is_object)
        {
            self.caps.insert("on_demand_permission_configuration", true);
        }
        if n == 7
            && prefix(p, &["apps", "tls", "automation", "policies"])
            && is_index(p, 4)
            && key(p, 5) == Some("issuers")
            && is_index(p, 6)
        {
            self.field_module(v, "module", "tls.issuance.", p)?;
        }
        if n == 4 && prefix(p, &["logging", "logs"]) {
            match key(p, 3) {
                Some("output") => self.field_module(v, "writer", "caddy.logging.writers.", p)?,
                Some("encoder") => self.field_module(v, "format", "caddy.logging.encoders.", p)?,
                _ => {}
            }
        }
        if n == 1 && key(p, 0) == Some("storage") {
            self.field_module(v, "module", "caddy.storage.", p)?;
        }
        Ok(())
    }
    fn server(&mut self, v: &Value, p: &[Segment]) -> Result<()> {
        let mut ports = BTreeSet::new();
        let mut unparsed = 0usize;
        if let Some(a) = v.get("listen").and_then(Value::as_array) {
            for address in a {
                if let Some(s) = address.as_str() {
                    if let Some(port) = port(s) {
                        ports.insert(port);
                    } else {
                        unparsed += 1;
                    }
                }
            }
        }
        let mut protocols = BTreeSet::new();
        let mut unrecognized = 0usize;
        if let Some(a) = v.get("protocols").and_then(Value::as_array) {
            for item in a {
                if let Some(s) = item.as_str() {
                    if matches!(s, "h1" | "h2" | "h2c" | "h3") {
                        protocols.insert(s);
                    } else {
                        unrecognized += 1;
                    }
                }
            }
        }
        let mut flags = BTreeMap::new();
        if let Some(auto) = v.get("automatic_https").and_then(Value::as_object) {
            self.caps.insert("automatic_https_configuration", true);
            for field in [
                "disable",
                "disable_redirects",
                "disable_certificates",
                "ignore_loaded_certificates",
            ] {
                if let Some(b) = auto.get(field).and_then(Value::as_bool) {
                    flags.insert(field, b);
                }
            }
        }
        if v.get("tls_connection_policies").is_some() {
            self.caps.insert("tls_connection_configuration", true);
        }
        if let Some(t) = v.get("trusted_proxies") {
            self.field_module(
                t,
                "source",
                "http.ip_sources.",
                &child(p, "trusted_proxies"),
            )?;
        }
        self.servers.insert(pointer(p), json!({"listen_ports": ports, "unparsed_listen_values": unparsed, "explicit_protocols": protocols, "unrecognized_protocol_values": unrecognized, "automatic_https_flags": flags}));
        Ok(())
    }
    fn scan_placeholders(&mut self, s: &str, p: &[Segment]) -> Result<()> {
        let bytes = s.as_bytes();
        for i in 0..bytes.len() {
            if bytes[i] != b'{' {
                continue;
            }
            for j in i + 1..bytes.len().min(i + 257) {
                let b = bytes[j];
                if b == b'{' {
                    break;
                }
                if b == b'}' {
                    let inner = &s[i + 1..j];
                    if ["http.", "env.", "system.", "time.", "re.", "vars."]
                        .iter()
                        .any(|prefix| inner.starts_with(prefix) && inner.len() > prefix.len())
                        && inner.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')
                        })
                    {
                        self.placeholders.insert((s[i..=j].into(), pointer(p)));
                        if self.placeholders.len() > MAX_USES {
                            bail!("placeholder surface exceeds bounded limit");
                        }
                    }
                    break;
                }
                if !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'.' | b':' | b'-') {
                    break;
                }
            }
        }
        Ok(())
    }
    fn walk(&mut self, v: &Value, p: &mut Vec<Segment>) -> Result<()> {
        self.fields.insert(pointer(p), value_type(v));
        if self.fields.len() > MAX_FIELDS {
            bail!("field surface exceeds bounded limit");
        }
        self.semantics(v, p)?;
        match v {
            Value::Object(m) => {
                for (k, child) in m {
                    p.push(Segment::Key(k.clone()));
                    self.walk(child, p)?;
                    p.pop();
                }
            }
            Value::Array(a) => {
                for (i, child) in a.iter().enumerate() {
                    p.push(Segment::Index(i));
                    self.walk(child, p)?;
                    p.pop();
                }
            }
            Value::String(s) => self.scan_placeholders(s, p)?,
            _ => {}
        }
        Ok(())
    }
}

pub fn inspect(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_INPUT {
        bail!("configuration exceeds 16 MiB limit");
    }
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("configuration is not valid bounded JSON"))?;
    if !root.is_object() {
        bail!("configuration root must be an object");
    }
    let mut visitor = Visitor::default();
    visitor.walk(&root, &mut Vec::new())?;
    let modules: Vec<Value> = visitor
        .modules
        .iter()
        .map(|(id, pointer)| json!({"id":id,"pointer":pointer}))
        .collect();
    let placeholders: Vec<Value> = visitor
        .placeholders
        .iter()
        .map(|(token, pointer)| json!({"token":token,"pointer":pointer}))
        .collect();
    let fields: Vec<Value> = visitor
        .fields
        .iter()
        .map(|(pointer, value_type)| json!({"pointer":pointer,"value_type":value_type}))
        .collect();
    Ok(
        json!({"config_sha256":hex(bytes),"modules":modules,"fields":fields,"placeholders":placeholders,"servers":visitor.servers,"required_capabilities":visitor.caps,"unrecognized_module_tokens":visitor.unknown_module_tokens,"metadata":{"read_only":true,"not_a_runtime_validator":true,"not_a_compatibility_verdict":true,"pointer_encoding":"RFC6901 structural references; dynamic and unknown object keys are full SHA256 pseudonyms; not Admin API writable paths","capability_semantics":"explicit configuration signals only; absence does not prove that implicit defaults or unlisted namespaces are unnecessary","covered_module_namespaces":["apps","http.handlers","http.matchers","http.encoders","http.reverse_proxy.transport","http.reverse_proxy.selection_policies","http.ip_sources","tls.issuance","tls.certificates","caddy.listeners","caddy.logging.writers","caddy.logging.encoders","caddy.storage"]}}),
    )
}
