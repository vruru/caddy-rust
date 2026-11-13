//! Typed ordered TLS connection policies; provisioning performs no hot-path I/O.
pub(crate) mod certificate_selection;
mod client_auth;
pub(crate) use client_auth::{source_certificates,source_inline,source_append_certificates};
mod client_paths;
mod provision;
pub(crate) use provision::key_exchange_group;

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::go_regexp::{GoRegexp, ReplaceBudget};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde_json::{Map, Value};
use std::sync::Arc;

const MAX_POLICIES: usize = 1024;
const MAX_STRING_LEN: usize = 4096;
const MAX_ARRAY_LEN: usize = 256;
const MAX_MATCHERS_PER_POLICY: usize = 16;
const REGEX_SIZE_LIMIT: usize = 8 * 1024 * 1024;

// ─── HelloInfo ────────────────────────────────────────────────────────────────

pub struct HelloInfo<'a> {
    pub sni: &'a str,
    pub remote: Option<IpAddr>,
    pub local: Option<IpAddr>,
    pub remote_has_zone: bool,
    pub local_has_zone: bool,
}

// ─── ProtocolVersion ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolVersion {
    Tls12,
    Tls13,
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls12 => f.write_str("tls1.2"),
            Self::Tls13 => f.write_str("tls1.3"),
        }
    }
}

impl FromStr for ProtocolVersion {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "tls1.2" => Ok(Self::Tls12),
            "tls1.3" => Ok(Self::Tls13),
            _ => bail!("not a supported protocol: {s}"),
        }
    }
}

// ─── Matchers ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Matcher {
    Sni {
        patterns: Vec<String>,
    },
    SniRegexp {
        entry: SniRegexpEntry,
    },
    RemoteIp {
        ranges: Vec<IpNet>,
        not_ranges: Vec<IpNet>,
    },
    LocalIp {
        ranges: Vec<IpNet>,
    },
}

#[derive(Clone)]
pub struct SniRegexpEntry {
    pub name: Option<String>,
    pub pattern: String,
    pub(crate) compiled: Arc<GoRegexp>,
}

impl fmt::Debug for SniRegexpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniRegexpEntry")
            .field("name", &self.name)
            .field("pattern", &self.pattern)
            .finish_non_exhaustive()
    }
}

// ─── ClientAuth ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ClientAuth {
    pub ca: Option<Value>,
    pub trusted_ca_certs: Vec<String>,
    pub trusted_ca_certs_pem_files: Vec<String>,
    pub trusted_leaf_certs: Vec<String>,
    pub verifiers: Vec<Value>,
    pub mode: Option<ClientAuthMode>,
}

impl fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientAuth")
            .field("trusted_ca_certs", &self.trusted_ca_certs)
            .field(
                "trusted_ca_certs_pem_files",
                &self.trusted_ca_certs_pem_files,
            )
            .field("trusted_leaf_certs", &self.trusted_leaf_certs)
            .field("mode", &self.mode)
            .field("ca", &self.ca.as_ref().map(|_| "[redacted]"))
            .field("verifiers", &self.verifiers.len())
            .finish()
    }
}

impl ClientAuth {
    pub fn is_active(&self) -> bool {
        !self.trusted_ca_certs.is_empty()
            || !self.trusted_ca_certs_pem_files.is_empty()
            || !self.trusted_leaf_certs.is_empty()
            || !self.verifiers.is_empty()
            || self.mode.is_some()
            || self.ca.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMode {
    Request,
    Require,
    VerifyIfGiven,
    RequireAndVerify,
}

impl ClientAuthMode {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "request" => Ok(Self::Request),
            "require" => Ok(Self::Require),
            "verify_if_given" => Ok(Self::VerifyIfGiven),
            "require_and_verify" => Ok(Self::RequireAndVerify),
            _ => bail!("client auth mode not recognized"),
        }
    }
}

// ─── ConnectionPolicy ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ConnectionPolicy {
    pub(crate) identity: [u8; 32],
    pub matcher: Vec<Matcher>,
    pub(crate) certificate_selection: Option<Arc<certificate_selection::CertificateFilter>>,
    pub protocol_min: Option<ProtocolVersion>,
    pub protocol_max: Option<ProtocolVersion>,
    pub cipher_suites: Option<Vec<String>>,
    pub curves: Option<Vec<String>>,
    pub alpn: Option<Vec<String>>,
    pub drop: bool,
    pub client_auth: Option<ClientAuth>,
    pub default_sni: Option<String>,
    pub fallback_sni: Option<String>,
    pub insecure_secrets_log: Option<String>,
    pub handshake_context: Option<Value>,
}

impl fmt::Debug for ConnectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionPolicy")
            .field("matcher", &self.matcher)
            .field("certificate_selection", &self.certificate_selection)
            .field("protocol_min", &self.protocol_min)
            .field("protocol_max", &self.protocol_max)
            .field("cipher_suites", &self.cipher_suites)
            .field("curves", &self.curves)
            .field("alpn", &self.alpn)
            .field("drop", &self.drop)
            .field("client_auth", &self.client_auth)
            .field("default_sni", &self.default_sni)
            .field("fallback_sni", &self.fallback_sni)
            .field("insecure_secrets_log", &self.insecure_secrets_log)
            .field(
                "handshake_context",
                &self.handshake_context.as_ref().map(|_| "[raw]"),
            )
            .finish()
    }
}

/// Normalize the read-only wire name for certificate lookup only. Use the
/// original offered name separately for policy matching and HTTP identity.
pub fn normalized_offered_name(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    if raw.ends_with('.') {
        bail!("trailing dot in TLS server name");
    }
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return Ok(crate::tls_resolver::canonical_certificate_ip(ip));
    }
    crate::challenge::normalize_domain(raw)
}

impl ConnectionPolicy {
    /// Ordered certificate lookups after matching the unchanged ClientHello.
    /// The caller passes a normalized offered DNS SNI (or an empty string)
    /// and the canonical IP of this socket's local endpoint.
    pub fn certificate_names<'a>(
        &'a self,
        offered_sni: &'a str,
        local_ip: &'a str,
    ) -> [Option<&'a str>; 3] {
        if offered_sni.is_empty() {
            [
                Some(local_ip),
                self.default_sni.as_deref(),
                self.fallback_sni.as_deref(),
            ]
        } else {
            [Some(offered_sni), None, self.fallback_sni.as_deref()]
        }
    }

    pub(crate) fn requires_certificate_tags(&self) -> bool {
        self.certificate_selection
            .as_ref()
            .is_some_and(|filter| filter.requires_tags())
    }

    fn default_empty() -> Self {
        Self {
            identity: <sha2::Sha256 as sha2::Digest>::digest(b"{}").into(),
            matcher: Vec::new(),
            certificate_selection: None,
            protocol_min: None,
            protocol_max: None,
            cipher_suites: None,
            curves: None,
            alpn: None,
            drop: false,
            client_auth: None,
            default_sni: None,
            fallback_sni: None,
            insecure_secrets_log: None,
            handshake_context: None,
        }
    }
}

// ─── Parser Entry Point ───────────────────────────────────────────────────────

pub fn parse_policies(input: Option<&Value>) -> Result<Vec<ConnectionPolicy>> {
    let arr: &[Value] = match input {
        None => return Ok(vec![ConnectionPolicy::default_empty()]),
        Some(Value::Null) => return Ok(vec![ConnectionPolicy::default_empty()]),
        Some(Value::Array(a)) => a.as_slice(),
        Some(other) => bail!("policies must be a JSON array, got {}", json_type(other)),
    };

    if arr.is_empty() {
        return Ok(vec![ConnectionPolicy::default_empty()]);
    }
    if arr.len() > MAX_POLICIES {
        bail!(
            "too many connection policies: {} (max {MAX_POLICIES})",
            arr.len()
        );
    }

    let mut policies = Vec::with_capacity(arr.len());
    let mut total = 0usize;
    for value in arr {
        let policy = parse_one_policy(value)?;
        for matcher in &policy.matcher {
            if let Matcher::SniRegexp { entry } = matcher {
                total = total
                    .checked_add(entry.compiled.memory_usage())
                    .ok_or_else(|| anyhow::anyhow!("TLS regexp memory overflow"))?;
                anyhow::ensure!(
                    total <= 64 << 20,
                    "TLS policy regexp memory budget exceeded"
                );
            }
        }
        policies.push(policy);
    }
    Ok(policies)
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ─── Single Policy Parser ─────────────────────────────────────────────────────

fn parse_one_policy(v: &Value) -> Result<ConnectionPolicy> {
    let obj = require_object(v)?;

    let known = [
        "match",
        "certificate_selection",
        "cipher_suites",
        "curves",
        "alpn",
        "protocol_min",
        "protocol_max",
        "drop",
        "client_authentication",
        "default_sni",
        "fallback_sni",
        "insecure_secrets_log",
        "handshake_context",
    ];
    for key in obj.keys() {
        if !known.contains(&key.as_str()) {
            bail!("unknown field in connection policy");
        }
    }

    let matcher = parse_matchers(obj.get("match"))?;
    let certificate_selection =
        certificate_selection::parse(obj.get("certificate_selection"))?.map(Arc::new);

    let protocol_min = parse_protocol(obj.get("protocol_min"), "protocol_min")?;
    let protocol_max = parse_protocol(obj.get("protocol_max"), "protocol_max")?;

    if let (Some(mn), Some(mx)) = (&protocol_min, &protocol_max)
        && mn > mx
    {
        bail!("protocol_min ({mn}) > protocol_max ({mx})");
    }

    let cipher_suites = parse_string_array(obj.get("cipher_suites"), "cipher_suites")?;
    let curves = parse_string_array(obj.get("curves"), "curves")?;
    let alpn = parse_optional_string_array(obj.get("alpn"), "alpn")?;

    let drop = obj
        .get("drop")
        .filter(|v| !v.is_null())
        .map(|v| v.as_bool().with_context(|| "drop must be a boolean"))
        .transpose()?
        .unwrap_or(false);

    let client_auth = parse_client_auth(obj.get("client_authentication"))?;

    let certificate_name = |field| -> Result<Option<String>> {
        let configured = parse_opt_string(obj.get(field), field)?;
        configured
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(crate::tls_resolver::normalize_certificate_name)
            .transpose()
            .with_context(|| format!("invalid {field} certificate name"))
    };
    let default_sni = certificate_name("default_sni")?;
    let fallback_sni = certificate_name("fallback_sni")?;

    let insecure_secrets_log =
        parse_opt_string(obj.get("insecure_secrets_log"), "insecure_secrets_log")?;
    if insecure_secrets_log.is_some() {
        bail!("insecure_secrets_log is non-empty → unsupported in this module");
    }

    let handshake_context = obj.get("handshake_context").cloned();
    if handshake_context.is_some() {
        bail!("handshake_context module is not implemented");
    }

    Ok(ConnectionPolicy {
        identity: <sha2::Sha256 as sha2::Digest>::digest(serde_json::to_vec(v)?).into(),
        matcher,
        certificate_selection,
        protocol_min,
        protocol_max,
        cipher_suites,
        curves,
        alpn,
        drop,
        client_auth,
        default_sni,
        fallback_sni,
        insecure_secrets_log,
        handshake_context,
    })
}

// ─── Match Parsing ────────────────────────────────────────────────────────────

fn parse_matchers(v: Option<&Value>) -> Result<Vec<Matcher>> {
    let obj = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(o) => require_object(o)?,
    };

    if obj.is_empty() {
        return Ok(Vec::new());
    }

    let known = ["sni", "sni_regexp", "remote_ip", "local_ip"];
    for key in obj.keys() {
        if !known.contains(&key.as_str()) {
            bail!("unknown match field");
        }
    }

    let mut out: Vec<Matcher> = Vec::new();

    if let Some(sni_v) = obj.get("sni") {
        let arr = require_array(sni_v, "match.sni")?;
        if arr.len() > MAX_ARRAY_LEN {
            bail!("match.sni: too many entries (max {MAX_ARRAY_LEN})");
        }
        let patterns: Vec<String> = arr
            .iter()
            .map(|e| {
                let s = require_string(e, "match.sni entry")?;
                check_len(s, MAX_STRING_LEN, "match.sni entry")?;
                Ok(s.to_owned())
            })
            .collect::<Result<_>>()?;
        out.push(Matcher::Sni { patterns });
    }

    if let Some(re_v) = obj.get("sni_regexp") {
        let entry = parse_sni_regexp_single(re_v)?;
        out.push(Matcher::SniRegexp { entry });
    }

    if let Some(rip_v) = obj.get("remote_ip") {
        let o = require_object(rip_v)?;
        check_unknown(o, &["ranges", "not_ranges"], "match.remote_ip")?;
        let ranges = parse_ip_ranges(o.get("ranges"), "remote_ip.ranges")?;
        let not_ranges = parse_ip_ranges(o.get("not_ranges"), "remote_ip.not_ranges")?;
        out.push(Matcher::RemoteIp { ranges, not_ranges });
    }

    if let Some(lip_v) = obj.get("local_ip") {
        let o = require_object(lip_v)?;
        check_unknown(o, &["ranges"], "match.local_ip")?;
        let ranges = parse_ip_ranges(o.get("ranges"), "local_ip.ranges")?;
        out.push(Matcher::LocalIp { ranges });
    }

    Ok(out)
}

fn parse_sni_regexp_single(v: &Value) -> Result<SniRegexpEntry> {
    let o = require_object(v)?;
    check_unknown(o, &["name", "pattern"], "match.sni_regexp")?;

    let name = parse_opt_string(o.get("name"), "sni_regexp.name")?;

    anyhow::ensure!(
        name.as_ref().is_none_or(|name| name.is_empty()
            || name
                .bytes()
                .any(|byte| byte.is_ascii_alphanumeric() || byte == b'_')),
        "invalid TLS regexp name"
    );

    let pattern = match o.get("pattern") {
        None | Some(Value::Null) => "",
        Some(value) => require_string(value, "sni_regexp.pattern")?,
    };
    check_len(pattern, MAX_STRING_LEN, "sni_regexp.pattern")?;

    let expanded = crate::http_config::helpers::replace(
        pattern,
        true,
        crate::http_config::helpers::global_lookup,
    )?;
    let compiled = Arc::new(
        GoRegexp::compile(&expanded, REGEX_SIZE_LIMIT)
            .with_context(|| "sni_regexp: invalid pattern")?,
    );

    Ok(SniRegexpEntry {
        name,
        pattern: pattern.to_string(),
        compiled,
    })
}

fn parse_ip_ranges(v: Option<&Value>, ctx: &str) -> Result<Vec<IpNet>> {
    let arr: &[Value] = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(a) => require_array(a, ctx)?,
    };
    if arr.len() > MAX_ARRAY_LEN {
        bail!("{ctx}: too many entries (max {MAX_ARRAY_LEN})");
    }
    arr.iter()
        .map(|e| {
            let s = require_string(e, ctx)?;
            check_len(s, 64, ctx)?;
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .map_err(|e| anyhow::anyhow!(e))
                .with_context(|| format!("{ctx}: invalid IP range"))
        })
        .collect()
}

// ─── Protocol ─────────────────────────────────────────────────────────────────

fn parse_protocol(v: Option<&Value>, field: &str) -> Result<Option<ProtocolVersion>> {
    let s = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(sv)) => {
            if sv.is_empty() {
                return Ok(None);
            }
            sv.as_str()
        }
        Some(other) => bail!("{field}: expected string, got {}", json_type(other)),
    };
    check_len(s, 16, field)?;
    match s {
        "tls1.2" => Ok(Some(ProtocolVersion::Tls12)),
        "tls1.3" => Ok(Some(ProtocolVersion::Tls13)),
        "ssl3.0" | "tls1.0" | "tls1.1" => {
            bail!("{field}: \"{s}\" → not implemented (only tls1.2/tls1.3 supported)")
        }
        _ => bail!("{field}: unrecognized protocol"),
    }
}

// ─── Client Auth Parsing ──────────────────────────────────────────────────────

fn parse_client_auth(v: Option<&Value>) -> Result<Option<ClientAuth>> {
    let v = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj = require_object(v)?;
    check_unknown(
        obj,
        &[
            "ca",
            "trusted_ca_certs",
            "trusted_ca_certs_pem_files",
            "trusted_leaf_certs",
            "verifiers",
            "mode",
        ],
        "client_authentication",
    )?;

    let ca = obj.get("ca").cloned();

    let trusted_ca_certs =
        parse_string_array(obj.get("trusted_ca_certs"), "ca.trusted_ca_certs")?.unwrap_or_default();
    let trusted_ca_certs_pem_files = parse_string_array(
        obj.get("trusted_ca_certs_pem_files"),
        "ca.trusted_ca_certs_pem_files",
    )?
    .unwrap_or_default();
    let trusted_leaf_certs =
        parse_string_array(obj.get("trusted_leaf_certs"), "ca.trusted_leaf_certs")?
            .unwrap_or_default();

    let verifiers: Vec<Value> = match obj.get("verifiers") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => {
            let arr = require_array(v, "ca.verifiers")?;
            if arr.len() > MAX_MATCHERS_PER_POLICY {
                bail!("ca.verifiers: too many entries");
            }
            arr.to_vec()
        }
    };

    let mode: Option<ClientAuthMode> = match obj.get("mode") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            if s.is_empty() {
                None
            } else {
                check_len(s, 32, "ca.mode")?;
                Some(ClientAuthMode::parse(s)?)
            }
        }
        Some(other) => bail!("ca.mode: expected string, got {}", json_type(other)),
    };

    Ok(Some(ClientAuth {
        ca,
        trusted_ca_certs,
        trusted_ca_certs_pem_files,
        trusted_leaf_certs,
        verifiers,
        mode,
    }))
}

// ─── String / Array Helpers ───────────────────────────────────────────────────

fn require_object(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object()
        .with_context(|| format!("expected JSON object, got {}", json_type(v)))
}

fn require_array<'a>(v: &'a Value, ctx: &str) -> Result<&'a [Value]> {
    v.as_array()
        .map(|a| a.as_slice())
        .with_context(|| format!("{ctx}: expected array, got {}", json_type(v)))
}

fn require_string<'a>(v: &'a Value, ctx: &str) -> Result<&'a str> {
    v.as_str()
        .with_context(|| format!("{ctx}: expected string, got {}", json_type(v)))
}

fn check_len(s: &str, max: usize, ctx: &str) -> Result<()> {
    if s.len() > max {
        bail!("{ctx}: string exceeds {max} bytes");
    }
    Ok(())
}

fn parse_opt_string(v: Option<&Value>, ctx: &str) -> Result<Option<String>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(sv) => {
            let s = require_string(sv, ctx)?;
            check_len(s, MAX_STRING_LEN, ctx)?;
            Ok(Some(s.to_string()))
        }
    }
}

fn parse_string_array(v: Option<&Value>, ctx: &str) -> Result<Option<Vec<String>>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(arr) => {
            let a = require_array(arr, ctx)?;
            if a.len() > MAX_ARRAY_LEN {
                bail!("{ctx}: too many entries (max {MAX_ARRAY_LEN})");
            }
            let out = a
                .iter()
                .map(|e| {
                    let s = require_string(e, ctx)?;
                    check_len(s, MAX_STRING_LEN, ctx)?;
                    Ok(s.to_string())
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Some(out))
        }
    }
}

fn parse_optional_string_array(v: Option<&Value>, ctx: &str) -> Result<Option<Vec<String>>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) if a.is_empty() => Ok(Some(Vec::new())),
        Some(_) => parse_string_array(v, ctx),
    }
}

fn check_unknown(obj: &Map<String, Value>, known: &[&str], ctx: &str) -> Result<()> {
    for key in obj.keys() {
        if !known.contains(&key.as_str()) {
            bail!("unknown field in {ctx}");
        }
    }
    Ok(())
}

// ─── SNI Normalization ────────────────────────────────────────────────────────

fn normalize_sni_for_match(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    if s.bytes().all(|b| b < 0x80) {
        return s.to_ascii_lowercase();
    }
    let labels: Vec<&str> = s.split('.').collect();
    let mut out: Vec<String> = Vec::with_capacity(labels.len());
    for label in labels {
        if label.is_empty() || label == "*" {
            out.push(label.to_string());
            continue;
        }
        match idna::domain_to_ascii(label) {
            Ok(ascii) => out.push(ascii.to_ascii_lowercase()),
            _ => out.push(label.to_ascii_lowercase()),
        }
    }
    out.join(".")
}

// ─── Wildcard Match ───────────────────────────────────────────────────────────

fn wildcard_match(input: &str, pattern: &str) -> bool {
    if input == pattern {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }
    // CertMagic MatchWildcard cumulatively replaces each nonempty label,
    // from the left, rather than allowing a wildcard in an arbitrary label.
    let mut labels = input.split('.').collect::<Vec<_>>();
    for index in 0..labels.len() {
        if labels[index].is_empty() {
            continue;
        }
        labels[index] = "*";
        if labels.join(".") == pattern {
            return true;
        }
    }
    false
}

// ─── Matcher Logic ────────────────────────────────────────────────────────────

impl ConnectionPolicy {
    pub(crate) fn compiled_memory(&self) -> usize {
        self.matcher
            .iter()
            .map(|matcher| match matcher {
                Matcher::SniRegexp { entry } => entry.compiled.memory_usage(),
                _ => 0,
            })
            .sum()
    }
    pub fn select(&self, hello: &HelloInfo<'_>) -> bool {
        self.match_captures(hello)
            .is_ok_and(|captures| captures.is_some())
    }
    pub fn match_captures(
        &self,
        hello: &HelloInfo<'_>,
    ) -> Result<Option<BTreeMap<String, String>>> {
        let mut values = BTreeMap::new();
        for matcher in &self.matcher {
            if let Matcher::SniRegexp { entry } = matcher {
                let Some(captures) = entry.compiled.first_match(
                    hello.sni,
                    &ReplaceBudget::new(entry.compiled.search_memory(), None),
                )?
                else {
                    return Ok(None);
                };
                for (key, value) in captures {
                    values.insert(format!("tls.regexp.{key}"), value.clone());
                    if let Some(name) = entry.name.as_ref().filter(|name| !name.is_empty()) {
                        values.insert(format!("tls.regexp.{name}.{key}"), value);
                    }
                }
            } else if !matcher.matches(hello) {
                return Ok(None);
            }
        }
        Ok(Some(values))
    }
}

impl Matcher {
    fn matches(&self, hello: &HelloInfo<'_>) -> bool {
        match self {
            Self::Sni { patterns } => {
                if patterns.is_empty() {
                    return false;
                }
                let normalized_sni = normalize_sni_for_match(hello.sni);
                patterns.iter().any(|p| {
                    let Ok(expanded) = crate::http_config::helpers::replace(
                        p,
                        true,
                        crate::http_config::helpers::global_lookup,
                    ) else {
                        return false;
                    };
                    let np = normalize_sni_for_match(&expanded);
                    wildcard_match(&normalized_sni, &np)
                })
            }
            Self::SniRegexp { entry } => entry
                .compiled
                .first_match(
                    hello.sni,
                    &ReplaceBudget::new(entry.compiled.search_memory(), None),
                )
                .is_ok_and(|captures| captures.is_some()),
            Self::RemoteIp { ranges, not_ranges } => {
                hello.remote.is_some_and(|ip|{
                    let in_ranges=ranges.is_empty()||(!hello.remote_has_zone&&ranges.iter().any(|n|n.contains(&ip)));
                    let not_excluded=not_ranges.is_empty()||hello.remote_has_zone||!not_ranges.iter().any(|n|n.contains(&ip));
                    in_ranges&&not_excluded
                })
            }
            Self::LocalIp { ranges } => {
                hello.local.is_some_and(|ip|ranges.is_empty()||(!hello.local_has_zone&&ranges.iter().any(|n|n.contains(&ip))))
            }
        }
    }
}

// ─── Select Among Policies (First-Match) ──────────────────────────────────────

pub fn select_policy<'a>(
    policies: &'a [ConnectionPolicy],
    hello: &HelloInfo<'_>,
) -> Option<&'a ConnectionPolicy> {
    policies.iter().find(|p| p.select(hello))
}
