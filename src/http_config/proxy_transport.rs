// http_config/proxy_transport.rs
//
// Parsing for the new TransportOptions fields added alongside the existing
// transport config.  Only the *new* keys are inspected here; every other key
// that the legacy transport parser consumes is silently ignored.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use serde_json::{Map, Value};

// ─── public types ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct KeepAlive {
    pub enabled: bool,
    pub probe_ns: i64,
    pub idle_ns: i64,
    pub max_idle: usize,
    pub max_idle_per_host: usize,
}

#[derive(Clone)]
pub enum NetworkProxy {
    Environment,
    Direct,
    Url(Arc<str>),
}

impl std::fmt::Debug for NetworkProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Environment => f.write_str("Environment"),
            Self::Direct => f.write_str("Direct"),
            Self::Url(_) => f.write_str("Url(<redacted>)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportOptions {
    pub resolvers: Arc<[String]>,
    pub keep_alive: KeepAlive,
    pub max_conns_per_host: usize,
    pub proxy_protocol: Option<u8>,
    pub forward_proxy: NetworkProxy,
    pub fallback_ns: i64,
    pub expect_continue_ns: i64,
    pub max_header_bytes: usize,
    pub read_buffer: usize,
    pub write_buffer: usize,
    pub local_address: Option<String>,
    pub http3: bool,
}

// ─── defaults (mirrors the Go reference implementation) ─────────────────────

const DEFAULT_PROBE_NS: i64 = 30_000_000_000; // 30 s
const DEFAULT_IDLE_NS: i64 = 120_000_000_000; // 120 s
const DEFAULT_MAX_IDLE_PER_HOST: usize = 32;
const DEFAULT_FALLBACK_NS: i64 = 300_000_000; // 300 ms
const DEFAULT_MAX_HEADER_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
const DEFAULT_BUF: usize = 4096;

impl Default for KeepAlive {
    fn default() -> Self {
        Self {
            enabled: true,
            probe_ns: DEFAULT_PROBE_NS,
            idle_ns: DEFAULT_IDLE_NS,
            max_idle: 0, // 0 == unlimited
            max_idle_per_host: DEFAULT_MAX_IDLE_PER_HOST,
        }
    }
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            resolvers: Arc::new([]),
            keep_alive: KeepAlive::default(),
            max_conns_per_host: 0, // 0 == unlimited
            proxy_protocol: None,
            forward_proxy: NetworkProxy::Environment,
            fallback_ns: DEFAULT_FALLBACK_NS,
            expect_continue_ns: 0,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            read_buffer: DEFAULT_BUF,
            write_buffer: DEFAULT_BUF,
            local_address: None,
            http3: false,
        }
    }
}

/// Convenience: default options behind an `Arc`.
pub(crate) fn default_transport_options() -> Arc<TransportOptions> {
    Arc::new(TransportOptions::default())
}

// ─── helpers (private) ──────────────────────────────────────────────────────

fn as_i64(v: &Value, path: &str) -> Result<i64> {
    v.as_i64()
        .ok_or_else(|| anyhow!("{path}: expected integer"))
}

/// Parse a positive size, returning `default` when the value is ≤ 0.
/// The value must fit in `usize` (checked cast).
fn positive_size(v: &Value, default: usize, path: &str) -> Result<usize> {
    let raw = as_i64(v, path)?;
    if raw <= 0 {
        return Ok(default);
    }
    usize::try_from(raw).map_err(|_| anyhow!("{path}: value exceeds platform usize range"))
}

/// Validate a proxy URL.  Returns `Ok(Arc<str>)` on success.
/// Scheme ∈ {http, https, socks5, socks5h}; host required; fragment forbidden.
/// Errors are static – the URL (which may contain credentials) is never
/// echoed back.
fn validate_proxy_url(raw: &str, _path: &str) -> Result<Arc<str>> {
    let url = url::Url::parse(raw).map_err(|_| anyhow!("invalid forward proxy URL"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
            && url.host_str().is_some()
            && url.fragment().is_none(),
        "invalid forward proxy URL"
    );
    Ok(Arc::from(raw))
}

// ─── sub-parsers ────────────────────────────────────────────────────────────

fn parse_resolvers(obj: &Map<String, Value>, path: &str) -> Result<Arc<[String]>> {
    // The resolver object must be exactly { "addresses": [...] }.
    // Any other key is an error.
    for key in obj.keys() {
        if key.as_str() != "addresses" {
            return Err(anyhow!(
                "{path}: resolver object contains unknown key \"{key}\""
            ));
        }
    }

    let addrs = obj
        .get("addresses")
        .filter(|v| !v.is_null())
        .ok_or_else(|| anyhow!("{path}: resolver object missing \"addresses\""))?
        .as_array()
        .ok_or_else(|| anyhow!("{path}: \"addresses\" must be an array"))?;

    if addrs.is_empty() {
        return Err(anyhow!(
            "{path}: resolver addresses array must be non-empty"
        ));
    }

    let mut out: Vec<String> = Vec::with_capacity(addrs.len());
    for (i, item) in addrs.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| anyhow!("{path}: resolver addresses[{i}] must be a string"))?
            .to_owned();
        // Each entry is a network address (tcp/udp/unix scheme); the
        // runtime's existing DNS parser validates the format.  Here we
        // only require a non-empty string.
        if s.is_empty() {
            return Err(anyhow!("{path}: resolver addresses[{i}] is empty"));
        }
        out.push(s);
    }
    Ok(Arc::from(out))
}

fn parse_keep_alive(obj: &Map<String, Value>, path: &str) -> Result<KeepAlive> {
    // Strictly five sub-fields.
    const ALLOWED: &[&str] = &[
        "enabled",
        "probe_interval",
        "idle_timeout",
        "max_idle_conns",
        "max_idle_conns_per_host",
    ];
    for key in obj.keys() {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(anyhow!(
                "{path}: keep_alive contains unknown field \"{key}\""
            ));
        }
    }

    let enabled = obj
        .get("enabled")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| anyhow!("keep_alive.enabled must be boolean"))
        })
        .transpose()?
        .unwrap_or(true);

    // durations – delegate to super::helpers::signed_duration
    let probe_ns = obj
        .get("probe_interval")
        .filter(|v| !v.is_null())
        .map(|v| super::helpers::signed_duration(v, &format!("{path}.probe_interval")))
        .transpose()?
        .map(|ns| {
            if ns < 0 {
                0 // negative → disable TCP keepalive
            } else if ns == 0 {
                DEFAULT_PROBE_NS
            } else {
                ns
            }
        })
        .unwrap_or(DEFAULT_PROBE_NS);

    let idle_ns = obj
        .get("idle_timeout")
        .filter(|v| !v.is_null())
        .map(|v| super::helpers::signed_duration(v, &format!("{path}.idle_timeout")))
        .transpose()?
        .map(|ns| {
            if ns < 0 {
                0 // negative → disable idle expiry
            } else if ns == 0 {
                DEFAULT_IDLE_NS
            } else {
                ns
            }
        })
        .unwrap_or(DEFAULT_IDLE_NS);

    // max_idle_conns: integer, <=0 → unlimited (0)
    let max_idle = obj
        .get("max_idle_conns")
        .filter(|v| !v.is_null())
        .map(|v| {
            let n = as_i64(v, &format!("{path}.max_idle_conns"))?;
            Ok::<usize, anyhow::Error>(if n <= 0 { 0 } else { n as usize })
        })
        .transpose()?
        .unwrap_or(0);

    // max_idle_conns_per_host: 0→32, negative→0 (disable idle)
    let max_idle_per_host = obj
        .get("max_idle_conns_per_host")
        .filter(|v| !v.is_null())
        .map(|v| {
            let n = as_i64(v, &format!("{path}.max_idle_conns_per_host"))?;
            Ok::<usize, anyhow::Error>(match n {
                n if n > 0 => n as usize,
                0 => DEFAULT_MAX_IDLE_PER_HOST,
                _ => 0, // negative → disable idle
            })
        })
        .transpose()?
        .unwrap_or(DEFAULT_MAX_IDLE_PER_HOST);

    Ok(KeepAlive {
        enabled,
        probe_ns,
        idle_ns,
        max_idle,
        max_idle_per_host,
    })
}

fn parse_proxy_protocol(v: &Value, path: &str) -> Result<Option<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("{path}: proxy_protocol must be a string"))?;

    match s {
        "" => Ok(None),
        "v1" => Ok(Some(1)),
        "v2" => Ok(Some(2)),
        _ => Err(anyhow!(
            "{path}: proxy_protocol must be \"\", \"v1\", or \"v2\""
        )),
    }
}

fn parse_network_proxy(obj: &Map<String, Value>, path: &str) -> Result<NetworkProxy> {
    // Keys allowed: "from", "url".
    for key in obj.keys() {
        match key.as_str() {
            "from" | "url" => {}
            other => {
                return Err(anyhow!(
                    "{path}: network_proxy contains unknown key \"{other}\""
                ));
            }
        }
    }

    let from = obj
        .get("from")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_str()
                .ok_or_else(|| anyhow!("{path}.from: must be a string"))
        })
        .transpose()?
        .unwrap_or("");

    match from {
        "none" => Ok(NetworkProxy::Direct),
        "url" => {
            let url_raw = obj
                .get("url")
                .filter(|v| !v.is_null())
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow!("{path}: network_proxy url from=\"url\" requires a url string")
                })?;
            let validated = validate_proxy_url(url_raw, &format!("{path}.url"))?;
            Ok(NetworkProxy::Url(validated))
        }
        _other => Err(anyhow!(
            "{path}: network_proxy from must be \"none\" or \"url\""
        )),
    }
}

/// Determine `http3` from the `versions` array.
/// "3" is valid **only** as the sole element AND the `tls` object must exist.
/// All other version strings are left for the legacy parser to validate.
fn parse_http3(t: &Map<String, Value>, path: &str) -> Result<bool> {
    let versions = match t.get("versions").filter(|v| !v.is_null()) {
        Some(Value::Array(arr)) => arr,
        Some(_) => {
            return Err(anyhow!("{path}: versions must be an array"));
        }
        None => return Ok(false),
    };

    // Only inspect for the exact "3" token.
    let has3 = versions.iter().any(|v| v.as_str() == Some("3"));
    if !has3 {
        return Ok(false);
    }

    // "3" must appear exactly once and be the *only* element.
    if versions.len() != 1 {
        return Err(anyhow!(
            "{path}: versions may contain \"3\" only as the sole element"
        ));
    }

    // TLS object must be present.
    if !t.get("tls").is_some_and(Value::is_object) {
        return Err(anyhow!("{path}: HTTP/3 requires a tls object"));
    }

    Ok(true)
}

// ─── main entry point ───────────────────────────────────────────────────────

/// Parse **only** the new transport fields.  Unknown / legacy keys are
/// silently skipped so that this function can run alongside the existing
/// transport parser without conflict.
pub(crate) fn parse(t: Option<&Map<String, Value>>, path: &str) -> Result<Arc<TransportOptions>> {
    let t = match t {
        Some(map) => map,
        None => return Ok(default_transport_options()),
    };

    let mut opts = TransportOptions::default();

    // ── resolvers ───────────────────────────────────────────────────────────
    if let Some(val) = t.get("resolver").filter(|v| !v.is_null()) {
        let obj = val
            .as_object()
            .ok_or_else(|| anyhow!("{path}: resolvers must be an object"))?;
        opts.resolvers = parse_resolvers(obj, &format!("{path}.resolvers"))?;
    }

    // ── keep_alive ──────────────────────────────────────────────────────────
    if let Some(val) = t.get("keep_alive").filter(|v| !v.is_null()) {
        let obj = val
            .as_object()
            .ok_or_else(|| anyhow!("{path}: keep_alive must be an object"))?;
        opts.keep_alive = parse_keep_alive(obj, &format!("{path}.keep_alive"))?;
    }

    // ── max_conns_per_host ──────────────────────────────────────────────────
    if let Some(val) = t.get("max_conns_per_host").filter(|v| !v.is_null()) {
        let n = as_i64(val, &format!("{path}.max_conns_per_host"))?;
        opts.max_conns_per_host = if n <= 0 { 0 } else { n as usize };
    }

    // ── proxy_protocol ──────────────────────────────────────────────────────
    if let Some(val) = t.get("proxy_protocol").filter(|v| !v.is_null()) {
        opts.proxy_protocol = parse_proxy_protocol(val, &format!("{path}.proxy_protocol"))?;
    }

    // ── network_proxy  (new) + forward_proxy_url (legacy override) ─────────
    let mut proxy = NetworkProxy::Environment;

    if let Some(val) = t.get("network_proxy").filter(|v| !v.is_null()) {
        let obj = val
            .as_object()
            .ok_or_else(|| anyhow!("{path}: network_proxy must be an object"))?;
        proxy = parse_network_proxy(obj, &format!("{path}.network_proxy"))?;
    }

    // Legacy key wins when non-empty.
    if let Some(val) = t.get("forward_proxy_url").filter(|v| !v.is_null()) {
        let s = val
            .as_str()
            .ok_or_else(|| anyhow!("{path}: forward_proxy_url must be a string"))?;
        if !s.is_empty() {
            proxy = NetworkProxy::Url(validate_proxy_url(s, &format!("{path}.forward_proxy_url"))?);
        }
    }

    opts.forward_proxy = proxy;

    // ── fallback_timeout ────────────────────────────────────────────────────
    if let Some(val) = t.get("dial_fallback_delay").filter(|v| !v.is_null()) {
        opts.fallback_ns =
            super::helpers::signed_duration(val, &format!("{path}.fallback_timeout"))?;
    }

    // ── expect_continue_timeout ─────────────────────────────────────────────
    if let Some(val) = t.get("expect_continue_timeout").filter(|v| !v.is_null()) {
        opts.expect_continue_ns =
            super::helpers::signed_duration(val, &format!("{path}.expect_continue_timeout"))?;
    }

    // ── max_header_bytes ────────────────────────────────────────────────────
    if let Some(val) = t.get("max_response_header_size").filter(|v| !v.is_null()) {
        opts.max_header_bytes = positive_size(
            val,
            DEFAULT_MAX_HEADER_BYTES,
            &format!("{path}.max_header_bytes"),
        )?;
    }

    // ── read_buffer_size / write_buffer_size ────────────────────────────────
    if let Some(val) = t.get("read_buffer_size").filter(|v| !v.is_null()) {
        opts.read_buffer = positive_size(val, DEFAULT_BUF, &format!("{path}.read_buffer_size"))?;
    }
    if let Some(val) = t.get("write_buffer_size").filter(|v| !v.is_null()) {
        opts.write_buffer = positive_size(val, DEFAULT_BUF, &format!("{path}.write_buffer_size"))?;
    }

    // ── local_address ───────────────────────────────────────────────────────
    if let Some(val) = t.get("local_address").filter(|v| !v.is_null()) {
        let s = val
            .as_str()
            .ok_or_else(|| anyhow!("{path}: local_address must be a string"))?;
        if !s.is_empty() {
            opts.local_address = Some(s.to_owned());
        }
    }

    // ── http3 (derived from versions + tls) ─────────────────────────────────
    if opts.fallback_ns == 0 {
        opts.fallback_ns = DEFAULT_FALLBACK_NS;
    }
    anyhow::ensure!(
        opts.max_conns_per_host <= tokio::sync::Semaphore::MAX_PERMITS,
        "max_conns_per_host exceeds supported admission capacity"
    );
    opts.http3 = parse_http3(t, path)?;

    Ok(Arc::new(opts))
}
