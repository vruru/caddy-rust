//! Bounded tracing configuration; runtime/provider setup is separate.

use std::sync::Arc;
use std::time::Duration;
use anyhow::{anyhow, bail, Result};
use serde_json::Value;

/// Trace span configuration parsed from JSON.
#[derive(Clone)]
pub(crate) struct Config {
    pub span: Arc<str>,
    pub attributes: Arc<[(Arc<str>, Arc<str>)]>,
}

impl Config {
    /// Parse tracing config from a JSON object.
    /// Only "handler", "span", and "span_attributes" are accepted.
    pub fn parse(v: &Value) -> Result<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| anyhow!("config must be a JSON object"))?;

        // Validate keys and, for span_attributes, enforce entry-count in a single pass.
        for key in obj.keys() {
            match key.as_str() {
                "handler" | "@id" | "span" | "span_attributes" => {}
                other => bail!("unknown field: {}", other),
            }
        }

        let span_default = "handler";

        let span = match obj.get("span") {
            None | Some(Value::Null) => Arc::from(span_default),
            Some(Value::String(s)) => {
                if s.is_empty() {
                    Arc::from(span_default)
                } else {
                    if s.len() > 16384 {
                        bail!("span exceeds 16KiB");
                    }
                    Arc::from(s.as_str())
                }
            }
            Some(_) => bail!("span must be a string"),
        };

        let attributes: Arc<[(Arc<str>, Arc<str>)]> = match obj.get("span_attributes") {
            None | Some(Value::Null) => Arc::from(Vec::new()),
            Some(Value::Object(map)) => {
                if map.len() > 128 {
                    bail!("span_attributes must have at most 128 entries");
                }
                // Single pass: validate + size-check + build.
                let mut vec: Vec<(Arc<str>, Arc<str>)> = Vec::new();
                vec.try_reserve_exact(map.len())
                    .map_err(|_| anyhow!("span_attributes reservation failed"))?;
                let mut total_len: usize = 0;
                for (k, v) in map {
                    // Go's map[string]string decoder maps a JSON null value
                    // to the empty string, while non-string scalars still fail.
                    let val_str = match v {
                        Value::Null => "",
                        Value::String(value) => value.as_str(),
                        _ => bail!("span_attributes value must be a string for key '{}'", k),
                    };
                    total_len = total_len
                        .checked_add(k.len())
                        .and_then(|x| x.checked_add(val_str.len()))
                        .filter(|n| *n <= 131072)
                        .ok_or_else(|| anyhow!("span attributes exceed 128KiB"))?;
                    vec.push((Arc::from(k.as_str()), Arc::from(val_str)));
                }
                Arc::from(vec)
            }
            Some(_) => bail!("span_attributes must be an object"),
        };

        Ok(Config { span, attributes })
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Exporter {
    Otlp,
    Console,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Propagator {
    TraceContext,
    Baggage,
    B3,
    B3Multi,
    Jaeger,
    Xray,
    OtTrace,
}

#[derive(Clone)]
pub(crate) struct Settings {
    pub disabled: bool,
    pub unknown_propagators: usize,
    pub exporters: Vec<Exporter>,
    pub propagators: Vec<Propagator>,
    pub queue: usize,
    pub batch: usize,
    pub schedule: Duration,
    pub timeout: Duration,
}

/// Each selected environment value is read once for this prepared provider.
/// This is not an atomic process-wide environment snapshot; host applications
/// must synchronize their own environment updates. Unset slots remain `None`.
struct EnvSnapshot {
    sdk_disabled: Option<String>,
    traces_exporter: Option<String>,
    propagators: Option<String>,
    bsp_queue: Option<String>,
    bsp_batch: Option<String>,
    bsp_schedule: Option<String>,
    bsp_timeout: Option<String>,
}

fn snapshot_env() -> EnvSnapshot {
    EnvSnapshot {
        sdk_disabled: std::env::var("OTEL_SDK_DISABLED").ok(),
        traces_exporter: std::env::var("OTEL_TRACES_EXPORTER").ok(),
        propagators: std::env::var("OTEL_PROPAGATORS").ok(),
        bsp_queue: std::env::var("OTEL_BSP_MAX_QUEUE_SIZE").ok(),
        bsp_batch: std::env::var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE").ok(),
        bsp_schedule: std::env::var("OTEL_BSP_SCHEDULE_DELAY").ok(),
        bsp_timeout: std::env::var("OTEL_BSP_EXPORT_TIMEOUT").ok(),
    }
}

impl EnvSnapshot {
    fn total_len(&self) -> usize {
        let mut n: usize = 0;
        for slot in [
            &self.sdk_disabled,
            &self.traces_exporter,
            &self.propagators,
            &self.bsp_queue,
            &self.bsp_batch,
            &self.bsp_schedule,
            &self.bsp_timeout,
        ] {
            n = n.saturating_add(slot.as_ref().map_or(0, |s| s.len()));
        }
        n
    }
}

impl Settings {
    pub fn read() -> Result<Self> {
        // ENV collected ONCE before any clone/allocation processing.
        let env = snapshot_env();

        // Enforce 16 KiB aggregate bound over the snapshot.
        if env.total_len() > 16384 {
            bail!("environment values exceed 16KiB");
        }

        // --- disabled ---
        let disabled = env
            .sdk_disabled
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // --- exporters (Go signal semantics: single exact-case name, empty→otlp) ---
        let exporters_raw = env.traces_exporter.unwrap_or_default();
        let exporters = parse_exporters(&exporters_raw)?;

        // --- propagators (Go semantics: comma-split, case-sensitive, no trim) ---
        let propagators_raw = env.propagators.unwrap_or_default();
        let (propagators, unknown_propagators) = parse_propagators(&propagators_raw)?;

        // --- numeric BSP: invalid/zero/negative → default; >65536 → reject ---
        const DEFAULT_QUEUE: usize = 2048;
        const DEFAULT_BATCH: usize = 512;

        let queue = parse_bsp_size(
            env.bsp_queue.as_deref(),
            DEFAULT_QUEUE,
            "OTEL_BSP_MAX_QUEUE_SIZE",
        )?;
        let batch_raw =
            parse_bsp_size(env.bsp_batch.as_deref(), DEFAULT_BATCH, "OTEL_BSP_MAX_EXPORT_BATCH_SIZE")?;
        let batch = batch_raw.min(queue);

        // --- timers: invalid/zero → default; platform deadline checked ---
        let schedule = parse_timer(env.bsp_schedule.as_deref(), 5000);
        let timeout = parse_timer(env.bsp_timeout.as_deref(), 30000);

        // Platform deadline sanity (Instant::checked_add may overflow on some platforms).
        let now = std::time::Instant::now();
        if now.checked_add(schedule).is_none() {
            bail!("schedule timer exceeds platform instant range");
        }
        if now.checked_add(timeout).is_none() {
            bail!("timeout exceeds platform instant range");
        }

        Ok(Settings {
            disabled,
            unknown_propagators,
            exporters,
            propagators,
            queue,
            batch,
            schedule,
            timeout,
        })
    }
}

/// Parse a BSP size value.
/// Rules: non-numeric / zero / negative → default; valid range [1,65536]; >65536 → reject.
fn parse_bsp_size(raw: Option<&str>, default: usize, var: &str) -> Result<usize> {
    let Some(s) = raw else {
        return Ok(default);
    };
    // Parse as i64 so negatives are detected as "invalid → default".
    match s.parse::<i64>() {
        Ok(v) if v <= 0 => Ok(default),
        Ok(v) if v > 65536 => bail!("{} value {} exceeds 65536 native resource bound", var, v),
        Ok(v) => Ok(v as usize),
        Err(_) => Ok(default), // non-numeric → default
    }
}

/// Parse a millisecond timer. Invalid/zero/overflow → default_ms.
fn parse_timer(raw: Option<&str>, default_ms: u64) -> Duration {
    let ms = raw
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0);
    match ms {
        Some(v) => Duration::from_millis(v),
        None => Duration::from_millis(default_ms),
    }
}

/// Parse OTEL_TRACES_EXPORTER with exact Go signal semantics.
/// - Empty (unset or "") → defaults to "otlp".
/// - Exact, case-sensitive registry lookup. No trimming, no comma splitting.
/// - Supported registered names: "otlp", "console", "none".
/// - "none" → empty exporter list (noop).
/// - Unknown → error.
fn parse_exporters(raw: &str) -> Result<Vec<Exporter>> {
    // Go: `expType := os.Getenv(s.envKey); if expType == "" { expType = "otlp" }`
    let name = if raw.is_empty() {
        "otlp"
    } else {
        raw
    };

    match name {
        "none" => Ok(Vec::new()),
        "otlp" => Ok(vec![Exporter::Otlp]),
        "console" => Ok(vec![Exporter::Console]),
        _ => bail!("OTEL_TRACES_EXPORTER: unknown exporter"),
    }
}

/// Parse OTEL_PROPAGATORS with Go-compatible semantics.
/// - Unset/empty → default ["tracecontext","baggage"].
/// - Comma-split, exact case-sensitive, NO whitespace trimming.
/// - "none" appearing in ANY position overrides all → empty.
/// - Unknown names are silently ignored (with bounded warn).
/// - Dedup known entries preserving first-seen order.
/// - All-unknown (no known entries remain) → fall back to defaults.
fn parse_propagators(raw: &str) -> Result<(Vec<Propagator>,usize)> {
    if raw.is_empty() {
        return Ok((vec![Propagator::TraceContext, Propagator::Baggage],0));
    }

    let parts = raw.split(',');

    // "none" ANYWHERE overrides all to empty.
    if parts.clone().any(|p| p == "none") {
        return Ok((Vec::new(),0));
    }

    let mut result: Vec<Propagator> = Vec::new();
    let mut unknown_count: usize = 0;

    for part in parts {
        let prop = match part {
            "tracecontext" => Propagator::TraceContext,
            "baggage" => Propagator::Baggage,
            "b3" => Propagator::B3,
            "b3multi" => Propagator::B3Multi,
            "jaeger" => Propagator::Jaeger,
            "xray" => Propagator::Xray,
            "ottrace" => Propagator::OtTrace,
            _ => {
                unknown_count = unknown_count.saturating_add(1);
                continue;
            }
        };
        // Dedup preserving order.
        if result.contains(&prop) {
            continue;
        }
        result.push(prop);
    }

    // The provider emits this bounded count through native logging after
    // preparation. Do not block configuration processing on stdout here.
    // All-unknown → fall back to defaults.
    if result.is_empty() {
        return Ok((vec![Propagator::TraceContext, Propagator::Baggage],unknown_count));
    }

    Ok((result,unknown_count))
}
