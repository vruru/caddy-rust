use anyhow::{Result, anyhow, ensure};
use serde_json::{Map, Value};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    pub allowed_http_verbs: Vec<String>,
    pub cache_name: String,
    pub default_cache_control: String,
    pub hash: bool,
    pub hide: bool,
    pub max_body_bytes: usize,
    pub capacity: usize,
    pub ttl: Duration,
    pub log_level: u8,
}
fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("cache configuration requires object"))?;
    for key in obj.keys() {
        ensure!(
            key == "@id" || allowed.contains(&key.as_str()),
            "unsupported cache field {key}"
        );
    }
    Ok(obj)
}
fn field<'a>(obj: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    obj.get(name).filter(|v| !v.is_null())
}
fn text(obj: &Map<String, Value>, name: &str, default: &str) -> Result<String> {
    let value = match field(obj, name) {
        None => default,
        Some(v) => v
            .as_str()
            .ok_or_else(|| anyhow!("cache {name} requires string"))?,
    };
    ensure!(value.len() <= 8192, "cache text exceeds resource bound");
    Ok(value.into())
}
fn boolean(obj: &Map<String, Value>, name: &str) -> Result<bool> {
    field(obj, name).map_or(Ok(false), |v| {
        v.as_bool()
            .ok_or_else(|| anyhow!("cache {name} requires boolean"))
    })
}
fn duration(obj: &Map<String, Value>, name: &str, default: &str) -> Result<Duration> {
    let raw = text(obj, name, default)?;
    let n = crate::duration::parse_go(if raw.is_empty() { "0" } else { &raw })?;
    ensure!(n >= 0, "cache duration must be nonnegative");
    Ok(Duration::from_nanos(n as u64))
}
impl Config {
    pub fn parse(value: &Value) -> Result<Self> {
        let o = object(
            value,
            &[
                "allowed_http_verbs",
                "cache_name",
                "default_cache_control",
                "key",
                "max_cacheable_body_bytes",
                "otter",
                "ttl",
                "stale",
                "storers",
                "log_level",
            ],
        )?;
        let mut verbs = Vec::new();
        if let Some(v) = field(o, "allowed_http_verbs") {
            let a = v
                .as_array()
                .ok_or_else(|| anyhow!("cache verbs requires array"))?;
            ensure!(a.len() <= 2, "cache supports GET/HEAD only");
            for v in a {
                let s = v
                    .as_str()
                    .ok_or_else(|| anyhow!("cache verb requires string"))?;
                ensure!(matches!(s, "GET" | "HEAD"), "cache supports GET/HEAD only");
                verbs.push(s.into());
            }
        }
        if verbs.is_empty() {
            verbs = vec!["GET".into(), "HEAD".into()];
        }
        let mut name = text(o, "cache_name", "Souin")?;
        if name.is_empty() {
            name = "Souin".into();
        }
        ensure!(
            name.len() <= 128
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)),
            "cache_name must be a bounded Cache-Status token"
        );
        let cc = text(o, "default_cache_control", "")?;
        http::HeaderValue::from_str(&cc)?;
        let (hash, hide) = if let Some(v) = field(o, "key") {
            let k = object(v, &["hash", "hide"])?;
            (boolean(k, "hash")?, boolean(k, "hide")?)
        } else {
            (false, false)
        };
        let max = field(o, "max_cacheable_body_bytes").map_or(Ok(4_194_304), |v| {
            v.as_number()
                .and_then(serde_json::Number::as_go_i64)
                .and_then(|n| u64::try_from(n).ok())
                .ok_or_else(|| anyhow!("cache max body requires uint"))
        })?;
        ensure!(
            max > 0 && max <= 16_777_216,
            "cache max body resource bound is 1..16777216"
        );
        let mut capacity = 10_000;
        if let Some(v) = field(o, "otter") {
            let otter = object(v, &["found", "configuration"])?;
            let _ = boolean(otter, "found")?;
            if let Some(v) = field(otter, "configuration") {
                let c = object(v, &["size"])?;
                if let Some(v) = field(c, "size") {
                    capacity = if let Some(s) = v.as_str() {
                        s.parse::<u64>()?
                    } else {
                        v.as_number()
                            .and_then(serde_json::Number::as_go_i64)
                            .and_then(|n| u64::try_from(n).ok())
                            .ok_or_else(|| anyhow!("otter size requires uint or decimal string"))?
                    };
                    if capacity == 0 {
                        capacity = 10_000;
                    }
                }
            }
        }
        ensure!(capacity <= 1_000_000, "otter size exceeds resource bound");
        if let Some(v) = field(o, "storers") {
            let a = v
                .as_array()
                .ok_or_else(|| anyhow!("cache storers requires array"))?;
            ensure!(
                a.len() <= 1 && a.iter().all(|v| v.as_str() == Some("OTTER")),
                "only OTTER cache storage is implemented"
            );
        }
        let mut ttl = duration(o, "ttl", "120s")?;
        if ttl.is_zero() {
            ttl = Duration::from_secs(120);
        }
        ensure!(
            duration(o, "stale", "0s")?.is_zero(),
            "nonzero cache stale is not implemented"
        );
        let level = text(o, "log_level", "")?;
        ensure!(
            matches!(
                level.as_str(),
                "" | "debug" | "info" | "warn" | "error" | "dpanic" | "panic" | "fatal"
            ),
            "invalid cache log_level"
        );
        Ok(Self {
            allowed_http_verbs: verbs,
            cache_name: name,
            default_cache_control: cc,
            hash,
            hide,
            max_body_bytes: max as usize,
            capacity: capacity as usize,
            ttl,
            log_level: match level.as_str() {
                "debug" => 0,
                "info" | "" => 1,
                "warn" => 2,
                "error" => 3,
                "dpanic" => 4,
                "panic" => 5,
                _ => 6,
            },
        })
    }
}
