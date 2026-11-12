use anyhow::{Result, ensure};
use serde_json::Value;
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Config {
    pub per_host: bool,
    pub observe_catchall_hosts: bool,
    pub otlp: bool,
}
impl Config {
    pub fn parse(value: &Value) -> Result<Self> {
        let map = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("metrics object required"))?;
        ensure!(
            map.keys()
                .all(|key| matches!(key.as_str(), "per_host" | "observe_catchall_hosts" | "otlp")),
            "unknown HTTP metrics field"
        );
        let flag = |key: &str| -> Result<bool> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(false),
                Some(Value::Bool(value)) => Ok(*value),
                _ => anyhow::bail!("metrics {key} must be a boolean"),
            }
        };
        Ok(Self {
            per_host: flag("per_host")?,
            observe_catchall_hosts: flag("observe_catchall_hosts")?,
            otlp: flag("otlp")?,
        })
    }
    pub fn merge(&mut self, other: Self) {
        self.per_host |= other.per_host;
        self.observe_catchall_hosts |= other.observe_catchall_hosts;
        self.otlp |= other.otlp;
    }
}
pub(super) fn method(value: &str) -> &'static str {
    match value {
        "GET" | "get" => "GET",
        "HEAD" | "head" => "HEAD",
        "POST" | "post" => "POST",
        "PUT" | "put" => "PUT",
        "DELETE" | "delete" => "DELETE",
        "CONNECT" | "connect" => "CONNECT",
        "OPTIONS" | "options" => "OPTIONS",
        "TRACE" | "trace" => "TRACE",
        "PATCH" | "patch" => "PATCH",
        _ => "OTHER",
    }
}
