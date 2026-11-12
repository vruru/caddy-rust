//! Ordered PROXY listener policy and bounded native header reader.
pub(crate) mod frame;
pub(crate) mod io;
use crate::{http_config::helpers::*, net_address::NetAddress};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::time::Duration;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Config {
    pub timeout: Option<Duration>,
    allow: Vec<ipnet::IpNet>,
    deny: Vec<ipnet::IpNet>,
    fallback: io::Policy,
}
impl Config {
    pub fn parse(value: &Value, path: &str) -> Result<Self> {
        let map = object(value, path)?;
        deny_unknown(
            map,
            &["wrapper", "timeout", "allow", "deny", "fallback_policy"],
            path,
        )?;
        let timeout = match map
            .get("timeout")
            .filter(|v| !v.is_null())
            .map(|v| signed_duration(v, path))
            .transpose()?
        {
            None | Some(0) => Some(Duration::from_secs(10)),
            Some(n) if n > 0 => Some(Duration::from_nanos(n as u64)),
            Some(_) => None,
        };
        let ranges = |key| -> Result<Vec<ipnet::IpNet>> {
            let Some(value) = map.get(key).filter(|v| !v.is_null()) else {
                return Ok(vec![]);
            };
            let items = strings(value, path)?;
            ensure!(items.len() <= 1024, "PROXY policy range limit exceeded");
            items
                .into_iter()
                .map(|s| {
                    s.parse::<ipnet::IpNet>()
                        .map_err(|_| anyhow::anyhow!("invalid PROXY source prefix"))
                })
                .collect()
        };
        let fallback = match map.get("fallback_policy").filter(|v| !v.is_null()) {
            None => io::Policy::Ignore,
            Some(Value::String(value)) if value.len() <= 32 => {
                match value.to_uppercase().as_str() {
                    "IGNORE" => io::Policy::Ignore,
                    "USE" => io::Policy::Use,
                    "REJECT" => io::Policy::Reject,
                    "REQUIRE" => io::Policy::Require,
                    "SKIP" => io::Policy::Skip,
                    _ => anyhow::bail!("invalid PROXY fallback policy"),
                }
            }
            _ => anyhow::bail!("PROXY fallback policy must be a string"),
        };
        Ok(Self {
            timeout,
            allow: ranges("allow")?,
            deny: ranges("deny")?,
            fallback,
        })
    }
    pub fn policy(&self, peer: &NetAddress) -> Result<io::Policy> {
        if peer.network().starts_with("unix") {
            return Ok(io::Policy::Use);
        }
        let ip = peer
            .ip()
            .ok_or_else(|| anyhow::anyhow!("invalid PROXY upstream address"))?;
        if self.deny.iter().any(|range| range.contains(&ip)) {
            return Ok(io::Policy::Reject);
        }
        if self.allow.iter().any(|range| range.contains(&ip)) {
            return Ok(io::Policy::Use);
        }
        Ok(self.fallback)
    }
}
impl From<frame::Address> for NetAddress {
    fn from(value: frame::Address) -> Self {
        match value {
            frame::Address::Socket { address, datagram } => {
                NetAddress::Socket { address, datagram }
            }
            frame::Address::Unix { path, datagram } => NetAddress::Unix {
                path: path.into(),
                datagram,
            },
        }
    }
}
