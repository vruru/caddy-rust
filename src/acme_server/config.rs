use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use crate::duration;

/// Represents the ACME server configuration parsed from JSON.
#[derive(Clone, Debug)]
pub struct Config {
    pub ca: String,
    pub lifetime: Duration,
    pub host: String,
    pub path_prefix: String,
    pub sign_with_root: bool,
    pub resolvers: std::sync::Arc<[String]>,
    pub challenges: Vec<Challenge>,
    pub policy: Option<Policy>,
}

/// Supported ACME challenge types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Challenge {
    Http,
    Dns,
    TlsAlpn,
}

impl Challenge {
    /// Returns the canonical string representation of the challenge.
    pub fn name(&self) -> &'static str {
        match self {
            Challenge::Http => "http-01",
            Challenge::Dns => "dns-01",
            Challenge::TlsAlpn => "tls-alpn-01",
        }
    }
}

/// Policy configuration for domain/IP allow/deny lists.
#[derive(Clone, Debug)]
pub struct Policy {
    pub allow: Option<Rules>,
    pub deny: Option<Rules>,
    pub allow_wildcard_names: bool,
}

/// Set of allowed/denied domains and IP ranges.
#[derive(Clone, Debug)]
pub struct Rules {
    pub domains: Vec<String>,
    pub ip_ranges: Vec<String>,
}

/// Parses the ACME server configuration from a JSON Value.
///
/// Enforces strict schema validation:
/// - Only allows known fields: `handler`, `ca`, `lifetime`, `host`, `path_prefix`,
///   `sign_with_root`, `resolvers`, `challenges`, `policy`.
/// - `handler` must be `"acme_server"` if present.
/// - Null/missing fields are replaced with Go-like zero values.
/// - Empty `ca` becomes `"local"`.
/// - Empty `path_prefix` becomes `"/acme/"`.
/// - Empty/0 `lifetime` becomes 12 hours.
/// - Validates `path_prefix` format.
/// - Validates `challenges` strings strictly.
pub fn parse(json: &Value) -> Result<Config> {
    // Ensure the root is an object
    let obj = json
        .as_object()
        .ok_or_else(|| anyhow!("config root must be an object"))?;

    // Validate top-level keys (strict)
    let allowed_keys = [
        "handler",
        "ca",
        "lifetime",
        "host",
        "path_prefix",
        "sign_with_root",
        "resolvers",
        "challenges",
        "policy",
    ];
    for key in obj.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(anyhow!("unknown field: {}", key));
        }
    }

    // Handler validation (must be "acme_server" if present)
    if let Some(handler_val) = obj.get("handler") {
        let handler_str = extract_string_opt(handler_val)?;
        if let Some(h) = handler_str {
            if h != "acme_server" {
                return Err(anyhow!("handler must be \"acme_server\""));
            }
        }
    }

    // CA
    let ca_raw = obj.get("ca").unwrap_or(&Value::Null);
    let ca = extract_string_opt(&ca_raw)?;
    let ca = ca.unwrap_or_default();
    let ca = if ca.is_empty() {
        "local".to_string()
    } else {
        ca
    };

    // Lifetime
    let lifetime_raw = obj.get("lifetime").unwrap_or(&Value::Null);
    let lifetime = extract_duration(&lifetime_raw)?;
    let lifetime = if lifetime == Duration::ZERO {
        Duration::from_secs(12 * 60 * 60)
    } else {
        lifetime
    };
    ensure!(
        (Duration::from_secs(300)..=Duration::from_secs(365 * 86400)).contains(&lifetime),
        "ACME default certificate lifetime must be between 5 minutes and 365 days"
    );

    // Host
    let host_raw = obj.get("host").unwrap_or(&Value::Null);
    let host = extract_string_opt(&host_raw)?.unwrap_or_default();

    // Path Prefix
    let prefix_raw = obj.get("path_prefix").unwrap_or(&Value::Null);
    let mut path_prefix = extract_string_opt(&prefix_raw)?.unwrap_or_default();
    if path_prefix.is_empty() {
        path_prefix = "/acme/".to_string();
    }
    validate_path_prefix(&path_prefix)?;

    // Sign With Root
    let sign_raw = obj.get("sign_with_root").unwrap_or(&Value::Null);
    let sign_with_root = extract_bool_opt(&sign_raw)?.unwrap_or(false);

    // Resolvers
    let resolvers_raw = obj.get("resolvers").unwrap_or(&Value::Null);
    let resolvers = extract_string_array(&resolvers_raw)?;
    crate::http_runtime::acme_dns::validate_resolvers(&resolvers)?;

    // Challenges
    let challenges_raw = obj.get("challenges").unwrap_or(&Value::Null);
    let challenge_strings = extract_string_array(&challenges_raw)?;
    let mut challenges = Vec::with_capacity(challenge_strings.len());
    for s in challenge_strings {
        challenges.push(parse_challenge(&s)?);
    }

    // Policy
    let policy_raw = obj.get("policy").unwrap_or(&Value::Null);
    let policy = parse_policy(&policy_raw)?;
    super::policy::validate(policy.as_ref())?;

    Ok(Config {
        ca,
        lifetime,
        host,
        path_prefix,
        sign_with_root,
        resolvers: resolvers.into(),
        challenges,
        policy,
    })
}

fn extract_string_opt(val: &Value) -> Result<Option<String>> {
    match val {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        _ => Err(anyhow!("expected string or null")),
    }
}

fn extract_bool_opt(val: &Value) -> Result<Option<bool>> {
    match val {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        _ => Err(anyhow!("expected bool or null")),
    }
}

fn extract_duration(val: &Value) -> Result<Duration> {
    if val.is_null() {
        return Ok(Duration::ZERO);
    }
    let nanos = duration::parse_value(val)?;
    if nanos < 0 {
        return Err(anyhow!("duration must be non-negative"));
    }
    Ok(Duration::from_nanos(nanos as u64))
}

fn extract_string_array(val: &Value) -> Result<Vec<String>> {
    match val {
        Value::Null => Ok(Vec::new()),
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    // encoding/json null into a fresh string preserves its zero value.
                    Value::Null => out.push(String::new()),
                    _ => return Err(anyhow!("array elements must be strings")),
                }
            }
            Ok(out)
        }
        _ => Err(anyhow!("expected array or null")),
    }
}

fn validate_path_prefix(prefix: &str) -> Result<()> {
    if !prefix.starts_with('/') {
        return Err(anyhow!("path_prefix must start with '/'"));
    }
    // Disallow query, fragment, and control characters
    for c in prefix.chars() {
        if c == '?' || c == '#' || c.is_control() {
            return Err(anyhow!("path_prefix contains invalid character"));
        }
    }
    Ok(())
}

fn parse_challenge(s: &str) -> Result<Challenge> {
    let trimmed = s.trim();
    let lower = trimmed.to_lowercase();
    match lower.as_str() {
        "http-01" => Ok(Challenge::Http),
        "dns-01" => Ok(Challenge::Dns),
        "tls-alpn-01" => Ok(Challenge::TlsAlpn),
        _ => Err(anyhow!("invalid challenge: {}", s)),
    }
}

fn parse_policy(val: &Value) -> Result<Option<Policy>> {
    match val {
        Value::Null => Ok(None),
        Value::Object(obj) => {
            // Check for unknown fields in policy
            for key in obj.keys() {
                if key != "allow" && key != "deny" && key != "allow_wildcard_names" {
                    return Err(anyhow!("unknown policy field: {}", key));
                }
            }

            let allow_raw = obj.get("allow").unwrap_or(&Value::Null);
            let allow = parse_rules(&allow_raw)?;

            let deny_raw = obj.get("deny").unwrap_or(&Value::Null);
            let deny = parse_rules(&deny_raw)?;

            let wildcard_raw = obj.get("allow_wildcard_names").unwrap_or(&Value::Null);
            let allow_wildcard_names = extract_bool_opt(&wildcard_raw)?.unwrap_or(false);

            Ok(Some(Policy {
                allow,
                deny,
                allow_wildcard_names,
            }))
        }
        _ => Err(anyhow!("policy must be an object or null")),
    }
}

fn parse_rules(val: &Value) -> Result<Option<Rules>> {
    match val {
        Value::Null => Ok(None),
        Value::Object(obj) => {
            // Check for unknown fields in rules
            for key in obj.keys() {
                if key != "domains" && key != "ip_ranges" {
                    return Err(anyhow!("unknown rules field: {}", key));
                }
            }

            let domains_raw = obj.get("domains").unwrap_or(&Value::Null);
            let domains = extract_string_array(&domains_raw)?;

            let ip_ranges_raw = obj.get("ip_ranges").unwrap_or(&Value::Null);
            let ip_ranges = extract_string_array(&ip_ranges_raw)?;

            Ok(Some(Rules { domains, ip_ranges }))
        }
        _ => Err(anyhow!("rules must be an object or null")),
    }
}
