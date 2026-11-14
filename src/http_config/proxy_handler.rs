use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use serde_json::Value;

use super::helpers;

#[derive(Clone)]
pub(crate) struct HandlerOptions {
    pub(crate) trusted_proxies: Vec<IpNet>,
    pub(crate) response_buffers: i64,
    pub(crate) proxy_status_name: String,
    pub(crate) stream_timeout: Option<Duration>,
    pub(crate) stream_buffer_size: usize,
    pub(crate) verbose_logs: bool,
}

impl Default for HandlerOptions {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            response_buffers: 0,
            proxy_status_name: String::new(),
            stream_timeout: None,
            stream_buffer_size: 32 * 1024,
            verbose_logs: false,
        }
    }
}

const MAX_ARRAY_ITEMS: usize = 4096;
const MAX_STRING_BYTES: usize = 4096;

pub(crate) fn parse(m: &serde_json::Map<String, Value>, path: &str) -> Result<HandlerOptions> {
    let mut opts = HandlerOptions::default();

    // trusted_proxies
    if let Some(v) = m.get("trusted_proxies") {
        if !v.is_null() {
            let arr = v.as_array().ok_or_else(|| {
                anyhow!("{}: expected array for 'trusted_proxies'", path)
            })?;
            if arr.len() > MAX_ARRAY_ITEMS {
                return Err(anyhow!(
                    "{}: 'trusted_proxies' exceeds max items {}",
                    path,
                    MAX_ARRAY_ITEMS
                ));
            }
            let mut proxies = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| anyhow!("{}: each 'trusted_proxies' item must be a string", path))?;
                let net = parse_ip_net(s, path)?;
                proxies.push(net);
            }
            opts.trusted_proxies = proxies;
        }
    }

    // response_buffers
    if let Some(v) = m.get("response_buffers") {
        if !v.is_null() {
            let n = v.as_i64().ok_or_else(|| {
                anyhow!("{}: 'response_buffers' must be an integer", path)
            })?;
            opts.response_buffers = n;
        }
    }

    // proxy_status_name
    if let Some(v) = m.get("proxy_status_name") {
        if !v.is_null() {
            let s = v.as_str().ok_or_else(|| {
                anyhow!("{}: 'proxy_status_name' must be a string", path)
            })?;
            if s.as_bytes().len() > MAX_STRING_BYTES {
                return Err(anyhow!(
                    "{}: 'proxy_status_name' exceeds max bytes {}",
                    path,
                    MAX_STRING_BYTES
                ));
            }
            opts.proxy_status_name = s.to_string();
        }
    }

    // stream_timeout
    if let Some(v) = m.get("stream_timeout") {
        if !v.is_null() {
            let ns = helpers::signed_duration(v,path).map_err(|e| {
                anyhow!("{}: invalid 'stream_timeout': {}", path, e)
            })?;
            if ns > 0 {
                opts.stream_timeout = Some(Duration::from_nanos(ns as u64));
            } else {
                opts.stream_timeout = None;
            }
        }
    }

    // stream_buffer_size
    if let Some(v) = m.get("stream_buffer_size") {
        if !v.is_null() {
            let n = v.as_i64().ok_or_else(|| {
                anyhow!("{}: 'stream_buffer_size' must be an integer", path)
            })?;
            if n < 0 {
                return Err(anyhow!(
                    "{}: 'stream_buffer_size' must not be negative",
                    path
                ));
            }
            let usize_val = usize::try_from(n).map_err(|_| anyhow!("{}: stream buffer size out of range",path))?;
            if n == 0 {
                opts.stream_buffer_size = 32 * 1024;
            } else {
                opts.stream_buffer_size = usize_val;
            }
        }
    }

    // verbose_logs
    if let Some(v) = m.get("verbose_logs") {
        if !v.is_null() {
            let b = v.as_bool().ok_or_else(|| {
                anyhow!("{}: 'verbose_logs' must be a boolean", path)
            })?;
            opts.verbose_logs = b;
        }
    }

    Ok(opts)
}

fn parse_ip_net(s: &str, path: &str) -> Result<IpNet> {
    if s.len()>MAX_STRING_BYTES{return Err(anyhow!("{}: trusted proxy expression exceeds limit",path));}
    // Check if it's a CIDR (contains '/')
    if s.contains('/') {
        let net: IpNet = s.parse().map_err(|_| {
            anyhow!("{}: invalid CIDR in 'trusted_proxies'", path)
        })?;
        return Ok(net);
    }

    // No slash: parse as IP address
    // IPv6 with zone: netip.PrefixFrom semantics – strip zone if IPv6 and zone non-empty
    if let Some(pos) = s.find('%') {
        // Check if it's an IPv6 address with zone
        // We need to determine if the base (without zone) is a valid IPv6
        let base = &s[..pos];
        let zone = &s[pos + 1..];

        // Try parsing base as IPv6
        if let Ok(ipv6) = base.parse::<std::net::Ipv6Addr>() {
            if !zone.is_empty() {
                // Strip zone and return IPv6Net
                return Ok(IpNet::from(IpAddr::V6(ipv6)));
            } else {
                // Zone is empty, treat '%' as part of string? Invalid.
                // The spec says: IPv6 zone non-empty时尝试剥zone并IPv6parse，IPv4%拒
                // If zone is empty, it's not a valid IPv6 zone. Treat as error.
                return Err(anyhow!(
                    "{}: invalid IP in 'trusted_proxies'",
                    path
                ));
            }
        } else {
            // Base is not valid IPv6. Check if it's IPv4 (which doesn't support %)
            // If base parses as IPv4, then '%' makes it invalid for IPv4
            if base.parse::<std::net::Ipv4Addr>().is_ok() {
                return Err(anyhow!(
                    "{}: IPv4 address with % zone is not allowed in 'trusted_proxies'",
                    path
                ));
            }
            // Not valid IPv6 base, not valid IPv4 base
            return Err(anyhow!(
                "{}: invalid IP in 'trusted_proxies'",
                path
            ));
        }
    }

    // No '%'
    let ip: IpAddr = s.parse().map_err(|_| {
        anyhow!("{}: invalid IP address in 'trusted_proxies'", path)
    })?;
    Ok(IpNet::from(ip))
}
