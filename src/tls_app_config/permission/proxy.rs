//! net/http's Go 1.27 proxy environment semantics. Decide before constructing
//! the endpoint-specific client; reqwest NoProxy treats leading dots differently.
use super::{PermissionFailure, env};
use anyhow::Result;
use std::net::IpAddr;
use url::{Host, Url};
pub(super) fn selected(url: &Url) -> Result<Option<Url>> {
    let proxy = match url.scheme() {
        "http" => env("HTTP_PROXY"),
        "https" => env("HTTPS_PROXY"),
        _ => None,
    };
    let Some(mut proxy) = proxy.and_then(|proxy| parse_proxy(&proxy)) else {
        return Ok(None);
    };
    // Go checks the CGI guard before the localhost / no_proxy bypass.
    if url.scheme() == "http" && std::env::var("REQUEST_METHOD").is_ok_and(|v| !v.is_empty()) {
        return Err(PermissionFailure::Transport.into());
    }
    if bypass(url, &env("NO_PROXY").unwrap_or_default()) {
        Ok(None)
    } else {
        match proxy.scheme() {
            "socks5" => {
                // Both Go variants send the unresolved DNS name to the proxy.
                proxy
                    .set_scheme("socks5h")
                    .map_err(|_| PermissionFailure::Transport)?;
            }
            "socks5h" | "http" | "https" => {}
            _ => {
                // Go's transport uses an HTTP proxy for other schemes with an
                // explicit port, rather than using reqwest's SOCKS4 semantics.
                if proxy.port().is_none() {
                    return Err(PermissionFailure::Transport.into());
                }
                let (_, authority_and_path) = proxy
                    .as_str()
                    .split_once("://")
                    .ok_or(PermissionFailure::Transport)?;
                proxy = Url::parse(&format!("http://{authority_and_path}"))
                    .map_err(|_| PermissionFailure::Transport)?;
            }
        }
        Ok(Some(proxy))
    }
}
fn parse_proxy(value: &str) -> Option<Url> {
    Url::parse(value)
        .ok()
        .filter(|url| url.host().is_some())
        .or_else(|| {
            Url::parse(&format!("http://{value}"))
                .ok()
                .filter(|url| url.host().is_some())
        })
}
pub(super) fn bypass(url: &Url, rules: &str) -> bool {
    let (host, ip) = match url.host() {
        Some(Host::Ipv4(ip)) => (ip.to_string(), Some(IpAddr::V4(ip))),
        Some(Host::Ipv6(ip)) => (ip.to_string(), Some(IpAddr::V6(ip).to_canonical())),
        Some(Host::Domain(host)) => (host.to_ascii_lowercase(), None),
        None => return true,
    };
    if host == "localhost" || ip.is_some_and(|ip| ip.is_loopback()) {
        return true;
    }
    let port = url
        .port_or_known_default()
        .map(|port| port.to_string())
        .unwrap_or_default();
    for rule in rules.split(',') {
        let rule = rule.trim().to_lowercase();
        if rule == "*" {
            return true;
        }
        if rule.is_empty() {
            continue;
        }
        if let Ok(network) = rule.parse::<ipnet::IpNet>() {
            if ip.is_some_and(|ip| network.contains(&ip)) {
                return true;
            }
            continue;
        }
        let (domain, required_port) = split_host_port(&rule);
        if !required_port.is_empty() && required_port != port {
            continue;
        }
        if let Ok(address) = domain.parse::<IpAddr>() {
            if ip.is_some_and(|ip| ip == address.to_canonical()) {
                return true;
            }
            continue;
        }
        let domain = if domain.starts_with("*.") {
            &domain[1..]
        } else {
            domain
        };
        // ASCII values are intentionally not revalidated, matching Go's fast path.
        let domain = if domain.is_ascii() {
            domain.to_owned()
        } else {
            idna::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_owned())
        };
        if domain.is_empty() {
            continue;
        }
        if domain.starts_with('.') {
            if host.ends_with(&domain) {
                return true;
            }
        } else if host == domain || host.ends_with(&format!(".{domain}")) {
            return true;
        }
    }
    false
}
fn split_host_port(rule: &str) -> (&str, &str) {
    if let Some(rest) = rule.strip_prefix('[')
        && let Some((host, port)) = rest.split_once("]:")
    {
        return (host, port);
    }
    if rule.bytes().filter(|byte| *byte == b':').count() == 1
        && let Some((host, port)) = rule.rsplit_once(':')
    {
        return (host, port);
    }
    (rule, "")
}
