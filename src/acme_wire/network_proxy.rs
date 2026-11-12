//! ACME wire network proxy configuration.
//!
//! URL and global placeholders (`{...}`) are resolved exactly once during
//! independent ACME client construction on the cert_cpu blocking lane.
//! No business-layer `RequestReplacer` is available; unknown placeholders
//! resolve to empty, and a final URL with no host (empty) must fail-closed
//! rather than silently falling back to `Direct`.

use anyhow::{Result, bail};
use std::sync::Arc;

#[derive(Clone)]
pub enum NetworkProxy {
    Direct,
    Url(Arc<str>),
}

impl NetworkProxy {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Direct => Ok(()),
            Self::Url(raw) => {
                if raw.is_empty() {
                    bail!("proxy url must not be empty");
                }
                if raw.len() > 65536 {
                    bail!("proxy url exceeds 65536 bytes");
                }
                if raw.contains('{') && raw.contains('}') {
                    return Ok(());
                }
                parse_static(raw).map(|_| ())
            }
        }
    }

    pub(crate) fn apply(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        match self {
            Self::Direct => Ok(builder.no_proxy()),
            Self::Url(raw) => {
                let resolved = if raw.contains('{') && raw.contains('}') {
                    let r = crate::http_config::helpers::replace(
                        raw,
                        true,
                        crate::http_config::helpers::global_lookup,
                    )
                    .map_err(|_| anyhow::anyhow!("ACME proxy placeholder expansion failed"))?;
                    if r.len() > 65536 {
                        bail!("resolved proxy url exceeds 65536 bytes");
                    }
                    r
                } else {
                    raw.to_string()
                };
                let mut url = parse_static(&resolved)?;
                // Go's net/http deliberately treats socks5 as socks5h: the
                // destination name is resolved at the proxy in either spelling.
                if url.scheme() == "socks5" {
                    url.set_scheme("socks5h")
                        .map_err(|_| anyhow::anyhow!("invalid ACME SOCKS proxy"))?;
                }
                let proxy = reqwest::Proxy::all(url)
                    .map_err(|_| anyhow::anyhow!("proxy url is malformed"))?;
                Ok(builder.no_proxy().proxy(proxy))
            }
        }
    }

    pub(crate) fn fingerprint(&self) -> (&'static [u8], &[u8]) {
        match self {
            Self::Direct => (b"direct", b""),
            Self::Url(raw) => (b"url", raw.as_bytes()),
        }
    }
}

fn parse_static(url: &str) -> Result<url::Url> {
    if url.is_empty() {
        bail!("proxy url must not be empty");
    }
    let implicit_http;
    let url = if url.starts_with("//") {
        implicit_http = format!("http:{url}");
        implicit_http.as_str()
    } else {
        url
    };
    let parsed = url::Url::parse(url).map_err(|_| anyhow::anyhow!("proxy url is malformed"))?;
    if parsed.host_str().unwrap_or("").is_empty() {
        bail!("proxy url has no host");
    }
    match parsed.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        _ => bail!("proxy url scheme must be http/https/socks5/socks5h"),
    }
    Ok(parsed)
}
