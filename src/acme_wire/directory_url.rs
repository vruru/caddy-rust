//! ACME directory normalization and its explicit, origin-scoped HTTP grant.
//! No DNS lookup or inferred trust from a directory response takes place here.
use anyhow::{Result, anyhow, ensure};
use url::Url;

pub(crate) fn normalize(raw: &str) -> Result<Url> {
    let qualified;
    let text = if raw.contains("://") {
        raw
    } else {
        qualified = format!("https://{raw}");
        &qualified
    };
    let url = Url::parse(text).map_err(|_| anyhow!("invalid ACME directory URL"))?;
    ensure!(
        matches!(url.scheme(), "https" | "http")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "invalid ACME directory URL"
    );
    ensure!(
        url.scheme() == "https" || internal(&url),
        "ACME directory requires HTTPS outside internal hosts"
    );
    Ok(url)
}

pub(super) fn allowed_http_origin(url: &Url) -> Option<String> {
    (url.scheme() == "http" && internal(url)).then(|| url.origin().ascii_serialization())
}

fn internal(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            let host = host.trim_end_matches('.');
            host.eq_ignore_ascii_case("localhost")
                || [".localhost", ".local", ".internal", ".home.arpa"]
                    .iter()
                    .any(|suffix| {
                        host.len() > suffix.len()
                            && host
                                .get(host.len() - suffix.len()..)
                                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
                    })
        }
        Some(url::Host::Ipv4(ip)) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        Some(url::Host::Ipv6(ip)) => match ip.to_ipv4_mapped() {
            Some(ip) => {
                ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
            }
            None => {
                ip.is_loopback()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip.is_unspecified()
            }
        },
        None => false,
    }
}
