//! Concrete per-transport socket/pool settings. These are connection limits,
//! never HTTP stream limits or crypto/CPU permits.
use super::{
    http_dial::{Family, FamilyResolver},
    proxy_dynamic::DnsShared,
};
use crate::http_config::proxy_transport::TransportOptions;
use anyhow::{Result, ensure};
use hyper_util::client::legacy::connect::HttpConnector;
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
pub(super) enum LocalAddress {
    Tcp(SocketAddr),
    Unix(Arc<str>),
}
pub(super) struct Settings {
    pub options: Arc<TransportOptions>,
    pub dns: Arc<DnsShared>,
    pub local: Option<LocalAddress>,
    limits: Mutex<HashMap<String, Weak<tokio::sync::Semaphore>>>,
}
impl Settings {
    pub fn new(options: Arc<TransportOptions>, dns: Arc<DnsShared>) -> Result<Arc<Self>> {
        super::proxy_dynamic::validate_acme_resolvers(&options.resolvers)?;
        let local = options
            .local_address
            .as_deref()
            .map(|raw| -> Result<_> {
                let (network, value) = raw.split_once('/').unwrap_or(("tcp", raw));
                match network {
                    "tcp" | "tcp4" | "tcp6" => {
                        let authority = if value.starts_with('[') && value.ends_with(']') {
                            format!("{value}:0")
                        } else if !value.starts_with('[') && value.matches(':').count() > 1 {
                            format!("[{value}]:0")
                        } else if value.rsplit_once(':').is_none() {
                            format!("{value}:0")
                        } else {
                            value.to_owned()
                        };
                        let authority = if authority.starts_with(':') {
                            format!(
                                "{}{}",
                                if network == "tcp6" { "[::]" } else { "0.0.0.0" },
                                authority
                            )
                        } else {
                            authority
                        };
                        let address = authority
                            .to_socket_addrs()?
                            .find(|a| match network {
                                "tcp4" => a.is_ipv4(),
                                "tcp6" => a.is_ipv6(),
                                _ => true,
                            })
                            .ok_or_else(|| anyhow::anyhow!("local address has no usable IP"))?;
                        Ok(LocalAddress::Tcp(address))
                    }
                    "unix" | "unixgram" | "unixpacket" => {
                        ensure!(!value.is_empty(), "empty local Unix address");
                        Ok(LocalAddress::Unix(Arc::from(value)))
                    }
                    _ => anyhow::bail!("local_address must use TCP or Unix"),
                }
            })
            .transpose()?;
        Ok(Arc::new(Self {
            options,
            dns,
            local,
            limits: Mutex::new(HashMap::new()),
        }))
    }
    pub fn http(
        &self,
        family: Family,
        mut resolver: FamilyResolver,
        dial_timeout: Duration,
    ) -> HttpConnector<FamilyResolver> {
        if !self.options.resolvers.is_empty() {
            resolver = resolver.with_custom(
                self.dns.clone(),
                self.options.resolvers.clone(),
                dial_timeout,
                self.options.fallback_ns,
            );
        }
        let mut http = HttpConnector::new_with_resolver(resolver);
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout((!dial_timeout.is_zero()).then_some(dial_timeout));
        http.set_happy_eyeballs_timeout(
            (self.options.fallback_ns >= 0)
                .then(|| Duration::from_nanos(self.options.fallback_ns as u64)),
        );
        let keep = (self.options.keep_alive.probe_ns > 0)
            .then(|| Duration::from_nanos(self.options.keep_alive.probe_ns as u64));
        // Go sets Interval from probe_interval and leaves Idle at the net
        // package's 15-second default. They are different socket controls.
        http.set_keepalive(keep.map(|_|Duration::from_secs(15)));
        http.set_keepalive_interval(keep);
        if let Some(LocalAddress::Tcp(address)) = &self.local {
            http.set_native_local_address(Some(*address));
        }
        let _ = family;
        http
    }
    pub fn gate(&self, host: &str) -> Result<Option<Arc<tokio::sync::Semaphore>>> {
        let n = self.options.max_conns_per_host;
        if n == 0 {
            return Ok(None);
        }
        let mut states = self
            .limits
            .lock()
            .map_err(|_| anyhow::anyhow!("upstream connection capacity unavailable"))?;
        states.retain(|_, value| value.strong_count() > 0);
        if let Some(old) = states.get(host).and_then(Weak::upgrade) {
            return Ok(Some(old));
        }
        let gate = Arc::new(tokio::sync::Semaphore::new(n));
        states.insert(host.to_owned(), Arc::downgrade(&gate));
        Ok(Some(gate))
    }
}
pub(super) fn proxy_header(version: u8, source: SocketAddr) -> Vec<u8> {
    match (version, source) {
        (1, SocketAddr::V4(a)) => {
            format!("PROXY TCP4 {} 0.0.0.0 {} 0\r\n", a.ip(), a.port()).into_bytes()
        }
        (1, SocketAddr::V6(a)) => {
            format!("PROXY TCP6 {} :: {} 0\r\n", a.ip(), a.port()).into_bytes()
        }
        (_, source) => {
            let mut bytes = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            bytes.push(0x21);
            match source {
                SocketAddr::V4(a) => {
                    bytes.extend_from_slice(&[0x11, 0, 12]);
                    bytes.extend_from_slice(&a.ip().octets());
                    bytes.extend_from_slice(&[0; 4]);
                    bytes.extend_from_slice(&a.port().to_be_bytes());
                    bytes.extend_from_slice(&[0, 0]);
                }
                SocketAddr::V6(a) => {
                    bytes.extend_from_slice(&[0x21, 0, 36]);
                    bytes.extend_from_slice(&a.ip().octets());
                    bytes.extend_from_slice(&[0; 16]);
                    bytes.extend_from_slice(&a.port().to_be_bytes());
                    bytes.extend_from_slice(&[0, 0]);
                }
            }
            bytes
        }
    }
}

/// One concrete proxy destination. Debug deliberately excludes credentials.
pub(super) struct ProxyRoute {
    pub endpoint: http::Uri,
    pub kind: ProxyKind,
    pub auth: Option<http::HeaderValue>,
    pub socks_auth: Option<(Vec<u8>, Vec<u8>)>,
    pub identity: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ProxyKind {
    Http,
    Https,
    Socks,
}
impl Settings {
    pub fn proxy(
        &self,
        target: &http::Uri,
        resolved: Option<&str>,
    ) -> Result<Option<Arc<ProxyRoute>>> {
        use crate::http_config::proxy_transport::NetworkProxy;
        let raw = match &self.options.forward_proxy {
            NetworkProxy::Direct => return Ok(None),
            NetworkProxy::Url(raw) => resolved.unwrap_or(raw).to_owned(),
            NetworkProxy::Environment => {
                let host = target.host().unwrap_or("").trim_matches(['[', ']']);
                if host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                {
                    return Ok(None);
                }
                let env = |upper: &str, lower: &str| {
                    std::env::var(upper)
                        .ok()
                        .filter(|s| !s.is_empty())
                        .or_else(|| std::env::var(lower).ok())
                        .unwrap_or_default()
                };
                let no = env("NO_PROXY", "no_proxy");
                let port = target
                    .port_u16()
                    .unwrap_or(if target.scheme_str() == Some("https") {
                        443
                    } else {
                        80
                    });
                for item in no.split(',').map(str::trim) {
                    if let Some((domain, p)) = item.rsplit_once(':') {
                        if p.parse::<u16>().ok() == Some(port) {
                            let domain = domain.trim_matches(['[', ']']);
                            let m = hyper_util::client::proxy::matcher::Matcher::builder()
                                .all("http://unused.invalid")
                                .no(domain)
                                .build();
                            if m.intercept(target).is_none() {
                                return Ok(None);
                            }
                        }
                    }
                }
                let mut m = hyper_util::client::proxy::matcher::Matcher::builder().no(no);
                let http = env("HTTP_PROXY", "http_proxy");
                let https = env("HTTPS_PROXY", "https_proxy");
                if target.scheme_str() == Some("http")
                    && !http.is_empty()
                    && std::env::var_os("REQUEST_METHOD").is_some()
                {
                    anyhow::bail!("HTTP_PROXY is refused in CGI context")
                }
                m = m.http(http).https(https);
                let Some(proxy) = m.build().intercept(target) else {
                    return Ok(None);
                };
                // Preserve raw decoded SOCKS credentials when the matcher provides them.
                let mut url = url::Url::parse(&proxy.uri().to_string())
                    .map_err(|_| anyhow::anyhow!("invalid environment proxy"))?;
                if let Some((user, password)) = proxy.raw_auth() {
                    url.set_username(user)
                        .map_err(|_| anyhow::anyhow!("invalid environment proxy authentication"))?;
                    url.set_password(Some(password))
                        .map_err(|_| anyhow::anyhow!("invalid environment proxy authentication"))?;
                }
                if let Some(auth) = proxy.basic_auth() {
                    let mut route = parse_proxy(url.as_str())?;
                    route.auth = Some(auth.clone());
                    return Ok(Some(Arc::new(route)));
                }
                return Ok(Some(Arc::new(parse_proxy(url.as_str())?)));
            }
        };
        Ok(Some(Arc::new(parse_proxy(&raw)?)))
    }
}
fn parse_proxy(raw: &str) -> Result<ProxyRoute> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    ensure!(raw.len() <= 65536, "forward proxy URL exceeds bounds");
    let url = url::Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid forward proxy URL"))?;
    let kind = match url.scheme() {
        "http" => ProxyKind::Http,
        "https" => ProxyKind::Https,
        "socks5" | "socks5h" => ProxyKind::Socks,
        _ => anyhow::bail!("unsupported forward proxy scheme"),
    };
    ensure!(url.fragment().is_none(), "invalid forward proxy URL");
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("forward proxy has no host"))?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let port = url.port().unwrap_or(match kind {
        ProxyKind::Http => 80,
        ProxyKind::Https => 443,
        ProxyKind::Socks => 1080,
    });
    let endpoint = format!(
        "{}://{host}:{port}",
        if kind == ProxyKind::Https {
            "https"
        } else {
            "http"
        }
    )
    .parse()?;
    let user = percent_encoding::percent_decode_str(url.username()).collect::<Vec<_>>();
    let password =
        percent_encoding::percent_decode_str(url.password().unwrap_or("")).collect::<Vec<_>>();
    let (auth, socks_auth) = if !url.username().is_empty() || url.password().is_some() {
        let mut data = user.clone();
        data.push(b':');
        data.extend_from_slice(&password);
        let header = http::HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(data)
        ))?;
        (Some(header), Some((user, password)))
    } else {
        (None, None)
    };
    Ok(ProxyRoute {
        endpoint,
        kind,
        auth,
        socks_auth,
        identity: Sha256::digest(raw.as_bytes()).into(),
    })
}
