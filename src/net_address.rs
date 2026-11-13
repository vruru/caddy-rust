//! Connection addresses retain the actual PROXY address family. A Unix address
//! is never replaced with a fabricated IP for ACLs, routing or client identity.
use std::{
    borrow::Cow,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Canonicalize only IPv4-mapped addresses. Rebuilding a real IPv6 endpoint
/// from its IP and port would discard its interface scope and flow information.
pub(crate) fn canonical_socket(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(value) => value.ip().to_ipv4_mapped()
            .map_or(address, |ip| SocketAddr::new(ip.into(), value.port())),
        SocketAddr::V4(_) => address,
    }
}

fn socket_host(address: SocketAddr) -> String {
    match canonical_socket(address) {
        SocketAddr::V6(value) if value.scope_id() != 0 => {
            format!("{}%{}", value.ip(), value.scope_id())
        }
        address => address.ip().to_string(),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetAddress {
    Socket { address: SocketAddr, datagram: bool },
    Unix { path: Arc<[u8]>, datagram: bool },
}
impl From<SocketAddr> for NetAddress {
    fn from(address: SocketAddr) -> Self {
        Self::Socket {
            address,
            datagram: false,
        }
    }
}
impl NetAddress {
    pub fn udp(address: SocketAddr) -> Self {
        Self::Socket {
            address,
            datagram: true,
        }
    }
    pub fn network(&self) -> &'static str {
        match self {
            Self::Socket {
                datagram: false, ..
            } => "tcp",
            Self::Socket { datagram: true, .. } => "udp",
            Self::Unix {
                datagram: false, ..
            } => "unix",
            Self::Unix { datagram: true, .. } => "unixgram",
        }
    }
    pub fn text(&self) -> Cow<'_, str> {
        match self {
            Self::Socket { address, .. } => {
                Cow::Owned(canonical_socket(*address).to_string())
            }
            Self::Unix { path, .. } => String::from_utf8_lossy(path),
        }
    }
    pub fn raw_text(&self) -> Cow<'_, [u8]> {
        match self {
            Self::Unix { path, .. } => Cow::Borrowed(path),
            _ => Cow::Owned(self.text().into_owned().into_bytes()),
        }
    }
    pub fn host_port_bytes(&self) -> Option<(Cow<'_, [u8]>, Cow<'_, [u8]>)> {
        match self {
            Self::Socket { address, .. } => Some((
                Cow::Owned(socket_host(*address).into_bytes()),
                Cow::Owned(address.port().to_string().into_bytes()),
            )),
            Self::Unix { path, .. } => {
                let (host, port) = split_host_port_bytes(path)?;
                Some((Cow::Borrowed(host), Cow::Borrowed(port)))
            }
        }
    }
    pub fn host_port(&self) -> Option<(String, String)> {
        self.host_port_bytes().map(|(host, port)| {
            (
                String::from_utf8_lossy(&host).into_owned(),
                String::from_utf8_lossy(&port).into_owned(),
            )
        })
    }
    pub fn raw_host(&self) -> Cow<'_, [u8]> {
        self.host_port_bytes()
            .map_or_else(|| self.raw_text(), |(host, _)| host)
    }
    pub fn raw_port(&self) -> Cow<'_, [u8]> {
        self.host_port_bytes()
            .map_or(Cow::Borrowed(b""), |(_, port)| port)
    }
    pub fn host(&self) -> String {
        String::from_utf8_lossy(&self.raw_host()).into_owned()
    }
    pub fn port_text(&self) -> String {
        String::from_utf8_lossy(&self.raw_port()).into_owned()
    }
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Socket { address, .. } => Some(address.ip().to_canonical()),
            Self::Unix { path, .. } => {
                let (host, _) = split_host_port_bytes(path)?;
                let host = std::str::from_utf8(host).ok()?;
                host.split('%').next()?.parse::<IpAddr>().ok()
            }
        }
    }
    /// HTTP remote-IP matchers fall back to a bare IP when no port is present.
    /// The trusted-proxy/client-IP path intentionally uses strict `ip()` above.
    pub fn matcher_ip(&self) -> Option<IpAddr> {
        let raw = self.raw_host();
        std::str::from_utf8(&raw)
            .ok()?
            .split('%')
            .next()?
            .parse()
            .ok()
    }
    /// TLS preserves a valid zone as a distinct identity. netip.Prefix cannot
    /// contain a scoped address, although an empty-range matcher accepts it.
    pub fn tls_ip(&self) -> Option<(IpAddr, bool)> {
        if let Self::Socket { address, .. } = self {
            let scoped = matches!(address,SocketAddr::V6(address)if address.scope_id()!=0);
            return Some((address.ip().to_canonical(), scoped));
        }
        let raw = self.raw_host();
        let text = std::str::from_utf8(&raw).ok()?;
        if let Some((ip, zone)) = text.split_once('%') {
            if zone.is_empty() {
                return None;
            }
            let ip = ip.parse::<std::net::Ipv6Addr>().ok()?;
            Some((IpAddr::V6(ip), true))
        } else {
            Some((text.parse().ok()?, false))
        }
    }
    pub fn socket(&self) -> Option<SocketAddr> {
        match self {
            Self::Socket { address, .. } => Some(*address),
            _ => None,
        }
    }
    /// FastCGI deliberately splits at the final colon, which is more lenient than
    /// net.SplitHostPort. Preserve this separately from HTTP/IP trust parsing.
    pub fn fastcgi_remote(&self) -> (Vec<u8>, Vec<u8>) {
        let text = self.raw_text();
        let (host, port) = text
            .iter()
            .rposition(|b| *b == b':')
            .map_or((text.as_ref(), b"".as_slice()), |at| {
                (&text[..at], &text[at + 1..])
            });
        let mut host = host.to_vec();
        for bracket in [b'[', b']'] {
            if let Some(at) = host.iter().position(|b| *b == bracket) {
                host.remove(at);
            }
        }
        (host, port.to_vec())
    }
}
impl fmt::Display for NetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}
/// The structural part of Go net.SplitHostPort: port may be empty or textual;
/// brackets are mandatory for IPv6, and zones are retained in the host.
fn split_host_port_bytes(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = text.iter().rposition(|b| *b == b':')?;
    let host = if text.starts_with(b"[") {
        let end = text.iter().position(|b| *b == b']')?;
        if end + 1 != colon {
            return None;
        }
        &text[1..end]
    } else {
        let host = &text[..colon];
        if host.contains(&b':') {
            return None;
        }
        host
    };
    let port = &text[colon + 1..];
    if host.contains(&b'[') || host.contains(&b']') || port.contains(&b'[') || port.contains(&b']')
    {
        return None;
    }
    Some((host, port))
}
