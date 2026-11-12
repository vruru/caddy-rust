//! IP answers retain zones for dialing. Caddy dynamic A also preserves a usable
//! link-local scope; global and loopback output retains Go-compatible formatting.
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};
#[derive(Clone)]
pub(super) struct Address {
    pub(super) ip: IpAddr,
    pub(super) zone: Option<Arc<str>>,
}
impl Address {
    pub(super) fn plain(ip: IpAddr) -> Self {
        Self { ip, zone: None }
    }
    pub(super) fn lookup_literal(input: &str) -> Option<IpAddr> {
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Some(ip);
        }
        let (ip, zone) = input.split_once('%')?;
        if zone.is_empty() {
            return None;
        }
        Some(IpAddr::V6(ip.parse::<Ipv6Addr>().ok()?))
    }
    pub(super) fn parse(input: &str) -> Option<Self> {
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Some(Self::plain(ip));
        }
        let (ip, zone) = input.split_once('%')?;
        if zone.is_empty() {
            return None;
        }
        let ip = IpAddr::V6(ip.parse::<Ipv6Addr>().ok()?);
        #[cfg(unix)]
        if zone.len() >= libc::IFNAMSIZ {
            // No interface name can have this byte length on these Unix targets. Numeric indexes
            // (including leading zeros) remain valid, without copying the input.
            let numeric = zone.parse::<u32>().ok();
            return Some(Self {
                ip,
                zone: numeric
                    .filter(|n| *n != 0)
                    .map(|n| Arc::from(n.to_string())),
            });
        }
        Some(Self {
            ip,
            zone: Some(Arc::from(zone)),
        })
    }
    /// Named-zone conversion belongs on the bounded configuration I/O worker.
    pub(super) fn socket(&self, port: u16) -> SocketAddr {
        let (IpAddr::V6(ip), Some(zone)) = (self.ip, &self.zone) else {
            return SocketAddr::new(self.ip, port);
        };
        let index = zone.parse::<u32>().unwrap_or_else(|_| {
            #[cfg(unix)]
            {
                let Ok(name) = std::ffi::CString::new(zone.as_bytes()) else {
                    return 0;
                };
                // SAFETY: name is a live NUL-terminated CString; libc only reads
                // it during this call and returns zero for unknown interfaces.
                unsafe { libc::if_nametoindex(name.as_ptr()) }
            }
            #[cfg(not(unix))]
            {
                0
            }
        });
        SocketAddr::V6(SocketAddrV6::new(ip, port, 0, index))
    }
}
