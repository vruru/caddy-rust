use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::vec;

use anyhow::anyhow;
use http::Uri;
use http::uri::Authority;
use hyper_util::client::legacy::connect::dns::Name;
use tower_service::Service;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Family {
    Any,
    V4,
    V6,
}

impl Family {
    pub(super) fn parse(raw: &str) -> anyhow::Result<(Family, &str)> {
        let (family, address) = match raw.split_once('/') {
            Some(("tcp", a)) => (Family::Any, a),
            Some(("tcp4", a)) => (Family::V4, a),
            Some(("tcp6", a)) => (Family::V6, a),
            Some(_) => return Err(anyhow!("unsupported HTTP upstream network")),
            None => (Family::Any, raw),
        };
        if address.is_empty() || address.contains(['@', '#', '?', '/', '\r', '\n', '\0']) {
            return Err(anyhow!("invalid HTTP upstream address"));
        }
        let authority = address.parse::<Authority>()?;
        anyhow::ensure!(!authority.host().is_empty(), "empty HTTP upstream host");
        Ok((family, address))
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Family::Any => "tcp",
            Family::V4 => "tcp4",
            Family::V6 => "tcp6",
        }
    }

    pub(super) fn admit(self, addr: SocketAddr) -> Option<SocketAddr> {
        match self {
            Family::Any => Some(addr),
            Family::V4 => match addr.ip() {
                IpAddr::V4(_) => Some(addr),
                IpAddr::V6(v6) => v6
                    .to_ipv4_mapped()
                    .map(|v4| SocketAddr::new(IpAddr::V4(v4), addr.port())),
            },
            Family::V6 => match addr.ip() {
                IpAddr::V6(v6) => {
                    if v6.to_ipv4_mapped().is_some() {
                        None
                    } else {
                        Some(addr)
                    }
                }
                IpAddr::V4(_) => None,
            },
        }
    }

    pub(super) fn literal_uri(&self, uri: &Uri) -> io::Result<Uri> {
        let authority: Authority = uri
            .authority()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing authority"))?
            .clone();
        let host = authority.host();
        if host.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty host"));
        }

        let port = authority.port_u16();
        let mut ip_str = host.to_string();
        if ip_str.starts_with('[') {
            ip_str.remove(0);
            if ip_str.ends_with(']') {
                ip_str.pop();
            }
        }
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return Ok(uri.clone()),
        };

        let sock = match port {
            Some(p) => SocketAddr::new(ip, p),
            None => SocketAddr::new(ip, 0),
        };

        let admitted = self.admit(sock).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "address family not admitted",
            )
        })?;
        let new_ip = admitted.ip();
        let new_port = admitted.port();

        if new_ip == ip && new_port == port.unwrap_or(0) {
            return Ok(uri.clone());
        }

        let new_host = match new_ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{}]", v6),
        };

        let mut parts = uri.clone().into_parts();
        let mut new_authority = new_host;
        if let Some(p) = port {
            new_authority.push(':');
            new_authority.push_str(&p.to_string());
        }
        parts.authority = Some(
            new_authority
                .parse::<Authority>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        Uri::from_parts(parts).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[derive(Clone)]
pub(super) struct FamilyResolver {
    inner: hyper_util::client::legacy::connect::dns::GaiResolver,
    family: Family,
    retained:Option<(super::resource_budget::BlockingBudget,std::sync::Arc<super::map_runtime::DialOwner>)>,
}

impl FamilyResolver {
    pub(super) fn new(family: Family) -> Self {
        Self {
            inner: hyper_util::client::legacy::connect::dns::GaiResolver::new(),
            family,
            retained:None,
        }
    }
    pub(super) fn with_map(family:Family,budget:super::resource_budget::BlockingBudget,owner:std::sync::Arc<super::map_runtime::DialOwner>)->Self{
        Self{inner:hyper_util::client::legacy::connect::dns::GaiResolver::new(),family,retained:Some((budget,owner))}
    }
}

pub(super) struct FamilyAddrs{values:vec::IntoIter<SocketAddr>,_retained:Option<super::resource_budget::RetainedBlockingOutput<io::Result<Vec<SocketAddr>>>>}
impl Iterator for FamilyAddrs{type Item=SocketAddr;fn next(&mut self)->Option<SocketAddr>{self.values.next()}fn size_hint(&self)->(usize,Option<usize>){self.values.size_hint()}}

impl Service<Name> for FamilyResolver {
    type Response = FamilyAddrs;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let family=self.family;
        if let Some((budget,owner))=&self.retained{
            let task=match owner.dns_work(name.as_str().len()){
                Ok(task)=>task,Err(error)=>return Box::pin(async move{Err(io::Error::other(error.to_string()))}),
            };
            let budget=budget.clone();
            return Box::pin(async move{
                use std::net::ToSocketAddrs;
                // Same synchronous NSS semantics as GaiResolver. The actual
                // Name and result stay behind the closed retained envelope,
                // including after a detached receiver is cancelled.
                let output=budget.run_retained(task.clone(),move||{
                    (name.as_str(),0).to_socket_addrs()
                        .and_then(|addrs|super::mapped_dns::copy_admitted(addrs,|addr|family.admit(addr)))
                }).await.map_err(|error|io::Error::other(format!("proxy DNS lane: {error:?}")))?;
                let values=match output.get(){Ok(values)=>values,Err(error)=>return Err(io::Error::new(error.kind(),error.to_string()))};
                if values.is_empty(){return Err(io::Error::new(io::ErrorKind::AddrNotAvailable,"no addresses admitted"))}
                crate::cert_cpu::MaterialOwner::reserve(&*task,values.len().saturating_mul(std::mem::size_of::<SocketAddr>()*2).saturating_add(2048)).map_err(|error|io::Error::other(error.to_string()))?;
                let values=values.clone().into_iter();Ok(FamilyAddrs{values,_retained:Some(output)})
            })
        }
        let mut inner = self.inner.clone();
        let family = self.family;
        Box::pin(async move {
            let addrs = inner.call(name).await?;
            let mut result = Vec::new();
            for addr in addrs {
                if let Some(admitted) = family.admit(addr) {
                    result.push(admitted);
                }
            }
            if result.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no addresses admitted",
                ));
            }
            Ok(FamilyAddrs{values:result.into_iter(),_retained:None})
        })
    }
}

/// Keep the Unix physical endpoint separate from the HTTP URI authority.
pub(super) fn unix_path(raw:&str)->anyhow::Result<Option<&str>> {
    let Some(path)=raw.strip_prefix("unix/")else{return Ok(None)};
    anyhow::ensure!(!path.is_empty()&&!path.contains(['\r','\n','\0']),"invalid Unix upstream path");
    Ok(Some(path))
}
#[cfg(unix)]
pub(super) async fn connect_unix(path:&str)->io::Result<tokio::net::UnixStream>{
    #[cfg(any(target_os="linux",target_os="android"))]
    if let Some(name)=path.strip_prefix('@'){
        use std::os::unix::ffi::OsStringExt;
        let mut raw=Vec::with_capacity(name.len()+1);raw.push(0);raw.extend_from_slice(name.as_bytes());
        return tokio::net::UnixStream::connect(std::ffi::OsString::from_vec(raw)).await
    }
    tokio::net::UnixStream::connect(path).await
}

/// TLS identifies the IP itself; a local interface zone is never a DNS/SNI name.
pub(super) fn tls_host(raw: &str) -> &str {
    let host = raw.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(raw);
    if let Some((ip, _)) = host.split_once('%') && ip.parse::<std::net::Ipv6Addr>().is_ok() { ip } else { host }
}

/// A local zone is socket-routing information, removed from HTTP Host/authority.
/// Keep the physical connector address scoped independently.
pub(super) fn wire_host(raw: &str) -> std::borrow::Cow<'_, str> {
    let Some(rest) = raw.strip_prefix('[') else { return std::borrow::Cow::Borrowed(raw) };
    let Some(close) = rest.find(']') else { return std::borrow::Cow::Borrowed(raw) };
    let scoped = &rest[..close];
    if let Some((ip, _)) = scoped.split_once('%') && ip.parse::<std::net::Ipv6Addr>().is_ok() {
        std::borrow::Cow::Owned(format!("[{ip}]{}", &rest[close+1..]))
    } else { std::borrow::Cow::Borrowed(raw) }
}

/// A Unix socket path is not an HTTP authority. A configured TLS identity is
/// usable as the logical host; otherwise the connector's logical localhost is.
pub(super) fn unix_tls_host(name: Option<&rustls::pki_types::ServerName<'_>>) -> String {
    let name = name.map(|name| name.to_str().into_owned()).unwrap_or_else(|| "localhost".to_owned());
    match name.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => "localhost".to_owned(),
        Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
        _ => name,
    }
}
