//! Numeric TCP endpoints use the existing socket ownership/rollback path.
//! Expand only after validating the complete range and its existing capacity.
use anyhow::{Result,anyhow,ensure};
use std::{collections::HashSet,net::{IpAddr,Ipv4Addr,Ipv6Addr,SocketAddr},sync::Arc};

pub(super) fn append(input:&str,out:&mut Vec<SocketAddr>,v6_only:&mut HashSet<SocketAddr>)->Result<()> {
    let (network,address)=input.split_once('/').unwrap_or(("tcp",input));
    let network=network.trim();
    let ipv4=network.eq_ignore_ascii_case("tcp4");
    let ipv6=network.eq_ignore_ascii_case("tcp6");
    ensure!(network.is_empty()||network.eq_ignore_ascii_case("tcp")||ipv4||ipv6,
        "unsupported HTTP listener network");
    let bare=address.trim_matches(['[',']']);
    let (mut seed,port)=if bare.is_empty() {
        (SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED),0),"")
    } else if let Ok(ip)=bare.parse::<IpAddr>() {
        (SocketAddr::new(ip,0),"")
    } else {
        let (host,port)=address.rsplit_once(':')
            .ok_or_else(||anyhow!("unsupported HTTP listener hostname or address"))?;
        let host=if host.is_empty(){"[::]"}else{host};
        let seed=format!("{host}:0").parse::<SocketAddr>()
            .map_err(|_|anyhow!("unsupported HTTP listener hostname or address"))?;
        (seed,port)
    };
    if ipv4 {
        if let IpAddr::V6(ip)=seed.ip() {
            let mapped=if ip.is_unspecified(){Some(Ipv4Addr::UNSPECIFIED)}else{ip.to_ipv4_mapped()};
            seed=SocketAddr::new(IpAddr::V4(mapped.ok_or_else(||anyhow!("tcp4 requires an IPv4 address"))?),0);
        }
    } else if ipv6 {
        ensure!(matches!(seed.ip(),IpAddr::V6(ip)if ip.to_ipv4_mapped().is_none()),
            "tcp6 requires an IPv6 address");
    }
    let parse=|s:&str|->Result<u16>{
        ensure!(!s.is_empty()&&s.bytes().all(|b|b.is_ascii_digit()),"invalid HTTP listener port");
        s.parse().map_err(|_|anyhow!("HTTP listener port exceeds 65535"))
    };
    let (first,last)=if port.is_empty(){(0,0)}else{
        let (a,b)=port.split_once('-').unwrap_or((port,port));(parse(a)?,parse(b)?)
    };
    ensure!(last>=first,"HTTP listener port range reversed");
    let span=usize::from(last)-usize::from(first)+1;
    ensure!(out.len().checked_add(span).is_some_and(|n|n<=1024),"HTTP listener capacity exceeded");
    // Preserve scope IDs and original duplicate/ephemeral semantics. Check the
    // whole range before publishing any address or its kernel binding mode.
    for port in first..=last {
        seed.set_port(port);
        ensure!(!out.contains(&seed)||v6_only.contains(&seed)==ipv6,
            "HTTP listener address has conflicting IPv6-only modes");
    }
    out.try_reserve_exact(span).map_err(|_|anyhow!("HTTP listener allocation failed"))?;
    if ipv6 {v6_only.try_reserve(span).map_err(|_|anyhow!("HTTP listener allocation failed"))?;}
    for port in first..=last {seed.set_port(port);out.push(seed);if ipv6 {v6_only.insert(seed);}}
    Ok(())
}


/// Builtin networks are concrete socket kinds, never fabricated IP endpoints.
#[derive(Clone,Copy,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub(crate) enum Network { Tcp,Udp,Unix,UnixPacket,Fd,Fdgram }
impl Network {
 pub(crate) fn stream(self)->bool{matches!(self,Self::Tcp|Self::Unix|Self::UnixPacket|Self::Fd)}
 pub(crate) fn unix(self)->bool{matches!(self,Self::Unix|Self::UnixPacket)}
}
#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub(crate) enum Address {
 Inet(SocketAddr),
 Unix{path:Arc<[u8]>,packet:bool},
 Fd{number:u32,datagram:bool},
}
impl From<SocketAddr> for Address {fn from(v:SocketAddr)->Self{Self::Inet(v)}}
impl Address {
 pub(crate) fn socket(&self)->Option<SocketAddr>{match self{Self::Inet(a)=>Some(*a),_=>None}}
 pub(crate) fn port(&self)->u16{self.socket().map_or(0,|a|a.port())}
 pub(crate) fn is_ipv4(&self)->bool{self.socket().is_some_and(|a|a.is_ipv4())}
 pub(crate) fn is_ipv6(&self)->bool{self.socket().is_some_and(|a|a.is_ipv6())}
 pub(crate) fn ip(&self)->Option<IpAddr>{self.socket().map(|a|a.ip())}
}
impl std::fmt::Display for Address {
 fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{match self{
  Self::Inet(a)=>a.fmt(f),Self::Unix{path,packet}=>write!(f,"{}/{}",if *packet{"unixpacket"}else{"unix"},String::from_utf8_lossy(path)),Self::Fd{number,datagram}=>write!(f,"{}/{number}",if *datagram{"fdgram"}else{"fd"}),
 }}
}
/// A pure declaration. Only stage may turn a hostname into a kernel endpoint.
#[derive(Clone,Copy,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub(crate) enum Family { Any, V4, V6 }
#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub(crate) struct ListenIdentity {pub(crate) host:Arc<str>,pub(crate) family:Family,pub(crate) port:u16,pub(crate) network:Network}
#[derive(Clone,Debug,Eq,PartialEq,Hash)]
pub(crate) enum ListenSpec {
    Numeric { address:SocketAddr, only_v6:bool, identity:Arc<ListenIdentity> },
    Unix {path:Arc<str>,packet:bool,mode:u32,identity:Arc<ListenIdentity>},
    Fd {number:u32,datagram:bool,identity:Arc<ListenIdentity>},
    Hostname { host:Arc<str>, port:u16, family:Family, identity:Arc<ListenIdentity> },
}
impl ListenSpec {
    pub(crate) fn identity(&self)->&Arc<ListenIdentity>{match self{Self::Numeric{identity,..}|Self::Hostname{identity,..}|Self::Unix{identity,..}|Self::Fd{identity,..}=>identity}}

    pub(crate) fn port(&self)->u16 {match self {Self::Numeric{address,..}=>address.port(),Self::Hostname{port,..}=>*port,Self::Unix{..}|Self::Fd{..}=>0}}
    pub(crate) fn numeric(&self)->Option<(SocketAddr,bool)> {match self {Self::Numeric{address,only_v6,..}=>Some((*address,*only_v6)),_=>None}}
}
/// Go first tries SplitHostPort; after a missing/invalid split it treats the
/// complete bracket-trimmed input as a host and supplies the default port zero.
fn declared_host_port(address:&str)->(&str,&str) {
    if let Some(rest)=address.strip_prefix('[') {
        if let Some(end)=rest.find(']') {
            if let Some(port)=rest[end+1..].strip_prefix(':') {return (&rest[..end],port);}
        }
    } else if address.bytes().filter(|b|*b==b':').count()==1 {
        if let Some((host,port))=address.rsplit_once(':') {return (host,port);}
    }
    (address.trim_matches(['[',']']),"")
}
pub(super) fn append_specs(input:&str,out:&mut Vec<ListenSpec>)->Result<()> {
    let (network,address)=input.split_once('/').unwrap_or(("tcp",input));
    let network=network.trim();
    let kind=match network {"unix"=>Some(Network::Unix),"unixpacket"=>Some(Network::UnixPacket),"fd"=>Some(Network::Fd),"fdgram"=>Some(Network::Fdgram),_=>None};
    if let Some(kind)=kind {
        ensure!(out.len()<1024,"HTTP listener capacity exceeded");
        if kind.unix(){
            let(path,mode)=if let Some((path,mode))=address.split_once('|'){
                ensure!(!mode.is_empty()&&mode.bytes().all(|v|matches!(v,b'0'..=b'7')),"invalid Unix socket mode");
                let mode=u32::from_str_radix(mode,8).map_err(|_|anyhow!("Unix socket mode out of range"))?;
                ensure!(mode&0o200!=0,"Unix socket owner requires write permission");(path,mode)
            }else{(address,0o200)};
            ensure!(!path.is_empty()&&path.len()<=4096&&!path.as_bytes().contains(&0),"invalid Unix HTTP listener path");
            let path:Arc<str>=Arc::from(path);let identity=Arc::new(ListenIdentity{host:path.clone(),family:Family::Any,port:0,network:kind});
            out.push(ListenSpec::Unix{path,packet:kind==Network::UnixPacket,mode,identity});
        }else{
            let digits=address.strip_prefix("0x").map(|v|(v,16)).or_else(||address.strip_prefix("0X").map(|v|(v,16))).or_else(||address.strip_prefix("0o").map(|v|(v,8))).or_else(||address.strip_prefix("0b").map(|v|(v,2))).or_else(||address.strip_prefix('0').filter(|v|!v.is_empty()).map(|v|(v,8))).unwrap_or((address,10));
            let number=u32::from_str_radix(digits.0,digits.1).map_err(|_|anyhow!("invalid listener file descriptor"))?;
            ensure!(number<=i32::MAX as u32,"listener file descriptor out of range");
            let identity=Arc::new(ListenIdentity{host:Arc::from(number.to_string()),family:Family::Any,port:0,network:kind});
            out.push(ListenSpec::Fd{number,datagram:kind==Network::Fdgram,identity});
        }
        return Ok(());
    }
    let datagram=matches!(network,"udp"|"udp4"|"udp6");
    let network=if datagram{match network{"udp4"=>"tcp4","udp6"=>"tcp6",_=>"tcp"}}else{network};
    let normalized;if datagram{normalized=format!("{network}/{address}");}else{normalized=input.to_owned();}
    let family=if network.eq_ignore_ascii_case("tcp4") {Family::V4}
        else if network.eq_ignore_ascii_case("tcp6") {Family::V6}
        else if network.is_empty()||network.eq_ignore_ascii_case("tcp") {Family::Any}
        else {return Err(anyhow!("unsupported HTTP listener network"));};
    let mut numeric=Vec::new();let mut modes=HashSet::new();
    match append(&normalized,&mut numeric,&mut modes) {
        Ok(())=>{
            ensure!(out.len().checked_add(numeric.len()).is_some_and(|n|n<=1024),"HTTP listener capacity exceeded");
            out.try_reserve_exact(numeric.len()).map_err(|_|anyhow!("HTTP listener declaration allocation failed"))?;
            let (host,_)=declared_host_port(address);let host:Arc<str>=Arc::from(host);
            for address in numeric {let identity=Arc::new(ListenIdentity{host:host.clone(),family,port:address.port(),network:if datagram{Network::Udp}else{Network::Tcp}});out.push(ListenSpec::Numeric{address,only_v6:modes.contains(&address),identity});}
            return Ok(());
        }
        Err(original)=>{
            let (host,port)=declared_host_port(address);
            // A numeric-family error must not be disguised as a DNS lookup.
            ensure!(host.len()<=2048&&!host.bytes().any(|b|matches!(b,0|b'\r'|b'\n')),"invalid HTTP listener hostname");
            if host.is_empty()||host.parse::<IpAddr>().is_ok()
                ||format!("[{host}]:0").parse::<SocketAddr>().is_ok() {return Err(original);}
            let parse=|raw:&str|->Result<u16>{ensure!(!raw.is_empty()&&raw.bytes().all(|b|b.is_ascii_digit()),"invalid HTTP listener port");raw.parse().map_err(|_|anyhow!("HTTP listener port exceeds65535"))};
            let (first,last)=if port.is_empty(){(0,0)}else{let(a,b)=port.split_once('-').unwrap_or((port,port));(parse(a)?,parse(b)?)};
            ensure!(last>=first,"HTTP listener port range reversed");let count=usize::from(last)-usize::from(first)+1;
            ensure!(out.len().checked_add(count).is_some_and(|n|n<=1024),"HTTP listener capacity exceeded");
            // One original hostname allocation is shared by all range entries.
            // No resolver, environment rewrite or certificate-name rule runs here.
            out.try_reserve_exact(count).map_err(|_|anyhow!("HTTP listener declaration allocation failed"))?;
            let host:Arc<str>=Arc::from(host);
            for port in first..=last {out.push(ListenSpec::Hostname{host:host.clone(),port,family,identity:Arc::new(ListenIdentity{host:host.clone(),family,port,network:if datagram{Network::Udp}else{Network::Tcp}})});}
            Ok(())
        }
    }
}
