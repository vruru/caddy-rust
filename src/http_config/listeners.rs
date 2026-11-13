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


/// A pure declaration. Only stage may turn a hostname into a kernel endpoint.
#[derive(Clone,Copy,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub(crate) enum Family { Any, V4, V6 }
#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub(crate) struct ListenIdentity {pub(crate) host:Arc<str>,pub(crate) family:Family,pub(crate) port:u16}
#[derive(Clone,Debug,Eq,PartialEq,Hash)]
pub(crate) enum ListenSpec {
    Numeric { address:SocketAddr, only_v6:bool, identity:Arc<ListenIdentity> },
    Hostname { host:Arc<str>, port:u16, family:Family, identity:Arc<ListenIdentity> },
}
impl ListenSpec {
    pub(crate) fn identity(&self)->&Arc<ListenIdentity>{match self{Self::Numeric{identity,..}|Self::Hostname{identity,..}=>identity}}

    pub(crate) fn port(&self)->u16 {match self {Self::Numeric{address,..}=>address.port(),Self::Hostname{port,..}=>*port}}
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
    let family=if network.eq_ignore_ascii_case("tcp4") {Family::V4}
        else if network.eq_ignore_ascii_case("tcp6") {Family::V6}
        else if network.is_empty()||network.eq_ignore_ascii_case("tcp") {Family::Any}
        else {return Err(anyhow!("unsupported HTTP listener network"));};
    let mut numeric=Vec::new();let mut modes=HashSet::new();
    match append(input,&mut numeric,&mut modes) {
        Ok(())=>{
            ensure!(out.len().checked_add(numeric.len()).is_some_and(|n|n<=1024),"HTTP listener capacity exceeded");
            out.try_reserve_exact(numeric.len()).map_err(|_|anyhow!("HTTP listener declaration allocation failed"))?;
            let (host,_)=declared_host_port(address);let host:Arc<str>=Arc::from(host);
            for address in numeric {let identity=Arc::new(ListenIdentity{host:host.clone(),family,port:address.port()});out.push(ListenSpec::Numeric{address,only_v6:modes.contains(&address),identity});}
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
            for port in first..=last {out.push(ListenSpec::Hostname{host:host.clone(),port,family,identity:Arc::new(ListenIdentity{host:host.clone(),family,port})});}
            Ok(())
        }
    }
}
