//! Numeric TCP endpoints use the existing socket ownership/rollback path.
//! Expand only after validating the complete range and its existing capacity.
use anyhow::{Result,anyhow,ensure};
use std::{collections::HashSet,net::{IpAddr,Ipv4Addr,Ipv6Addr,SocketAddr}};

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
