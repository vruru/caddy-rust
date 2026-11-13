//! Numeric TCP endpoints use the existing socket ownership/rollback path.
//! Expand only after validating the complete range and its existing capacity.
use anyhow::{Result,anyhow,ensure};
use std::net::{IpAddr,Ipv6Addr,SocketAddr};

pub(super) fn append(input:&str,out:&mut Vec<SocketAddr>)->Result<()> {
    let (network,address)=input.split_once('/').unwrap_or(("tcp",input));
    ensure!(network.trim().is_empty()||network.trim().eq_ignore_ascii_case("tcp"),
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
    out.try_reserve_exact(span).map_err(|_|anyhow!("HTTP listener allocation failed"))?;
    for port in first..=last {seed.set_port(port);out.push(seed);}
    Ok(())
}
