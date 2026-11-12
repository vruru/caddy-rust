//! Sprig's DNS helper runs only inside the separately bounded template lane.
use super::*;
use std::net::{IpAddr,ToSocketAddrs};
fn address(ip:IpAddr)->String{match ip{IpAddr::V6(ip)=>ip.to_ipv4_mapped().map_or_else(||ip.to_string(),|ip|ip.to_string()),ip=>ip.to_string()}}
pub(super) fn add(m:&mut M){put(m,"getHostByName",|a|{
    arity(a,1,1)?;let name=arg_text(a,0)?;
    if let Ok(ip)=name.parse::<IpAddr>(){return output(address(ip));}
    if let Some((ip,zone))=name.split_once('%'){if !zone.is_empty(){if let Ok(ip)=ip.parse::<std::net::Ipv6Addr>(){return output(format!("{ip}%{zone}"));}}}
    let mut addresses=(name,0).to_socket_addrs().map_err(|_|err("DNS name lookup returned no addresses"))?.map(|address|address.ip()).take(MAX_ITEMS+1).collect::<Vec<_>>();
    addresses.dedup();if addresses.is_empty()||addresses.len()>MAX_ITEMS{return Err(err("DNS address count outside bounds"));}
    let count=addresses.len()as u64;let limit=u64::MAX-u64::MAX%count;
    let selected=loop{let mut bytes=[0u8;8];getrandom::fill(&mut bytes).map_err(|_|err("DNS address selection random source failed"))?;let value=u64::from_le_bytes(bytes);if value<limit{break value%count;}};
    output(address(addresses[selected as usize]))
});}
