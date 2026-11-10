// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    address::Address,
    budget::{Budget, add, mul},
    globals::Options,
    site::Site,
};
use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, PartialEq, Eq)]
pub(super) struct SiteRef {
    pub site: usize,
    pub keys: Vec<usize>,
}
pub(super) struct Pairing {
    pub listeners: Vec<(String, Vec<String>)>,
    pub sites: Vec<SiteRef>,
}
pub(super) fn pairings(
    sites: &[Site],
    options: &Options,
    budget: &mut Budget,
) -> Result<Vec<Pairing>> {
    let mut map: BTreeMap<String, BTreeMap<String, Vec<SiteRef>>> = BTreeMap::new();
    for (i, site) in sites.iter().enumerate() {
        let mut local: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
        for (j, key) in site.keys.iter().enumerate() {
            let port = port(key, options)?;
            let owned;
            let binds = if !site.binds.is_empty() {
                &site.binds
            } else if !options.default_bind.is_empty() {
                &options.default_bind
            } else {
                owned = vec![super::builtin_state::Bind {
                    addresses: vec![String::new()],
                    protocols: Vec::new(),
                }];
                &owned
            };
            for bind in binds {
                for address in &bind.addresses {
                    let listener = network_address(address, &port)?;
                    budget.work(listener.len() as u64 + bind.protocols.len() as u64 + 1)?;
                    budget.materialize(listener.len() as u64 + 64)?;
                    let protocols = local.entry(listener).or_default();
                    if bind.protocols.is_empty() {
                        protocols.entry(String::new()).or_default().push(j);
                    } else {
                        for protocol in &bind.protocols {
                            budget.materialize(protocol.len() as u64 + 32)?;
                            protocols.entry(protocol.clone()).or_default().push(j);
                        }
                    }
                }
            }
        }
        for (address, protocols) in local {
            let destination = map.entry(address).or_default();
            for (protocol, keys) in protocols {
                budget.materialize((keys.len() * std::mem::size_of::<usize>() + 64) as u64)?;
                destination
                    .entry(protocol)
                    .or_default()
                    .push(SiteRef { site: i, keys });
            }
        }
    }
    let mut result = Vec::new();
    for address in map.keys() {
        budget.materialize(add(address.len() as u64, 64)?)?;
        budget.work(1)?;
    }
    let addresses = map.keys().cloned().collect::<Vec<_>>();
    for address in addresses {
        for protocol in map[&address].keys() {
            budget.materialize(add(protocol.len() as u64, 64)?)?;
            budget.work(1)?;
        }
        let protocols = map[&address].keys().cloned().collect::<Vec<_>>();
        for protocol in protocols {
            if let Some(sites) = map[&address].get(&protocol) {
                budget.materialize(ref_cost(sites)?)?;
                budget.work(sites.len() as u64)?;
            }
            let sites = map[&address].get(&protocol).cloned();
            let mut listeners = BTreeMap::<String, BTreeSet<String>>::new();
            for (other_address, other_protocols) in &mut map {
                for (p, refs) in other_protocols.iter() {
                    budget.work(add(
                        ref_cost(refs)?,
                        sites
                            .as_ref()
                            .map(|s| ref_cost(s))
                            .transpose()?
                            .unwrap_or(0),
                    )?)?;
                    budget.materialize(add(p.len() as u64, 64)?)?;
                }
                let matches = other_protocols
                    .iter()
                    .filter(|(other_protocol, other_sites)| {
                        address == *other_address && protocol == ***other_protocol
                            || sites.as_ref() == Some(*other_sites)
                    })
                    .map(|(p, _)| p.clone())
                    .collect::<Vec<_>>();
                for p in matches {
                    budget
                        .materialize(add(add(other_address.len() as u64, p.len() as u64)?, 128)?)?;
                    other_protocols.remove(&p);
                    listeners
                        .entry(other_address.clone())
                        .or_default()
                        .insert(p);
                }
            }
            // Preserve the pinned original's snapshot-of-protocols behavior:
            // a protocol consumed by an earlier pairing produces an empty
            // pairing when its still-snapshotted key is visited later.
            budget.work(1)?;
            result.push(Pairing {
                listeners: listeners
                    .into_iter()
                    .map(|(a, p)| (a, p.into_iter().collect()))
                    .collect(),
                sites: sites.unwrap_or_default(),
            });
        }
    }
    Ok(result)
}
fn port(addr: &Address, options: &Options) -> Result<String> {
    match addr.scheme.as_str() {
        "" | "http" | "https" => {}
        "ws" | "wss" => bail!("WebSocket site scheme is browser-only; use HTTP or HTTPS"),
        s => bail!("unsupported URL scheme {s}://"),
    }
    let http = options.integer("http_port", 80).to_string();
    let https = options.integer("https_port", 443).to_string();
    let p = if !addr.port.is_empty() {
        addr.port.clone()
    } else if addr.scheme == "http" {
        http.clone()
    } else {
        https.clone()
    };
    if addr.scheme == "http" && p == https || addr.scheme == "https" && p == http {
        bail!("scheme and port violate convention");
    }
    Ok(p)
}
fn network_address(bind: &str, port: &str) -> Result<String> {
    let (network, address) = if let Some((n, a)) = bind.split_once('/') {
        (super::address::go_lower(n.trim()), a)
    } else {
        (String::new(), bind)
    };
    let network = if network.is_empty() {
        "tcp".to_owned()
    } else {
        network
    };
    if network.starts_with("unix") {
        if let Some((_, mode)) = address.split_once('|') {
            if mode.is_empty() || !mode.bytes().all(|b| matches!(b, b'0'..=b'7')) {
                bail!("invalid Unix socket permission bits");
            }
            let mode = u32::from_str_radix(mode, 8)
                .map_err(|_| anyhow!("invalid Unix socket permission bits"))?;
            if mode & 0o200 == 0 {
                bail!("Unix socket owner requires write permission");
            }
        }
        return Ok(format!("{network}/{address}"));
    }
    if network.starts_with("fd") {
        return Ok(format!("{network}/{address}"));
    }
    let (mut host, _, error) = super::address::split_host_port(address);
    if error.is_some() {
        let raw = address.trim_matches(['[', ']']);
        let joined = if raw.contains(':') {
            format!("[{raw}]:0")
        } else {
            format!("{raw}:0")
        };
        let (h, _, error) = super::address::split_host_port(&joined);
        if error.is_some() {
            bail!("invalid bind network address");
        }
        host = h;
    }
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid listener port");
    }
    let p: u16 = port
        .parse()
        .map_err(|_| anyhow!("listener port out of range"))?;
    let prefix = if network == "tcp" {
        String::new()
    } else {
        format!("{network}/")
    };
    if host.contains(':') {
        Ok(format!("{prefix}[{host}]:{p}"))
    } else {
        Ok(format!("{prefix}{host}:{p}"))
    }
}

fn ref_cost(refs: &[SiteRef]) -> Result<u64> {
    let mut bytes = 0;
    for r in refs {
        bytes = add(
            bytes,
            add(
                64,
                mul(r.keys.len() as u64, std::mem::size_of::<usize>() as u64)?,
            )?,
        )?;
    }
    Ok(bytes)
}

pub(super) fn uses_other_port(listeners: &[(String, Vec<String>)], other: &str) -> bool {
    let Ok(other) = other.parse::<isize>() else {
        return false;
    };
    let other = other as usize;
    listeners.iter().any(|(a, _)| {
        let port = if a
            .split_once('/')
            .is_some_and(|(n, _)| n.starts_with("unix") || n.starts_with("fd"))
        {
            0
        } else {
            a.rsplit_once(':')
                .and_then(|(_, p)| p.parse::<usize>().ok())
                .unwrap_or(0)
        };
        port != other
    })
}
