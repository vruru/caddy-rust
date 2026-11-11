// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
//! Caddy NetworkAddress parsing for a single network writer endpoint. Network
//! syntax is not URL syntax. Dial behavior is resolved by the writer backend.
use anyhow::{Result, anyhow, ensure};
pub(super) struct Address {
    pub network: String,
    pub host: String,
    pub port: u16,
}
impl Address {
    pub(super) fn parse(input: &str) -> Result<Self> {
        ensure!(
            input.len() <= 1 << 20,
            "log network address byte limit exceeded"
        );
        let (network, address) = if let Some((n, a)) = input.split_once('/') {
            let network = super::config::simple_lower(n.trim());
            (
                if network.is_empty() {
                    "tcp".into()
                } else {
                    network
                },
                a,
            )
        } else {
            ("tcp".into(), input)
        };
        if network.starts_with("unix") {
            if let Some((_, mode)) = address.split_once('|') {
                ensure!(
                    !mode.is_empty() && mode.bytes().all(|b| matches!(b, b'0'..=b'7')),
                    "invalid log unix socket permissions"
                );
                let bits = u32::from_str_radix(mode, 8)
                    .map_err(|_| anyhow!("log unix socket permissions overflow"))?;
                ensure!(
                    bits & 0o200 != 0,
                    "log unix socket owner write permission required"
                );
            }
            return Ok(Self {
                network,
                host: address.into(),
                port: 0,
            });
        }
        if network.starts_with("fd") {
            return Ok(Self {
                network,
                host: address.into(),
                port: 0,
            });
        }
        // Go first tries SplitHostPort. On any split error it joins the entire
        // bracket-trimmed input to a dummy port, then discards that dummy port.
        let (host, port) =
            split_host_port(address).unwrap_or_else(|| (address.trim_matches(['[', ']']), ""));
        let port = if port.is_empty() {
            0
        } else {
            let (first, last) = port.split_once('-').unwrap_or((port, port));
            let parse = |s: &str| -> Result<u16> {
                ensure!(
                    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                    "invalid log network port"
                );
                s.parse().map_err(|_| anyhow!("log network port overflow"))
            };
            let first = parse(first)?;
            let last = parse(last)?;
            ensure!(last >= first, "log network port range reversed");
            ensure!(first == last, "multiple log network ports unsupported");
            first
        };
        Ok(Self {
            network,
            host: host.into(),
            port,
        })
    }
    pub(super) fn key(&self) -> String {
        if self.network.starts_with("unix") || self.network.starts_with("fd") {
            return format!("{}/{}", self.network, self.host);
        }
        let address = self.join_host_port();
        if self.network == "tcp" {
            address
        } else {
            format!("{}/{address}", self.network)
        }
    }
    pub(super) fn join_host_port(&self) -> String {
        if self.network.starts_with("unix") || self.network.starts_with("fd") {
            return self.host.clone();
        }
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}
pub(super) fn split_host_port(input: &str) -> Option<(&str, &str)> {
    let colon = input.rfind(':')?;
    let (host, port) = if input.starts_with('[') {
        let end = input.find(']')?;
        if end + 1 != colon {
            return None;
        }
        (&input[1..end], &input[colon + 1..])
    } else {
        let host = &input[..colon];
        if host.contains(':') {
            return None;
        }
        (host, &input[colon + 1..])
    };
    if host.contains(['[', ']']) || port.contains(['[', ']']) {
        return None;
    }
    Some((host, port))
}
