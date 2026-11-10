// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::anyhow;
use std::net::Ipv6Addr;

const MAX_LEN: usize = 4096;

#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct Address {
    pub original: String,
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub path: String,
}

impl Address {
    pub(super) fn parse(input: &str) -> anyhow::Result<Self> {
        let truncated = truncate_utf8(input);
        let s = truncated.as_str();
        let remaining = s.trim();
        let mut a = Address {
            original: remaining.to_string(),
            ..Default::default()
        };

        let mut rem = remaining;

        let parts: Vec<&str> = rem.splitn(2, "://").collect();
        match parts.len() {
            0 => return Ok(a),
            1 => {
                rem = parts[0];
            }
            2 => {
                a.scheme = parts[0].to_string();
                rem = parts[1];
            }
            _ => {}
        }

        let host_split: Vec<&str> = rem.splitn(2, '/').collect();

        if !host_split.is_empty() {
            let (mut host, mut port, err) = split_host_port(host_split[0]);
            if err.is_some() {
                let retry_str = format!("{}:", host_split[0]);
                let (h2, p2, e2) = split_host_port(&retry_str);
                if e2.is_some() {
                    host = host_split[0].to_string();
                    port = "".to_string();
                } else {
                    host = h2;
                    port = p2;
                }
            }
            a.host = host;
            a.port = port;
        }

        if host_split.len() == 2 {
            a.path = format!("/{}", host_split[1]);
        }

        if !a.port.is_empty() {
            match a.port.parse::<i64>() {
                Ok(port_num) => {
                    if !(0..=65535).contains(&port_num) {
                        return Err(anyhow!("port {} is out of range", port_num));
                    }
                }
                Err(_) => {
                    return Err(anyhow!("invalid port '{}'", a.port));
                }
            }
        }

        Ok(a)
    }

    pub(super) fn normalized(&self) -> Self {
        let path = self.path.clone();

        let mut host = self.host.trim().to_string();

        let mut zone_suffix = String::new();
        let mut host_part = host.as_str();

        if let Some(pos) = host.find('%') {
            host_part = &host[..pos];
            zone_suffix = host[pos..].to_owned();
        }

        if (zone_suffix.is_empty() || zone_suffix.len() > 1)
            && let Ok(ip) = host_part.parse::<Ipv6Addr>()
        {
            let is_4in6 = ip.to_ipv4_mapped().is_some();

            if !is_4in6 {
                host = ip.to_string();
                if !zone_suffix.is_empty() {
                    host.push_str(&zone_suffix);
                }
            }
        }

        let lower_host = lower_except_placeholders(&host);
        let lower_scheme = lower_except_placeholders(&self.scheme);

        Address {
            original: self.original.clone(),
            scheme: lower_scheme,
            host: lower_host,
            port: self.port.clone(),
            path,
        }
    }
}

pub(super) fn split_host_port(hostport: &str) -> (String, String, Option<String>) {
    // Follows Go net.SplitHostPort (Go Authors, BSD-style license), including
    // the unbracketed ']' check over the entire address, not just the port.
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";

    let i = match hostport.rfind(':') {
        Some(idx) => idx,
        None => {
            return (
                "".to_string(),
                "".to_string(),
                Some(format!("{}: {}", hostport, MISSING_PORT)),
            );
        }
    };

    let host;
    let j;
    let k;

    if hostport.starts_with('[') {
        let end = match hostport.find(']') {
            Some(idx) => idx,
            None => {
                return (
                    "".to_string(),
                    "".to_string(),
                    Some(format!("{}: missing ']' in address", hostport)),
                );
            }
        };

        if end + 1 == hostport.len() {
            return (
                "".to_string(),
                "".to_string(),
                Some(format!("{}: {}", hostport, MISSING_PORT)),
            );
        }

        if end + 1 != i {
            if hostport.as_bytes().get(end + 1) == Some(&b':') {
                return (
                    "".to_string(),
                    "".to_string(),
                    Some(format!("{}: {}", hostport, TOO_MANY_COLONS)),
                );
            }
            return (
                "".to_string(),
                "".to_string(),
                Some(format!("{}: {}", hostport, MISSING_PORT)),
            );
        }

        host = hostport[1..end].to_string();
        j = 1;
        k = end + 1;
    } else {
        host = hostport[..i].to_string();
        if host.contains(':') {
            return (
                "".to_string(),
                "".to_string(),
                Some(format!("{}: {}", hostport, TOO_MANY_COLONS)),
            );
        }
        j = 0;
        k = 0;
    }

    let rest_j = &hostport[j..];
    if rest_j.contains('[') {
        return (
            "".to_string(),
            "".to_string(),
            Some(format!("{}: unexpected '[' in address", hostport)),
        );
    }

    let rest_k = &hostport[k..];
    if rest_k.contains(']') {
        return (
            "".to_string(),
            "".to_string(),
            Some(format!("{}: unexpected ']' in address", hostport)),
        );
    }

    let port = hostport[i + 1..].to_string();

    (host, port, None)
}

fn lower_except_placeholders(s: &str) -> String {
    let mut sb = String::with_capacity(s.len());
    let mut escaped = false;
    let mut in_placeholder = false;

    for ch in s.chars() {
        if ch == '\\' && !escaped {
            escaped = true;
            sb.push(ch);
            continue;
        }

        if ch == '{' && !escaped {
            in_placeholder = true;
        }
        if ch == '}' && in_placeholder && !escaped {
            in_placeholder = false;
        }

        if in_placeholder {
            sb.push(ch);
        } else {
            let lower = ch.to_lowercase().next().unwrap_or(ch);
            sb.push(lower);
        }

        escaped = false;
    }

    sb
}

fn truncate_utf8(input: &str) -> String {
    let bytes = &input.as_bytes()[..input.len().min(MAX_LEN)];
    match std::str::from_utf8(bytes) {
        Ok(valid) => valid.to_owned(),
        Err(error) => {
            let mut result = input[..error.valid_up_to()].to_owned();
            for _ in error.valid_up_to()..bytes.len() {
                result.push(char::REPLACEMENT_CHARACTER);
            }
            result
        }
    }
}

/// Go Unicode simple lowercase: one rune maps to one rune (no full-case expansion).
pub(super) fn go_lower(input: &str) -> String {
    input
        .chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}
