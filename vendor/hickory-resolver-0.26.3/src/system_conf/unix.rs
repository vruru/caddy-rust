// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading
//!
//! This module is responsible for parsing and returning the configuration from
//!  the host system. It will read from the default location on each operating
//!  system, e.g. most Unixes have this written to `/etc/resolv.conf`

use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use tracing::warn;

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use crate::net::NetError;
use crate::proto::rr::Name;

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), NetError> {
    read_resolv_conf("/etc/resolv.conf")
}

fn read_resolv_conf<P: AsRef<Path>>(path: P) -> Result<(ResolverConfig, ResolverOpts), NetError> {
    parse_resolv_conf(fs::read(path)?)
}

pub fn parse_resolv_conf(
    data: impl AsRef<[u8]>,
) -> Result<(ResolverConfig, ResolverOpts), NetError> {
    let (parsed_conf, errors) = resolv_conf::Config::parse_with_errors(data.as_ref());
    for error in errors {
        warn!(%error, "error parsing resolv.conf");
    }
    into_resolver_config(parsed_conf)
}

// TODO: use a custom parsing error type maybe?
fn into_resolver_config(
    parsed_config: resolv_conf::Config,
) -> Result<(ResolverConfig, ResolverOpts), NetError> {
    let domain = if let Some(domain) = parsed_config.get_system_domain() {
        // The system domain name maybe appear to be valid to the resolv_conf
        // crate but actually be invalid. For example, if the hostname is "matt.schulte's computer"
        // In order to prevent a hostname which macOS or Windows would consider
        // valid from returning an error here we turn parse errors to options
        Name::from_str(domain.as_str()).ok()
    } else {
        None
    };

    // nameservers
    let nameservers = parsed_config
        .nameservers
        .iter()
        .map(|ip| NameServerConfig::udp_and_tcp(ip.into()))
        .collect::<Vec<_>>();
    if nameservers.is_empty() {
        Err(io::Error::other("no nameservers found in config"))?;
    }

    // search
    let mut search = vec![];
    for search_domain in parsed_config.get_last_search_or_domain() {
        // Ignore invalid search domains
        if search_domain == "--" {
            continue;
        }

        search.push(
            Name::from_str_relaxed(search_domain)
                .map_err(|e| io::Error::other(format!("Error parsing resolv.conf: {e}")))?,
        );
    }

    let config = ResolverConfig::from_parts(domain, search, nameservers);

    let options = ResolverOpts {
        ndots: parsed_config.ndots as usize,
        timeout: Duration::from_secs(u64::from(parsed_config.timeout)),
        attempts: parsed_config.attempts as usize,
        edns0: parsed_config.edns0,
        ..ResolverOpts::default()
    };

    Ok((config, options))
}
