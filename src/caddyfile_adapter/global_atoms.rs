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

use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::dispenser::Dispenser;
use crate::duration::parse_str;
use anyhow::Result;

/// Values are interpreted by option name: Bool(true) for ocsp_stapling
/// means DisableStapling, while Bool(false) for storage_clean_interval is off.
#[derive(Clone)]
pub(super) enum Atom {
    Bool(bool),
    Integer(isize),
    Duration(i64),
    String(String),
    Strings(Vec<String>),
    Float(f64),
}

pub(super) fn parse(name: &str, tokens: &[Token], previous: Option<&Atom>) -> Result<Option<Atom>> {
    let mut d = Dispenser::new(tokens.to_vec());

    if !d.next() {
        return Err(d.arg_err());
    }

    match name {
        "debug" | "skip_install_trust" | "local_certs" | "persist_config" => {
            if name == "persist_config" {
                return parse_opt_persist_config(d).map(Some);
            }

            Ok(Some(Atom::Bool(true)))
        }

        "http_port" | "https_port" => parse_opt_port(d, name).map(Some),

        "grace_period" | "shutdown_delay" | "renew_interval" | "ocsp_interval"
        | "cert_lifetime" => parse_opt_duration(d).map(Some),

        "default_sni" | "fallback_sni" | "acme_ca" | "acme_ca_root" | "email" | "key_type" => {
            parse_opt_single_string(d).map(Some)
        }

        "storage_check" => parse_storage_check(d).map(Some),

        "storage_clean_interval" => parse_storage_clean_interval(d).map(Some),

        "auto_https" => parse_opt_auto_https(d).map(Some),

        "ocsp_stapling" => parse_ocsp_stapling(d).map(Some),

        "tls_resolvers" => parse_opt_tls_resolvers(d).map(Some),

        "tls_automate_names" => parse_opt_automate_names(d, previous).map(Some),

        "renewal_window_ratio" => parse_opt_renewal_window_ratio(d).map(Some),

        _ => Ok(None),
    }
}

fn parse_opt_persist_config(mut d: Dispenser) -> Result<Atom> {
    if !d.next() {
        return Err(d.arg_err());
    }
    let val = d.val().to_string();

    if d.next() {
        return Err(d.arg_err());
    }

    if val != "off" {
        return Err(d.error("persist_config must be 'off'"));
    }

    Ok(Atom::String(val))
}

fn parse_opt_port(mut d: Dispenser, name: &str) -> Result<Atom> {
    if let Some(args) = d.all_args(1) {
        let port_str = &args[0];
        match port_str.parse::<isize>() {
            Ok(port) => Ok(Atom::Integer(port)),
            Err(_) => Err(d.error(format!(
                "converting port '{}' to integer value for {}: invalid number",
                port_str, name
            ))),
        }
    } else {
        Err(d.arg_err())
    }
}

fn parse_opt_duration(mut d: Dispenser) -> Result<Atom> {
    if !d.next() {
        return Err(d.arg_err());
    }
    let val = d.val().to_string();

    match parse_str(&val) {
        Ok(dur) => Ok(Atom::Duration(dur)),
        Err(e) => Err(d.error(format!("failed to parse duration: {}", e))),
    }
}

fn parse_opt_single_string(mut d: Dispenser) -> Result<Atom> {
    if !d.next() {
        return Err(d.arg_err());
    }
    let val = d.val().to_string();

    if d.next() {
        return Err(d.arg_err());
    }

    Ok(Atom::String(val))
}

fn parse_storage_check(mut d: Dispenser) -> Result<Atom> {
    if !d.next() {
        return Err(d.arg_err());
    }
    let val = d.val().to_string();

    if d.next() {
        return Err(d.arg_err());
    }

    if val != "off" {
        return Err(d.error("storage_check must be 'off'"));
    }

    Ok(Atom::String(val))
}

fn parse_storage_clean_interval(mut d: Dispenser) -> Result<Atom> {
    if !d.next() {
        return Err(d.arg_err());
    }
    let val = d.val().to_string();

    if d.next() {
        return Err(d.arg_err());
    }

    if val == "off" {
        return Ok(Atom::Bool(false));
    }

    match parse_str(&val) {
        Ok(dur) => Ok(Atom::Duration(dur)),
        Err(e) => Err(d.error(format!(
            "failed to parse storage_clean_interval, must be a duration or 'off': {}",
            e
        ))),
    }
}

fn parse_opt_auto_https(mut d: Dispenser) -> Result<Atom> {
    let val = d.remaining_args();

    if val.is_empty() {
        return Err(d.arg_err());
    }

    for v in &val {
        match v.as_str() {
            "off" | "disable_redirects" | "disable_certs" | "ignore_loaded_certs" => {}
            _ => {
                return Err(d.error(
                    "auto_https must be one of 'off', 'disable_redirects', 'disable_certs', or 'ignore_loaded_certs'"
                ));
            }
        }
    }

    Ok(Atom::Strings(val))
}

fn parse_ocsp_stapling(mut d: Dispenser) -> Result<Atom> {
    if let Some(args) = d.all_args(1) {
        let val = &args[0];
        if val != "off" {
            return Err(d.error(format!("invalid argument '{}'", val)));
        }
        Ok(Atom::Bool(true))
    } else {
        Err(d.arg_err())
    }
}

fn parse_opt_tls_resolvers(mut d: Dispenser) -> Result<Atom> {
    let resolvers = d.remaining_args();
    if resolvers.is_empty() {
        return Err(d.arg_err());
    }
    Ok(Atom::Strings(resolvers))
}

fn parse_opt_automate_names(mut d: Dispenser, previous: Option<&Atom>) -> Result<Atom> {
    let mut names = d.remaining_args();
    if names.is_empty() {
        return Err(d.arg_err());
    }

    if let Some(prev_atom) = previous
        && let Atom::Strings(prev_names) = prev_atom
    {
        names = [prev_names.as_slice(), names.as_slice()].concat();
    }

    Ok(Atom::Strings(names))
}

fn parse_opt_renewal_window_ratio(mut d: Dispenser) -> Result<Atom> {
    if !d.next() {
        return Err(d.arg_err());
    }
    let ratio = crate::caddyfile_parser::scalar::parse_float(d.val())
        .ok_or_else(|| d.error("parsing renewal_window_ratio: invalid float"))?;
    // Match ParseFloat/range/extra-token ordering, including Go's NaN parse
    // result. The TLS assembly boundary must handle non-finite JSON explicitly.
    if ratio <= 0.0 || ratio >= 1.0 {
        return Err(d.error("renewal_window_ratio must be between 0 and 1 (exclusive)"));
    }
    if d.next() {
        return Err(d.arg_err());
    }
    Ok(Atom::Float(ratio))
}
