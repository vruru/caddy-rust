// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::tls_policy::IssuerDef;
use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::Dispenser;
use anyhow::{Result, bail};
use serde_json::{Map, Value};

pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<IssuerDef> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next(); // consume issuer name (first token, no outer issuer token)
    match name {
        "internal" => parse_internal(&mut d),
        "acme" => parse_acme(&mut d),
        "zerossl" => parse_zerossl(&mut d),
        _ => bail!("unknown issuer module '{name}'"),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub(super) fn set_str(map: &mut Map<String, Value>, key: &str, value: &str) {
    if value.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.to_owned(), Value::String(value.to_owned()));
    }
}

fn set_str_retain(map: &mut Map<String, Value>, key: &str, value: &str) {
    map.insert(key.to_owned(), Value::String(value.to_owned()));
}

pub(super) fn set_i64(map: &mut Map<String, Value>, key: &str, value: i64) {
    if value == 0 {
        map.remove(key);
    } else {
        map.insert(key.to_owned(), Value::Number(value.into()));
    }
}

fn set_bool(map: &mut Map<String, Value>, key: &str, value: bool) {
    if !value {
        map.remove(key);
    } else {
        map.insert(key.to_owned(), Value::Bool(true));
    }
}

fn set_retain_bool(map: &mut Map<String, Value>, key: &str, value: bool) {
    map.insert(key.to_owned(), Value::Bool(value));
}

pub(super) fn section_mut<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>> {
    map.entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("tls issuer: {key} must be an object"))
}

fn set_string_array(map: &mut Map<String, Value>, key: &str, values: &[String]) {
    if values.is_empty() {
        map.remove(key);
    } else {
        map.insert(
            key.to_owned(),
            Value::Array(values.iter().map(|s| Value::String(s.clone())).collect()),
        );
    }
}

fn set_string_array_retain(map: &mut Map<String, Value>, key: &str, values: &[String]) {
    map.insert(
        key.to_owned(),
        Value::Array(values.iter().map(|s| Value::String(s.clone())).collect()),
    );
}

// ---------------------------------------------------------------------------
// internal
// ---------------------------------------------------------------------------

fn parse_internal(d: &mut Dispenser) -> Result<IssuerDef> {
    let mut config = Map::new();
    while d.next_block(0) {
        match d.val() {
            "ca" => {
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                set_str(&mut config, "ca", &args[0]);
            }
            "lifetime" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let dur = crate::duration::parse_str(d.val())?;
                set_i64(&mut config, "lifetime", dur);
            }
            "sign_with_root" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                set_bool(&mut config, "sign_with_root", true);
            }
            name => bail!("unrecognized subdirective '{name}'"),
        }
    }
    Ok(IssuerDef::Internal(config))
}

// ---------------------------------------------------------------------------
// acme
// ---------------------------------------------------------------------------

fn parse_acme(d: &mut Dispenser) -> Result<IssuerDef> {
    let mut config = Map::new();
    // inline CA
    if d.next_arg() {
        let ca = d.val().to_owned();
        if d.next_arg() {
            return Err(d.arg_err());
        }
        set_str(&mut config, "ca", &ca);
    }
    while d.next_block(0) {
        match d.val() {
            "lifetime" => {
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                let dur = crate::duration::parse_str(&args[0])
                    .map_err(|e| d.error(format!("invalid lifetime {}: {e}", args[0])))?;
                if dur < 0 {
                    return Err(d.error(format!("lifetime must be >= 0: {dur}")));
                }
                set_i64(&mut config, "certificate_lifetime", dur);
            }
            "dir" => {
                if let Some(Value::String(s)) = config.get("ca")
                    && !s.is_empty()
                {
                    return Err(d.error(format!("directory is already specified: {s}")));
                }
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                set_str(&mut config, "ca", &args[0]);
            }
            "test_dir" => {
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                set_str(&mut config, "test_ca", &args[0]);
            }
            "email" => {
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                set_str(&mut config, "email", &args[0]);
            }
            "profile" => {
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                set_str(&mut config, "profile", &args[0]);
            }
            "timeout" => {
                let args = d.all_args(1).ok_or_else(|| d.arg_err())?;
                let dur = crate::duration::parse_str(&args[0])
                    .map_err(|e| d.error(format!("invalid timeout duration {}: {e}", args[0])))?;
                set_i64(&mut config, "acme_timeout", dur);
            }
            "disable_http_challenge" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                let ch = section_mut(&mut config, "challenges")?;
                let http = section_mut(ch, "http")?;
                set_bool(http, "disabled", true);
            }
            "disable_tlsalpn_challenge" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                let ch = section_mut(&mut config, "challenges")?;
                let alpn = section_mut(ch, "tls-alpn")?;
                set_bool(alpn, "disabled", true);
            }
            "distributed" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                if d.val() != "false" {
                    return Err(d.error("only accepted value is 'false'"));
                }
                let ch = section_mut(&mut config, "challenges")?;
                set_retain_bool(ch, "distributed", false);
            }
            "alt_http_port" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let port: isize = d
                    .val()
                    .parse()
                    .map_err(|e| d.error(format!("invalid port {}: {e}", d.val())))?;
                let ch = section_mut(&mut config, "challenges")?;
                let http = section_mut(ch, "http")?;
                set_i64(http, "alternate_port", port as i64);
            }
            "alt_tlsalpn_port" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let port: isize = d
                    .val()
                    .parse()
                    .map_err(|e| d.error(format!("invalid port {}: {e}", d.val())))?;
                let ch = section_mut(&mut config, "challenges")?;
                let alpn = section_mut(ch, "tls-alpn")?;
                set_i64(alpn, "alternate_port", port as i64);
            }
            "eab" => {
                let args = d.all_args(2).ok_or_else(|| d.arg_err())?;
                let eab = section_mut(&mut config, "external_account")?;
                set_str_retain(eab, "key_id", &args[0]);
                set_str_retain(eab, "mac_key", &args[1]);
            }
            "trusted_roots" => {
                let args = d.remaining_args();
                set_string_array(&mut config, "trusted_roots_pem_files", &args);
            }
            "dns" => {
                let ch = section_mut(&mut config, "challenges")?;
                let dns = section_mut(ch, "dns")?;
                if d.next_arg() {
                    // Named provider: no dns.providers registered → always unknown module
                    return Err(d.error(format!(
                        "unrecognized module name: dns.providers.{}",
                        d.val()
                    )));
                }
                // empty DNS {} supported (dns section already created by section_mut)
                let _ = dns;
            }
            "propagation_delay" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let dur = crate::duration::parse_str(d.val()).map_err(|e| {
                    d.error(format!(
                        "invalid propagation_delay duration {}: {e}",
                        d.val()
                    ))
                })?;
                let ch = section_mut(&mut config, "challenges")?;
                let dns = section_mut(ch, "dns")?;
                set_i64(dns, "propagation_delay", dur);
            }
            "propagation_timeout" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let val = d.val().to_owned();
                let dur: i64 = if val == "-1" {
                    -1
                } else {
                    crate::duration::parse_str(&val).map_err(|e| {
                        d.error(format!("invalid propagation_timeout duration {}: {e}", val))
                    })?
                };
                let ch = section_mut(&mut config, "challenges")?;
                let dns = section_mut(ch, "dns")?;
                set_i64(dns, "propagation_timeout", dur);
            }
            "resolvers" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.arg_err());
                }
                let ch = section_mut(&mut config, "challenges")?;
                let dns = section_mut(ch, "dns")?;
                set_string_array_retain(dns, "resolvers", &args);
            }
            "dns_ttl" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let dur = crate::duration::parse_str(d.val())
                    .map_err(|e| d.error(format!("invalid dns_ttl duration {}: {e}", d.val())))?;
                let ch = section_mut(&mut config, "challenges")?;
                let dns = section_mut(ch, "dns")?;
                set_i64(dns, "ttl", dur);
            }
            "dns_challenge_override_domain" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                let ch = section_mut(&mut config, "challenges")?;
                let dns = section_mut(ch, "dns")?;
                set_str(dns, "override_domain", &args[0]);
            }
            "preferred_chains" => {
                let chains = preferred_chains(d)?;
                config.insert("preferred_chains".to_owned(), chains);
            }
            name => bail!("unrecognized ACME issuer property: {name}"),
        }
    }
    Ok(IssuerDef::Acme(config))
}

// ---------------------------------------------------------------------------
// zerossl
// ---------------------------------------------------------------------------

fn parse_zerossl(d: &mut Dispenser) -> Result<IssuerDef> {
    let mut config = Map::new();
    // API key is required
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let api_key = d.val().to_owned();
    if d.next_arg() {
        return Err(d.arg_err());
    }
    set_str(&mut config, "api_key", &api_key);

    let mut validity_days: i64 = 0;
    let mut validity_days_seen = false;

    while d.next_block(0) {
        match d.val() {
            "validity_days" => {
                if validity_days_seen {bail!("validity days is already specified: {validity_days}");}
                if !d.next_arg(){return Err(d.arg_err());}
                validity_days=d.val().parse().map_err(|e|d.error(format!("invalid number of days: {e}")))?;
                if d.next_arg(){return Err(d.arg_err());}
                validity_days_seen=true;
            }
            "alt_http_port" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let port: isize = d
                    .val()
                    .parse()
                    .map_err(|e| d.error(format!("invalid port {}: {e}", d.val())))?;
                set_i64(&mut config, "alternate_http_port", port as i64);
            }
            "dns" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                // Named provider required → always unknown module (no dns.providers)
                return Err(d.error(format!(
                    "unrecognized module name: dns.providers.{}",
                    d.val()
                )));
            }
            "propagation_delay" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let dur = crate::duration::parse_str(d.val()).map_err(|e| {
                    d.error(format!(
                        "invalid propagation_delay duration {}: {e}",
                        d.val()
                    ))
                })?;
                let cv = section_mut(&mut config, "cname_validation")?;
                set_i64(cv, "propagation_delay", dur);
            }
            "propagation_timeout" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let val = d.val().to_owned();
                let dur: i64 = if val == "-1" {
                    -1
                } else {
                    crate::duration::parse_str(&val).map_err(|e| {
                        d.error(format!("invalid propagation_timeout duration {}: {e}", val))
                    })?
                };
                let cv = section_mut(&mut config, "cname_validation")?;
                set_i64(cv, "propagation_timeout", dur);
            }
            "resolvers" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.arg_err());
                }
                let cv = section_mut(&mut config, "cname_validation")?;
                set_string_array_retain(cv, "resolvers", &args);
            }
            "dns_ttl" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let dur = crate::duration::parse_str(d.val())
                    .map_err(|e| d.error(format!("invalid dns_ttl duration {}: {e}", d.val())))?;
                let cv = section_mut(&mut config, "cname_validation")?;
                set_i64(cv, "ttl", dur);
            }
            name => bail!("unrecognized zerossl issuer property: {name}"),
        }
    }

    // Read the actual numeric argument; the pinned Go adapter parses its keyword.
    set_i64(&mut config, "validity_days", validity_days);

    Ok(IssuerDef::ZeroSsl(config))
}

// ---------------------------------------------------------------------------
// preferred_chains (shared global/local)
// ---------------------------------------------------------------------------

pub(super) fn preferred_chains(d: &mut Dispenser) -> Result<Value> {
    let mut pref = Map::new();
    if d.next_arg() {
        if d.val() != "smallest" {
            return Err(d.error(format!("Invalid argument '{}'", d.val())));
        }
        pref.insert("smallest".into(), true.into());
        if d.next_arg() {
            return Err(d.arg_err());
        }
        if d.next_block(d.nesting()) {
            return Err(d.error("No more options are accepted when using the 'smallest' option"));
        }
    }
    let nesting = d.nesting();
    while d.next_block(nesting) {
        let key = d.val().to_owned();
        let other = match key.as_str() {
            "root_common_name" => "any_common_name",
            "any_common_name" => "root_common_name",
            _ => return Err(d.error(format!("Received unrecognized parameter '{key}'"))),
        };
        let args = d.remaining_args();
        if args.is_empty() {
            return Err(d.arg_err());
        }
        if pref.contains_key(other) {
            return Err(d.error(format!("Can't set {key} when {other} is already set")));
        }
        let array = pref
            .entry(key)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid chain preference"))?;
        array.extend(args.into_iter().map(Value::String));
    }
    if pref.is_empty() {
        return Err(d.error("No options for preferred_chains received"));
    }
    Ok(Value::Object(pref))
}
