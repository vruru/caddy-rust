// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::budget::Budget;
use super::globals::Options;
use super::site::reserve_helper;
use super::tls_acme_merge::implicit as tls_acme_merge_implicit;
use super::tls_client_auth::parse as tls_client_auth_parse;
use super::tls_issuers::{parse as tls_issuers_parse, set_i64, set_str};
use super::tls_policy::{IssuerDef, IssuerRef, RawModule, shared};
use super::tls_sources::manager as tls_sources_manager;
use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::Dispenser;
use crate::caddyfile_parser::scalar::parse_float;
use crate::duration::parse_str as parse_duration_str;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Default)]
pub(super) struct TlsDirective {
    pub connection: Map<String, Value>,
    pub files: Vec<Value>,
    pub folders: Vec<String>,
    pub issuers: Vec<IssuerRef>,
    pub managers: Vec<RawModule>,
    pub key_type: String,
    pub on_demand: bool,
    pub reuse_private_keys: bool,
    pub force_automate: bool,
    pub renewal_window_ratio: f64,
}

impl TlsDirective {
    /// Number of ConfigValues emitted by the original parseTLS. Ordered nested
    /// scopes discard them, but sorting must still see every actual value.
    pub(super) fn config_value_count(&self) -> anyhow::Result<u64> {
        let mut count = super::budget::add(1, self.issuers.len() as u64)?;
        count = super::budget::add(count, self.managers.len() as u64)?;
        for enabled in [
            !self.files.is_empty(),
            !self.folders.is_empty(),
            !self.key_type.is_empty(),
            self.on_demand,
            self.reuse_private_keys,
            self.renewal_window_ratio > 0.0,
            self.force_automate,
        ] {
            count = super::budget::add(count, u64::from(enabled))?;
        }
        Ok(count)
    }
}

const SUPPORTED_PROTOCOLS: &[&str] = &["tls1.2", "tls1.3"];
const SUPPORTED_CURVES: &[&str] = &[
    "x25519mlkem768",
    "x25519",
    "secp256r1",
    "secp384r1",
    "secp521r1",
];
const SUPPORTED_CIPHERS: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
];

pub(super) fn parse(
    tokens: &[Token],
    tags: &mut BTreeMap<String, String>,
    options: &Options,
    cwd: &Path,
    budget: &mut Budget,
) -> anyhow::Result<TlsDirective> {
    let _reservation = reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next(); // consume directive name

    let mut directive = TlsDirective::default();

    // Track issuer specific state (mutually exclusive with issuers)
    let mut acme_issuer_present = false;
    let mut acme_issuer_email: Option<String> = None;
    let mut acme_issuer_ca: Option<String> = None;
    let mut acme_issuer_eab_key_id: Option<String> = None;
    let mut acme_issuer_eab_mac_key: Option<String> = None;
    let mut acme_issuer_dns: Map<String, Value> = Map::new();
    let acme_issuer_dns_provider_set = false;
    let mut dns_present = false;
    let mut acme_issuer_dns_options_set: Vec<String> = Vec::new();
    let mut acme_issuer_trusted_roots: Vec<String> = Vec::new();

    let mut internal_issuer_present = false;
    let mut force_automate = false;

    let mut has_block = false;

    // Parse first line args
    let first_line = d.remaining_args();

    match first_line.len() {
        0 => {}
        1 => {
            let arg = &first_line[0];
            if arg == "internal" {
                internal_issuer_present = true;
            } else if arg == "force_automate" {
                force_automate = true;
            } else if !arg.contains('@') {
                return Err(d.error("single argument must either be 'internal', 'force_automate', or an email address"));
            } else {
                acme_issuer_present = true;
                acme_issuer_email = Some(arg.clone());
            }
        }
        2 => {
            // File certificate loader
            let cert_filename = &first_line[0];
            let key_filename = &first_line[1];

            // Dedup logic
            let tag = match tags.get(cert_filename) {
                Some(t) => t.clone(),
                None => {
                    let new_tag = format!("cert{}", tags.len());
                    tags.insert(cert_filename.clone(), new_tag.clone());

                    let mut file_obj = Map::new();
                    file_obj.insert(
                        "certificate".to_string(),
                        Value::String(cert_filename.clone()),
                    );
                    file_obj.insert("key".to_string(), Value::String(key_filename.clone()));
                    file_obj.insert(
                        "tags".to_string(),
                        Value::Array(vec![Value::String(new_tag.clone())]),
                    );

                    directive.files.push(Value::Object(file_obj));
                    new_tag
                }
            };

            directive.connection.insert(
                "certificate_selection".into(),
                serde_json::json!({"any_tag":[tag]}),
            );
        }
        _ => {
            return Err(d.arg_err());
        }
    }

    // Parse block
    while d.next_block(0) {
        has_block = true;
        let val = d.val();
        match val {
            "protocols" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.error("protocols requires one or two arguments"));
                }
                if !args.is_empty() {
                    if !SUPPORTED_PROTOCOLS.contains(&args[0].as_str()) {
                        return Err(d.error(format!(
                            "wrong protocol name or protocol not supported: '{}'",
                            args[0]
                        )));
                    }
                    set_str(&mut directive.connection, "protocol_min", args[0].as_str());
                }
                if args.len() > 1 {
                    if !SUPPORTED_PROTOCOLS.contains(&args[1].as_str()) {
                        return Err(d.error(format!(
                            "wrong protocol name or protocol not supported: '{}'",
                            args[1]
                        )));
                    }
                    set_str(&mut directive.connection, "protocol_max", args[1].as_str());
                }
            }
            "ciphers" => {
                let mut ciphers = Vec::new();
                while d.next_arg() {
                    let v = d.val();
                    if !SUPPORTED_CIPHERS.contains(&v) {
                        return Err(d.error(format!(
                            "wrong cipher suite name or cipher suite not supported: '{}'",
                            v
                        )));
                    }
                    ciphers.push(v.to_string());
                }
                append_list(&mut directive.connection, "cipher_suites", ciphers);
            }
            "curves" => {
                let mut curves = Vec::new();
                while d.next_arg() {
                    let v = d.val();
                    if !SUPPORTED_CURVES.contains(&v) {
                        return Err(
                            d.error(format!("Wrong curve name or curve not supported: '{}'", v))
                        );
                    }
                    curves.push(v.to_string());
                }
                append_list(&mut directive.connection, "curves", curves);
            }
            "client_auth" => {
                let segment = d.next_segment();
                let client_auth_val = tls_client_auth_parse(&segment, cwd, budget)?;
                directive
                    .connection
                    .insert("client_authentication".to_string(), client_auth_val);
            }
            "alpn" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.arg_err());
                }
                set_str_list(&mut directive.connection, "alpn", args);
            }
            "load" => {
                let args = d.remaining_args();
                directive.folders.extend(args);
            }
            "ca" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                acme_issuer_present = true;
                acme_issuer_ca = Some(args[0].clone());
            }
            "key_type" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                directive.key_type = args[0].clone();
            }
            "eab" => {
                let args = d.remaining_args();
                if args.len() != 2 {
                    return Err(d.arg_err());
                }
                acme_issuer_present = true;
                acme_issuer_eab_key_id = Some(args[0].clone());
                acme_issuer_eab_mac_key = Some(args[1].clone());
            }
            "issuer" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let mod_name = d.val().to_owned();
                let segment = d.next_segment();
                match tls_issuers_parse(&mod_name, &segment) {
                    Ok(issuer) => {
                        directive.issuers.push(shared(issuer));
                    }
                    Err(e) => {
                        return Err(d.error(format!("failed to parse issuer: {}", e)));
                    }
                }
            }
            "get_certificate" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let mod_name = d.val().to_owned();
                let segment = d.next_segment();
                match tls_sources_manager(&mod_name, &segment) {
                    Ok(manager_val) => {
                        // Wrap in RawModule as per API hint: RawModule::from_value
                        directive.managers.push(RawModule::from_value(manager_val)?);
                    }
                    Err(e) => {
                        return Err(d.error(format!("failed to parse get_certificate: {}", e)));
                    }
                }
            }
            "dns" => {
                acme_issuer_present = true;
                dns_present = true;

                if d.next_arg() {
                    return Err(d.error(format!("getting module named 'dns.providers.{}': module not registered: dns.providers.{}",d.val(),d.val())));
                } else if !options.atoms.contains_key("dns") {
                    return Err(d.arg_err());
                }
            }
            "resolvers" => {
                let args = d.remaining_args();
                if args.is_empty() {
                    return Err(d.arg_err());
                }
                acme_issuer_present = true;
                dns_present = true;
                acme_issuer_dns_options_set.push("resolvers".to_string());
                set_str_list(&mut acme_issuer_dns, "resolvers", args);
            }
            "propagation_delay" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                let delay = parse_duration_str(&args[0])?;
                acme_issuer_present = true;
                dns_present = true;
                acme_issuer_dns_options_set.push("propagation_delay".to_string());
                set_i64(&mut acme_issuer_dns, "propagation_delay", delay);
            }
            "propagation_timeout" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                let timeout_str = &args[0];
                let timeout = if timeout_str == "-1" {
                    -1
                } else {
                    parse_duration_str(timeout_str)?
                };
                acme_issuer_present = true;
                dns_present = true;
                acme_issuer_dns_options_set.push("propagation_timeout".to_string());
                set_i64(&mut acme_issuer_dns, "propagation_timeout", timeout);
            }
            "dns_ttl" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                let ttl = parse_duration_str(&args[0])?;
                acme_issuer_present = true;
                dns_present = true;
                acme_issuer_dns_options_set.push("dns_ttl".to_string());
                set_i64(&mut acme_issuer_dns, "ttl", ttl);
            }
            "dns_challenge_override_domain" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                acme_issuer_present = true;
                dns_present = true;
                acme_issuer_dns_options_set.push("dns_challenge_override_domain".to_string());
                set_str(&mut acme_issuer_dns, "override_domain", &args[0]);
            }
            "ca_root" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                acme_issuer_present = true;
                acme_issuer_trusted_roots.push(args[0].clone());
            }
            "on_demand" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                directive.on_demand = true;
            }
            "reuse_private_keys" => {
                if d.next_arg() {
                    return Err(d.arg_err());
                }
                directive.reuse_private_keys = true;
            }
            "insecure_secrets_log" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                set_str(&mut directive.connection, "insecure_secrets_log", d.val());
            }
            "renewal_window_ratio" => {
                let args = d.remaining_args();
                if args.len() != 1 {
                    return Err(d.arg_err());
                }
                let ratio = parse_float(&args[0])
                    .ok_or_else(|| d.error("parsing renewal_window_ratio: invalid float"))?;
                // "NaN原Go允许但最后>0为false所以输出cfg保持0"

                if ratio <= 0.0 || ratio >= 1.0 {
                    return Err(d.error("renewal_window_ratio must be between 0 and 1 (exclusive)"));
                }
                directive.renewal_window_ratio = if ratio > 0.0 { ratio } else { 0.0 };
            }
            _ => {
                return Err(d.error(format!("unknown subdirective: {}", val)));
            }
        }
    }

    // Validate DNS challenge config
    if acme_issuer_present && dns_present {
        let provider_set = acme_issuer_dns_provider_set || options.atoms.contains_key("dns");
        if !acme_issuer_dns_options_set.is_empty() && !provider_set {
            return Err(d.error(format!(
                "setting DNS challenge options [{}] requires a DNS provider (set with the 'dns' subdirective or 'acme_dns' global option)",
                acme_issuer_dns_options_set.join(", ")
            )));
        }
    }

    // Naked tls directive not allowed
    if first_line.is_empty() && !has_block {
        return Err(d.arg_err());
    }

    // Mutual exclusivity checks for issuers
    if !directive.issuers.is_empty() && (acme_issuer_present || internal_issuer_present) {
        return Err(d.error("cannot mix issuer subdirective (explicit issuers) with other issuer-specific subdirectives (implicit issuers)"));
    }
    if acme_issuer_present && internal_issuer_present {
        return Err(d.error("cannot create both ACME and internal certificate issuers"));
    }

    // Finalize Issuers
    if !directive.issuers.is_empty() {
        // Already populated
    } else if acme_issuer_present {
        // Construct local map for implicit merge
        let mut local_map = Map::new();
        if let Some(email) = acme_issuer_email {
            set_str(&mut local_map, "email", &email);
        }
        if let Some(ca) = acme_issuer_ca {
            set_str(&mut local_map, "ca", &ca);
        }
        if dns_present {
            local_map.insert(
                "challenges".to_string(),
                Value::Object({
                    let mut challenges = Map::new();
                    challenges.insert("dns".to_string(), Value::Object(acme_issuer_dns));
                    challenges
                }),
            );
        }
        if !acme_issuer_trusted_roots.is_empty() {
            local_map.insert(
                "trusted_roots_pem_files".to_string(),
                Value::Array(
                    acme_issuer_trusted_roots
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        if let (Some(kid), Some(mac)) = (acme_issuer_eab_key_id, acme_issuer_eab_mac_key) {
            local_map.insert(
                "external_account".to_string(),
                Value::Object({
                    let mut eab = Map::new();
                    eab.insert("key_id".to_string(), Value::String(kid));
                    eab.insert("mac_key".to_string(), Value::String(mac));
                    eab
                }),
            );
        }

        // Call implicit merge
        let merged_issuers = tls_acme_merge_implicit(options, local_map, budget)?;
        directive.issuers = merged_issuers;
    } else if internal_issuer_present {
        directive
            .issuers
            .push(shared(IssuerDef::Internal(Map::new())));
    }

    directive.force_automate = force_automate;

    Ok(directive)
}

fn set_str_list(map: &mut Map<String, Value>, key: &str, values: Vec<String>) {
    if values.is_empty() {
        map.remove(key);
        return;
    }
    map.insert(
        key.to_string(),
        Value::Array(values.into_iter().map(Value::String).collect()),
    );
}

fn append_list(map: &mut Map<String, Value>, key: &str, values: Vec<String>) {
    if values.is_empty() {
        return;
    }
    let array = map
        .entry(key.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("typed TLS list");
    array.extend(values.into_iter().map(Value::String));
}
