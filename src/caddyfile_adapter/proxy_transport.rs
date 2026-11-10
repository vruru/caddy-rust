// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::Budget,
    globals::Options,
    tls_issuers::{set_i64, set_str},
};
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
fn child<'a>(m: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    m.entry(key)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap()
}
fn required(d: &mut Dispenser) -> Result<String> {
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    Ok(d.val().into())
}
fn array(v: Vec<String>) -> Value {
    v.into_iter().map(Value::String).collect()
}
fn strings(d: &mut Dispenser) -> Result<Vec<String>> {
    let a = d.remaining_args();
    if a.is_empty() {
        return Err(d.arg_err());
    }
    Ok(a)
}
pub(super) fn parse(
    name: &str,
    tokens: &[Token],
    budget: &mut Budget,
    options: &Options,
) -> Result<Value> {
    let r = super::site::reserve_helper(tokens, budget)?;
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut m = Map::new();
    m.insert("protocol".into(), name.into());
    match name {
        "fastcgi" => {
            while d.next_block(0) {
                let k = d.val().to_owned();
                match k.as_str() {
                    "root" => set_str(&mut m, "root", &required(&mut d)?),
                    "split" => {
                        m.insert("split_path".into(), array(strings(&mut d)?));
                    }
                    "env" => {
                        let a = d.remaining_args();
                        if a.len() != 2 {
                            return Err(d.arg_err());
                        }
                        child(&mut m, "env").insert(a[0].clone(), a[1].clone().into());
                    }
                    "resolve_root_symlink" | "capture_stderr" => {
                        if d.next_arg() {
                            return Err(d.arg_err());
                        }
                        m.insert(k, true.into());
                    }
                    "dial_timeout" | "read_timeout" | "write_timeout" => {
                        set_i64(&mut m, &k, crate::duration::parse_str(&required(&mut d)?)?);
                    }
                    _ => return Err(d.error(format!("unrecognized subdirective {k}"))),
                }
            }
        }
        "http" => {
            while d.next_block(0) {
                let k = d.val().to_owned();
                match k.as_str() {
                    "read_buffer" | "write_buffer" | "max_response_header" => {
                        let v = super::handler_limits::parse_size(&required(&mut d)?)? as i64;
                        let key = match k.as_str() {
                            "read_buffer" => "read_buffer_size",
                            "write_buffer" => "write_buffer_size",
                            _ => "max_response_header_size",
                        };
                        set_i64(&mut m, key, v);
                    }
                    "read_timeout"
                    | "write_timeout"
                    | "dial_timeout"
                    | "dial_fallback_delay"
                    | "response_header_timeout"
                    | "expect_continue_timeout" => {
                        set_i64(&mut m, &k, crate::duration::parse_str(&required(&mut d)?)?);
                    }
                    "proxy_protocol" => {
                        let v = required(&mut d)?;
                        if !matches!(v.as_str(), "v1" | "v2") {
                            return Err(d.error("invalid proxy protocol version"));
                        }
                        set_str(&mut m, &k, &v);
                    }
                    "forward_proxy_url" => {
                        warn(
                            &d,
                            options,
                            budget,
                            "The 'forward_proxy_url' field is deprecated. Use 'network_proxy <url>' instead.",
                        )?;
                        m.insert(
                            "network_proxy".into(),
                            json!({"from":"url","url":required(&mut d)?}),
                        );
                    }
                    "network_proxy" => {
                        let name = required(&mut d)?;
                        let segment = d.next_segment();
                        let value = match name.as_str() {
                            "none" => json!({"from":"none"}),
                            "url" => {
                                let mut n = Dispenser::new(segment);
                                n.next();
                                n.next();
                                json!({"from":"url","url":n.val()})
                            }
                            _ => {
                                return Err(d.error(format!(
                                    "module caddy.network_proxy.{name} not registered"
                                )));
                            }
                        };
                        m.insert("network_proxy".into(), value);
                    }
                    "resolvers" => {
                        m.insert("resolver".into(), json!({"addresses":strings(&mut d)?}));
                    }
                    "tls" => {
                        child(&mut m, "tls");
                    }
                    "tls_client_auth" => {
                        let a = d.remaining_args();
                        let tls = child(&mut m, "tls");
                        match a.as_slice() {
                            [name] => set_str(tls, "client_certificate_automate", name),
                            [cert, key] => {
                                set_str(tls, "client_certificate_file", cert);
                                set_str(tls, "client_certificate_key_file", key)
                            }
                            _ => return Err(d.arg_err()),
                        }
                    }
                    "tls_insecure_skip_verify" => {
                        if d.next_arg() {
                            return Err(d.arg_err());
                        }
                        child(&mut m, "tls").insert("insecure_skip_verify".into(), true.into());
                    }
                    "tls_curves" | "tls_except_ports" => {
                        let a = strings(&mut d)?;
                        child(&mut m, "tls").insert(
                            if k == "tls_curves" {
                                "curves"
                            } else {
                                "except_ports"
                            }
                            .into(),
                            array(a),
                        );
                    }
                    "tls_timeout" => {
                        set_i64(
                            child(&mut m, "tls"),
                            "handshake_timeout",
                            crate::duration::parse_str(&required(&mut d)?)?,
                        );
                    }
                    "tls_trusted_ca_certs" => {
                        warn(
                            &d,
                            options,
                            budget,
                            "The 'tls_trusted_ca_certs' field is deprecated. Use the 'tls_trust_pool' field instead.",
                        )?;
                        let a = strings(&mut d)?;
                        let tls = child(&mut m, "tls");
                        if tls.contains_key("ca") {
                            return Err(d.error(
                                "cannot specify both 'tls_trust_pool' and 'tls_trusted_ca_certs",
                            ));
                        }
                        tls.insert("root_ca_pem_files".into(), array(a));
                    }
                    "tls_server_name" => {
                        set_str(child(&mut m, "tls"), "server_name", &required(&mut d)?);
                    }
                    "tls_renegotiation" => {
                        let tls = child(&mut m, "tls");
                        let v = required(&mut d)?;
                        if !matches!(v.as_str(), "never" | "once" | "freely") {
                            return Err(d.arg_err());
                        }
                        set_str(tls, "renegotiation", &v);
                    }
                    "keepalive" => {
                        let v = required(&mut d)?;
                        let ka = child(&mut m, "keep_alive");
                        if v == "off" {
                            ka.insert("enabled".into(), false.into());
                        } else {
                            set_i64(ka, "idle_timeout", crate::duration::parse_str(&v)?);
                        }
                    }
                    "keepalive_interval" => {
                        set_i64(
                            child(&mut m, "keep_alive"),
                            "probe_interval",
                            crate::duration::parse_str(&required(&mut d)?)?,
                        );
                    }
                    "keepalive_idle_conns" | "keepalive_idle_conns_per_host" => {
                        let v = required(&mut d)?.parse::<i64>()?;
                        let key = if k == "keepalive_idle_conns" {
                            "max_idle_conns"
                        } else {
                            "max_idle_conns_per_host"
                        };
                        set_i64(child(&mut m, "keep_alive"), key, v);
                    }
                    "versions" => {
                        m.insert(k, array(strings(&mut d)?));
                    }
                    "compression" => {
                        if d.next_arg() && d.val() == "off" {
                            m.insert(k, false.into());
                        }
                    }
                    "max_conns_per_host" => {
                        set_i64(&mut m, &k, required(&mut d)?.parse::<i64>()?);
                    }
                    "tls_trust_pool" => {
                        let name = required(&mut d)?;
                        let value = super::tls_sources::pool(&name, &d.next_segment(), budget)?;
                        let tls = child(&mut m, "tls");
                        if tls.contains_key("root_ca_pem_files") {
                            return Err(d.error(
                                "cannot specify both 'tls_trust_pool' and 'tls_trusted_ca_certs'",
                            ));
                        }
                        if tls.contains_key("ca") {
                            return Err(d.error("cannot specify tls_trust_pool twice"));
                        }
                        tls.insert("ca".into(), value);
                    }
                    "local_address" => {
                        set_str(&mut m, &k, &required(&mut d)?);
                    }
                    _ => return Err(d.error(format!("unrecognized subdirective {k}"))),
                }
            }
        }
        _ => bail!("module http.reverse_proxy.transport.{name} not registered"),
    }
    let v = super::module_value::normalize(Value::Object(m))?;
    budget.finish_value(r, &v)?;
    Ok(v)
}
fn warn(d: &Dispenser, o: &Options, b: &mut Budget, message: &str) -> Result<()> {
    let t = d.token();
    o.warn(&t.file, t.line, "reverse_proxy", message, b)
}
