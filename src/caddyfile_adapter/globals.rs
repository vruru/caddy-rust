// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::Budget,
    builtin_state::{self, Bind},
    global_atoms::{self, Atom},
    order,
    tls_policy::{IssuerRef, shared},
};
use crate::caddyfile_parser::Segment;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
const REGISTERED: &[&str] = &[
    "debug",
    "http_port",
    "https_port",
    "default_bind",
    "grace_period",
    "shutdown_delay",
    "default_sni",
    "fallback_sni",
    "order",
    "storage",
    "storage_check",
    "storage_clean_interval",
    "renew_interval",
    "ocsp_interval",
    "acme_ca",
    "acme_ca_root",
    "acme_dns",
    "acme_eab",
    "cert_issuer",
    "skip_install_trust",
    "email",
    "admin",
    "on_demand_tls",
    "local_certs",
    "key_type",
    "auto_https",
    "metrics",
    "servers",
    "ocsp_stapling",
    "cert_lifetime",
    "log",
    "preferred_chains",
    "persist_config",
    "dns",
    "tls_resolvers",
    "tls_automate_names",
    "ech",
    "renewal_window_ratio",
    "pki",
    "events",
    "filesystem",
];
pub(super) struct Options {
    pub atoms: BTreeMap<String, Atom>,
    pub order: Vec<String>,
    pub default_bind: Vec<Bind>,
    pub admin: Option<Value>,
    pub pki: Map<String, Value>,
    pub issuers: Option<Vec<IssuerRef>>,
    pub eab: Option<Value>,
    pub preferred: Option<Value>,
    pub on_demand: Option<Value>,
    pub ech: Option<Value>,
    pub storage: Option<Value>,
    pub metrics: Option<Value>,
    pub events: Option<Value>,
    pub logs: Vec<super::log_config::Entry>,
    pub servers: Vec<super::global_servers::Settings>,
    log_names: std::collections::BTreeSet<String>,
    pub diagnostics: std::cell::RefCell<Vec<super::Warning>>,
}
impl Options {
    pub fn new() -> Self {
        Self {
            atoms: BTreeMap::new(),
            order: super::routes::DEFAULT_ORDER
                .iter()
                .map(|s| s.to_string())
                .collect(),
            default_bind: Vec::new(),
            admin: None,
            pki: Map::new(),
            issuers: None,
            eab: None,
            preferred: None,
            on_demand: None,
            ech: None,
            storage: None,
            metrics: None,
            events: None,
            logs: Vec::new(),
            servers: Vec::new(),
            log_names: Default::default(),
            diagnostics: Default::default(),
        }
    }
    pub(super) fn warn(
        &self,
        file: &str,
        line: usize,
        directive: &str,
        message: &str,
        budget: &mut Budget,
    ) -> Result<()> {
        let bytes = super::budget::add(
            super::budget::add(file.len() as u64, directive.len() as u64)?,
            super::budget::add(
                message.len() as u64,
                std::mem::size_of::<super::Warning>() as u64,
            )?,
        )?;
        budget.materialize(bytes)?;
        self.diagnostics.borrow_mut().push(super::Warning {
            file: file.into(),
            line,
            directive: directive.into(),
            message: message.into(),
        });
        Ok(())
    }
    pub fn integer(&self, name: &str, default: isize) -> isize {
        match self.atoms.get(name) {
            Some(Atom::Integer(n)) => *n,
            _ => default,
        }
    }
    pub fn strings(&self, name: &str) -> &[String] {
        match self.atoms.get(name) {
            Some(Atom::Strings(v)) => v,
            _ => &[],
        }
    }
    pub fn parse(&mut self, segments: &[Segment], budget: &mut Budget) -> Result<()> {
        for seg in segments {
            let Some(first) = seg.first() else { continue };
            let name = first.text.as_str();
            if !REGISTERED.contains(&name) {
                bail!(
                    "{}:{}: unrecognized global option: {name}",
                    first.file,
                    first.line
                );
            }
            // Options may produce vectors and owned token dispensers. Charge
            // their complete token/metadata copies before invoking a parser.
            let reservation = super::site::reserve_helper(seg, budget)?;
            if name == "tls_automate_names"
                && let Some(Atom::Strings(previous)) = self.atoms.get(name)
            {
                for value in previous {
                    budget.work(value.len() as u64 + 1)?;
                    budget.materialize(value.len() as u64 + 64)?;
                }
            }
            (|| -> Result<()> {
            match name {
                "servers"=>{self.servers.push(super::global_servers::parse(seg,budget)?);}
                "log"=>{
                    // Pass names separately because parsing diagnostics borrow Options.
                    let mut names=std::mem::take(&mut self.log_names);
                    let result=super::log_config::parse(seg,Some(&mut names),&mut 0,budget,self);
                    self.log_names=names;
                    self.logs.push(result?);
                }
                "events" => {
                    self.events=Some(super::global_auxiliary::events(seg)?);
                }
                "filesystem" => {
                    super::global_auxiliary::filesystem(seg)?;
                }
                "storage" => {
                    let mut d = crate::caddyfile_parser::Dispenser::new(seg.to_vec());
                    if !d.next() || !d.next() {
                        return Err(d.arg_err());
                    }
                    self.storage = Some(super::module_value::normalize(
                        super::tls_sources::storage(&d.next_segment())?,
                    )?);
                }
                "metrics" => {
                    self.metrics = Some(super::global_metrics::parse(seg)?);
                }

                "on_demand_tls"=>{self.on_demand=Some(super::global_tls::on_demand(seg)?);}
                "ech"=>{self.ech=Some(super::global_tls::ech(seg)?);}
                "cert_issuer" => {
                    let mut d = crate::caddyfile_parser::Dispenser::new(seg.to_vec());
                    d.next();
                    if !d.next() {
                        return Err(d.arg_err());
                    }
                    let name = d.val().to_owned();
                    let issuer = super::tls_issuers::parse(&name, &d.next_segment())?;
                    self.issuers.get_or_insert_with(Vec::new).push(shared(issuer));
                }
                "preferred_chains" => {
                    let mut d = crate::caddyfile_parser::Dispenser::new(seg.to_vec());
                    d.next();
                    self.preferred = Some(super::tls_issuers::preferred_chains(&mut d)?);
                }
                "acme_eab" => {
                    let mut d = crate::caddyfile_parser::Dispenser::new(seg.to_vec());
                    d.next();
                    if d.next_arg() {
                        return Err(d.arg_err());
                    }
                    let mut eab = Map::from_iter([
                        ("key_id".into(), Value::String(String::new())),
                        ("mac_key".into(), Value::String(String::new())),
                    ]);
                    while d.next_block(0) {
                        let field = d.val().to_owned();
                        if !["key_id", "mac_key"].contains(&field.as_str()) {
                            return Err(d.error(format!("unrecognized parameter '{field}'")));
                        }
                        if !d.next_arg() {
                            return Err(d.arg_err());
                        }
                        eab.insert(field, d.val().into());
                    }
                    self.eab = Some(Value::Object(eab));
                }
                "acme_dns" | "dns" => {
                    let mut d = crate::caddyfile_parser::Dispenser::new(seg.to_vec());
                    d.next();
                    if d.next_arg() {
                        return Err(d.error(format!(
                            "getting module named 'dns.providers.{}': module not registered: dns.providers.{}",
                            d.val(), d.val()
                        )));
                    }
                    if name == "dns" {
                        return Err(d.arg_err());
                    }
                    self.atoms.insert(name.into(), Atom::Bool(true));
                }
                "pki" => {
                    self.pki = super::global_pki::parse(seg)?;
                }
                "admin" => {
                    self.admin = Some(super::global_admin::parse(seg)?);
                }
                "order" => {
                    self.order = order::parse(seg, Some(&self.order))?;
                }
                "default_bind" => {
                    self.default_bind.push(builtin_state::bind(seg, true)?);
                }
                _ => {
                    if let Some(value) = global_atoms::parse(name, seg, self.atoms.get(name))? {
                        if let Atom::Float(v) = value
                            && !v.is_finite()
                        {
                            bail!("non-finite global option is not JSON: {name}");
                        }
                        self.atoms.insert(name.into(), value);
                    } else {
                        bail!("Caddyfile global option {name} is registered but not implemented");
                    }
                }
            }
                Ok(())
            })().map_err(|e|anyhow::anyhow!("parsing caddyfile tokens for '{name}': {e}"))?;
            // Atom/type-specific validation precedes physical JSON assembly.
            // Reservation is retained; it is not reusable memory credit.
            match name {
                "events" => {
                    budget.finish_value(reservation, self.events.as_ref().unwrap())?;
                }
                "storage" => {
                    budget.finish_value(reservation, self.storage.as_ref().unwrap())?;
                }
                "metrics" => {
                    budget.finish_value(reservation, self.metrics.as_ref().unwrap())?;
                }
                "on_demand_tls" => {
                    budget.finish_value(reservation, self.on_demand.as_ref().unwrap())?;
                }
                "ech" => {
                    budget.finish_value(reservation, self.ech.as_ref().unwrap())?;
                }
                "pki" => {
                    budget.finish_map(reservation, &self.pki)?;
                }
                "admin" => {
                    budget.finish_value(reservation, self.admin.as_ref().unwrap())?;
                }
                "acme_eab" => {
                    budget.finish_value(reservation, self.eab.as_ref().unwrap())?;
                }
                "preferred_chains" => {
                    budget.finish_value(reservation, self.preferred.as_ref().unwrap())?;
                }
                "cert_issuer" => {
                    budget.finish_map(
                        reservation,
                        self.issuers
                            .as_ref()
                            .and_then(|v| v.last())
                            .unwrap()
                            .borrow()
                            .fields(),
                    )?;
                }
                _ => {
                    budget.finish_value(reservation, &Value::Null)?;
                }
            }
        }
        Ok(())
    }
    pub fn http(&self, servers: Map<String, Value>) -> Map<String, Value> {
        let mut result = Map::new();
        result.insert("servers".into(), Value::Object(servers));
        for (name, key) in [
            ("http_port", "http_port"),
            ("https_port", "https_port"),
            ("grace_period", "grace_period"),
            ("shutdown_delay", "shutdown_delay"),
        ] {
            let value = match self.atoms.get(name) {
                Some(Atom::Integer(v)) => *v as i64,
                Some(Atom::Duration(v)) => *v,
                _ => 0,
            };
            if value != 0 {
                result.insert(key.into(), Value::from(value));
            }
        }
        if let Some(metrics) = &self.metrics {
            result.insert("metrics".into(), metrics.clone());
        }
        result
    }
    pub fn top(&self, result: &mut Map<String, Value>, budget: &mut Budget) -> Result<()> {
        // Fixed debug/logging and persist-config objects have depth <= 4.
        // The authoritative final root walk still rechecks all added depth.
        budget.materialize(2048)?;
        if let Some(admin) = &self.admin {
            let cost = budget.measure(admin)?;
            budget.copies(cost, 1, 1)?;
            result.insert("admin".into(), admin.clone());
        }
        if self.atoms.contains_key("debug") {
            result.insert(
                "logging".into(),
                json!({"logs":{"default":{"level":"DEBUG"}}}),
            );
        }
        if self.atoms.contains_key("persist_config") {
            let admin = result.entry("admin").or_insert_with(|| json!({}));
            admin
                .as_object_mut()
                .unwrap()
                .insert("config".into(), json!({"persist":false}));
        }
        if let Some(storage) = &self.storage {
            let cost = budget.measure(storage)?;
            budget.copies(cost, 1, 1)?;
            result.insert("storage".into(), storage.clone());
        }
        Ok(())
    }
    pub fn auto_https(&self) -> Option<Value> {
        let mut map = Map::new();
        for val in self.strings("auto_https") {
            let key = match val.as_str() {
                "off" => "disable",
                "disable_redirects" => "disable_redirects",
                "disable_certs" => "disable_certificates",
                "ignore_loaded_certs" => "ignore_loaded_certificates",
                _ => continue,
            };
            map.insert(key.into(), true.into());
        }
        if map.is_empty() {
            None
        } else {
            Some(Value::Object(map))
        }
    }
}

impl Options {
    pub fn pki_app(
        &self,
        budget: &mut Budget,
        pairings: &[super::listeners::Pairing],
        sites: &[super::site::Site],
    ) -> Result<Option<Value>> {
        let cost = budget.measure_map(&self.pki)?;
        budget.copies(cost, 1, 3)?;
        let mut cas = self.pki.clone();
        let skip = self.atoms.contains_key("skip_install_trust");
        for p in pairings {
            for s in &p.sites {
                for id in &sites[s.site].ca_names {
                    budget.work(id.len() as u64 + 1)?;
                    if !cas.contains_key(id) {
                        budget.materialize(id.len() as u64 + 192)?;
                        cas.insert(id.clone(), Value::Object(Map::new()));
                    }
                }
            }
        }
        if skip {
            for ca in cas.values_mut() {
                ca.as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("PKI authority must be an object"))?
                    .insert("install_trust".into(), false.into());
            }
            if cas.is_empty() && !self.strings("auto_https").iter().any(|s| s == "off") {
                cas.insert("local".into(), json!({"install_trust":false}));
            }
        }
        if skip {
            for p in pairings {
                for s in &p.sites {
                    for issuer in &sites[s.site].tls.issuers {
                        budget.work(1)?;
                        let issuer = issuer.borrow();
                        if issuer.module() != "internal" {
                            continue;
                        }
                        let id = issuer
                            .fields()
                            .get("ca")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .unwrap_or("local");
                        budget.work(id.len() as u64 + 1)?;
                        if !cas.contains_key(id) {
                            budget.materialize(id.len() as u64 + 192)?;
                            cas.insert(id.into(), json!({"install_trust":false}));
                        }
                    }
                }
            }
        }
        if cas.is_empty() {
            return Ok(None);
        }
        let mut app = Map::new();
        app.insert("certificate_authorities".into(), Value::Object(cas));
        Ok(Some(Value::Object(app)))
    }
}
