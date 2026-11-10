// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Automation-policy and manual-loader assembly preserving native issuer aliases.
use super::{
    budget::{Budget, add, mul},
    global_atoms::Atom,
    globals::Options,
    listeners::Pairing,
    site::Site,
    subjects, tls_global_defaults,
    tls_policy::{IssuerDef, IssuerRef, PolicyConfig, RawModule, shared},
};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
#[derive(Clone)]
struct Policy {
    cfg: PolicyConfig,
    bytes: u64,
    text_bytes: u64,
}
impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.cfg == other.cfg
    }
}
impl Policy {
    fn new(subjects: Option<Vec<String>>, internal: bool, budget: &mut Budget) -> Result<Self> {
        budget.materialize(2048)?;
        let mut cfg = PolicyConfig {
            subjects,
            ..Default::default()
        };
        if internal {
            cfg.issuers_raw = Some(vec![RawModule::from_value(
                serde_json::json!({"module":"internal"}),
            )?]);
        }
        Self::from_config(cfg, budget)
    }
    fn from_config(cfg: PolicyConfig, budget: &mut Budget) -> Result<Self> {
        let mut p = Self {
            cfg,
            bytes: 0,
            text_bytes: 0,
        };
        p.refresh(budget)?;
        Ok(p)
    }
    fn refresh(&mut self, budget: &mut Budget) -> Result<()> {
        let mut bytes = add(2048, self.cfg.key_type.len() as u64)?;
        let mut text = 0;
        for name in self.names() {
            bytes = add(bytes, add(name.len() as u64, 64)?)?;
            text = add(text, add(name.len() as u64, 1)?)?;
        }
        if let Some(issuers) = &self.cfg.issuers {
            for issuer in issuers {
                let cost = budget.measure_map(issuer.borrow().fields())?;
                budget.copies(cost, 0, 4)?;
                bytes = add(bytes, add(cost.bytes, 128)?)?;
            }
        }
        for raws in [&self.cfg.issuers_raw, &self.cfg.managers_raw]
            .into_iter()
            .flatten()
        {
            for raw in raws {
                let cost = budget.measure(&raw.value)?;
                budget.copies(cost, 0, 4)?;
                bytes = add(bytes, add(add(cost.bytes, raw.bytes.len() as u64)?, 128)?)?;
            }
        }
        if let Some(storage) = &self.cfg.storage_raw {
            bytes = add(bytes, storage.len() as u64)?;
        }
        if let Some(overrides) = &self.cfg.ocsp_overrides {
            let cost = budget.measure_map(overrides)?;
            bytes = add(bytes, cost.bytes)?;
        }
        self.bytes = bytes;
        self.text_bytes = text;
        Ok(())
    }
    fn names(&self) -> &[String] {
        self.cfg.subjects.as_deref().unwrap_or(&[])
    }
    fn class(&self) -> u8 {
        if self.names().is_empty() {
            return 0;
        }
        let public = self
            .names()
            .iter()
            .any(|s| subjects::public_implicit(s, self.cfg.on_demand));
        let private = self
            .names()
            .iter()
            .any(|s| !subjects::public_implicit(s, self.cfg.on_demand));
        match (public, private) {
            (true, true) => 3,
            (true, false) => 1,
            _ => 2,
        }
    }
    fn uses_default_internal(&self) -> bool {
        let raw = self.cfg.issuers_raw.as_deref().unwrap_or(&[]);
        let native = self.cfg.issuers.as_deref().unwrap_or(&[]);
        if raw.is_empty() && native.is_empty() {
            return self.class() == 2;
        }
        raw.len() == 1 && native.is_empty() && raw[0].bytes == b"{\"module\":\"internal\"}"
    }
    fn value(self) -> Result<Value> {
        self.cfg.into_value()
    }
}
fn new_base(options: &Options, always: bool, budget: &mut Budget) -> Result<Option<Policy>> {
    let has = [
        "local_certs",
        "key_type",
        "ocsp_stapling",
        "renewal_window_ratio",
    ]
    .iter()
    .any(|n| options.atoms.contains_key(*n))
        || options.issuers.is_some();
    let acme_defaults = tls_global_defaults::has_non_email_defaults(options);
    if !always && !has && !acme_defaults {
        return Ok(None);
    }
    budget.materialize(2048)?;
    let mut cfg = PolicyConfig::default();
    if let Some(Atom::String(key)) = options.atoms.get("key_type") {
        budget.materialize(add(key.len() as u64, 64)?)?;
        cfg.key_type = key.clone();
    }
    if options.issuers.is_some() && options.atoms.contains_key("local_certs") {
        bail!(
            "global options are ambiguous: local_certs is confusing when combined with cert_issuer, because local_certs is also a specific kind of issuer"
        );
    }
    if let Some(issuers) = &options.issuers {
        budget.materialize(mul(issuers.len() as u64, 128)?)?;
        for issuer in issuers {
            let cost = budget.measure_map(issuer.borrow().fields())?;
            budget.copies(cost, 1, 5)?;
        }
        cfg.issuers = Some(issuers.clone());
    } else if options.atoms.contains_key("local_certs") {
        cfg.issuers = Some(vec![shared(IssuerDef::Internal(Map::new()))]);
    }
    if acme_defaults && let Some(issuers) = &mut cfg.issuers {
        for (i, issuer) in issuers.iter_mut().enumerate() {
            tls_global_defaults::fill(&mut issuer.borrow_mut(), options, budget).map_err(|e| {
                anyhow::anyhow!("filling in global issuer defaults for issuer {i}: {e}")
            })?;
        }
    }
    if let Some(Atom::Bool(disabled)) = options.atoms.get("ocsp_stapling") {
        cfg.disable_ocsp_stapling = *disabled;
    }
    if let Some(Atom::Float(ratio)) = options.atoms.get("renewal_window_ratio") {
        cfg.renewal_window_ratio = *ratio;
    }
    Policy::from_config(cfg, budget).map(Some)
}
fn default_issuers(options: &Options, budget: &mut Budget) -> Result<Vec<IssuerRef>> {
    budget.materialize(2048)?;
    let mut issuers = vec![shared(IssuerDef::Acme(Map::new()))];
    if !options.atoms.contains_key("acme_ca")
        && let Some(Atom::String(email)) = options.atoms.get("email")
        && !email.trim().is_empty()
    {
        budget.materialize(add(email.len() as u64, 256)?)?;
        let fields = Map::from_iter([
            ("ca".into(), Value::from("https://acme.zerossl.com/v2/DV90")),
            ("email".into(), email.clone().into()),
        ]);
        issuers.push(shared(IssuerDef::Acme(fields)));
    }
    Ok(issuers)
}
pub(super) fn build(
    sites: &[Site],
    pairs: &[Pairing],
    options: &Options,
    budget: &mut Budget,
) -> Result<Option<Value>> {
    let http = options.integer("http_port", 80).to_string();
    let off = options.strings("auto_https").iter().any(|s| s == "off");
    let no_certs = options
        .strings("auto_https")
        .iter()
        .any(|s| s == "disable_certs");
    let mut shared = BTreeSet::new();
    if !off {
        for p in pairs {
            for r in &p.sites {
                let keys = || r.keys.iter().map(|k| &sites[r.site].keys[*k]);
                if keys().any(|k| k.host.is_empty()) {
                    for key in keys() {
                        if !key.host.is_empty() && key.scheme != "http" && key.port != http {
                            budget.materialize(key.host.len() as u64 + 64)?;
                            shared.insert(key.host.clone());
                        }
                    }
                }
            }
        }
    }
    let mut forced = BTreeSet::new();
    let mut files = Vec::new();
    let mut folders = Vec::new();
    let mut arena = Vec::<Policy>::new();
    let mut policies = Vec::new();
    let mut catchall = None;
    if let Some(default) = new_base(options, false, budget)? {
        arena.push(default);
        policies.push(0);
        catchall = Some(0);
    }
    for pair in pairs {
        if !super::listeners::uses_other_port(&pair.listeners, &http) {
            continue;
        }
        for r in &pair.sites {
            let keys = || r.keys.iter().map(|k| &sites[r.site].keys[*k]);
            if keys().all(|k| k.scheme == "http") {
                continue;
            }
            let hostless = keys().any(|k| k.host.is_empty());
            let mut names = BTreeSet::new();
            for key in keys() {
                if !key.host.is_empty() && key.scheme != "http" && key.port != http {
                    budget.materialize(key.host.len() as u64 + 64)?;
                    names.insert(key.host.clone());
                }
            }
            let names = names.into_iter().collect::<Vec<_>>();
            let policy = if let (true, Some(index)) = (hostless, catchall) {
                index
            } else {
                arena.push(
                    new_base(options, true, budget)?
                        .ok_or_else(|| anyhow::anyhow!("required automation policy missing"))?,
                );
                arena.len() - 1
            };
            let site = &sites[r.site];
            let cfg = &mut arena[policy].cfg;
            cfg.on_demand |= site.tls.on_demand;
            cfg.reuse_private_keys |= site.tls.reuse_private_keys;
            if let Some(key) = &site.tls.key_type {
                budget.materialize(key.len() as u64 + 96)?;
                cfg.key_type = key.clone();
            }
            if let Some(ratio) = site.tls.renewal_window_ratio {
                cfg.renewal_window_ratio = ratio;
            } else if let Some(Atom::Float(ratio)) = options.atoms.get("renewal_window_ratio") {
                // Reused catch-all policies observe the per-site fallback,
                // not merely the value initially copied by new_base.
                cfg.renewal_window_ratio = *ratio;
            }
            if !site.tls.issuers.is_empty() {
                if catchall == Some(policy) && cfg.issuers.as_ref() != Some(&site.tls.issuers) {
                    bail!(
                        "automation policy from site block is also default/catch-all policy because of key without hostname, and the two are in conflict"
                    );
                }
                budget.materialize(mul(site.tls.issuers.len() as u64, 128)?)?;
                cfg.issuers = Some(site.tls.issuers.clone());
            }
            if !site.tls.managers.is_empty() {
                let destination = cfg.managers_raw.get_or_insert_with(Vec::new);
                for manager in &site.tls.managers {
                    let cost = budget.measure(&manager.value)?;
                    budget.copies(cost, 1, 4)?;
                    budget.materialize(manager.bytes.len() as u64 + 128)?;
                    destination.push(manager.clone());
                }
            }
            if site.tls.force_automate {
                for host in super::tls_server::hosts(site, &r.keys, budget)? {
                    forced.insert(host);
                }
            }
            for bind in &site.binds {
                if let Some(issuers) = &cfg.issuers {
                    for issuer in issuers {
                        let mut issuer = issuer.borrow_mut();
                        // The zerossl API issuer does not wrap an ACME issuer.
                        if !matches!(&*issuer, IssuerDef::Acme(_)) {
                            continue;
                        }
                        budget.materialize(512)?;
                        let fields = issuer.fields_mut();
                        let challenges = fields
                            .entry("challenges")
                            .or_insert_with(|| Value::Object(Map::new()))
                            .as_object_mut()
                            .ok_or_else(|| {
                                anyhow::anyhow!("typed ACME challenges must be an object")
                            })?;
                        if challenges
                            .get("bind_host")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .is_empty()
                        {
                            let address = bind
                                .addresses
                                .first()
                                .map(String::as_str)
                                .unwrap_or_default();
                            budget.materialize(address.len() as u64 + 96)?;
                            if !address.is_empty() {
                                challenges.insert("bind_host".into(), address.into());
                            }
                        }
                    }
                }
            }
            for file in &site.tls.files {
                let cost = budget.measure(file)?;
                budget.copies(cost, 1, 4)?;
                files.push(file.clone());
            }
            for folder in &site.tls.folders {
                budget.materialize(folder.len() as u64 + 96)?;
                folders.push(folder.clone());
            }
            let mut public = Vec::new();
            let mut private = Vec::new();
            if arena[policy]
                .cfg
                .issuers
                .as_deref()
                .unwrap_or(&[])
                .is_empty()
            {
                for s in &names {
                    budget.work(s.len() as u64 + 1)?;
                    if subjects::tailscale(s) {
                        continue;
                    }
                    if !subjects::qualifies(s) {
                        bail!("subject does not qualify for certificate: '{s}'");
                    }
                    budget.materialize(s.len() as u64 + 64)?;
                    if subjects::public_implicit(s, arena[policy].cfg.on_demand) {
                        public.push(s.clone());
                    } else {
                        private.push(s.clone());
                    }
                }
            }
            if hostless && catchall.is_none() {
                catchall = Some(policy);
            }
            arena[policy].cfg.subjects = Some(names);
            arena[policy].refresh(budget)?;
            if !public.is_empty() && !private.is_empty() {
                arena[policy].cfg.subjects = Some(public);
                arena[policy].refresh(budget)?;
                budget.materialize(arena[policy].bytes)?;
                budget.materialize(1024)?;
                let mut second = arena[policy].cfg.clone();
                second.subjects = Some(private);
                second.issuers_raw = Some(vec![RawModule::from_value(
                    serde_json::json!({"module":"internal"}),
                )?]);
                arena.push(Policy::from_config(second, budget)?);
                policies.push(policy);
                policies.push(arena.len() - 1);
            } else {
                policies.push(policy);
            }
        }
    }
    if let Some(ech) = &options.ech {
        let mut policy = new_base(options, true, budget)?
            .ok_or_else(|| anyhow::anyhow!("required ECH automation policy missing"))?;
        let mut names = Vec::new();
        let configs = ech
            .get("configs")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow::anyhow!("typed ECH configurations must be a nonempty array"))?;
        for config in configs {
            let name = config
                .get("public_name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("typed ECH public name must be a string"))?;
            if !name.is_empty() {
                budget.materialize(name.len() as u64 + 96)?;
                names.push(name.to_owned());
            }
        }
        if !names.is_empty() {
            policy.cfg.subjects = Some(names);
        }
        policy.refresh(budget)?;
        arena.push(policy);
        policies.push(arena.len() - 1);
    }
    let mut automate = Vec::new();
    let mut internal = Vec::new();
    if !off && !no_certs {
        for name in shared {
            budget.materialize(name.len() as u64 + 64)?;
            if !subjects::public_certmagic(&name) {
                internal.push(name.clone());
            }
            automate.push(name);
        }
    }
    // Explicit names need no serving site and remain managed even with
    // automatic HTTPS disabled. A site's existing policy takes precedence.
    let mut managed = automate.into_iter().collect::<BTreeSet<_>>();
    managed.extend(forced);
    let mut configured = BTreeSet::new();
    for &id in &policies {
        for name in arena[id].names() {
            budget.materialize(64)?;
            budget.work(mul(add(name.len() as u64, 1)?, 64)?)?;
            configured.insert(name.as_str());
        }
    }
    let mut public_names = Vec::new();
    for name in options.strings("tls_automate_names") {
        budget.work(mul(add(name.len() as u64, 1)?, 128)?)?;
        if managed.contains(name) {
            continue;
        }
        budget.materialize(add(name.len() as u64, 64)?)?;
        managed.insert(name.clone());
        if configured.contains(name.as_str()) {
            continue;
        }
        budget.materialize(add(name.len() as u64, 64)?)?;
        if subjects::public_certmagic(name) {
            public_names.push(name.clone());
        } else {
            internal.push(name.clone());
        }
    }
    drop(configured);
    if !public_names.is_empty()
        && let Some(mut p) = new_base(
            options,
            tls_global_defaults::has_acme_defaults(options),
            budget,
        )?
    {
        p.cfg.subjects = Some(public_names);
        p.refresh(budget)?;
        arena.push(p);
        policies.push(arena.len() - 1);
    }
    let automate = managed.into_iter().collect::<Vec<_>>();
    if !internal.is_empty() {
        budget.materialize(1024)?;
        arena.push(Policy::new(Some(internal), true, budget)?);
        policies.push(arena.len() - 1);
    }
    if tls_global_defaults::has_acme_defaults(options) {
        for &id in &policies {
            if arena[id].cfg.issuers.as_deref().unwrap_or(&[]).is_empty()
                && arena[id].names().iter().all(|name| {
                    subjects::public_implicit(name, arena[id].cfg.on_demand)
                        && !subjects::tailscale(name)
                })
            {
                arena[id].cfg.issuers = Some(default_issuers(options, budget)?);
            }
        }
    }
    // Native concrete issuers remain on the config after their public raw
    // JSON is rendered; Go's consolidation distinguishes both states.
    for (i, &id) in policies.iter().enumerate() {
        if let Some(issuers) = &mut arena[id].cfg.issuers {
            for (j, issuer) in issuers.iter_mut().enumerate() {
                tls_global_defaults::fill(&mut issuer.borrow_mut(), options, budget).map_err(
                    |e| {
                        anyhow::anyhow!(
                            "filling in global issuer defaults for AP {i}, issuer {j}: {e}"
                        )
                    },
                )?;
            }
        }

        if arena[id].cfg.issuers_raw.is_none()
            && let Some(issuers) = &arena[id].cfg.issuers
            && !issuers.is_empty()
        {
            let mut raw = Vec::new();
            for issuer in issuers {
                let cost = budget.measure_map(issuer.borrow().fields())?;
                budget.copies(cost, 6, 4)?;
                budget.materialize(add(mul(cost.json_upper, 3)?, 2048)?)?;
                raw.push(issuer.borrow().raw()?);
            }
            arena[id].cfg.issuers_raw = Some(raw);
        }
        arena[id].refresh(budget)?;
    }
    consolidate(&mut policies, &mut arena, budget)?;
    let mut seen = BTreeSet::new();
    for &id in &policies {
        for name in arena[id].names() {
            budget.work(1)?;
            if !seen.insert(name) {
                bail!(
                    "hostname appears in more than one automation policy, making certificate management ambiguous: {name}"
                );
            }
        }
    }
    let mut tls = Map::new();
    if !automate.is_empty() || !files.is_empty() || !folders.is_empty() {
        let mut certificates = Map::new();
        if !files.is_empty() {
            certificates.insert("load_files".into(), Value::Array(files));
        }
        if !folders.is_empty() {
            certificates.insert(
                "load_folders".into(),
                folders.into_iter().map(Value::String).collect(),
            );
        }
        if !automate.is_empty() {
            certificates.insert(
                "automate".into(),
                Value::Array(automate.into_iter().map(Value::String).collect()),
            );
        }
        tls.insert("certificates".into(), Value::Object(certificates));
    }
    if !policies.is_empty() {
        let mut values = Vec::new();
        for id in policies {
            budget.materialize(arena[id].bytes)?;
            values.push(arena[id].clone().value()?);
        }
        let mut automation = Map::new();
        automation.insert("policies".into(), Value::Array(values));
        tls.insert("automation".into(), Value::Object(automation));
    }
    Ok(if tls.is_empty() {
        None
    } else {
        Some(Value::Object(tls))
    })
}
fn subset(a: &Policy, b: &Policy, budget: &mut Budget) -> Result<bool> {
    if b.names().is_empty() {
        return Ok(true);
    }
    if a.names().is_empty() {
        return Ok(false);
    }
    let comparisons = mul(add(a.text_bytes, 1)?, add(b.text_bytes, 1)?)?;
    budget.work(comparisons)?;
    // Each linear wildcard comparison owns host/lowercase temporaries.
    // Charge their conservative aggregate before entering nested matches.
    budget.materialize(mul(comparisons, 8)?)?;
    Ok(a.names()
        .iter()
        .all(|s| b.names().iter().any(|p| subjects::wildcard(s, p))))
}
fn shadows(
    i: usize,
    ids: &[usize],
    arena: &[Policy],
    budget: &mut Budget,
) -> Result<Option<usize>> {
    for j in i + 1..ids.len() {
        if subset(&arena[ids[i]], &arena[ids[j]], budget)? {
            return Ok(Some(j));
        }
    }
    Ok(None)
}
fn same_issuers(a: &Policy, b: &Policy) -> bool {
    if a.cfg.issuers_raw == b.cfg.issuers_raw {
        if !a.cfg.issuers_raw.as_deref().unwrap_or(&[]).is_empty()
            || !a.cfg.issuers.as_deref().unwrap_or(&[]).is_empty()
            || !b.cfg.issuers.as_deref().unwrap_or(&[]).is_empty()
        {
            return true;
        }
        let ac = a.class();
        let bc = b.class();
        ac == 0 || bc == 0 || ac == bc
    } else {
        a.uses_default_internal() && b.uses_default_internal()
    }
}
fn same_merge_fields(a: &Policy, b: &Policy) -> bool {
    same_issuers(a, b)
        && a.cfg.managers_raw == b.cfg.managers_raw
        && a.cfg.storage_raw.as_deref().unwrap_or(&[])
            == b.cfg.storage_raw.as_deref().unwrap_or(&[])
        && a.cfg.must_staple == b.cfg.must_staple
        && a.cfg.key_type == b.cfg.key_type
        && a.cfg.on_demand == b.cfg.on_demand
        && a.cfg.reuse_private_keys == b.cfg.reuse_private_keys
        && a.cfg.renewal_window_ratio == b.cfg.renewal_window_ratio
    // The pinned Go merge deliberately does not compare OCSP settings.
}
fn consolidate(ids: &mut Vec<usize>, arena: &mut [Policy], budget: &mut Budget) -> Result<()> {
    let n = ids.len() as u64;
    let log = (usize::BITS - ids.len().leading_zeros() + 1) as u64;
    budget.work(mul(mul(n, log)?, mul(log, 4)?)?)?;
    let mut error = None;
    super::stable_sort::stable_sort(ids, |a, b| {
        if error.is_some() {
            return false;
        }
        let cmp = (|| -> Result<bool> {
            if subset(&arena[*a], &arena[*b], budget)? {
                return Ok(true);
            }
            if subset(&arena[*b], &arena[*a], budget)? {
                return Ok(false);
            }
            Ok(arena[*a].names().len() > arena[*b].names().len())
        })();
        match cmp {
            Ok(v) => v,
            Err(e) => {
                error = Some(e);
                false
            }
        }
    });
    if let Some(e) = error {
        return Err(e);
    }
    let original = ids.len();
    let mut empty = 0;
    let mut i = 0;
    while i < ids.len() {
        if arena[ids[i]].cfg.is_go_zero_ignoring_subjects(false) {
            empty += 1;
            let shadow = shadows(i, ids, arena, budget)?;
            if i == ids.len() - 1
                || shadow.is_some_and(|s| arena[ids[s]].cfg.is_go_zero_ignoring_subjects(true))
            {
                ids.remove(i);
                continue;
            }
        }
        i += 1;
    }
    if empty == original {
        ids.clear();
        return Ok(());
    }
    let mut i = 0;
    'outer: while i < ids.len() {
        let mut j = i + 1;
        while j < ids.len() {
            let (a, b) = (ids[i], ids[j]);
            budget.work(add(arena[a].bytes, arena[b].bytes)?)?;
            if arena[a] == arena[b] {
                ids.remove(j);
                continue 'outer;
            }
            if same_merge_fields(&arena[a], &arena[b]) {
                if !arena[a].names().is_empty() && arena[b].names().is_empty() {
                    if shadows(i, ids, arena, budget)?.is_some_and(|s| s >= j) {
                        ids.remove(i);
                        continue 'outer;
                    }
                } else {
                    let more = arena[b].names();
                    budget.materialize(arena[b].bytes)?;
                    let more = more.to_vec();
                    let target = arena[a].cfg.subjects.get_or_insert_with(Vec::new);
                    for s in more {
                        budget.work(mul(target.len() as u64 + 1, s.len() as u64 + 1)?)?;
                        if !target.contains(&s) {
                            budget.materialize(s.len() as u64 + 64)?;
                            target.push(s);
                        }
                    }
                    arena[a].refresh(budget)?;
                    ids.remove(j);
                    continue;
                }
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}
