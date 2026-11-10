// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, add, mul},
    global_atoms::Atom,
    globals::Options,
    tls_issuers::{section_mut, set_i64, set_str},
    tls_policy::IssuerDef,
};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
pub(super) fn has_acme_defaults(options: &Options) -> bool {
    options.atoms.contains_key("email") || has_non_email_defaults(options)
}
pub(super) fn has_non_email_defaults(options: &Options) -> bool {
    ["acme_ca", "acme_ca_root", "acme_dns"]
        .iter()
        .any(|k| options.atoms.contains_key(*k))
        || options.eab.is_some()
        || options.preferred.is_some()
}
fn pay_string(budget: &mut Budget, s: &str) -> Result<()> {
    budget.work(s.len() as u64)?;
    budget.materialize(add(s.len() as u64, 64)?)
}
fn empty_string(fields: &Map<String, Value>, name: &str) -> bool {
    fields
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
}
fn zero_number(fields: &Map<String, Value>, name: &str) -> bool {
    fields.get(name).and_then(Value::as_i64).unwrap_or(0) == 0
}
fn has_dns(fields: &Map<String, Value>) -> bool {
    fields
        .get("challenges")
        .and_then(|v| v.get("dns"))
        .is_some()
}
fn has_provider(fields: &Map<String, Value>) -> bool {
    fields
        .get("challenges")
        .and_then(|v| v.get("dns"))
        .and_then(|v| v.get("provider"))
        .is_some()
}
pub(super) fn fill(issuer: &mut IssuerDef, options: &Options, budget: &mut Budget) -> Result<()> {
    let IssuerDef::Acme(fields) = issuer else {
        return Ok(());
    };
    budget.materialize(2048)?;
    for (option, key) in [("email", "email"), ("acme_ca", "ca")] {
        if let Some(Atom::String(value)) = options.atoms.get(option)
            && empty_string(fields, key)
        {
            pay_string(budget, value)?;
            set_str(fields, key, value);
        }
    }
    if let Some(Atom::String(root)) = options.atoms.get("acme_ca_root") {
        let already = fields
            .get("trusted_roots_pem_files")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(root)));
        if !already {
            pay_string(budget, root)?;
            let roots = fields
                .entry("trusted_roots_pem_files")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| anyhow::anyhow!("trusted roots must be an array"))?;
            roots.push(root.clone().into());
        }
    }
    let acme_dns = options.atoms.contains_key("acme_dns");
    if acme_dns && !has_provider(fields) {
        // The fixed original binary has no dns.providers modules. Named
        // providers fail during parsing; a bare acme_dns is present-as-nil.
        bail!(
            "acme_dns specified without DNS provider config, but no provider specified with 'dns' global option"
        );
    }
    for (key, value) in [
        ("external_account", options.eab.as_ref()),
        ("preferred_chains", options.preferred.as_ref()),
    ] {
        if let Some(value) = value
            && !fields.contains_key(key)
        {
            let cost = budget.measure(value)?;
            budget.copies(cost, 1, 5)?;
            fields.insert(key.into(), value.clone());
        }
    }
    if !has_dns(fields) {
        for (option, key) in [("http_port", "http"), ("https_port", "tls-alpn")] {
            if let Some(Atom::Integer(port)) = options.atoms.get(option) {
                let existing = fields
                    .get("challenges")
                    .and_then(|v| v.get(key))
                    .and_then(|v| v.get("alternate_port"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if existing == 0 {
                    let challenges = section_mut(fields, "challenges")?;
                    let challenge = section_mut(challenges, key)?;
                    set_i64(challenge, "alternate_port", *port as i64);
                }
            }
        }
    }
    let bind_empty = fields
        .get("challenges")
        .and_then(|v| v.get("bind_host"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty();
    if !has_dns(fields)
        && bind_empty
        && let Some(bind) = options.default_bind.first()
        && let Some(address) = bind.addresses.first()
    {
        pay_string(budget, address)?;
        set_str(section_mut(fields, "challenges")?, "bind_host", address);
    }
    if let Some(Atom::Duration(lifetime)) = options.atoms.get("cert_lifetime")
        && zero_number(fields, "certificate_lifetime")
    {
        set_i64(fields, "certificate_lifetime", *lifetime);
    }
    if has_dns(fields)
        && (acme_dns || has_provider(fields))
        && let Some(Atom::Strings(resolvers)) = options.atoms.get("tls_resolvers")
    {
        let empty = fields
            .get("challenges")
            .and_then(|v| v.get("dns"))
            .and_then(|v| v.get("resolvers"))
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty);
        if empty {
            budget.materialize(mul(resolvers.len() as u64, 64)?)?;
            let mut values = Vec::new();
            for resolver in resolvers {
                pay_string(budget, resolver)?;
                values.push(resolver.clone().into());
            }
            let dns = section_mut(section_mut(fields, "challenges")?, "dns")?;
            if !values.is_empty() {
                dns.insert("resolvers".into(), Value::Array(values));
            } else {
                dns.remove("resolvers");
            }
        }
    }
    Ok(())
}
