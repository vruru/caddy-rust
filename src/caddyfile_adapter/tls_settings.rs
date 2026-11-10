// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Scalar TLS-app settings; issuer/policy options use a separate assembly path.
use super::{
    budget::{Budget, add},
    global_atoms::Atom,
    globals::Options,
};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
pub(super) fn apply(
    tls: Option<Value>,
    options: &Options,
    budget: &mut Budget,
) -> Result<Option<Value>> {
    budget.work(8)?;
    budget.materialize(2048)?;
    let mut root = match tls {
        None => Map::new(),
        Some(Value::Object(m)) => m,
        _ => bail!("TLS app assembly expected an object"),
    };
    let mut automation = match root.remove("automation") {
        None => Map::new(),
        Some(Value::Object(m)) => m,
        _ => bail!("TLS automation assembly expected an object"),
    };
    if matches!(options.atoms.get("ocsp_stapling"), Some(Atom::Bool(true))) {
        root.insert("disable_ocsp_stapling".into(), true.into());
    }
    if matches!(options.atoms.get("storage_check"), Some(Atom::String(s)) if s=="off") {
        root.insert("disable_storage_check".into(), true.into());
    }
    if matches!(
        options.atoms.get("storage_clean_interval"),
        Some(Atom::Bool(false))
    ) {
        root.insert("disable_storage_clean".into(), true.into());
    }
    for name in ["storage_clean_interval", "renew_interval", "ocsp_interval"] {
        if let Some(Atom::Duration(n)) = options.atoms.get(name)
            && *n != 0
        {
            automation.insert(name.into(), (*n).into());
            // Final buildTLSApp removes a zero-valued AutomationConfig,
            // including one allocated by an explicitly configured zero.
        }
    }
    if let Some(Atom::Strings(values)) = options.atoms.get("tls_resolvers") {
        let mut bytes = 64;
        for s in values {
            bytes = add(bytes, add(s.len() as u64, 64)?)?;
        }
        budget.materialize(bytes)?;
        if !values.is_empty() {
            root.insert(
                "resolvers".into(),
                values.iter().cloned().map(Value::String).collect(),
            );
        }
    }
    if let Some(on_demand) = &options.on_demand {
        let cost = budget.measure(on_demand)?;
        budget.copies(cost, 1, 4)?;
        automation.insert("on_demand".into(), on_demand.clone());
    }
    if let Some(ech) = &options.ech {
        let cost = budget.measure(ech)?;
        budget.copies(cost, 1, 3)?;
        root.insert("encrypted_client_hello".into(), ech.clone());
    }
    if !automation.is_empty() {
        root.insert("automation".into(), Value::Object(automation));
    }
    Ok(if root.is_empty() {
        None
    } else {
        Some(Value::Object(root))
    })
}
