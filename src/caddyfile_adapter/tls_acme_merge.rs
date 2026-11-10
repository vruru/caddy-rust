// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::{Budget, add, mul},
    globals::Options,
    tls_policy::{IssuerDef, IssuerRef, shared},
};
use anyhow::Result;
use serde_json::{Map, Value};

pub(super) fn implicit(
    options: &Options,
    local: Map<String, Value>,
    budget: &mut Budget,
) -> Result<Vec<IssuerRef>> {
    let mut result = Vec::new();
    if let Some(templates) = &options.issuers {
        for issuer in templates {
            if let IssuerDef::Acme(base) = &*issuer.borrow() {
                result.push(shared(IssuerDef::Acme(merge(base, &local, budget)?)));
            }
        }
    }
    if !result.is_empty() {
        return Ok(result);
    }
    result.push(shared(IssuerDef::Acme(merge(&Map::new(), &local, budget)?)));
    let email = local.get("email").and_then(Value::as_str).unwrap_or("");
    let ca = local.get("ca").and_then(Value::as_str).unwrap_or("");
    // This deliberately uses the local shortcut's email, before later global
    // defaults. A global email alone must not add a fallback to this shortcut.
    if ca.is_empty() && !email.trim().is_empty() {
        budget.materialize(email.len() as u64 + 512)?;
        let base = Map::from_iter([
            ("ca".into(), "https://acme.zerossl.com/v2/DV90".into()),
            ("email".into(), email.into()),
        ]);
        result.push(shared(IssuerDef::Acme(merge(&base, &local, budget)?)));
    }
    Ok(result)
}

fn merge(
    base: &Map<String, Value>,
    local: &Map<String, Value>,
    budget: &mut Budget,
) -> Result<Map<String, Value>> {
    let base_cost = budget.measure_map(base)?;
    let local_cost = budget.measure_map(local)?;
    budget.copies(base_cost, 1, 0)?;
    // At most four nested concrete challenge structs are cloned; this covers
    // their pointer-preserving native representation before raw JSON rendering.
    budget.copies(local_cost, 4, 4)?;
    let mut result = base.clone();
    for (name, value) in local {
        if name == "trusted_roots_pem_files" {
            let additions = value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("ACME roots must be an array"))?;
            let roots = result
                .entry(name.clone())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| anyhow::anyhow!("ACME roots must be an array"))?;
            let base_text = roots.iter().try_fold(1u64, |n, v| {
                add(n, v.as_str().map_or(1, |s| s.len() as u64 + 1))
            })?;
            let local_text = additions.iter().try_fold(1u64, |n, v| {
                add(n, v.as_str().map_or(1, |s| s.len() as u64 + 1))
            })?;
            budget.work(mul(base_text, local_text)?)?;
            for item in additions {
                if !roots.contains(item) {
                    roots.push(item.clone());
                }
            }
        } else if name == "challenges" {
            let local = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("ACME challenges must be an object"))?;
            let current = result
                .entry(name.clone())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("ACME challenges must be an object"))?;
            merge_challenges(current, local)?;
        } else {
            // Native parsers omit zero scalar fields, but preserve pointer
            // objects. Thus presence here is precisely Go's nonzero/nonnil guard.
            result.insert(name.clone(), value.clone());
        }
    }
    Ok(result)
}
fn merge_challenges(current: &mut Map<String, Value>, local: &Map<String, Value>) -> Result<()> {
    for (name, value) in local {
        if matches!(name.as_str(), "http" | "tls-alpn" | "dns") {
            let fields = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("ACME challenge must be an object"))?;
            let target = current
                .entry(name.clone())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("ACME challenge must be an object"))?;
            for (key, value) in fields {
                target.insert(key.clone(), value.clone());
            }
        } else {
            current.insert(name.clone(), value.clone());
        }
    }
    Ok(())
}
