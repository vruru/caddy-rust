// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::budget::{Budget, Cost, add, mul};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
use std::{
    cell::{Ref, RefCell},
    rc::Rc,
};

struct Selector {
    fields: Map<String, Value>,
    cost: Cost,
}

struct Node {
    fields: Map<String, Value>,
    cost: Cost,
    selector: Option<Rc<RefCell<Selector>>>,
}

/// Shared only within one synchronous adaptation; output contains owned JSON.
#[derive(Clone)]
pub(super) struct Connection(Rc<RefCell<Node>>);

impl Connection {
    pub(super) fn new(fields: Map<String, Value>, budget: &mut Budget) -> Result<Self> {
        // Split selector from base fields
        let mut selector_fields = None;
        let mut base_fields = fields;
        if let Some(sel) = base_fields.remove("certificate_selection") {
            let Value::Object(map) = sel else {
                bail!("typed certificate selector must be an object")
            };
            selector_fields = Some(map);
        }

        let base_cost = budget.measure_map(&base_fields)?;
        budget.copies(base_cost, 0, 6)?;
        budget.materialize(128)?;

        let selector = if let Some(sel_map) = selector_fields {
            let sel_cost = budget.measure_map(&sel_map)?;
            budget.copies(sel_cost, 0, 6)?;
            budget.materialize(128)?;
            Some(Rc::new(RefCell::new(Selector {
                fields: sel_map,
                cost: sel_cost,
            })))
        } else {
            None
        };

        Ok(Self(Rc::new(RefCell::new(Node {
            fields: base_fields,
            cost: base_cost,
            selector,
        }))))
    }

    pub(super) fn fields(&self) -> Ref<'_, Map<String, Value>> {
        Ref::map(self.0.borrow(), |n| &n.fields)
    }

    pub(super) fn cost(&self) -> Result<Cost> {
        let node = self.0.borrow();
        let base_cost = node.cost;
        let sel_cost = match &node.selector {
            Some(s) => s.borrow().cost,
            None => Cost::default(),
        };

        let bytes = add(base_cost.bytes, add(sel_cost.bytes, 128)?)?;
        let nodes = add(base_cost.nodes, sel_cost.nodes)?;
        let json_upper = add(base_cost.json_upper, sel_cost.json_upper)?;
        let depth = std::cmp::max(
            base_cost.depth,
            sel_cost
                .depth
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("TLS selector depth overflow"))?,
        );

        Ok(Cost {
            bytes,
            nodes,
            json_upper,
            depth,
        })
    }

    pub(super) fn change(
        &self,
        budget: &mut Budget,
        f: impl FnOnce(&mut Map<String, Value>, &mut Budget) -> Result<()>,
    ) -> Result<()> {
        let mut node = self.0.borrow_mut();
        // Reject insertion of certificate_selection
        f(&mut node.fields, budget)?;

        // If certificate_selection was inserted, it's an invariant violation
        if node.fields.contains_key("certificate_selection") {
            bail!("certificate_selection cannot be inserted into base fields");
        }

        node.cost = budget.measure_map(&node.fields)?;
        budget.copies(node.cost, 0, 6)?;
        Ok(())
    }

    pub(super) fn shallow_copy(&self, budget: &mut Budget) -> Result<Connection> {
        let node = self.0.borrow();
        let base_cost = node.cost;

        // Prepay for deep clone of base
        budget.copies(base_cost, 1, 6)?;
        budget.materialize(128)?;

        let base_fields = node.fields.clone();
        let selector = node.selector.clone();

        // Recalculate selector cost if needed? No, selector is shared, cost is stored inside.
        // The new Node has the same selector Rc.

        Ok(Self(Rc::new(RefCell::new(Node {
            fields: base_fields,
            cost: base_cost,
            selector,
        }))))
    }

    pub(super) fn render(&self, budget: &mut Budget) -> Result<Map<String, Value>> {
        let node = self.0.borrow();

        // Charge for cloning base
        budget.copies(node.cost, 1, 6)?;
        budget.materialize(128)?;

        let mut result = node.fields.clone();

        if let Some(sel_ref) = &node.selector {
            let sel = sel_ref.borrow();
            budget.copies(sel.cost, 1, 6)?;
            budget.materialize(128)?;
            let sel_clone = sel.fields.clone();

            // Insert selector back as object
            result.insert("certificate_selection".into(), Value::Object(sel_clone));
        }

        Ok(result)
    }
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        if Rc::ptr_eq(&self.0, &other.0) {
            return true;
        }

        let n1 = self.0.borrow();
        let n2 = other.0.borrow();

        if n1.fields != n2.fields {
            return false;
        }

        match (&n1.selector, &n2.selector) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                if Rc::ptr_eq(a, b) {
                    true
                } else {
                    a.borrow().fields == b.borrow().fields
                }
            }
            _ => false,
        }
    }
}

fn selectors_equal(a: &Option<Rc<RefCell<Selector>>>, b: &Option<Rc<RefCell<Selector>>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Rc::ptr_eq(a, b) || a.borrow().fields == b.borrow().fields,
        _ => false,
    }
}
fn merge_selectors(target: &Connection, source: &Connection, budget: &mut Budget) -> Result<()> {
    let a = target.0.borrow().selector.clone();
    let b = source.0.borrow().selector.clone();
    match (a, b) {
        (None, Some(b)) => target.0.borrow_mut().selector = Some(b),
        (Some(a), Some(b)) if !Rc::ptr_eq(&a, &b) => {
            let b = b.borrow();
            let mut a = a.borrow_mut();
            for field in [
                "serial_number",
                "subject_organization",
                "public_key_algorithm",
                "all_tags",
            ] {
                if a.fields.get(field) != b.fields.get(field) {
                    bail!("two policies with same match criteria have conflicting cert selections");
                }
            }
            if let Some(tags) = b.fields.get("any_tag").and_then(Value::as_array) {
                budget.copies(b.cost, 1, 0)?;
                if !tags.is_empty() {
                    let existing = a
                        .fields
                        .entry("any_tag")
                        .or_insert_with(|| Value::Array(Vec::new()))
                        .as_array_mut()
                        .ok_or_else(|| {
                            anyhow::anyhow!("typed certificate tags must be an array")
                        })?;
                    for tag in tags {
                        budget.work(mul(
                            existing.len() as u64 + 1,
                            tag.as_str().map_or(1, |s| s.len() as u64 + 1),
                        )?)?;
                        if !existing.contains(tag) {
                            existing.push(tag.clone());
                        }
                    }
                }
            }
            a.cost = budget.measure_map(&a.fields)?;
            budget.copies(a.cost, 0, 7)?;
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn settings_empty(connection: &Connection) -> bool {
    if connection.0.borrow().selector.is_some() {
        return false;
    }
    let policy = connection.fields();
    // The Caddyfile parsers omit zero scalar fields and nil lists, while
    // retaining nonnil pointer objects such as client_authentication:{}.
    ![
        "certificate_selection",
        "cipher_suites",
        "curves",
        "alpn",
        "protocol_min",
        "protocol_max",
        "client_authentication",
        "default_sni",
        "fallback_sni",
        "insecure_secrets_log",
    ]
    .iter()
    .any(|name| policy.contains_key(*name))
}
fn settings_equal(left: &Connection, right: &Connection) -> bool {
    let left = left.0.borrow();
    let right = right.0.borrow();
    if !selectors_equal(&left.selector, &right.selector) {
        return false;
    }
    let a = &left.fields;
    let b = &right.fields;
    let count =
        |map: &Map<String, Value>| map.keys().filter(|name| name.as_str() != "match").count();
    count(a) == count(b)
        && a.iter()
            .filter(|(name, _)| name.as_str() != "match")
            .all(|(name, value)| b.get(name) == Some(value))
}
fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, Vec::len)
}
fn nonempty_string(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}
fn sni(policy: &Map<String, Value>) -> Option<&Vec<Value>> {
    let matcher = policy.get("match")?.as_object()?;
    if matcher.len() != 1 {
        return None;
    }
    let names = matcher.get("sni")?.as_array()?;
    names.iter().all(Value::is_string).then_some(names)
}

pub(super) fn consolidate(
    mut policies: Vec<Connection>,
    budget: &mut Budget,
) -> Result<Vec<Connection>> {
    let n = policies.len() as u64;
    let log = 64 - n.max(1).leading_zeros() as u64;
    budget.work(mul(mul(n, log + 1)?, 64)?)?;
    super::stable_sort::stable_sort(&mut policies, |a, b| {
        !b.fields().contains_key("match") && a.fields().contains_key("match")
    });
    let mut i = 0;
    'outer: while i < policies.len() {
        for j in 0..policies.len() {
            if i == j {
                continue;
            }
            budget.work(mul(
                add(policies[i].cost()?.bytes, policies[j].cost()?.bytes)?,
                4,
            )?)?;
            if policies[i] == policies[j] {
                policies.remove(j);
                continue 'outer;
            }
            let additional_sni = {
                let a = policies[i].fields();
                let b = policies[j].fields();
                if j == i + 1 && settings_equal(&policies[i], &policies[j]) && sni(&a).is_some() {
                    if let Some(more) = sni(&b) {
                        budget.copies(policies[j].cost()?, 1, 0)?;
                        Some(more.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(more) = additional_sni {
                policies[i].change(budget, |fields, _| {
                    fields
                        .get_mut("match")
                        .and_then(Value::as_object_mut)
                        .unwrap()
                        .get_mut("sni")
                        .and_then(Value::as_array_mut)
                        .unwrap()
                        .extend(more);
                    Ok(())
                })?;
                policies.remove(j);
                continue 'outer;
            }
            if policies[i].fields().get("match") != policies[j].fields().get("match") {
                continue;
            }
            {
                let a = policies[i].fields();
                let b = policies[j].fields();
                for (field, label) in [("alpn", "ALPN"), ("cipher_suites", "cipher suites")] {
                    if array_len(a.get(field)) > 0
                        && array_len(b.get(field)) > 0
                        && a.get(field) != b.get(field)
                    {
                        bail!("two policies with same match criteria have conflicting {label}");
                    }
                }
                // The pinned source deliberately has this asymmetric check.
                if !a.contains_key("client_authentication")
                    && b.contains_key("client_authentication")
                {
                    bail!(
                        "two policies with same match criteria have conflicting client auth configuration"
                    );
                }
                if array_len(a.get("curves")) > 0
                    && array_len(b.get("curves")) > 0
                    && a.get("curves") != b.get("curves")
                {
                    bail!("two policies with same match criteria have conflicting curves");
                }
                for (field, label) in [
                    ("default_sni", "default SNI"),
                    ("fallback_sni", "fallback SNI"),
                    ("protocol_min", "min protocol"),
                    ("protocol_max", "max protocol"),
                ] {
                    if nonempty_string(a.get(field))
                        && nonempty_string(b.get(field))
                        && a.get(field) != b.get(field)
                    {
                        bail!("two policies with same match criteria have conflicting {label}");
                    }
                }
            }
            merge_selectors(&policies[i], &policies[j], budget)?;
            budget.copies(policies[j].cost()?, 2, 0)?;
            let source = (*policies[j].fields()).clone();
            policies[i].change(budget, |target, _| {
                for field in ["alpn", "cipher_suites", "curves"] {
                    if array_len(target.get(field)) == 0 && array_len(source.get(field)) > 0 {
                        target.insert(field.into(), source[field].clone());
                    }
                }
                if !target.contains_key("client_authentication")
                    && let Some(value) = source.get("client_authentication")
                {
                    target.insert("client_authentication".into(), value.clone());
                }
                for field in [
                    "default_sni",
                    "fallback_sni",
                    "protocol_min",
                    "protocol_max",
                ] {
                    if !nonempty_string(target.get(field)) && nonempty_string(source.get(field)) {
                        target.insert(field.into(), source[field].clone());
                    }
                }
                Ok(())
            })?;
            policies.remove(j);
            continue 'outer;
        }
        i += 1;
    }
    Ok(policies)
}
