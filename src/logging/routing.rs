// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Fixed Caddy CustomLog namespace filtering, independent of writers and IO.
use anyhow::{Result, ensure};
struct Namespace {
    raw: String,
    prefix: String,
}
impl Namespace {
    fn new(raw: String) -> Self {
        let prefix = format!("{raw}.");
        Self { raw, prefix }
    }
}
pub(super) struct Routing {
    include: Vec<Namespace>,
    exclude: Vec<Namespace>,
}
impl Routing {
    pub(super) fn has_filters(&self) -> bool {
        !self.include.is_empty() || !self.exclude.is_empty()
    }
    pub(super) fn new(include: Vec<String>, exclude: Vec<String>) -> Result<Self> {
        // This is the original asymmetric validation: every include must nest
        // with some exclusion, not an invented requirement on each exclusion.
        if !include.is_empty() && !exclude.is_empty() {
            for allow in &include {
                ensure!(
                    !exclude.contains(allow),
                    "logging include/exclude intersect"
                );
                let prefix = format!("{allow}.");
                ensure!(
                    exclude.iter().any(|deny| {
                        let other = format!("{deny}.");
                        prefix.starts_with(&other) || other.starts_with(&prefix)
                    }),
                    "logging include/exclude namespaces do not nest"
                );
            }
        }
        Ok(Self {
            include: include.into_iter().map(Namespace::new).collect(),
            exclude: exclude.into_iter().map(Namespace::new).collect(),
        })
    }
    pub(super) fn allows(&self, name: &str, is_module: bool) -> bool {
        if self.include.is_empty() && self.exclude.is_empty() {
            return true;
        }
        let name = if !name.is_empty() && name != "*" && name != "." {
            format!("{name}.")
        } else {
            name.to_owned()
        };
        let mut accept = 0;
        let mut reject = 0;
        for rule in &self.include {
            let matched = if is_module {
                rule.prefix.starts_with(&name)
            } else {
                name.starts_with(&rule.prefix)
            };
            if matched {
                accept = accept.max(rule.raw.len());
            }
        }
        if !self.include.is_empty() && accept == 0 {
            return false;
        }
        for rule in &self.exclude {
            if (rule.raw == "*" && name != ".") || (rule.raw == "." && name == ".") {
                return false;
            }
            if name.starts_with(&rule.prefix) {
                reject = reject.max(rule.raw.len());
            }
        }
        accept > reject || (self.include.is_empty() && reject == 0)
    }
}
