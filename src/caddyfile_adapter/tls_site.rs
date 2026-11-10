// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::Budget,
    tls_connections::Connection,
    tls_policy::{IssuerRef, RawModule},
};
use anyhow::Result;
use serde_json::Value;

#[derive(Default)]
pub(super) struct SiteTls {
    pub connections: Vec<Connection>,
    pub files: Vec<Value>,
    pub folders: Vec<String>,
    pub issuers: Vec<IssuerRef>,
    pub managers: Vec<RawModule>,
    pub key_type: Option<String>,
    pub on_demand: bool,
    pub reuse_private_keys: bool,
    pub force_automate: bool,
    pub renewal_window_ratio: Option<f64>,
}
impl SiteTls {
    pub(super) fn push(
        &mut self,
        directive: super::tls_directive::TlsDirective,
        budget: &mut Budget,
    ) -> Result<()> {
        budget.materialize(512)?;
        self.connections
            .push(Connection::new(directive.connection, budget)?);
        self.files.extend(directive.files);
        self.folders.extend(directive.folders);
        self.issuers.extend(directive.issuers);
        self.managers.extend(directive.managers);
        // parseTLS emits pile entries only for nonzero values. The first
        // emitted entry wins; an earlier empty value does not reserve it.
        if self.key_type.is_none() && !directive.key_type.is_empty() {
            self.key_type = Some(directive.key_type);
        }
        if self.renewal_window_ratio.is_none() && directive.renewal_window_ratio > 0.0 {
            self.renewal_window_ratio = Some(directive.renewal_window_ratio);
        }
        self.on_demand |= directive.on_demand;
        self.reuse_private_keys |= directive.reuse_private_keys;
        self.force_automate |= directive.force_automate;
        Ok(())
    }
}
