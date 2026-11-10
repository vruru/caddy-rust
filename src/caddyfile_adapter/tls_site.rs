// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use super::{
    budget::Budget,
    globals::Options,
    tls_connections::Connection,
    tls_policy::{IssuerRef, RawModule},
};
use crate::caddyfile_parser::Segment;
use anyhow::Result;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

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
pub(super) fn parse(
    segments: &[Segment],
    tags: &mut BTreeMap<String, String>,
    options: &Options,
    cwd: &Path,
    budget: &mut Budget,
) -> Result<SiteTls> {
    let mut site = SiteTls::default();
    for segment in segments {
        if !segment.first().is_some_and(|t| t.text == "tls") {
            continue;
        }
        let directive = super::tls_directive::parse(segment, tags, options, cwd, budget)?;
        budget.materialize(512)?;
        site.connections
            .push(Connection::new(directive.connection, budget)?);
        site.files.extend(directive.files);
        site.folders.extend(directive.folders);
        site.issuers.extend(directive.issuers);
        site.managers.extend(directive.managers);
        // parseTLS emits pile entries only for nonzero values. The first
        // emitted entry wins; an earlier empty value does not reserve it.
        if site.key_type.is_none() && !directive.key_type.is_empty() {
            site.key_type = Some(directive.key_type);
        }
        if site.renewal_window_ratio.is_none() && directive.renewal_window_ratio > 0.0 {
            site.renewal_window_ratio = Some(directive.renewal_window_ratio);
        }
        site.on_demand |= directive.on_demand;
        site.reuse_private_keys |= directive.reuse_private_keys;
        site.force_automate |= directive.force_automate;
    }
    Ok(site)
}
