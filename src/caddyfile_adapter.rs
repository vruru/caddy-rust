// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Native HTTP Caddyfile adapter. Synchronous filesystem/CPU work must be
//! offloaded by the caller to a bounded blocking worker.
use crate::caddyfile_parser::{self, ParseOptions};
use anyhow::Result;
use serde_json::Value;
#[path = "caddyfile_adapter/address.rs"]
mod address;
#[path = "caddyfile_adapter/budget.rs"]
mod budget;
#[path = "caddyfile_adapter/builtin_state.rs"]
mod builtin_state;
#[path = "caddyfile_adapter/file_finalize.rs"]
mod file_finalize;
#[path = "caddyfile_adapter/format.rs"]
mod format;
#[path = "caddyfile_adapter/global_admin.rs"]
mod global_admin;
#[path = "caddyfile_adapter/global_atoms.rs"]
mod global_atoms;
#[path = "caddyfile_adapter/global_auxiliary.rs"]
mod global_auxiliary;
#[path = "caddyfile_adapter/global_metrics.rs"]
mod global_metrics;
#[path = "caddyfile_adapter/global_pki.rs"]
mod global_pki;
#[path = "caddyfile_adapter/global_tls.rs"]
mod global_tls;
#[path = "caddyfile_adapter/globals.rs"]
mod globals;
#[path = "caddyfile_adapter/handler_atoms.rs"]
mod handler_atoms;
#[path = "caddyfile_adapter/handler_auth_trace.rs"]
mod handler_auth_trace;
#[path = "caddyfile_adapter/handler_encode.rs"]
mod handler_encode;
#[path = "caddyfile_adapter/handler_errors_status.rs"]
mod handler_errors_status;
#[path = "caddyfile_adapter/handler_files.rs"]
mod handler_files;
#[path = "caddyfile_adapter/handler_headers.rs"]
mod handler_headers;
#[path = "caddyfile_adapter/handler_invoke.rs"]
mod handler_invoke;
#[path = "caddyfile_adapter/handler_limits.rs"]
mod handler_limits;
#[path = "caddyfile_adapter/handler_map.rs"]
mod handler_map;
#[path = "caddyfile_adapter/handler_misc.rs"]
mod handler_misc;
#[path = "caddyfile_adapter/handler_observe.rs"]
mod handler_observe;
#[path = "caddyfile_adapter/handler_redir.rs"]
mod handler_redir;
#[path = "caddyfile_adapter/handler_rewrite.rs"]
mod handler_rewrite;
#[path = "caddyfile_adapter/handler_try_files.rs"]
mod handler_try_files;
#[path = "caddyfile_adapter/listeners.rs"]
mod listeners;
#[path = "caddyfile_adapter/matcher_atoms.rs"]
mod matcher_atoms;
#[path = "caddyfile_adapter/matcher_file.rs"]
mod matcher_file;
#[path = "caddyfile_adapter/matcher_more.rs"]
mod matcher_more;
#[path = "caddyfile_adapter/matcher_regexp.rs"]
mod matcher_regexp;
#[path = "caddyfile_adapter/matcher_urlpattern.rs"]
mod matcher_urlpattern;
#[path = "caddyfile_adapter/module_value.rs"]
mod module_value;
#[path = "caddyfile_adapter/named_matchers.rs"]
mod named_matchers;
#[path = "caddyfile_adapter/named_routes.rs"]
mod named_routes;
#[path = "caddyfile_adapter/order.rs"]
mod order;
#[path = "caddyfile_adapter/response_matcher.rs"]
mod response_matcher;
#[path = "caddyfile_adapter/route_build.rs"]
mod route_build;
#[path = "caddyfile_adapter/routes.rs"]
mod routes;
#[path = "caddyfile_adapter/setup.rs"]
mod setup;
#[path = "caddyfile_adapter/shorthands.rs"]
mod shorthands;
#[path = "caddyfile_adapter/site.rs"]
mod site;
#[path = "caddyfile_adapter/stable_sort.rs"]
mod stable_sort;
#[path = "caddyfile_adapter/subjects.rs"]
mod subjects;
#[path = "caddyfile_adapter/tls_client_auth.rs"]
mod tls_client_auth;
#[path = "caddyfile_adapter/tls_defaults.rs"]
mod tls_defaults;
#[path = "caddyfile_adapter/tls_global_defaults.rs"]
mod tls_global_defaults;
#[path = "caddyfile_adapter/tls_issuers.rs"]
mod tls_issuers;
#[path = "caddyfile_adapter/tls_pem.rs"]
mod tls_pem;
#[path = "caddyfile_adapter/tls_policy.rs"]
mod tls_policy;
#[path = "caddyfile_adapter/tls_settings.rs"]
mod tls_settings;
#[path = "caddyfile_adapter/tls_sources.rs"]
mod tls_sources;

#[path = "caddyfile_adapter/tls_acme_merge.rs"]
mod tls_acme_merge;

#[path = "caddyfile_adapter/tls_directive.rs"]
mod tls_directive;

#[path = "caddyfile_adapter/tls_connections.rs"]
mod tls_connections;

#[path = "caddyfile_adapter/tls_site.rs"]
mod tls_site;

#[path = "caddyfile_adapter/tls_server.rs"]
mod tls_server;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub file: String,
    pub line: usize,
    pub directive: String,
    pub message: String,
}
pub struct Adapted {
    pub config: Value,
    pub warnings: Vec<Warning>,
}
/// Format a Caddyfile with an explicit maximum output size, including the
/// final newline. Run this synchronous work on a bounded blocking worker.
pub fn format_caddyfile(input: &[u8], max_output_bytes: usize) -> Result<Vec<u8>> {
    format::format(input, max_output_bytes)
}
/// Compare original formatting with CRLF normalization and return the first
/// differing source line. This synchronous operation has an explicit input cap.
pub fn formatting_difference(input: &[u8], max_input_bytes: usize) -> Result<Option<usize>> {
    format::formatting_difference(input, max_input_bytes)
}
/// Return a candidate only; runtime module provisioning and atomic publication
/// are separate operations. Known but unfinished directives are hard errors.
pub fn adapt(options: &ParseOptions, input: &[u8], filename: &str) -> Result<Adapted> {
    let filename = if filename.is_empty() {
        "Caddyfile"
    } else {
        filename
    };
    let parsed = caddyfile_parser::parse(filename, input, options)?;
    let mut budget = budget::Budget::new(budget::Limits::from_parse(&options.limits));
    let mut warnings = parsed
        .warnings
        .into_iter()
        .map(|w| Warning {
            file: w.file,
            line: w.line,
            directive: String::new(),
            message: w.category,
        })
        .collect::<Vec<_>>();
    let config = setup::setup(parsed.blocks, &mut budget, &mut warnings, &options.cwd)?;
    // Formatting is deliberately last and does not mask a failed adaptation.
    // The comparator streams output; indentation still performs at most one
    // bounded nesting run for each input rune. Charge that CPU work up front.
    budget.work(budget::mul(
        input.len() as u64,
        (options.limits.nesting as u64).saturating_add(16),
    )?)?;
    budget.materialize(input.len() as u64)?;
    if let Some(line) = format::formatting_difference(input, options.limits.source_bytes)? {
        warnings.push(Warning{file:filename.into(),line,directive:String::new(),message:"Caddyfile input is not formatted; run 'caddy fmt --overwrite' to fix inconsistencies".into()});
    }
    budget.check_json(&config)?;
    Ok(Adapted { config, warnings })
}

#[path = "caddyfile_adapter/handler_proxy.rs"]
mod handler_proxy;

#[path = "caddyfile_adapter/proxy_addresses.rs"]
mod proxy_addresses;

#[path = "caddyfile_adapter/proxy_transport.rs"]
mod proxy_transport;

#[path = "caddyfile_adapter/proxy_sources.rs"]
mod proxy_sources;

#[path = "caddyfile_adapter/proxy_shortcuts.rs"]
mod proxy_shortcuts;

#[path = "caddyfile_adapter/log_writers.rs"]
mod log_writers;

#[path = "caddyfile_adapter/log_filters.rs"]
mod log_filters;

#[path = "caddyfile_adapter/log_encoders.rs"]
mod log_encoders;

#[path = "caddyfile_adapter/log_config.rs"]
mod log_config;

#[path = "caddyfile_adapter/log_assembly.rs"]
mod log_assembly;

#[path = "caddyfile_adapter/global_servers.rs"]
mod global_servers;

#[path = "caddyfile_adapter/pdqsort.rs"]
mod pdqsort;

#[path = "caddyfile_adapter/handler_acmeserver.rs"]
mod handler_acmeserver;
