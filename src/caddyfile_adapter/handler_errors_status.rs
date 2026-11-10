// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use anyhow::{Result, bail};

pub(super) fn expression(args: &[String]) -> Result<Option<String>> {
    if args.is_empty() {
        return Ok(None);
    }

    let mut expr = String::new();
    let mut codes: Vec<&str> = Vec::new();

    for val in args {
        if val.len() != 3 {
            bail!("bad status value '{}'", shown(val));
        }

        if val.ends_with("xx") {
            let prefix = &val[..1];
            if let Err(e) = prefix.parse::<isize>() {
                bail!("bad status value '{}': {}", prefix, e);
            }

            if !expr.is_empty() {
                expr.push_str(" || ");
            }
            expr.push_str(&format!(
                "{{http.error.status_code}} >= {}00 && {{http.error.status_code}} <= {}99",
                prefix, prefix
            ));
            continue;
        }

        if let Err(e) = val.parse::<isize>() {
            bail!("bad status value '{}': {}", val, e);
        }
        codes.push(val.as_str());
    }

    if !codes.is_empty() {
        if !expr.is_empty() {
            expr.push_str(" || ");
        }
        expr.push_str("{http.error.status_code} in [");
        expr.push_str(&codes.join(", "));
        expr.push(']');
    }

    Ok(Some(expr))
}

pub(super) struct Status {
    pub args: usize,
    pub expression: Option<String>,
}
pub(super) fn status(tokens: &[crate::caddyfile_lexer::Token]) -> Result<Status> {
    let mut d = crate::caddyfile_parser::Dispenser::new(tokens.to_vec());
    d.next();
    let args = d.remaining_args();
    let expression = expression(&args).map_err(|e| d.error(e.to_string()))?;
    Ok(Status {
        args: args.len(),
        expression,
    })
}
pub(super) fn expression_matcher(expression: String) -> serde_json::Map<String, serde_json::Value> {
    serde_json::Map::from_iter([("expression".into(), serde_json::Value::String(expression))])
}
fn shown(value: &str) -> String {
    match value.char_indices().nth(32) {
        Some((i, _)) => format!("{}…", value[..i].escape_debug()),
        None => value.escape_debug().to_string(),
    }
}
