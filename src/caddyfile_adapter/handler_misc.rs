// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Option<Value>> {
    if name != "templates" && name != "push" {
        return Ok(None);
    }

    let mut d = Dispenser::new(tokens.to_vec());
    d.next(); // consume directive name

    let mut value = Map::new();
    value.insert("handler".into(), name.into());

    match name {
        // ----------------------------------------------------------------
        // templates { mime … / between … / root … / extensions {} }
        // ----------------------------------------------------------------
        "templates" => {
            // Preserve the source cursor: extra first-line tokens also
            // prevent NextBlock from entering a following block.

            while d.next_block(0) {
                match d.val() {
                    "mime" => {
                        let types = d.remaining_args();
                        if types.is_empty() {
                            return Err(d.arg_err());
                        }
                        value.insert(
                            "mime_types".into(),
                            Value::Array(types.into_iter().map(Value::String).collect()),
                        );
                    }
                    "between" => {
                        let delims = d.remaining_args();
                        if delims.len() != 2 {
                            return Err(d.arg_err());
                        }
                        value.insert(
                            "delimiters".into(),
                            Value::Array(delims.into_iter().map(Value::String).collect()),
                        );
                    }
                    "root" => {
                        if !d.next_arg() {
                            return Err(d.arg_err());
                        }
                        let root = d.val().to_owned();
                        // Leave remaining tokens for the outer NextBlock.
                        value.remove("file_root");
                        if !root.is_empty() {
                            value.insert("file_root".into(), Value::String(root));
                        }
                    }
                    "extensions" => {
                        // No args on the keyword line itself.
                        if d.next_arg() {
                            return Err(d.arg_err());
                        }
                        // Open nested block.
                        // Standard Caddy ships no template-function modules;
                        // an empty block {} is accepted (loop body never runs).
                        // Any named extension is an unknown-module error.
                        if d.next_block(1) {
                            return Err(d.error(format!("getting module named 'http.handlers.templates.functions.{}': module not registered", d.val())));
                        }
                    }
                    _ => {
                        // Unknown subdirectives deliberately ignored (no default).
                    }
                }
            }
        }

        // ----------------------------------------------------------------
        // push [<resource>] { GET/HEAD <res> / <res> / headers {…} }
        // ----------------------------------------------------------------
        "push" => {
            // Consume only the first inline resource, as the source does.
            let mut resources: Vec<Value> = Vec::new();

            if d.next_arg() {
                let mut res = Map::new();
                if !d.val().is_empty() {
                    res.insert("target".into(), d.val().into());
                }
                resources.push(Value::Object(res));
                // Do not advance over additional tokens.
            }

            // Ops allocated lazily on first header entry; headers{} empty → field omitted.
            let mut ops: Option<super::handler_headers::Ops> = None;

            while d.next_block(0) {
                match d.val() {
                    "headers" => {
                        // No args on the "headers" keyword line.
                        if d.next_arg() {
                            return Err(d.arg_err());
                        }
                        // Nested block: each line is one header operation.
                        while d.next_block(1) {
                            // h.Val() is the field; RemainingArgs() are value / replacement.
                            let field = d.val().to_owned();
                            let rest = d.remaining_args();
                            let total = 1 + rest.len(); // must be 1..=3

                            if total > 3 {
                                return Err(d.arg_err());
                            }

                            if ops.is_none() {
                                ops = Some(super::handler_headers::Ops::default());
                            }
                            let o = ops.as_mut().unwrap();

                            match rest.len() {
                                0 => {
                                    o.apply(false, &field, "", None)
                                        .map_err(|e| d.error(e.to_string()))?;
                                }
                                1 => {
                                    o.apply(false, &field, &rest[0], None)
                                        .map_err(|e| d.error(e.to_string()))?;
                                }
                                _ => {
                                    // 2 remaining → field + value + replacement
                                    o.apply(false, &field, &rest[0], Some(rest[1].clone()))
                                        .map_err(|e| d.error(e.to_string()))?;
                                }
                            }
                        }
                    }

                    "GET" | "HEAD" => {
                        let method = d.val().to_owned();
                        if !d.next_arg() {
                            return Err(d.arg_err());
                        }
                        let target = d.val().to_owned();
                        // Additional block tokens are separate resources.

                        let mut res = Map::new();
                        res.insert("method".into(), Value::String(method));
                        if !target.is_empty() {
                            res.insert("target".into(), Value::String(target));
                        }
                        resources.push(Value::Object(res));
                    }

                    _ => {
                        // Any other token is a target; keep source cursor behavior.
                        let mut res = Map::new();
                        if !d.val().is_empty() {
                            res.insert("target".into(), d.val().into());
                        }
                        resources.push(Value::Object(res));
                    }
                }
            }

            if !resources.is_empty() {
                value.insert("resources".into(), Value::Array(resources));
            }

            if let Some(o) = ops {
                value.insert("headers".into(), o.value(false));
            }
        }

        _ => unreachable!(),
    }

    super::module_value::normalize(Value::Object(value)).map(Some)
}
