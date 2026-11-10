// Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

/// Handler directives only: their optional matcher was removed by the wrapper.
pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Option<Value>> {
    if !matches!(name, "method" | "uri") {
        return Ok(None);
    }
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut value = Map::new();
    if name == "method" {
        if !d.next_arg() {
            return Err(d.arg_err());
        }
        let method = d.val().to_owned();
        if d.next_arg() {
            return Err(d.arg_err());
        }
        string(&mut value, "method", &method);
    } else {
        let args = d.remaining_args();
        let Some(op) = args.first() else {
            return Err(d.arg_err());
        };
        match op.as_str() {
            "strip_prefix" | "strip_suffix" => {
                if args.len() != 2 {
                    return Err(d.arg_err());
                }
                string(
                    &mut value,
                    if op == "strip_prefix" {
                        "strip_path_prefix"
                    } else {
                        "strip_path_suffix"
                    },
                    &args[1],
                );
            }
            "replace" => {
                if !(3..=4).contains(&args.len()) {
                    return Err(d.arg_err());
                }
                let limit = match args.get(3).filter(|s| !s.is_empty()) {
                    None => 0,
                    Some(s) => s
                        .parse::<isize>()
                        .map_err(|_| d.error("limit must be an integer"))?,
                };
                let mut replacement = Map::new();
                string(&mut replacement, "find", &args[1]);
                string(&mut replacement, "replace", &args[2]);
                if limit != 0 {
                    replacement.insert("limit".into(), (limit as i64).into());
                }
                value.insert(
                    "uri_substring".into(),
                    Value::Array(vec![replacement.into()]),
                );
            }
            "path_regexp" => {
                if args.len() != 3 {
                    return Err(d.arg_err());
                }
                let mut replacement = Map::new();
                string(&mut replacement, "find", &args[1]);
                string(&mut replacement, "replace", &args[2]);
                value.insert("path_regexp".into(), Value::Array(vec![replacement.into()]));
            }
            "query" => {
                if args.len() > 4 {
                    return Err(d.arg_err());
                }
                let mut query = Map::new();
                let has_args = args.len() > 1;
                if has_args {
                    query_op(&d, &mut query, &args[1..])?;
                }
                while d.next_block(0) {
                    if has_args {
                        return Err(d.error(
                            "cannot specify uri query rewrites in both argument and block",
                        ));
                    }
                    let mut line = vec![d.val().to_owned()];
                    line.extend(d.remaining_args());
                    query_op(&d, &mut query, &line)?;
                }
                value.insert("query".into(), query.into());
            }
            _ => return Err(d.error(format!("unrecognized URI manipulation '{op}'"))),
        }
    }
    value.insert("handler".into(), "rewrite".into());
    super::module_value::normalize(value.into()).map(Some)
}

fn query_op(d: &Dispenser, query: &mut Map<String, Value>, args: &[String]) -> Result<()> {
    let key = &args[0];
    let (kind, item) = if key.starts_with('-') {
        if args.len() != 1 {
            return Err(d.arg_err());
        }
        (
            "delete",
            Value::String(key.trim_start_matches('-').to_owned()),
        )
    } else if key.starts_with('+') {
        if args.len() != 2 {
            return Err(d.arg_err());
        }
        ("add", argument(key.trim_start_matches('+'), &args[1]))
    } else if key.contains('>') {
        if args.len() != 1 {
            return Err(d.arg_err());
        }
        // Go strings.Split uses only its first two entries, including empties.
        let mut parts = key.split('>');
        (
            "rename",
            argument(parts.next().unwrap(), parts.next().unwrap()),
        )
    } else if args.len() == 3 {
        let mut replacement = Map::new();
        string(&mut replacement, "key", key);
        string(&mut replacement, "search_regexp", &args[1]);
        string(&mut replacement, "replace", &args[2]);
        ("replace", replacement.into())
    } else {
        if args.len() != 2 {
            return Err(d.arg_err());
        }
        ("set", argument(key, &args[1]))
    };
    let values = query
        .entry(kind)
        .or_insert_with(|| Value::Array(Vec::new()));
    // Only this function inserts these entries, always as arrays.
    values
        .as_array_mut()
        .expect("query operations array")
        .push(item);
    Ok(())
}

fn argument(key: &str, value: &str) -> Value {
    let mut result = Map::new();
    string(&mut result, "key", key);
    string(&mut result, "val", value);
    result.into()
}

fn string(map: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.to_owned(), Value::String(value.to_owned()));
    }
}
