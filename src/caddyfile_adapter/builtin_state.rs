// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::module_value::normalize;
use super::named_matchers::{Definitions, extract};
use super::routes::Route;
use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::Dispenser;
use anyhow::Result;
use serde_json::{Map, Value, json};

pub(super) struct Bind {
    pub addresses: Vec<String>,
    pub protocols: Vec<String>,
}

pub(super) fn bind(tokens: &[Token], global_default: bool) -> Result<Bind> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut addresses = d.remaining_args();
    let mut protocols = Vec::new();

    if global_default && addresses.is_empty() {
        addresses.push(String::new());
    }

    while d.next_block(0) {
        match d.val() {
            "protocols" => {
                protocols = d.remaining_args();
                if protocols.is_empty() {
                    return Err(d.error("protocols requires one or more arguments"));
                }
            }
            _ => {
                return Err(d.error(format!("unknown subdirective: {}", d.val())));
            }
        }
    }

    Ok(Bind {
        addresses,
        protocols,
    })
}

pub(super) struct RootValue {
    pub route: Route,
}

pub(super) fn root(tokens: &[Token], defs: &Definitions) -> Result<RootValue> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();

    let args_count = d.count_remaining_args();
    if args_count == 0 {
        return Err(d.error("too few arguments; must have at least a root path"));
    }
    if args_count > 2 {
        return Err(d.error("too many arguments; should only be a matcher and a path"));
    }

    if args_count == 1 {
        if !d.next_arg() {
            return Err(d.arg_err());
        }
        let rootpath = d.val().to_string();

        // normalize json!({"handler":"vars","root":rootpath})
        let handler_val = normalize(json!({"handler": "vars", "root": rootpath}))?;

        let handlers = vec![handler_val];

        return Ok(RootValue {
            route: Route {
                matchers: Vec::new(),
                handlers,
                group: String::new(),
                terminal: false,
            },
        });
    }

    // args_count == 2
    let user_matcher_set = extract(tokens, defs)?;
    let (matcher_map, remaining) = user_matcher_set;
    d = Dispenser::new(remaining);
    d.next();

    if !d.next_arg() {
        return Err(d.arg_err());
    }

    let rootpath = d.val().to_string();

    // matcher Some(emptyMap) adds one map; None adds empty vec
    let matchers: Vec<Map<String, Value>> = match matcher_map {
        Some(m) => vec![m],
        None => Vec::new(),
    };

    let handler_val = normalize(json!({"handler": "vars", "root": rootpath}))?;

    Ok(RootValue {
        route: Route {
            matchers,
            handlers: vec![handler_val],
            group: String::new(),
            terminal: false,
        },
    })
}
