// Copyright 2015 Matthew Holt and The Caddy Authors.
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

use anyhow::Result;
use serde_json::{Map, Value};

use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::Dispenser;

pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    let mut pattern = String::new();
    let mut base_url = String::new();
    let mut ignore_case = false;

    while d.next() {
        if let Some(args) = d.args(1) {
            pattern = args[0].clone();
        } else {
            return Err(d.error("expected exactly one URL pattern".to_string()));
        }

        while d.next_block(0) {
            let key = d.val();
            match key {
                "base_url" => {
                    if let Some(args) = d.args(1) {
                        base_url = args[0].clone();
                    } else {
                        return Err(d.arg_err());
                    }
                }
                "ignore_case" => {
                    if d.next_arg() {
                        return Err(d.arg_err());
                    }
                    ignore_case = true;
                }
                _ => {
                    return Err(d.error(format!("unrecognized url_pattern option '{}'", key)));
                }
            }
        }
    }

    let mut map = Map::new();
    if !pattern.is_empty() {
        map.insert("pattern".to_string(), Value::String(pattern));
    }
    if !base_url.is_empty() {
        map.insert("base_url".to_string(), Value::String(base_url));
    }
    if ignore_case {
        map.insert("ignore_case".to_string(), Value::Bool(true));
    }
    Ok(Value::Object(map))
}
