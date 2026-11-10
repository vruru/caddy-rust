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

use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut root = String::new();
    let mut files: Vec<String> = Vec::new();
    let mut policy = String::new();
    let mut splits: Vec<String> = Vec::new();

    let mut d = Dispenser::new(tokens.to_vec());
    while d.next() {
        files.extend(d.remaining_args());
        while d.next_block(0) {
            match d.val() {
                "root" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    root = d.val().to_string();
                }
                "try_files" => {
                    files.extend(d.remaining_args());
                    if files.is_empty() {
                        return Err(d.arg_err());
                    }
                }
                "try_policy" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    policy = d.val().to_string();
                }
                "split_path" => {
                    splits = d.remaining_args();
                    if splits.is_empty() {
                        return Err(d.arg_err());
                    }
                }
                _ => {
                    return Err(d.error(format!("unrecognized subdirective: {}", d.val())));
                }
            }
        }
    }

    let mut map = Map::new();
    if !root.is_empty() {
        map.insert("root".to_string(), Value::String(root));
    }
    if !policy.is_empty() {
        map.insert("try_policy".to_string(), Value::String(policy));
    }
    if !files.is_empty() {
        map.insert(
            "try_files".to_string(),
            Value::Array(files.into_iter().map(Value::String).collect()),
        );
    }
    if !splits.is_empty() {
        map.insert(
            "split_path".to_string(),
            Value::Array(splits.into_iter().map(Value::String).collect()),
        );
    }
    Ok(Value::Object(map))
}
