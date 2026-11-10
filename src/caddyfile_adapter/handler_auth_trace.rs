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

use crate::caddyfile_parser::Dispenser;
use anyhow::Result;
use serde_json::{Map, Value};

use super::module_value::normalize;
use crate::caddyfile_lexer::Token;

pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Option<Value>> {
    if !["basic_auth", "basicauth", "tracing"].contains(&name) {
        return Ok(None);
    }
    let mut d = Dispenser::new(tokens.to_vec());
    d.next(); // consume directive name

    match name {
        "basic_auth" | "basicauth" => parse_basic_auth(&mut d, name),
        "tracing" => parse_tracing(&mut d),
        _ => Ok(None),
    }
}

fn parse_basic_auth(d: &mut Dispenser, _directive_name: &str) -> Result<Option<Value>> {
    // "basicauth" is deprecated, replaced by "basic_auth"
    // The calling parser emits the compatibility deprecation diagnostic.

    let args = d.remaining_args();

    let hash_name: String;
    let mut realm: Option<String> = None;

    match args.len() {
        0 => {
            hash_name = "bcrypt".to_string();
        }
        1 => {
            hash_name = args[0].clone();
        }
        2 => {
            hash_name = args[0].clone();
            realm = Some(args[1].clone());
        }
        _ => {
            return Err(d.arg_err());
        }
    }

    match hash_name.as_str() {
        "bcrypt" | "argon2id" => {}
        _ => {
            return Err(d.error(format!("unrecognized hash algorithm: {}", hash_name)));
        }
    }

    let mut accounts = Vec::new();

    while d.next_block(0) {
        let username = d.val().to_owned();

        let pwd_arg = d
            .args(1)
            .and_then(|v| v.into_iter().next())
            .unwrap_or_default();
        if d.next_arg() {
            return Err(d.arg_err());
        }

        if username.is_empty() || pwd_arg.is_empty() {
            return Err(d.error("username and password cannot be empty or missing"));
        }

        let mut acc = Map::new();
        acc.insert("username".to_string(), Value::String(username));
        acc.insert("password".to_string(), Value::String(pwd_arg));
        accounts.push(Value::Object(acc));
    }

    let mut hash_map = Map::new();
    hash_map.insert("algorithm".to_string(), Value::String(hash_name));

    let mut http_basic = Map::new();
    http_basic.insert("hash".to_string(), Value::Object(hash_map));
    http_basic.insert("hash_cache".to_string(), Value::Object(Map::new()));

    if let Some(r) = realm
        && !r.is_empty()
    {
        http_basic.insert("realm".to_string(), Value::String(r));
    }

    if !accounts.is_empty() {
        http_basic.insert("accounts".to_string(), Value::Array(accounts));
    }

    let mut providers = Map::new();
    providers.insert("http_basic".to_string(), Value::Object(http_basic));

    let mut result = Map::new();
    result.insert(
        "handler".to_string(),
        Value::String("authentication".to_string()),
    );
    result.insert("providers".to_string(), Value::Object(providers));

    normalize(Value::Object(result)).map(Some)
}

fn parse_tracing(d: &mut Dispenser) -> Result<Option<Value>> {
    if d.next_arg() {
        return Err(d.arg_err());
    }

    let mut span: Option<String> = None;
    let mut span_attributes: Option<Map<String, Value>> = None;

    while d.next_block(0) {
        let key = d.val().to_owned();
        match key.as_str() {
            "span_attributes" => {
                if span_attributes.is_none() {
                    span_attributes = Some(Map::new());
                }
                let attrs_map = span_attributes.as_mut().unwrap();
                while d.next_block(1) {
                    let attr_key = d.val().to_owned();
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    let attr_val = d.val().to_owned();
                    if d.next_arg() {
                        return Err(d.arg_err());
                    }
                    attrs_map.insert(attr_key, Value::String(attr_val));
                }
            }
            "span" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                span = Some(d.val().to_owned());
                if d.next_arg() {
                    return Err(d.arg_err());
                }
            }
            _ => {
                return Err(d.arg_err());
            }
        }
    }

    let mut result = Map::new();
    result.insert("handler".to_string(), Value::String("tracing".to_string()));
    result.insert("span".to_string(), Value::String(span.unwrap_or_default()));

    if let Some(attrs) = span_attributes
        && !attrs.is_empty()
    {
        result.insert("span_attributes".to_string(), Value::Object(attrs));
    }

    normalize(Value::Object(result)).map(Some)
}
