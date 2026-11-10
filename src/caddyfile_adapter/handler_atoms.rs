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

use anyhow::Result;
use serde_json::{Map, Value};

use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::dispenser::Dispenser;

pub(super) fn parse(name: &str, tokens: &[Token]) -> Result<Option<Value>> {
    match name {
        "respond" => parse_respond(tokens).map(Some),
        "abort" => parse_abort(tokens).map(Some),
        "error" => parse_error(tokens).map(Some),
        "fs" => parse_fs(tokens).map(Some),
        "vars" => parse_vars(tokens).map(Some),
        _ => Ok(None),
    }
}

fn weak_string_to_value(ws: &str) -> Value {
    if ws == "true" {
        Value::Bool(true)
    } else if ws == "false" {
        Value::Bool(false)
    } else if let Ok(num) = ws.parse::<isize>() {
        Value::from(num as i64)
    } else {
        Value::String(ws.to_string())
    }
}

fn parse_respond(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());

    d.next();

    let args = d.remaining_args();
    let mut body = String::new();
    let mut status_code_opt: Option<String> = None;
    let mut close = false;

    match args.len() {
        1 => {
            if args[0].len() == 3 {
                if let Ok(num) = args[0].parse::<isize>() {
                    if num > 0 {
                        status_code_opt = Some(args[0].clone());
                    } else {
                        body = args[0].clone();
                    }
                } else {
                    body = args[0].clone();
                }
            } else {
                body = args[0].clone();
            }
        }
        2 => {
            body = args[0].clone();
            status_code_opt = Some(args[1].clone());
        }
        _ => {
            return Err(d.arg_err());
        }
    }

    while d.next_block(0) {
        let val = d.val().to_owned();
        match val.as_str() {
            "body" => {
                if !body.is_empty() {
                    return Err(d.error("body already specified"));
                }
                match d.all_args(1) {
                    Some(v) => {
                        body = v[0].clone();
                    }
                    None => return Err(d.arg_err()),
                }
            }
            "close" => {
                if close {
                    return Err(d.error("close already specified"));
                }
                close = true;
            }
            _ => {
                return Err(d.error(format!("unrecognized subdirective '{}'", val)));
            }
        }
    }

    let mut map = Map::new();
    map.insert(
        "handler".to_string(),
        Value::String("static_response".to_string()),
    );

    if !body.is_empty() {
        map.insert("body".to_string(), Value::String(body));
    }

    if let Some(sc) = status_code_opt.filter(|s| !s.is_empty()) {
        map.insert("status_code".to_string(), weak_string_to_value(&sc));
    }

    if close {
        map.insert("close".to_string(), Value::Bool(true));
    }

    super::module_value::normalize(Value::Object(map))
}

fn parse_abort(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());

    d.next();

    if d.next() {
        return Err(d.arg_err());
    }

    if d.next_block(0) {
        return Err(d.arg_err());
    }

    let mut map = Map::new();
    map.insert(
        "handler".to_string(),
        Value::String("static_response".to_string()),
    );
    map.insert("abort".to_string(), Value::Bool(true));

    super::module_value::normalize(Value::Object(map))
}

fn parse_error(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());

    d.next();

    let args = d.remaining_args();
    let mut error_msg = String::new();
    let mut status_code_opt: Option<String> = None;

    match args.len() {
        1 => {
            if args[0].len() == 3 {
                if let Ok(num) = args[0].parse::<isize>() {
                    if num > 0 {
                        status_code_opt = Some(args[0].clone());
                    } else {
                        error_msg = args[0].clone();
                    }
                } else {
                    error_msg = args[0].clone();
                }
            } else {
                error_msg = args[0].clone();
            }
        }
        2 => {
            error_msg = args[0].clone();
            status_code_opt = Some(args[1].clone());
        }
        _ => {
            return Err(d.arg_err());
        }
    }

    while d.next_block(0) {
        let val = d.val().to_owned();
        match val.as_str() {
            "message" => {
                if !error_msg.is_empty() {
                    return Err(d.error("message already specified"));
                }
                match d.all_args(1) {
                    Some(v) => {
                        error_msg = v[0].clone();
                    }
                    None => return Err(d.arg_err()),
                }
            }
            _ => {
                return Err(d.error(format!("unrecognized subdirective '{}'", val)));
            }
        }
    }

    let mut map = Map::new();
    map.insert("handler".to_string(), Value::String("error".to_string()));

    if !error_msg.is_empty() {
        map.insert("error".to_string(), Value::String(error_msg));
    }

    if let Some(sc) = status_code_opt.filter(|s| !s.is_empty()) {
        map.insert("status_code".to_string(), weak_string_to_value(&sc));
    }

    super::module_value::normalize(Value::Object(map))
}

fn parse_fs(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());

    d.next();

    if !d.next_arg() {
        return Err(d.arg_err());
    }

    if d.next_arg() {
        return Err(d.arg_err());
    }

    let val = d.val().to_owned();

    let mut vars_map = Map::new();
    vars_map.insert("fs".to_string(), Value::String(val));

    let mut map = vars_map;
    map.insert("handler".to_string(), Value::String("vars".to_string()));

    super::module_value::normalize(Value::Object(map))
}

// Non-finite ScalarVal values fail here: Go adapts with a warning and a null
// handler which its runtime rejects; native reports the unusable config early.
fn parse_vars(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());

    d.next();

    let mut vars_map = Map::new();

    if d.next_arg() {
        let var_name = d.val().to_owned();

        if !d.next_arg() {
            return Err(d.arg_err());
        }

        let var_val = d.scalar_val()?;

        if d.next_arg() {
            return Err(d.arg_err());
        }

        vars_map.insert(var_name, var_val.unwrap_or(Value::Null));
    }

    while d.next_block(0) {
        let var_name = d.val().to_owned();

        if !d.next_arg() {
            return Err(d.arg_err());
        }

        let var_val = d.scalar_val()?;

        if d.next_arg() {
            return Err(d.arg_err());
        }

        vars_map.insert(var_name, var_val.unwrap_or(Value::Null));
    }

    let mut map = vars_map;
    map.insert("handler".to_string(), Value::String("vars".to_string()));

    super::module_value::normalize(Value::Object(map))
}
