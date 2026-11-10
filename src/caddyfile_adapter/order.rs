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

use super::routes::DEFAULT_ORDER;
use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::dispenser::Dispenser;
use anyhow::Result;

pub(super) const REGISTERED_DIRECTIVES: &[&str] = &[
    "abort",
    "acme_server",
    "basic_auth",
    "basicauth",
    "bind",
    "copy_response",
    "copy_response_headers",
    "encode",
    "error",
    "file_server",
    "forward_auth",
    "fs",
    "handle",
    "handle_errors",
    "handle_path",
    "header",
    "intercept",
    "invoke",
    "log",
    "log_append",
    "log_name",
    "log_skip",
    "map",
    "method",
    "metrics",
    "php_fastcgi",
    "push",
    "redir",
    "request_body",
    "request_header",
    "respond",
    "reverse_proxy",
    "rewrite",
    "root",
    "route",
    "skip_log",
    "templates",
    "timeouts",
    "tls",
    "tracing",
    "try_files",
    "uri",
    "vars",
];

pub(super) fn parse(tokens: &[Token], previous: Option<&[String]>) -> Result<Vec<String>> {
    let mut d = Dispenser::new(tokens.to_vec());
    let mut order: Vec<String> = match previous {
        Some(p) => p.to_vec(),
        None => DEFAULT_ORDER.iter().map(|s| s.to_string()).collect(),
    };

    if !d.next() {
        return Err(d.arg_err());
    } // consume order
    if !d.next() {
        return Err(d.arg_err());
    }
    let dir_name = d.val().to_owned();
    if !REGISTERED_DIRECTIVES.contains(&dir_name.as_str()) {
        return Err(d.error(format!("{} is not a registered directive", dir_name)));
    }

    if !d.next() {
        return Err(d.arg_err());
    }
    let pos = d.val().to_owned();

    order.retain(|d| d != &dir_name);

    match pos.as_str() {
        "first" => {
            order.insert(0, dir_name);
            if d.next_arg() {
                return Err(d.arg_err());
            }
            return Ok(order);
        }
        "last" => {
            order.push(dir_name);
            if d.next_arg() {
                return Err(d.arg_err());
            }
            return Ok(order);
        }
        "before" | "after" => {}
        _ => {
            return Err(d.error(format!("unknown positional '{}'", pos)));
        }
    }

    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let other_dir = d.val().to_owned();
    if d.next_arg() {
        return Err(d.arg_err());
    }

    let target_idx = order
        .iter()
        .position(|x| x == &other_dir)
        .ok_or_else(|| d.error(format!("directive '{}' not found", other_dir)))?;

    let insert_idx = if pos == "after" {
        target_idx + 1
    } else {
        target_idx
    };
    order.insert(insert_idx, dir_name);

    Ok(order)
}
