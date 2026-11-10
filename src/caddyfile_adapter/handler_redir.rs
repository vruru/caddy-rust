// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::Result;
use serde_json::{Map, Value};

const META_REDIR: &str = "<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<title>Redirecting...</title>\n\t\t<script>window.location.replace(\"%s\");</script>\n\t\t<meta http-equiv=\"refresh\" content=\"0; URL='%s'\">\n\t</head>\n\t<body>Redirecting to <a href=\"%s\">%s</a>...</body>\n</html>\n";

fn html_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    let to = d.val().to_owned();

    let mut code = if d.next_arg() {
        d.val().to_owned()
    } else {
        String::new()
    };

    let mut body = String::new();
    let mut hdr_keys = Vec::new();
    let mut hdr_vals: Vec<Vec<String>> = Vec::new();

    match code.as_str() {
        "permanent" => {
            code = "301".to_owned();
        }
        "temporary" | "" => {
            code = "302".to_owned();
        }
        "html" => {
            let safe_to = html_escape_string(&to);
            body = META_REDIR.replace("%s", &safe_to);
            hdr_keys.push("Content-Type".to_owned());
            hdr_vals.push(vec!["text/html; charset=utf-8".to_owned()]);
            code = "200".to_owned();
        }
        _ => {
            if code.starts_with('{') {
                // placeholder
            } else {
                match code.parse::<isize>() {
                    Ok(code_int) => {
                        if code_int < 300 || (code_int > 399 && code_int != 401) {
                            return Err(d.error(format!(
                                "Redir code not in the 3xx range or 401: '{code_int}'"
                            )));
                        }
                    }
                    Err(_) => {
                        return Err(d.error(format!(
                            "Not a supported redir code type or not valid integer: '{code}'"
                        )));
                    }
                }
            }
        }
    }

    if code != "200" {
        hdr_keys.clear();
        hdr_vals.clear();
        hdr_keys.push("Location".to_owned());
        hdr_vals.push(vec![to]);
    }

    let mut headers_map = Map::new();
    for (k, v) in hdr_keys.into_iter().zip(hdr_vals) {
        headers_map.insert(k, Value::Array(v.into_iter().map(Value::String).collect()));
    }

    let mut map = Map::new();
    map.insert(
        "handler".to_owned(),
        Value::String("static_response".to_owned()),
    );

    if code == "true" {
        map.insert("status_code".to_owned(), Value::Bool(true));
    } else if code == "false" {
        map.insert("status_code".to_owned(), Value::Bool(false));
    } else {
        match code.parse::<isize>() {
            Ok(n) => map.insert("status_code".to_owned(), Value::Number((n as i64).into())),
            Err(_) => map.insert("status_code".to_owned(), Value::String(code)),
        };
    }

    if !headers_map.is_empty() {
        map.insert("headers".to_owned(), Value::Object(headers_map));
    }

    if !body.is_empty() {
        map.insert("body".to_owned(), Value::String(body));
    }

    super::module_value::normalize(map.into())
}
