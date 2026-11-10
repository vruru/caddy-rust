// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::{caddyfile_lexer::Token, caddyfile_parser::Dispenser};
use anyhow::{Result, bail};
use serde_json::{Map, Value};
pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut args = d.remaining_args();
    let mut encodings = Map::new();
    let mut prefer = Vec::new();
    let mut object = Map::new();
    object.insert("handler".into(), "encode".into());
    let mut matcher = None;
    while d.next_block(0) {
        match d.val() {
            "minimum_length" => {
                if !d.next_arg() {
                    return Err(d.arg_err());
                }
                let length = d.val().parse::<isize>()?;
                object.remove("minimum_length");
                if length != 0 {
                    object.insert("minimum_length".into(), length.into());
                }
            }
            "match" => {
                if matcher.is_some() {
                    bail!("matcher is defined more than once: match");
                }
                matcher = Some(super::response_matcher::parse(&d.next_segment())?);
            }
            name => {
                let name = name.to_owned();
                let value = encoder(&name, &d.next_segment())?;
                encodings.insert(name.clone(), value);
                prefer.push(name);
            }
        }
    }
    if prefer.is_empty() && args.is_empty() {
        args = vec!["zstd".into(), "gzip".into()];
    }
    for name in args {
        if !["zstd", "gzip"].contains(&name.as_str()) {
            bail!("unknown HTTP encoder module: {name}");
        }
        encodings.insert(name.clone(), Value::Object(Map::new()));
        prefer.push(name);
    }
    if !encodings.is_empty() {
        object.insert("encodings".into(), Value::Object(encodings));
    }
    if !prefer.is_empty() {
        object.insert(
            "prefer".into(),
            prefer.into_iter().map(Value::String).collect(),
        );
    }
    if let Some(matcher) = matcher {
        object.insert("match".into(), matcher);
    }
    super::module_value::normalize(Value::Object(object))
}
fn encoder(name: &str, tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());
    d.next();
    let mut object = Map::new();
    match name {
        "gzip" => {
            if d.next_arg() {
                let level = d.val().parse::<isize>()?;
                if level != 0 {
                    object.insert("level".into(), level.into());
                }
            }
        }
        "zstd" => {
            let args = d.remaining_args();
            if args.len() > 1 {
                return Err(d.arg_err());
            }
            if let Some(level) = args.first() {
                validate_level(level)?;
                if !level.is_empty() {
                    object.insert("level".into(), level.clone().into());
                }
            }
            while d.next_block(0) {
                match d.val() {
                    "level" => {
                        let args = d.remaining_args();
                        if args.len() != 1 {
                            return Err(d.arg_err());
                        }
                        if object.contains_key("level") {
                            bail!("compression level already specified");
                        }
                        validate_level(&args[0])?;
                        if !args[0].is_empty() {
                            object.insert("level".into(), args[0].clone().into());
                        }
                    }
                    "disable_checksum" => {
                        if d.next_arg() {
                            return Err(d.arg_err());
                        }
                        if object.contains_key("checksum") {
                            bail!("checksum already specified");
                        }
                        object.insert("checksum".into(), false.into());
                    }
                    name => bail!("unknown zstd subdirective '{name}'"),
                }
            }
        }
        _ => bail!("unknown HTTP encoder module: {name}"),
    }
    Ok(Value::Object(object))
}
fn validate_level(level: &str) -> Result<()> {
    if !["fastest", "better", "best", "default"].iter().any(|s| {
        level
            .chars()
            .map(|c| match c {
                'ſ' => 's',
                'K' => 'k',
                c => c.to_ascii_lowercase(),
            })
            .eq(s.chars())
    }) {
        bail!("unexpected compression level {level}");
    }
    Ok(())
}
