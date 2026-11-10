// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
use crate::caddyfile_lexer::Token;
use crate::caddyfile_parser::Dispenser;
use anyhow::{Result, anyhow};
use serde_json::{Map, Value, json};

pub(super) fn parse(tokens: &[Token]) -> Result<Value> {
    let mut d = Dispenser::new(tokens.to_vec());

    // Consume directive name
    d.next();

    // Handle initial args
    let remaining_args = d.remaining_args();
    let mut browse_config: Option<BrowseConfig> = None;

    match remaining_args.len() {
        0 => {}
        1 => {
            if remaining_args[0] == "browse" {
                browse_config = Some(BrowseConfig::default());
            } else {
                return Err(anyhow!("unexpected argument: {}", remaining_args[0]));
            }
        }
        _ => return Err(anyhow!("unexpected number of arguments")),
    }

    // Prepare result map
    let mut result = Map::new();
    let mut fs_value: Option<String> = None;
    let mut root_value: Option<String> = None;
    let mut hide_list: Vec<String> = Vec::new();
    let mut index_names: Vec<String> = Vec::new();
    let mut precompressed_order: Option<Vec<String>> = None;
    let mut precompressed_raw: Map<String, Value> = Map::new();
    let mut status_code: Option<WeakString> = None;
    let mut canonical_uris: Option<bool> = None;
    let mut pass_thru: bool = false;
    let mut etag_file_extensions: Vec<String> = Vec::new();

    let nesting = d.nesting();
    while d.next_block(nesting) {
        let key = d.val();

        match key {
            "fs" => {
                if !d.next_arg() {
                    return Err(anyhow!("fs: expected argument"));
                }
                let val = d.val().to_owned();
                if fs_value.is_some() {
                    return Err(anyhow!("file system already specified"));
                }
                fs_value = (!val.is_empty()).then_some(val);
            }
            "hide" => {
                let h = d.remaining_args();
                if h.is_empty() {
                    return Err(anyhow!("hide: expected arguments"));
                }
                hide_list.extend(h);
            }
            "index" => {
                let inames = d.remaining_args();
                if inames.is_empty() {
                    return Err(anyhow!("index: expected arguments"));
                }
                index_names = inames;
            }
            "root" => {
                if !d.next_arg() {
                    return Err(anyhow!("root: expected argument"));
                }
                let val = d.val().to_owned();
                root_value = (!val.is_empty()).then_some(val);
            }
            "browse" => {
                if browse_config.is_some() {
                    return Err(anyhow!("browsing is already configured"));
                }
                let mut bc = BrowseConfig::default();

                // Optional template_file arg
                if d.next_arg() {
                    let t = d.val().to_owned();
                    if !t.is_empty() {
                        bc.template_file = Some(t);
                    }
                }

                let inner_nesting = d.nesting();
                while d.next_block(inner_nesting) {
                    match d.val() {
                        "reveal_symlinks" => {
                            if bc.reveal_symlinks {
                                return Err(anyhow!("Symlinks path reveal is already enabled"));
                            }
                            bc.reveal_symlinks = true;
                        }
                        "sort" => {
                            while d.next_arg() {
                                let s = d.val().to_owned();
                                match s.as_str() {
                                    "name" | "namedirfirst" | "size" | "time" | "asc" | "desc" => {
                                        bc.sort_options.push(s);
                                    }
                                    _ => return Err(anyhow!("unknown sort option '{}'", s)),
                                }
                            }
                        }
                        "file_limit" => {
                            let args = d.remaining_args();
                            if args.len() != 1 {
                                return Err(anyhow!("file_limit should have an integer value"));
                            }
                            let limit: isize = args[0]
                                .parse()
                                .map_err(|_| anyhow!("file_limit should have an integer value"))?;
                            if bc.file_limit != 0 {
                                return Err(anyhow!("file_limit is already enabled"));
                            }
                            bc.file_limit = limit;
                        }
                        _ => {
                            return Err(anyhow!("unknown subdirective '{}'", d.val()));
                        }
                    }
                }
                browse_config = Some(bc);
            }
            "precompressed" => {
                let mut args = d.remaining_args();
                if args.is_empty() {
                    args = vec!["br".to_string(), "zstd".to_string(), "gzip".to_string()];
                }

                for format in &args {
                    match format.as_str() {
                        "br" | "zstd" | "gzip" => {
                            precompressed_raw.insert(format.clone(), json!({}));
                        }
                        _ => return Err(anyhow!("unsupported precompressed format: {}", format)),
                    }
                }
                precompressed_order = Some(args);
            }
            "status" => {
                if !d.next_arg() {
                    return Err(anyhow!("status: expected argument"));
                }
                let val = d.val().to_owned();
                status_code = (!val.is_empty()).then_some(WeakString(val));
            }
            "disable_canonical_uris" => {
                if d.next_arg() {
                    return Err(anyhow!("disable_canonical_uris: unexpected argument"));
                }
                canonical_uris = Some(false);
            }
            "pass_thru" => {
                if d.next_arg() {
                    return Err(anyhow!("pass_thru: unexpected argument"));
                }
                pass_thru = true;
            }
            "etag_file_extensions" => {
                let exts = d.remaining_args();
                if exts.is_empty() {
                    return Err(anyhow!("etag_file_extensions: expected arguments"));
                }
                etag_file_extensions = exts;
            }
            _ => {
                return Err(anyhow!("unknown subdirective '{}'", key));
            }
        }
    }

    result.insert(
        "handler".to_string(),
        Value::String("file_server".to_string()),
    );

    if let Some(fs) = fs_value {
        result.insert("fs".to_string(), Value::String(fs));
    }
    if let Some(root) = root_value {
        result.insert("root".to_string(), Value::String(root));
    }
    if !hide_list.is_empty() {
        result.insert(
            "hide".to_string(),
            Value::Array(hide_list.into_iter().map(Value::String).collect()),
        );
    }
    if !index_names.is_empty() {
        result.insert(
            "index_names".to_string(),
            Value::Array(index_names.into_iter().map(Value::String).collect()),
        );
    }

    if let Some(bc) = browse_config {
        let mut browse_map = Map::new();
        if let Some(t) = bc.template_file {
            browse_map.insert("template_file".to_string(), Value::String(t));
        }
        if bc.reveal_symlinks {
            browse_map.insert("reveal_symlinks".to_string(), Value::Bool(true));
        }
        if !bc.sort_options.is_empty() {
            browse_map.insert(
                "sort".to_string(),
                Value::Array(bc.sort_options.into_iter().map(Value::String).collect()),
            );
        }
        if bc.file_limit != 0 {
            browse_map.insert("file_limit".to_string(), Value::from(bc.file_limit));
        }
        result.insert("browse".to_string(), Value::Object(browse_map));
    }

    if let Some(order) = precompressed_order {
        result.insert(
            "precompressed_order".to_string(),
            Value::Array(order.into_iter().map(Value::String).collect()),
        );
    }
    if !precompressed_raw.is_empty() {
        result.insert(
            "precompressed".to_string(),
            Value::Object(precompressed_raw),
        );
    }

    if let Some(sc) = status_code {
        result.insert("status_code".to_string(), sc.to_json()?);
    }
    if let Some(c) = canonical_uris {
        result.insert("canonical_uris".to_string(), Value::Bool(c));
    }
    if pass_thru {
        result.insert("pass_thru".to_string(), Value::Bool(true));
    }
    if !etag_file_extensions.is_empty() {
        result.insert(
            "etag_file_extensions".to_string(),
            Value::Array(
                etag_file_extensions
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    let val = Value::Object(result);
    super::module_value::normalize(val)
}

#[derive(Default)]
struct BrowseConfig {
    template_file: Option<String>,
    reveal_symlinks: bool,
    sort_options: Vec<String>,
    file_limit: isize,
}

struct WeakString(String);

impl WeakString {
    fn to_json(&self) -> Result<Value> {
        if self.0 == "true" {
            Ok(Value::Bool(true))
        } else if self.0 == "false" {
            Ok(Value::Bool(false))
        } else if let Ok(i) = self.0.parse::<isize>() {
            Ok(Value::from(i))
        } else {
            Ok(Value::String(self.0.clone()))
        }
    }
}
