use anyhow::{Result, bail, ensure};
use serde_json::{Map, Value, json};

pub(super) fn matcher_data(name: &str, data: Value, default_name: &str) -> Result<Option<Value>> {
    match name {
        "host_match_request_list" => {
            ensure!(data.is_array(), "host_match_request_list expects array");
            let arr = data.as_array().unwrap();
            for v in arr {
                ensure!(v.is_string(), "list elements must be string");
            }
            Ok(Some(json!({"host": arr})))
        }
        "path_match_request_list" => {
            ensure!(data.is_array(), "path_match_request_list expects array");
            let arr = data.as_array().unwrap();
            for v in arr {
                ensure!(v.is_string(), "list elements must be string");
            }
            Ok(Some(json!({"path": arr})))
        }
        "method_request_list" => {
            ensure!(data.is_array(), "method_request_list expects array");
            let arr = data.as_array().unwrap();
            for v in arr {
                ensure!(v.is_string(), "list elements must be string");
            }
            Ok(Some(json!({"method": arr})))
        }
        "remote_ip_match_request_list" => {
            ensure!(
                data.is_array(),
                "remote_ip_match_request_list expects array"
            );
            let arr = data.as_array().unwrap();
            for v in arr {
                ensure!(v.is_string(), "list elements must be string");
            }
            Ok(Some(json!({"remote_ip": {"ranges": arr}})))
        }
        "client_ip_match_request_list" => {
            ensure!(
                data.is_array(),
                "client_ip_match_request_list expects array"
            );
            let arr = data.as_array().unwrap();
            for v in arr {
                ensure!(v.is_string(), "list elements must be string");
            }
            Ok(Some(json!({"client_ip": {"ranges": arr}})))
        }
        "protocol_request_string" => {
            ensure!(data.is_string(), "protocol_request_string expects string");
            Ok(Some(json!({"protocol": data.as_str().unwrap()})))
        }
        "query_matcher_request_map" => {
            ensure!(data.is_object(), "query_matcher_request_map expects map");
            let m = data.as_object().unwrap();
            let mut out_map = Map::new();
            for (k, v) in m {
                if v.is_string() {
                    out_map.insert(k.clone(), json!([v.as_str().unwrap()]));
                } else if v.is_array() {
                    let arr = v.as_array().unwrap();
                    for item in arr {
                        ensure!(item.is_string(), "map list values must be string");
                    }
                    out_map.insert(k.clone(), Value::Array(arr.clone()));
                } else {
                    bail!("query_matcher_request_map value must be string or list of strings");
                }
            }
            Ok(Some(json!({"query": out_map})))
        }
        "header_matcher_request_map" => {
            ensure!(data.is_object(), "header_matcher_request_map expects map");
            let m = data.as_object().unwrap();
            let mut out_map = Map::new();
            for (k, v) in m {
                if v.is_string() {
                    out_map.insert(k.clone(), json!([v.as_str().unwrap()]));
                } else if v.is_array() {
                    let arr = v.as_array().unwrap();
                    for item in arr {
                        ensure!(item.is_string(), "map list values must be string");
                    }
                    out_map.insert(k.clone(), Value::Array(arr.clone()));
                } else {
                    bail!("header_matcher_request_map value must be string or list of strings");
                }
            }
            Ok(Some(json!({"header": out_map})))
        }
        "vars_matcher_request_map" => {
            ensure!(data.is_object(), "vars_matcher_request_map expects map");
            let m = data.as_object().unwrap();
            let mut out_map = Map::new();
            for (k, v) in m {
                if v.is_string() {
                    out_map.insert(k.clone(), json!([v.as_str().unwrap()]));
                } else if v.is_array() {
                    let arr = v.as_array().unwrap();
                    for item in arr {
                        ensure!(item.is_string(), "map list values must be string");
                    }
                    out_map.insert(k.clone(), Value::Array(arr.clone()));
                } else {
                    bail!("vars_matcher_request_map value must be string or list of strings");
                }
            }
            Ok(Some(json!({"vars": out_map})))
        }
        "path_regexp_request_string" => {
            ensure!(
                data.is_string(),
                "path_regexp_request_string expects string"
            );
            Ok(Some(
                json!({"path_regexp": {"name": default_name, "pattern": data.as_str().unwrap()}}),
            ))
        }
        "path_regexp_request_string_string" => {
            ensure!(
                data.is_array(),
                "path_regexp_request_string_string expects list"
            );
            let arr = data.as_array().unwrap();
            ensure!(arr.len() == 2, "list must have 2 items");
            ensure!(
                arr[0].is_string() && arr[1].is_string(),
                "list items must be string"
            );
            let name = arr[0].as_str().unwrap();
            let pattern = arr[1].as_str().unwrap();
            let n = if name.is_empty() { default_name } else { name };
            Ok(Some(
                json!({"path_regexp": {"name": n, "pattern": pattern}}),
            ))
        }
        "header_regexp_request_string_string" => {
            ensure!(
                data.is_array(),
                "header_regexp_request_string_string expects list"
            );
            let arr = data.as_array().unwrap();
            ensure!(arr.len() == 2, "list must have 2 items");
            ensure!(
                arr[0].is_string() && arr[1].is_string(),
                "list items must be string"
            );
            let field = arr[0].as_str().unwrap();
            let pattern = arr[1].as_str().unwrap();
            Ok(Some(
                json!({"header_regexp": {field: {"name": default_name, "pattern": pattern}}}),
            ))
        }
        "vars_regexp_request_string_string" => {
            ensure!(
                data.is_array(),
                "vars_regexp_request_string_string expects list"
            );
            let arr = data.as_array().unwrap();
            ensure!(arr.len() == 2, "list must have 2 items");
            ensure!(
                arr[0].is_string() && arr[1].is_string(),
                "list items must be string"
            );
            let field = arr[0].as_str().unwrap();
            let pattern = arr[1].as_str().unwrap();
            Ok(Some(
                json!({"vars_regexp": {field: {"name": default_name, "pattern": pattern}}}),
            ))
        }
        "header_regexp_request_string_string_string" => {
            ensure!(
                data.is_array(),
                "header_regexp_request_string_string_string expects list"
            );
            let arr = data.as_array().unwrap();
            ensure!(arr.len() == 3, "list must have 3 items");
            ensure!(
                arr[0].is_string() && arr[1].is_string() && arr[2].is_string(),
                "list items must be string"
            );
            let name = arr[0].as_str().unwrap();
            let field = arr[1].as_str().unwrap();
            let pattern = arr[2].as_str().unwrap();
            let n = if name.is_empty() { default_name } else { name };
            Ok(Some(
                json!({"header_regexp": {field: {"name": n, "pattern": pattern}}}),
            ))
        }
        "vars_regexp_request_string_string_string" => {
            ensure!(
                data.is_array(),
                "vars_regexp_request_string_string_string expects list"
            );
            let arr = data.as_array().unwrap();
            ensure!(arr.len() == 3, "list must have 3 items");
            ensure!(
                arr[0].is_string() && arr[1].is_string() && arr[2].is_string(),
                "list items must be string"
            );
            let name = arr[0].as_str().unwrap();
            let field = arr[1].as_str().unwrap();
            let pattern = arr[2].as_str().unwrap();
            let n = if name.is_empty() { default_name } else { name };
            Ok(Some(
                json!({"vars_regexp": {field: {"name": n, "pattern": pattern}}}),
            ))
        }
        "url_pattern_request_string" => {
            ensure!(
                data.is_string(),
                "url_pattern_request_string expects string"
            );
            Ok(Some(
                json!({"url_pattern": {"pattern": data.as_str().unwrap()}}),
            ))
        }
        "url_pattern_request_string_string" => {
            ensure!(
                data.is_array(),
                "url_pattern_request_string_string expects list"
            );
            let arr = data.as_array().unwrap();
            ensure!(arr.len() == 2, "list must have 2 items");
            ensure!(
                arr[0].is_string() && arr[1].is_string(),
                "list items must be string"
            );
            Ok(Some(
                json!({"url_pattern": {"pattern": arr[0].as_str().unwrap(), "base_url": arr[1].as_str().unwrap()}}),
            ))
        }
        "file" | "file_request_map" => {
            ensure!(data.is_object(), "file expects map");
            let m = data.as_object().unwrap();
            for (k, v) in m {
                match k.as_str() {
                    "root" | "try_policy" => ensure!(v.is_string(), "{} must be string", k),
                    "try_files" | "split_path" => {
                        ensure!(v.is_array(), "{} must be list", k);
                        for item in v.as_array().unwrap() {
                            ensure!(item.is_string(), "{} elements must be string", k);
                        }
                    }
                    _ => bail!("unknown key: {}", k),
                }
            }
            Ok(Some(json!({"file": data})))
        }
        _ => Ok(None),
    }
}
