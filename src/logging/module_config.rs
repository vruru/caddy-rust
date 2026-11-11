// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
//! Consume the same typed view as the shared Go inline module decoder.
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};

pub(super) fn inline(
    value: Value,
    key: &str,
    limit: usize,
    inherited: bool,
) -> Result<(String, Map<String, Value>)> {
    let value = if inherited {
        value
    } else {
        crate::admin_json::encoded_len(&value, limit)
            .map_err(|_| anyhow!("log inline module byte or depth limit exceeded"))?;
        crate::module_json::inline(&value, key, false)
            .map_err(|_| anyhow!("log inline module encoding failed"))?
            .into_owned()
    };
    let Value::Object(mut fields) = value else {
        bail!("log inline module object required");
    };
    let name = match fields.remove(key) {
        Some(Value::String(name)) if !name.is_empty() => name,
        _ => bail!("log inline module name required"),
    };
    Ok((name, fields))
}
