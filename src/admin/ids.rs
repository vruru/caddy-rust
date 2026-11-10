use super::AdminError;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
#[derive(Clone)]
pub(super) struct Indexed {
    pub raw: Arc<Value>,
    pub ids: HashMap<String, String>,
}
fn invalid() -> AdminError {
    AdminError::new(400, "invalid_configuration_id")
}
fn numeric_id(n: &serde_json::Number) -> Result<String, AdminError> {
    let v = n.as_f64().filter(|v| v.is_finite()).ok_or_else(invalid)?;
    if v == 0.0 {
        return Ok(if v.is_sign_negative() { "-0" } else { "0" }.to_owned());
    }
    let scientific = format!("{v:e}");
    let (significand, exponent) = scientific.split_once('e').ok_or_else(invalid)?;
    let exp: i32 = exponent.parse().map_err(|_| invalid())?;
    if !(-4..6).contains(&exp) {
        Ok(format!(
            "{significand}e{}{:02}",
            if exp < 0 { '-' } else { '+' },
            exp.unsigned_abs()
        ))
    } else {
        Ok(format!("{v}"))
    }
}
pub(super) fn clean(path: &str) -> String {
    let mut out = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut result = format!("/{}", out.join("/"));
    if path.ends_with('/') && result != "/" {
        result.push('/');
    }
    result
}
fn join(base: &str, rest: &str) -> Result<String, AdminError> {
    let path = clean(&format!("{base}/{rest}"));
    if path != "/config" && !path.starts_with("/config/") {
        return Err(invalid());
    }
    Ok(path)
}
fn collect(
    value: &Value,
    path: &str,
    ids: &mut HashMap<String, String>,
    depth: usize,
    count: &mut usize,
) -> Result<(), AdminError> {
    if depth > crate::admin_json::MAX_CONFIG_DEPTH || *count > 100000 {
        return Err(AdminError::new(400, "configuration_index_limit_exceeded"));
    }
    match value {
        Value::Object(map) => {
            if let Some(id) = map.get("@id") {
                let id = match id {
                    Value::String(v) => v.clone(),
                    Value::Number(n) => numeric_id(n)?,
                    _ => return Err(invalid()),
                };
                if path != "/config" && !path.starts_with("/config/") {
                    return Err(invalid());
                }
                if ids.insert(id, path.to_owned()).is_some() {
                    return Err(AdminError::new(400, "duplicate_configuration_id"));
                }
            }
            for (name, child) in map {
                *count += 1;
                if name != "@id" {
                    collect(
                        child,
                        &clean(&format!("{path}/{name}")),
                        ids,
                        depth + 1,
                        count,
                    )?;
                }
            }
        }
        Value::Array(array) => {
            for (i, child) in array.iter().enumerate() {
                *count += 1;
                collect(child, &join(path, &i.to_string())?, ids, depth + 1, count)?;
            }
        }
        _ => {}
    }
    Ok(())
}
impl Indexed {
    pub fn new(raw: Value) -> Result<Self, AdminError> {
        let mut ids = HashMap::new();
        collect(&raw, "/config", &mut ids, 0, &mut 0)?;
        Ok(Self {
            raw: Arc::new(raw),
            ids,
        })
    }
    pub fn runtime(&self) -> Value {
        let mut value = self.raw.as_ref().clone();
        strip_meta(&mut value);
        value
    }
    pub fn rewrite(&self, path: &str) -> Result<String, AdminError> {
        let Some(rest) = path.strip_prefix("/id/") else {
            return Ok(path.to_owned());
        };
        let (id, rest) = rest.split_once('/').unwrap_or((rest, ""));
        let target = self
            .ids
            .get(id)
            .ok_or_else(|| AdminError::new(404, "configuration_id_not_found"))?;
        if rest.is_empty() {
            Ok(target.clone())
        } else {
            join(target, rest)
        }
    }
}

pub(super) fn strip_meta(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("@id");
            for v in m.values_mut() {
                strip_meta(v)
            }
        }
        Value::Array(a) => {
            for v in a {
                strip_meta(v)
            }
        }
        _ => {}
    }
}
