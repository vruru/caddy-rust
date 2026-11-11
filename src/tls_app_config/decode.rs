//! Borrowed, strict Go-compatible field decoding. Configuration values are not
//! cloned during key validation and never interpolated into diagnostics.
use super::{
    error::{ConfigError, pointer},
    schema::ObjectKind,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(super) type Result<T> = std::result::Result<T, ConfigError>;

pub(super) struct Object<'a> {
    fields: BTreeMap<&'static str, &'a Value>,
    path: String,
}

// Go encoding/json uses Unicode SimpleFold. For matching the fixed ASCII field
// names below, the only additional non-ASCII fold-set members are long S and
// the Kelvin sign. User map keys (CA IDs, overrides) never pass through this.
fn folded_ascii_eq(input: &str, canonical: &str) -> bool {
    let mut bytes = canonical.bytes();
    for ch in input.chars() {
        let folded = match ch {
            '\u{017f}' => b'S',
            '\u{212a}' => b'K',
            ch if ch.is_ascii() => (ch as u8).to_ascii_uppercase(),
            _ => return false,
        };
        if bytes.next().map(|b| b.to_ascii_uppercase()) != Some(folded) {
            return false;
        }
    }
    bytes.next().is_none()
}

impl<'a> Object<'a> {
    pub(super) fn new(value: Option<&'a Value>, kind: ObjectKind, path: &str) -> Result<Self> {
        let mut fields = BTreeMap::new();
        if let Some(value) = value.filter(|v| !v.is_null()) {
            let object = value
                .as_object()
                .ok_or_else(|| ConfigError::invalid(path.into()))?;
            for (key, value) in object {
                let canonical = kind
                    .fields()
                    .iter()
                    .copied()
                    .find(|f| *f == key)
                    .or_else(|| {
                        if kind == ObjectKind::Certificates {
                            return None;
                        }
                        kind.fields()
                            .iter()
                            .copied()
                            .find(|f| folded_ascii_eq(key, f))
                    })
                    .ok_or_else(|| ConfigError::unknown(pointer(path, key)))?;
                // serde_json::Value no longer contains source member order.
                // Never choose BTree order for Go's last-written alias value.
                if fields.insert(canonical, value).is_some() {
                    return Err(ConfigError::unsupported(
                        pointer(path, canonical),
                        "go_json_alias_order",
                    ));
                }
            }
        }
        Ok(Self {
            fields,
            path: path.into(),
        })
    }
    pub(super) fn value(&self, key: &'static str) -> Option<&'a Value> {
        self.fields.get(key).copied().filter(|v| !v.is_null())
    }
    /// RawMessage fields distinguish explicit null from an absent value.
    pub(super) fn raw_value(&self, key: &'static str) -> Option<&'a Value> {
        self.fields.get(key).copied()
    }
    pub(super) fn at(&self, key: &str) -> String {
        pointer(&self.path, key)
    }
    pub(super) fn string(&self, key: &'static str) -> Result<&'a str> {
        match self.value(key) {
            Some(v) => v.as_str().ok_or_else(|| ConfigError::invalid(self.at(key))),
            None => Ok(""),
        }
    }
    pub(super) fn boolean(&self, key: &'static str) -> Result<Option<bool>> {
        self.value(key)
            .map(|v| {
                v.as_bool()
                    .ok_or_else(|| ConfigError::invalid(self.at(key)))
            })
            .transpose()
    }
    pub(super) fn integer(&self, key: &'static str) -> Result<Option<i64>> {
        self.value(key)
            .map(|v| {
                v.as_number()
                    .and_then(|n| n.as_go_i64())
                    .ok_or_else(|| ConfigError::invalid(self.at(key)))
            })
            .transpose()
    }
    pub(super) fn number(&self, key: &'static str) -> Result<Option<f64>> {
        self.value(key)
            .map(|v| {
                v.as_f64()
                    .filter(|f| f.is_finite())
                    .ok_or_else(|| ConfigError::invalid(self.at(key)))
            })
            .transpose()
    }
    pub(super) fn array(&self, key: &'static str) -> Result<&'a [Value]> {
        match self.value(key) {
            Some(Value::Array(values)) => Ok(values),
            Some(_) => Err(ConfigError::invalid(self.at(key))),
            None => Ok(&[]),
        }
    }
    pub(super) fn strings(&self, key: &'static str) -> Result<Vec<&'a str>> {
        self.array(key)?
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                Value::String(value) => Ok(value.as_str()),
                Value::Null => Ok(""), // Go null into an array's fresh string is a no-op.
                _ => Err(ConfigError::invalid(pointer(
                    &self.at(key),
                    &index.to_string(),
                ))),
            })
            .collect()
    }
    pub(super) fn map(&self, key: &'static str) -> Result<Option<&'a Map<String, Value>>> {
        self.value(key)
            .map(|v| {
                v.as_object()
                    .ok_or_else(|| ConfigError::invalid(self.at(key)))
            })
            .transpose()
    }
    pub(super) fn duration_ns(&self, key: &'static str) -> Result<i64> {
        match self.value(key) {
            Some(value) => {
                crate::duration::parse_value(value).map_err(|_| ConfigError::invalid(self.at(key)))
            }
            None => Ok(0),
        }
    }
}

/// Caddy's module inline discriminator is read from a map with an exact key,
/// unlike the case-folded fields of the subsequently decoded Go struct.
pub(super) fn discriminator<'a>(value: &'a Value, key: &str, path: &str) -> Result<&'a str> {
    value
        .as_object()
        .and_then(|v| v.get(key))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ConfigError::invalid(pointer(path, key)))
}
