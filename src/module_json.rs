//! Go inline modules decode through a map before strict field decoding.
//! Keep this boundary separate from typed app fields and keyed modules.
use crate::admin_json::{self, ConfigError};
use serde_json::Value;
use std::borrow::Cow;
const MAX_INLINE_BYTES: usize = 64 * 1024 * 1024;
fn invalid(category: &'static str) -> ConfigError {
    ConfigError {
        status: 400,
        category,
    }
}
/// An enclosing inline module has already normalized its entire subtree. The
/// flag is passed explicitly through its route recursion, never inferred from
/// depth, field name or an untrusted configuration value.
pub(crate) fn inline<'a>(
    value: &'a Value,
    key: &str,
    inherited: bool,
) -> Result<Cow<'a, Value>, ConfigError> {
    let map = value
        .as_object()
        .ok_or_else(|| invalid("inline_module_object_required"))?;
    if !map
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty())
    {
        return Err(invalid("inline_module_name_required"));
    }
    if inherited {
        return Ok(Cow::Borrowed(value));
    }
    // The discriminator remains only for the existing strict parser's lookup;
    // it is a string and is included in that parser's explicit allowed fields.
    admin_json::encoded_len(value, MAX_INLINE_BYTES)?;
    let bytes = admin_json::encoded(value)?;
    Ok(Cow::Owned(admin_json::decoded_typed(&bytes)?))
}
/// Caddy WeakString stores any non-string JSON token as its encoded bytes;
/// null leaves the zero value untouched. Numeric validity belongs to execution.
pub(crate) fn weak_string(value: &Value) -> Result<String, ConfigError> {
    match value {
        Value::Null => Ok(String::new()),
        Value::String(s) => Ok(s.clone()),
        _ => {
            admin_json::encoded_len_typed(value, MAX_INLINE_BYTES)?;
            let mut bytes = admin_json::encoded_typed(value)?;
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            String::from_utf8(bytes).map_err(|_| invalid("invalid_weak_string_encoding"))
        }
    }
}
