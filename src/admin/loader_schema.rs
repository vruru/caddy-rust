//! Native equivalent of caddy.config_loaders.http's external schema.
use super::AdminError;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
#[derive(Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct LoaderTls {
    pub use_server_identity: bool,
    pub client_certificate_file: String,
    pub client_certificate_key_file: String,
    pub root_ca_pem_files: Vec<String>,
}
#[derive(Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct HttpLoader {
    pub method: String,
    pub url: String,
    pub header: BTreeMap<String, Vec<String>>,
    pub timeout: Option<Value>,
    pub adapter: String,
    pub tls: Option<LoaderTls>,
    #[serde(skip)]
    pub parsed_timeout: std::time::Duration,
}
fn invalid() -> AdminError {
    AdminError::new(400, "invalid_http_config_loader")
}
impl HttpLoader {
    pub fn parse(raw: &Value) -> Result<Self, AdminError> {
        let mut object = raw.as_object().ok_or_else(invalid)?.clone();
        if object.remove("module") != Some(Value::String("http".to_owned())) {
            return Err(AdminError::new(400, "unsupported_config_loader_module"));
        }
        normalize_fields(
            &mut object,
            &["method", "url", "header", "timeout", "adapter", "tls"],
        );
        if let Some(Value::Object(header)) = object.get_mut("header") {
            for values in header.values_mut() {
                if values.is_null() {
                    *values = Value::Array(Vec::new());
                } else if let Value::Array(values) = values {
                    for value in values {
                        if value.is_null() {
                            *value = Value::String(String::new());
                        }
                    }
                }
            }
        }
        if let Some(Value::Object(tls)) = object.get_mut("tls") {
            normalize_fields(
                tls,
                &[
                    "use_server_identity",
                    "client_certificate_file",
                    "client_certificate_key_file",
                    "root_ca_pem_files",
                ],
            );
            if let Some(Value::Array(files)) = tls.get_mut("root_ca_pem_files") {
                for path in files {
                    if path.is_null() {
                        *path = Value::String(String::new());
                    }
                }
            }
        }
        let mut loader: Self =
            serde_json::from_value(Value::Object(object)).map_err(|_| invalid())?;
        if loader.method.len() > 128
            || loader.url.is_empty()
            || loader.url.len() > 65536
            || loader.adapter.len() > 128
            || loader.header.len() > 256
        {
            return Err(invalid());
        }
        if loader.header.iter().any(|(key, values)| {
            key.len() > 1024
                || values.len() > 1024
                || values.iter().any(|value| value.len() > 65536)
        }) {
            return Err(invalid());
        }
        let timeout = loader
            .timeout
            .as_ref()
            .map(|v| crate::http_config::helpers::signed_duration(v, "admin.config.load.timeout"))
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or(0);
        loader.parsed_timeout = if timeout > 0 {
            std::time::Duration::from_nanos(timeout as u64)
        } else {
            std::time::Duration::from_secs(30)
        };
        if let Some(tls) = &loader.tls
            && (tls.client_certificate_file.len() > 4096
                || tls.client_certificate_key_file.len() > 4096
                || tls.root_ca_pem_files.len() > 256
                || tls.root_ca_pem_files.iter().any(|path| path.len() > 4096))
        {
            return Err(invalid());
        }
        Ok(loader)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct LoaderPlan {
    pub http: HttpLoader,
    pub delay: std::time::Duration,
}
impl LoaderPlan {
    pub fn parse(raw: Option<&Value>, delay: Option<&Value>) -> Result<Option<Self>, AdminError> {
        let delay = delay
            .filter(|v| !v.is_null())
            .map(|v| crate::http_config::helpers::signed_duration(v, "admin.config.load_delay"))
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or(0);
        let Some(raw) = raw.filter(|v| !v.is_null()) else {
            return Ok(None);
        };
        Ok(Some(Self {
            http: HttpLoader::parse(raw)?,
            delay: std::time::Duration::from_nanos(delay.max(0) as u64),
        }))
    }
}

// Go encoding/json matches struct fields case-insensitively and treats null
// as the zero value. Unknown names remain present for strict rejection.
fn normalize_fields(map: &mut serde_json::Map<String, Value>, fields: &[&str]) {
    let original = std::mem::take(map);
    for (key, value) in original {
        if let Some(canonical) = fields.iter().find(|name| key.eq_ignore_ascii_case(name)) {
            let canonical = (*canonical).to_owned();
            if value.is_null() {
                match canonical.as_str() {
                    "header" => {
                        map.insert(canonical, Value::Object(Default::default()));
                    }
                    "root_ca_pem_files" => {
                        map.insert(canonical, Value::Array(Vec::new()));
                    }
                    "tls" | "timeout" => {
                        map.insert(canonical, Value::Null);
                    }
                    _ => {}
                }
            } else {
                map.insert(canonical, value);
            }
        } else {
            map.insert(key, value);
        }
    }
}
