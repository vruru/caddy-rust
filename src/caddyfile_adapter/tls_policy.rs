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

use anyhow::Result;
use serde_json::{Map, Value};
use std::{cell::RefCell, rc::Rc};
pub(super) type IssuerRef = Rc<RefCell<IssuerDef>>;
pub(super) fn shared(issuer: IssuerDef) -> IssuerRef {
    Rc::new(RefCell::new(issuer))
}

/// Identifies the issuer module family without exposing inner fields.
#[derive(Clone, PartialEq)]
pub(super) enum IssuerDef {
    Internal(Map<String, Value>),
    Acme(Map<String, Value>),
    ZeroSsl(Map<String, Value>),
}

impl IssuerDef {
    pub(super) fn module(&self) -> &'static str {
        match self {
            IssuerDef::Internal(_) => "internal",
            IssuerDef::Acme(_) => "acme",
            IssuerDef::ZeroSsl(_) => "zerossl",
        }
    }

    pub(super) fn fields(&self) -> &Map<String, Value> {
        match self {
            IssuerDef::Internal(m) | IssuerDef::Acme(m) | IssuerDef::ZeroSsl(m) => m,
        }
    }

    pub(super) fn fields_mut(&mut self) -> &mut Map<String, Value> {
        match self {
            IssuerDef::Internal(m) | IssuerDef::Acme(m) | IssuerDef::ZeroSsl(m) => m,
        }
    }

    pub(super) fn raw(&self) -> Result<RawModule> {
        let mut map = self.fields().clone();
        map.insert("module".to_owned(), Value::String(self.module().to_owned()));
        RawModule::from_value(Value::Object(map))
    }
}

/// Normalized module representation preserving exact Go Module.Raw bytes.
/// Intentionally no Debug impl to avoid leaking potential secret keys.
#[derive(Clone, PartialEq)]
pub(super) struct RawModule {
    pub(super) value: Value,
    pub(super) bytes: Vec<u8>,
}

impl RawModule {
    pub(super) fn from_value(v: Value) -> Result<RawModule> {
        let normalized = super::module_value::normalize(v)?;
        let mut encoded =
            crate::admin_json::encoded(&normalized).map_err(|e| anyhow::Error::msg(e.category))?;
        if encoded.ends_with(b"\n") {
            encoded.truncate(encoded.len() - 1);
        }
        Ok(RawModule {
            value: normalized,
            bytes: encoded,
        })
    }
}

/// TLS policy configuration mirroring Go AutomationPolicy configuration semantics.
#[derive(Clone, Default, PartialEq)]
pub(super) struct PolicyConfig {
    pub(super) subjects: Option<Vec<String>>,
    pub(super) issuers: Option<Vec<IssuerRef>>,
    pub(super) issuers_raw: Option<Vec<RawModule>>,
    pub(super) managers_raw: Option<Vec<RawModule>>,
    pub(super) storage_raw: Option<Vec<u8>>,
    pub(super) must_staple: bool,
    pub(super) key_type: String,
    pub(super) on_demand: bool,
    pub(super) reuse_private_keys: bool,
    pub(super) renewal_window_ratio: f64,
    pub(super) disable_ocsp_stapling: bool,
    pub(super) ocsp_overrides: Option<Map<String, Value>>,
}

impl PolicyConfig {
    /// Mirrors Go isZero() semantics for DeepEqual comparison,
    /// optionally ignoring managers.
    pub(super) fn is_go_zero_ignoring_subjects(&self, ignore_managers: bool) -> bool {
        self.issuers.is_none()
            && self.issuers_raw.is_none()
            && (ignore_managers || self.managers_raw.is_none())
            && self.storage_raw.is_none()
            && !self.must_staple
            && self.key_type.is_empty()
            && !self.on_demand
            && !self.reuse_private_keys
            && self.renewal_window_ratio == 0.0
            && !self.disable_ocsp_stapling
            && self.ocsp_overrides.is_none()
    }

    /// Serializes to a JSON Value matching the Go admin API shape.
    /// Native issuers are NOT serialized here; they feed issuers_raw
    /// via the outer pipeline.
    pub(super) fn into_value(self) -> Result<Value> {
        let mut map = Map::new();

        if let Some(v) = self.subjects
            && !v.is_empty()
        {
            map.insert(
                "subjects".to_owned(),
                Value::Array(v.into_iter().map(Value::String).collect()),
            );
        }

        if let Some(raws) = self.issuers_raw
            && !raws.is_empty()
        {
            let arr: Vec<Value> = raws.into_iter().map(|r| r.value).collect();
            map.insert("issuers".to_owned(), Value::Array(arr));
        }

        if let Some(raws) = self.managers_raw
            && !raws.is_empty()
        {
            let arr: Vec<Value> = raws.into_iter().map(|r| r.value).collect();
            map.insert("get_certificate".to_owned(), Value::Array(arr));
        }

        if let Some(ref bytes) = self.storage_raw
            && !bytes.is_empty()
        {
            let decoded =
                crate::admin_json::decoded(bytes).map_err(|e| anyhow::Error::msg(e.category))?;
            map.insert("storage".to_owned(), decoded);
        }

        if self.must_staple {
            map.insert("must_staple".to_owned(), Value::Bool(true));
        }
        if !self.key_type.is_empty() {
            map.insert("key_type".to_owned(), Value::String(self.key_type));
        }
        if self.on_demand {
            map.insert("on_demand".to_owned(), Value::Bool(true));
        }
        if self.reuse_private_keys {
            map.insert("reuse_private_keys".to_owned(), Value::Bool(true));
        }
        if self.renewal_window_ratio != 0.0 {
            if !self.renewal_window_ratio.is_finite() {
                return Err(anyhow::anyhow!("renewal_window_ratio must be finite"));
            }
            map.insert(
                "renewal_window_ratio".to_owned(),
                Value::from(self.renewal_window_ratio),
            );
        }
        if self.disable_ocsp_stapling {
            map.insert("disable_ocsp_stapling".to_owned(), Value::Bool(true));
        }

        if let Some(m) = self.ocsp_overrides
            && !m.is_empty()
        {
            map.insert("ocsp_overrides".to_owned(), Value::Object(m));
        }

        Ok(Value::Object(map))
    }
}
