//! ACME new-order request parameters captured at intent-creation time.
//!
//! Parameters are persisted with the order intent.  For an *unknown* ACME
//! result the caller must replay the exact explicit date/profile to match a
//! pending/ready observation; a known URL resuming normally allows the CA to
//! ignore the requested lifetime, so this module never forces CA-side
//! configuration onto issuance.  `not_after` is computed once by the
//! high-level layer (e.g. Caddy `certificate_lifetime`) before the real
//! `new_order_intent` call and truncated to whole seconds—recovery from an
//! unknown outcome must not recompute it.

use anyhow::{bail, Result};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Clone, Default)]
pub struct OrderParameters {
    pub not_after: Option<String>,
    pub profile: String,
}

impl OrderParameters {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.profile.len() > 1024 {
            bail!("profile exceeds 1024 bytes");
        }
        if let Some(ref dt) = self.not_after {
            if dt.len() > 64 {
                bail!("not_after exceeds 64 bytes");
            }
            let parsed = OffsetDateTime::parse(dt, &Rfc3339)
                .map_err(|_| anyhow::anyhow!("not_after is not valid RFC 3339"))?;
            if parsed.nanosecond() != 0 {
                bail!("not_after must be truncated to whole seconds");
            }
        }
        Ok(())
    }

    pub(crate) fn write_payload(&self, payload: &mut Value) {
        let obj = payload.as_object_mut().expect("payload must be a JSON object");
        if let Some(ref dt) = self.not_after {
            obj.insert("notAfter".into(), Value::String(dt.clone()));
        }
        if !self.profile.is_empty() {
            obj.insert("profile".into(), Value::String(self.profile.clone()));
        }
    }

    pub(crate) fn matches_observation(&self, order: &super::Order) -> bool {
        if !self.profile.is_empty() && self.profile != order.profile {
            return false;
        }
        if let Some(ref want) = self.not_after {
            let have = match &order.not_after {
                Some(s) => s,
                None => return false,
            };
            let want_ts = match OffsetDateTime::parse(want, &Rfc3339) {
                Ok(dt) => dt.unix_timestamp_nanos(),
                Err(_) => return false,
            };
            let have_ts = match OffsetDateTime::parse(have, &Rfc3339) {
                Ok(dt) => dt.unix_timestamp_nanos(),
                Err(_) => return false,
            };
            if want_ts != have_ts {
                return false;
            }
        }
        true
    }
}
