//! Shared metadata for the TLS app's real certificate lifecycle checkpoints.
use crate::events::{EmitContext, EventData, EventsApp, Value};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub(crate) struct Attempt {
    pub identifier: String,
    pub renewal: bool,
    pub remaining: Option<i64>,
}
impl Attempt {
    pub(crate) fn new(identifier: &str, not_after: Option<i64>) -> Self {
        let remaining = not_after.map(|end| {
            let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_nanos() as i128,
                Err(e) => -(e.duration().as_nanos() as i128),
            };
            (i128::from(end) * 1_000_000_000 - now)
                .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
        });
        Self {
            identifier: identifier.into(),
            renewal: not_after.is_some(),
            remaining,
        }
    }
    fn base(&self) -> EventData {
        let mut data = EventData::from([
            ("renewal".into(), Value::Bool(self.renewal)),
            ("identifier".into(), Value::Str(self.identifier.clone())),
        ]);
        if let Some(nanos) = self.remaining {
            data.insert("remaining".into(), Value::Duration(nanos));
        }
        data
    }
    pub(crate) async fn obtaining(
        &self,
        app: Option<&Arc<EventsApp>>,
        issuer: &str,
        forced: bool,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        let Some(app) = app.filter(|app| app.should_emit("cert_obtaining")) else {
            return Ok(());
        };
        let mut data =
            EventData::from([("identifier".into(), Value::Str(self.identifier.clone()))]);
        if let Some(remaining) = self.remaining {
            data.insert("renewal".into(), Value::Bool(true));
            data.insert("forced".into(), Value::Bool(forced));
            data.insert("remaining".into(), Value::Duration(remaining));
            data.insert("issuer".into(), Value::Str(issuer.into()));
        }
        match app
            .emit(
                EmitContext {
                    cancel: cancel.child_token(),
                },
                "cert_obtaining",
                "tls",
                data,
            )
            .await
            .status
        {
            crate::events::Status::Completed => Ok(()),
            crate::events::Status::Aborted => {
                Err(crate::cert_automation::ObtainEventAborted.into())
            }
            crate::events::Status::Cancelled => {
                Err(crate::cert_automation::ObtainEventCancelled.into())
            }
            crate::events::Status::Rejected(r) => {
                Err(crate::cert_automation::ObtainEventRejected(r).into())
            }
        }
    }
    pub(crate) async fn failed(
        &self,
        app: Option<&Arc<EventsApp>>,
        issuers: &[String],
        error: &anyhow::Error,
        cancel: &CancellationToken,
    ) {
        let Some(app) = app.filter(|app| app.should_emit("cert_failed")) else {
            return;
        };
        let mut data = self.base();
        data.insert("issuers".into(), Value::Strings(issuers.to_vec().into()));
        data.insert(
            "error".into(),
            Value::Opaque(Arc::new(Failure(format!("{error:#}")))),
        );
        let _ = app
            .emit(
                EmitContext {
                    cancel: cancel.child_token(),
                },
                "cert_failed",
                "tls",
                data,
            )
            .await;
    }
    /// Call only after save_certificate completed. Handler abort is a report;
    /// it never rolls back stored material or prevents its subsequent use.
    pub(crate) async fn obtained(
        &self,
        app: Option<&Arc<EventsApp>>,
        issuer: &str,
        names: &[String],
        csr: &[u8],
        cancel: &CancellationToken,
    ) {
        let Some(app) = app.filter(|app| app.should_emit("cert_obtained")) else {
            return;
        };
        let Ok(key) = crate::certstore::names_key(names) else {
            return;
        };
        let issuer_component = crate::certstore::safe(issuer);
        let key_component = crate::certstore::safe(&key);
        let path = format!("certificates/{issuer_component}/{key_component}");
        let file = format!("{path}/{key_component}");
        let mut data = self.base();
        for (key, value) in [
            ("issuer", issuer.to_owned()),
            ("storage_path", path),
            ("private_key_path", format!("{file}.key")),
            ("certificate_path", format!("{file}.crt")),
            ("metadata_path", format!("{file}.json")),
        ] {
            data.insert(key.into(), Value::Str(value));
        }
        data.insert(
            "csr_pem".into(),
            Value::Bytes(pem_lf("CERTIFICATE REQUEST", csr).into()),
        );
        let _ = app
            .emit(
                EmitContext {
                    cancel: cancel.child_token(),
                },
                "cert_obtained",
                "tls",
                data,
            )
            .await;
    }
}
#[derive(Debug)]
pub struct Failure(pub String);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Failure {}
pub(crate) async fn cached(
    app: Option<&Arc<EventsApp>>,
    managed: bool,
    names: &[String],
    cancel: &CancellationToken,
) {
    let kind = if managed {
        "cached_managed_cert"
    } else {
        "cached_unmanaged_cert"
    };
    let Some(app) = app.filter(|app| app.should_emit(kind)) else {
        return;
    };
    let data = EventData::from([("sans".into(), Value::Strings(names.to_vec().into()))]);
    let _ = app
        .emit(
            EmitContext {
                cancel: cancel.child_token(),
            },
            kind,
            "tls",
            data,
        )
        .await;
}
pub(crate) fn pem_lf(kind: &str, bytes: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {kind}-----\n").into_bytes();
    for line in encoded.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {kind}-----\n").as_bytes());
    out
}
