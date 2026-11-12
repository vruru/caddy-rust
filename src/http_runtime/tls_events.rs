//! Generation-pinned, asynchronous tls_get_certificate admission.
use super::resource_budget::Resources;
use crate::events::{EmitContext, EventData, EventsApp, Status, Value};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;
pub(super) const POOL_UNITS: usize = 16 * 1024;
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HelloFields {
    pub cipher_suites: Vec<u16>,
    pub server_name: String,
    pub supported_curves: Option<Vec<u16>>,
    pub supported_points: Option<Vec<u8>>,
    pub signature_schemes: Option<Vec<u16>>,
    #[serde(serialize_with = "protocols_json")]
    pub supported_protos: Option<Vec<Vec<u8>>>,
    pub supported_versions: Vec<u16>,
}
fn protocols_json<S: serde::Serializer>(
    value: &Option<Vec<Vec<u8>>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|b| String::from_utf8_lossy(b))
                .collect::<Vec<_>>()
        })
        .serialize(serializer)
}
impl HelloFields {
    pub(super) fn capture(hello: &rustls::server::ClientHello<'_>) -> Self {
        let versions = hello
            .offered_versions()
            .filter(|v| !v.is_empty())
            .map(|v| v.iter().map(|v| u16::from(*v)).collect())
            .unwrap_or_else(|| {
                [0x0304, 0x0303, 0x0302, 0x0301]
                    .into_iter()
                    .filter(|v| *v <= u16::from(hello.legacy_version()))
                    .collect()
            });
        Self {
            cipher_suites: hello
                .cipher_suites()
                .iter()
                .map(|v| u16::from(*v))
                .collect(),
            server_name: hello.offered_server_name().unwrap_or_default().to_owned(),
            supported_curves: hello
                .named_groups()
                .map(|v| v.iter().map(|v| u16::from(*v)).collect()),
            supported_points: hello.offered_ec_point_formats().map(<[u8]>::to_vec),
            signature_schemes: hello
                .offered_signature_schemes()
                .map(|v| v.iter().map(|v| u16::from(*v)).collect()),
            supported_protos: hello.alpn().map(|v| v.map(<[u8]>::to_vec).collect()),
            supported_versions: versions,
        }
    }
    fn cost(&self) -> usize {
        let items = self.cipher_suites.len()
            + self.supported_curves.as_ref().map_or(0, Vec::len)
            + self.supported_points.as_ref().map_or(0, Vec::len)
            + self.signature_schemes.as_ref().map_or(0, Vec::len)
            + self.supported_versions.len();
        items
            .saturating_mul(128)
            .saturating_add(self.server_name.len().saturating_mul(4))
            .saturating_add(4096)
            .saturating_add(
                self.supported_protos
                    .as_ref()
                    .map_or(0, |v| v.iter().map(|b| b.len() * 4 + 128).sum::<usize>()),
            )
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Transport {
    Tcp,
    Quic,
}
#[derive(Clone, Debug, Serialize)]
pub struct Address {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Zone")]
    pub zone: String,
    #[serde(skip)]
    pub transport: Transport,
}
impl Address {
    fn new(address: SocketAddr, transport: Transport) -> Self {
        let scope = match address {
            SocketAddr::V6(v) => v.scope_id(),
            _ => 0,
        };
        let zone = if scope == 0 {
            String::new()
        } else {
            zone_name(scope)
        };
        Self {
            ip: address.ip().to_canonical().to_string(),
            port: address.port(),
            zone,
            transport,
        }
    }
    pub fn network(&self) -> &'static str {
        match self.transport {
            Transport::Tcp => "tcp",
            Transport::Quic => "udp",
        }
    }
}
#[cfg(unix)]
fn zone_name(index: u32) -> String {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // The output buffer has exactly the size required by if_indextoname.
    let result = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if result.is_null() {
        index.to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }
}
#[cfg(not(unix))]
fn zone_name(index: u32) -> String {
    index.to_string()
}
#[derive(Debug, Serialize)]
pub struct ClientHello {
    #[serde(flatten)]
    pub hello: HelloFields,
    #[serde(rename = "RemoteAddr")]
    pub remote_addr: Address,
    #[serde(rename = "LocalAddr")]
    pub local_addr: Address,
    #[serde(skip)]
    _credit: OwnedSemaphorePermit,
}
pub(super) async fn emit(
    app: Option<&Arc<EventsApp>>,
    fields: &HelloFields,
    resources: &Resources,
    connection: (SocketAddr, SocketAddr, Transport),
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let Some(app) = app.filter(|app| app.should_emit("tls_get_certificate")) else {
        return Ok(());
    };
    let units = u32::try_from(fields.cost().div_ceil(1024))
        .map_err(|_| anyhow::anyhow!("TLS event metadata overflow"))?;
    let credit = resources
        .tls_event_bytes
        .clone()
        .try_acquire_many_owned(units)
        .map_err(|_| anyhow::anyhow!("TLS event metadata pool exhausted"))?;
    let (peer, local, transport) = connection;
    let hello = Arc::new(ClientHello {
        hello: fields.clone(),
        remote_addr: Address::new(peer, transport),
        local_addr: Address::new(local, transport),
        _credit: credit,
    });
    let json = Arc::new(serde_json::to_value(hello.as_ref())?);
    let data = EventData::from([("client_hello".into(), Value::Native { value: hello, json })]);
    let emitted = app
        .emit(
            EmitContext {
                cancel: cancel.child_token(),
            },
            "tls_get_certificate",
            "tls",
            data,
        )
        .await;
    match emitted.status {
        Status::Completed => Ok(()),
        Status::Aborted => anyhow::bail!("TLS certificate selection aborted by event handler"),
        Status::Cancelled => anyhow::bail!("TLS certificate selection event cancelled"),
        Status::Rejected(reason) => {
            anyhow::bail!("TLS certificate selection event rejected: {reason:?}")
        }
    }
}
/// QUIC may perform a stateless Retry before starting an issuance job. Share
/// this one gate between that job and actual accept so it emits exactly once.
pub(super) struct Admission<'a> {
    app: Option<&'a Arc<EventsApp>>,
    fields: &'a HelloFields,
    resources: &'a Resources,
    connection: (SocketAddr, SocketAddr, Transport),
    cancel: &'a CancellationToken,
    done: bool,
}
impl<'a> Admission<'a> {
    pub(super) fn new(
        app: Option<&'a Arc<EventsApp>>,
        fields: &'a HelloFields,
        resources: &'a Resources,
        connection: (SocketAddr, SocketAddr, Transport),
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            app,
            fields,
            resources,
            connection,
            cancel,
            done: false,
        }
    }
    pub(super) async fn run(&mut self) -> anyhow::Result<()> {
        if !self.done {
            emit(
                self.app,
                self.fields,
                self.resources,
                self.connection,
                self.cancel,
            )
            .await?;
            self.done = true;
        }
        Ok(())
    }
}
