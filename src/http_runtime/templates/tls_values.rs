//! Go tls.ConnectionState values backed by the accepted connection's owned
//! snapshot. Accessors never retain or lock a TLS transport.
#[path = "x509_values.rs"]
mod x509_values;
use super::super::Control;
use super::{RenderResult, arity, error};
use crate::http_runtime::{
    ConnectionSnapshot,
    connection_snapshot::{CertificateChain, ConnectionSnapshotError},
};
use gotmpl::{ArgKind, Object, Signature, TypedSlice, Value, ValueFunc};
use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock, Mutex, Weak},
};
pub(super) type Cache = Arc<Mutex<Option<(Weak<Control>, Arc<Factory>)>>>;
pub(super) fn cache() -> Cache {
    Arc::new(Mutex::new(None))
}
const FIELDS: &[&str] = &[
    "Version",
    "HandshakeComplete",
    "DidResume",
    "CipherSuite",
    "CurveID",
    "NegotiatedProtocol",
    "NegotiatedProtocolIsMutual",
    "ServerName",
    "PeerCertificates",
    "VerifiedChains",
    "SignedCertificateTimestamps",
    "OCSPResponse",
    "TLSUnique",
    "ECHAccepted",
    "HelloRetryRequest",
    "LocalCertificate",
];
pub(super) struct Factory {
    pub(super) snapshot: Option<Arc<ConnectionSnapshot>>,
    pub(super) control: Weak<Control>,
    certificates: Mutex<BTreeMap<usize, Arc<x509_values::Certificate>>>,
}
impl Factory {
    pub(super) fn owner(&self) -> RenderResult<Arc<Control>> {
        self.control
            .upgrade()
            .ok_or_else(|| error("TLS template owner retired"))
    }
    pub(super) fn reserve(&self, bytes: usize) -> RenderResult<()> {
        self.owner()?.reserve_host_bytes(bytes)
    }
    pub(super) fn work(&self, units: usize) -> RenderResult<()> {
        self.owner()?.charge(units)
    }
    fn snapshot(&self) -> RenderResult<&ConnectionSnapshot> {
        self.snapshot
            .as_deref()
            .ok_or_else(|| error("TLS connection snapshot missing"))
    }
    fn metadata(
        &self,
    ) -> RenderResult<&crate::http_runtime::connection_snapshot::ConnectionMetadata> {
        self.snapshot()?.metadata().map_err(observation)
    }
    fn certificate(self: &Arc<Self>, der: Arc<[u8]>) -> RenderResult<Value> {
        let key = Arc::as_ptr(&der) as *const u8 as usize;
        let entry = {
            let mut entries = self
                .certificates
                .lock()
                .map_err(|_| error("certificate projection cache poisoned"))?;
            if let Some(entry) = entries.get(&key) {
                entry.clone()
            } else {
                self.reserve(1536)?;
                let entry = x509_values::Certificate::new(der);
                entries.insert(key, entry.clone());
                entry
            }
        };
        x509_values::value(self, entry)
    }
    fn certificates(self: &Arc<Self>, chain: &CertificateChain, nil: bool) -> RenderResult<Value> {
        if nil {
            return Ok(Value::Slice(TypedSlice::nil("[]*x509.Certificate")));
        }
        self.reserve(sequence_peak(chain.len())?)?;
        let mut values = Vec::with_capacity(chain.len());
        for der in chain.iter() {
            self.work(1)?;
            values.push(self.certificate(der.clone())?);
        }
        Ok(Value::Slice(TypedSlice::values(
            "[]*x509.Certificate",
            Some(values.into()),
        )?))
    }
    fn field(self: &Arc<Self>, name: &str) -> RenderResult<Option<Value>> {
        self.work(1)?;
        let meta = self.metadata()?;
        Ok(Some(match name {
            "Version" => Value::Uint16(meta.version),
            "HandshakeComplete" => Value::Bool(meta.handshake_complete),
            "DidResume" => Value::Bool(meta.did_resume),
            "CipherSuite" => Value::Uint16(meta.cipher_suite),
            "CurveID" => curve(self.snapshot()?.curve_id().map_err(observation)?),
            "NegotiatedProtocol" => self.go_string(&meta.alpn)?,
            "NegotiatedProtocolIsMutual" => Value::Bool(meta.negotiated_protocol_is_mutual),
            "ServerName" => {
                self.reserve(meta.server_name.len() + 64)?;
                Value::String(meta.server_name.clone())
            }
            "PeerCertificates" => {
                self.certificates(&meta.peer_certificates, meta.peer_certificates.is_empty())?
            }
            "VerifiedChains" => match self.snapshot()?.verified_chains().map_err(observation)? {
                None => Value::Slice(TypedSlice::nil("[][]*x509.Certificate")),
                Some(chains) => {
                    self.reserve(sequence_peak(chains.len())?)?;
                    let mut values = Vec::with_capacity(chains.len());
                    for chain in chains.iter() {
                        values.push(self.certificates(chain, false)?);
                    }
                    Value::Slice(TypedSlice::values(
                        "[][]*x509.Certificate",
                        Some(values.into()),
                    )?)
                }
            },
            "SignedCertificateTimestamps" => {
                let data = self
                    .snapshot()?
                    .signed_certificate_timestamps()
                    .map_err(observation)?;
                self.byte_matrix(&data, data.is_empty())?
            }
            "OCSPResponse" => {
                let data = self.snapshot()?.ocsp_response().map_err(observation)?;
                self.byte_slice(data.clone(), data.is_empty())?
            }
            "TLSUnique" => match self.snapshot()?.tls_unique().map_err(observation)? {
                None => Value::Slice(TypedSlice::nil("[]uint8")),
                Some(data) => self.byte_slice(data, false)?,
            },
            "ECHAccepted" => Value::Bool(meta.ech_accepted),
            "HelloRetryRequest" => Value::Bool(
                self.snapshot()?
                    .hello_retry_request()
                    .map_err(observation)?,
            ),
            "LocalCertificate" => {
                match self.snapshot()?.local_certificate().map_err(observation)? {
                    None => Value::Slice(TypedSlice::nil("[][]uint8")),
                    Some(chain) => self.byte_matrix(&chain, false)?,
                }
            }
            _ => return Ok(None),
        }))
    }
    pub(super) fn go_string(&self, bytes: &[u8]) -> RenderResult<Value> {
        self.reserve(
            bytes
                .len()
                .checked_add(64)
                .ok_or_else(|| error("TLS string size overflow"))?,
        )?;
        Ok(Value::from_go_bytes(Arc::<[u8]>::from(bytes)))
    }
    pub(super) fn byte_slice(&self, bytes: Arc<[u8]>, nil: bool) -> RenderResult<Value> {
        self.reserve(128)?;
        Ok(Value::Slice(TypedSlice::bytes((!nil).then_some(bytes))))
    }
    fn byte_matrix(&self, values: &CertificateChain, nil: bool) -> RenderResult<Value> {
        if nil {
            return Ok(Value::Slice(TypedSlice::nil("[][]uint8")));
        }
        self.reserve(sequence_peak(values.len())?)?;
        let mut result = Vec::with_capacity(values.len());
        for bytes in values.iter() {
            result.push(self.byte_slice(bytes.clone(), false)?);
        }
        Ok(Value::Slice(TypedSlice::values(
            "[][]uint8",
            Some(result.into()),
        )?))
    }
    pub(super) fn append_bytes(&self, prefix: &Value, suffix: &[u8]) -> RenderResult<Value> {
        let slice = match prefix {
            Value::Nil => TypedSlice::nil("[]uint8"),
            Value::Slice(slice) => slice.clone().into_plain_bytes()?,
            _ => return Err(error("expected []uint8")),
        };
        let length = slice
            .len()
            .checked_add(suffix.len())
            .ok_or_else(|| error("byte append length overflow"))?;
        let backing = slice
            .byte_backing_len()
            .ok_or_else(|| error("invalid byte backing"))?;
        let peak = length
            .checked_mul(2)
            .and_then(|n| backing.checked_mul(2).and_then(|m| n.checked_add(m)))
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| error("byte append budget overflow"))?;
        self.reserve(peak)?;
        self.work((backing + length).div_ceil(64) + 1)?;
        if length <= slice.cap() {
            let result = slice.reslice(0, length)?;
            result.write_range(slice.len(), suffix)?;
            return Ok(Value::Slice(result));
        }
        let prefix = slice.visible_bytes();
        let mut bytes = Vec::with_capacity(length);
        if let Some(prefix) = prefix {
            bytes.extend_from_slice(&prefix);
        }
        bytes.extend_from_slice(suffix);
        self.byte_slice(bytes.into(), false)
    }
    fn exporter(&self, args: &[Value]) -> RenderResult<Value> {
        arity(args, 3, 3)?;
        let label = args[0]
            .as_go_bytes()
            .ok_or_else(|| error("TLS exporter label requires string"))?;
        let context = match &args[1] {
            Value::Nil => None,
            Value::Slice(slice) => {
                if !matches!(slice.go_type(), "[]uint8" | "[]byte")
                    && !slice
                        .named_type()
                        .is_some_and(|kind| kind.element == "uint8")
                {
                    return Err(error("TLS exporter context requires []uint8"));
                }
                if slice.is_nil() {
                    None
                } else {
                    Some(
                        slice
                            .visible_bytes()
                            .ok_or_else(|| error("TLS exporter context requires []uint8"))?,
                    )
                }
            }
            _ => return Err(error("TLS exporter context requires []uint8")),
        };
        let length = match args[2] {
            Value::Int(n) if n >= 0 => {
                usize::try_from(n).map_err(|_| error("invalid TLS exporter length"))?
            }
            _ => return Err(error("invalid TLS exporter length")),
        };
        if length > 1 << 20 {
            return Err(error("TLS exporter length exceeds byte limit"));
        }
        let peak = length
            .checked_mul(2)
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| error("TLS exporter size overflow"))?;
        self.reserve(peak)?;
        self.work(length.div_ceil(64) + 1)?;
        let output = self
            .snapshot()?
            .export_keying_material_bytes(label, context.as_deref(), length)
            .map_err(observation)?;
        if output.len() != length || output.capacity() > length {
            return Err(error("TLS exporter violated prepaid output capacity"));
        }
        Ok(Value::Slice(TypedSlice::bytes(Some(Arc::from(
            output.as_slice(),
        )))))
    }
}
fn observation(error: ConnectionSnapshotError) -> gotmpl::TemplateError {
    super::error(error.to_string())
}
fn sequence_peak(count: usize) -> RenderResult<usize> {
    count
        .checked_mul(std::mem::size_of::<Value>() * 2 + 32)
        .and_then(|n| n.checked_add(256))
        .ok_or_else(|| error("TLS slice size overflow"))
}
fn exporter_signature() -> Signature {
    Signature::new(vec![ArgKind::String, ArgKind::Any, ArgKind::Int], None)
}
pub(super) fn value(
    snapshot: Option<Arc<ConnectionSnapshot>>,
    slot: &Cache,
    control: &Arc<Control>,
    nil: bool,
) -> RenderResult<Value> {
    if nil {
        control.reserve_host_bytes(4096)?;
        let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
        methods.insert(
            "ExportKeyingMaterial".into(),
            Arc::new(|args| {
                arity(args, 3, 3)?;
                Err(error(
                    "nil pointer evaluating *tls.ConnectionState.ExportKeyingMaterial",
                ))
            }),
        );
        return Ok(Value::Object(Arc::new(Object {
            fields: FIELDS.iter().map(|s| (Arc::from(*s), Value::Nil)).collect(),
            nil_pointer: Some(Arc::new(|| true)),
            methods,
            method_signatures: BTreeMap::from([(
                "ExportKeyingMaterial".into(),
                exporter_signature(),
            )]),
            go_type: Some("*tls.ConnectionState"),
            ..Object::default()
        })));
    }
    let factory = {
        let mut slot = slot
            .lock()
            .map_err(|_| error("TLS request cache poisoned"))?;
        if let Some((owner, factory)) = &*slot {
            if Weak::ptr_eq(owner, &Arc::downgrade(control)) {
                factory.clone()
            } else {
                control.reserve_host_bytes(2048)?;
                let factory = Arc::new(Factory {
                    snapshot,
                    control: Arc::downgrade(control),
                    certificates: Mutex::new(BTreeMap::new()),
                });
                *slot = Some((Arc::downgrade(control), factory.clone()));
                factory
            }
        } else {
            control.reserve_host_bytes(2048)?;
            let factory = Arc::new(Factory {
                snapshot,
                control: Arc::downgrade(control),
                certificates: Mutex::new(BTreeMap::new()),
            });
            *slot = Some((Arc::downgrade(control), factory.clone()));
            factory
        }
    };
    control.reserve_host_bytes(4096)?;
    let fields = FIELDS
        .iter()
        .map(|name| (Arc::from(*name), Value::Nil))
        .collect();
    let dynamic = factory.clone();
    let exporter = factory.clone();
    let owner = Arc::downgrade(control);
    Ok(Value::Object(Arc::new(Object {
        fields,
        go_type: Some("*tls.ConnectionState"),
        field_order: Some(
            FIELDS
                .iter()
                .map(|s| Arc::from(*s))
                .collect::<Vec<_>>()
                .into(),
        ),
        pointer_identity: Some(factory.snapshot.as_ref().map_or_else(
            || Arc::as_ptr(&factory) as usize,
            |s| Arc::as_ptr(s) as usize,
        )),
        lazy_fields: true,
        dynamic_fields: Some(Arc::new(move |name| dynamic.field(name))),
        field_charge: Some(Arc::new(move |_| {
            owner
                .upgrade()
                .ok_or_else(|| error("TLS template owner retired"))?
                .check()
        })),
        methods: BTreeMap::from([(
            "ExportKeyingMaterial".into(),
            Arc::new(move |args: &[Value]| exporter.exporter(args)) as ValueFunc,
        )]),
        method_signatures: BTreeMap::from([("ExportKeyingMaterial".into(), exporter_signature())]),
        ..Object::default()
    })))
}
fn curve_string(value: i64) -> String {
    match value {
        23 => "CurveP256".into(),
        24 => "CurveP384".into(),
        25 => "CurveP521".into(),
        29 => "X25519".into(),
        4588 => "X25519MLKEM768".into(),
        4587 => "SecP256r1MLKEM768".into(),
        4589 => "SecP384r1MLKEM1024".into(),
        514 => "MLKEM1024".into(),
        _ => format!("CurveID({value})"),
    }
}
fn curve(value: u16) -> Value {
    static TYPE: LazyLock<Arc<gotmpl::Int64Type>> = LazyLock::new(|| {
        Arc::new(gotmpl::Int64Type {
            name: "tls.CurveID",
            kind: "uint16",
            stringer: Some(curve_string),
            methods: BTreeMap::from([(
                "String".into(),
                Arc::new(|value, args: &[Value]| {
                    arity(args, 0, 0)?;
                    Ok(Value::String(curve_string(value).into()))
                }) as gotmpl::Int64Method,
            )]),
            signatures: BTreeMap::new(),
        })
    });
    Value::NamedInt64(i64::from(value), TYPE.clone())
}
