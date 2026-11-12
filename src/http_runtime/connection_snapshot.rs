//! Owned observations from a completed TLS handshake. Request consumers never
//! borrow the TLS stream, and missing observations are not represented by zero.
use std::{fmt, sync::Arc};

pub type CertificateDer = Arc<[u8]>;
pub type CertificateChain = Arc<[CertificateDer]>;
pub type VerifiedChains = Arc<[CertificateChain]>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionSnapshotError {
    Unavailable(&'static str),
    InvalidExporterInput,
    ExporterFailed,
}
impl fmt::Display for ConnectionSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(field) => write!(f, "TLS connection metadata unavailable: {field}"),
            Self::InvalidExporterInput => f.write_str("invalid TLS exporter input"),
            Self::ExporterFailed => f.write_str("TLS exporter failed"),
        }
    }
}
impl std::error::Error for ConnectionSnapshotError {}

/// Implementations retain only an existing read-only exporter capability. They
/// must not introduce a lock around the application's TCP stream.
pub trait ConnectionExporter: Send + Sync {
    fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, ConnectionSnapshotError>;
    /// Preserve arbitrary Go string bytes for exporter labels. Existing custom
    /// exporters keep their UTF-8 method; native exporters override this path.
    fn export_keying_material_bytes(&self, label: &[u8], context: Option<&[u8]>, length: usize)
        -> Result<Vec<u8>, ConnectionSnapshotError> {
        let label = std::str::from_utf8(label).map_err(|_|ConnectionSnapshotError::InvalidExporterInput)?;
        self.export_keying_material(label, context, length)
    }
}

/// An owned snapshot associated with an accepted TLS connection. Public fields
/// contain actual negotiated values; it has no Default implementation.
#[derive(Clone)]
pub struct ConnectionMetadata {
    pub version: u16,
    pub handshake_complete: bool,
    pub did_resume: bool,
    pub cipher_suite: u16,
    pub curve_id_observation: Result<u16, ConnectionSnapshotError>,
    pub alpn: Arc<[u8]>,
    pub negotiated_protocol_is_mutual: bool,
    pub server_name: Arc<str>,
    pub peer_certificates: CertificateChain,
    pub ech_accepted: bool,
    pub verified_chains_observation: Result<Option<VerifiedChains>, ConnectionSnapshotError>,
    pub signed_certificate_timestamps_observation:
        Result<CertificateChain, ConnectionSnapshotError>,
    pub ocsp_response_observation: Result<Arc<[u8]>, ConnectionSnapshotError>,
    pub tls_unique_observation: Result<Option<Arc<[u8]>>, ConnectionSnapshotError>,
    pub hello_retry_request_observation: Result<bool, ConnectionSnapshotError>,
    pub local_certificate_observation: Result<Option<CertificateChain>, ConnectionSnapshotError>,
    pub exporter: Option<Arc<dyn ConnectionExporter>>,
}
#[derive(Clone, Debug)]
pub struct ConnectionSnapshot {
    metadata: Result<ConnectionMetadata, ConnectionSnapshotError>,
}
impl ConnectionSnapshot {
    pub(super) fn capture_tcp(
        connection: &rustls::ServerConnection,
        offered_name: &str,
        local_chain: &[rustls::pki_types::CertificateDer<'_>],
        client_auth: Option<&crate::tls_policy::ClientAuth>,
    ) -> Self {
        Self::from_metadata((|| {
            let native = connection.native_exporter().map_err(|_| ConnectionSnapshotError::Unavailable("TCP exporter"))?;
            let mut metadata = capture(
            Negotiated {
                version: connection.protocol_version().map(u16::from),
                suite: connection
                    .negotiated_cipher_suite()
                    .map(|suite| u16::from(suite.suite())),
                group: connection
                    .negotiated_key_exchange_group()
                    .map(|group| u16::from(group.name())),
                kind: connection.handshake_kind(),
                complete: !connection.is_handshaking(),
                alpn: connection.alpn_protocol().unwrap_or_default().into(),
                offered_name: offered_name.into(),
                peer: chain(connection.peer_certificates().unwrap_or_default()),
            },
            local_chain,
            verifies_chain(client_auth),
            Some(Arc::new(OwnedExporter(native))),
        )?;
            metadata.ocsp_response_observation = Ok(connection.native_peer_ocsp_response()
                .ok_or(ConnectionSnapshotError::Unavailable("completed client certificate OCSP"))?.into());
            metadata.signed_certificate_timestamps_observation = Ok(connection.native_peer_scts()
                .ok_or(ConnectionSnapshotError::Unavailable("completed client certificate SCTs"))?
                .iter().map(|sct|Arc::from(sct.as_slice())).collect::<Vec<_>>().into());
            metadata.tls_unique_observation = Ok(connection.native_tls_unique().map(Arc::from));
            metadata.hello_retry_request_observation = Ok(connection.native_hello_retry_request());
            metadata.curve_id_observation = connection.native_curve_id()
                .ok_or(ConnectionSnapshotError::Unavailable("authenticated session key exchange group"));
            metadata.verified_chains_observation = verified_paths(connection.native_client_chains(),
                &metadata.peer_certificates);

            Ok(metadata)
        })())
    }

    pub(super) fn capture_quic(
        connection: &quinn::Connection,
        offered_name: &str,
        local_chain: &[rustls::pki_types::CertificateDer<'_>],
        client_auth: Option<&crate::tls_policy::ClientAuth>,
    ) -> Self {
        Self::from_metadata((|| {
            let data = connection
                .handshake_data()
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .ok_or(ConnectionSnapshotError::Unavailable(
                    "QUIC negotiated handshake",
                ))?;
            let peer = match connection.peer_identity() {
                None => Arc::from([]),
                Some(peer) => {
                    let peer = peer
                        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                        .map_err(|_| {
                            ConnectionSnapshotError::Unavailable("QUIC peer certificates")
                        })?;
                    chain(&peer)
                }
            };
            let mut metadata = capture(
                Negotiated {
                    version: data.protocol_version,
                    suite: data.cipher_suite,
                    group: data.key_exchange_group,
                    kind: data.handshake_kind,
                    complete: data.handshake_complete,
                    alpn: data.protocol.as_deref().unwrap_or_default().into(),
                    offered_name: offered_name.into(),
                    peer,
                },
                local_chain,
                verifies_chain(client_auth),
                Some(Arc::new(OwnedExporter(data.owned_exporter.clone()
                    .ok_or(ConnectionSnapshotError::Unavailable("QUIC owned exporter"))?))),
            )?;
            metadata.ocsp_response_observation = Ok(data.peer_ocsp_response.as_deref()
                .ok_or(ConnectionSnapshotError::Unavailable("QUIC completed client certificate OCSP"))?.into());
            metadata.signed_certificate_timestamps_observation = Ok(data.peer_scts.as_ref()
                .ok_or(ConnectionSnapshotError::Unavailable("QUIC completed client certificate SCTs"))?
                .iter().map(|sct|Arc::from(sct.as_slice())).collect::<Vec<_>>().into());
            metadata.hello_retry_request_observation = Ok(data.hello_retry_request);
            metadata.verified_chains_observation = verified_paths(data.client_chain_observation.as_ref(),
                &metadata.peer_certificates);

            Ok(metadata)
        })())
    }

    pub fn from_metadata(metadata: Result<ConnectionMetadata, ConnectionSnapshotError>) -> Self {
        Self { metadata }
    }
    pub fn metadata(&self) -> Result<&ConnectionMetadata, ConnectionSnapshotError> {
        self.metadata.as_ref().map_err(|error| *error)
    }
    pub fn curve_id(&self) -> Result<u16, ConnectionSnapshotError> {
        self.metadata()?.curve_id_observation
    }

    pub fn verified_chains(&self) -> Result<Option<VerifiedChains>, ConnectionSnapshotError> {
        self.metadata()?.verified_chains_observation.clone()
    }
    pub fn signed_certificate_timestamps(
        &self,
    ) -> Result<CertificateChain, ConnectionSnapshotError> {
        self.metadata()?
            .signed_certificate_timestamps_observation
            .clone()
    }
    pub fn ocsp_response(&self) -> Result<Arc<[u8]>, ConnectionSnapshotError> {
        self.metadata()?.ocsp_response_observation.clone()
    }
    pub fn tls_unique(&self) -> Result<Option<Arc<[u8]>>, ConnectionSnapshotError> {
        self.metadata()?.tls_unique_observation.clone()
    }
    pub fn hello_retry_request(&self) -> Result<bool, ConnectionSnapshotError> {
        self.metadata()?.hello_retry_request_observation
    }
    pub fn local_certificate(&self) -> Result<Option<CertificateChain>, ConnectionSnapshotError> {
        self.metadata()?.local_certificate_observation.clone()
    }
    pub fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, ConnectionSnapshotError> {
        self.export_keying_material_bytes(label.as_bytes(), context, length)
    }
    /// Export with a byte-preserving Go label, including non-UTF-8 strings.
    pub fn export_keying_material_bytes(&self,label:&[u8],context:Option<&[u8]>,length:usize)
        -> Result<Vec<u8>,ConnectionSnapshotError> {
        self.metadata()?.exporter.as_ref()
            .ok_or(ConnectionSnapshotError::Unavailable("ExportKeyingMaterial"))?
            .export_keying_material_bytes(label,context,length)
    }
}

struct Negotiated {
    version: Option<u16>,
    suite: Option<u16>,
    group: Option<u16>,
    kind: Option<rustls::HandshakeKind>,
    complete: bool,
    alpn: Arc<[u8]>,
    offered_name: Arc<str>,
    peer: CertificateChain,
}

fn chain(certificates: &[rustls::pki_types::CertificateDer<'_>]) -> CertificateChain {
    certificates
        .iter()
        .map(|certificate| Arc::from(certificate.as_ref()))
        .collect::<Vec<_>>()
        .into()
}

fn verifies_chain(auth: Option<&crate::tls_policy::ClientAuth>) -> bool {
    use crate::tls_policy::ClientAuthMode;
    auth.filter(|auth| auth.is_active()).is_some_and(|auth| {
        let has_trust = auth.ca.is_some()
            || !auth.trusted_ca_certs.is_empty()
            || !auth.trusted_ca_certs_pem_files.is_empty()
            || !auth.trusted_leaf_certs.is_empty();
        let mode = auth.mode.unwrap_or(if has_trust {
            ClientAuthMode::RequireAndVerify
        } else {
            ClientAuthMode::Require
        });
        matches!(
            mode,
            ClientAuthMode::VerifyIfGiven | ClientAuthMode::RequireAndVerify
        )
    })
}

fn capture(
    observed: Negotiated,
    local_chain: &[rustls::pki_types::CertificateDer<'_>],
    verifies_peer: bool,
    exporter: Option<Arc<dyn ConnectionExporter>>,
) -> Result<ConnectionMetadata, ConnectionSnapshotError> {
    use ConnectionSnapshotError::Unavailable;
    use rustls::HandshakeKind;
    if !observed.complete {
        return Err(Unavailable("completed handshake"));
    }
    let version = observed.version.ok_or(Unavailable("TLS version"))?;
    if version != 0x0303 && version != 0x0304 {
        return Err(Unavailable("TLS version"));
    }
    let cipher_suite = observed.suite.ok_or(Unavailable("cipher suite"))?;
    let kind = observed.kind.ok_or(Unavailable("handshake kind"))?;
    let did_resume = match kind {
        HandshakeKind::Resumed => true,
        HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest => false,
    };
    let curve_id_observation = match observed.group {
        Some(group) => Ok(group),
        None if version == 0x0303 && did_resume => Err(Unavailable("TLS1.2 resumed CurveID")),
        None => return Err(Unavailable("negotiated key exchange group")),
    };
    let hello_retry_request_observation = if version == 0x0303 {
        Ok(false)
    } else {
        match kind {
            HandshakeKind::FullWithHelloRetryRequest => Ok(true),
            HandshakeKind::Full => Ok(false),
            _ => Err(Unavailable("TLS1.3 resumed HelloRetryRequest")),
        }
    };
    if !did_resume && local_chain.is_empty() {
        return Err(Unavailable("selected local certificate"));
    }
    let verified_chains_observation = if observed.peer.is_empty() || !verifies_peer {
        Ok(None)
    } else {
        Err(Unavailable("verified certificate paths"))
    };
    Ok(ConnectionMetadata {
        version,
        handshake_complete: observed.complete,
        did_resume,
        cipher_suite,
        curve_id_observation,
        alpn: observed.alpn,
        negotiated_protocol_is_mutual: true,
        server_name: observed.offered_name,
        peer_certificates: observed.peer,
        // This server does not implement ECH acceptance. Peer extensions are
        // replaced by authenticated completed TCP/QUIC observations above.
        ech_accepted: false,
        verified_chains_observation,
        signed_certificate_timestamps_observation: Ok(Arc::from([])),
        ocsp_response_observation: Ok(Arc::from([])),
        tls_unique_observation: if version == 0x0304 {
            Ok(None)
        } else {
            Err(Unavailable("TLS1.2 TLSUnique"))
        },
        hello_retry_request_observation,
        local_certificate_observation: Ok((!did_resume).then(|| chain(local_chain))),
        exporter,
    })
}

// Snapshot calls allocate owned output; retain a separate explicit request
// budget for TLS 1.2, whose PRF has no cryptographic output-size bound.
const MAX_TCP_EXPORT_BYTES: usize = 1024 * 1024;
struct OwnedExporter(Arc<dyn rustls::NativeExporter>);
impl ConnectionExporter for OwnedExporter {
    fn export_keying_material(&self,label:&str,context:Option<&[u8]>,length:usize)
        -> Result<Vec<u8>,ConnectionSnapshotError> {
        self.export_keying_material_bytes(label.as_bytes(),context,length)
    }
    fn export_keying_material_bytes(&self,label:&[u8],context:Option<&[u8]>,length:usize)
        -> Result<Vec<u8>,ConnectionSnapshotError> {
        if length > MAX_TCP_EXPORT_BYTES { return Err(ConnectionSnapshotError::InvalidExporterInput); }
        let mut output=vec![0;length];
        self.0.export_keying_material(&mut output,label,context)
            .map_err(|_|ConnectionSnapshotError::ExporterFailed)?;
        Ok(output)
    }
}

impl fmt::Debug for ConnectionMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSnapshot")
            .field("version", &self.version)
            .field("handshake_complete", &self.handshake_complete)
            .field("did_resume", &self.did_resume)
            .field("cipher_suite", &self.cipher_suite)
            .field("curve_id", &self.curve_id_observation)
            .finish_non_exhaustive()
    }
}

fn verified_paths(observation: Option<&rustls::ClientChainObservation>, peer: &CertificateChain)
    -> Result<Option<VerifiedChains>, ConnectionSnapshotError> {
    use rustls::{ClientChainObservation as Observation,ChainUnavailable};
    use ConnectionSnapshotError::Unavailable;
    if peer.is_empty() { return Ok(None); }
    match observation {
        Some(Observation::NotVerified) => Ok(None),
        Some(Observation::Unavailable(reason)) => Err(Unavailable(match reason {
            ChainUnavailable::EnumerationLimit => "verified certificate path enumeration limit",
            ChainUnavailable::RootSourceUnknown => "verified certificate exact root source",
            ChainUnavailable::PlatformVerifier => "platform verified certificate paths",
            ChainUnavailable::PolicyDivergence => "verified certificate path policy divergence",
            ChainUnavailable::TooLargeForSession => "verified certificate path session size limit",
            ChainUnavailable::LegacySession => "legacy verified certificate session observation",
        })),
        Some(Observation::Verified(set)) => {
            let leaf = peer.first().ok_or(Unavailable("verified certificate peer leaf"))?;
            let roots = set.roots().iter().map(|root|Arc::<[u8]>::from(root.as_ref()))
                .collect::<Vec<_>>();
            let mut chains = Vec::with_capacity(set.paths().len());
            for path in set.paths() {
                let mut chain = vec![leaf.clone()];
                for index in &path.intermediates {
                    chain.push(peer.get(usize::from(*index))
                        .ok_or(Unavailable("verified certificate intermediate index"))?.clone());
                }
                if let Some(index) = path.root {
                    chain.push(roots.get(usize::from(index))
                        .ok_or(Unavailable("verified certificate root index"))?.clone());
                }
                chains.push(Arc::<[CertificateDer]>::from(chain));
            }
            Ok(Some(chains.into()))
        }
        None if peer.is_empty() => Ok(None),
        None => Err(Unavailable("completed verifier path observation")),
    }
}
