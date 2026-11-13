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
/// Worker output owns its actual staged data before its credit. An abandoned
/// finished JoinHandle must not refund credit while its certificate copies live.
pub(super) struct StagedSnapshot {
    snapshot:ConnectionSnapshot,
    _memory:Option<crate::acme_wire::chain_memory::Scratch>,
}
impl StagedSnapshot {
    pub(super) fn metadata(&self)->Result<&ConnectionMetadata,ConnectionSnapshotError>{self.snapshot.metadata()}
    /// Call only after the host accepts this completed handshake's identity.
    /// Persistent connection/request snapshots retain their existing separate
    /// output/escaped-Arc boundary; the CPU staging loan ends at that handoff.
    pub(super) fn accept(self)->ConnectionSnapshot{
        let Self{snapshot,_memory}=self;drop(_memory);snapshot
    }
}
impl ConnectionSnapshot {
    pub(super) fn capture_ssl(ssl:&openssl::ssl::SslRef,offered_name:&str,local_chain:&[rustls::pki_types::CertificateDer<'_>],auth:&native_ssl_tls::ServerClientAuth,resumed_group:Option<i64> )->StagedSnapshot{
      let result=(||{
        use ConnectionSnapshotError::Unavailable;
        if !ssl.is_init_finished() || ssl.version2()!=Some(openssl::ssl::SslVersion::TLS1_2){return Err(Unavailable("completed native TLS12 handshake"))}
        let resumed=ssl.session_reused();
        let suite=u16::from_be_bytes(ssl.current_cipher().ok_or(Unavailable("native cipher"))?.protocol_id());
        let group=if resumed{resumed_group.ok_or(Unavailable("authenticated native session group"))?}else{native_ssl_tls::negotiated_group(ssl)};
        let curve=match group{415=>Ok(23),715=>Ok(24),716=>Ok(25),1034=>Ok(29),_=>Err(Unavailable("native negotiated group"))};
        let ems=native_ssl_tls::extended_master_secret(ssl);
        let mut master=zeroize::Zeroizing::new([0u8;48]);
        let session=ssl.session().ok_or(Unavailable("native session secret"))?;
        if session.master_key(master.as_mut())!=48{return Err(Unavailable("native master secret length"))}
        let mut client_random=[0u8;32];let mut server_random=[0u8;32];
        if ssl.client_random(&mut client_random)!=32 || ssl.server_random(&mut server_random)!=32{return Err(Unavailable("native handshake randoms"))}
        use rustls::crypto::aws_lc_rs::cipher_suite::{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384};
        let prf_suite=if matches!(suite,0xc02c|0xc030){TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}else{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
        let rustls::SupportedCipherSuite::Tls12(prf_suite)=prf_suite else{return Err(Unavailable("native PRF"))};let prf=prf_suite.prf_provider;
        let exporter=rustls::native_tls12_exporter(prf,master,client_random,server_random,ems);
        let (peer,observation)=auth.evidence().map_err(|_|Unavailable("native client authentication observation"))?;
        // Output staging covers the actual copied DER until it is accepted by
        // the existing immutable connection snapshot owner. Retained request
        // snapshots keep the existing output/escaped-Arc boundary, not an RSS
        // promise from this short CPU scratch pool.
        let peer_bytes=peer.as_ref().map_or(0,|p|p.certificates().map(<[u8]>::len).sum::<usize>());
        let root_bytes=match &observation {Some(rustls::ClientChainObservation::Verified(set))=>set.paths().iter().filter_map(|p|p.root).map(|i|set.roots().get(usize::from(i)).map_or(0,|r|r.len())).sum::<usize>(),_=>0};
        let local_bytes=local_chain.iter().map(|c|c.len()).sum::<usize>();
        let output_cost=peer_bytes.checked_add(root_bytes).and_then(|n|n.checked_add(local_bytes)).and_then(|n|n.checked_mul(2)).and_then(|n|n.checked_add(65536)).ok_or(Unavailable("native snapshot output staging size"))?;
        let _output=crate::cert_transient::reserve(output_cost).map_err(|_|Unavailable("native snapshot output staging budget"))?;
        let peer:CertificateChain=peer.as_ref().map(|p|p.certificates().map(Arc::<[u8]>::from).collect::<Vec<_>>().into()).unwrap_or_else(||Arc::from([]));
        let verified=verified_paths(observation.as_ref(),&peer);
        let mut finished=[0u8;64];let n=if resumed{ssl.finished(&mut finished)}else{ssl.peer_finished(&mut finished)};
        if n>finished.len(){return Err(Unavailable("native Finished length"))}
        let unique=(n!=0 && (!resumed || ems)).then(||Arc::from(&finished[..n]));
        Ok((ConnectionMetadata{version:0x303,handshake_complete:true,did_resume:resumed,cipher_suite:suite,curve_id_observation:curve,alpn:ssl.selected_alpn_protocol().unwrap_or_default().into(),negotiated_protocol_is_mutual:true,server_name:offered_name.into(),peer_certificates:peer,ech_accepted:false,verified_chains_observation:verified,signed_certificate_timestamps_observation:Ok(Arc::from([])),ocsp_response_observation:Ok(Arc::from([])),tls_unique_observation:Ok(unique),hello_retry_request_observation:Ok(false),local_certificate_observation:Ok(Some(chain(local_chain))),exporter:Some(Arc::new(OwnedExporter(exporter)))},_output))
      })();
      match result {
        Ok((metadata,memory))=>StagedSnapshot{snapshot:Self::from_metadata(Ok(metadata)),_memory:Some(memory)},
        Err(error)=>StagedSnapshot{snapshot:Self::from_metadata(Err(error)),_memory:None},
      }
    }

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
            // Path root indices are u8. Avoid copying every configured root
            // when only a small subset participated in actual verification.
            let mut roots:[Option<CertificateDer>;256]=std::array::from_fn(|_|None);
            let mut chains = Vec::with_capacity(set.paths().len());
            for path in set.paths() {
                let mut chain = vec![leaf.clone()];
                for index in &path.intermediates {
                    chain.push(peer.get(usize::from(*index))
                        .ok_or(Unavailable("verified certificate intermediate index"))?.clone());
                }
                if let Some(index) = path.root {
                    let index=usize::from(index);
                    let slot=&mut roots[index];
                    if slot.is_none(){*slot=Some(Arc::from(set.roots().get(index).ok_or(Unavailable("verified certificate root index"))?.as_ref()));}
                    chain.push(slot.as_ref().ok_or(Unavailable("verified certificate root source"))?.clone());
                }
                chains.push(Arc::<[CertificateDer]>::from(chain));
            }
            Ok(Some(chains.into()))
        }
        None if peer.is_empty() => Ok(None),
        None => Err(Unavailable("completed verifier path observation")),
    }
}
