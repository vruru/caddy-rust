//! Handshake identity remains attached to its TLS connection; each new HTTP
//! operation is admitted against the currently published route/TLS policy.
use super::*;
use crate::leaf_guard::{LeafState, leaf_id};
use crate::tls_resolver::CertificateSelection;
use rustls::{ProtocolVersion, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub(super) struct TlsIdentity {
    sni: String,
    offered_alpn: Vec<Vec<u8>>,
    schemes: Vec<SignatureScheme>,
    chain_hash: [u8; 32],
    version: ProtocolVersion,
    leaf: Arc<LeafState>,
}
fn chain_hash(key: &CertifiedKey) -> [u8; 32] {
    let mut hash = Sha256::new();
    for certificate in &key.cert {
        hash.update((certificate.as_ref().len() as u64).to_be_bytes());
        hash.update(certificate.as_ref());
    }
    hash.finalize().into()
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TlsVerdict {
    Serve,
    ServeThenClose,
    Reject,
}
impl TlsIdentity {
    pub(super) fn resumable_for(&self, chain_hash: &[u8; 32]) -> bool {
        self.chain_hash == *chain_hash && self.leaf.admission().allow_certificate
    }
    pub(super) fn verdict(&self, current: &ActiveServer, h2: bool) -> TlsVerdict {
        if !self.leaf.admission().allow_certificate
            || !current.plan.tls
            || !current
                .plan
                .protocols
                .iter()
                .any(|p| p == if h2 { "h2" } else { "h1" })
        {
            return TlsVerdict::Reject;
        }
        let alpn = self
            .offered_alpn
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let Some(key) = current.resolver.as_ref().and_then(|r| {
            r.select_for_version(Some(&self.sni), &alpn, &self.schemes, self.version)
        }) else {
            return TlsVerdict::Reject;
        };
        if chain_hash(&key.key) == self.chain_hash {
            TlsVerdict::Serve
        } else {
            TlsVerdict::ServeThenClose
        }
    }
}
struct FixedResolver {
    resolver: Arc<CandidateResolver>,
    state: Arc<connection_sessions::HandshakeState>,
    selection: OnceLock<(ProtocolVersion, CertificateSelection)>,
    sni: String,
    acme: bool,
    offered_alpn: Vec<Vec<u8>>,
}
impl fmt::Debug for FixedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedResolver").finish_non_exhaustive()
    }
}
impl ResolvesServerCert for FixedResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if crate::challenge::normalize_domain(hello.server_name()?)
            .ok()?
            .as_str()
            != self.sni
        {
            return None;
        }
        let protocols = hello
            .alpn()
            .map(|a| a.collect::<Vec<_>>())
            .unwrap_or_default();
        if !protocols
            .iter()
            .copied()
            .eq(self.offered_alpn.iter().map(Vec::as_slice))
        {
            return None;
        }
        if protocols.contains(&ACME_ALPN) {
            if !self.acme || protocols != [ACME_ALPN] {
                return None;
            }
        } else if self.acme {
            return None;
        }
        let version = hello.negotiated_version()?;
        if self.selection.get().is_none() {
            let selection = self.resolver.select_for_version(
                Some(&self.sni),
                &protocols,
                hello.signature_schemes(),
                version,
            )?;
            if !selection.signature_compatibility.allows(version) {
                return None;
            }
            let _ = self.selection.set((version, selection));
        }
        let (selected_version, selection) = self.selection.get()?;
        if *selected_version != version || !selection.signature_compatibility.allows(version) {
            return None;
        }
        selection.key.key.choose_scheme(hello.signature_schemes())?;
        let hash = chain_hash(&selection.key);
        if let Some(previous) = self.state.selected_chain.get() {
            if previous != &hash {
                return None;
            }
        } else if self.state.selected_chain.set(hash).is_err() {
            return None;
        }
        Some(selection.key.clone())
    }
}
pub(super) struct AcceptedTls {
    pub stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    pub identity: Arc<TlsIdentity>,
    pub server: Arc<ActiveServer>,
}
pub(super) async fn accept(
    inner: &Arc<Inner>,
    stream: tokio::net::TcpStream,
    address: SocketAddr,
) -> Result<AcceptedTls> {
    let start =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
    let generation = inner.current.load_full();
    let server = generation
        .servers
        .get(&address)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("TLS listener retired"))?;
    let resolver = server
        .resolver
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS listener policy changed"))?;
    let hello = start.client_hello();
    let raw_sni = hello
        .server_name()
        .ok_or_else(|| anyhow::anyhow!("TLS DNS identity required"))?
        .to_owned();
    let sni = crate::challenge::normalize_domain(&raw_sni)
        .map_err(|_| anyhow::anyhow!("invalid TLS identity name"))?;
    let protocols = hello
        .alpn()
        .map(|a| a.collect::<Vec<_>>())
        .unwrap_or_default();
    let schemes = hello.signature_schemes().to_vec();
    ensure!(
        !protocols.contains(&ACME_ALPN) || protocols == [ACME_ALPN],
        "mixed ACME ALPN offer"
    );
    // This is only an availability hint: protocol authorization occurs in the
    // real resolver callback after rustls has negotiated the protocol version.
    resolver
        .select_candidate(Some(&sni), &protocols, &schemes)
        .ok_or_else(|| anyhow::anyhow!("TLS identity unavailable"))?;
    let mut config = (**server
        .tls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS listener policy changed"))?)
    .clone();
    let state = Arc::new(connection_sessions::HandshakeState::new());
    let fixed = Arc::new(FixedResolver {
        resolver: resolver.clone(),
        state: state.clone(),
        selection: OnceLock::new(),
        sni: sni.clone(),
        acme: protocols == [ACME_ALPN],
        offered_alpn: protocols.iter().map(|p| p.to_vec()).collect(),
    });
    config.cert_resolver = fixed.clone();
    config.session_storage = Arc::new(connection_sessions::PerConnectionSessions::new(
        server.sessions.clone(),
        state.clone(),
    ));
    let offered_alpn = protocols.iter().map(|p| p.to_vec()).collect();
    // RFC8737 certificates have a mandatory unknown critical extension, so the
    // ordinary leaf-state parser deliberately does not admit them as business.
    if protocols == [ACME_ALPN] {
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        let stream = start.into_stream(Arc::new(config)).await?;
        drop(stream);
        anyhow::bail!("TLS validation completed");
    }
    let stream = start.into_stream(Arc::new(config)).await?;
    let (version, selection) = fixed
        .selection
        .get()
        .ok_or_else(|| anyhow::anyhow!("TLS actual selection unavailable"))?;
    ensure!(
        stream.get_ref().1.protocol_version() == Some(*version),
        "TLS selection version mismatch"
    );
    let key = &selection.key;
    let leaf_certificate = key
        .cert
        .first()
        .ok_or_else(|| anyhow::anyhow!("TLS identity has no certificate"))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf_certificate.as_ref())
        .map_err(|_| anyhow::anyhow!("TLS identity certificate invalid"))?;
    let leaf = resolver.managed.leaf_guard().intern(
        leaf_id(leaf_certificate.as_ref()),
        parsed.validity().not_after.timestamp(),
    )?;
    let full_identity = Arc::new(TlsIdentity {
        sni: sni.clone(),
        offered_alpn,
        schemes,
        chain_hash: chain_hash(key),
        version: *version,
        leaf,
    });
    if stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
        let resumed = state
            .resumed()
            .ok_or_else(|| anyhow::anyhow!("TLS resumption identity unavailable"))?;
        // The cache admitted this exact certificate chain, not just a resolver
        // pointer. ALPN/signature capabilities belong to the current hello,
        // including a resumed hello, rather than the previous connection.
        ensure!(
            resumed.chain_hash == full_identity.chain_hash && resumed.sni == sni,
            "TLS resumption identity mismatch"
        );
    }
    let identity = full_identity;
    state
        .identity
        .set(identity.clone())
        .map_err(|_| anyhow::anyhow!("TLS identity already finalized"))?;
    Ok(AcceptedTls {
        stream,
        identity,
        server,
    })
}
