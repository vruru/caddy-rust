//! Handshake identity remains attached to its TLS connection; each new HTTP
//! operation is admitted against the currently published route/TLS policy.
use super::*;
use crate::leaf_guard::{LeafState, leaf_id};
use rustls::SignatureScheme;
use sha2::{Digest, Sha256};

pub(super) struct TlsIdentity {
    sni: String,
    offered_alpn: Vec<Vec<u8>>,
    schemes: Vec<SignatureScheme>,
    chain_hash: [u8; 32],
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
        let Some(key) = current
            .resolver
            .as_ref()
            .and_then(|r| r.select(Some(&self.sni), &alpn, &self.schemes))
        else {
            return TlsVerdict::Reject;
        };
        if chain_hash(&key) == self.chain_hash {
            TlsVerdict::Serve
        } else {
            TlsVerdict::ServeThenClose
        }
    }
}
struct FixedResolver {
    key: Arc<CertifiedKey>,
    sni: String,
    acme: bool,
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
        if protocols.contains(&ACME_ALPN) {
            if !self.acme || protocols != [ACME_ALPN] {
                return None;
            }
        } else if self.acme {
            return None;
        }
        self.key.key.choose_scheme(hello.signature_schemes())?;
        Some(self.key.clone())
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
    let key = resolver
        .select(Some(&sni), &protocols, &schemes)
        .ok_or_else(|| anyhow::anyhow!("TLS identity unavailable"))?;
    let mut config = (**server
        .tls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS listener policy changed"))?)
    .clone();
    config.cert_resolver = Arc::new(FixedResolver {
        key: key.clone(),
        sni: sni.clone(),
        acme: protocols == [ACME_ALPN],
    });
    let state = Arc::new(connection_sessions::HandshakeState::new());
    config.session_storage = Arc::new(connection_sessions::PerConnectionSessions::new(
        server.sessions.clone(),
        state.clone(),
        chain_hash(&key),
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
        chain_hash: chain_hash(&key),
        leaf,
    });
    let stream = start.into_stream(Arc::new(config)).await?;
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
