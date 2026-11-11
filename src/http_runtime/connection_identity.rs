//! Handshake identity remains attached to its TLS connection; each new HTTP
//! operation is admitted against the currently published route/TLS policy.
use super::*;
use crate::leaf_guard::{LeafState, leaf_id};
use crate::stek::ticket::ConnectionTickets;
use crate::tls_resolver::CertificateSelection;
use rustls::{ProtocolVersion, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub(super) struct TlsIdentity {
    sni: String,
    offered_alpn: Vec<Vec<u8>>,
    schemes: Vec<SignatureScheme>,
    chain_hash: [u8; 32],
    not_after: i64,
    version: ProtocolVersion,
    leaf: Arc<LeafState>,
    scope: std::sync::Weak<CandidateResolver>,
    origin: CertificateOrigin,
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
    pub(super) fn server_name(&self) -> &str {
        &self.sni
    }
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
            // On-demand permission/storage errors can evict a managed cache
            // entry while an accepted connection still owns its valid identity.
            // Retain that connection only inside this exact immutable policy;
            // policy replacement, manual selection and leaf withdrawal do not
            // inherit this exception. New handshakes still need a real key.
            let same_scope=current.resolver.as_ref().is_some_and(|resolver| {
                self.scope.upgrade().is_some_and(|scope| Arc::ptr_eq(&scope,resolver))
            });
            // Certificate dates are checked when admitting TLS, not repeatedly
            // as access credentials for an already established connection. The
            // fixed Go server keeps accepted manual HTTP alive across NotAfter.
            // This only retains that exact immutable scope and still respects
            // the leaf-withdrawal and current protocol gates above.
            let naturally_expired=i64::try_from(rustls::pki_types::UnixTime::now().as_secs())
                .is_ok_and(|now| now >= self.not_after);
            let managed_eviction=self.origin == CertificateOrigin::Managed
                && current.resolver.as_ref().is_some_and(|resolver|resolver.provider.is_some());
            return if same_scope && (naturally_expired || managed_eviction) {
                TlsVerdict::Serve
            } else {
                TlsVerdict::Reject
            };
        };
        if chain_hash(&key.key) == self.chain_hash {
            TlsVerdict::Serve
        } else {
            TlsVerdict::ServeThenClose
        }
    }
}
struct FixedSelection {
    version: ProtocolVersion,
    certificate: CertificateSelection,
    origin: CertificateOrigin,
    chain_hash: [u8; 32],
    not_after: i64,
    leaf: Arc<LeafState>,
}
struct FixedResolver {
    resolver: Arc<CandidateResolver>,
    state: Arc<connection_sessions::HandshakeState>,
    selection: OnceLock<FixedSelection>,
    tickets: Option<Arc<ConnectionTickets>>,
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
            let (selection, origin) = self.resolver.select_for_version_with_origin(
                Some(&self.sni),
                &protocols,
                hello.signature_schemes(),
                version,
            )?;
            if !selection.signature_compatibility.allows(version) {
                return None;
            }
            // This is the authoritative selection. Parse the same leaf once,
            // before either resumption lookup, and retain it for final HTTP
            // identity instead of recomputing from a later resolver view.
            let leaf_certificate = selection.key.cert.first()?;
            let (_, parsed) =
                x509_parser::parse_x509_certificate(leaf_certificate.as_ref()).ok()?;
            let not_after = parsed.validity().not_after.timestamp();
            let leaf = self
                .resolver
                .managed
                .leaf_guard()
                .intern(leaf_id(leaf_certificate.as_ref()), not_after)
                .ok()?;
            let hash = chain_hash(&selection.key);
            self.selection
                .set(FixedSelection {
                    version,
                    certificate: selection,
                    origin,
                    chain_hash: hash,
                    not_after,
                    leaf,
                })
                .ok()?;
        }
        let selection = self.selection.get()?;
        if selection.version != version
            || !selection
                .certificate
                .signature_compatibility
                .allows(version)
            || !selection.leaf.admission().allow_certificate
        {
            return None;
        }
        selection
            .certificate
            .key
            .key
            .choose_scheme(hello.signature_schemes())?;
        if *self
            .state
            .selected_chain
            .get_or_init(|| selection.chain_hash)
            != selection.chain_hash
        {
            return None;
        }
        if let Some(tickets) = &self.tickets
            && !tickets.select(
                &self.sni,
                version,
                selection.chain_hash,
                selection.leaf.clone(),
                selection.not_after,
            )
        {
            return None;
        }
        Some(selection.certificate.key.clone())
    }
}
pub(super) struct AcceptedTls<I> {
    pub stream: tokio_rustls::server::TlsStream<I>,
    pub identity: Arc<TlsIdentity>,
    pub server: Arc<ActiveServer>,
}
fn same_business_view(
    generation: &Generation,
    address: &SocketAddr,
    server: &Arc<ActiveServer>,
    activity: &Arc<BusinessGeneration>,
) -> bool {
    generation
        .business(address)
        .is_some_and(|(current, group)| {
            Arc::ptr_eq(server, &current) && Arc::ptr_eq(activity, &group)
        })
}
/// Keep one outstanding acquisition through unrelated publication events. If
/// this exact binding changes policy or stops accepting, cancel only its wait
/// and choose from the latest published view before any TLS identity is pinned.
async fn server_for_hello(
    inner: &Arc<Inner>,
    address: SocketAddr,
    sni: &str,
    alpn: &[&[u8]],
    schemes: &[SignatureScheme],
) -> Result<Arc<ActiveServer>> {
    let mut retries = 0usize;
    'view: loop {
        retries += 1;
        if retries == 8 {
            retries = 0;
            tokio::task::yield_now().await;
        }
        ensure!(!inner.stopped.is_cancelled(), "HTTP runtime is stopping");
        let mut observed = inner.current.load_full();
        let (server, activity) = observed
            .business(&address)
            .ok_or_else(|| anyhow::anyhow!("TLS listener retired"))?;
        let resolver = server
            .resolver
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS listener policy changed"))?;
        // A loaded manual candidate does not ask permission or acquire another
        // certificate. Actual negotiated-version selection remains authoritative.
        let manual = resolver
            .static_certificates
            .select_candidate_filtered(Some(sni), alpn, schemes, &resolver.allowed_static)
            .is_some();
        if !manual && let Some(provider) = &resolver.provider {
            let cancel = CancellationToken::new();
            let _cancel_on_drop = cancel.clone().drop_guard();
            let acquiring = provider.ensure(sni.to_owned(), cancel);
            tokio::pin!(acquiring);
            loop {
                let changed = observed.activity.superseded.clone();
                tokio::select! {biased;
                    _=inner.stopped.cancelled()=>anyhow::bail!("HTTP runtime is stopping"),
                    _=activity.admission_closed.cancelled()=>continue 'view,
                    _=changed.cancelled()=>{
                        let latest=inner.current.load_full();
                        if !same_business_view(&latest,&address,&server,&activity) { continue 'view; }
                        observed=latest;
                        retries += 1;
                        if retries == 8 {
                            retries = 0;
                            tokio::task::yield_now().await;
                        }
                    },
                    result=&mut acquiring=>{
                        let latest=inner.current.load_full();
                        if !same_business_view(&latest,&address,&server,&activity) { continue 'view; }
                        result?;
                        break;
                    },
                }
            }
        }
        if same_business_view(&inner.current.load_full(), &address, &server, &activity) {
            return Ok(server);
        }
    }
}

/// Apply a socket-I/O deadline only while actually reading/writing TLS. A
/// potentially slow permission/issuance callback is governed by its own policy,
/// matching Go's socket deadlines rather than cancelling GetCertificate early.
async fn tls_io_deadline<T>(
    deadline: Option<tokio::time::Instant>,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match deadline {
        Some(deadline) => {
            ensure!(
                deadline > tokio::time::Instant::now(),
                "TLS I/O deadline elapsed"
            );
            tokio::select! {biased;
                _=tokio::time::sleep_until(deadline)=>anyhow::bail!("TLS I/O deadline elapsed"),
                result=future=>result,
            }
        }
        None => future.await,
    }
}
pub(super) async fn accept<I>(
    inner: &Arc<Inner>,
    stream: I,
    admission: std::sync::Weak<connection_budget::Admission>,
    address: SocketAddr,
    deadline: Option<tokio::time::Instant>,
    reply_http: bool,
) -> Result<AcceptedTls<http_redirect::ReplayIo<I>>>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let start = tls_io_deadline(deadline, async move {
        let stream = tls_first_record::prepare(stream, reply_http).await?;
        Ok(
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                .await?,
        )
    })
    .await?;
    let hello = start.client_hello();
    let raw_sni = hello
        .server_name()
        .ok_or_else(|| anyhow::anyhow!("TLS DNS identity required"))?
        .to_owned();
    let sni = crate::challenge::normalize_domain(&raw_sni)
        .map_err(|_| anyhow::anyhow!("invalid TLS identity name"))?;
    let offered_protocols = hello
        .alpn()
        .map(|a| a.map(<[u8]>::to_vec).collect::<Vec<_>>())
        .unwrap_or_default();
    let protocols = offered_protocols
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let schemes = hello.signature_schemes().to_vec();
    ensure!(
        !protocols.contains(&ACME_ALPN) || protocols == [ACME_ALPN],
        "mixed ACME ALPN offer"
    );
    // This connection was accepted in TLS mode, but its business role may have
    // disappeared while ClientHello was paused. A separate legitimate proof
    // owner still has the right to use the runtime registry on the same socket.
    if protocols == [ACME_ALPN] {
        connection_budget::classify_proof(&admission,deadline).await?;
        let config = proof_tls_config(inner.challenge_resolver.clone())?;
        let Some(executor) = inner.tls_executor.get() else {
            anyhow::bail!("TLS executor unavailable");
        };
        executor
            .execute_proof(
                async move {
                    let stream = start.into_stream(config).await?;
                    drop(stream);
                    Ok(())
                },
                inner.stopped.child_token(),
                deadline,
            )
            .await?;
        anyhow::bail!("TLS validation completed");
    }
    connection_budget::classify(&admission,connection_budget::ConnectionClass::Business)?;
    let server = server_for_hello(inner, address, &sni, &protocols, &schemes).await?;
    let resolver = server
        .resolver
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS listener policy changed"))?;
    // Availability is not authorization; final protocol-bound selection still
    // runs in the real resolver callback before session lookup.
    resolver
        .select_candidate(Some(&sni), &protocols, &schemes)
        .ok_or_else(|| anyhow::anyhow!("TLS identity unavailable"))?;
    let mut config = (**server
        .tls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS listener policy changed"))?)
    .clone();
    let state = Arc::new(connection_sessions::HandshakeState::new());
    let tickets =
        connection_sessions::configure(&mut config, &server.tickets, &server.sessions, &state);
    let fixed = Arc::new(FixedResolver {
        resolver: resolver.clone(),
        state: state.clone(),
        selection: OnceLock::new(),
        tickets: tickets.clone(),
        sni: sni.clone(),
        acme: false,
        offered_alpn: protocols.iter().map(|p| p.to_vec()).collect(),
    });
    config.cert_resolver = fixed.clone();
    let offered_alpn = protocols.iter().map(|p| p.to_vec()).collect();
    let resolver = resolver.clone();
    let Some(executor) = inner.tls_executor.get() else {
        anyhow::bail!("TLS executor unavailable");
    };
    let handshake = async move {
        let stream = start.into_stream(Arc::new(config)).await?;
        let selection = fixed
            .selection
            .get()
            .ok_or_else(|| anyhow::anyhow!("TLS actual selection unavailable"))?;
        ensure!(
            stream.get_ref().1.protocol_version() == Some(selection.version)
                && selection.leaf.admission().allow_certificate,
            "TLS selection identity changed"
        );
        let identity = Arc::new(TlsIdentity {
            sni: sni.clone(),
            offered_alpn,
            schemes,
            chain_hash: selection.chain_hash,
            not_after: selection.not_after,
            version: selection.version,
            leaf: selection.leaf.clone(),
            scope: Arc::downgrade(&resolver),
            origin: selection.origin,
        });
        if stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
            if let Some(tickets) = &tickets {
                ensure!(tickets.authenticated(), "TLS ticket identity unavailable");
            } else {
                let resumed = state
                    .resumed()
                    .ok_or_else(|| anyhow::anyhow!("TLS resumption identity unavailable"))?;
                // ALPN and signature capabilities belong to the current
                // hello, including a resumed hello.
                ensure!(
                    resumed.chain_hash == identity.chain_hash && resumed.sni == sni,
                    "TLS resumption identity mismatch"
                );
            }
        }
        state
            .identity
            .set(identity.clone())
            .map_err(|_| anyhow::anyhow!("TLS identity already finalized"))?;
        Ok(AcceptedTls {
            stream,
            identity,
            server,
        })
    };
    executor
        .execute(handshake, inner.stopped.child_token(), deadline)
        .await
}
