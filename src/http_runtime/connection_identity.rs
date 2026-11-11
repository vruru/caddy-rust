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
    wire_sni: String,
    local_ip: String,
    primary_certificate_only: bool,
    session_name: Arc<str>,
    offered_alpn: Vec<Vec<u8>>,
    schemes: Vec<SignatureScheme>,
    chain_hash: [u8; 32],
    not_after: i64,
    version: ProtocolVersion,
    leaf: Arc<LeafState>,
    scope: std::sync::Weak<CandidateResolver>,
    origin: CertificateOrigin,
    policy_index: usize,
    policy_identity: [u8; 32],
}
pub(super) fn chain_hash(key: &CertifiedKey) -> [u8; 32] {
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
        &self.wire_sni
    }
    pub(super) fn session_name(&self) -> &str {
        &self.session_name
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
        if current.policy_identity != self.policy_identity {
            return TlsVerdict::Reject;
        }
        let policy = current.tls_policies.get(self.policy_index);
        let current_resolver = policy.map(|policy| &policy.resolver);
        let Some(key) = policy.and_then(|policy| {
            policy
                .definition
                .certificate_names(&self.sni, &self.local_ip)
                .into_iter()
                .take(if self.primary_certificate_only { 1 } else { 3 })
                .flatten()
                .find_map(|name| {
                    policy.resolver.select_for_version(
                        Some(name),
                        &alpn,
                        &self.schemes,
                        self.version,
                    )
                })
        }) else {
            // On-demand permission/storage errors can evict a managed cache
            // entry while an accepted connection still owns its valid identity.
            // Retain that connection only inside this exact immutable policy;
            // policy replacement, manual selection and leaf withdrawal do not
            // inherit this exception. New handshakes still need a real key.
            let same_scope = current_resolver.is_some_and(|resolver| {
                self.scope
                    .upgrade()
                    .is_some_and(|scope| Arc::ptr_eq(&scope, resolver))
            });
            // Certificate dates are checked when admitting TLS, not repeatedly
            // as access credentials for an already established connection. The
            // fixed Go server keeps accepted manual HTTP alive across NotAfter.
            // This only retains that exact immutable scope and still respects
            // the leaf-withdrawal and current protocol gates above.
            let naturally_expired = i64::try_from(rustls::pki_types::UnixTime::now().as_secs())
                .is_ok_and(|now| now >= self.not_after);
            let managed_eviction = self.origin == CertificateOrigin::Managed
                && current_resolver.is_some_and(|resolver| resolver.provider.is_some());
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
    policy: Arc<tls_policies::PreparedPolicy>,
    state: Arc<connection_sessions::HandshakeState>,
    selection: OnceLock<FixedSelection>,
    tickets: Option<Arc<ConnectionTickets>>,
    sni: String,
    local_ip: String,
    primary_certificate_only: bool,
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
        let offered_name = crate::tls_policy::normalized_offered_name(
            hello.offered_server_name().unwrap_or_default(),
        )
        .ok()?;
        if offered_name != self.sni {
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
            let (selection, origin) = self
                .policy
                .definition
                .certificate_names(&self.sni, &self.local_ip)
                .into_iter()
                .take(if self.primary_certificate_only { 1 } else { 3 })
                .flatten()
                .find_map(|name| {
                    self.policy.resolver.select_for_version_with_origin(
                        Some(name),
                        &protocols,
                        hello.signature_schemes(),
                        version,
                    )
                })?;
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
                .policy
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
                &self.state.session_name,
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
    wire_sni: &str,
    alpn: &[&[u8]],
    schemes: &[SignatureScheme],
    peer_local: (SocketAddr, SocketAddr),
) -> Result<(Arc<ActiveServer>, usize, Arc<tls_policies::PreparedPolicy>)> {
    let (peer, local) = peer_local;
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
        let server_to_match = server.clone();
        let sni_to_match = wire_sni.to_owned();
        let (policy_index, policy) = inner
            .resources
            .metadata
            .run(move || server_to_match.policy(&sni_to_match, peer, local))
            .await
            .map_err(|_| anyhow::anyhow!("TLS policy matching worker unavailable"))?
            .ok_or_else(|| anyhow::anyhow!("no TLS connection policy matched"))?;
        ensure!(
            !policy.definition.drop,
            "TLS connection policy dropped the connection"
        );
        let resolver = &policy.resolver;
        // Never rewrite the actual Hello or its automation permission
        // target to the name of a resident fallback certificate.
        let manual = !sni.is_empty()
            && resolver
                .static_certificates
                .select_candidate_filtered(Some(sni), alpn, schemes, &resolver.allowed_static)
                .is_some();
        let fallback = policy
            .definition
            .fallback_sni
            .as_deref()
            .is_some_and(|name| {
                resolver
                    .select_candidate(Some(name), alpn, schemes)
                    .is_some()
            });
        if !sni.is_empty()
            && sni.parse::<std::net::IpAddr>().is_err()
            && !manual
            && let Some(provider) = &resolver.provider
            && (!fallback || provider.should_probe_before_fallback(sni))
        {
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
            return Ok((server, policy_index, policy));
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
    peer_local: (SocketAddr, SocketAddr),
) -> Result<AcceptedTls<http_redirect::ReplayIo<I>>>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (peer, local) = peer_local;
    let start = tls_io_deadline(deadline, async move {
        let stream = tls_first_record::prepare(stream, reply_http).await?;
        Ok(
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                .await?,
        )
    })
    .await?;
    let hello = start.client_hello();
    let raw_sni = hello.offered_server_name().unwrap_or_default().to_owned();
    let sni = crate::tls_policy::normalized_offered_name(&raw_sni)?;
    let ip_sni = sni.parse::<std::net::IpAddr>().is_ok();
    let local_ip = crate::tls_resolver::canonical_certificate_ip(local.ip());
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
        ensure!(
            !sni.is_empty() && !ip_sni,
            "ACME proof requires an explicit DNS SNI"
        );
        connection_budget::classify_proof(&admission, deadline).await?;
        let config = if let Some((business, _)) = inner.current.load_full().business(&address) {
            let matching = business.clone();
            let proof_name = raw_sni.clone();
            let (_, policy) = inner
                .resources
                .metadata
                .run(move || matching.policy(&proof_name, peer, local))
                .await
                .map_err(|_| anyhow::anyhow!("TLS proof policy worker unavailable"))?
                .ok_or_else(|| anyhow::anyhow!("no TLS proof connection policy matched"))?;
            ensure!(
                !policy.definition.drop,
                "TLS connection policy dropped proof connection"
            );
            let mut config = (*policy.tls).clone();
            config.cert_resolver = inner.challenge_resolver.clone();
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            config.max_tls13_tickets = 0;
            config.max_early_data_size = 0;
            Arc::new(config)
        } else {
            proof_tls_config(inner.challenge_resolver.clone())?
        };
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
    connection_budget::classify(&admission, connection_budget::ConnectionClass::Business)?;
    let (server, policy_index, policy) = server_for_hello(
        inner, address, &sni, &raw_sni, &protocols, &schemes, peer_local,
    )
    .await?;
    let resolver = &policy.resolver;
    // A primary typed IP SAN hit can serve without a permission round trip.
    // Go tries dynamic acquisition before serving any defaulted candidate.
    // Until typed no-SNI and IP admission are wired, fail closed on those
    // dynamic-policy misses; never reinterpret the candidate as a DNS request.
    let primary_certificate_only = (sni.is_empty() || ip_sni)
        && resolver
            .provider
            .as_ref()
            .is_some_and(|provider| provider.should_probe_before_fallback(&sni));
    // Availability is not authorization; final protocol-bound selection still
    // runs in the real resolver callback before session lookup.
    ensure!(
        policy
            .definition
            .certificate_names(&sni, &local_ip)
            .into_iter()
            .take(if primary_certificate_only { 1 } else { 3 })
            .flatten()
            .any(|name| resolver
                .select_candidate(Some(name), &protocols, &schemes)
                .is_some()),
        "{}",
        if primary_certificate_only {
            "typed no-SNI or IP certificate admission unavailable"
        } else {
            "TLS identity unavailable"
        }
    );
    let mut config = (*policy.tls).clone();
    // Go permits an h1-only client to reach a server which only advertised h2
    // without negotiating ALPN. This exception never applies to QUIC or proof.
    if protocols.contains(&b"http/1.1".as_slice())
        && config.alpn_protocols.iter().any(|value| value == b"h2")
        && !protocols.iter().any(|offer| {
            config
                .alpn_protocols
                .iter()
                .any(|value| value.as_slice() == *offer)
        })
    {
        config.alpn_protocols.clear();
    }
    // An omitted SNI uses a distinct session namespace bound to the actual
    // local address. It cannot borrow a ticket from a DNS-named handshake.
    let session_name: Arc<str> = if sni.is_empty() {
        format!("no-sni:{local_ip}").into()
    } else if ip_sni {
        format!("ip-sni:{sni}").into()
    } else {
        sni.as_str().into()
    };
    let state = Arc::new(connection_sessions::HandshakeState::new(
        session_name.clone(),
    ));
    let tickets = connection_sessions::configure(
        &mut config,
        &server.tickets,
        &policy.sessions,
        &state,
        policy.definition.client_auth.is_some(),
        policy.identity,
    );
    let fixed = Arc::new(FixedResolver {
        policy: policy.clone(),
        state: state.clone(),
        selection: OnceLock::new(),
        tickets: tickets.clone(),
        sni: sni.clone(),
        local_ip: local_ip.clone(),
        primary_certificate_only,
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
            sni,
            wire_sni: raw_sni,
            local_ip,
            primary_certificate_only,
            session_name,
            offered_alpn,
            schemes,
            chain_hash: selection.chain_hash,
            not_after: selection.not_after,
            version: selection.version,
            leaf: selection.leaf.clone(),
            scope: Arc::downgrade(&resolver),
            origin: selection.origin,
            policy_index,
            policy_identity: server.policy_identity,
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
                    resumed.chain_hash == identity.chain_hash
                        && resumed.session_name == identity.session_name,
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
