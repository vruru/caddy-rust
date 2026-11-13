//! Handshake identity remains attached to its TLS connection; each new HTTP
//! operation is admitted against the currently published route/TLS policy.
use crate::net_address::NetAddress;

// CertMagic selects the local host when SNI is absent. Unlike ACL parsing,
// this lookup may use a bare IP or a DNS-shaped Unix address, and drops zones.
fn local_certificate_name(local:&NetAddress)->String{
    let raw=local.raw_host();
    let host=raw.split(|byte|*byte==b'%').next().unwrap_or_default();
    let Ok(host)=std::str::from_utf8(host)else{return String::new();};
    host.parse::<std::net::IpAddr>().map(crate::tls_resolver::canonical_certificate_ip)
        .unwrap_or_else(|_|host.to_owned())
}
use super::certificate_choice::{Choice, eligible_names};
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
    acquired: Option<AcquiredCertificate>,
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
    explicit_selector: bool,
    instance: Option<crate::tls_resolver::CertificateInstance>,
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
        let Some((key, _)) = policy.and_then(|policy| {
            if let Some(acquired) = &self.acquired {
                return acquired.select(&policy.resolver.managed, &self.schemes, Some(self.version))
                    .map(|key| (key, CertificateOrigin::Managed));
            }
            if self.explicit_selector {
                return policy.resolver.choose_pinned(self.instance?, self.origin,
                    (!self.sni.is_empty()).then_some(self.sni.as_str()), &self.schemes, self.version).selected();
            }
            policy
                .resolver
                .choose(
                    eligible_names(
                        &policy.definition,
                        &self.sni,
                        &self.local_ip,
                        self.primary_certificate_only,
                    ),
                    (!self.sni.is_empty()).then_some(self.sni.as_str()),
                    &alpn,
                    &self.schemes,
                    Some(self.version),
                )
                .selected()
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
        // select_pinned checked the full-chain identity and exact publication
        // instance. No repeated DER hashing or global preference is needed.
        if self.explicit_selector || chain_hash(&key.key) == self.chain_hash {
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
struct PinnedProof {
    registry:crate::challenge::ChallengeRegistry,
    sni:String,
    registration:Option<crate::challenge::TlsRegistration>,
}
impl fmt::Debug for PinnedProof {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.debug_struct("PinnedProof").finish_non_exhaustive()}}
impl ResolvesServerCert for PinnedProof {
    fn resolve(&self,hello:ClientHello<'_>)->Option<Arc<CertifiedKey>> {
        let name=crate::tls_policy::normalized_offered_name(hello.offered_server_name().unwrap_or_default()).ok()?;
        let protocols=hello.alpn()?.collect::<Vec<_>>();
        let registration=self.registration.as_ref()?;
        (name==self.sni && protocols==[ACME_ALPN] && self.registry.tls_generation_current(&name,registration.generation))
            .then(||registration.certificate.clone())
    }
}
async fn proof_event(inner:&Arc<Inner>,registration:Option<&crate::challenge::TlsRegistration>,
    app:Option<&Arc<crate::events::EventsApp>>,fields:&super::tls_events::HelloFields,
    peer_local:(NetAddress,NetAddress),cancel:&CancellationToken)->Result<()> {
    let event_cancel=cancel.child_token();let _cancel_on_drop=event_cancel.clone().drop_guard();
    let future=super::tls_events::emit(app,fields,&inner.resources,
        (peer_local.0,peer_local.1,super::tls_events::Transport::Tcp),&event_cancel);
    if let Some(registration)=registration {
        tokio::select! {biased;
            _=registration.cancel.cancelled()=>anyhow::bail!("TLS proof owner cancelled"),
            _=tokio::time::sleep_until(registration.expires.into())=>anyhow::bail!("TLS proof expired"),
            result=future=>result,
        }
    }else{future.await}
}
async fn proof_lifetime<T>(future:impl std::future::Future<Output=Result<T>>,owner:Option<(CancellationToken,std::time::Instant)>)->Result<T>{
 if let Some((cancel,expires))=owner{
  tokio::select!{biased;
    _=cancel.cancelled()=>anyhow::bail!("TLS proof owner cancelled"),
    _=tokio::time::sleep_until(expires.into())=>anyhow::bail!("TLS proof expired"),
    result=future=>result,
  }
 }else{future.await}
}
pub(super) async fn accept_proof<I>(inner:&Arc<Inner>,stream:I,config:Arc<rustls::ServerConfig>,
    peer_local:(NetAddress,NetAddress),cancel:CancellationToken)->Result<()>
where I:tokio::io::AsyncRead+tokio::io::AsyncWrite+Unpin+Send+'static {
    let start=tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(),stream).await?;
    let hello=start.client_hello();let fields=super::tls_events::HelloFields::capture(&hello);
    let name=crate::tls_policy::normalized_offered_name(hello.offered_server_name().unwrap_or_default())?;
    let protocols=hello.alpn().map(|a|a.collect::<Vec<_>>()).unwrap_or_default();
    ensure!(protocols==[ACME_ALPN],"TLS proof listener requires ACME ALPN");
    let registration=inner.registry.tls_registration(&name,&protocols);
    let app=registration.as_ref().and_then(|r|r.events.clone());
    proof_event(inner,registration.as_ref(),app.as_ref(),&fields,peer_local,&cancel).await?;
    let proof_owner=registration.as_ref().map(|r|(r.cancel.clone(),r.expires));
    let mut config=(*config).clone();
    config.cert_resolver=Arc::new(PinnedProof{registry:inner.registry.clone(),sni:name,registration});
    let executor=inner.tls_executor.get().ok_or_else(||anyhow::anyhow!("TLS executor unavailable"))?;
    executor.execute_proof(proof_lifetime(async move {let stream=start.into_stream(Arc::new(config)).await?;drop(stream);Ok(())},proof_owner),cancel,None).await
}
struct FixedResolver {
    policy: Arc<tls_policies::PreparedPolicy>,
    state: Arc<connection_sessions::HandshakeState>,
    selection: OnceLock<FixedSelection>,
    tickets: Option<Arc<ConnectionTickets>>,
    sni: String,
    local_ip: String,
    primary_certificate_only: bool,
    acquired: Option<AcquiredCertificate>,
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
            let (selection, origin) = if let Some(acquired) = &self.acquired {
                let selection = acquired.select(&self.policy.resolver.managed, hello.signature_schemes(), Some(version))?;
                (selection, CertificateOrigin::Managed)
            } else {
                self.policy.resolver.choose(eligible_names(&self.policy.definition, &self.sni,
                    &self.local_ip, self.primary_certificate_only),
                    (!self.sni.is_empty()).then_some(self.sni.as_str()), &protocols,
                    hello.signature_schemes(), Some(version)).selected()?
            };
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
    pub stream: TlsStream<I>,
    pub identity: Arc<TlsIdentity>,
    pub snapshot: Arc<ConnectionSnapshot>,
    pub server: Arc<ActiveServer>,
}
pub(super) enum TlsStream<I> {
    Rustls(tokio_rustls::server::TlsStream<I>),
    Native(native_ssl_tls::ServerStream<I>),
}
impl<I: tokio::io::AsyncRead+tokio::io::AsyncWrite+Unpin> tokio::io::AsyncRead for TlsStream<I>{
 fn poll_read(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>,buf:&mut tokio::io::ReadBuf<'_>)->std::task::Poll<std::io::Result<()>>{match self.get_mut(){Self::Rustls(v)=>std::pin::Pin::new(v).poll_read(cx,buf),Self::Native(v)=>std::pin::Pin::new(v).poll_read(cx,buf)}}
}
impl<I: tokio::io::AsyncRead+tokio::io::AsyncWrite+Unpin> tokio::io::AsyncWrite for TlsStream<I>{
 fn poll_write(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>,buf:&[u8])->std::task::Poll<std::io::Result<usize>>{match self.get_mut(){Self::Rustls(v)=>std::pin::Pin::new(v).poll_write(cx,buf),Self::Native(v)=>std::pin::Pin::new(v).poll_write(cx,buf)}}
 fn poll_flush(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<std::io::Result<()>>{match self.get_mut(){Self::Rustls(v)=>std::pin::Pin::new(v).poll_flush(cx),Self::Native(v)=>std::pin::Pin::new(v).poll_flush(cx)}}
 fn poll_shutdown(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<std::io::Result<()>>{match self.get_mut(){Self::Rustls(v)=>std::pin::Pin::new(v).poll_shutdown(cx),Self::Native(v)=>std::pin::Pin::new(v).poll_shutdown(cx)}}
 fn is_write_vectored(&self)->bool{match self{Self::Rustls(v)=>tokio::io::AsyncWrite::is_write_vectored(v),Self::Native(v)=>tokio::io::AsyncWrite::is_write_vectored(v)}}
 fn poll_write_vectored(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>,bufs:&[std::io::IoSlice<'_>])->std::task::Poll<std::io::Result<usize>>{match self.get_mut(){Self::Rustls(v)=>tokio::io::AsyncWrite::poll_write_vectored(std::pin::Pin::new(v),cx,bufs),Self::Native(v)=>tokio::io::AsyncWrite::poll_write_vectored(std::pin::Pin::new(v),cx,bufs)}}
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
    connection: (NetAddress,NetAddress,&super::tls_events::HelloFields),
) -> Result<(
    Arc<ActiveServer>,
    usize,
    Arc<tls_policies::PreparedPolicy>,
    Option<AcquiredCertificate>,
)> {
    let (peer, local, event_fields) = connection;
    let mut retries = 0usize;
    let mut event_generation:Option<Arc<BusinessGeneration>>=None;
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
        let peer_to_match=peer.clone();let local_to_match=local.clone();
        let (policy_index, policy) = inner
            .resources
            .metadata
            .run(move || server_to_match.policy(&sni_to_match, peer_to_match, local_to_match))
            .await
            .map_err(|_| anyhow::anyhow!("TLS policy matching worker unavailable"))?
            .ok_or_else(|| anyhow::anyhow!("no TLS connection policy matched"))?;
        ensure!(
            !policy.definition.drop,
            "TLS connection policy dropped the connection"
        );
        if event_generation.as_ref().is_none_or(|g|!Arc::ptr_eq(g,&activity)) {
            super::tls_events::emit(server.events.as_ref(),event_fields,&inner.resources,
                (peer.clone(),local.clone(),super::tls_events::Transport::Tcp),&activity.admission_closed).await?;
            event_generation=Some(activity.clone());
            if !same_business_view(&inner.current.load_full(),&address,&server,&activity){continue 'view;}
        }
        let resolver = &policy.resolver;
        // Never rewrite the actual Hello or its automation permission
        // target to the name of a resident fallback certificate.
        let (cached, fallback) = if sni.is_empty() || sni.parse::<std::net::IpAddr>().is_ok() {
            (false, false)
        } else if policy.definition.certificate_selection.is_some() {
            let selected_policy = policy.clone();
            let name = sni.to_owned();
            let protocols = alpn.iter().map(|value| value.to_vec()).collect::<Vec<_>>();
            let schemes = schemes.to_vec();
            inner
                .resources
                .metadata
                .run(move || -> Result<(bool, bool)> {
                    let alpn = protocols.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    let resolver = &selected_policy.resolver;
                    match resolver.choose(
                        [Some(&name), None, None],
                        Some(&name),
                        &alpn,
                        &schemes,
                        None,
                    ) {
                        Choice::Selected(_, CertificateOrigin::Managed, false)
                        | Choice::Unusable {
                            managed: true,
                            global: false,
                        } => Ok((false, false)),
                        Choice::Selected(..) => Ok((true, false)),
                        Choice::Unusable { .. } => {
                            anyhow::bail!("explicit certificate selection is unusable")
                        }
                        Choice::Missing => {
                            let fallback = selected_policy.definition.fallback_sni.as_deref();
                            Ok((
                                false,
                                fallback.is_some_and(|fallback_name| {
                                    matches!(
                                        resolver.choose(
                                            [None, None, Some(fallback_name)],
                                            Some(&name),
                                            &alpn,
                                            &schemes,
                                            None
                                        ),
                                        Choice::Selected(..)
                                    )
                                }),
                            ))
                        }
                    }
                })
                .await
                .map_err(|_| anyhow::anyhow!("TLS certificate policy worker unavailable"))??
        } else {
            let manual = resolver
                .static_certificates
                .select_candidate_filtered(Some(sni), alpn, schemes, &resolver.allowed_static)
                .is_some();
            let fallback = policy
                .definition
                .fallback_sni
                .as_deref()
                .is_some_and(|name| {
                    matches!(
                        resolver.choose([None, None, Some(name)], Some(sni), alpn, schemes, None),
                        Choice::Selected(..)
                    )
                });
            (manual, fallback)
        };
        let typed = sni.is_empty() || sni.parse::<std::net::IpAddr>().is_ok();
        let local_ip = local_certificate_name(&local);
        let primary = if sni.is_empty() {
            local_ip.as_str()
        } else {
            sni
        };
        let primary_hit = typed && matches!(resolver.choose([Some(primary), None, None],
            (!sni.is_empty()).then_some(sni), alpn, schemes, None), Choice::Selected(..));
        let capture_target = |policy: &tls_policies::PreparedPolicy, primary: &str,
            offered: &str, protocols: &[Vec<u8>], schemes: &[SignatureScheme]| {
            let alpn = protocols.iter().map(Vec::as_slice).collect::<Vec<_>>();
            match policy.resolver.choose([Some(primary), None, None],
                (!offered.is_empty()).then_some(offered), &alpn, schemes, None) {
                Choice::Selected(certificate, CertificateOrigin::Managed, _) => {
                    let (receipt, slot) = policy.resolver.managed.scoped_instance(certificate.instance?)?;
                    Some(AcquiredCertificate { subject: primary.to_owned(), receipt, slot, external: None })
                }
                _ => None,
            }
        };
        let cached_target = if policy.definition.certificate_selection.is_some() {
            let selected_policy = policy.clone();
            let primary = primary.to_owned();
            let offered = sni.to_owned();
            let protocols = alpn.iter().map(|value| value.to_vec()).collect::<Vec<_>>();
            let schemes = schemes.to_vec();
            inner.resources.metadata.run(move ||
                capture_target(&selected_policy, &primary, &offered, &protocols, &schemes))
                .await.map_err(|_| anyhow::anyhow!("TLS certificate policy worker unavailable"))?
        } else {
            capture_target(&policy, primary, sni,
                &alpn.iter().map(|value| value.to_vec()).collect::<Vec<_>>(), schemes)
        };
        let mut acquired = None;
        if let Some(provider) = &resolver.provider
            && if typed {
                provider.should_probe_before_fallback(sni)
            } else {
                (cached_target.is_some() || !cached)
                    && (!fallback || provider.should_probe_before_fallback(sni))
            }
        {
            let cancel = CancellationToken::new();
            let _cancel_on_drop = cancel.clone().drop_guard();
            let effective = if typed {
                if primary_hit {
                    primary.to_owned()
                } else if sni.is_empty() {
                    policy
                        .definition
                        .default_sni
                        .clone()
                        .unwrap_or_else(|| local_ip.clone())
                } else {
                    sni.to_owned()
                }
            } else {
                sni.to_owned()
            };
            let force_lookup = if typed { !primary_hit }
                else { policy.definition.certificate_selection.is_some() && !cached && cached_target.is_none() };
            let acquiring = provider.ensure_request(CertificateRequest {
                origin: sni.to_owned(), subject: effective.clone(), force_lookup,
                hello: Some(CertificateHello { server_name: event_fields.server_name.clone(),
                    signatures: event_fields.signature_schemes.clone().unwrap_or_default(),
                    ciphers: event_fields.cipher_suites.clone(), local_ip: local.host_port_bytes().filter(|(host,_)|!host.is_empty()).map(|(host,_)|host.into_owned()) }),
                cached: cached_target,
                selection: Some(WarmSelection { filter: resolver.certificate_selection.clone(),
                    schemes: schemes.to_vec(), version: None }),
            }, cancel);
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
                        acquired = result?;
                        ensure!(acquired.as_ref().is_none_or(|certificate| certificate.subject == effective),
                            "acquired certificate subject changed");
                        break;
                    },
                }
            }
        }
        if same_business_view(&inner.current.load_full(), &address, &server, &activity) {
            return Ok((server, policy_index, policy, acquired));
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
    peer_local: (NetAddress, NetAddress),
) -> Result<AcceptedTls<super::ssl_capture::CaptureIo<http_redirect::ReplayIo<I>>>>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (peer, local) = peer_local;
    let mut start = tls_io_deadline(deadline, async move {
        let stream = super::ssl_capture::CaptureIo::new(tls_first_record::prepare(stream, reply_http).await?);
        Ok(
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                .await?,
        )
    })
    .await?;
    let hello = start.client_hello();
    let event_fields=super::tls_events::HelloFields::capture(&hello);
    let raw_sni = hello.offered_server_name().unwrap_or_default().to_owned();
    let sni = crate::tls_policy::normalized_offered_name(&raw_sni)?;
    let ip_sni = sni.parse::<std::net::IpAddr>().is_ok();
    let local_ip = local_certificate_name(&local);
    let offered_protocols = hello
        .alpn()
        .map(|a| a.map(<[u8]>::to_vec).collect::<Vec<_>>())
        .unwrap_or_default();
    let protocols = offered_protocols
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let schemes = hello.signature_schemes().to_vec();
    let offers_tls13=hello.offered_versions().is_some_and(|v|v.contains(&ProtocolVersion::TLSv1_3));
    let offered_ciphers=hello.cipher_suites().iter().copied().map(u16::from).collect::<Vec<_>>();
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
        let registration=inner.registry.tls_registration(&sni,&protocols);
        let mut event_app=registration.as_ref().and_then(|r|r.events.clone());
        let mut proof_native=None;
        let config = if let Some((business, _)) = inner.current.load_full().business(&address) {
            event_app=business.events.clone();
            let matching = business.clone();
            let proof_name = raw_sni.clone();
            let peer_to_match=peer.clone();let local_to_match=local.clone();
            let (_, policy) = inner
                .resources
                .metadata
                .run(move || matching.policy(&proof_name, peer_to_match, local_to_match))
                .await
                .map_err(|_| anyhow::anyhow!("TLS proof policy worker unavailable"))?
                .ok_or_else(|| anyhow::anyhow!("no TLS proof connection policy matched"))?;
            ensure!(
                !policy.definition.drop,
                "TLS connection policy dropped proof connection"
            );
            if policy.definition.protocol_min!=Some(crate::tls_policy::ProtocolVersion::Tls13) && policy.native_suites.is_some() && (!offers_tls13 || policy.definition.protocol_max==Some(crate::tls_policy::ProtocolVersion::Tls12)) {
                proof_native=Some((policy.native_suites.clone().expect("native suite policy"),policy.native_verifier.clone()));
            }
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
        proof_event(inner,registration.as_ref(),event_app.as_ref(),&event_fields,(peer.clone(),local.clone()),&inner.stopped).await?;
        let proof_owner=registration.as_ref().map(|r|(r.cancel.clone(),r.expires));
        if let Some((suites,verifier))=proof_native {
            let registration=registration.ok_or_else(||anyhow::anyhow!("native TLS proof unavailable"))?;
            let registry=inner.registry.clone();let name=sni.clone();let generation=registration.generation;
            let gate:Arc<dyn Fn()->bool+Send+Sync>=Arc::new(move||registry.tls_generation_current(&name,generation));
            let key=registration.certificate;let credential=registration.native_private_key;
            let auth=native_ssl_tls::ServerClientAuth::new(verifier);let scope=inner.resources.ssl_verify.clone();
            let io=start.io.replay();drop(start.accepted);
            let executor=inner.tls_executor.get().ok_or_else(||anyhow::anyhow!("TLS executor unavailable"))?;
            executor.execute_proof(proof_lifetime(async move {
                let stream=native_ssl_tls::ServerStream::prepare(io,scope,move ||super::tls_cbc::engine_with_key(key,config,super::tls_cbc::ordered(&suites,&offered_ciphers),auth,None,credential,gate,Arc::new(||false))).await?;
                drop(stream);Ok(())
            },proof_owner),inner.stopped.child_token(),deadline).await?;
            anyhow::bail!("TLS validation completed");
        }
        let mut config=(*config).clone();
        config.cert_resolver=Arc::new(PinnedProof{registry:inner.registry.clone(),sni:sni.clone(),registration});
        let config=Arc::new(config);
        let Some(executor) = inner.tls_executor.get() else {
            anyhow::bail!("TLS executor unavailable");
        };
        start.io.discard();
        executor
            .execute_proof(
                proof_lifetime(async move {
                    let stream = start.into_stream(config).await?;
                    drop(stream);
                    Ok(())
                },proof_owner),
                inner.stopped.child_token(),
                deadline,
            )
            .await?;
        anyhow::bail!("TLS validation completed");
    }
    connection_budget::classify(&admission, connection_budget::ConnectionClass::Business)?;
    let (server, policy_index, policy, acquired) = server_for_hello(
        inner, address, &sni, &raw_sni, &protocols, &schemes, (peer.clone(),local.clone(),&event_fields),
    )
    .await?;
    let resolver = &policy.resolver;
    // A primary typed IP SAN hit can serve without a permission round trip.
    // Go tries dynamic acquisition before serving any defaulted candidate.
    // Until typed no-SNI and IP admission are wired, fail closed on those
    // dynamic-policy misses; never reinterpret the candidate as a DNS request.
    let primary_certificate_only = acquired.is_none()
        && (sni.is_empty() || ip_sni)
        && resolver
            .provider
            .as_ref()
            .is_some_and(|provider| provider.should_probe_before_fallback(&sni));
    // Availability is not authorization; final protocol-bound selection still
    // runs in the real resolver callback before session lookup.
    ensure!(
        if let Some(acquired) = &acquired {
            acquired.select(&resolver.managed, &schemes, None).is_some()
        } else {
            policy.definition.certificate_selection.is_some()
                || matches!(resolver.choose(eligible_names(&policy.definition, &sni, &local_ip,
                    primary_certificate_only), (!sni.is_empty()).then_some(sni.as_str()),
                    &protocols, &schemes, None), Choice::Selected(..))
        },
        "{}",
        if primary_certificate_only {
            "typed no-SNI or IP certificate admission unavailable"
        } else {
            "TLS identity unavailable"
        }
    );
    let native_tls12=policy.definition.protocol_min!=Some(crate::tls_policy::ProtocolVersion::Tls13) && policy.native_suites.is_some()
        && (!offers_tls13 || policy.definition.protocol_max==Some(crate::tls_policy::ProtocolVersion::Tls12));
    if native_tls12 {
        let ids=policy.native_suites.clone().expect("native cipher policy");
        let worker_policy=policy.clone(); let worker_acquired=acquired.clone();let worker_sni=sni.clone();let worker_local=local_ip.clone();let worker_protocols=offered_protocols.clone();let worker_schemes=schemes.clone();let worker_ids=ids;
        let (selection,names)=inner.resources.metadata.run(move ||{
            let protocols=worker_protocols.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let schemes=super::tls_cbc::compatible_schemes(&worker_ids,&offered_ciphers,&worker_schemes);
            if schemes.is_empty(){return None}
            let (certificate,origin)=if let Some(acquired)=&worker_acquired{acquired.select(&worker_policy.resolver.managed,&schemes,Some(ProtocolVersion::TLSv1_2)).map(|c|(c,CertificateOrigin::Managed))}else{worker_policy.resolver.choose(eligible_names(&worker_policy.definition,&worker_sni,&worker_local,primary_certificate_only),(!worker_sni.is_empty()).then_some(worker_sni.as_str()),&protocols,&schemes,Some(ProtocolVersion::TLSv1_2)).selected()}?;
            let native=certificate.native.as_ref()?;
            if !native.admitted() || !certificate.signature_compatibility.allows(ProtocolVersion::TLSv1_2){return None}
            let not_after=native.not_after;let leaf=native.leaf.clone();let chain_hash=chain_hash(&certificate.key);
            let ordered=super::tls_cbc::ordered(&worker_ids,&offered_ciphers);
            Some((FixedSelection{version:ProtocolVersion::TLSv1_2,certificate,origin,chain_hash,not_after,leaf},ordered))
        }).await.map_err(|_|anyhow::anyhow!("native TLS certificate selection worker unavailable"))?.ok_or_else(||anyhow::anyhow!("native TLS identity unavailable"))?;
        let session_name:Arc<str>=if sni.is_empty(){if local.socket().is_some(){format!("no-sni:{local_ip}").into()}else{format!("no-sni:{}:{}",local.network(),local.raw_text().iter().map(|v|format!("{v:02x}")).collect::<String>()).into()}}else if ip_sni{format!("ip-sni:{sni}").into()}else{sni.as_str().into()};
        let native_config=Arc::new(super::tls_cbc::alpn_config(&policy.tls,&protocols));
        let identity=Arc::new(TlsIdentity{sni:sni.clone(),wire_sni:raw_sni.clone(),local_ip,primary_certificate_only,acquired,session_name,offered_alpn:offered_protocols,schemes,chain_hash:selection.chain_hash,not_after:selection.not_after,version:selection.version,leaf:selection.leaf.clone(),scope:Arc::downgrade(&policy.resolver),origin:selection.origin,policy_index,policy_identity:server.policy_identity,explicit_selector:policy.definition.certificate_selection.is_some(),instance:selection.certificate.instance});
        let state=Arc::new(connection_sessions::HandshakeState::new(identity.session_name.clone()));
        let _=state.selected_chain.set(identity.chain_hash);
        let mut ticket_auth:Option<Arc<ConnectionTickets>>=None;
        let mut hash=Sha256::new();hash.update(b"native-ssl12-session-context-v1");hash.update(policy.identity);hash.update(identity.session_name.as_bytes());hash.update(identity.chain_hash);
        let binding:[u8;32]=hash.finalize().into();
        let sessions=if policy.definition.client_auth.is_some(){None}else{match &server.tickets{
          crate::stek::TicketRuntime::RuntimeDefault=>{
            let cache=Arc::new(connection_sessions::PerConnectionSessions::new(policy.sessions.clone(),state.clone()));
            Some((super::tls_cbc::Sessions::Cache(native_ssl_tls::ServerSessions::new(cache)),binding))
          }
          #[cfg(feature="native-run")]
          crate::stek::TicketRuntime::Disabled=>None,
          #[cfg(feature="native-run")]
          crate::stek::TicketRuntime::Rotating{owner,realm,..}=>{
            let mut bound=Sha256::new();bound.update(b"caddy-connection-ticket-policy-v1");bound.update(realm);bound.update(policy.identity);
            let tickets=Arc::new(ConnectionTickets::new(owner.clone(),bound.finalize().into()));
            ensure!(tickets.select(&identity.session_name,ProtocolVersion::TLSv1_2,identity.chain_hash,identity.leaf.clone(),identity.not_after),"native TLS ticket selection unavailable");
            let bridge=native_ssl_tls::ServerTickets::new(tickets.clone());ticket_auth=Some(tickets);
            Some((super::tls_cbc::Sessions::Tickets(bridge),binding))
          }
        }};
        let session_evidence=sessions.as_ref().map(|(s,_)|s.clone());
        let auth=native_ssl_tls::ServerClientAuth::new(policy.native_verifier.clone());
        let engine_auth=auth.clone();let config=native_config;let certificate=selection.certificate;
        let final_credential=certificate.native.clone().ok_or_else(||anyhow::anyhow!("native TLS credential unavailable"))?;
        let local_key=certificate.key.clone();let capture_name=raw_sni.clone();
        let scope=inner.resources.ssl_verify.clone();
        let executor=inner.tls_executor.get().ok_or_else(||anyhow::anyhow!("TLS executor unavailable"))?;
        let io=start.io.replay();drop(start.accepted);
        let handshake=async move {
            let stream=native_ssl_tls::ServerStream::prepare(io,scope,move ||super::tls_cbc::engine(certificate,config,names,engine_auth,sessions)).await?;
            let (stream,snapshot)=stream.inspect(move |ssl|ConnectionSnapshot::capture_ssl(ssl,&capture_name,&local_key.cert,&auth,session_evidence.as_ref().and_then(|e|e.resumed_group()))).await?;
            let metadata=snapshot.metadata()?;
            if metadata.did_resume {ensure!(if let Some(tickets)=&ticket_auth{tickets.authenticated()}else{state.resumed().is_some()},"native TLS resumption identity unavailable");}
            ensure!(final_credential.admitted(),"native TLS selected certificate withdrawn");
            state.identity.set(identity.clone()).map_err(|_|anyhow::anyhow!("native TLS identity already finalized"))?;
            let snapshot=Arc::new(snapshot.accept());
            Ok(AcceptedTls{stream:TlsStream::Native(stream),identity,snapshot,server})
        };
        return executor.execute(handshake,inner.stopped.child_token(),deadline).await;
    }
    start.io.discard();
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
        if local.socket().is_some(){format!("no-sni:{local_ip}").into()}else{format!("no-sni:{}:{}",local.network(),local.raw_text().iter().map(|byte|format!("{byte:02x}")).collect::<String>()).into()}
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
        acquired: acquired.clone(),
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
        let snapshot = Arc::new(ConnectionSnapshot::capture_tcp(
            stream.get_ref().1, &raw_sni, &selection.certificate.key.cert,
            policy.definition.client_auth.as_ref(),
        ));
        let identity = Arc::new(TlsIdentity {
            sni,
            wire_sni: raw_sni,
            local_ip,
            primary_certificate_only,
            acquired,
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
            explicit_selector: policy.definition.certificate_selection.is_some(),
            instance: selection.certificate.instance,
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
            stream:TlsStream::Rustls(stream),
            identity,
            snapshot,
            server,
        })
    };
    executor
        .execute(handshake, inner.stopped.child_token(), deadline)
        .await
}
