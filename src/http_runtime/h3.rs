//! Transactional QUIC listener and isolated HTTP/3 request streams.
use super::*;
use crate::leaf_guard::LeafState;
use http::{HeaderValue, Method};
use quinn::{
    Endpoint, ServerConfig as QuicConfig, TransportConfig, crypto::rustls::QuicServerConfig,
};
use sha2::{Digest, Sha256};
use std::{net::UdpSocket, sync::Weak};
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};

mod hello;
mod write_control;
mod continue_flow;
mod sessions;
pub(super) mod stream;
pub(super) type Pool = HashMap<SocketAddr, Weak<Binding>>;
const STREAMS: usize = 64;
const MAX_CONNECTIONS: usize = 256;
struct PreflightLanes {
    fragments: Semaphore,
    issuance: Semaphore,
}
impl PreflightLanes {
    fn new(fragments: usize, issuance: usize) -> Self {
        Self {
            fragments: Semaphore::new(fragments),
            issuance: Semaphore::new(issuance),
        }
    }
}
pub(super) struct Limits {
    handshakes: Arc<Semaphore>,
    preflight: PreflightLanes,
    connections: Arc<Semaphore>,
    streams: Arc<Semaphore>,
}
impl Limits {
    pub(super) fn new() -> Self {
        Self {
            handshakes: Arc::new(Semaphore::new(32)),
            preflight: PreflightLanes::new(8, 16),
            connections: Arc::new(Semaphore::new(512)),
            streams: Arc::new(Semaphore::new(2048)),
        }
    }
}

#[derive(Clone)]
pub(super) struct AltSvc(pub(super) HeaderValue);

pub(super) struct Binding {
    pub(super) actual: SocketAddr,
    pub(super) advertisement: AltSvc,
    _endpoint: Endpoint,
    accept_stop: CancellationToken,
    handshakes: Arc<Semaphore>,
    preflight: PreflightLanes,
    connections: Arc<Semaphore>,
}
impl Drop for Binding {
    fn drop(&mut self) {
        self.accept_stop.cancel();
    }
}
#[derive(Clone)]
pub(super) struct Listener {
    pub(super) binding: Arc<Binding>,
    crypto: Arc<rustls::ServerConfig>,
    transport: Arc<TransportConfig>,
    sessions: Arc<sessions::Shared>,
    scope: IpScope,
}

pub(super) fn enabled(server: &ActiveServer) -> bool {
    server.plan.tls && server.plan.protocols.iter().any(|p| p == "h3")
}

pub(super) fn tcp_enabled(server: &ActiveServer) -> bool {
    server
        .plan
        .protocols
        .iter()
        .any(|p| matches!(p.as_str(), "h1" | "h2" | "h2c"))
}

fn initial_config(
    crypto: rustls::ServerConfig,
    transport: &Arc<TransportConfig>,
    scope: IpScope,
) -> Result<QuicConfig> {
    let mut config = QuicConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config
        .transport_config(transport.clone())
        .migration(!scope.remote && !scope.local)
        .max_incoming(128)
        .incoming_buffer_size(64 * 1024)
        .incoming_buffer_size_total(4 * 1024 * 1024);
    Ok(config)
}
pub(super) fn stage(
    inner: &Arc<Inner>,
    pool: &mut Pool,
    servers: &HashMap<SocketAddr, Arc<ActiveServer>>,
    tcp: &[StagedAddress],
) -> Result<HashMap<SocketAddr, Listener>> {
    pool.retain(|_, binding| binding.strong_count() != 0);
    let mut listeners = HashMap::new();
    for (&key, server) in servers.iter().filter(|(_, server)| enabled(server)) {
        let resolver = server
            .resolver
            .clone()
            .ok_or_else(|| anyhow::anyhow!("HTTP/3 TLS resolver missing"))?;
        let mut crypto = rustls::ServerConfig::builder_with_provider(crate::crypto::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        crypto.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        crypto.send_tls13_tickets = 0;
        crypto.max_early_data_size = 0;
        let mut transport = TransportConfig::default();
        transport
            .max_concurrent_bidi_streams((STREAMS as u32).into())
            .max_concurrent_uni_streams(8u8.into())
            .max_idle_timeout(Some(Duration::from_secs(30).try_into()?))
            .stream_receive_window((256u32 * 1024).into())
            .receive_window((2u32 * 1024 * 1024).into())
            .send_window(2u64 * 1024 * 1024);
        let transport = Arc::new(transport);
        let scope = IpScope::of(server);
        let tcp_actual = tcp
            .iter()
            .find(|address| address.declared == key)
            .map(|a| a.actual);
        let wanted = tcp_actual.unwrap_or(key);
        let binding = if let Some(binding) = pool.get(&key).and_then(Weak::upgrade) {
            ensure!(
                wanted.port() == 0 || wanted == binding.actual,
                "HTTP/3 listener address changed across reload"
            );
            binding
        } else {
            let socket = udp_socket(wanted)?;
            let endpoint = Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(initial_config(crypto.clone(), &transport, scope)?),
                socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            let actual = endpoint.local_addr()?;
            let binding = Arc::new(Binding {
                actual,
                advertisement: AltSvc(HeaderValue::from_str(&format!(
                    "h3=\":{}\"; ma=2592000",
                    actual.port()
                ))?),
                _endpoint: endpoint.clone(),
                accept_stop: CancellationToken::new(),
                handshakes: Arc::new(Semaphore::new(16)),
                preflight: PreflightLanes::new(4, 8),
                connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            });
            pool.insert(key, Arc::downgrade(&binding));
            inner.tasks.spawn(accept_loop(
                Arc::downgrade(inner),
                Arc::downgrade(&binding),
                endpoint,
                key,
                binding.accept_stop.clone(),
            ));
            binding
        };
        listeners.insert(
            key,
            Listener {
                binding,
                crypto: Arc::new(crypto),
                transport,
                sessions: Arc::new(sessions::Shared::new()),
                scope,
            },
        );
    }
    Ok(listeners)
}

fn udp_socket(address: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if let SocketAddr::V6(address) = address {
        socket.set_only_v6(!address.ip().is_unspecified())?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}
struct Preselected {
    certificate: crate::tls_resolver::CertificateSelection,
    chain: [u8; 32],
    protocols: Vec<Vec<u8>>,
    schemes: Vec<rustls::SignatureScheme>,
}

struct SeenCert {
    selected_policy: Arc<tls_policies::PreparedPolicy>,
    local_ip: String,
    selection: Arc<sessions::SelectionSlot>,
    inspected_name: Option<String>,
    policy: PolicyScope,
    preselected: Option<Preselected>,
    acquired: Option<AcquiredCertificate>,
}

impl fmt::Debug for SeenCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http3Certificate").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for SeenCert {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wire_name = hello.offered_server_name().unwrap_or_default();
        let name = crate::tls_policy::normalized_offered_name(wire_name).ok()?;
        let is_ip = name.parse::<std::net::IpAddr>().is_ok();
        let dns_sni = hello.server_name();
        if (name.is_empty() || is_ip) != dns_sni.is_none()
            || dns_sni.is_some_and(|value| !value.eq_ignore_ascii_case(&name))
        {
            self.selection.poison();
            return None;
        }
        let protocols = hello.alpn()?.collect::<Vec<_>>();
        let version = hello.negotiated_version()?;
        if self
            .inspected_name
            .as_ref()
            .is_some_and(|expected| expected != wire_name)
            || !protocols.contains(&b"h3".as_slice())
            || protocols.contains(&ACME_ALPN)
            || version != rustls::ProtocolVersion::TLSv1_3
        {
            self.selection.poison();
            return None;
        }
        let session_name = if name.is_empty() {
            format!("no-sni:{}", self.local_ip)
        } else if is_ip {
            format!("ip-sni:{name}")
        } else {
            name.clone()
        };
        let resolver = &self.selected_policy.resolver;
        let primary_only = (name.is_empty() || is_ip)
            && resolver
                .provider
                .as_ref()
                .is_some_and(|provider| provider.should_probe_before_fallback(&name));
        if let Some(p) = &self.preselected {
            if !p
                .protocols
                .iter()
                .map(Vec::as_slice)
                .eq(protocols.iter().copied())
                || p.schemes.as_slice() != hello.signature_schemes()
                || !p.certificate.signature_compatibility.allows(version)
                || !p
                    .certificate
                    .leaf_state
                    .as_ref()
                    .is_some_and(|leaf| leaf.admission().allow_certificate)
            {
                self.selection.poison();
                return None;
            }
        }
        // A repeated real hello may reuse the pinned signer, but never a
        // retired acquisition receipt. This check also runs after HRR.
        if let Some(acquired) = &self.acquired
            && acquired.select(&resolver.managed, hello.signature_schemes(), Some(version)).is_none()
        {
            self.selection.poison();
            return None;
        }
        let selected =
            self.selection
                .select(&session_name, wire_name, self.policy.digest, || {
                    if let Some(acquired) = &self.acquired {
                        acquired.select(&resolver.managed, hello.signature_schemes(), Some(version))
                    } else if let Some(p) = &self.preselected {
                        Some(p.certificate.clone())
                    } else {
                        if resolver.certificate_selection.is_some() {
                            return None;
                        }
                        resolver
                            .choose(
                                super::certificate_choice::eligible_names(
                                    &self.selected_policy.definition,
                                    &name,
                                    &self.local_ip,
                                    primary_only,
                                ),
                                (!name.is_empty()).then_some(name.as_str()),
                                &protocols,
                                hello.signature_schemes(),
                                Some(version),
                            )
                            .selected()
                            .map(|(cert, _)| cert)
                    }
                })?;
        if let Some(p) = &self.preselected {
            if super::connection_identity::chain_hash(&selected.certificate.key) != p.chain {
                self.selection.poison();
                return None;
            }
        }
        let key = &selected.certificate.key;
        if key.key.choose_scheme(hello.signature_schemes()).is_none() {
            self.selection.poison();
            return None;
        }
        Some(key.clone())
    }
}
enum FlightState {
    Unchanged,
    Incomplete(usize),
    Ready(hello::Hello),
}

fn inspect_client_hello(
    incoming: &quinn::Incoming,
    tls: &rustls::ServerConfig,
    previous: Option<usize>,
) -> Option<FlightState> {
    let Some((revision, flight)) = incoming.initial_flight(previous).ok()? else {
        return Some(FlightState::Unchanged);
    };
    let version = flight.version();
    let mut crypto = hello::Crypto::new();
    for (offset, bytes) in flight.crypto_fragments().ok()? {
        crypto.add(offset, &bytes).ok()?;
    }
    Some(match crypto.parse(tls, version).ok()? {
        Some(hello) => FlightState::Ready(hello),
        None => FlightState::Incomplete(revision),
    })
}

enum Preflight {
    Ready(hello::Hello),
    Retry,
}

struct PolicyScope {
    digest: [u8; 32],
    client_auth: bool,
}

impl PolicyScope {
    fn new(server: &ActiveServer, index: usize, policy: &tls_policies::PreparedPolicy) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"caddy-rust/h3/policy-scope/v1");
        hash.update(server.policy_identity);
        hash.update((index as u64).to_be_bytes());
        hash.update(policy.identity);
        Self {
            digest: hash.finalize().into(),
            client_auth: policy.definition.client_auth.is_some(),
        }
    }
}

async fn inspect_hello(
    incoming: &quinn::Incoming,
    tls: &rustls::ServerConfig,
    header_timeout: Duration,
    listener: &PreflightLanes,
    process: &PreflightLanes,
) -> Option<Preflight> {
    let validated = incoming.remote_address_validated();
    let hello = match inspect_client_hello(incoming, tls, None)? {
        FlightState::Ready(hello) => hello,
        FlightState::Unchanged => return None,
        // Don't keep an unverified source in the fragment-wait lane. Retry is
        // stateless; even many incomplete first packets cannot occupy it.
        FlightState::Incomplete(_) if !validated => return Some(Preflight::Retry),
        FlightState::Incomplete(revision) => {
            let _fragments = (
                listener.fragments.try_acquire().ok()?,
                process.fragments.try_acquire().ok()?,
            );
            tokio::time::timeout(header_timeout, async {
                let mut previous = Some(revision);
                loop {
                    tokio::time::sleep(Duration::from_millis(8)).await;
                    match inspect_client_hello(incoming, tls, previous)? {
                        FlightState::Ready(hello) => return Some(hello),
                        FlightState::Incomplete(revision) => previous = Some(revision),
                        FlightState::Unchanged => {}
                    }
                }
            })
            .await
            .ok()??
        }
    };
    Some(Preflight::Ready(hello))
}

enum Prepared {
    Ready(Option<AcquiredCertificate>),
    Retry,
}

fn probe_cached_certificate(
    policy: &tls_policies::PreparedPolicy,
    name: &str,
    offered: &str,
    protocols: &[Vec<u8>],
    schemes: &[rustls::SignatureScheme],
) -> (certificate_choice::Choice, bool) {
    let protocols = protocols.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let resolver = &policy.resolver;
    let primary = resolver.choose(
        [Some(name), None, None],
        (!offered.is_empty()).then_some(offered),
        &protocols,
        schemes,
        Some(rustls::ProtocolVersion::TLSv1_3),
    );
    let fallback = policy
        .definition
        .fallback_sni
        .as_deref()
        .is_some_and(|fallback| {
            matches!(
                resolver.choose(
                    [None, None, Some(fallback)],
                    (!offered.is_empty()).then_some(offered),
                    &protocols,
                    schemes,
                    Some(rustls::ProtocolVersion::TLSv1_3)
                ),
                certificate_choice::Choice::Selected(..)
            )
        });
    (primary, fallback)
}

async fn prepare_certificate(
    incoming: &quinn::Incoming,
    current: Option<CertificateOrigin>,
    has_fallback: bool,
    provider: &dyn ScopedCertificateProvider,
    request: CertificateRequest,
    lanes: (&PreflightLanes, &PreflightLanes),
    event:&mut super::tls_events::Admission<'_>,
) -> Option<Prepared> {
    let validated = incoming.remote_address_validated();
    let probe_fallback = has_fallback && provider.should_probe_before_fallback(&request.origin);
    if current == Some(CertificateOrigin::Manual)
        || (has_fallback && !probe_fallback)
        || (!probe_fallback && !provider.can_acquire_quic_name(&request.origin))
    {
        return Some(Prepared::Ready(None));
    }
    if !validated {
        return Some(if current.is_none()
            || (current == Some(CertificateOrigin::Managed) && provider.maintenance_due_for(&request))
        {
            Prepared::Retry
        } else {
            Prepared::Ready(None)
        });
    }
    // A hit can become unusable before ensure() so even a validated cache hit
    // requires a cold slot for the ensure call, never borrowing a warm slot.
    let _issuance = match (
        lanes.0.issuance.try_acquire(),
        lanes.1.issuance.try_acquire(),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        _ if current.is_some() => return Some(Prepared::Ready(None)),
        _ => return None,
    };
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    event.run().await.ok()?;
    let acquired = provider.ensure_request(request, cancel).await.ok()?;
    Some(Prepared::Ready(acquired))
}

async fn accept_loop(
    inner: Weak<Inner>,
    listener: Weak<Binding>,
    endpoint: Endpoint,
    key: SocketAddr,
    stop: CancellationToken,
) {
    let Some(runtime) = inner.upgrade() else {
        return;
    };
    let stopped = runtime.stopped.clone();
    drop(runtime);
    loop {
        let incoming = tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            _=stopped.cancelled()=>break,
            value=endpoint.accept()=>match value {Some(value)=>value,None=>break},
        };
        let (Some(inner), Some(binding)) = (inner.upgrade(), listener.upgrade()) else {
            incoming.refuse();
            break;
        };
        let generation = inner.current.load_full();
        let Some((server, activity)) = generation.business(&key) else {
            incoming.refuse();
            continue;
        };
        let Some(config) = generation
            .quic
            .get(&key)
            .filter(|entry| Arc::ptr_eq(&entry.binding, &binding))
            .cloned()
        else {
            incoming.refuse();
            continue;
        };
        let Ok(handshake_slot) = binding.handshakes.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let Ok(connection_slot) = binding.connections.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let Ok(process_handshake) = inner.quic_limits.handshakes.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let Ok(process_connection) = inner.quic_limits.connections.clone().try_acquire_owned()
        else {
            incoming.refuse();
            continue;
        };
        let peer = incoming.remote_address();
        let local_ip = incoming.local_ip();
        let local = SocketAddr::new(
            local_ip.unwrap_or(binding.actual.ip()),
            binding.actual.port(),
        );
        let runtime = inner.clone();
        inner.tasks.spawn(async move {
            let _connection_slot=(connection_slot,process_connection);
            let budget = server.plan.read_header_timeout.unwrap_or(Duration::from_secs(15)).min(Duration::from_secs(15));
            let deadline = Instant::now() + budget;
            let Some(first) = server.tls_policies.first() else { return; };
            let certificate_ip = if local.ip().is_unspecified() { String::new() }
                else { crate::tls_resolver::canonical_certificate_ip(local.ip()) };
            let preflight = server.tls_policies.len() != 1
                || server.events.as_ref().is_some_and(|events|events.should_emit("tls_get_certificate"))
                || first.definition.has_custom_settings()
                || first.resolver.certificate_selection.is_some()
                || first.resolver.provider.as_ref().is_some_and(|p| p.needs_quic_preflight());
            let (index, policy, inspected_name, preselected, acquired) = if preflight {
                let prepared = tokio::select! {
                    biased;
                    _=activity.superseded.cancelled()=>return,
                    _=activity.admission_closed.cancelled()=>return,
                    _=activity.hard_stop.cancelled()=>return,
                    value=tokio::time::timeout_at(deadline, inspect_hello(&incoming, &config.crypto, budget.min(Duration::from_secs(3)), &binding.preflight, &runtime.quic_limits.preflight))=>value.ok().flatten(),
                };
                let hello = match prepared {
                    Some(Preflight::Ready(hello)) => hello,
                    Some(Preflight::Retry) => { let _ = incoming.retry(); return; }
                    None => return,
                };
                let wire_name = hello.server_name.as_deref().unwrap_or_default();
                let Ok(name) = crate::tls_policy::normalized_offered_name(wire_name) else { return; };
                if !hello.protocols.iter().any(|p| p == b"h3") || hello.protocols.iter().any(|p| p == ACME_ALPN) {
                    return;
                }
                if local_ip.is_none() && local.ip().is_unspecified() && config.scope.local {
                    return;
                }
                let policy_server = server.clone();
                let inspected_name = wire_name.to_owned();
                let match_name = inspected_name.clone();
                let selected = tokio::select! {
                    biased;
                    _=activity.superseded.cancelled()=>return,
                    _=activity.admission_closed.cancelled()=>return,
                    _=activity.hard_stop.cancelled()=>return,
                    value=tokio::time::timeout_at(deadline, runtime.resources.metadata.run(move || {
                        policy_server.policy(&match_name, canonical(peer), canonical(local))
                    }))=>value,
                };
                let Ok(Ok(Some((index, policy)))) = selected else { return; };
                if policy.definition.drop || policy.definition.protocol_max == Some(crate::tls_policy::ProtocolVersion::Tls12) {
                    return;
                }
                let mut event=super::tls_events::Admission::new(server.events.as_ref(),&hello.event,&runtime.resources,
                    (peer,local,super::tls_events::Transport::Quic),&activity.admission_closed);
                let typed = name.is_empty() || name.parse::<std::net::IpAddr>().is_ok();
                let primary_name = if name.is_empty() { certificate_ip.as_str() } else { name.as_str() };
                let mut acquired = None;
                if let Some(provider) = policy.resolver.provider.as_deref().filter(|p| {
                        p.needs_quic_preflight() || policy.definition.fallback_sni.is_some()
                    })
                {
                    // The permission/storage decision sees primary availability
                    // separately from the exact fallback, matching TCP. A
                    // manual fallback must not suppress a required probe.
                    let availability = if policy.definition.certificate_selection.is_some() {
                        let choice_policy = policy.clone();
                        let choice_name = primary_name.to_owned();
                        let choice_offered = name.clone();
                        let choice_protocols = hello.protocols.clone();
                        let choice_schemes = hello.signatures.clone();
                        tokio::select! {
                            biased;
                            _=activity.superseded.cancelled()=>return,
                            _=activity.admission_closed.cancelled()=>return,
                            _=activity.hard_stop.cancelled()=>return,
                            value=tokio::time::timeout_at(deadline, runtime.resources.metadata.run(move || {
                                probe_cached_certificate(&choice_policy, &choice_name, &choice_offered, &choice_protocols, &choice_schemes)
                            }))=>value.ok().and_then(|result| result.ok()),
                        }
                    } else {
                        // No explicit selector: the two bounded alias lookups
                        // retain the existing direct preflight path.
                        Some(probe_cached_certificate(&policy, primary_name, &name, &hello.protocols, &hello.signatures))
                    };
                    let Some((primary, fallback)) = availability else { return; };
                    let primary_hit = matches!(primary, certificate_choice::Choice::Selected(..));
                    let (current, skip_probe, cached_target) = match primary {
                        certificate_choice::Choice::Selected(certificate, origin, _) => {
                            let target = if origin == CertificateOrigin::Managed {
                                certificate.instance.and_then(|instance| policy.resolver.managed.scoped_instance(instance))
                                    .map(|(receipt, slot)| AcquiredCertificate {
                                        subject: primary_name.to_owned(), receipt, slot, external: None,
                                    })
                            } else { None };
                            (Some(origin), origin == CertificateOrigin::Manual, target)
                        }
                        certificate_choice::Choice::Missing
                        | certificate_choice::Choice::Unusable { managed: true, global: false } => (None, false, None),
                        certificate_choice::Choice::Unusable { .. } => return,
                    };
                    let skip_probe = if typed { !provider.should_probe_before_fallback(&name) } else { skip_probe };
                    if !skip_probe {
                        let subject = if typed && !primary_hit && name.is_empty() {
                            policy.definition.default_sni.clone().unwrap_or_else(|| certificate_ip.clone())
                        } else { primary_name.to_owned() };
                        let force_lookup = if typed { !primary_hit }
                            else { policy.definition.certificate_selection.is_some() && !primary_hit };
                        let request = CertificateRequest { origin: name.clone(), subject: subject.clone(), force_lookup, cached: cached_target,
                            hello: Some(CertificateHello { server_name: hello.event.server_name.clone(),
                                signatures: hello.event.signature_schemes.clone().unwrap_or_default(),
                                ciphers: hello.event.cipher_suites.clone(), local_ip: Some(local.ip().to_canonical().to_string().into_bytes()) }),
                            selection: Some(WarmSelection { filter: policy.resolver.certificate_selection.clone(),
                                schemes: hello.signatures.clone(), version: Some(rustls::ProtocolVersion::TLSv1_3) }),
                        };
                        let prepared = tokio::select! {
                            biased;
                            _=activity.superseded.cancelled()=>return,
                            _=activity.admission_closed.cancelled()=>return,
                            _=activity.hard_stop.cancelled()=>return,
                            value=tokio::time::timeout_at(deadline, prepare_certificate(&incoming, current, !typed && fallback, provider, request, (&binding.preflight, &runtime.quic_limits.preflight),&mut event))=>value.ok().flatten(),
                        };
                        match prepared {
                            Some(Prepared::Ready(value)) => {
                                if value.as_ref().is_some_and(|certificate| certificate.subject != subject) { return; }
                                acquired = value;
                            }
                            Some(Prepared::Retry) => { let _ = incoming.retry(); return; }
                            None => return,
                        }
                    }
                }
                if event.run().await.is_err(){return;}
                // Global explicit selection runs on the bounded metadata
                // worker before accept_with can acquire the endpoint lock.
                let preselected = if acquired.is_some() || policy.definition.certificate_selection.is_some() {
                let choice_acquired = acquired.clone();
                let choice_policy = policy.clone();
                let choice_name = name.clone();
                let choice_ip = certificate_ip.clone();
                let choice_protocols = hello.protocols.clone();
                let choice_schemes = hello.signatures.clone();
                let choice = tokio::select! {
                    biased;
                    _=activity.superseded.cancelled()=>return,
                    _=activity.admission_closed.cancelled()=>return,
                    _=activity.hard_stop.cancelled()=>return,
                    value=tokio::time::timeout_at(deadline, runtime.resources.metadata.run(move || {
                        let protocols = choice_protocols.iter().map(Vec::as_slice).collect::<Vec<_>>();
                        let resolver = &choice_policy.resolver;
                        if let Some(acquired) = choice_acquired {
                            return acquired.select(&resolver.managed, &choice_schemes, Some(rustls::ProtocolVersion::TLSv1_3))
                                .map_or(certificate_choice::Choice::Missing, |certificate|
                                    certificate_choice::Choice::Selected(certificate, CertificateOrigin::Managed, false));
                        }
                        let primary_only = (choice_name.is_empty() || choice_name.parse::<std::net::IpAddr>().is_ok())
                            && resolver.provider.as_ref().is_some_and(|provider| provider.should_probe_before_fallback(&choice_name));
                        resolver.choose(certificate_choice::eligible_names(&choice_policy.definition,
                            &choice_name, &choice_ip, primary_only),
                            (!choice_name.is_empty()).then_some(choice_name.as_str()),
                            &protocols, &choice_schemes, Some(rustls::ProtocolVersion::TLSv1_3))
                    }))=>value,
                };
                let Ok(Ok(certificate_choice::Choice::Selected(certificate, _, _))) = choice else { return; };
                if !certificate.signature_compatibility.allows(rustls::ProtocolVersion::TLSv1_3)
                    || !certificate.leaf_state.as_ref().is_some_and(|leaf| leaf.admission().allow_certificate) {
                    return;
                }
                Some(Preselected {
                    chain: connection_identity::chain_hash(&certificate.key),
                    certificate, protocols: hello.protocols, schemes: hello.signatures,
                })
                } else { None };
                (index, policy, Some(inspected_name), preselected, acquired)
            } else {
                (0, first.clone(), None, None, None)
            };
            if activity.superseded.is_cancelled() || activity.admission_closed.is_cancelled() {
                return;
            }
            let seen = Arc::new(SeenCert {
                selected_policy: policy.clone(),
                local_ip: certificate_ip,
                selection: Arc::new(sessions::SelectionSlot::default()),
                inspected_name,
                preselected,
                acquired,
                policy: PolicyScope::new(&server, index, &policy),
            });
            let mut crypto = (*policy.tls).clone();
            crypto.alpn_protocols = vec![b"h3".to_vec()];
            crypto.cert_resolver = seen.clone();
            sessions::configure(&mut crypto, &server.tickets, &config.sessions, seen.selection.clone(), &seen.policy);
            let Ok(crypto) = initial_config(crypto, &config.transport, config.scope) else {
                return;
            };
            let Ok(connecting) = incoming.accept_with(Arc::new(crypto)) else {
                return;
            };
            let connection=tokio::select! {
                biased;
                _=activity.superseded.cancelled()=>return,
                _=activity.drain.cancelled()=>return,
                _=activity.hard_stop.cancelled()=>return,
                value=tokio::time::timeout_at(deadline,connecting)=>match value {Ok(Ok(value))=>value,_=>return},
            };
            drop((handshake_slot,process_handshake));
            let Some(selected) = seen.selection.current() else { return; };
            let snapshot = Arc::new(ConnectionSnapshot::capture_quic(
                &connection, &selected.raw_sni, &selected.certificate.key.cert,
                policy.definition.client_auth.as_ref(),
            ));
            let identity = QuicIdentity { leaf: selected.leaf().clone(), sni: selected.raw_sni.clone(), snapshot };
            let peer = Peer {key,peer,local,scope:config.scope};
            if !peer.permits(&connection) { return; }
            serve_connection(runtime,connection,peer,server,activity,identity).await;
            drop(binding);
        });
    }
}

#[derive(Clone, Copy, Default)]
struct IpScope {
    remote: bool,
    local: bool,
}
impl IpScope {
    fn of(server: &ActiveServer) -> Self {
        let mut scope = Self::default();
        for policy in &server.tls_policies {
            for matcher in &policy.definition.matcher {
                use crate::tls_policy::Matcher;
                match matcher {
                    Matcher::RemoteIp { .. } => scope.remote = true,
                    Matcher::LocalIp { .. } => scope.local = true,
                    _ => {}
                }
            }
        }
        scope
    }
}

#[derive(Clone, Copy)]
struct Peer {
    key: SocketAddr,
    peer: SocketAddr,
    local: SocketAddr,
    scope: IpScope,
}
impl Peer {
    fn permits(&self, connection: &quinn::Connection) -> bool {
        (!self.scope.remote
            || canonical(connection.remote_address()).ip() == canonical(self.peer).ip())
            && (!self.scope.local
                || connection
                    .local_ip()
                    .is_none_or(|ip| ip.to_canonical() == self.local.ip().to_canonical()))
    }
}
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

struct QuicIdentity {
    snapshot: Arc<ConnectionSnapshot>,
    leaf: Arc<LeafState>,
    sni: Arc<str>,
}

async fn serve_connection(
    inner: Arc<Inner>,
    quic: quinn::Connection,
    peer: Peer,
    server: Arc<ActiveServer>,
    activity: Arc<BusinessGeneration>,
    identity: QuicIdentity,
) {
    let QuicIdentity { leaf, sni, snapshot } = identity;
    let client_cert_cache = super::client_cert_facts::Cache::new(snapshot.clone());
    let sni = server.plan.strict_sni_host.then_some(sni);
    let mut builder = ::h3::server::builder();
    builder.max_field_section_size(16 * 1024).enable_extended_connect(true);
    let mut connection = tokio::select! {
        biased;
        _=activity.hard_stop.cancelled()=>return,
        _=activity.superseded.cancelled()=>return,
        _=activity.drain.cancelled()=>return,
        value=tokio::time::timeout(
            server.plan.read_header_timeout.unwrap_or(Duration::from_secs(5)).min(Duration::from_secs(5)),
            builder.build(h3_quinn::Connection::new(quic.clone()))
        )=>match value {Ok(Ok(value))=>value,_=>return},
    };
    let mut streams = JoinSet::new();
    let mut draining = false;
    let mut idle_deadline = None;
    loop {
        if !streams.is_empty() { idle_deadline = None; }
        else if idle_deadline.is_none() {
            idle_deadline = server.plan.idle_timeout.map(|duration| Instant::now() + duration);
        }
        if draining && streams.is_empty() {
            // FIN and GOAWAY remain available for retransmission while the
            // client drains. A retirement never extends the business guard.
            let _ = tokio::time::timeout(Duration::from_secs(2), quic.closed()).await;
            quic.close(
                ::h3::error::Code::H3_NO_ERROR
                    .value()
                    .try_into()
                    .expect("valid H3 code"),
                b"",
            );
            return;
        }
        tokio::select! {
            biased;
            _=activity.hard_stop.cancelled()=>break,
            _=activity.superseded.cancelled(),if !draining=>{
                draining=true;
                let _=tokio::time::timeout(Duration::from_millis(250),connection.shutdown(0)).await;
            },
            _=activity.drain.cancelled(),if !draining=>{
                draining=true;
                let _=tokio::time::timeout(Duration::from_millis(250),connection.shutdown(0)).await;
            },
            _=streams.join_next(),if !streams.is_empty()=>{},
            _=async {
                match idle_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            },if !draining && streams.is_empty()=>{
                quic.close(::h3::error::Code::H3_NO_ERROR.value().try_into().expect("valid H3 code"), b"idle timeout");
                break;
            },
            next=connection.accept()=>{
                let Ok(Some(resolver))=next else {break;};
                if draining || streams.len()>=STREAMS || !leaf.admission().allow_certificate {
                    drop(resolver);
                    continue;
                }
                let Ok(stream_slot)=inner.quic_limits.streams.clone().try_acquire_owned() else {
                    drop(resolver);
                    continue;
                };
                let runtime=inner.clone();
                let server=server.clone();
                let activity=activity.clone();
                let leaf=leaf.clone();
                let sni = sni.clone();
                let snapshot = snapshot.clone();
                let client_cert_cache = client_cert_cache.clone();
                let quic_for_stream=quic.clone();
                streams.spawn(async move {
                    let _stream_slot=stream_slot;
                    let head = async {
                        match server.plan.read_header_timeout {
                            Some(timeout) => tokio::time::timeout(timeout, resolver.resolve_request()).await.ok()?.ok(),
                            None => resolver.resolve_request().await.ok(),
                        }
                    };
                    let Some((mut request,wire)) = (tokio::select! { biased;
                        _=activity.hard_stop.cancelled()=>None,
                        _=activity.superseded.cancelled()=>None,
                        _=activity.drain.cancelled()=>None,
                        value=head=>value,
                    }) else { return; };
                    let Ok(business)=activity.begin() else {return;};
                    if !runtime.current.load().business(&peer.key)
                        .is_some_and(|(s,a)|Arc::ptr_eq(&s,&server)&&Arc::ptr_eq(&a,&activity))
                        || !leaf.admission().allow_certificate || !peer.permits(&quic_for_stream)
                    {return;}
                    let Ok(id)=quinn::VarInt::from_u64(wire.send_id().into_inner()) else{return;};
                    let Ok(stopped)=quic_for_stream.observe_send_stopped(quinn::StreamId::from(id)) else{return;};
                    let stopped=async move {
                        if let Ok(None)=stopped.await {
                            std::future::pending::<()>().await;
                        }
                    };
                    let head=request.method()==Method::HEAD;
                    let Ok(metadata)=trailer_policy::prepare_request(&mut request) else{return;};
                    request.extensions_mut().insert(metadata);
                    request.extensions_mut().insert(snapshot);
                    request.extensions_mut().insert(client_cert_cache);
                    let Some((interim, receiver)) = stream::interim_channel() else {
                        let mut rejected = wire;
                        rejected.stop_stream(::h3::error::Code::H3_REQUEST_REJECTED);
                        rejected.stop_sending(::h3::error::Code::H3_REQUEST_REJECTED);
                        return;
                    };
                    let Ok((mut request,wire))=stream::start(request,wire) else{return;};
                    request.body_mut().attach_interim(&interim);
                    let task=async move {
                        let response = request::handle_business(runtime,server,request,request::RequestOrigin { peer:crate::net_address::NetAddress::udp(canonical(peer.peer)), local:crate::net_address::NetAddress::udp(canonical(peer.local)), tls:true, sni:sni.as_deref() },business.clone(),Some(request::InformationalOutput::Quic(interim)));
                        let _=stream::drive(wire,receiver,response,head,quic_for_stream).await;
                        drop(business);
                    };
                    tokio::select! { biased;
                        _=activity.hard_stop.cancelled()=>{},
                        _=stopped=>{},
                        _=task=>{},
                    };
                });
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}
