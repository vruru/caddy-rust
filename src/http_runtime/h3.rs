//! Transactional QUIC listener and isolated HTTP/3 request streams.
use super::*;
use crate::{leaf_guard::LeafState, tls_resolver::CertificateSelection};
use http::{HeaderValue, Method};
use quinn::{
    Endpoint, ServerConfig as QuicConfig, TransportConfig, crypto::rustls::QuicServerConfig,
};
use std::{
    net::UdpSocket,
    sync::{OnceLock, Weak},
};
use tokio::{sync::Semaphore, task::JoinSet};

mod hello;
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
) -> Result<QuicConfig> {
    let mut config = QuicConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config
        .transport_config(transport.clone())
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
                Some(initial_config(crypto.clone(), &transport)?),
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

/// A handshake records exactly the selected leaf, never the best matching
/// candidate at a later instant. QUIC does not consult the TCP proof resolver.
struct SeenCert {
    resolver: Arc<CandidateResolver>,
    selected: OnceLock<CertificateSelection>,
    inspected_name: Option<String>,
}
impl fmt::Debug for SeenCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http3Certificate").finish_non_exhaustive()
    }
}
impl ResolvesServerCert for SeenCert {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = &self.inspected_name
            && !hello
                .server_name()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(name))
        {
            return None;
        }
        let protocols = hello.alpn()?.collect::<Vec<_>>();
        let version = hello.negotiated_version()?;
        if !protocols.contains(&b"h3".as_slice())
            || protocols.contains(&ACME_ALPN)
            || version != rustls::ProtocolVersion::TLSv1_3
        {
            return None;
        }
        if self.selected.get().is_none() {
            let key = self.resolver.select_for_version(
                hello.server_name(),
                &protocols,
                hello.signature_schemes(),
                version,
            )?;
            let _ = self.selected.set(key);
        }
        let key = &self.selected.get()?.key;
        key.key.choose_scheme(hello.signature_schemes())?;
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

enum Prepared {
    Retry,
    Inspected(String),
}

async fn prepare_certificate(
    incoming: &quinn::Incoming,
    resolver: &CandidateResolver,
    tls: &rustls::ServerConfig,
    provider: &dyn ScopedCertificateProvider,
    header_timeout: Duration,
    listener: &PreflightLanes,
    process: &PreflightLanes,
) -> Option<Prepared> {
    let validated = incoming.remote_address_validated();
    let hello = match inspect_client_hello(incoming, tls, None)? {
        FlightState::Ready(hello) => hello,
        FlightState::Unchanged => return None,
        // Don't keep an unverified source in the fragment-wait lane. Retry is
        // stateless; even many incomplete first packets cannot occupy it.
        FlightState::Incomplete(_) if !validated => return Some(Prepared::Retry),
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
    let name = hello.server_name?.to_ascii_lowercase();
    let protocols = hello
        .protocols
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    if !protocols.contains(&b"h3".as_slice()) || protocols.contains(&ACME_ALPN) {
        return None;
    }
    let selected = resolver.select_for_version_with_origin(
        Some(&name),
        &protocols,
        &hello.signatures,
        rustls::ProtocolVersion::TLSv1_3,
    );
    if selected
        .as_ref()
        .is_some_and(|(_, origin)| *origin == CertificateOrigin::Manual)
        || !provider.can_acquire_quic_name(&name)
    {
        return Some(Prepared::Inspected(name));
    }
    if !validated {
        return Some(if selected.is_none() {
            Prepared::Retry
        } else {
            Prepared::Inspected(name)
        });
    }
    // A hit can become unusable before ensure() so even a validated cache hit
    // requires a cold slot for the ensure call, never borrowing a warm slot.
    let _issuance = match (
        listener.issuance.try_acquire(),
        process.issuance.try_acquire(),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        _ if selected.is_some() => return Some(Prepared::Inspected(name)),
        _ => return None,
    };
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    provider.ensure(name.clone(), cancel).await.ok()?;
    Some(Prepared::Inspected(name))
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
        let Some(resolver) = server.resolver.clone() else {
            incoming.refuse();
            continue;
        };
        let peer = incoming.remote_address();
        let local = SocketAddr::new(
            incoming.local_ip().unwrap_or(binding.actual.ip()),
            binding.actual.port(),
        );
        let runtime = inner.clone();
        inner.tasks.spawn(async move {
            let _connection_slot=(connection_slot,process_connection);
            let deadline=server.plan.read_header_timeout.min(Duration::from_secs(15));
            let mut inspected_name = None;
            if let Some(provider) = resolver.provider.as_deref().filter(|provider| provider.needs_quic_preflight()) {
                let prepared = tokio::select! {
                    biased;
                    _=activity.superseded.cancelled()=>return,
                    _=activity.admission_closed.cancelled()=>return,
                    _=activity.hard_stop.cancelled()=>return,
                    value=tokio::time::timeout(deadline,prepare_certificate(&incoming,&resolver,&config.crypto,provider,deadline.min(Duration::from_secs(3)),&binding.preflight,&runtime.quic_limits.preflight))=>value.ok().flatten(),
                };
                match prepared {
                    Some(Prepared::Inspected(name)) => inspected_name = Some(name),
                    Some(Prepared::Retry) => {
                        let _ = incoming.retry();
                        return;
                    },
                    None => return,
                }
            }
            if activity.superseded.is_cancelled() || activity.admission_closed.is_cancelled() {
                return;
            }
            let seen = Arc::new(SeenCert {
                resolver,
                selected: OnceLock::new(),
                inspected_name,
            });
            let mut crypto = (*config.crypto).clone();
            crypto.cert_resolver = seen.clone();
            let Ok(crypto) = initial_config(crypto, &config.transport) else {
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
                value=tokio::time::timeout(deadline,connecting)=>match value {Ok(Ok(value))=>value,_=>return},
            };
            drop((handshake_slot,process_handshake));
            let leaf = seen.selected.get().and_then(|selected| selected.leaf_state.clone());
            let Some(leaf)=leaf else {return;};
            serve_connection(runtime,connection,Peer {key,peer,local},server,activity,leaf).await;
            drop(binding);
        });
    }
}

#[derive(Clone, Copy)]
struct Peer {
    key: SocketAddr,
    peer: SocketAddr,
    local: SocketAddr,
}
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

async fn serve_connection(
    inner: Arc<Inner>,
    quic: quinn::Connection,
    peer: Peer,
    server: Arc<ActiveServer>,
    activity: Arc<BusinessGeneration>,
    leaf: Arc<LeafState>,
) {
    let sni: Option<Arc<str>> = if server.plan.strict_sni_host {
        quic.handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.server_name.map(Arc::from))
    } else {
        None
    };
    let mut builder = ::h3::server::builder();
    builder.max_field_section_size(16 * 1024);
    let mut connection = tokio::select! {
        biased;
        _=activity.hard_stop.cancelled()=>return,
        _=activity.superseded.cancelled()=>return,
        _=activity.drain.cancelled()=>return,
        value=tokio::time::timeout(
            server.plan.read_header_timeout.min(Duration::from_secs(5)),
            builder.build(h3_quinn::Connection::new(quic.clone()))
        )=>match value {Ok(Ok(value))=>value,_=>return},
    };
    let mut streams = JoinSet::new();
    let mut draining = false;
    loop {
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
                streams.spawn(async move {
                    let _stream_slot=stream_slot;
                    let Ok(Ok((mut request,wire)))=tokio::time::timeout(server.plan.read_header_timeout,resolver.resolve_request()).await else{return;};
                    let Ok(business)=activity.begin() else {return;};
                    if !runtime.current.load().business(&peer.key)
                        .is_some_and(|(s,a)|Arc::ptr_eq(&s,&server)&&Arc::ptr_eq(&a,&activity))
                        || !leaf.admission().allow_certificate
                    {return;}
                    let head=request.method()==Method::HEAD;
                    let Ok(metadata)=trailer_policy::prepare_request(&mut request) else{return;};
                    request.extensions_mut().insert(metadata);
                    let Ok((request,wire))=stream::start(request,wire) else{return;};
                    let task=async move {
                        let (interim, receiver) = stream::interim_channel();
                        let response = request::handle_business(runtime,server,request,request::RequestOrigin { peer:canonical(peer.peer), local:canonical(peer.local), tls:true, sni:sni.as_deref() },business.clone(),Some(request::InformationalOutput::Quic(interim)));
                        let _=stream::drive(wire,receiver,response,head).await;
                        drop(business);
                    };
                    tokio::select! { biased;
                        _=activity.hard_stop.cancelled()=>{},
                        _=task=>{},
                    };
                });
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}
