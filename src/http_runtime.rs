//! Native HTTP listeners with request-scoped configuration snapshots. Preparation is
//! isolated from publication; failed binds and certificate loads preserve the
//! active generation. This module never starts a Go process.
#[path = "http_runtime/auth_cache.rs"]
pub(crate) mod auth_cache;
#[path = "http_runtime/connection_identity.rs"]
mod connection_identity;
#[path = "http_runtime/connection_sessions.rs"]
mod connection_sessions;
#[path = "http_runtime/files.rs"]
mod files;
use connection_identity::{TlsIdentity, TlsVerdict};
#[path = "http_runtime/lifecycle.rs"]
mod lifecycle;
pub use lifecycle::{CommitOutcome, HttpStage, StagedAddress};
#[path = "http_runtime/mime.rs"]
mod mime;
#[path = "http_runtime/path_glob.rs"]
mod path_glob;
pub(crate) use path_glob::go_path_glob;
#[path = "http_runtime/proxy.rs"]
mod proxy;
#[path = "http_runtime/resource_budget.rs"]
mod resource_budget;
pub use resource_budget::{BudgetSnapshot, ResourceDiagnostics, ResourceLimits};
#[path = "http_runtime/request.rs"]
mod request;

#[path = "http_runtime/rewrite_uri.rs"]
mod rewrite_uri;
#[path = "http_runtime/sniff.rs"]
#[allow(dead_code)] // Used by the following encode middleware stage, not file_server.
mod sniff;
#[path = "http_runtime/timeout_io.rs"]
mod timeout_io;
#[path = "http_runtime/trailer_policy.rs"]
mod trailer_policy;
#[path = "http_runtime/upstream_tls.rs"]
mod upstream_tls;
pub use upstream_tls::NativeTrustDiagnostics;

use crate::{
    challenge::{ACME_ALPN, ChallengeRegistry},
    http_config::{PreparedConfig, ServerConfig, types::*},
    tls_resolver::{CertificateInput, HotCertificateResolver},
};
use anyhow::{Result, ensure};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    collections::HashMap, convert::Infallible, fmt, net::SocketAddr, sync::Arc, time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Body = UnsyncBoxBody<Bytes, BoxError>;

pub struct HttpRuntime {
    inner: Arc<Inner>,
    control: Arc<lifecycle::Lifecycle>,
}
impl HttpRuntime {
    /// Process-level native CA load and skipped-root counts, without material.
    pub fn native_upstream_trust_diagnostics(&self) -> NativeTrustDiagnostics {
        upstream_tls::diagnostics()
    }
    /// Process-wide count of trailer values excluded by the proxy policy.
    /// Header values and per-user labels are never retained in this counter.
    pub fn filtered_trailer_values(&self) -> u64 {
        trailer_policy::filtered_values()
    }
    /// Process-wide later request trailer values omitted by the pinned clone
    /// policy; separate from forbidden response trailer value diagnostics.
    pub fn dropped_request_trailer_values(&self) -> u64 {
        trailer_policy::dropped_request_values()
    }
}
struct Inner {
    current: ArcSwap<Generation>,
    registry: ChallengeRegistry,
    managed: Arc<HotCertificateResolver>,
    tasks: TaskTracker,
    upgrades: TaskTracker,
    resources: Arc<resource_budget::Resources>,
    stopped: CancellationToken,
}
struct Generation {
    id: u64,
    servers: HashMap<SocketAddr, Arc<ActiveServer>>,
    drain: CancellationToken,
    managed_names: Vec<Vec<String>>,
}
#[derive(Clone)]
struct ActiveServer {
    plan: Arc<ServerConfig>,
    tls: Option<Arc<rustls::ServerConfig>>,
    resolver: Option<Arc<CandidateResolver>>,
    sessions: Arc<connection_sessions::SharedSessions>,
    clients: Arc<HashMap<usize, proxy::ProxyClient>>,
}
struct CandidateResolver {
    static_certificates: Arc<HotCertificateResolver>,
    managed: Arc<HotCertificateResolver>,
    allowed_managed: Vec<String>,
}
impl fmt::Debug for CandidateResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateResolver").finish_non_exhaustive()
    }
}
impl ResolvesServerCert for CandidateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let alpn = hello
            .alpn()
            .map(|x| x.collect::<Vec<_>>())
            .unwrap_or_default();
        self.select_for_version(
            hello.server_name(),
            &alpn,
            hello.signature_schemes(),
            hello.negotiated_version()?,
        )
        .map(|selection| selection.key)
    }
}
impl CandidateResolver {
    fn select_candidate(
        &self,
        sni: Option<&str>,
        alpn: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
    ) -> Option<crate::tls_resolver::CertificateSelection> {
        self.select_using(sni, alpn, |resolver, sni| {
            resolver.select_candidate(Some(sni), alpn, schemes)
        })
    }
    fn select_for_version(
        &self,
        sni: Option<&str>,
        alpn: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
        version: rustls::ProtocolVersion,
    ) -> Option<crate::tls_resolver::CertificateSelection> {
        self.select_using(sni, alpn, |resolver, sni| {
            resolver.select_for_version(Some(sni), alpn, schemes, version)
        })
    }
    fn select_using(
        &self,
        sni: Option<&str>,
        alpn: &[&[u8]],
        mut select: impl FnMut(
            &HotCertificateResolver,
            &str,
        ) -> Option<crate::tls_resolver::CertificateSelection>,
    ) -> Option<crate::tls_resolver::CertificateSelection> {
        let sni = sni?;
        if alpn.contains(&ACME_ALPN) {
            return select(&self.managed, sni);
        }
        select(&self.static_certificates, sni).or_else(|| {
            self.allowed_managed
                .iter()
                .any(|name| dns_covers(name, sni))
                .then(|| select(&self.managed, sni))
                .flatten()
        })
    }
}
impl HttpRuntime {
    pub fn new(registry: ChallengeRegistry, resolver: Arc<HotCertificateResolver>) -> Self {
        Self::from_resources(
            registry,
            resolver,
            Arc::new(resource_budget::Resources::automatic()),
        )
    }
    /// Explicit native resource policy. `None` disables an independent timer;
    /// `Some(Duration::ZERO)` is rejected. Operation/waiter counts stay bounded.
    /// These options do not introduce or ignore fields in Caddy JSON.
    pub fn with_resource_limits(
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        limits: ResourceLimits,
    ) -> Result<Self> {
        Ok(Self::from_resources(
            registry,
            resolver,
            Arc::new(resource_budget::Resources::from_limits(limits)?),
        ))
    }
    fn from_resources(
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        resources: Arc<resource_budget::Resources>,
    ) -> Self {
        let initial = Generation {
            id: 0,
            servers: HashMap::new(),
            drain: CancellationToken::new(),
            managed_names: Vec::new(),
        };
        Self {
            inner: Arc::new(Inner {
                current: ArcSwap::from_pointee(initial),
                registry,
                managed: resolver,
                tasks: TaskTracker::new(),
                upgrades: TaskTracker::new(),
                resources,
                stopped: CancellationToken::new(),
            }),
            control: Arc::new(lifecycle::Lifecycle::new()),
        }
    }
    /// CPU-adaptive HTTP work admission; snapshots contain counts only.
    pub fn resource_diagnostics(&self) -> ResourceDiagnostics {
        self.inner.resources.snapshot()
    }
    pub fn generation(&self) -> u64 {
        self.inner.current.load().id
    }
    pub fn active_managed_names(&self) -> Vec<Vec<String>> {
        self.inner.current.load().managed_names.clone()
    }
}

async fn prepare_servers(
    config: &PreparedConfig,
    registry: &ChallengeRegistry,
    managed: &Arc<HotCertificateResolver>,
) -> Result<(HashMap<SocketAddr, Arc<ActiveServer>>, Vec<Vec<String>>)> {
    let mut actual_managed = std::collections::BTreeSet::new();
    let mut redirects = HashMap::<SocketAddr, Vec<Route>>::new();
    let mut output = HashMap::new();
    for server in &config.servers {
        let local = Arc::new(HotCertificateResolver::with_leaf_guard(
            registry.clone(),
            managed.leaf_guard(),
        ));
        let mut materials = Vec::new();
        if server.tls {
            for file in &config.certificates {
                if !server.certificate_tags.is_empty()
                    && !file
                        .tags
                        .iter()
                        .any(|tag| server.certificate_tags.contains(tag))
                {
                    continue;
                }
                let certificate_path = crate::http_config::helpers::replace(
                    &file.certificate,
                    true,
                    crate::http_config::helpers::global_lookup,
                )?;
                let key_path = crate::http_config::helpers::replace(
                    &file.key,
                    true,
                    crate::http_config::helpers::global_lookup,
                )?;
                let chain = read_bounded(&certificate_path, 4 * 1024 * 1024).await?;
                let key = zeroize::Zeroizing::new(read_bounded(&key_path, 128 * 1024).await?);
                let names = certificate_names(&chain)?;
                materials.push((names, chain, key));
            }
            let inputs = materials
                .iter()
                .map(|(names, chain, key)| CertificateInput {
                    names,
                    certificate_pem: chain,
                    private_key_pem: key,
                })
                .collect::<Vec<_>>();
            local.replace(&inputs)?;
            ensure!(
                server.certificate_tags.is_empty() || !materials.is_empty(),
                "TLS certificate tags matched no certificate"
            );
        }
        let loaded_names = materials
            .iter()
            .flat_map(|(names, _, _)| names.iter())
            .collect::<Vec<_>>();
        let managed_names = if server.manage_certificates {
            crate::http_config::server_names(server)
                .into_iter()
                .filter(|name| {
                    !server
                        .skip_manage
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(name))
                        && (server.ignore_loaded_certificates
                            || !loaded_names.iter().any(|loaded| dns_covers(loaded, name)))
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if server.tls {
            actual_managed.extend(managed_names.iter().cloned());
        }
        if server.tls && server.redirect_http {
            let names = crate::http_config::server_names(server)
                .into_iter()
                .filter(|name| {
                    !server
                        .skip_redirect
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(name))
                })
                .collect::<Vec<_>>();
            if !names.is_empty() {
                for address in &server.listen {
                    let redirect_addr = SocketAddr::new(address.ip(), 80);
                    let port = if address.port() == 443 {
                        String::new()
                    } else {
                        format!(":{}", address.port())
                    };
                    redirects.entry(redirect_addr).or_default().push(Route {
                        group: None,
                        matchers: vec![vec![Matcher::Host(names.clone())]],
                        handlers: vec![Handler::StaticResponse {
                            status: "308".into(),
                            body: String::new(),
                            headers: HeaderOps {
                                set: vec![(
                                    "Location".into(),
                                    vec![format!(
                                        "https://{{http.request.host}}{port}{{http.request.uri}}"
                                    )],
                                )],
                                ..Default::default()
                            },
                            close: false,
                        }],
                        terminal: true,
                    });
                }
            }
        }
        let (tls, resolver) = if server.tls {
            let resolver = Arc::new(CandidateResolver {
                static_certificates: local,
                managed: managed.clone(),
                allowed_managed: if server.certificate_tags.is_empty() {
                    managed_names.clone()
                } else {
                    Vec::new()
                },
            });
            let mut tls = rustls::ServerConfig::builder_with_provider(crate::crypto::provider())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_cert_resolver(resolver.clone());
            if server.protocols.iter().any(|p| p == "h2") {
                tls.alpn_protocols.push(b"h2".to_vec());
            }
            if server.protocols.iter().any(|p| p == "h1") {
                tls.alpn_protocols.push(b"http/1.1".to_vec());
            }
            tls.alpn_protocols.push(ACME_ALPN.to_vec());
            ensure!(
                !tls.ticketer.enabled() && tls.max_early_data_size == 0,
                "unsupported TLS session policy"
            );
            (Some(Arc::new(tls)), Some(resolver))
        } else {
            (None, None)
        };
        let client_plan = server.clone();
        let clients = tokio::task::spawn_blocking(move || {
            let mut clients = HashMap::new();
            proxy::prepare_clients(&client_plan.routes, &mut clients)?;
            proxy::prepare_clients(&client_plan.errors, &mut clients)?;
            Ok::<_, anyhow::Error>(clients)
        })
        .await
        .map_err(|_| anyhow::anyhow!("candidate proxy provisioning task failed"))??;
        let active = ActiveServer {
            plan: server.clone(),
            tls,
            resolver,
            sessions: Arc::new(connection_sessions::SharedSessions::new()),
            clients: Arc::new(clients),
        };
        for addr in &server.listen {
            output.insert(*addr, Arc::new(active.clone()));
        }
    }
    for (address, routes) in redirects {
        if let Some(existing) = output.get(&address).cloned() {
            ensure!(
                !existing.plan.tls,
                "automatic redirect listener conflicts with TLS"
            );
            let mut plan = (*existing.plan).clone();
            let split = plan
                .routes
                .iter()
                .position(|route| {
                    !route
                        .matchers
                        .iter()
                        .flatten()
                        .any(|m| matches!(m, Matcher::Host(_)))
                })
                .unwrap_or(plan.routes.len());
            plan.routes.splice(split..split, routes);
            let plan = Arc::new(plan);
            let client_plan = plan.clone();
            let clients = tokio::task::spawn_blocking(move || {
                let mut clients = HashMap::new();
                proxy::prepare_clients(&client_plan.routes, &mut clients)?;
                proxy::prepare_clients(&client_plan.errors, &mut clients)?;
                Ok::<_, anyhow::Error>(clients)
            })
            .await
            .map_err(|_| anyhow::anyhow!("candidate proxy provisioning task failed"))??;
            output.insert(
                address,
                Arc::new(ActiveServer {
                    plan,
                    tls: None,
                    resolver: None,
                    sessions: Arc::new(connection_sessions::SharedSessions::new()),
                    clients: Arc::new(clients),
                }),
            );
        } else {
            let plan = ServerConfig {
                listen: vec![address],
                routes,
                errors: Vec::new(),
                tls: false,
                certificate_tags: Vec::new(),
                trusted_proxies: Vec::new(),
                trusted_strict: false,
                client_ip_headers: vec!["X-Forwarded-For".into()],
                read_header_timeout: Duration::from_secs(60),
                read_idle_timeout: Duration::from_secs(60),
                protocols: vec!["h1".into(), "h2".into()],
                redirect_http: false,
                manage_certificates: false,
                skip_manage: vec![],
                skip_redirect: vec![],
                ignore_loaded_certificates: false,
            };
            output.insert(
                address,
                Arc::new(ActiveServer {
                    plan: Arc::new(plan),
                    tls: None,
                    resolver: None,
                    sessions: Arc::new(connection_sessions::SharedSessions::new()),
                    clients: Arc::new(HashMap::new()),
                }),
            );
        }
    }
    Ok((
        output,
        actual_managed.into_iter().map(|n| vec![n]).collect(),
    ))
}
fn plain_transport_compatible(old: &ServerConfig, next: &ServerConfig) -> bool {
    !old.tls
        && !next.tls
        && old.protocols == next.protocols
        && old.read_header_timeout == next.read_header_timeout
}
fn dns_covers(pattern: &str, name: &str) -> bool {
    if pattern.eq_ignore_ascii_case(name) {
        return true;
    }
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        name.split_once('.')
            .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(suffix))
    })
}
fn bind_listener(address: SocketAddr) -> Result<TcpListener> {
    let domain = if address.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() && address.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}

async fn read_bounded(path: &str, limit: u64) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let path = path.to_owned();
    let file =
        tokio::task::spawn_blocking(move || crate::http_config::helpers::open_regular_file(path))
            .await?
            .map_err(|_| anyhow::anyhow!("configured TLS material unavailable"))?;
    let file = tokio::fs::File::from_std(file);
    let meta = file.metadata().await?;
    ensure!(
        meta.is_file() && meta.len() > 0 && meta.len() <= limit,
        "configured TLS material outside bounds"
    );
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len() as u64 <= limit,
        "TLS material grew beyond limit"
    );
    Ok(bytes)
}
fn certificate_names(chain: &[u8]) -> Result<Vec<String>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain)
        .map_err(|_| anyhow::anyhow!("invalid TLS certificate PEM"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|_| anyhow::anyhow!("invalid TLS certificate DER"))?;
    let san = cert
        .subject_alternative_name()?
        .ok_or_else(|| anyhow::anyhow!("TLS certificate lacks SAN"))?;
    let names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| {
            if let x509_parser::extensions::GeneralName::DNSName(name) = name {
                Some(name.to_ascii_lowercase())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    ensure!(!names.is_empty(), "DNS TLS certificate has no DNS SAN");
    Ok(names)
}
/// A newly bound candidate socket can prove ownership before publication, but
/// never exposes the candidate routes. Mode is fixed when a connection accepts.
#[derive(Clone)]
struct ProofListener {
    tls: Option<Arc<rustls::ServerConfig>>,
    cancel: CancellationToken,
}
struct ProofResolver(Arc<HotCertificateResolver>);
impl fmt::Debug for ProofResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofResolver").finish_non_exhaustive()
    }
}
impl ResolvesServerCert for ProofResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let protocols = hello.alpn()?.collect::<Vec<_>>();
        if protocols != [ACME_ALPN] {
            return None;
        }
        self.0
            .select_for_version(
                hello.server_name(),
                &protocols,
                hello.signature_schemes(),
                hello.negotiated_version()?,
            )
            .map(|selection| selection.key)
    }
}
fn proof_tls_config(managed: Arc<HotCertificateResolver>) -> Result<Arc<rustls::ServerConfig>> {
    let mut tls = rustls::ServerConfig::builder_with_provider(crate::crypto::provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ProofResolver(managed)));
    tls.alpn_protocols = vec![ACME_ALPN.to_vec()];
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    Ok(Arc::new(tls))
}
async fn accept_loop(
    inner: Arc<Inner>,
    socket: TcpListener,
    key: SocketAddr,
    cancel: CancellationToken,
    fallback: Option<ProofListener>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = inner.stopped.cancelled() => break,
            result = socket.accept() => result,
        };
        let Ok((stream, peer)) = accepted else {
            if cancel.is_cancelled() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        // Proof/business mode is fixed at accept. A TLS ClientHello selects
        // from one current identity view; each HTTP operation later checks its
        // actual handshake identity against the current published policy.
        let snapshot = loop {
            let snapshot = inner.current.load_full();
            if !snapshot.drain.is_cancelled() || inner.stopped.is_cancelled() {
                break snapshot;
            }
        };
        let server = snapshot.servers.get(&key).cloned();
        let canonical =
            |address: SocketAddr| SocketAddr::new(address.ip().to_canonical(), address.port());
        let peer = canonical(peer);
        let local = canonical(stream.local_addr().unwrap_or(key));
        let _ = stream.set_nodelay(true);
        let task_inner = inner.clone();
        if let Some(server) = server {
            inner.tasks.spawn(async move {
                if server.tls.is_some() {
                    let handshake = connection_identity::accept(&task_inner, stream, key);
                    let accepted = tokio::select! {
                        biased;
                        _ = task_inner.stopped.cancelled() => return,
                        result = tokio::time::timeout(Duration::from_secs(30), handshake) => match result {
                            Ok(Ok(accepted)) => accepted,
                            _ => return,
                        },
                    };
                    let negotiated_h2 = accepted.stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    serve_connection(task_inner, TokioIo::new(accepted.stream), peer, local, ConnectionView {
                        key, server: accepted.server,
                        negotiated_tls_h2: Some(negotiated_h2), identity: Some(accepted.identity),
                    }).await;
                } else {
                    serve_connection(task_inner, TokioIo::new(stream), peer, local, ConnectionView { key, server, negotiated_tls_h2: None, identity: None }).await;
                }
            });
        } else if let Some(proof) = fallback.clone() {
            // A proof connection accepted before commit cannot turn into a
            // business connection after commit, even if it delays its headers.
            inner.tasks.spawn(async move {
                if proof.cancel.is_cancelled() {
                    return;
                }
                if let Some(tls) = proof.tls {
                    let handshake = tokio_rustls::TlsAcceptor::from(tls).accept(stream);
                    tokio::select! {
                        biased;
                        _ = proof.cancel.cancelled() => {},
                        _ = task_inner.stopped.cancelled() => {},
                        _ = tokio::time::timeout(Duration::from_secs(30), handshake) => {},
                    }
                    // ACME ALPN never speaks HTTP after its handshake.
                } else {
                    serve_proof_connection(task_inner, TokioIo::new(stream), proof.cancel).await;
                }
            });
        }
    }
}
async fn serve_proof_connection<I>(inner: Arc<Inner>, io: I, cancel: CancellationToken)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let registry = inner.registry.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let response = match request::proof_response(&registry, &request) {
            Ok(Some(response)) => response,
            Ok(None) => simple(StatusCode::NOT_FOUND, "Not Found\n"),
            Err(()) => simple(StatusCode::BAD_REQUEST, "Bad Request\n"),
        };
        async { Ok::<_, Infallible>(response) }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(60));
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = cancel.cancelled() => {},
        _ = inner.stopped.cancelled() => {},
    }
}
struct ConnectionView {
    key: SocketAddr,
    server: Arc<ActiveServer>,
    negotiated_tls_h2: Option<bool>,
    identity: Option<Arc<TlsIdentity>>,
}
async fn serve_connection<I>(
    inner: Arc<Inner>,
    io: I,
    peer: SocketAddr,
    local: SocketAddr,
    view: ConnectionView,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let ConnectionView {
        key,
        server,
        negotiated_tls_h2,
        identity,
    } = view;
    let tls = negotiated_tls_h2.is_some();
    let svc_inner = inner.clone();
    let svc_server = server.clone();
    let requested_drain = CancellationToken::new();
    let service_drain = requested_drain.clone();
    let service = service_fn(move |mut request: Request<Incoming>| {
        let inner = svc_inner.clone();
        let accepted_server = svc_server.clone();
        let identity = identity.clone();
        let requested_drain = service_drain.clone();
        async move {
            let snapshot = inner.current.load_full();
            let current = snapshot.servers.get(&key).cloned();
            let verdict = match (identity.as_ref(), current.as_ref()) {
                (Some(identity), Some(current)) => {
                    identity.verdict(current, negotiated_tls_h2 == Some(true))
                }
                (None, Some(current))
                    if plain_transport_compatible(&accepted_server.plan, &current.plan) =>
                {
                    TlsVerdict::Serve
                }
                _ => TlsVerdict::Reject,
            };
            if verdict == TlsVerdict::Reject {
                let mut response = simple(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable\n");
                response.headers_mut().insert(
                    http::header::RETRY_AFTER,
                    http::HeaderValue::from_static("0"),
                );
                if request.version() != http::Version::HTTP_2 {
                    response.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                } else {
                    requested_drain.cancel();
                }
                return Ok(response);
            }
            let Some(current) = current else {
                return Ok(simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service Unavailable\n",
                ));
            };
            let close_after = verdict == TlsVerdict::ServeThenClose
                || current.plan.read_header_timeout != accepted_server.plan.read_header_timeout;
            let request_h2 = request.version() == http::Version::HTTP_2;
            let metadata = match trailer_policy::prepare_request(&mut request) {
                Ok(metadata) => metadata,
                Err(()) => {
                    let mut response = simple(StatusCode::BAD_REQUEST, "Bad Request\n");
                    response.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                    return Ok(response);
                }
            };
            let fault = metadata.fault.clone();
            if !metadata.is_empty() {
                request.extensions_mut().insert(metadata);
            }
            let keep = current.clone();
            let mut response = request::handle(
                inner,
                current,
                request,
                peer,
                local,
                tls,
                snapshot.drain.clone(),
            )
            .await;
            if close_after {
                if request_h2 {
                    requested_drain.cancel();
                } else {
                    response.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
            }
            if fault.as_ref().is_some_and(CancellationToken::is_cancelled) {
                return Err(h2::Error::from(h2::Reason::PROTOCOL_ERROR));
            }
            Ok(response.map(|body| {
                trailer_policy::guard_response(RetainedBody { body, keep }.boxed_unsync(), fault)
            }))
        }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .allow_undeclared_trailers(true)
        .max_trailer_size(4096)
        .allow_obsolete_multiline_trailers(true)
        .timer(TokioTimer::new())
        .header_read_timeout(server.plan.read_header_timeout);
    let allow_h2 = server
        .plan
        .protocols
        .iter()
        .any(|p| p == if tls { "h2" } else { "h2c" });
    if let Some(negotiated_h2) = negotiated_tls_h2 {
        builder = if negotiated_h2 {
            builder.http2_only()
        } else {
            builder.http1_only()
        };
    } else if !allow_h2 {
        builder = builder.http1_only();
    }
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = requested_drain.cancelled() => { connection.as_mut().graceful_shutdown(); let _ = connection.await; },
        _ = inner.stopped.cancelled() => { connection.as_mut().graceful_shutdown(); let _ = connection.await; },
    }
}
struct RetainedBody {
    body: Body,
    keep: Arc<ActiveServer>,
}
impl hyper::body::Body for RetainedBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        let _keep = &self.keep;
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
pub(crate) fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never: Infallible| -> BoxError { match never {} })
        .boxed_unsync()
}
pub(crate) fn simple(status: StatusCode, body: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(full(body));
    *r.status_mut() = status;
    r
}

impl Drop for HttpRuntime {
    fn drop(&mut self) {
        self.force_shutdown();
    }
}
