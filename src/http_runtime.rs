//! Native HTTP listeners with request-scoped configuration snapshots. Preparation is
//! isolated from publication; failed binds and certificate loads preserve the
//! active generation. This module never starts a Go process.
#[path = "http_runtime/files.rs"]
mod files;
#[path = "http_runtime/mime.rs"]
mod mime;
#[path = "http_runtime/proxy.rs"]
mod proxy;
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
use tokio::{net::TcpListener, sync::Mutex};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Body = UnsyncBoxBody<Bytes, BoxError>;

pub struct HttpRuntime {
    inner: Arc<Inner>,
    control: Mutex<Control>,
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
    stopped: CancellationToken,
}
struct Control {
    listeners: HashMap<SocketAddr, ListenerControl>,
    generation: u64,
    stopped: bool,
}
struct ListenerControl {
    cancel: CancellationToken,
    actual: SocketAddr,
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
    clients: Arc<HashMap<usize, proxy::ProxyClient>>,
    policy_key: Vec<u8>,
    connection_cancel: CancellationToken,
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
        let sni = hello.server_name()?;
        if alpn.contains(&ACME_ALPN) {
            // The same challenge registry backs both resolvers. Only the
            // managed resolver needs to answer validation certificates.
            return self
                .managed
                .select(Some(sni), &alpn, hello.signature_schemes());
        }
        self.static_certificates
            .select(Some(sni), &alpn, hello.signature_schemes())
            .or_else(|| {
                self.allowed_managed
                    .iter()
                    .any(|name| dns_covers(name, sni))
                    .then(|| {
                        self.managed
                            .select(Some(sni), &alpn, hello.signature_schemes())
                    })
                    .flatten()
            })
    }
}
impl HttpRuntime {
    pub fn new(registry: ChallengeRegistry, resolver: Arc<HotCertificateResolver>) -> Self {
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
                stopped: CancellationToken::new(),
            }),
            control: Mutex::new(Control {
                listeners: HashMap::new(),
                generation: 0,
                stopped: false,
            }),
        }
    }
    pub async fn validate_prepared(&self, config: &PreparedConfig) -> Result<()> {
        let _ = prepare_servers(config, &self.inner).await?;
        Ok(())
    }
    pub async fn apply(&self, config: PreparedConfig) -> Result<()> {
        // Serializing apply does not serialize request handling or certificate
        // renewal. The lock is never held by a request or TLS resolver.
        let mut control = self.control.lock().await;
        ensure!(!control.stopped, "HTTP runtime is stopped");
        let generation = control
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("HTTP generation exhausted"))?;
        let (servers, managed_names) = prepare_servers(&config, &self.inner).await?;
        let mut new_listeners = Vec::new();
        for addr in servers.keys() {
            if !control.listeners.contains_key(addr) {
                let socket = bind_listener(*addr)
                    .map_err(|_| anyhow::anyhow!("candidate HTTP listener bind failed"))?;
                let actual = socket.local_addr()?;
                new_listeners.push((*addr, actual, socket, CancellationToken::new()));
            }
        }
        let next = Arc::new(Generation {
            id: generation,
            servers,
            drain: CancellationToken::new(),
            managed_names,
        });
        // From here publication is infallible: all parsing, provision, roots,
        // certificates and socket binds completed without touching old state.
        let previous = self.inner.current.swap(next.clone());
        control.generation = generation;
        for (addr, actual, socket, cancel) in new_listeners {
            control.listeners.insert(
                addr,
                ListenerControl {
                    cancel: cancel.clone(),
                    actual,
                },
            );
            let inner = self.inner.clone();
            self.inner.tasks.spawn(async move {
                accept_loop(inner, socket, addr, cancel).await;
            });
        }
        control.listeners.retain(|addr, listener| {
            if next.servers.contains_key(addr) {
                true
            } else {
                listener.cancel.cancel();
                false
            }
        });
        for (address, old) in &previous.servers {
            if next
                .servers
                .get(address)
                .is_none_or(|new| new.policy_key != old.policy_key)
            {
                old.connection_cancel.cancel();
            }
        }
        previous.drain.cancel();
        Ok(())
    }
    pub fn generation(&self) -> u64 {
        self.inner.current.load().id
    }
    pub fn active_managed_names(&self) -> Vec<Vec<String>> {
        self.inner.current.load().managed_names.clone()
    }
    pub async fn bound_addresses(&self) -> Vec<SocketAddr> {
        self.control
            .lock()
            .await
            .listeners
            .values()
            .map(|l| l.actual)
            .collect()
    }
    /// Stops accepting first, requests protocol-level graceful drain, and waits.
    /// A deadline does not abort active upgrades; timeout is reported and the
    /// runtime stays stopped. Calling shutdown again can await their completion.
    pub async fn shutdown(&self, deadline: Duration) -> Result<()> {
        {
            let mut control = self.control.lock().await;
            control.stopped = true;
            for listener in control.listeners.values() {
                listener.cancel.cancel();
            }
            self.inner.current.load().drain.cancel();
            for server in self.inner.current.load().servers.values() {
                server.connection_cancel.cancel();
            }
            self.inner.stopped.cancel();
            self.inner.tasks.close();
            self.inner.upgrades.close();
        }
        tokio::time::timeout(deadline, async {
            self.inner.tasks.wait().await;
            self.inner.upgrades.wait().await;
        })
        .await
        .map_err(|_| anyhow::anyhow!("HTTP shutdown deadline elapsed with active connections"))?;
        Ok(())
    }
}
async fn prepare_servers(
    config: &PreparedConfig,
    inner: &Arc<Inner>,
) -> Result<(HashMap<SocketAddr, Arc<ActiveServer>>, Vec<Vec<String>>)> {
    let mut actual_managed = std::collections::BTreeSet::new();
    let mut redirects = HashMap::<SocketAddr, Vec<Route>>::new();
    let mut output = HashMap::new();
    for server in &config.servers {
        let local = Arc::new(HotCertificateResolver::with_leaf_guard(
            inner.registry.clone(),
            inner.managed.leaf_guard(),
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
        let tls = if server.tls {
            let mut tls = rustls::ServerConfig::builder_with_provider(crate::crypto::provider())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CandidateResolver {
                    static_certificates: local,
                    managed: inner.managed.clone(),
                    allowed_managed: if server.certificate_tags.is_empty() {
                        managed_names.clone()
                    } else {
                        Vec::new()
                    },
                }));
            if server.protocols.iter().any(|p| p == "h2") {
                tls.alpn_protocols.push(b"h2".to_vec());
            }
            if server.protocols.iter().any(|p| p == "h1") {
                tls.alpn_protocols.push(b"http/1.1".to_vec());
            }
            tls.alpn_protocols.push(ACME_ALPN.to_vec());
            Some(Arc::new(tls))
        } else {
            None
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
        let policy_key = policy_key(server, !materials.is_empty());
        let active = ActiveServer {
            plan: server.clone(),
            tls,
            clients: Arc::new(clients),
            policy_key,
            connection_cancel: CancellationToken::new(),
        };
        let previous = inner.current.load_full();
        for addr in &server.listen {
            let mut active = active.clone();
            if let Some(old) = previous.servers.get(addr)
                && old.policy_key == active.policy_key
            {
                active.connection_cancel = old.connection_cancel.clone();
            }
            output.insert(*addr, Arc::new(active));
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
            let policy_key = policy_key(&plan, false);
            let connection_cancel = inner
                .current
                .load()
                .servers
                .get(&address)
                .filter(|old| old.policy_key == policy_key)
                .map(|old| old.connection_cancel.clone())
                .unwrap_or_default();
            output.insert(
                address,
                Arc::new(ActiveServer {
                    plan,
                    tls: None,
                    clients: Arc::new(clients),
                    policy_key,
                    connection_cancel,
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
            let policy_key = policy_key(&plan, false);
            let connection_cancel = inner
                .current
                .load()
                .servers
                .get(&address)
                .filter(|old| old.policy_key == policy_key)
                .map(|old| old.connection_cancel.clone())
                .unwrap_or_default();
            output.insert(
                address,
                Arc::new(ActiveServer {
                    plan: Arc::new(plan),
                    tls: None,
                    clients: Arc::new(HashMap::new()),
                    policy_key,
                    connection_cancel,
                }),
            );
        }
    }
    Ok((
        output,
        actual_managed.into_iter().map(|n| vec![n]).collect(),
    ))
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
async fn accept_loop(
    inner: Arc<Inner>,
    socket: TcpListener,
    key: SocketAddr,
    cancel: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {biased;_ = cancel.cancelled()=>break,_=inner.stopped.cancelled()=>break,result=socket.accept()=>result};
        let Ok((stream, peer)) = accepted else {
            if cancel.is_cancelled() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let snapshot = inner.current.load_full();
        let Some(server) = snapshot.servers.get(&key).cloned() else {
            continue;
        };
        let canonical =
            |address: SocketAddr| SocketAddr::new(address.ip().to_canonical(), address.port());
        let peer = canonical(peer);
        let local = canonical(stream.local_addr().unwrap_or(key));
        let _ = stream.set_nodelay(true);
        let inner_clone = inner.clone();
        inner.tasks.spawn(async move {
            if let Some(tls)=server.tls.clone() {
                let handshake=tokio_rustls::TlsAcceptor::from(tls).accept(stream);
                let tls=tokio::select!{_ = server.connection_cancel.cancelled()=>return,result=tokio::time::timeout(Duration::from_secs(30),handshake)=>match result{Ok(Ok(tls))=>tls,_=>return}};
                if tls.get_ref().1.alpn_protocol()==Some(ACME_ALPN){return;}
                let negotiated_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                serve_connection(inner_clone,TokioIo::new(tls),peer,local,key,server,Some(negotiated_h2)).await;
            }else{serve_connection(inner_clone,TokioIo::new(stream),peer,local,key,server,None).await;}
        });
    }
}
fn policy_key(server: &ServerConfig, has_static: bool) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(serde_json::to_vec(&serde_json::json!({"tls":server.tls,"protocols":server.protocols,"certificate_tags":server.certificate_tags,"static_resolver":has_static,"header_read_timeout_ns":server.read_header_timeout.as_nanos()})).expect("known policy JSON serializes")).to_vec()
}
async fn serve_connection<I>(
    inner: Arc<Inner>,
    io: I,
    peer: SocketAddr,
    local: SocketAddr,
    key: SocketAddr,
    server: Arc<ActiveServer>,
    negotiated_tls_h2: Option<bool>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let tls = negotiated_tls_h2.is_some();
    let svc_inner = inner.clone();
    let accepted_policy = server.policy_key.clone();
    let policy_cancel = server.connection_cancel.clone();
    let requested_drain = CancellationToken::new();
    let service_drain = requested_drain.clone();
    let service = service_fn(move |mut request: Request<Incoming>| {
        let inner = svc_inner.clone();
        let accepted_policy = accepted_policy.clone();
        let requested_drain = service_drain.clone();
        async move {
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
            let snapshot = inner.current.load_full();
            let Some(current) = snapshot.servers.get(&key).cloned() else {
                requested_drain.cancel();
                let mut r = simple(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable\n");
                if request.version() != http::Version::HTTP_2 {
                    r.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                return Ok::<_, h2::Error>(r);
            };
            if current.policy_key != accepted_policy {
                requested_drain.cancel();
                let mut r = simple(StatusCode::MISDIRECTED_REQUEST, "Misdirected Request\n");
                if request.version() != http::Version::HTTP_2 {
                    r.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                return Ok(r);
            }
            let keep = current.clone();
            let response = request::handle(
                inner,
                current,
                request,
                peer,
                local,
                tls,
                snapshot.drain.clone(),
            )
            .await;
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
        // TLS chooses the HTTP protocol during ALPN, not by sniffing a
        // mismatched client preface after the handshake.
        builder = if negotiated_h2 {
            builder.http2_only()
        } else {
            builder.http1_only()
        };
    } else if !allow_h2 {
        builder = builder.http1_only();
    }
    drop(server);
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);
    tokio::select! {
        result=&mut connection=>{let _=result;},
        _=policy_cancel.cancelled()=>{connection.as_mut().graceful_shutdown();let _=connection.await;},
        _=requested_drain.cancelled()=>{connection.as_mut().graceful_shutdown();let _=connection.await;},
        _=inner.stopped.cancelled()=>{connection.as_mut().graceful_shutdown();let _=connection.await;}
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
        self.inner.stopped.cancel();
        self.inner.current.load().drain.cancel();
    }
}
