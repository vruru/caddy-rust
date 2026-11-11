//! Native HTTP listeners with request-scoped configuration snapshots. Preparation is
//! isolated from publication; failed binds and certificate loads preserve the
//! active generation. This module never starts a Go process.
#[path = "http_runtime/pressure.rs"]
mod pressure;
#[path = "http_runtime/connection_budget.rs"]
mod connection_budget;
#[path = "http_runtime/descriptor_budget.rs"]
mod descriptor_budget;
pub use connection_budget::{ConnectionLimits,ConnectionDiagnostics,ConnectionPoolSnapshot};
#[path = "http_runtime/auth_cache.rs"]
pub(crate) mod auth_cache;
#[path = "http_runtime/certificate_provider.rs"]
mod certificate_provider;
pub use certificate_provider::ScopedCertificateProvider;
#[path = "http_runtime/connection_identity.rs"]
mod connection_identity;
#[path = "http_runtime/connection_sessions.rs"]
mod connection_sessions;
#[path = "http_runtime/files.rs"]
mod files;

#[path = "http_runtime/fastcgi/mod.rs"]
mod fastcgi;

#[path = "http_runtime/access_log.rs"]
mod access_log;
#[path = "http_runtime/tls_executor.rs"]
mod tls_executor;
pub use tls_executor::TlsHandshakeDiagnostics;
use connection_identity::{TlsIdentity, TlsVerdict};
#[path = "http_runtime/lifecycle.rs"]
mod lifecycle;
#[path = "http_runtime/manual_certificates.rs"]
mod manual_certificates;
pub use lifecycle::{CommitOutcome, HttpStage, StagedAddress};
#[path = "http_runtime/listener_lease.rs"]
mod listener_lease;
pub use listener_lease::{
    ChallengeBindingRequest, ChallengeListenerLease, ChallengeListenerProvider,
};
#[path = "http_runtime/mime.rs"]
mod mime;
#[path = "http_runtime/path_glob.rs"]
mod path_glob;
pub(crate) use path_glob::go_path_glob;
#[path = "http_runtime/proxy.rs"]
mod proxy;
#[path = "http_runtime/retirement.rs"]
mod retirement;
use retirement::{BusinessGeneration, BusinessGuard};
pub use retirement::{HttpRetirement, RetirementOutcome};
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
    tls_resolver::{CertificateInput, HotCertificateResolver, ManualCertificates},
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
    connections:Arc<connection_budget::Budgets>,
    tls_executor: std::sync::OnceLock<tls_executor::TlsExecutor>,
    tls_executor_init: std::sync::Mutex<()>,
    tls_executor_failure: std::sync::atomic::AtomicU8,
    tls_executor_attempts: std::sync::atomic::AtomicU64,
    current: ArcSwap<Generation>,
    registry: ChallengeRegistry,
    managed: Arc<HotCertificateResolver>,
    challenge_resolver: Arc<HotCertificateResolver>,
    tasks: TaskTracker,
    upgrades: TaskTracker,
    resources: Arc<resource_budget::Resources>,
    stopped: CancellationToken,
}
struct Generation {
    id: u64,
    activity: Arc<BusinessGeneration>,
    servers: HashMap<SocketAddr, Arc<ActiveServer>>,
    retiring: HashMap<SocketAddr, std::sync::Weak<lifecycle::RetiringBinding>>,
    drain: CancellationToken,
    managed_names: Vec<Vec<String>>,
}
impl Generation {
    fn business(&self, key: &SocketAddr) -> Option<(Arc<ActiveServer>, Arc<BusinessGeneration>)> {
        if let Some(server) = self.servers.get(key) {
            return self.activity.is_admitting().then(|| (server.clone(),self.activity.clone()));
        }
        let binding = self.retiring.get(key)?.upgrade()?;
        binding
            .is_accepting()
            .then(|| (binding.server.clone(), binding.activity.clone()))
    }
}
#[derive(Clone)]
struct ActiveServer {
    logging: Option<Arc<crate::logging::Logging>>,
    plan: Arc<ServerConfig>,
    tls: Option<Arc<rustls::ServerConfig>>,
    resolver: Option<Arc<CandidateResolver>>,
    sessions: Arc<connection_sessions::SharedSessions>,
    clients: Arc<HashMap<usize, proxy::ProxyClient>>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum CertificateOrigin { Manual, Managed, Proof }
struct CandidateResolver {
    challenges: Arc<HotCertificateResolver>,
    static_certificates: Arc<HotCertificateResolver>,
    managed: Arc<HotCertificateResolver>,
    allowed_managed: Vec<String>,
    allowed_static: std::collections::HashSet<[u8; 32]>,
    provider: Option<Arc<dyn ScopedCertificateProvider>>,
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
        self.select_using(sni, alpn, |resolver, sni, allowed| match allowed {
            Some(identities) => {
                resolver.select_candidate_filtered(Some(sni), alpn, schemes, identities)
            }
            None => resolver.select_candidate(Some(sni), alpn, schemes),
        })
    }
    fn select_for_version(
        &self, sni: Option<&str>, alpn: &[&[u8]], schemes: &[rustls::SignatureScheme], version: rustls::ProtocolVersion,
    ) -> Option<crate::tls_resolver::CertificateSelection> {
        self.select_for_version_with_origin(sni,alpn,schemes,version).map(|(selection,_)|selection)
    }
    fn select_for_version_with_origin(
        &self, sni: Option<&str>, alpn: &[&[u8]], schemes: &[rustls::SignatureScheme], version: rustls::ProtocolVersion,
    ) -> Option<(crate::tls_resolver::CertificateSelection, CertificateOrigin)> {
        let sni=sni?;
        if alpn.contains(&ACME_ALPN) {
            return self.challenges.select_for_version(Some(sni),alpn,schemes,version).map(|key|(key,CertificateOrigin::Proof));
        }
        self.static_certificates.select_for_version_filtered(Some(sni),alpn,schemes,version,&self.allowed_static)
            .map(|key|(key,CertificateOrigin::Manual))
            .or_else(|| self.managed_name_allowed(sni)
                .then(||self.managed.select_for_version(Some(sni),alpn,schemes,version)).flatten()
                .map(|key|(key,CertificateOrigin::Managed)))
    }
    fn managed_name_allowed(&self, sni:&str)->bool {
        self.allowed_managed.iter().any(|name|dns_covers(name,sni))
            || self.provider.as_ref().is_some_and(|provider|provider.cached_name(sni))
    }
    fn select_using(
        &self,
        sni: Option<&str>,
        alpn: &[&[u8]],
        mut select: impl FnMut(
            &HotCertificateResolver,
            &str,
            Option<&std::collections::HashSet<[u8; 32]>>,
        ) -> Option<crate::tls_resolver::CertificateSelection>,
    ) -> Option<crate::tls_resolver::CertificateSelection> {
        let sni = sni?;
        if alpn.contains(&ACME_ALPN) {
            return select(&self.challenges, sni, None);
        }
        select(&self.static_certificates, sni, Some(&self.allowed_static)).or_else(|| {
            self.managed_name_allowed(sni)
                .then(|| select(&self.managed, sni, None))
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
            connection_budget::Budgets::new(ConnectionLimits::automatic()).expect("valid automatic connection budgets"),
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
        Self::with_limits(registry,resolver,limits,ConnectionLimits::automatic())
    }
    /// Native admission options do not add or ignore Caddy JSON fields.
    pub fn with_connection_limits(registry:ChallengeRegistry,resolver:Arc<HotCertificateResolver>,limits:ConnectionLimits)->Result<Self> {
        Self::with_limits(registry,resolver,ResourceLimits::automatic(),limits)
    }
    pub fn with_limits(registry:ChallengeRegistry,resolver:Arc<HotCertificateResolver>,resources:ResourceLimits,connections:ConnectionLimits)->Result<Self> {
        let resources=Arc::new(resource_budget::Resources::from_limits(resources)?);
        let connections=connection_budget::Budgets::new(connections)?;
        Ok(Self::from_resources(registry,resolver,resources,connections))
    }
    /// Independent-pool diagnostics; not one atomic cross-pool snapshot.
    pub fn connection_diagnostics(&self)->ConnectionDiagnostics { self.inner.connections.snapshot() }
    fn from_resources(
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        resources: Arc<resource_budget::Resources>,
        connections:Arc<connection_budget::Budgets>,
    ) -> Self {
        let activity =
            BusinessGeneration::new(0, crate::http_config::HttpShutdownPolicy::default());
        let initial = Generation {
            id: 0,
            activity: activity.clone(),
            servers: HashMap::new(),
            retiring: HashMap::new(),
            drain: activity.drain.clone(),
            managed_names: Vec::new(),
        };
        let challenge_resolver = Arc::new(HotCertificateResolver::with_leaf_guard(
            registry.clone(),
            resolver.leaf_guard(),
        ));
        Self {
            inner: Arc::new(Inner {
                current: ArcSwap::from_pointee(initial),
                tls_executor: std::sync::OnceLock::new(),
                tls_executor_init: std::sync::Mutex::new(()),
                tls_executor_failure: std::sync::atomic::AtomicU8::new(0),
                tls_executor_attempts: std::sync::atomic::AtomicU64::new(0),
                registry,
                managed: resolver,
                challenge_resolver,
                tasks: TaskTracker::new(),
                upgrades: TaskTracker::new(),
                resources,
                connections,
                stopped: CancellationToken::new(),
            }),
            control: Arc::new(lifecycle::Lifecycle::new()),
        }
    }
    /// CPU-adaptive HTTP work admission; snapshots contain counts only.
    pub fn resource_diagnostics(&self) -> ResourceDiagnostics {
        self.inner.resources.snapshot()
    }
    /// Counts describe live handshake running/waiting lanes. CPU work executes
    /// on the separate all-available-CPU runtime; this snapshot is not atomic
    /// across pools and does not include pre-ClientHello socket admission.
    pub fn tls_handshake_diagnostics(&self)->Option<TlsHandshakeDiagnostics> {
        self.inner.tls_executor.get().map(tls_executor::TlsExecutor::diagnostics)
    }
    /// Last safe failure category; retained after a successful retry.
    pub fn last_tls_executor_initialization_failure(&self)->Option<&'static str> {
        tls_initialization_failure_name(self.inner.tls_executor_failure.load(std::sync::atomic::Ordering::Acquire))
    }
    /// Number of actual constructor attempts, excluding already initialized reads.
    pub fn tls_executor_initialization_attempts(&self)->u64 {
        self.inner.tls_executor_attempts.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn generation(&self) -> u64 {
        self.inner.current.load().id
    }
    pub fn active_managed_names(&self) -> Vec<Vec<String>> {
        self.inner.current.load().managed_names.clone()
    }
}

async fn ensure_tls_executor(inner: &Arc<Inner>) -> Result<()> {
    ensure!(!inner.stopped.is_cancelled(), "HTTP runtime is stopping");
    // An initialized runtime does not need another blocking-pool admission.
    if inner.tls_executor.get().is_some() {
        return Ok(());
    }
    let observer = inner.clone();
    let inner = inner.clone();
    let resources = inner.resources.clone();
    let result = resources
        .metadata
        .run(move || {
            // This mutex protects only initialization ordering, not user data. It
            // is never acquired on an HTTP reactor. Recovering a poisoned unit
            // lock is safe: the success-only OnceLock remains authoritative.
            let _initializing = match inner.tls_executor_init.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    inner
                        .tls_executor_failure
                        .store(6, std::sync::atomic::Ordering::Release);
                    poisoned.into_inner()
                }
            };
            ensure!(!inner.stopped.is_cancelled(), "HTTP runtime is stopping");
            if inner.tls_executor.get().is_none() {
                inner
                    .tls_executor_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let created = match tls_executor::TlsExecutor::new() {
                    Ok(created) => created,
                    Err(error) => {
                        let code = tls_initialization_failure(&error);
                        inner
                            .tls_executor_failure
                            .store(code, std::sync::atomic::Ordering::Release);
                        anyhow::bail!(
                            "TLS executor initialization failed: {}",
                            tls_initialization_failure_name(code).unwrap_or("system")
                        );
                    }
                };
                // Only this serialized owned worker writes the cell. It publishes
                // even if its caller was cancelled, so shutdown can close and join
                // a late successful constructor after joining metadata work.
                inner.tls_executor.get_or_init(|| created);
            }
            let executor = inner
                .tls_executor
                .get()
                .ok_or_else(|| anyhow::anyhow!("TLS executor initialization state unavailable"))?;
            if inner.stopped.is_cancelled() {
                executor.close();
                anyhow::bail!("HTTP runtime is stopping");
            }
            Ok(())
        })
        .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            if observer.stopped.is_cancelled() {
                anyhow::bail!("HTTP runtime is stopping");
            }
            observer
                .tls_executor_failure
                .store(5, std::sync::atomic::Ordering::Release);
            anyhow::bail!("TLS executor initialization failed: worker-unavailable")
        }
    }
}
fn tls_initialization_failure(error: &std::io::Error) -> u8 {
    #[cfg(unix)]
    if error.raw_os_error().is_some_and(|code| {
        [libc::EAGAIN, libc::ENOMEM, libc::EMFILE, libc::ENFILE].contains(&code)
    }) {
        return 1;
    }
    match error.kind() {
        std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::OutOfMemory
        | std::io::ErrorKind::ResourceBusy => 1,
        std::io::ErrorKind::PermissionDenied => 2,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported => 3,
        _ => 4,
    }
}
fn tls_initialization_failure_name(code: u8) -> Option<&'static str> {
    match code {
        0 => None,
        1 => Some("resource-exhausted"),
        2 => Some("permission-denied"),
        3 => Some("unsupported-configuration"),
        4 => Some("system"),
        5 => Some("worker-unavailable"),
        6 => Some("initializer-poisoned"),
        _ => Some("system"),
    }
}

struct ServingMaterial<'a> {
    manual: Option<&'a ManualCertificates>,
    provider: Option<&'a Arc<dyn ScopedCertificateProvider>>,
    logging: Option<&'a Arc<crate::logging::Logging>>,
    validate_only: bool,
}

async fn prepare_servers(
    config: &PreparedConfig,
    registry: &ChallengeRegistry,
    managed: &Arc<HotCertificateResolver>,
    challenges: &Arc<HotCertificateResolver>,
    material: ServingMaterial<'_>,
    resources: &Arc<resource_budget::Resources>,
) -> Result<(HashMap<SocketAddr, Arc<ActiveServer>>, Vec<Vec<String>>)> {
    let ServingMaterial { manual, provider, logging, validate_only } = material;
    let logging_available = logging.is_some() || validate_only;
    let standalone;
    let manual = if let Some(manual) = manual {
        ensure!(
            config.certificates.is_empty(),
            "external manual inventory conflicts with raw TLS load_files"
        );
        manual
    } else {
        standalone = manual_certificates::load(config, registry, managed, resources).await?;
        &standalone
    };
    ensure!(
        Arc::ptr_eq(&manual.resolver.leaf_guard(), &managed.leaf_guard()),
        "manual inventory must share the runtime leaf guard"
    );
    let validation = manual.clone();
    resources
        .metadata
        .run(move || manual_certificates::validate(&validation))
        .await
        .map_err(|_| anyhow::anyhow!("manual inventory worker unavailable"))??;
    let mut actual_managed = std::collections::BTreeSet::new();
    let mut redirects = HashMap::<SocketAddr, Vec<Route>>::new();
    let mut output = HashMap::new();
    for server in &config.servers {
        // One generation owns one manual resolver. Tags are per-server
        // identity filters, not separate key/OCSP snapshots.
        let selected_manual = manual
            .certificates
            .iter()
            .filter(|certificate| {
                server.certificate_tags.is_empty()
                    || certificate
                        .tags
                        .iter()
                        .any(|tag| server.certificate_tags.contains(tag))
            })
            .collect::<Vec<_>>();
        ensure!(
            !server.tls || server.certificate_tags.is_empty() || !selected_manual.is_empty(),
            "TLS certificate tags matched no certificate"
        );
        let allowed_static = selected_manual
            .iter()
            .map(|certificate| certificate.identity)
            .collect::<std::collections::HashSet<_>>();
        let loaded_names = selected_manual
            .iter()
            .flat_map(|certificate| certificate.names.iter())
            .collect::<Vec<_>>();
        let managed_names = if server.manage_certificates && server.certificate_tags.is_empty() {
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
                challenges: challenges.clone(),
                static_certificates: manual.resolver.clone(),
                allowed_static,
                provider: if server.certificate_tags.is_empty() { provider.cloned() } else { None },
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
            proxy::prepare_clients(&client_plan.routes, &mut clients, logging_available)?;
            proxy::prepare_clients(&client_plan.errors, &mut clients, logging_available)?;
            Ok::<_, anyhow::Error>(clients)
        })
        .await
        .map_err(|_| anyhow::anyhow!("candidate proxy provisioning task failed"))??;
        let active = ActiveServer {
            logging: logging.cloned(),
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
                proxy::prepare_clients(&client_plan.routes, &mut clients, logging_available)?;
                proxy::prepare_clients(&client_plan.errors, &mut clients, logging_available)?;
                Ok::<_, anyhow::Error>(clients)
            })
            .await
            .map_err(|_| anyhow::anyhow!("candidate proxy provisioning task failed"))??;
            output.insert(
                address,
                Arc::new(ActiveServer {
                    logging: logging.cloned(),
                    plan,
                    tls: None,
                    resolver: None,
                    sessions: Arc::new(connection_sessions::SharedSessions::new()),
                    clients: Arc::new(clients),
                }),
            );
        } else {
            let plan = ServerConfig {
                access_logs: None,
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
                    logging: logging.cloned(),
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
fn proof_tls_config(challenges: Arc<HotCertificateResolver>) -> Result<Arc<rustls::ServerConfig>> {
    let mut tls = rustls::ServerConfig::builder_with_provider(crate::crypto::provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ProofResolver(challenges)));
    tls.alpn_protocols = vec![ACME_ALPN.to_vec()];
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    Ok(Arc::new(tls))
}
async fn accept_loop(
    inner: Arc<Inner>,
    socket: lifecycle::ListenerSocket,
    key: SocketAddr,
    cancel: CancellationToken,
    fallback: Arc<ArcSwap<ProofListener>>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = inner.stopped.cancelled() => break,
            result = socket.socket().accept() => result,
        };
        let Ok((stream, peer)) = accepted else {
            if cancel.is_cancelled() {
                break;
            }
            tokio::select! { biased;
                _ = cancel.cancelled() => break,
                _ = inner.stopped.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {},
            }
            continue;
        };
        // Proof/business mode is fixed at accept. A TLS ClientHello selects
        // from one current identity view; each HTTP operation later checks its
        // actual handshake identity against the current published policy.
        let server = inner
            .current
            .load()
            .business(&key)
            .map(|(server, _)| server);
        let canonical =
            |address: SocketAddr| SocketAddr::new(address.ip().to_canonical(), address.port());
        let peer = canonical(peer);
        let local = canonical(stream.local_addr().unwrap_or(key));
        let _ = stream.set_nodelay(true);
        let task_inner = inner.clone();
        let class=if server.is_some(){connection_budget::ConnectionClass::Classifying}else{connection_budget::ConnectionClass::Proof};
        let admission=tokio::select! {biased;
            _=cancel.cancelled()=>break,
            _=inner.stopped.cancelled()=>break,
            result=socket.admission.admit_with_pressure(class,&cancel)=>match result{Ok(admission)=>admission,Err(_)=>{drop(stream);continue;}},
        };
        let stream=connection_budget::AdmittedIo::new(stream,admission);
        let admission=stream.admission();
        let eviction=stream.eviction_token();
        if let Some(server) = server {
            spawn_admitted(&inner,eviction,async move {
                if server.tls.is_some() {
                    let deadline=tokio::time::Instant::now().checked_add(server.plan.read_header_timeout);
                    let Some(deadline)=deadline else { return; };
                    let handshake = connection_identity::accept(&task_inner, stream, key,Some(deadline));
                    let accepted = tokio::select! {
                        biased;
                        _ = task_inner.stopped.cancelled() => return,
                        result = handshake => match result {
                            Ok(accepted) => accepted,
                            Err(_) => return,
                        },
                    };
                    let negotiated_h2 = accepted.stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    let tls_details = fastcgi::TlsDetails::of(accepted.stream.get_ref().1);
                    let tls_log = Some(Arc::new(access_log::Tls::of(accepted.stream.get_ref().1)));

                    serve_connection(task_inner, TokioIo::new(accepted.stream), peer, local, ConnectionView {
                        key, server: accepted.server, admission,
                        negotiated_tls_h2: Some(negotiated_h2), identity: Some(accepted.identity), tls_log, tls_details: Some(tls_details),
                    }).await;
                } else {
                    serve_connection(task_inner, TokioIo::new(stream), peer, local, ConnectionView { key, server, admission, negotiated_tls_h2: None, identity: None, tls_log: None, tls_details: None }).await;
                }
            });
        } else {
            let proof = fallback.load_full();
            // A proof connection accepted before commit cannot turn into a
            // business connection after commit, even if it delays its headers.
            spawn_admitted(&inner,eviction,async move {
                if proof.cancel.is_cancelled() {
                    return;
                }
                if let Some(tls) = proof.tls.clone() {
                    let Some(executor)=task_inner.tls_executor.get() else { return; };
                    let handshake=executor.execute_proof(async move {
                        let stream=tokio_rustls::TlsAcceptor::from(tls).accept(stream).await?;
                        drop(stream);Ok(())
                    },proof.cancel.child_token(),None);
                    tokio::select! {
                        biased;
                        _ = proof.cancel.cancelled() => {},
                        _ = task_inner.stopped.cancelled() => {},
                        _ = handshake => {},
                    }
                    // ACME ALPN never speaks HTTP after its handshake.
                } else {
                    serve_proof_connection(task_inner, TokioIo::new(stream), proof.cancel.clone())
                        .await;
                }
            });
        }
    }
}
fn spawn_admitted(inner:&Arc<Inner>,eviction:CancellationToken,future:impl std::future::Future<Output=()>+Send+'static) {
    inner.tasks.spawn(async move {tokio::select!{biased;_=eviction.cancelled()=>{},_=future=>{}}});
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
    let mut builder = Builder::new(TokioExecutor::new()).http1_only();
    builder
        .http1()
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(None);
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = cancel.cancelled() => {},
        _ = inner.stopped.cancelled() => {},
    }
}
struct ConnectionView {
    admission:std::sync::Weak<connection_budget::Admission>,
    key: SocketAddr,
    server: Arc<ActiveServer>,
    negotiated_tls_h2: Option<bool>,
    tls_log: Option<Arc<access_log::Tls>>,
    tls_details: Option<fastcgi::TlsDetails>,
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
        tls_log,
        tls_details,
        identity,
        admission,
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
        let tls_log = tls_log.clone();
        let admission=admission.clone();
        async move {
            // Count admission before confirming that this exact view is still
            // current. A retire/join cannot observe zero and later miss a live
            // request admitted against a superseded snapshot.
            let mut view_retries = 0usize;
            let (current, business) = loop {
                let snapshot = inner.current.load_full();
                let Some((current, activity)) = snapshot.business(&key) else {
                    break (None, None);
                };
                let business = activity.begin();
                let latest = inner.current.load_full();
                let same = latest.business(&key).is_some_and(|(server, group)| {
                    Arc::ptr_eq(&activity, &group) && Arc::ptr_eq(&server, &current)
                });
                if !same {
                    drop(business);
                    view_retries += 1;
                    if view_retries == 8 {
                        view_retries = 0;
                        tokio::task::yield_now().await;
                    }
                    continue;
                }
                let Ok(business) = business else {
                    break (None, None);
                };
                break (Some(current), Some(business));
            };
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
            let Some(business) = business else {
                return Ok(simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service Unavailable\n",
                ));
            };
            // Pin this lookup once: an expired proof cannot later fall through
            // to business routes while still using the proof connection pool.
            let proof=request::proof_response(&inner.registry,&request).unwrap_or_default();
            let classified=if proof.is_some() {
                connection_budget::classify_proof(&admission,None).await
            }else{
                connection_budget::classify(&admission,connection_budget::ConnectionClass::Business)
            };
            if classified.is_err() {
                let mut response=simple(StatusCode::SERVICE_UNAVAILABLE,"Service Unavailable\n");
                if request.version()==http::Version::HTTP_2 { requested_drain.cancel(); }
                else {response.headers_mut().insert(http::header::CONNECTION,http::HeaderValue::from_static("close"));}
                return Ok(response);
            }
            let activity = business.generation().clone();
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
            if let Some(tls_log) = tls_log.filter(|_| current.plan.access_logs.is_some()) {
                request.extensions_mut().insert(tls_log);
            }
            if let Some(details)=tls_details {
                request.extensions_mut().insert(details);
            }
            let fault = metadata.fault.clone();
            if !metadata.is_empty() {
                request.extensions_mut().insert(metadata);
            }
            let keep = current.clone();
            let mut response = tokio::select! { biased;
                _ = activity.hard_stop.cancelled() => {
                    let mut response = simple(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable\n");
                    if !request_h2 { response.headers_mut().insert(http::header::CONNECTION,http::HeaderValue::from_static("close")); }
                    return Ok(response);
                },
                response = async {
                    if let Some(proof)=proof { proof }
                    else { request::handle_business(inner,current,request,peer,local,tls,business.clone()).await }
                } => response,
            };
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
                trailer_policy::guard_response(
                    RetainedBody {
                        body,
                        keep,
                        _business: business,
                        cancelled: Box::pin(activity.hard_stop.clone().cancelled_owned()),
                        ended: false,
                    }
                    .boxed_unsync(),
                    fault,
                )
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
    _business: Arc<BusinessGuard>,
    cancelled: std::pin::Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>,
    ended: bool,
}
impl hyper::body::Body for RetainedBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        let _keep = &self.keep;
        if self.ended {
            return std::task::Poll::Ready(None);
        }
        if std::future::Future::poll(self.cancelled.as_mut(), cx).is_ready() {
            self.ended = true;
            return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                "HTTP business generation stopped",
            )
            .into())));
        }
        let frame = std::pin::Pin::new(&mut self.body).poll_frame(cx);
        if matches!(frame, std::task::Poll::Ready(None | Some(Err(_)))) {
            self.ended = true;
        }
        frame
    }
    fn is_end_stream(&self) -> bool {
        self.ended || self.body.is_end_stream()
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
