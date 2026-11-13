//! Native HTTP listeners with request-scoped configuration snapshots. Preparation is
//! isolated from publication; failed binds and certificate loads preserve the
//! active generation. This module never starts a Go process.
#[path = "http_runtime/connection_budget.rs"]
mod connection_budget;
#[path="http_runtime/push.rs"]
mod push;
#[path="http_runtime/path_match.rs"]
pub(crate) mod path_match;
#[path = "http_runtime/descriptor_budget.rs"]
mod descriptor_budget;
#[path = "http_runtime/pressure.rs"]
mod pressure;
pub use connection_budget::{ConnectionDiagnostics, ConnectionLimits, ConnectionPoolSnapshot};
#[path = "http_runtime/auth_cache.rs"]
pub(crate) mod auth_cache;
#[path="http_runtime/auth_hash.rs"]
pub(crate) mod auth_hash;
#[path = "http_runtime/certificate_provider.rs"]
mod certificate_provider;
pub use certificate_provider::{AcquiredCertificate, CertificateRequest, ScopedCertificateProvider};
pub(crate) use certificate_provider::{WarmSelection, CertificateHello, TransientCertificate};
#[path = "http_runtime/browse.rs"]
pub(crate) mod browse;
#[path = "http_runtime/connection_identity.rs"]
mod connection_identity;
#[path = "http_runtime/connection_snapshot.rs"]
mod connection_snapshot;
pub(crate) mod pkix_name;
pub(crate) mod client_cert_facts;
#[path = "http_runtime/cel_native_cert.rs"]
mod cel_native_cert;
mod cel_native_string;
mod cel_native_map;
mod cel_native_format;
mod cel_native_collections;
#[path="http_runtime/tls_events.rs"]
mod tls_events;
pub use tls_events::{ClientHello as EventClientHello,HelloFields as EventClientHelloFields,Address as EventAddress,Transport as EventTransport};
pub use connection_snapshot::{ConnectionSnapshot, ConnectionMetadata, ConnectionSnapshotError, ConnectionExporter};
#[path = "http_runtime/connection_sessions.rs"]
mod connection_sessions;
#[path = "http_runtime/file_match.rs"]
mod file_match;
#[path = "http_runtime/file_preconditions.rs"]
mod file_preconditions;
#[path = "http_runtime/file_sidecars.rs"]
pub(crate) mod file_sidecars;
#[path = "http_runtime/files.rs"]
mod files;
#[path = "http_runtime/http_redirect.rs"]
mod http_redirect;
#[path = "http_runtime/automatic_redirects.rs"]
mod automatic_redirects;
#[path = "http_runtime/tls_first_record.rs"]
mod tls_first_record;

#[path = "http_runtime/fastcgi/mod.rs"]
mod fastcgi;

#[path = "http_runtime/access_log.rs"]
mod access_log;
#[path = "http_runtime/tls_executor.rs"]
mod tls_executor;
use connection_identity::{TlsIdentity, TlsVerdict};
pub use tls_executor::TlsHandshakeDiagnostics;
mod h3;
#[path = "http_runtime/lifecycle.rs"]
mod lifecycle;
#[path = "http_runtime/manual_certificates.rs"]
mod manual_certificates;
#[path="http_runtime/ssl_capture.rs"]
mod ssl_capture;
mod tls_policies;
#[path="http_runtime/tls_cbc.rs"]
mod tls_cbc;
mod certificate_choice;
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
#[path = "http_runtime/proxy_buffer.rs"]
mod proxy_buffer;
#[path = "http_runtime/proxy_cleanup.rs"]
mod proxy_cleanup;
mod proxy_dns_addrselect;
mod proxy_dns_dial;
mod proxy_dns_exchange;
#[path = "http_runtime/proxy_dns_runtime.rs"]
mod proxy_dns_runtime;
mod proxy_dns_socket;
mod proxy_dns_stream;
pub(crate) mod acme_dns;
#[path = "http_runtime/proxy_dynamic.rs"]
mod proxy_dynamic;
#[path = "http_runtime/proxy_flush.rs"]
mod proxy_flush;
#[path = "http_runtime/proxy_health.rs"]
mod proxy_health;
#[path = "http_runtime/proxy_health_probe.rs"]
mod proxy_health_probe;
#[path = "http_runtime/proxy_hosts.rs"]
mod proxy_hosts;
#[path = "http_runtime/proxy_policy.rs"]
pub(crate) mod proxy_policy;
#[path = "http_runtime/proxy_replay.rs"]
mod proxy_replay;
#[path = "http_runtime/proxy_retry.rs"]
mod proxy_retry;
#[path = "http_runtime/request_body.rs"]
mod request_body;
#[path = "http_runtime/retirement.rs"]
mod retirement;
use retirement::{BusinessGeneration, BusinessGuard};
pub use retirement::{HttpRetirement, RetirementOutcome, RetirementDrainOutcome};
#[path = "http_runtime/resource_budget.rs"]
pub(crate) mod resource_budget;
pub use resource_budget::{BudgetSnapshot, ResourceDiagnostics, ResourceLimits};
#[path = "http_runtime/accepted_encodings.rs"]
pub(crate) mod accepted_encodings;
#[path = "http_runtime/encode_body.rs"]
pub(crate) mod encode_body;
#[path = "http_runtime/query_match.rs"]
mod query_match;
#[path = "http_runtime/request.rs"]
mod request;
#[path = "http_runtime/read_deadline.rs"]
mod read_deadline;
#[path = "http_runtime/route_timeouts.rs"]
mod route_timeouts;
#[path="http_runtime/response_length.rs"]
mod response_length;
#[path="http_runtime/templates.rs"]
pub(crate) mod templates;
#[path = "http_runtime/request_regex.rs"]
mod request_regex;
#[path = "http_runtime/response_matcher.rs"]
mod response_matcher;
#[path = "http_runtime/url_pattern.rs"]
pub(crate) mod url_pattern;
pub use encode_body::CompressionDiagnostics;
#[path = "http_runtime/encode_response.rs"]
pub(crate) mod encode_response;
#[path = "http_runtime/gzip_codec.rs"]
mod gzip_codec;
#[path = "http_runtime/incremental.rs"]
mod incremental;
#[path = "http_runtime/zstd_codec.rs"]
mod zstd_codec;

pub(crate) mod listener_stack;
mod http_dial;
mod http_dial_io;
#[path = "http_runtime/rewrite_uri.rs"]
mod rewrite_uri;
mod rewrite_ops;
mod rewrite_runtime;
#[path = "http_runtime/sniff.rs"]
mod sniff;
#[path = "http_runtime/timeout_io.rs"]
pub(crate) mod timeout_io;
#[path = "http_runtime/trailer_policy.rs"]
mod trailer_policy;
#[path = "http_runtime/upstream_tls.rs"]
mod upstream_tls;
pub(crate) use upstream_tls::{ca_source_client_tls,ca_source_prepared_tls};
pub(crate) mod metrics_client;
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
    pub fn metrics_registry(&self)->Arc<crate::metrics::Registry>{self.inner.current.load().metrics.clone()}
    pub fn metrics_process(&self)->Arc<crate::metrics::Process>{self.inner.metrics_process.clone()}

    /// Process-level native CA load and skipped-root counts, without material.
    pub fn native_upstream_trust_diagnostics(&self) -> NativeTrustDiagnostics {
        upstream_tls::diagnostics()
    }
    /// Process-wide count of trailer values excluded by the proxy policy.
    /// Header values and per-user labels are never retained in this counter.
    pub fn filtered_trailer_values(&self) -> u64 {
        trailer_policy::filtered_values()
    }
    /// Informational heads excluded by bounded per-request response budgets.
    /// Values and per-client labels are not retained.
    pub fn suppressed_informational_responses(&self) -> u64 {
        request::suppressed_informational()
    }
    /// Process-wide later request trailer values omitted by the pinned clone
    /// policy; separate from forbidden response trailer value diagnostics.
    pub fn dropped_request_trailer_values(&self) -> u64 {
        trailer_policy::dropped_request_values()
    }
}
struct Inner {
    metrics_process: Arc<crate::metrics::Process>,
    connections: Arc<connection_budget::Budgets>,
    tls_executor: std::sync::OnceLock<tls_executor::TlsExecutor>,
    tls_executor_init: std::sync::Mutex<()>,
    tls_executor_failure: std::sync::atomic::AtomicU8,
    tls_executor_attempts: std::sync::atomic::AtomicU64,
    current: ArcSwap<Generation>,
    quic_limits: h3::Limits,
    registry: ChallengeRegistry,
    managed: Arc<HotCertificateResolver>,
    challenge_resolver: Arc<HotCertificateResolver>,
    tasks: TaskTracker,
    upgrades: TaskTracker,
    resources: Arc<resource_budget::Resources>,
    stopped: CancellationToken,
}
struct Generation {
    tracing: Option<Arc<crate::metrics::distributed_trace::provider::Provider>>,
    metrics: Arc<crate::metrics::Registry>,
    id: u64,
    proxy_cleanup: Option<proxy_cleanup::Reservation>,
    activity: Arc<BusinessGeneration>,
    servers: HashMap<SocketAddr, Arc<ActiveServer>>,
    quic: HashMap<SocketAddr, h3::Listener>,
    retiring: HashMap<SocketAddr, std::sync::Weak<lifecycle::RetiringBinding>>,
    drain: CancellationToken,
    managed_names: Vec<Vec<String>>,
}
impl Generation {
    fn business(&self, key: &SocketAddr) -> Option<(Arc<ActiveServer>, Arc<BusinessGeneration>)> {
        if let Some(server) = self.servers.get(key) {
            return self
                .activity
                .is_admitting()
                .then(|| (server.clone(), self.activity.clone()));
        }
        let binding = self.retiring.get(key)?.upgrade()?;
        binding
            .is_accepting()
            .then(|| (binding.server.clone(), binding.activity.clone()))
    }
}
#[derive(Clone)]
struct ActiveServer {
    tracing: Option<Arc<crate::metrics::distributed_trace::provider::Provider>>,
    acme_servers:Arc<HashMap<usize,Arc<crate::acme_server::Controller>>>,
    metrics: Arc<crate::metrics::Registry>,
    events: Option<Arc<crate::events::EventsApp>>,
    logging: Option<Arc<crate::logging::Logging>>,
    plan: Arc<ServerConfig>,
    tls: Option<Arc<rustls::ServerConfig>>,
    resolver: Option<Arc<CandidateResolver>>,
    tls_policies: Vec<Arc<tls_policies::PreparedPolicy>>,
    policy_identity: [u8; 32],
    tickets: crate::stek::TicketRuntime,
    clients: Arc<HashMap<usize, proxy::ProxyClient>>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum CertificateOrigin {
    Manual,
    Managed,
    Proof,
}
struct CandidateResolver {
    challenges: Arc<HotCertificateResolver>,
    static_certificates: Arc<HotCertificateResolver>,
    managed: Arc<HotCertificateResolver>,
    allowed_managed: std::collections::HashSet<String>,
    allowed_static: std::collections::HashSet<[u8; 32]>,
    certificate_selection: Option<Arc<crate::tls_policy::certificate_selection::CertificateFilter>>,
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
impl HttpRuntime {
    pub fn new(registry: ChallengeRegistry, resolver: Arc<HotCertificateResolver>) -> Self {
        Self::from_resources(
            registry,
            resolver,
            Arc::new(resource_budget::Resources::automatic()),
            connection_budget::Budgets::new(ConnectionLimits::automatic())
                .expect("valid automatic connection budgets"),
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
        Self::with_limits(registry, resolver, limits, ConnectionLimits::automatic())
    }
    /// Native admission options do not add or ignore Caddy JSON fields.
    pub fn with_connection_limits(
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        limits: ConnectionLimits,
    ) -> Result<Self> {
        Self::with_limits(registry, resolver, ResourceLimits::automatic(), limits)
    }
    pub fn with_limits(
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        resources: ResourceLimits,
        connections: ConnectionLimits,
    ) -> Result<Self> {
        let resources = Arc::new(resource_budget::Resources::from_limits(resources)?);
        let connections = connection_budget::Budgets::new(connections)?;
        Ok(Self::from_resources(
            registry,
            resolver,
            resources,
            connections,
        ))
    }
    /// Independent-pool diagnostics; not one atomic cross-pool snapshot.
    pub fn connection_diagnostics(&self) -> ConnectionDiagnostics {
        self.inner.connections.snapshot()
    }
    fn from_resources(
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        resources: Arc<resource_budget::Resources>,
        connections: Arc<connection_budget::Budgets>,
    ) -> Self {
        let activity =
            BusinessGeneration::new(0, crate::http_config::HttpShutdownPolicy::default());
        let metrics_process=crate::metrics::Process::new();
        let initial = Generation {
            tracing: None,
            metrics: crate::metrics::Registry::initial(metrics_process.clone()),
            id: 0,
            proxy_cleanup: None,
            activity: activity.clone(),
            servers: HashMap::new(),
            quic: HashMap::new(),
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
                metrics_process,
                current: ArcSwap::from_pointee(initial),
                quic_limits: h3::Limits::new(),
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
    pub(crate) async fn upstream_statuses(&self) -> Result<Vec<crate::admin::UpstreamStatus>> {
        let hosts=self.inner.resources.proxy_hosts.clone();
        let generation=self.inner.current.load_full();
        self.inner.resources.proxy_selection.run(move || {
            let mut configured=std::collections::HashSet::new();
            for server in generation.servers.values() {
                for client in server.clients.values() {
                    for upstream in &client.config.upstreams {
                        let address=upstream.dial.as_str();
                        if !configured.contains(address) {
                            anyhow::ensure!(configured.len()<65536,"configured upstream status capacity exceeded");
                            configured.try_reserve(1)?;configured.insert(address);
                        }
                    }
                }
            }
            hosts.statuses(&configured)
        }).await
            .map_err(|_|anyhow::anyhow!("upstream snapshot worker unavailable"))?
    }
    /// CPU-adaptive HTTP work admission; snapshots contain counts only.
    pub fn resource_diagnostics(&self) -> ResourceDiagnostics {
        self.inner.resources.snapshot()
    }
    /// Counts describe live handshake running/waiting lanes. CPU work executes
    /// on the separate all-available-CPU runtime; this snapshot is not atomic
    /// across pools and does not include pre-ClientHello socket admission.
    pub fn tls_handshake_diagnostics(&self) -> Option<TlsHandshakeDiagnostics> {
        self.inner
            .tls_executor
            .get()
            .map(tls_executor::TlsExecutor::diagnostics)
    }
    /// Last safe failure category; retained after a successful retry.
    pub fn last_tls_executor_initialization_failure(&self) -> Option<&'static str> {
        tls_initialization_failure_name(
            self.inner
                .tls_executor_failure
                .load(std::sync::atomic::Ordering::Acquire),
        )
    }
    /// Number of actual constructor attempts, excluding already initialized reads.
    pub fn tls_executor_initialization_attempts(&self) -> u64 {
        self.inner
            .tls_executor_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
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
    tickets: Option<&'a crate::stek::TicketRuntime>,
    validate_only: bool,
}

async fn prepare_servers(
    config: &PreparedConfig,
    process: &Arc<crate::metrics::Process>,
    registry: &ChallengeRegistry,
    managed: &Arc<HotCertificateResolver>,
    challenges: &Arc<HotCertificateResolver>,
    material: ServingMaterial<'_>,
    resources: &Arc<resource_budget::Resources>,
) -> Result<(HashMap<SocketAddr, Arc<ActiveServer>>, Vec<Vec<String>>, Arc<crate::metrics::Registry>, Option<Arc<crate::metrics::distributed_trace::provider::Provider>>)> {
    let ServingMaterial {
        manual,
        provider,
        logging,
        tickets,
        validate_only,
    } = material;
    let logging_available = logging.is_some() || validate_only;
    let mut allowed=crate::metrics::allowed::Inputs::default();
    if config.metrics.is_some_and(|c|c.per_host&&!c.observe_catchall_hosts){
        for server in &config.servers{for route in &server.routes{for group in &route.matchers{for matcher in group{if let Matcher::Host(hosts)=matcher{for host in hosts{if !host.contains(['*','{']){allowed.push(host,process);tokio::task::consume_budget().await;}}}}}}}
    }
    let process=process.clone();let metrics_config=config.metrics;let https=config.servers.iter().any(|s|s.tls);let trace_required=tracing::needed(config);
    let (metrics,tracing)=resources.metadata.run(move||{
        let allowed=allowed.build(&process);let metrics=crate::metrics::Registry::prepare(process.clone(),metrics_config,allowed,https)?;
        let tracing=if trace_required{Some(crate::metrics::distributed_trace::provider::Provider::prepare(process)?)}else{None};
        Ok::<_,anyhow::Error>((metrics,tracing))
    }).await.map_err(|_|anyhow::anyhow!("observability provisioning worker unavailable"))??;
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
    let mut retained_client_auth_bytes = 0usize;
    let mut actual_managed = std::collections::BTreeSet::new();
    let mut redirect_domains = automatic_redirects::Domains::default();
    let mut output = HashMap::new();
    resources.proxy_hosts.prune();
    for server in &config.servers {
        // One generation owns one manual resolver. Tags are per-server
        // identity filters, not separate key/OCSP snapshots.
        let loaded_names = manual
            .certificates
            .iter()
            .flat_map(|certificate| certificate.names.iter())
            .collect::<Vec<_>>();
        let managed_names = if server.manage_certificates
        {
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
            redirect_domains.record(&names, &server.listen, config.https_port);
        }

        let policies = tls_policies::prepare(
            server,
            tls_policies::Sources {
                manual,
                managed,
                challenges,
                provider,
                managed_names: &managed_names,
            },
            resources,
            &mut retained_client_auth_bytes,
        )
        .await?;
        let policy_identity = tls_policies::set_identity(&policies);
        let tls = policies.first().map(|policy| policy.tls.clone());
        let resolver = policies.first().map(|policy| policy.resolver.clone());
        let client_plan = server.clone();
        let proxy_hosts = resources.proxy_hosts.clone();
        let proxy_dns = resources.proxy_dns.clone();
        let ssl_verify=resources.ssl_verify.clone();
        let clients = tokio::task::spawn_blocking(move || {
            let mut clients = HashMap::new();
            proxy::prepare_clients(
                &client_plan.routes,
                &mut clients,
                &proxy_hosts,
                &proxy_dns,
                logging_available,
                &ssl_verify,
            )?;
            proxy::prepare_clients(
                &client_plan.errors,
                &mut clients,
                &proxy_hosts,
                &proxy_dns,
                logging_available,
                &ssl_verify,
            )?;
            for route in client_plan.named_routes.values() {
                proxy::prepare_clients(
                    std::slice::from_ref(route),
                    &mut clients,
                    &proxy_hosts,
                    &proxy_dns,
                    logging_available,
                &ssl_verify,
                )?;
            }
            Ok::<_, anyhow::Error>(clients)
        })
        .await
        .map_err(|_| anyhow::anyhow!("candidate proxy provisioning task failed"))??;
        for client in clients.values(){metrics.upstreams(client.metric_probes());}
        let active = ActiveServer {
            tracing: tracing.clone(),
            acme_servers:prepare_acme_handlers(server,provider,validate_only).await?,
            metrics: metrics.clone(),
            events: config.events.clone(),
            logging: logging.cloned(),
            plan: server.clone(),
            tls,
            resolver,
            tls_policies: policies,
            policy_identity,
            tickets: tickets.cloned().unwrap_or_default(),
            clients: Arc::new(clients),
        };
        for addr in &server.listen {
            output.insert(*addr, Arc::new(active.clone()));
        }
    }
    for (address, mut routes) in redirect_domains.routes(config.http_port, config.https_port) {
        if let Some(existing) = output.get(&address).cloned() {
            ensure!(
                !existing.plan.tls,
                "automatic redirect listener conflicts with TLS"
            );
            let mut plan = (*existing.plan).clone();
            // Automatic named redirects belong after the last explicit Host
            // route. Without newly managed names, an existing HTTP catch-all
            // keeps precedence (including manually loaded TLS certificates).
            if actual_managed.iter().any(|name| !name.ends_with(".ts.net")
                || config.explicit_tls_subjects.contains(name)) {
                let split = plan.routes.iter().rposition(|route| route.matchers.iter().flatten()
                    .any(|matcher| matches!(matcher, Matcher::Host(_))))
                    .map_or(0, |index| index + 1);
                plan.routes.splice(split..split, routes);
            }
            plan.routes.push(automatic_redirects::fallback(config.http_port, config.https_port));
            let plan = Arc::new(plan);
            let client_plan = plan.clone();
            let proxy_hosts = resources.proxy_hosts.clone();
            let proxy_dns = resources.proxy_dns.clone();
        let ssl_verify=resources.ssl_verify.clone();
            let clients = tokio::task::spawn_blocking(move || {
                let mut clients = HashMap::new();
                proxy::prepare_clients(
                    &client_plan.routes,
                    &mut clients,
                    &proxy_hosts,
                    &proxy_dns,
                    logging_available,
                &ssl_verify,
                )?;
                proxy::prepare_clients(
                    &client_plan.errors,
                    &mut clients,
                    &proxy_hosts,
                    &proxy_dns,
                    logging_available,
                &ssl_verify,
                )?;
                for route in client_plan.named_routes.values() {
                    proxy::prepare_clients(
                        std::slice::from_ref(route),
                        &mut clients,
                        &proxy_hosts,
                        &proxy_dns,
                        logging_available,
                &ssl_verify,
                    )?;
                }
                Ok::<_, anyhow::Error>(clients)
            })
            .await
            .map_err(|_| anyhow::anyhow!("candidate proxy provisioning task failed"))??;
            output.insert(
                address,
                Arc::new(ActiveServer {
                    tracing: tracing.clone(),
                    acme_servers:existing.acme_servers.clone(),
                    metrics: metrics.clone(),
                    events: config.events.clone(),
                    logging: logging.cloned(),
                    plan,
                    tls: None,
                    resolver: None,
                    tls_policies: Vec::new(),
                    policy_identity: [0; 32],
                    tickets: crate::stek::TicketRuntime::RuntimeDefault,
                    clients: Arc::new(clients),
                }),
            );
        } else {
            routes.push(automatic_redirects::fallback(config.http_port, config.https_port));
            let plan = ServerConfig {
                name: Arc::from("remaining_auto_https_redirects"),
                access_logs: None,
                named_routes: Default::default(),
                header_aliases: Default::default(),
                listen: vec![address],
                routes,
                errors: Vec::new(),
                tls: false,
                redirect_before_tls: None,
                redirect_after_tls: None,
                strict_sni_host: false,
                tls_policies: Vec::new(),
                trusted_proxies: Vec::new(),
                trusted_strict: false,
                client_ip_headers: vec!["X-Forwarded-For".into()],
                read_header_timeout: Some(Duration::from_secs(60)),
                listener_stack:Arc::new(listener_stack::Stack::default()),
                read_idle_timeout: Duration::from_secs(60),
                transfers: crate::http_config::server_transfers::ServerTransfers::default(),
                idle_timeout: Some(Duration::from_secs(300)),
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
                    tracing: tracing.clone(),
                    metrics: metrics.clone(),
                    events: config.events.clone(),
                    logging: logging.cloned(),
                    plan: Arc::new(plan),
                    acme_servers:Arc::new(HashMap::new()),
                    tls: None,
                    resolver: None,
                    tls_policies: Vec::new(),
                    policy_identity: [0; 32],
                    tickets: crate::stek::TicketRuntime::RuntimeDefault,
                    clients: Arc::new(HashMap::new()),
                }),
            );
        }
    }
    Ok((
        output,
        actual_managed.into_iter().map(|n| vec![n]).collect(),
        metrics,
        tracing,
    ))
}
fn plain_transport_compatible(old: &ServerConfig, next: &ServerConfig) -> bool {
    !old.tls
        && !next.tls
        && old.protocols == next.protocols
        && old.listener_stack==next.listener_stack
        && old.request_head_limit() == next.request_head_limit()
}
async fn prepare_acme_handlers(server:&ServerConfig,provider:Option<&Arc<dyn ScopedCertificateProvider>>,validate_only:bool)
    ->Result<Arc<HashMap<usize,Arc<crate::acme_server::Controller>>>> {
    let mut pending=Vec::new();pending.extend(server.routes.iter());pending.extend(server.errors.iter());pending.extend(server.named_routes.values());
    let mut output=HashMap::new();
    while let Some(route)=pending.pop() {
        for handler in &route.handlers {match handler {
            Handler::AcmeServer(config)=>{
                // Provision-only HTTP name planning deliberately has no
                // provider. CertificateServices checks references beforehand.
                if validate_only {continue;}
                let provider=provider.ok_or_else(||anyhow::anyhow!("ACME server requires a generation signing capability"))?;
                provider.validate_acme_server(config)?;
                let identity=Arc::as_ptr(config)as usize;
                if !output.contains_key(&identity) {
                    output.insert(identity,provider.prepare_acme_server(config.clone(),CancellationToken::new()).await?);
                }
            }
            Handler::Subroute{routes,errors,..}=>{pending.extend(routes.iter());pending.extend(errors.iter());}
            Handler::Intercept(responses)=>for response in responses {if let Some(routes)=&response.routes {pending.extend(routes.iter());}},
            Handler::ReverseProxy(proxy)=>for response in &proxy.response_routes {if let Some(routes)=&response.routes {pending.extend(routes.iter());}},
            _=>{}
        }}
    }Ok(Arc::new(output))
}
fn dns_covers(pattern: &str, name: &str) -> bool {
    if pattern.eq_ignore_ascii_case(name) {
        return true;
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return false;
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
    let names = crate::tls_resolver::certificate_san_names(&cert)?;
    ensure!(
        !names.is_empty(),
        "TLS certificate has no usable DNS or IP SAN"
    );
    Ok(names)
}
/// A newly bound candidate socket can prove ownership before publication, but
/// never exposes the candidate routes. Mode is fixed when a connection accepts.
#[derive(Clone)]
struct ProofListener {
    listener_stack:Arc<listener_stack::Stack>,
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
            .map(|(server, _)| server)
            .filter(|server| h3::tcp_enabled(server));
        let canonical =
            |address: SocketAddr| SocketAddr::new(address.ip().to_canonical(), address.port());
        let peer = canonical(peer);
        let local = canonical(stream.local_addr().unwrap_or(key));
        let _ = stream.set_nodelay(true);
        let task_inner = inner.clone();
        let class = if server.is_some() {
            connection_budget::ConnectionClass::Classifying
        } else {
            connection_budget::ConnectionClass::Proof
        };
        let admission = tokio::select! {biased;
            _=cancel.cancelled()=>break,
            _=inner.stopped.cancelled()=>break,
            result=socket.admission.admit_with_pressure(class,&cancel)=>match result{Ok(admission)=>admission,Err(_)=>{drop(stream);continue;}},
        };
        let stream = connection_budget::AdmittedIo::new(stream, admission);
        let admission = stream.admission();
        let eviction = stream.eviction_token();
        if let Some(server) = server {
            spawn_admitted(&inner, eviction, Some((cancel.clone(), admission.clone())), async move {
                let (mut peer,mut local)=(crate::net_address::NetAddress::from(peer),crate::net_address::NetAddress::from(local));
                let accepted_listener_stack=server.plan.listener_stack.clone();
                let deadline = match server.plan.request_head_limit() {
                    Some(timeout) => match tokio::time::Instant::now().checked_add(timeout) {
                        Some(deadline) => Some(deadline),
                        None => return,
                    },
                    None => None,
                };
                let stream = match listener_stack::prepare(
                    stream,&accepted_listener_stack.before,&mut peer,&mut local,deadline,
                    task_inner.stopped.child_token(),
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                if server.tls.is_some() {
                    let handshake = connection_identity::accept(
                        &task_inner,
                        stream,
                        admission.clone(),
                        key,
                        deadline,
                        server.plan.redirect_after_tls.is_none(),
                        (peer.clone(), local.clone()),
                    );
                    let accepted = tokio::select! {
                        biased;
                        _ = task_inner.stopped.cancelled() => return,
                        result = handshake => match result {
                            Ok(accepted) => accepted,
                            Err(_) => return,
                        },
                    };
                    let metadata=match accepted.snapshot.metadata(){Ok(m)=>m,Err(_)=>return};
                    let negotiated_h2=metadata.alpn.as_ref()==b"h2";
                    let tls_details=fastcgi::TlsDetails::from_metadata(metadata);
                    let tls_log=Some(Arc::new(access_log::Tls::from_metadata(metadata)));

                    let deadline = match server.plan.request_head_limit() {
                        Some(timeout) => match tokio::time::Instant::now().checked_add(timeout) {
                            Some(deadline) => Some(deadline),
                            None => return,
                        },
                        None => None,
                    };
                    let stream = match listener_stack::prepare(
                        accepted.stream,&accepted_listener_stack.after,&mut peer,&mut local,deadline,
                        task_inner.stopped.child_token(),
                    )
                    .await
                    {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    serve_connection(
                        task_inner,
                        TokioIo::new(stream),
                        peer.into(),
                        local.into(),
                        ConnectionView {
                            listener_stack:accepted_listener_stack,
                            key,
                            server: accepted.server,
                            admission,
                            negotiated_tls_h2: Some(negotiated_h2),
                            identity: Some(accepted.identity),
                            tls_snapshot: Some(accepted.snapshot),
                            tls_log,
                            tls_details: Some(tls_details),
                        },
                    )
                    .await;
                } else {
                    let stream = match listener_stack::prepare(
                        stream,&accepted_listener_stack.after,&mut peer,&mut local,deadline,
                        task_inner.stopped.child_token(),
                    )
                    .await
                    {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    serve_connection(
                        task_inner,
                        TokioIo::new(stream),
                        peer.into(),
                        local.into(),
                        ConnectionView {
                            listener_stack:accepted_listener_stack,
                            key,
                            server,
                            admission,
                            negotiated_tls_h2: None,
                            identity: None,
                            tls_log: None,
                            tls_snapshot: None,
                            tls_details: None,
                        },
                    )
                    .await;
                }
            });
        } else {
            let proof = fallback.load_full();
            // A proof connection accepted before commit cannot turn into a
            // business connection after commit, even if it delays its headers.
            spawn_admitted(&inner, eviction, None, async move {
                if proof.cancel.is_cancelled() {
                    return;
                }
                let (mut peer,mut local)=(crate::net_address::NetAddress::from(peer),crate::net_address::NetAddress::from(local));
                let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
                let stream=match listener_stack::prepare(stream,&proof.listener_stack.before,&mut peer,&mut local,Some(deadline),proof.cancel.child_token()).await{
                    Ok(stream)=>stream,Err(_)=>return,
                };
                if let Some(tls) = proof.tls.clone() {
                    // Prefix classification is I/O, not TLS CPU work. The dedicated
                    // proof listener has no server read_header_timeout to inherit.
                    const PROOF_TLS_PREFIX_TIMEOUT: Duration = Duration::from_secs(10);
                    let stream = tokio::select! { biased;
                        _ = proof.cancel.cancelled() => return,
                        _ = task_inner.stopped.cancelled() => return,
                        result = tokio::time::timeout(PROOF_TLS_PREFIX_TIMEOUT, tls_first_record::prepare(stream, false)) => {
                            match result { Ok(Ok(stream)) => stream, _ => return }
                        }
                    };
                    let handshake=connection_identity::accept_proof(&task_inner,stream,tls,(peer.into(),local.into()),proof.cancel.child_token());
                    tokio::select! {
                        biased;
                        _ = proof.cancel.cancelled() => {},
                        _ = task_inner.stopped.cancelled() => {},
                        _ = handshake => {},
                    }
                    // ACME ALPN never speaks HTTP after its handshake.
                } else {
                    let stream=match listener_stack::prepare(stream,&proof.listener_stack.after,&mut peer,&mut local,Some(deadline),proof.cancel.child_token()).await{
                        Ok(stream)=>stream,Err(_)=>return,
                    };
                    serve_proof_connection(task_inner, TokioIo::new(stream), proof.cancel.clone()).await;
                }
            });
        }
    }
}
fn spawn_admitted(
    inner: &Arc<Inner>,
    eviction: CancellationToken,
    removed_listener: Option<(CancellationToken, std::sync::Weak<connection_budget::Admission>)>,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) {
    inner.tasks.spawn(async move {
        let removed = async move {
            if let Some((removed, admission)) = removed_listener {
                removed.cancelled().await;
                if let Some(admission) = admission.upgrade() {
                    admission.cancel_before_service();
                }
            }
            std::future::pending::<()>().await
        };
        tokio::select! {biased;_=eviction.cancelled()=>{},_=removed=>{},_=future=>{}}
    });
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
    listener_stack:Arc<listener_stack::Stack>,
    admission: std::sync::Weak<connection_budget::Admission>,
    key: SocketAddr,
    server: Arc<ActiveServer>,
    negotiated_tls_h2: Option<bool>,
    tls_log: Option<Arc<access_log::Tls>>,
    tls_snapshot: Option<Arc<ConnectionSnapshot>>,
    tls_details: Option<fastcgi::TlsDetails>,
    identity: Option<Arc<TlsIdentity>>,
}
async fn serve_connection<I>(
    inner: Arc<Inner>,
    io: I,
    peer: crate::net_address::NetAddress,
    local: crate::net_address::NetAddress,
    view: ConnectionView,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let ConnectionView {
        listener_stack,
        key,
        server,
        negotiated_tls_h2,
        tls_log,
        tls_snapshot,
        tls_details,
        identity,
        admission,
    } = view;
    let client_cert_cache = tls_snapshot.as_ref().map(|snapshot| client_cert_facts::Cache::new(snapshot.clone()));
    let tls = negotiated_tls_h2.is_some();
    let svc_inner = inner.clone();
    let svc_server = server.clone();
    let requested_drain = CancellationToken::new();
    let service_drain = requested_drain.clone();
    let push_pool=inner.resources.transfer_deadlines.clone();
    let service = service_fn(move |mut request: Request<Incoming>| {
        let service_entered = admission.upgrade().is_some_and(|owner| owner.enter_service());
        let inner = svc_inner.clone();
        let accepted_server = svc_server.clone();
        let identity = identity.clone();
        let requested_drain = service_drain.clone();
        let tls_log = tls_log.clone();
        let tls_snapshot = tls_snapshot.clone();
        let client_cert_cache = client_cert_cache.clone();
        let peer=peer.clone();let local=local.clone();let listener_stack=listener_stack.clone();
        let admission = admission.clone();
        async move {
            if !service_entered {
                return Err(h2::Error::from(h2::Reason::CANCEL));
            }
            // Count admission before confirming that this exact view is still
            // current. A retire/join cannot observe zero and later miss a live
            // request admitted against a superseded snapshot.
            let mut view_retries = 0usize;
            let (current, business, alt_svc) = loop {
                let snapshot = inner.current.load_full();
                let Some((current, activity)) = snapshot.business(&key) else {
                    break (None, None, None);
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
                    break (None, None, None);
                };
                let alt_svc = tls
                    .then(|| snapshot.quic.get(&key))
                    .flatten()
                    .map(|entry| entry.binding.advertisement.clone());
                break (Some(current), Some(business), alt_svc);
            };
            let verdict = if current.as_ref().is_some_and(|current|current.plan.listener_stack!=listener_stack){TlsVerdict::Reject}else{match (identity.as_ref(), current.as_ref()) {
                (Some(identity), Some(current)) => {
                    identity.verdict(current, negotiated_tls_h2 == Some(true))
                }
                (None, Some(current))
                    if plain_transport_compatible(&accepted_server.plan, &current.plan) =>
                {
                    TlsVerdict::Serve
                }
                _ => TlsVerdict::Reject,
            }};
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
            let proof = request::proof_response(&inner.registry, &request).unwrap_or_default();
            let classified = if proof.is_some() {
                connection_budget::classify_proof(&admission, None).await
            } else {
                connection_budget::classify(
                    &admission,
                    connection_budget::ConnectionClass::Business,
                )
            };
            if classified.is_err() {
                let mut response = simple(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable\n");
                if request.version() == http::Version::HTTP_2 {
                    requested_drain.cancel();
                } else {
                    response.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                return Ok(response);
            }
            let activity = business.generation().clone();
            let close_after = verdict == TlsVerdict::ServeThenClose
                || current.plan.request_head_limit() != accepted_server.plan.request_head_limit()
                || current.plan.idle_timeout != accepted_server.plan.idle_timeout;
            let request_h2 = request.version() == http::Version::HTTP_2;
            if !crate::go_url_compat::valid_path_escapes(request.uri().path().as_bytes()){
                if request_h2{return Err(h2::Error::from(h2::Reason::PROTOCOL_ERROR))}
                let mut response=simple(StatusCode::BAD_REQUEST,"Bad Request\n");response.headers_mut().insert(http::header::CONNECTION,http::HeaderValue::from_static("close"));return Ok(response);
            }
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
            if let Some(cache) = client_cert_cache { request.extensions_mut().insert(cache); }
            if let Some(snapshot) = tls_snapshot {
                request.extensions_mut().insert(snapshot);
            }
            if let Some(details) = tls_details {
                request.extensions_mut().insert(details);
            }
            if let Some(alt_svc) = alt_svc {
                request.extensions_mut().insert(alt_svc);
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
                    else {
                        let mut request=request;
                        let informational=hyper::ext::InformationalSender::take(&mut request).map(request::InformationalOutput::Http);
                        request::handle_business(inner,current,request,request::RequestOrigin { peer, local, tls, sni: identity.as_deref().map(TlsIdentity::server_name) },business.clone(),informational).await
                    }
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
    // A negotiated H2 connection has the protocol's 10s preface window;
    // ReadHeaderTimeout is an HTTP/1 head deadline, not an H2 idle deadline.
    let protocol_timeout = if negotiated_tls_h2 == Some(true) {
        Some(Duration::from_secs(10))
    } else { server.plan.request_head_limit() };
    if let Some(timeout) = protocol_timeout {
        builder.protocol_read_timeout(timeout, TokioTimer::new());
    }
    // The original HTTP/2 sender queues informational headers separately
    // from DATA flow control. Limit their aggregate per request/stream.
    if push::configured(&server.plan){builder.http2().server_push(8,32,push_pool);}
    builder.http2().enable_connect_protocol().native_plain_connect_body(true).timer(TokioTimer::new()).idle_timeout(server.plan.idle_timeout).informational_responses(
        request::MAX_INFORMATIONAL_HEADS,
        request::MAX_INFORMATIONAL_BYTES,
    );
    builder
        .http1()
        .informational_responses(
            request::MAX_INFORMATIONAL_HEADS,
            request::MAX_INFORMATIONAL_BYTES,
        )
        .allow_undeclared_trailers(true)
        .max_trailer_size(4096)
        .allow_obsolete_multiline_trailers(true)
        .timer(TokioTimer::new())
        .header_read_timeout(server.plan.request_head_limit())
        .idle_timeout(server.plan.idle_timeout);
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

#[path = "http_runtime/cel_matcher.rs"]
pub(crate) mod cel_matcher;
#[path = "http_runtime/cel_body.rs"]
mod cel_body;


#[path = "http_runtime/placeholder_value.rs"]
pub(crate) mod placeholder_value;


#[path = "http_runtime/proxy_nss.rs"]
mod proxy_nss;

#[path = "http_runtime/proxy_dns_unix.rs"]
mod proxy_dns_unix;

#[path = "http_runtime/proxy_dns_search.rs"]
mod proxy_dns_search;

#[path = "http_runtime/proxy_dns_ip.rs"]
mod proxy_dns_ip;
#[cfg(target_vendor = "apple")]
mod proxy_dns_native;

#[path = "http_runtime/proxy_dns_file.rs"]
mod proxy_dns_file;

#[path="http_runtime/handler_trace.rs"]
pub(crate) mod handler_trace;

#[path="http_runtime/tracing.rs"]
mod tracing;

#[path="http_runtime/headers_replace.rs"]
mod headers_replace;
