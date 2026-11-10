//! Native application transactions. Request routing reads the HTTP generation;
//! this root snapshot owns only administrative identities and background jobs.
use crate::{
    admin::{
        self, AdaptedConfig, AdminBackend, AdminError, AdminFinisher, AdminFuture,
        AdminTransaction, CandidateOwner, CandidateScope, Committed, StopMode,
    },
    challenge::ChallengeRegistry,
    http_config,
    http_runtime::{CommitOutcome, HttpRuntime},
    leaf_guard::LeafGuard,
    local_pki::TrustInstaller,
    tls_app_config::{
        CertificatePaths, CertificatePlan, CertificateResources, CertificateServices,
        CertificateViews, PrepareContext, PrepareMode, RetainedCertificates,
    },
    tls_resolver::HotCertificateResolver,
};
use arc_swap::ArcSwapOption;
use futures_util::FutureExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const RUNNING: u8 = 0;
const STOPPING: u8 = 1;
const FORCED: u8 = 2;
const JOIN_BOUND: Duration = Duration::from_secs(30);
type ClientIdentity = Arc<dyn rustls::client::ResolvesClientCert>;
type StopReceiver = watch::Receiver<Option<Result<(), AdminError>>>;

pub struct RootOptions {
    pub paths: CertificatePaths,
    pub trust_installer: Option<Arc<dyn TrustInstaller>>,
}
#[derive(Clone)]
pub struct NativeBackend {
    inner: Arc<Root>,
}
struct Root {
    options: RootOptions,
    challenges: ChallengeRegistry,
    guard: Arc<LeafGuard>,
    resources: Arc<CertificateResources>,
    http: Arc<HttpRuntime>,
    serial: AsyncMutex<()>,
    active: ArcSwapOption<Active>,
    retained: Mutex<Option<Predecessor>>,
    phase: AtomicU8,
    cancel: CancellationToken,
    candidates: CancellationToken,
    stop_job: Mutex<Option<StopReceiver>>,
    cpu: Arc<Semaphore>,
    retirement_slots: Arc<Semaphore>,
    retirements: TaskTracker,
}
struct Active {
    generation: u64,
    digest: [u8; 32],
    services: Arc<CertificateServices>,
    client: Option<ClientIdentity>,
}
#[derive(Clone)]
struct Predecessor {
    digest: [u8; 32],
    material: RetainedCertificates,
}
struct Prepared {
    digest: [u8; 32],
    certificates: CertificatePlan,
    http: http_config::PreparedConfig,
    needs_client: bool,
}
fn failed(category: &'static str) -> AdminError {
    AdminError::new(400, category)
}
fn stopping() -> AdminError {
    AdminError::new(503, "backend_stopping")
}

impl NativeBackend {
    pub fn new(options: RootOptions) -> Result<Self, AdminError> {
        if !options.paths.cwd.is_absolute()
            || !options.paths.default_storage.is_absolute()
            || !options.paths.state_root.is_absolute()
        {
            return Err(failed("root_paths_must_be_absolute"));
        }
        let challenges = ChallengeRegistry::new();
        let guard =
            Arc::new(LeafGuard::new(65_536).map_err(|_| failed("root_leaf_budget_invalid"))?);
        let resolver = Arc::new(HotCertificateResolver::with_leaf_guard(
            challenges.clone(),
            guard.clone(),
        ));
        let http = Arc::new(HttpRuntime::new(challenges.clone(), resolver));
        let resources = Arc::new(
            CertificateResources::new()
                .map_err(|_| failed("root_certificate_resources_invalid"))?,
        );
        Ok(Self {
            inner: Arc::new(Root {
                options,
                challenges,
                guard,
                resources,
                http,
                serial: AsyncMutex::new(()),
                active: ArcSwapOption::empty(),
                retained: Mutex::new(None),
                phase: AtomicU8::new(RUNNING),
                cancel: CancellationToken::new(),
                candidates: CancellationToken::new(),
                stop_job: Mutex::new(None),
                cpu: Arc::new(Semaphore::new(16)),
                retirement_slots: Arc::new(Semaphore::new(8)),
                retirements: TaskTracker::new(),
            }),
        })
    }
    /// Provision a runtime configuration without binding, activating apps or
    /// obtaining administrative/business identities. The caller supplies the
    /// metadata-free runtime value, just as configuration publication does.
    pub async fn validate_configuration(&self, raw: Value) -> Result<(), AdminError> {
        let root = self.inner.clone();
        let _serial = tokio::select! {biased;_=root.candidates.cancelled()=>return Err(stopping()),lock=root.serial.lock()=>lock};
        if root.phase.load(Ordering::Acquire) != RUNNING {
            return Err(stopping());
        }
        let prepared = root.offload(move || prepare(raw)).await?;
        let resolver = Arc::new(HotCertificateResolver::with_leaf_guard(
            root.challenges.clone(),
            root.guard.clone(),
        ));
        let token = root.cancel.child_token();
        let services = CertificateServices::new(
            prepared.certificates,
            PrepareContext {
                paths: root.options.paths.clone(),
                resources: root.resources.clone(),
                challenges: root.challenges.clone(),
                leaf_guard: root.guard.clone(),
                resolver,
                cancel: token.clone(),
                configuration_digest: prepared.digest,
                trust_installer: None,
                listener_provider: None,
            },
            PrepareMode::Normal,
        )
        .map_err(|_| failed("certificate_service_preparation_failed"))?;
        let mut cleanup = CandidateCleanup {
            root: root.clone(),
            services: services.clone(),
            token,
            slot: None,
            armed: true,
            publication_started: false,
        };
        let result = async {
            services
                .prepare(root.candidates.child_token())
                .await
                .map_err(|_| failed("certificate_storage_preparation_failed"))?;
            let manual = services
                .manual_certificates()
                .map_err(|_| failed("manual_certificate_inventory_failed"))?;
            let names = root
                .http
                .prepared_managed_names_with_certificates(
                    &prepared.http,
                    &services.business_resolver(),
                    &manual,
                )
                .await
                .map_err(|_| failed("http_candidate_provisioning_failed"))?;
            // These are declared addresses for dormant solver planning only;
            // no listener capability is acquired. Port zero has no actual bind.
            let bound = prepared
                .http
                .servers
                .iter()
                .flat_map(|server| {
                    server
                        .listen
                        .iter()
                        .filter(|a| a.port() != 0)
                        .map(|address| crate::http_runtime::StagedAddress {
                            declared: *address,
                            actual: *address,
                            reused: false,
                            http01: !server.tls,
                            tls_alpn01: server.tls,
                        })
                })
                .collect::<Vec<_>>();
            services
                .ensure_business(&names, &bound, root.candidates.child_token())
                .await
                .map_err(|_| failed("business_certificate_preparation_failed"))?;
            Ok(())
        }
        .await;
        cleanup.token.cancel();
        let closed = services
            .shutdown()
            .await
            .map_err(|_| AdminError::new(503, "validation_shutdown_incomplete"));
        cleanup.armed = false;
        result.and(closed)
    }
    pub async fn bound_addresses(&self) -> Vec<std::net::SocketAddr> {
        self.inner.http.bound_addresses().await
    }
}
impl Root {
    fn force(&self) {
        self.phase.store(FORCED, Ordering::Release);
        self.candidates.cancel();
        self.cancel.cancel();
        self.http.force_shutdown();
    }
    async fn offload<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, AdminError> + Send + 'static,
    ) -> Result<T, AdminError> {
        let permit = tokio::select! { biased; _=self.candidates.cancelled()=>return Err(stopping()),
        p=self.cpu.clone().acquire_owned()=>p.map_err(|_| stopping())? };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|_| AdminError::new(500, "root_preparation_worker_failed"))?
    }
    async fn transact(
        self: Arc<Self>,
        transaction: AdminTransaction,
        finish: AdminFinisher,
    ) -> Result<Committed, AdminError> {
        let _serial = tokio::select! { biased; _=self.candidates.cancelled()=>return Err(stopping()), lock=self.serial.lock()=>lock };
        if self.phase.load(Ordering::Acquire) != RUNNING {
            return Err(stopping());
        }
        let previous = self.active.load_full();
        let generation = previous.as_ref().map_or(0, |a| a.generation);
        if transaction
            .expected_generation
            .is_some_and(|expected| expected != generation)
        {
            return Err(AdminError::new(409, "backend_generation_fenced"));
        }
        let prepared = self.offload(move || prepare(transaction.config)).await?;
        let mode = if transaction.restore_only {
            let old = self
                .retained
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .filter(|old| old.digest == prepared.digest)
                .ok_or_else(|| failed("retained_configuration_unavailable"))?;
            PrepareMode::RestoreOnly {
                retained: old.material,
            }
        } else {
            PrepareMode::Normal
        };
        // Bound retirement ownership before starting another candidate. Existing
        // request/renewal workers do not acquire this transaction admission slot.
        let slot = tokio::select! { biased; _=self.candidates.cancelled()=>return Err(stopping()),
        p=self.retirement_slots.clone().acquire_owned()=>p.map_err(|_|stopping())? };
        let resolver = Arc::new(HotCertificateResolver::with_leaf_guard(
            self.challenges.clone(),
            self.guard.clone(),
        ));
        let token = self.cancel.child_token();
        let services = CertificateServices::new(
            prepared.certificates,
            PrepareContext {
                paths: self.options.paths.clone(),
                resources: self.resources.clone(),
                challenges: self.challenges.clone(),
                leaf_guard: self.guard.clone(),
                resolver,
                cancel: token.clone(),
                configuration_digest: prepared.digest,
                trust_installer: self.options.trust_installer.clone(),
                listener_provider: Some(self.http.challenge_listener_provider()),
            },
            mode,
        )
        .map_err(|_| failed("certificate_service_preparation_failed"))?;
        let mut cleanup = CandidateCleanup {
            root: self.clone(),
            services: services.clone(),
            token,
            slot: Some(slot),
            armed: true,
            publication_started: false,
        };
        let result = async {
            services
                .prepare(self.candidates.child_token())
                .await
                .map_err(|_| failed("certificate_storage_preparation_failed"))?;
            let manual = services
                .manual_certificates()
                .map_err(|_| failed("manual_certificate_inventory_failed"))?;
            let stage = self
                .http
                .stage_with_certificates(prepared.http, services.business_resolver(), manual)
                .await
                .map_err(|_| failed("http_candidate_staging_failed"))?;
            services
                .ensure_business(
                    &stage.managed_names(),
                    &stage.bound_addresses(),
                    self.candidates.child_token(),
                )
                .await
                .map_err(|_| failed("business_certificate_preparation_failed"))?;
            let client = Arc::new(Mutex::new(None));
            if prepared.needs_client {
                let identity = services
                    .identity_client(self.candidates.child_token())
                    .await
                    .map_err(|_| failed("admin_client_identity_unavailable"))?;
                *client.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);
            }
            let owner = CandidateOwner::new(Arc::new(Scope {
                services: services.clone(),
                client: client.clone(),
                cancel: self.candidates.child_token(),
                retirement: stage.retirement(),
            }));
            let retained = match &previous {
                Some(previous) => Some(Predecessor {
                    digest: previous.digest,
                    material: previous.services.retained().await.map_err(|_| {
                        AdminError::new(500, "predecessor_certificate_snapshot_failed")
                    })?,
                }),
                None => None,
            };
            let finished = finish(owner.handle()).await;
            drop(owner);
            finished?;
            let next = Arc::new(Active {
                generation: generation
                    .checked_add(1)
                    .ok_or_else(|| AdminError::new(500, "root_generation_exhausted"))?,
                digest: prepared.digest,
                services: services.clone(),
                client: client.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            });
            if self.phase.load(Ordering::Acquire) != RUNNING || self.cancel.is_cancelled() {
                return Err(stopping());
            }
            let retirement = stage.retirement();
            cleanup.publication_started = true;
            let CommitOutcome::Published { generation } = stage.commit() else {
                return Err(AdminError::new(503, "backend_commit_discarded"));
            };
            // No await, fallible allocation or external call follows publication.
            if next.generation != generation {
                return Err(AdminError::new(500, "root_generation_mismatch"));
            }
            let retired = self.active.swap(Some(next));
            *self.retained.lock().unwrap_or_else(|e| e.into_inner()) = retained;
            services.activate();
            cleanup.armed = false;
            if let Some(retired) = retired {
                let slot = cleanup.slot.take();
                let root = Arc::downgrade(&self);
                self.retirements.spawn(async move {
                    let _slot = slot;
                    if !matches!(
                        retirement.acceptance_closed().await,
                        Ok(crate::http_runtime::RetirementOutcome::AcceptanceClosed
                            | crate::http_runtime::RetirementOutcome::Forced)
                    ) && let Some(root) = root.upgrade()
                    {
                        root.force();
                    }
                    if retired.services.shutdown().await.is_err() {
                        eprintln!(
                            "root event=retirement_failed category=certificate_shutdown_failed"
                        );
                    }
                });
            }
            Ok(Committed {
                generation,
                stop_pending: self.phase.load(Ordering::Acquire) != RUNNING,
            })
        }
        .await;
        if result.is_err() {
            if cleanup.publication_started {
                self.force();
            }
            cleanup.token.cancel();
            if services.shutdown().await.is_err() {
                eprintln!(
                    "root event=candidate_cleanup_failed category=certificate_shutdown_failed"
                );
            }
            cleanup.armed = false;
        }
        if result.is_err() && cleanup.publication_started {
            Err(AdminError::new(503, "backend_runtime_halted"))
        } else {
            result
        }
    }
}

impl AdminBackend for NativeBackend {
    fn check_available(&self) -> Result<(), AdminError> {
        if self.inner.phase.load(Ordering::Acquire) == FORCED {
            Err(AdminError::new(503, "backend_runtime_halted"))
        } else {
            Ok(())
        }
    }
    fn transact(
        &self,
        transaction: AdminTransaction,
        finish: AdminFinisher,
    ) -> AdminFuture<Committed> {
        Box::pin(self.inner.clone().transact(transaction, finish))
    }
    fn adapt(
        &self,
        input: Vec<u8>,
        adapter: Option<String>,
        filename: Option<String>,
    ) -> AdminFuture<AdaptedConfig> {
        let root = self.inner.clone();
        let cwd = root.options.paths.cwd.clone();
        Box::pin(async move {
            root.offload(move||{
            match adapter.as_deref() {
                None|Some("json") => Ok(AdaptedConfig {result:crate::admin_json::decoded(&input)
                    .map_err(|_|failed("invalid_json_configuration"))?,warnings:Vec::new()}),
                Some("caddyfile") => {
                    let mut options=crate::caddyfile_parser::ParseOptions::capture().map_err(|_|failed("caddyfile_environment_unavailable"))?; options.cwd=cwd;
                    let adapted=crate::caddyfile_adapter::adapt(&options,&input,filename.as_deref().unwrap_or("Caddyfile"))
                        .map_err(|_|failed("caddyfile_adaptation_failed"))?;
                    Ok(AdaptedConfig {result:adapted.config,warnings:adapted.warnings.into_iter().map(|warning|
                        json!({"file":warning.file,"line":warning.line,"directive":warning.directive,"message":warning.message})).collect()})
                }
                _=>Err(failed("unsupported_configuration_adapter")),
            }
        }).await
        })
    }
    fn active_identity_client(&self) -> Option<ClientIdentity> {
        if self.inner.phase.load(Ordering::Acquire) != RUNNING {
            return None;
        }
        self.inner
            .active
            .load()
            .as_ref()
            .and_then(|active| active.client.clone())
    }
    fn stop(&self, mode: StopMode) -> AdminFuture<()> {
        let bound = match mode {
            StopMode::Force => JOIN_BOUND,
            StopMode::Graceful(bound) => bound,
        };
        self.stop_with_wait(mode, Some(bound))
    }
    fn stop_unbounded(&self) -> AdminFuture<()> {
        self.stop_with_wait(StopMode::Graceful(Duration::MAX), None)
    }
}

impl NativeBackend {
    fn stop_with_wait(&self, mode: StopMode, deadline: Option<Duration>) -> AdminFuture<()> {
        let root = self.inner.clone();
        match mode {
            StopMode::Force => root.force(),
            StopMode::Graceful(_) => {
                let _ = root.phase.compare_exchange(
                    RUNNING,
                    STOPPING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                root.candidates.cancel();
            }
        }
        // Fencing is synchronous; aborting a caller cannot drop cleanup ownership.
        let receiver = tokio::runtime::Handle::try_current()
            .ok()
            .map(|_| root.start_stop());
        Box::pin(async move {
            let mut receiver = match receiver {
                Some(result) => result?,
                None => root.start_stop()?,
            };
            let wait = async move {
                loop {
                    if let Some(result) = *receiver.borrow_and_update() {
                        return result;
                    }
                    receiver
                        .changed()
                        .await
                        .map_err(|_| AdminError::new(503, "root_shutdown_worker_unavailable"))?;
                }
            };
            match deadline {
                Some(bound) => tokio::time::timeout(bound, wait)
                    .await
                    .map_err(|_| AdminError::new(503, "root_shutdown_deadline_elapsed"))?,
                None => wait.await,
            }
        })
    }
}
struct StopGuard(Option<Arc<Root>>);
impl Drop for StopGuard {
    fn drop(&mut self) {
        if let Some(root) = self.0.take() {
            root.force();
        }
    }
}
impl Root {
    fn start_stop(self: &Arc<Self>) -> Result<StopReceiver, AdminError> {
        let mut slot = self.stop_job.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(receiver) = slot.as_ref() {
            return Ok(receiver.clone());
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| AdminError::new(503, "root_shutdown_runtime_unavailable"))?;
        let (sender, receiver) = watch::channel(None);
        *slot = Some(receiver.clone());
        let root = self.clone();
        // Guard exists before spawn, including if the spawned future is unpolled.
        let guard = StopGuard(Some(root.clone()));
        runtime.spawn(async move {
            let mut guard = guard;
            let result = std::panic::AssertUnwindSafe(root.drain_owned())
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(AdminError::new(503, "root_shutdown_worker_failed")));
            if result.is_ok() {
                let _ = guard.0.take();
            }
            sender.send_replace(Some(result));
        });
        Ok(receiver)
    }
    async fn drain_owned(self: &Arc<Self>) -> Result<(), AdminError> {
        let _serial = self.serial.lock().await;
        self.cpu.close();
        self.retirement_slots.close();
        let receipt = self
            .http
            .begin_shutdown()
            .map_err(|_| AdminError::new(503, "http_shutdown_start_failed"))?;
        let active = self.active.swap(None);
        self.retained
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.retirements.close();
        let http = self.http.shutdown_wait(None);
        let certificates = async {
            receipt
                .acceptance_closed()
                .await
                .map_err(|_| AdminError::new(503, "http_retirement_incomplete"))?;
            // Renewals and solver leases stay live through shutdown_delay.
            self.cancel.cancel();
            let result = if let Some(active) = active {
                active
                    .services
                    .shutdown()
                    .await
                    .map_err(|_| AdminError::new(503, "certificate_shutdown_incomplete"))
            } else {
                Ok(())
            };
            self.retirements.wait().await;
            result
        };
        let (http, certificates) = tokio::join!(http, certificates);
        http.map_err(|_| AdminError::new(503, "http_shutdown_incomplete"))?;
        certificates
    }
}

struct CandidateCleanup {
    root: Arc<Root>,
    services: Arc<CertificateServices>,
    token: CancellationToken,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
    armed: bool,
    publication_started: bool,
}
impl Drop for CandidateCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.token.cancel();
        if self.publication_started {
            self.root.force();
        }
        let services = self.services.clone();
        let slot = self.slot.take();
        if tokio::runtime::Handle::try_current().is_ok() {
            self.root.retirements.spawn(async move {
                let _slot = slot;
                let _ = services.shutdown().await;
            });
        }
    }
}
struct Scope {
    services: Arc<CertificateServices>,
    client: Arc<Mutex<Option<ClientIdentity>>>,
    cancel: CancellationToken,
    retirement: crate::http_runtime::HttpRetirement,
}
impl CandidateScope for Scope {
    fn publication_completion(&self) -> AdminFuture<()> {
        let receipt = self.retirement.clone();
        Box::pin(async move {
            match receipt.acceptance_closed().await {
                Ok(crate::http_runtime::RetirementOutcome::AcceptanceClosed) => Ok(()),
                Ok(crate::http_runtime::RetirementOutcome::Forced) => Err(stopping()),
                _ => Err(AdminError::new(503, "http_publication_completion_failed")),
            }
        })
    }
    fn identity(&self) -> AdminFuture<Arc<dyn rustls::server::ResolvesServerCert>> {
        let services = self.services.clone();
        let cancel = self.cancel.child_token();
        Box::pin(async move {
            services
                .identity(cancel)
                .await
                .map_err(|_| failed("admin_server_identity_unavailable"))
        })
    }
    fn identity_client(&self) -> AdminFuture<ClientIdentity> {
        let services = self.services.clone();
        let cancel = self.cancel.child_token();
        let slot = self.client.clone();
        Box::pin(async move {
            let identity = services
                .identity_client(cancel)
                .await
                .map_err(|_| failed("admin_client_identity_unavailable"))?;
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity.clone());
            Ok(identity)
        })
    }
    fn cancellation(&self) -> CancellationToken {
        self.cancel.child_token()
    }
}

fn prepare(raw: Value) -> Result<Prepared, AdminError> {
    let empty = json!({});
    let root = if raw.is_null() { &empty } else { &raw };
    let object = root
        .as_object()
        .ok_or_else(|| failed("configuration_must_be_object_or_null"))?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "admin" | "apps" | "storage" | "logging"))
    {
        return Err(failed("unknown_root_configuration_field"));
    }
    admin::validate(root)?;
    if root.get("logging").is_some_and(|v| !v.is_null()) {
        return Err(failed("logging_app_integration_pending"));
    }
    let apps = root.get("apps").filter(|v| !v.is_null());
    if apps.is_some_and(|v| {
        v.as_object().is_none_or(|o| {
            o.keys()
                .any(|key| !matches!(key.as_str(), "http" | "tls" | "pki"))
        })
    }) {
        return Err(failed("unsupported_application_module"));
    }
    let certificates = CertificatePlan::parse(CertificateViews {
        storage: root.get("storage"),
        tls: apps.and_then(|a| a.get("tls")),
        pki: apps.and_then(|a| a.get("pki")),
        identity: root.get("admin").and_then(|a| a.get("identity")),
    })
    .map_err(|_| failed("invalid_certificate_application"))?;
    let http = apps
        .and_then(|a| a.get("http"))
        .filter(|v| !v.is_null())
        .cloned()
        .unwrap_or_else(|| json!({"servers":{}}));
    let http = http_config::validate_json(&json!({"apps":{"http":http}}))
        .map_err(|_| failed("invalid_http_application"))?;
    let digest = Sha256::digest(
        crate::admin_json::encoded(&raw).map_err(|_| failed("invalid_configuration_encoding"))?,
    )
    .into();
    Ok(Prepared {
        digest,
        certificates,
        http,
        needs_client: admin::client_identity_required(root)?,
    })
}
