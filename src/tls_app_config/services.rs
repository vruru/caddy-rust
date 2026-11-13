use super::{
    CertificatePlan,
    material::Material,
    model::{Issuer, PermissionSetting, Policy},
    storage::{CertificatePaths, CertificateResources, Store},
};
#[cfg(feature = "native-run")]
use crate::stek::{Provider as TicketProvider, TicketMode, TicketRuntime};
use crate::{
    cert_automation::{self, AutomationOptions, CertificateManager},
    cert_status::{OcspConfig, OcspManager, OcspOptions, OcspState},
    certstore::{CertificateBundle, names_key},
    challenge::ChallengeRegistry,
    http_runtime::{ChallengeListenerProvider, StagedAddress},
    leaf_guard::LeafGuard,
    local_pki::{InternalIssuerOptions, LocalPki, TrustInstaller},
    tls_resolver::{
        CertificateInput, CertificateResidency, CertificateScope, HotCertificateResolver,
        ManualCertificateInfo, ManualCertificates, ScopedCertificate,
    },
};
use anyhow::{Result, anyhow, ensure};
use futures_util::{StreamExt, stream};
use serde_json::json;
use std::{
    collections::HashMap,
    future::Future,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex as AsyncMutex, OnceCell, broadcast, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
#[path = "services/ca_pools.rs"]
mod ca_pools;
#[path = "services/ca_consumers.rs"]
mod ca_consumers;
#[path = "services/storage_pools.rs"]
mod storage_pools;
#[path = "services/http_pools.rs"]
mod http_pools;
#[path = "services/capacity.rs"]
mod capacity;
#[path = "services/group.rs"]
mod group;
#[path = "services/external.rs"]
mod external;
#[path = "services/identity.rs"]
mod identity;
#[path = "services/maintenance.rs"]
mod maintenance;
#[path = "services/ocsp_scope.rs"]
mod ocsp_scope;
use ocsp_scope::OcspScope;
#[path = "services/physical_ocsp.rs"]
mod physical_ocsp;
use physical_ocsp::physical_ocsp_key;
#[path = "services/on_demand.rs"]
mod on_demand;
#[path = "services/solver.rs"]
mod solver;

pub struct PrepareContext {
    pub events: Option<Arc<crate::events::EventsApp>>,
    pub paths: CertificatePaths,
    pub resources: Arc<CertificateResources>,
    pub challenges: ChallengeRegistry,
    pub leaf_guard: Arc<LeafGuard>,
    pub resolver: Arc<HotCertificateResolver>,
    pub cancel: CancellationToken,
    pub configuration_digest: [u8; 32],
    /// Root explicitly supplies this only when host trust installation is allowed.
    pub trust_installer: Option<Arc<dyn TrustInstaller>>,
    pub listener_provider: Option<Arc<dyn ChallengeListenerProvider>>,
}

/// Opaque, in-memory rollback capability; never constructible from JSON.
#[derive(Clone)]
pub struct RetainedCertificates {
    digest: [u8; 32],
    material: Vec<RetainedMaterial>,
    permission: Option<PermissionSetting>,
    business_names: Vec<Vec<String>>,
    on_demand_names: Vec<(Vec<String>, String)>,
    capacity_displaced: std::collections::HashSet<Vec<String>>,
}
#[derive(Clone)]
struct RetainedMaterial {
    material: Arc<Material>,
    identity: bool,
    managed_names: Option<Vec<String>>,
    renew_at: i64,
    ari_after: i64,
    origin: String,
}
pub enum PrepareMode {
    Normal,
    RestoreOnly { retained: RetainedCertificates },
}

#[derive(Clone, Debug)]
pub struct CertificateEvent {
    pub kind: &'static str,
    pub names: Vec<String>,
}
enum GroupIssuer {
    Acme(CertificateManager),
    Internal {
        pki: LocalPki,
        ca: String,
        options: InternalIssuerOptions,
    },
}
struct Group {
    key: String,
    names: Vec<String>,
    origin: String,
    policy: Policy,
    store: Arc<Store>,
    resolver: Arc<HotCertificateResolver>,
    issuer: GroupIssuer,
    identity: bool,
    gate: AsyncMutex<()>,
    solver: Option<Arc<solver::SolverBroker>>,
    leaf_state: Mutex<Option<Arc<crate::leaf_guard::LeafState>>>,
    spki: Mutex<Option<Arc<[u8]>>>,
    scope: CertificateScope,
    residency: Mutex<Option<ResidencyBinding>>,
    publication: Arc<Mutex<Option<ScopedCertificate>>>,
    renew_at: AtomicI64,
    ari_after: AtomicI64,
    background: AtomicBool,
    restoring: AtomicBool,
    cache_event_emitted: AtomicBool,
    cancel: CancellationToken,
    tasks: TaskTracker,
    started: Mutex<bool>,
    _admission: tokio::sync::OwnedSemaphorePermit,
}
#[derive(Clone)]
struct ResidencyBinding {
    slot: Arc<CertificateResidency>,
    source: Option<Arc<CertificateResidency>>,
    receipt: Option<super::resident_cache::Receipt>,
}
#[derive(Clone)]
struct RenewalTarget {
    material: Arc<Material>,
    receipt: ScopedCertificate,
    binding: ResidencyBinding,
    leaf: Arc<crate::leaf_guard::LeafState>,
    selection: Option<crate::http_runtime::WarmSelection>,
}
#[derive(Clone)]
enum PublishIntent {
    Insert,
    Renew { old: super::resident_cache::Receipt },
    ReplaceTarget { old: super::resident_cache::Receipt, binding: ResidencyBinding,
        selection: Option<crate::http_runtime::WarmSelection> },
    WarmInsert { selection: Option<crate::http_runtime::WarmSelection> },
}
impl ResidencyBinding {
    fn local() -> Self {
        Self {
            slot: Arc::new(CertificateResidency::default()),
            source: None,
            receipt: None,
        }
    }
    fn shared(entry: &super::resident_cache::CacheEntry) -> Self {
        Self {
            slot: Arc::new(entry.revision.projection()),
            source: Some(entry.slot.clone()),
            receipt: Some(entry.receipt()),
        }
    }
    fn projects(&self, source: &super::resident_cache::CacheEntry) -> bool {
        self.source
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, &source.slot))
            && self.receipt
                .as_ref()
                .is_some_and(|r| r.is(source))
    }
    fn superseded(&self) -> bool {
        !self.slot.live()
            && self.source
                .as_ref()
                .is_some_and(|s| s.live())
            && self.receipt
                .as_ref()
                .map(|r| !r.revision.live())
                .unwrap_or(false)
    }
    fn occupies(&self) -> bool {
        self.slot.live() || self.superseded()
    }
}
struct State {
    material: Vec<RetainedMaterial>,
    groups: HashMap<String, Arc<Group>>,
    pki: HashMap<String, LocalPki>,
    ocsp: HashMap<String, OcspScope>,
    bound: Option<Vec<StagedAddress>>,
    planned: Option<Vec<Vec<String>>>,
    ensured: Option<Vec<Vec<String>>>,
}

pub struct CertificateServices {
    ssl_verify:Arc<native_ssl_tls::VerificationScope>,
    plan: CertificatePlan,
    context: PrepareContext,
    restore: Option<RetainedCertificates>,
    identity_resolver: Arc<HotCertificateResolver>,
    manual_resolver: Arc<HotCertificateResolver>,
    manual_inventory: arc_swap::ArcSwap<ManualCertificates>,
    identity_client: Arc<identity::IdentityClient>,
    identity_ready: OnceCell<()>,
    prepared: OnceCell<()>,
    ensure_gate: AsyncMutex<()>,
    staged_publication: AsyncMutex<()>,
    state: AsyncMutex<State>,
    tasks: TaskTracker,
    // True closes every task-admission path before cancellation wakes callers.
    admission: Mutex<bool>,
    activate: Mutex<Option<oneshot::Sender<()>>>,
    events: broadcast::Sender<CertificateEvent>,
    maintenance_changed: Arc<tokio::sync::Notify>,
    on_demand: Arc<on_demand::OnDemand>,
    permission: OnceCell<Option<Arc<super::permission::HttpPermission>>>,
    group_slots: Arc<tokio::sync::Semaphore>,
    cache_epoch: OnceCell<Arc<super::resident_cache::Epoch>>,
    effective_tls: AtomicBool,
    implicit_tailscale: std::sync::OnceLock<std::collections::HashSet<String>>,
}

impl CertificateServices {
    /// Pure construction; the only spawned task sleeps until an explicit commit.
    /// Keep this handle until preparation is aborted or its generation is stopped.
    pub fn new(
        plan: CertificatePlan,
        context: PrepareContext,
        mode: PrepareMode,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(&context.leaf_guard, &context.resolver.leaf_guard()),
            "certificate resolver does not share the root leaf guard"
        );
        ensure!(
            context.paths.cwd.is_absolute()
                && context.paths.default_storage.is_absolute()
                && context.paths.state_root.is_absolute(),
            "certificate paths must be absolute"
        );
        let restore = match mode {
            PrepareMode::Normal => None,
            PrepareMode::RestoreOnly { retained } => {
                ensure!(
                    retained.digest == context.configuration_digest,
                    "retained certificate configuration differs"
                );
                Some(retained)
            }
        };
        let identity_resolver = Arc::new(HotCertificateResolver::with_managed_leaf_guard(
            context.challenges.clone(),
            context.leaf_guard.clone(),
        ));
        let manual_resolver = Arc::new(HotCertificateResolver::with_leaf_guard(
            context.challenges.clone(),
            context.leaf_guard.clone(),
        ));
        let manual_inventory = arc_swap::ArcSwap::from_pointee(ManualCertificates {
            resolver: manual_resolver.clone(),
            certificates: Arc::new(Vec::new()),
        });
        let (events, _) = broadcast::channel(256);
        let (activate, committed) = oneshot::channel();
        let tasks = TaskTracker::new();
        let cancel = context.cancel.clone();
        let cache_receiver = context.resources.resident_cache.subscribe();
        let on_demand = Arc::new(on_demand::OnDemand::new(cache_receiver,
            context.leaf_guard.key_deny().clone()));
        let this = Arc::new(Self {
            ssl_verify:native_ssl_tls::VerificationScope::new(),
            plan,
            context,
            restore,
            identity_resolver,
            manual_resolver,
            manual_inventory,
            identity_client: Arc::new(identity::IdentityClient::new()),
            identity_ready: OnceCell::new(),
            prepared: OnceCell::new(),
            ensure_gate: AsyncMutex::new(()),
            staged_publication: AsyncMutex::new(()),
            state: AsyncMutex::new(State {
                material: Vec::new(),
                groups: HashMap::new(),
                pki: HashMap::new(),
                ocsp: HashMap::new(),
                bound: None,
                planned: None,
                ensured: None,
            }),
            tasks: tasks.clone(),
            admission: Mutex::new(false),
            activate: Mutex::new(Some(activate)),
            events,
            maintenance_changed: Arc::new(tokio::sync::Notify::new()),
            on_demand,
            permission: OnceCell::new(),
            // Inventory capacity and the admission headroom needed to replace
            // a resident certificate are distinct from running job limits.
            group_slots: Arc::new(tokio::sync::Semaphore::new(capacity::GROUP_LIMIT)),
            cache_epoch: OnceCell::new(),
            effective_tls: AtomicBool::new(true),
            implicit_tailscale: std::sync::OnceLock::new(),
        });
        let weak = Arc::downgrade(&this);
        tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {},
                result = committed => if result.is_ok() && let Some(this) = weak.upgrade() { this.maintenance().await; },
            }
        });
        Ok(this)
    }
    /// Read/provision public authority data under this generation's ownership.
    /// An implicit default CA requested only by the Admin API is deliberately
    /// not registered for background trust installation.
    pub(crate) async fn public_ca(self:&Arc<Self>,id:String,cancel:CancellationToken)->Result<Option<crate::admin::PkiInfo>> {
        self.owned(cancel,move|this,token|Box::pin(async move {
            if id!="local" && !this.plan.authorities.contains_key(&id) {return Ok(None);}
            let configured=this.plan.authorities.contains_key(&id);
            let existing=this.state.lock().await.pki.get(&id).cloned();
            let pki=if let Some(pki)=existing {pki} else if configured {this.authority(&id,token.clone()).await?} else {
                let storage=this.plan.storage.as_ref().unwrap_or(&this.context.paths.default_storage).clone();
                let store=this.context.resources.store(storage,&this.context.paths,token.clone()).await?;
                let config=crate::local_pki::CaConfig{install_trust:false,..Default::default()};
                LocalPki::with_resources(store.fs.clone(),vec![config],this.context.resources.pki.clone())?
            };
            let snapshot=pki.provision(&id,token.clone()).await?;
            let (name,root_common_name,intermediate_common_name)=pki.public_names(&id)?;
            Ok(Some(crate::admin::PkiInfo{id:snapshot.id,name,root_common_name,intermediate_common_name,
                root_certificate:String::from_utf8(snapshot.root_certificate_pem)?,
                intermediate_certificate:String::from_utf8(snapshot.intermediate_chain_pem)?}))
        })).await
    }
    pub fn business_resolver(&self) -> Arc<HotCertificateResolver> {
        self.context.resolver.clone()
    }
    pub(crate) fn validate_acme_server_config(&self,config:&crate::acme_server::Config)->Result<()> {
        let resolvers=if config.resolvers.is_empty(){self.plan.tls_resolvers.as_ref()}else{&config.resolvers};
        crate::http_runtime::acme_dns::validate_resolvers(resolvers)?;
        let authority=self.plan.authorities.get(&config.ca);
        anyhow::ensure!(authority.is_some()||config.ca=="local","unknown ACME signing authority");
        let custom=authority.is_some_and(|a|a.config.intermediate.is_some());
        let lifetime=authority.map_or(std::time::Duration::from_secs(7*86400),|a|a.config.intermediate_lifetime);
        anyhow::ensure!(custom||config.lifetime<lifetime,"ACME certificate lifetime must be below managed intermediate lifetime");
        Ok(())
    }
    pub(crate) fn validate_acme_routes(&self,config:&crate::http_config::PreparedConfig)->Result<()> {
        use crate::http_config::types::Handler;
        let mut pending=Vec::new();for server in &config.servers {
            pending.extend(server.routes.iter());pending.extend(server.errors.iter());pending.extend(server.named_routes.values());
        }
        while let Some(route)=pending.pop() {for handler in &route.handlers {match handler {
            Handler::AcmeServer(config)=>self.validate_acme_server_config(config)?,
            Handler::Subroute{routes,errors,..}=>{pending.extend(routes.iter());pending.extend(errors.iter());}
            Handler::Intercept(responses)=>for response in responses {if let Some(routes)=&response.routes {pending.extend(routes.iter());}},
            Handler::ReverseProxy(proxy)=>for response in &proxy.response_routes {if let Some(routes)=&response.routes {pending.extend(routes.iter());}},
            _=>{}
        }}}Ok(())
    }
    pub(crate) async fn prepare_acme_server(self:&Arc<Self>,config:Arc<crate::acme_server::Config>,cancel:CancellationToken)
        ->Result<Arc<crate::acme_server::Controller>> {
        self.owned(cancel,move|this,token|Box::pin(async move {
            // Resolver lists can be large. Keep pure validation ahead of CA
            // side effects, on the same owned CPU lane as certificate work.
            let validator=this.clone();
            let config=crate::cert_cpu::run(this.context.resources.cpu.clone(),token.clone(),move||{
                validator.validate_acme_server_config(&config)?;
                Ok(config)
            }).await?;
            let pki=this.authority(&config.ca,token.clone()).await?;
            let snapshot=pki.provision(&config.ca,token.clone()).await?;drop(snapshot);
            this.context.resources.acme_server.prepare(config,this.plan.tls_resolvers.clone(),pki,&this.context.paths.default_storage,token).await
        })).await
    }
    pub fn manual_certificates(&self) -> Result<ManualCertificates> {
        ensure!(
            self.prepared.initialized(),
            "certificate services are not prepared"
        );
        Ok(self.manual_inventory.load_full().as_ref().clone())
    }
    pub fn plan(&self) -> &CertificatePlan {
        &self.plan
    }
    pub fn subscribe(&self) -> broadcast::Receiver<CertificateEvent> {
        self.events.subscribe()
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.context.cancel.child_token()
    }

    #[cfg(feature = "native-run")]
    pub(crate) async fn prepare_tcp_tickets(
        &self,
        cancel: CancellationToken,
    ) -> Result<TicketRuntime> {
        match &self.plan.ticket_mode {
            TicketMode::RuntimeDefault => Ok(TicketRuntime::RuntimeDefault),
            TicketMode::Disabled => Ok(TicketRuntime::Disabled),
            TicketMode::Rotating(settings) => match settings.provider() {
                TicketProvider::Standard => Ok(self
                    .context
                    .resources
                    .ticket_owners
                    .standard(settings.clone())),
                TicketProvider::Distributed { storage } => {
                    let namespace = storage
                        .as_ref()
                        .or(self.plan.storage.as_ref())
                        .unwrap_or(&self.context.paths.default_storage);
                    let store = self
                        .context
                        .resources
                        .store(namespace.clone(), &self.context.paths, cancel)
                        .await?;
                    self.context.resources.ticket_owners.distributed(
                        &store.fs,
                        &store.root,
                        settings.clone(),
                    )
                }
            },
        }
    }

    /// Reserve an owned worker before publication. An abandoned candidate
    /// drops the signal and cannot initialize or rotate a shared store.
    #[cfg(feature = "native-run")]
    pub(crate) fn stage_ticket_worker(
        &self,
        tickets: &TicketRuntime,
        generation: u64,
    ) -> Result<Option<oneshot::Sender<()>>> {
        let TicketRuntime::Rotating { owner, .. } = tickets else {
            return Ok(None);
        };
        let (task,activate) = {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let token = self.context.cancel.child_token();
        ensure!(
            !*_admission && !token.is_cancelled() && !self.tasks.is_closed(),
            "certificate service stopped"
        );
        let owner = owner.clone();
        let (activate, signal) = oneshot::channel();
        let task=self.tasks.track_future(async move {
            tokio::select! { biased;
                _=token.cancelled()=>{},
                ready=signal=>{ if ready.is_ok() { owner.run(generation, token).await; } },
            }
        });
        (task,activate)
        };
        tokio::spawn(task);
        Ok(Some(activate))
    }

    /// All fallible preparation/ensure work precedes this synchronous signal.
    /// Repeated calls are harmless; a dropped sender never activates maintenance.
    pub fn activate(&self) {
        let (signal,prune) = {
            let closed = self.admission.lock().unwrap_or_else(|e| e.into_inner());
            if *closed || self.context.cancel.is_cancelled() { return; }
            let signal = self.activate.lock().unwrap_or_else(|e|e.into_inner()).take();
            let mut prune=None;
            if signal.is_some() {
                if let Some(epoch) = self.cache_epoch.get() {
                    let cache = self.context.resources.resident_cache.clone();
                    let epoch = epoch.clone();
                    let old = cache.activate(epoch.clone());
                    let cpu = self.context.resources.cpu.clone();
                    let cancel = self.context.cancel.clone();
                    prune=Some(self.tasks.track_future(async move {
                        let _ = super::loaders::blocking(cpu, cancel, move || {
                            cache.prune(&epoch)?; drop(old); Ok(())
                        }).await;
                    }));
                }
                self.on_demand.active.store(true, Ordering::Release);
            }
            (signal,prune)
        };
        if let Some(task)=prune {tokio::spawn(task);}
        // oneshot delivery may synchronously re-enter this service.
        if let Some(signal) = signal { let _ = signal.send(()); }
    }
    pub async fn shutdown(&self) -> Result<()> {
        let activation = {
            let mut closed = self.admission.lock().unwrap_or_else(|e|e.into_inner());
            *closed = true;
            self.activate.lock().unwrap_or_else(|e|e.into_inner()).take()
        };
        // The closed fence rejects all new admissions before any wake/drop.
        // Token cancellation, verifier close, sender drop and tracker close
        // invoke no external waker while either service mutex is held.
        self.context.cancel.cancel();
        self.ssl_verify.close();
        drop(activation);
        self.tasks.close();
        self.tasks.wait().await;
        self.ssl_verify.wait().await;
        let pki = self
            .state
            .lock()
            .await
            .pki
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let results = stream::iter(pki)
            .map(|pki| async move { pki.shutdown().await })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        ensure!(
            results.into_iter().all(|result| result.is_ok()),
            "certificate authority shutdown failed"
        );
        Ok(())
    }
    pub async fn retained(&self) -> Result<RetainedCertificates> {
        ensure!(
            self.prepared.initialized(),
            "certificate services are not prepared"
        );
        let state = self.state.lock().await;
        Ok(RetainedCertificates {
            digest: self.context.configuration_digest,
            material: state
                .material
                .iter()
                .filter(|item| {
                    item.identity
                        || item.managed_names.as_ref().is_none_or(|names| {
                            self.on_demand
                                .bound_material(names, item.material.identity)
                                .is_some_and(|current| Arc::ptr_eq(&current, &item.material))
                        })
                })
                .cloned()
                .collect(),
            permission: self
                .permission
                .get()
                .and_then(|permission| permission.as_ref())
                .map(|permission| PermissionSetting {
                    endpoint: permission.endpoint().to_owned(),
                    legacy: false,
                }),
            business_names: state.planned.clone().unwrap_or_default(),
            on_demand_names: state
                .planned
                .as_ref()
                .into_iter()
                .flatten()
                .filter(|names| self.policy(&names[0]).on_demand)
                .map(|names| (names.clone(), names[0].clone()))
                .chain(
                    state
                        .material
                        .iter()
                        .filter_map(|item| {
                            item.managed_names
                                .as_ref()
                                .map(|names| (names.clone(), item.origin.clone()))
                        })
                        .filter(|(_, origin)| self.policy(origin).on_demand),
                )
                .collect(),
            capacity_displaced: self.on_demand.displaced_groups()?,
        })
    }

    async fn owned<T: Send + 'static>(
        self: &Arc<Self>,
        caller: CancellationToken,
        work: impl FnOnce(
            Arc<Self>,
            CancellationToken,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<T>> + Send>>
        + Send
        + 'static,
    ) -> Result<T> {
        let (sender, mut receiver) = oneshot::channel();
        let (token,task) = {
            let _admission = self
                .admission
                .lock()
                .map_err(|_| anyhow!("certificate service admission unavailable"))?;
            ensure!(
                !*_admission && !self.context.cancel.is_cancelled(),
                "certificate services stopped"
            );
            let token = self.context.cancel.child_token();
            let this = self.clone();
            let operation_token = token.clone();
            let task=self.tasks.track_future(async move {
                let result = work(this, operation_token).await;
                let _ = sender.send(result);
            });
            (token,task)
        };
        // Tracking is admitted under the fence; runtime-side synchronous drop
        // and payload destruction happen only after the gate is released.
        tokio::spawn(task);
        let guard = token.clone().drop_guard();
        let result = tokio::select! {
            biased;
            _ = caller.cancelled() => { token.cancel(); let _ = receiver.await; Err(anyhow!("certificate operation cancelled")) }
            result = &mut receiver => result.map_err(|_| anyhow!("certificate operation worker failed"))?,
        };
        drop(guard);
        result
    }
    pub async fn prepare(self: &Arc<Self>, cancel: CancellationToken) -> Result<()> {
        self.owned(cancel, |this, token| {
            Box::pin(async move {
                this.prepared
                    .get_or_try_init(|| this.prepare_inner(token))
                    .await
                    .map(|_| ())
            })
        })
        .await
    }
    async fn prepare_inner(&self, cancel: CancellationToken) -> Result<()> {
        self.prepare_permission(cancel.clone()).await?;
        if let Some(retained) = &self.restore {
            self.context.leaf_guard.key_deny().require_loaded()?;
            self.on_demand
                .set_configured_groups(&retained.business_names, &retained.capacity_displaced)?;
            let mut manual = Vec::new();
            let mut managed = Vec::new();
            for item in &retained.material {
                ensure!(!cancel.is_cancelled(), "certificate preparation cancelled");
                item.material.validate_at(now()?, false)?;
                reject_revoked(&item.material, &self.context.leaf_guard,
                    item.identity || item.managed_names.is_some())?;
                if !item.identity && item.managed_names.is_none() {
                    manual.push(item.material.clone());
                } else {
                    if item.identity {
                        self.publish_material(
                            item.material.clone(),
                            self.identity_resolver.clone(),
                            cancel.clone(),
                        )
                        .await?;
                    } else {
                        managed.push(item.clone());
                    }
                }
            }
            self.install_manual(&manual, cancel.clone()).await?;
            for item in managed {
                self.publish_restored_resident(item, cancel.clone()).await?;
            }
            self.state.lock().await.material = retained.material.clone();
            if let Some(identity) = &self.plan.identity {
                let names = identity
                    .identifiers
                    .iter()
                    .map(|name| cert_automation::normalize_names(std::slice::from_ref(name)))
                    .collect::<Result<Vec<_>>>()?;
                self.validate_retained_groups(&names, true).await?;
                self.refresh_client_keys().await?;
            }
            return Ok(());
        }
        // Instance-owned signed veto history is loaded before every managed
        // load; this never borrows any policy's certificate-store authority.
        let deny_store = self.context.resources.store(
            self.context.paths.state_root.join("key-compromise"), &self.context.paths,
            cancel.child_token()).await?;
        self.context.leaf_guard.key_deny().load(deny_store.fs.clone(),
            self.context.resources.cpu.clone(), cancel.child_token()).await?;
        // Files and caches are loaded before staged listeners can serve traffic.
        let storage = self
            .plan
            .storage
            .as_ref()
            .unwrap_or(&self.context.paths.default_storage);
        let materials =
            super::loaders::load_manual(&self.plan.manual, storage, &self.context, cancel.clone())
                .await?;
        let materials = materials.into_iter().map(Arc::new).collect::<Vec<_>>();
        self.install_manual(&materials, cancel.clone()).await?;
        for material in &materials {crate::cert_events::cached(self.context.events.as_ref(),false,&material.names,&cancel).await;}
        self.state.lock().await.material = materials
            .into_iter()
            .map(|material| RetainedMaterial {
                material,
                identity: false,
                managed_names: None,
                renew_at: 0,
                ari_after: i64::MAX,
                origin: String::new(),
            })
            .collect();
        self.manual_ocsp(cancel).await?;
        Ok(())
    }
    async fn parse_material(
        &self,
        certificate: Vec<u8>,
        key: zeroize::Zeroizing<Vec<u8>>,
        cancel: CancellationToken,
    ) -> Result<Material> {
        let deny=self.context.leaf_guard.key_deny().clone();
        super::loaders::blocking(self.context.resources.cpu.clone(), cancel, move || {
            let material=Material::from_pem(certificate,key)?;
            material.register_key(&deny)?;Ok(material)
        }).await
    }
    async fn parse_owned_material(&self,bundle:crate::certstore::OwnedCertificateBundle,group:Arc<Group>,cancel:CancellationToken)->Result<Material>{
        let deny=self.context.leaf_guard.key_deny().clone();
        super::loaders::blocking(self.context.resources.cpu.clone(),cancel,move||{
            let material=Material::from_owned(bundle,&group.names)?;
            material.register_key(&deny)?;Ok(material)
        }).await
    }
    async fn publish_material(
        &self,
        material: Arc<Material>,
        resolver: Arc<HotCertificateResolver>,
        cancel: CancellationToken,
    ) -> Result<()> {
        super::loaders::blocking(self.context.resources.cpu.clone(), cancel, move || {
            material.publish(&resolver)
        })
        .await
    }
    async fn install_manual(
        &self,
        material: &[Arc<Material>],
        cancel: CancellationToken,
    ) -> Result<()> {
        let material = material.to_vec();
        let materials_for_index = material.clone();
        let resolver = self.manual_resolver.clone();
        let certificates = super::loaders::blocking(
            self.context.resources.cpu.clone(),
            cancel.clone(),
            move || {
                let inputs = material
                    .iter()
                    .map(|material| CertificateInput {
                        names: &material.names,
                        certificate_pem: &material.certificate,
                        private_key_pem: &material.key,
                    })
                    .collect::<Vec<_>>();
                resolver.replace(&inputs)?;
                let certificates = material
                    .iter()
                    .map(|material| ManualCertificateInfo {
                        identity: material.identity,
                        names: material.names.clone(),
                        tags: material.tags.clone(),
                    })
                    .collect();
                Ok(certificates)
            },
        )
        .await?;
        let state = self.on_demand.clone();
        let materials = materials_for_index;
        super::loaders::blocking(
            self.context.resources.cpu.clone(),
            cancel.clone(),
            move || state.install_manual(&materials),
        )
        .await?;
        self.manual_inventory.store(Arc::new(ManualCertificates {
            resolver: self.manual_resolver.clone(),
            certificates: Arc::new(certificates),
        }));
        Ok(())
    }

    pub async fn ensure_business(
        self: &Arc<Self>,
        names: &[Vec<String>],
        bound: &[StagedAddress],
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut names = names.to_vec();
        names.extend(self.plan.automate.iter().map(|name| vec![name.clone()]));
        let bound = bound.to_vec();
        self.owned(cancel, move |this, token| {
            Box::pin(async move { this.ensure_business_inner(names, bound, token).await })
        })
        .await
    }
    async fn ensure_business_inner(
        &self,
        names: Vec<Vec<String>>,
        bound: Vec<StagedAddress>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let _ensure = self
            .ensure_gate
            .try_lock()
            .map_err(|_| anyhow!("candidate certificate acquisition already running"))?;
        ensure!(
            self.prepared.initialized(),
            "certificate services are not prepared"
        );
        let names = self.preflight(names)?;
        if let Some(retained) = &self.restore {
            ensure!(
                retained.business_names == names,
                "retained registered certificate names changed"
            );
        }
        {
            let mut state = self.state.lock().await;
            if let Some(planned) = &state.planned {
                ensure!(planned == &names, "candidate certificate names changed");
                ensure!(
                    state.bound.as_ref() == Some(&bound),
                    "candidate listener bindings changed"
                );
            } else {
                state.planned = Some(names.clone());
                state.bound = Some(bound.clone());
            }
            if let Some(previous) = &state.ensured {
                ensure!(previous == &names, "candidate certificate names changed");
                ensure!(
                    state.bound.as_ref() == Some(&bound),
                    "candidate listener bindings changed"
                );
                return Ok(());
            }
        }
        self.implicit_tailscale.get_or_init(|| names.iter().flat_map(|group|group.iter())
            .filter(|name|name.to_ascii_lowercase().ends_with(".ts.net")
                && !self.plan.policies.iter().any(|policy|policy.subjects.iter().any(|subject|subject==*name)))
            .cloned().collect());
        self.prepare_resident_cache(&names, cancel.clone()).await?;
        if self.restore.is_some() {
            self.validate_retained_groups(&names, false).await?;
        } else {
            self.provision_authorities(cancel.clone()).await?;
            let groups = stream::iter(names.iter().cloned())
                .map(|names| async {
                    if self.policy(&names[0]).on_demand {
                        return Ok(None);
                    }
                    self.group(names, false, &bound, cancel.clone())
                        .await
                        .map(Some)
                })
                .buffer_unordered(8)
                .collect::<Vec<_>>()
                .await;
            let groups = groups
                .into_iter()
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            let results =
                stream::iter(groups)
                    .map(|group| {
                        let cancel = cancel.clone();
                        async move {
                            let result = self.probe_group(group.clone(), cancel).await;
                            if result.as_ref().is_err_and(|error| {
                                error.is::<super::resident_cache::CacheChanged>()
                            }) && group.residency.lock().is_ok_and(|binding| {
                                binding.as_ref().is_some_and(|binding| !binding.slot.live())
                            }) {
                                return Ok(());
                            }
                            result
                        }
                    })
                    .buffer_unordered(10)
                    .collect::<Vec<_>>()
                    .await;
            for result in results {
                result?;
            }
            self.restore_ocsp(false, cancel.clone()).await?;
        }
        ensure!(!cancel.is_cancelled(), "certificate operation cancelled");
        self.state.lock().await.ensured = Some(names);
        Ok(())
    }
    fn preflight(&self, names: Vec<Vec<String>>) -> Result<Vec<Vec<String>>> {
        ensure!(
            names.len() <= crate::tls_resolver::MAX_CERTIFICATES,
            "certificate group capacity exceeded"
        );
        let mut result = Vec::new();
        let mut groups = std::collections::HashSet::new();
        let mut aliases = std::collections::HashSet::new();
        for group in names {
            let normalized = cert_automation::normalize_names(&group)?;
            let first = self.policy_index(&normalized[0]);
            ensure!(
                normalized
                    .iter()
                    .all(|name| self.policy_index(name) == first),
                "SAN group crosses automation policies"
            );
            if groups.insert(normalized.clone()) {
                ensure!(
                    normalized.iter().all(|name| aliases.insert(name.clone())),
                    "overlapping SAN groups require explicit separate aliases"
                );
                result.push(normalized);
            }
        }
        Ok(result)
    }
    fn policy_index(&self, name: &str) -> Option<usize> {
        self.plan.policies.iter().position(|policy| {
            policy.subjects.is_empty()
                || policy
                    .subjects
                    .iter()
                    .any(|subject| matches_subject(name, subject))
        })
    }
    fn policy(&self, name: &str) -> Policy {
        let mut policy=self.policy_index(name)
            .map(|index| self.plan.policies[index].clone()).unwrap_or_default();
        if let Some(subject)=self.implicit_tailscale.get()
            .and_then(|names|names.get(name).or_else(||names.iter().find(|subject|subject.contains('*') && matches_subject(name,subject)))) {
            policy.subjects=vec![subject.clone()];
            policy.issuers.clear();
            policy.managers.push(super::external::Manager::Tailscale);
            policy.on_demand=true;
        } else if policy.on_demand && policy.managers.is_empty() {
            // HTTP's on-demand convenience manager is tried before the real
            // permission endpoint. For other suffixes it performs no IO.
            policy.managers.push(super::external::Manager::Tailscale);
        }
        policy
    }
    fn policy_for_origin(&self, origin: &str) -> Policy {
        self.policy(origin)
    }
    // Management jobs use the current policy; physical cache entries are
    // separately identified by the complete chain, never by this key.
    fn management_key(&self, names: &[String], identity: bool, origin: &str) -> String {
        let key = group_key(names, identity);
        if !identity && self.policy_for_origin(origin).on_demand {
            format!("{key}:on-demand:{:?}", self.policy_index(origin))
        } else { key }
    }
    async fn validate_retained_groups(&self, names: &[Vec<String>], identity: bool) -> Result<()> {
        let material = self.state.lock().await.material.clone();
        for names in names {
            let retained = material.iter().find(|item| {
                item.identity == identity && item.managed_names.as_ref() == Some(names)
            });
            let Some(retained) = retained else {
                // The opaque, digest-bound snapshot records which subjects
                // really were registered under its old on-demand policy.
                if !identity
                    && self.restore.as_ref().is_some_and(|retained| {
                        retained.capacity_displaced.contains(names)
                            || retained.on_demand_names.iter().any(|(n, origin)| {
                                n == names && self.policy_for_origin(origin).on_demand
                            })
                    })
                {
                    continue;
                }
                return Err(anyhow!(
                    "retained managed certificate missing for required group"
                ));
            };
            retained.material.validate_at(now()?, false)?;
            if identity {
                retained.material.validate_at(now()?, true)?;
            }
            reject_revoked(&retained.material, &self.context.leaf_guard, true)?;
        }
        Ok(())
    }
}

fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}
fn group_key(names: &[String], identity: bool) -> String {
    use sha2::{Digest, Sha256};
    let mut names = names.to_vec();
    names.sort();
    let mut hash = Sha256::new();
    hash.update(b"caddy-certificate-service-group-v1\0");
    hash.update([u8::from(identity)]);
    hash.update((names.len() as u64).to_be_bytes());
    for name in names {
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn matches_subject(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let pattern = pattern.to_lowercase();
    if name == pattern {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }
    let mut labels = name.split('.').collect::<Vec<_>>();
    for index in 0..labels.len() {
        if labels[index].is_empty() {
            continue;
        }
        labels[index] = "*";
        if labels.join(".") == pattern {
            return true;
        }
    }
    false
}
fn reject_revoked(material: &Material, guard: &LeafGuard, key_veto: bool) -> Result<()> {
    let key=material.register_key(guard.key_deny())?;
    if key_veto { guard.key_deny().check_state(&key)?; }
    let (_, expiry) = material.times()?;
    ensure!(
        guard
            .intern(material.leaf_id, expiry)?
            .revocation()?
            .is_none(),
        "retained certificate is revoked"
    );
    Ok(())
}
