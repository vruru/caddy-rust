use super::{
    CertificatePlan,
    material::Material,
    model::{Issuer, Policy},
    storage::{CertificatePaths, CertificateResources, Store},
};
use crate::{
    cert_automation::{self, AutomationOptions, CertificateManager},
    cert_status::{OcspConfig, OcspManager, OcspOptions, OcspState},
    certstore::{CertificateBundle, names_key},
    challenge::ChallengeRegistry,
    http_runtime::{ChallengeListenerProvider, StagedAddress},
    leaf_guard::LeafGuard,
    local_pki::{InternalIssuerOptions, LocalPki, TrustInstaller},
    tls_resolver::{
        CertificateInput, HotCertificateResolver, ManualCertificateInfo, ManualCertificates,
    },
};
use anyhow::{Result, anyhow, ensure};
use futures_util::{StreamExt, stream};
use serde_json::json;
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex as AsyncMutex, OnceCell, broadcast, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
#[path = "services/group.rs"]
mod group;
#[path = "services/identity.rs"]
mod identity;
#[path = "services/maintenance.rs"]
mod maintenance;
#[path = "services/solver.rs"]
mod solver;

pub struct PrepareContext {
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
}
#[derive(Clone)]
struct RetainedMaterial {
    material: Arc<Material>,
    identity: bool,
    managed_names: Option<Vec<String>>,
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
    names: Vec<String>,
    policy: Policy,
    store: Arc<Store>,
    resolver: Arc<HotCertificateResolver>,
    issuer: GroupIssuer,
    identity: bool,
    gate: AsyncMutex<()>,
    solver: Option<Arc<solver::SolverBroker>>,
    leaf_state: Mutex<Option<Arc<crate::leaf_guard::LeafState>>>,
}
struct State {
    material: Vec<RetainedMaterial>,
    groups: HashMap<String, Arc<Group>>,
    pki: HashMap<String, LocalPki>,
    ocsp: HashMap<String, OcspManager>,
    bound: Option<Vec<StagedAddress>>,
    planned: Option<Vec<Vec<String>>>,
    ensured: Option<Vec<Vec<String>>>,
}

pub struct CertificateServices {
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
    state: AsyncMutex<State>,
    tasks: TaskTracker,
    admission: Mutex<()>,
    activate: Mutex<Option<oneshot::Sender<()>>>,
    events: broadcast::Sender<CertificateEvent>,
    maintenance_changed: tokio::sync::Notify,
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
        let identity_resolver = Arc::new(HotCertificateResolver::with_leaf_guard(
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
        let this = Arc::new(Self {
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
            admission: Mutex::new(()),
            activate: Mutex::new(Some(activate)),
            events,
            maintenance_changed: tokio::sync::Notify::new(),
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
    pub fn business_resolver(&self) -> Arc<HotCertificateResolver> {
        self.context.resolver.clone()
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

    /// All fallible preparation/ensure work precedes this synchronous signal.
    /// Repeated calls are harmless; a dropped sender never activates maintenance.
    pub fn activate(&self) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.context.cancel.is_cancelled() {
            return;
        }
        if let Some(signal) = self
            .activate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = signal.send(());
        }
    }
    pub async fn shutdown(&self) -> Result<()> {
        {
            let _admission = self
                .admission
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            self.context.cancel.cancel();
            self.activate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            self.tasks.close();
        }
        self.tasks.wait().await;
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
            material: state.material.clone(),
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
        let token = {
            let _admission = self
                .admission
                .lock()
                .map_err(|_| anyhow!("certificate service admission unavailable"))?;
            ensure!(
                !self.context.cancel.is_cancelled(),
                "certificate services stopped"
            );
            let token = self.context.cancel.child_token();
            let this = self.clone();
            let operation_token = token.clone();
            self.tasks.spawn(async move {
                let result = work(this, operation_token).await;
                let _ = sender.send(result);
            });
            token
        };
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
        if let Some(retained) = &self.restore {
            let mut manual = Vec::new();
            for item in &retained.material {
                ensure!(!cancel.is_cancelled(), "certificate preparation cancelled");
                item.material.validate_at(now()?, false)?;
                reject_revoked(&item.material, &self.context.leaf_guard)?;
                if !item.identity && item.managed_names.is_none() {
                    manual.push(item.material.clone());
                } else {
                    let resolver = if item.identity {
                        &self.identity_resolver
                    } else {
                        &self.context.resolver
                    };
                    self.publish_material(item.material.clone(), resolver.clone(), cancel.clone()).await?;
                }
            }
            self.install_manual(&manual,cancel.clone()).await?;
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
        self.install_manual(&materials,cancel.clone()).await?;
        self.state.lock().await.material = materials
            .into_iter()
            .map(|material| RetainedMaterial {
                material,
                identity: false,
                managed_names: None,
            })
            .collect();
        self.manual_ocsp(cancel).await?;
        Ok(())
    }
    async fn parse_material(&self, certificate: Vec<u8>, key: zeroize::Zeroizing<Vec<u8>>, cancel: CancellationToken) -> Result<Material> {
        super::loaders::blocking(self.context.resources.cpu.clone(),cancel,move || Material::from_pem(certificate,key)).await
    }
    async fn publish_material(&self, material: Arc<Material>, resolver: Arc<HotCertificateResolver>, cancel: CancellationToken) -> Result<()> {
        super::loaders::blocking(self.context.resources.cpu.clone(),cancel,move || material.publish(&resolver)).await
    }
    async fn install_manual(&self, material: &[Arc<Material>], cancel: CancellationToken) -> Result<()> {
        let material = material.to_vec();
        let resolver = self.manual_resolver.clone();
        let certificates = super::loaders::blocking(self.context.resources.cpu.clone(),cancel,move || {

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
        }).await?;
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
        if self.restore.is_some() {
            self.validate_retained_groups(&names, false).await?;
        } else {
            self.provision_authorities(cancel.clone()).await?;
            let groups = stream::iter(names.iter().cloned())
                .map(|names| async { self.group(names, false, &bound, cancel.clone()).await })
                .buffer_unordered(8)
                .collect::<Vec<_>>()
                .await;
            let groups = groups.into_iter().collect::<Result<Vec<_>>>()?;
            let results = stream::iter(groups)
                .map(|group| self.probe_group(group, cancel.clone()))
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
        ensure!(names.len() <= 4096, "certificate group capacity exceeded");
        let mut result = Vec::new();
        for group in names {
            let normalized = cert_automation::normalize_names(&group)?;
            let first = self.policy_index(&normalized[0]);
            ensure!(
                normalized
                    .iter()
                    .all(|name| self.policy_index(name) == first),
                "SAN group crosses automation policies"
            );
            ensure!(
                result
                    .iter()
                    .all(|existing: &Vec<String>| existing == &normalized
                        || existing.iter().all(|name| !normalized.contains(name))),
                "overlapping SAN groups require explicit separate aliases"
            );
            if !result.contains(&normalized) {
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
        self.policy_index(name)
            .map(|index| self.plan.policies[index].clone())
            .unwrap_or_default()
    }
    async fn validate_retained_groups(&self, names: &[Vec<String>], identity: bool) -> Result<()> {
        let material = self.state.lock().await.material.clone();
        for names in names {
            let retained = material
                .iter()
                .find(|item| {
                    item.identity == identity && item.managed_names.as_ref() == Some(names)
                })
                .ok_or_else(|| {
                    anyhow!("retained managed certificate missing for required group")
                })?;
            retained.material.validate_at(now()?, false)?;
            if identity {
                retained.material.validate_at(now()?, true)?;
            }
            reject_revoked(&retained.material, &self.context.leaf_guard)?;
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
fn reject_revoked(material: &Material, guard: &LeafGuard) -> Result<()> {
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
