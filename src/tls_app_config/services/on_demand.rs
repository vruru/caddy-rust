//! Generation-owned on-demand acquisition. Admission is separate from CA and
//! CPU budgets, so queued handshakes cannot consume a permit needed by proofs.
use super::*;
use crate::http_runtime::{AcquiredCertificate, ScopedCertificateProvider};
use crate::tls_resolver::{CertificatePublicationConflict, CertificateResidencyRetired};
use futures_util::{FutureExt, future::BoxFuture};
use std::sync::{RwLock, Weak, atomic::AtomicUsize};

type Outcome = std::result::Result<Option<AcquiredCertificate>, Arc<str>>;
struct ActionOutcome {
    maintain: bool,
    acquired: Option<AcquiredCertificate>,
}
impl ActionOutcome {
    fn cached() -> Self { Self { maintain: false, acquired: None } }
}
#[derive(Clone, Copy)]
enum Action {
    Miss,
    Maintenance,
}
struct Resident {
    material: Arc<Material>,
    binding: ResidencyBinding,
    leaf: Arc<crate::leaf_guard::LeafState>,
    group: std::sync::OnceLock<Arc<Group>>,
    receipt: ScopedCertificate,
    scope: CertificateScope,
    cache_entry: Option<Arc<super::super::resident_cache::CacheEntry>>,
    renew_at: i64,
    ari_after: i64,
    next_check: AtomicI64,
    retry_after: AtomicI64,
    origin: String,
    kind:cert_automation::ManagedKind,
}
#[derive(Clone, Copy)]
enum PendingKind {
    Expired,
    Revoked,
    Future(i64),
    Withdrawn,
}
enum SharedImport {
    Ready,
    Pending(PendingKind),
    Drop,
    Superseded,
}
struct PendingRestore {
    entry: Arc<super::super::resident_cache::CacheEntry>,
    kind: PendingKind,
}
struct Flight {
    action: Action,
    policy_index: Option<usize>,
    force_lookup: bool,
    quiet: CancellationToken,
    _admission: tokio::sync::OwnedSemaphorePermit,
    residency: Option<Arc<CertificateResidency>>,
    target: Option<Arc<Resident>>,
    selection: Option<crate::http_runtime::WarmSelection>,
    cancel: CancellationToken,
    result: Mutex<Option<Outcome>>,
    done: tokio::sync::Notify,
    waiters: AtomicUsize,
    background: bool,
}
pub(super) struct OnDemand {
    key_deny: Arc<crate::key_compromise::KeyDeny>,
    pub(super) active: AtomicBool,
    pending: Mutex<HashMap<[u8; 32], PendingRestore>>,
    pending_changed: tokio::sync::Notify,
    resident: RwLock<HashMap<String, Vec<Arc<Resident>>>>,
    manual: arc_swap::ArcSwap<HashMap<String, Vec<Arc<Material>>>>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    flight_slots: Arc<tokio::sync::Semaphore>,
    waiters: Arc<tokio::sync::Semaphore>,
    cleanup_changed: tokio::sync::Notify,
    cache_receiver: AsyncMutex<Option<broadcast::Receiver<u64>>>,
    capacity: super::capacity::Ledger,
    attach_changed: tokio::sync::Notify,
}
impl OnDemand {
    pub(super) fn external_waiter(&self)->Result<tokio::sync::OwnedSemaphorePermit> {
        self.waiters.clone().try_acquire_owned().map_err(|_|anyhow!("external certificate waiter capacity exceeded"))
    }
    pub(super) fn new(receiver: broadcast::Receiver<u64>, key_deny: Arc<crate::key_compromise::KeyDeny>) -> Self {
        Self {
            key_deny,
            active: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            pending_changed: tokio::sync::Notify::new(),
            cleanup_changed: tokio::sync::Notify::new(),
            cache_receiver: AsyncMutex::new(Some(receiver)),
            capacity: super::capacity::Ledger::default(),
            attach_changed: tokio::sync::Notify::new(),
            resident: RwLock::new(HashMap::new()),
            manual: arc_swap::ArcSwap::from_pointee(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            flight_slots: Arc::new(tokio::sync::Semaphore::new(256)),
            waiters: Arc::new(tokio::sync::Semaphore::new(1024)),
        }
    }
    fn resident(&self, name: &str) -> Option<Arc<Resident>> {
        self.resident_if(name, |_| true)
    }
    fn resident_if(
        &self,
        name: &str,
        predicate: impl Fn(&Resident) -> bool,
    ) -> Option<Arc<Resident>> {
        let entries = self.resident.read().ok()?;
        let select = |name: &str| {
            entries.get(name).and_then(|residents| {
                residents
                    .iter()
                    .find(|resident| resident.binding.slot.live()
                        && resident.material.key_allowed(&self.key_deny)
                        && predicate(resident))
                    .cloned()
            })
        };
        select(name).or_else(|| {
            if name.parse::<std::net::IpAddr>().is_ok() {
                return None;
            }
            name.split_once('.')
                .and_then(|(_, rest)| select(&format!("*.{rest}")))
        })
    }
    fn index(&self, resident: &Arc<Resident>) {
        // All aliases become visible together; no certificate parsing, IO,
        // callbacks or resolver acquisition under the small index lock.
        let mut entries = self
            .resident
            .write()
            .unwrap_or_else(|error| error.into_inner());
        for name in &resident.material.names {
            let candidates = entries.entry(name.clone()).or_default();
            candidates.retain(|prior| !Arc::ptr_eq(&prior.binding.slot, &resident.binding.slot));
            candidates.push(resident.clone());
        }
    }
    fn unindex(&self, resident: &Arc<Resident>) {
        let mut entries = self
            .resident
            .write()
            .unwrap_or_else(|error| error.into_inner());
        for name in &resident.material.names {
            if let Some(candidates) = entries.get_mut(name) {
                candidates.retain(|current| !Arc::ptr_eq(current, resident));
                if candidates.is_empty() {
                    entries.remove(name);
                }
            }
        }
    }
    fn indexed(&self, resident: &Arc<Resident>) -> bool {
        self.resident.read().is_ok_and(|entries| {
            entries
                .get(&resident.material.names[0])
                .is_some_and(|candidates| {
                    candidates
                        .iter()
                        .any(|current| Arc::ptr_eq(current, resident))
                })
        })
    }
    fn manual(&self, name: &str, at: i64) -> bool {
        let entries = self.manual.load();
        let valid = |entries: Option<&Vec<Arc<Material>>>| {
            entries.is_some_and(|entries| {
                entries
                    .iter()
                    .any(|material| material.validate_at(at, false).is_ok())
            })
        };
        valid(entries.get(name))
            || (name.parse::<std::net::IpAddr>().is_err()
                && name
                    .split_once('.')
                    .is_some_and(|(_, rest)| valid(entries.get(&format!("*.{rest}")))))
    }
    pub(super) fn references_group(&self, group: &Arc<Group>) -> bool {
        self.resident.read().is_ok_and(|entries| {
            entries.values().flatten().any(|resident| {
                resident
                    .group
                    .get()
                    .is_some_and(|actual| Arc::ptr_eq(actual, group))
            })
        })
    }
    pub(super) fn bound_material(
        &self,
        names: &[String],
        identity: [u8; 32],
    ) -> Option<Arc<Material>> {
        self.resident_if(names.first()?, |resident| {
            resident.material.names == names && resident.material.identity == identity
        })
        .map(|resident| resident.material.clone())
    }
    fn resident_receipt(&self, cached: &AcquiredCertificate) -> Option<Arc<Resident>> {
        self.resident_if(cached.receipt.names().first()?, |resident|
            resident.receipt.same_instance(&cached.receipt)
                && Arc::ptr_eq(&resident.binding.slot, &cached.slot))
    }
    fn cached(&self, name: &str) -> bool {
        let Ok(at) = now() else { return false };
        self.manual(name, at)
            || self
                .resident_if(name, |resident| resident.usable(at))
                .is_some()
    }
    fn almost_full(&self, capacity: usize) -> bool {
        self.capacity.almost_full(capacity)
    }
    pub(super) fn set_configured_groups(
        &self,
        groups: &[Vec<String>],
        retained: &std::collections::HashSet<Vec<String>>,
    ) -> Result<()> {
        self.capacity.set_configured(groups, retained)
    }
    pub(super) fn displaced_groups(&self) -> Result<std::collections::HashSet<Vec<String>>> {
        self.capacity.displaced()
    }
    pub(super) fn imported_binding(
        &self,
        names: &[String],
        identity: Option<[u8; 32]>,
    ) -> Option<(
        CertificateScope,
        ScopedCertificate,
        i64,
        i64,
        ResidencyBinding,
    )> {
        let resident = self.resident_if(names.first()?, |resident| {
            resident.material.names == names && resident.group.get().is_none()
                && identity.is_none_or(|identity| resident.material.identity == identity)
        })?;
        Some((
            resident.scope.clone(),
            resident.receipt.clone(),
            resident.renew_at,
            resident.ari_after,
            resident.binding.clone(),
        ))
    }
    pub(super) fn install_manual(&self, material: &[Arc<Material>]) -> Result<()> {
        let mut entries: HashMap<String, Vec<Arc<Material>>> = HashMap::new();
        for material in material {
            for name in &material.names {
                entries
                    .entry(name.clone())
                    .or_default()
                    .push(material.clone());
            }
        }
        let identities = material
            .iter()
            .map(|item| item.identity)
            .collect::<std::collections::HashSet<_>>();
        self.capacity.set_manual(identities.len())?;
        self.manual.store(Arc::new(entries));
        Ok(())
    }
    fn restore_resident(
        &self,
        material: Arc<Material>,
        binding: ResidencyBinding,
        leaf: Arc<crate::leaf_guard::LeafState>,
        scope: CertificateScope,
        receipt: ScopedCertificate,
        schedule: (i64, i64),
        origin: String,
        kind:cert_automation::ManagedKind,
    ) {
        let resident = Arc::new(Resident {
            material: material.clone(),
            binding,
            leaf,
            group: std::sync::OnceLock::new(),
            receipt,
            scope,
            cache_entry: None,
            renew_at: schedule.0,
            ari_after: schedule.1,
            next_check: AtomicI64::new(schedule.0.min(schedule.1)),
            retry_after: AtomicI64::new(0),
            origin,
            kind,
        });
        self.index(&resident);
    }
    fn record(
        &self,
        group: Arc<Group>,
        material: Arc<Material>,
        receipt: ScopedCertificate,
        cache_entry: Option<Arc<super::super::resident_cache::CacheEntry>>,
        binding: ResidencyBinding,
        leaf: Arc<crate::leaf_guard::LeafState>,
        kind:cert_automation::ManagedKind,
    ) {
        let at = now().unwrap_or(i64::MAX);
        let next_check = next_check(&group, at);
        let resident = Arc::new(Resident {
            material,
            binding,
            leaf,
            group: std::sync::OnceLock::from(group.clone()),
            receipt,
            scope: group.scope.clone(),
            cache_entry,
            renew_at: group.renew_at.load(Ordering::Acquire),
            ari_after: group.ari_after.load(Ordering::Acquire),
            next_check: AtomicI64::new(next_check),
            retry_after: AtomicI64::new(0),
            origin: group.origin.clone(),
            kind,
        });
        self.index(&resident);
    }
}
impl Resident {
    fn usable(&self, at: i64) -> bool {
        self.binding.slot.live()
            && self.leaf.admission().allow_certificate
            && self.material.validate_at(at, false).is_ok()
    }
}
struct Provider {
    service: Weak<CertificateServices>,
    state: Arc<OnDemand>,
}
impl ScopedCertificateProvider for Provider {
    fn validate_acme_server(&self,config:&crate::acme_server::Config)->Result<()> {
        self.service.upgrade().ok_or_else(||anyhow!("certificate services stopped"))?.validate_acme_server_config(config)
    }
    fn prepare_acme_server(&self,config:Arc<crate::acme_server::Config>,cancel:CancellationToken)
        -> BoxFuture<'static,Result<Arc<crate::acme_server::Controller>>> {
        let service=self.service.upgrade();Box::pin(async move {
            let service=service.ok_or_else(||anyhow!("certificate services stopped"))?;
            service.prepare_acme_server(config,cancel).await
        })
    }
    fn ensure_request(
        &self,
        request: crate::http_runtime::CertificateRequest,
        cancel: CancellationToken,
    ) -> BoxFuture<'static, Result<Option<AcquiredCertificate>>> {
        let service = self.service.upgrade();
        Box::pin(async move {
            service
                .ok_or_else(|| anyhow!("certificate services stopped"))?
                .on_demand_ensure_request(
                    request.origin,
                    request.subject,
                    request.force_lookup,
                    request.cached,
                    request.selection,
                    request.hello,
                    cancel,
                )
                .await
        })
    }

    fn needs_quic_preflight(&self) -> bool {
        self.service
            .upgrade()
            .is_some_and(|service| service.plan.policies.iter().any(|policy| policy.on_demand)
                || service.implicit_tailscale.get().is_some_and(|names|!names.is_empty()))
    }
    fn can_acquire_quic_name(&self, name: &str) -> bool {
        self.service.upgrade().is_some_and(|service| {
            service.policy(name).is_ok_and(|policy| policy.on_demand)
        })
    }
    fn should_probe_before_fallback(&self, name: &str) -> bool {
        self.service.upgrade().is_none_or(|service| {
            service.policy(name).map_or(true, |policy| policy.on_demand) || self.state.almost_full(service.plan.cache_capacity)
        })
    }
    fn cached_name(&self, name: &str) -> bool {
        self.state.cached(name)
    }
    fn maintenance_due(&self, name: &str) -> bool {
        let Some(service) = self.service.upgrade() else { return false; };
        let Ok(at) = now() else { return false; };
        let policy=match service.policy(name) { Ok(policy)=>policy, Err(_)=>return true };
        if !self.state.active.load(Ordering::Acquire)
            || service.context.cancel.is_cancelled()
            || !policy.on_demand
            || self.state.manual(name, at)
        {
            return false;
        }
        self.state.resident_if(name, |resident| resident.usable(at))
            .is_some_and(|resident| {
                service.current_maintenance_at(name, &resident).is_ok_and(|due| due <= at)
                    || resident.leaf.needs_renewal()
            })
    }
    fn maintenance_due_for(&self, request: &crate::http_runtime::CertificateRequest) -> bool {
        let Some(cached) = &request.cached else { return self.maintenance_due(&request.subject); };
        let Some(service) = self.service.upgrade() else { return false; };
        let Ok(at) = now() else { return false; };
        let policy=match service.policy_for_origin(&request.origin) { Ok(policy)=>policy, Err(_)=>return true };
        self.state.active.load(Ordering::Acquire)
            && !service.context.cancel.is_cancelled()
            && policy.on_demand
            && self.state.resident_receipt(cached).is_some_and(|resident|
                resident.usable(at) && (service.current_maintenance_at(&request.origin, &resident)
                    .is_ok_and(|due| due <= at) || resident.leaf.needs_renewal()))
    }
    fn ensure(&self, name: String, cancel: CancellationToken) -> BoxFuture<'static, Result<()>> {
        let service = self.service.upgrade();
        Box::pin(async move {
            service
                .ok_or_else(|| anyhow!("certificate services stopped"))?
                .on_demand_ensure(name, cancel)
                .await
        })
    }
}
struct Waiter {
    flight: Arc<Flight>,
    state: Arc<OnDemand>,
    released: bool,
}
impl Waiter {
    fn release(&mut self) -> bool {
        if self.released {
            return false;
        }
        // Joining a flight and cancelling its last waiter use one lock. A late
        // join cannot revive a leader already committed to cancellation.
        let _flights = self.state.flights.lock().unwrap_or_else(|e| e.into_inner());
        self.released = true;
        let cancel =
            self.flight.waiters.fetch_sub(1, Ordering::AcqRel) == 1 && !self.flight.background;
        if cancel {
            self.flight.cancel.cancel();
        }
        cancel
    }
}
impl Drop for Waiter {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

impl CertificateServices {
    fn current_maintenance_at(&self, origin: &str, resident: &Resident) -> Result<i64> {
        let policy = self.policy_for_origin(origin)?;
        let scheduled = resident.next_check.load(Ordering::Acquire);
        if self.policy_index(origin)? == self.policy_index(&resident.origin)?
            && resident.kind!=cert_automation::ManagedKind::Internal
        { return Ok(scheduled); }
        let ordinary = self.current_renewal_time(&resident.material, &policy,resident.kind)?;
        // Preserve an already selected ARI/refresh deadline across a policy
        // change; current-policy lifetime checks can only make it earlier.
        Ok(if resident.ari_after == i64::MAX { ordinary } else { ordinary.min(scheduled) })
    }
    /// One service-owned worker handles authenticated revocation facts for
    /// all managed physical chains, including on-demand acquisitions. The
    /// notification is only a hint; every wake and initial pass rescans state.
    pub(super) async fn run_revoked_business(self: Arc<Self>) {
        tokio::join!(self.clone().run_revoked_scan(), self.run_key_compromise_flush());
    }
    async fn run_revoked_scan(self: Arc<Self>) {
        let mut key_changes = self.context.leaf_guard.key_deny().subscribe();
        loop {
            if self.context.cancel.is_cancelled() { break; }
            let changed = self.context.resources.revoked.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.reconcile_revoked_business().await.is_err() {
                let _ = self.events.send(CertificateEvent {
                    kind: "revoked_certificate_maintenance_failed", names: Vec::new(),
                });
            }
            tokio::select! { biased;
                _ = self.context.cancel.cancelled() => break,
                _ = &mut changed => {},
                _ = key_changes.changed() => {},
                _ = tokio::time::sleep(self.plan.renew_interval) => {},
            }
        }
    }
    async fn run_key_compromise_flush(self: Arc<Self>) {
        let mut key_changes = self.context.leaf_guard.key_deny().subscribe();
        let mut backoff = Duration::from_secs(1);
        loop {
            if self.context.cancel.is_cancelled() { break; }
            let delay = match self.context.leaf_guard.key_deny().flush(self.context.resources.cpu.clone(),
                self.context.cancel.child_token()).await {
                Ok(()) => { backoff = Duration::from_secs(1); self.plan.renew_interval },
                Err(_) => {
                    let _ = self.events.send(CertificateEvent {
                        kind: "key_compromise_not_durable", names: Vec::new(),
                    });
                    let delay = backoff;
                    backoff = backoff.saturating_mul(2).min(Duration::from_secs(30));
                    delay
                },
            };
            tokio::select! { biased;
                _ = self.context.cancel.cancelled() => break,
                _ = key_changes.changed() => {},
                _ = tokio::time::sleep(delay) => {},
            }
        }
    }

    async fn reconcile_revoked_business(&self) -> Result<()> {
        if !self.on_demand.active.load(Ordering::Acquire) { return Ok(()); }
        let Some(epoch) = self.cache_epoch.get().cloned() else { return Ok(()); };
        if !self.context.resources.resident_cache.is_active(&epoch)? { return Ok(()); }
        let indexed = self.on_demand.clone();
        let key_deny = self.context.leaf_guard.key_deny().clone();
        let targets = crate::cert_cpu::run(self.context.resources.cpu.clone(),
            self.context.cancel.clone(), move || {
                let indexed = indexed.resident.read()
                    .map_err(|_| anyhow!("certificate resident index unavailable"))?;
                let mut seen = std::collections::HashSet::new();
                let mut targets = Vec::new();
                for resident in indexed.values().flatten() {
                    if resident.binding.slot.live()
                        && (resident.leaf.pending_revocation()?.is_some()
                            || !resident.material.key_allowed(&key_deny))
                        && seen.insert(resident.material.identity)
                    { targets.push(resident.clone()); }
                }
                Ok(targets)
            }).await?;
        // Snapshot all physical targets before any failure withdraws their
        // shared leaf. Distinct chains containing that leaf are still jobs.
        let outcomes = stream::iter(targets).map(|resident| {
            let epoch = epoch.clone();
            async move {
            if !self.context.resources.resident_cache.is_active(&epoch)?
                || self.context.cancel.is_cancelled() || !self.on_demand.indexed(&resident)
                || !self.context.resolver.receipt_current(&resident.receipt, &resident.binding.slot)?
            { return Ok(()); }
            let name0 = resident.material.management_name.to_string();
            // CertMagic selects current management config using real Names[0].
            // Existing managed worknames retain renewal authority even when
            // another alias now matches a different policy; this is not a new
            // Hello permission decision or authority to expand SAN scope.
            let bound = self.state.lock().await.bound.clone().unwrap_or_default();
            // Existing managed material supplies renewal authority. Unlike a
            // new Hello acquisition, Go background forceRenew does not ask.
            // Current Name0 policy selects issuer/storage; retained worknames
            // are never expanded to unrelated names from the certificate.
            let group = self.replacement_group(resident.material.names.clone(),
                &bound, self.context.cancel.clone(), name0).await?;
            self.ensure_group_target(group.clone(), false, Some(RenewalTarget {
                material: resident.material.clone(), receipt: resident.receipt.clone(),
                binding: resident.binding.clone(), leaf: resident.leaf.clone(), selection: None,
            }), self.context.cancel.clone()).await?;
            group.background.store(true, Ordering::Release);
            self.maintenance_changed.notify_one();
            let maintenance = self.ocsp_manager(&group).await;
            // Retire the exact revoked projection even if status-handle
            // preparation failed. Conversely, retirement failure cannot
            // prevent the new publication's periodic maintenance rescan.
            let retirement = if self.context.resolver.receipt_current(&resident.receipt, &resident.binding.slot)? {
                self.evict_resident(resident, self.context.cancel.clone()).await
            } else { Ok(()) };
            maintenance?;
            retirement?;
            Ok::<_, anyhow::Error>(())
            }
        }).buffer_unordered(10).collect::<Vec<_>>().await;
        for outcome in outcomes { outcome?; }
        Ok(())
    }

    pub(super) async fn publish_restored_resident(
        &self,
        retained: RetainedMaterial,
        cancel: CancellationToken,
    ) -> Result<()> {
        // Rollback capability retains in-process material and the shared
        // authenticated LeafGuard. This path must remain memory-only: status
        // handles and raw-store restoration start after actual activation.
        let kind=retained.kind.ok_or_else(||anyhow!("retained managed issuer attribution missing"))?;
        let resolver = self.context.resolver.clone();
        let guard = self.context.leaf_guard.clone();
        let state = self.on_demand.clone();
        let publication_cancel = cancel.clone();
        let capacity = self.plan.cache_capacity;
        let changed = self.maintenance_changed.clone();
        super::super::loaders::blocking(self.context.resources.cpu.clone(), cancel, move || {
            let material = retained.material;
            material.validate_at(now()?, false)?;
            let leaf = guard.intern(material.leaf_id, material.times()?.1)?;
            ensure!(
                leaf.revocation()?.is_none(),
                "retained certificate is revoked"
            );
            let scope = CertificateScope::new();
            let binding = ResidencyBinding::local();
            let receipt = resolver.upsert_resident(
                &CertificateInput {
                    names: &material.names,
                    certificate_pem: &material.certificate,
                    private_key_pem: &material.key,
                },
                &scope,
                &binding.slot,
                &publication_cancel,
                || {
                    if state
                        .capacity
                        .admit(&material.names, &binding, None, capacity, |_| Ok(()))?
                    {
                        state.cleanup_changed.notify_one();
                    }
                    Ok(())
                },
            )?;
            state.restore_resident(
                material,
                binding,
                leaf,
                scope,
                receipt,
                (retained.renew_at, retained.ari_after),
                retained.origin,
                kind,
            );
            changed.notify_one();
            Ok(())
        })
        .await
    }

    /// Root supplies effective TLS-app provisioning (including unconditional HTTP-app provisioning;
    /// Admin identity uses a separate cache and does not by itself enable this app), before ensure_business. Changing this is not a
    /// live policy update; each transaction needs a fresh services generation.
    pub fn set_effective_tls_app(&self, enabled: bool) -> Result<()> {
        ensure!(
            !self.cache_epoch.initialized(),
            "certificate cache epoch is already prepared"
        );
        self.effective_tls.store(enabled, Ordering::Release);
        Ok(())
    }
    pub(super) async fn prepare_resident_cache(
        &self,
        names: &[Vec<String>],
        cancel: CancellationToken,
    ) -> Result<()> {
        self.cache_epoch
            .get_or_try_init(|| async {
                if self.restore.is_none() {
                    self.on_demand
                        .set_configured_groups(names, &Default::default())?;
                }
                let bytes=names.iter().try_fold(8192usize,|n,group|{
                    let n=n.checked_add(group.len()*std::mem::size_of::<String>()+std::mem::size_of::<Vec<String>>())
                        .ok_or(crate::cert_transient::ResourceDenied)?;
                    group.iter().try_fold(n,|n,name|n.checked_add(name.len()).ok_or(crate::cert_transient::ResourceDenied))
                })?;
                let memory=crate::cert_transient::reserve(bytes)?;
                let mut copied=Vec::new();copied.try_reserve_exact(names.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;
                let mut batch=0usize;let mut items=0usize;
                for group in names {
                    let mut values=Vec::new();values.try_reserve_exact(group.len()).map_err(|_|crate::cert_transient::ResourceDenied)?;
                    for name in group {
                        values.push(name.clone());batch=batch.saturating_add(name.len());items+=1;
                        if batch>=65536||items%128==0{ensure!(!cancel.is_cancelled(),"certificate registration cancelled");tokio::task::yield_now().await;batch=0;}
                    }
                    copied.push(values);
                }
                let input=RegistrationInput{names:copied,plan:self.plan.clone(),cancel:cancel.clone(),_memory:memory};
                let cache = self.context.resources.resident_cache.clone();
                let enabled = self.effective_tls.load(Ordering::Acquire);
                let (epoch, entries) = super::super::loaders::blocking(
                    self.context.resources.cpu.clone(),cancel.clone(),
                    move || cache.prepare(input.execute()?, enabled),
                ).await?;
                if self.restore.is_none() {
                    for entry in entries {
                        self.import_shared_entry(epoch.clone(), entry, cancel.clone())
                            .await?;
                    }
                }
                Ok::<_, anyhow::Error>(epoch)
            })
            .await
            .map(|_| ())
    }
    async fn import_shared_name(&self, name: &str, cancel: CancellationToken) -> Result<bool> {
        let Some(epoch) = self.cache_epoch.get().cloned() else { return Ok(false); };
        let mut prior = None;
        for _ in 0..3 {
            let Some(entry) = self.shared_entry(epoch.clone(), name, cancel.clone()).await? else {
                return Ok(false);
            };
            if prior.as_ref().is_some_and(|old| Arc::ptr_eq(old, &entry)) { return Ok(false); }
            if self.import_shared_entry(epoch.clone(), entry.clone(), cancel.clone()).await? {
                return Ok(true);
            }
            prior = Some(entry);
        }
        Err(super::super::resident_cache::CacheChanged.into())
    }

    /// Repair an actual warm selection from the current shared revision before
    /// permission or issuance. Filtering precedes any resolver/ledger mutation.
    async fn import_shared_selected(&self, name: &str,
        selection: &crate::http_runtime::WarmSelection,
        cancel: CancellationToken) -> Result<Option<AcquiredCertificate>> {
        let Some(epoch) = self.cache_epoch.get().cloned() else { return Ok(None); };
        for _ in 0..3 {
            let cache = self.context.resources.resident_cache.clone();
            let lookup_epoch = epoch.clone();
            let subject = name.to_owned();
            let resolver = self.context.resolver.clone();
            let selection = selection.clone();
            let guard = self.context.leaf_guard.clone();
            let entry = super::super::loaders::blocking(self.context.resources.cpu.clone(),
                cancel.clone(), move || {
                    let entries = cache.snapshot(&lookup_epoch)?;
                    let wildcard = if subject.parse::<std::net::IpAddr>().is_err() {
                        subject.split_once('.').map(|(_, suffix)| format!("*.{suffix}"))
                    } else { None };
                    for exact in [true, false] {
                        for entry in &entries {
                            let named = if exact { entry.material.names.contains(&subject) }
                                else { wildcard.as_ref().is_some_and(|name|
                                    entry.material.names.contains(name)) };
                            if !named || guard.key_deny().check_spki_der(&entry.material.spki_der).is_err() {
                                continue;
                            }
                            let input = CertificateInput { names: &entry.material.names,
                                certificate_pem: &entry.material.certificate,
                                private_key_pem: &entry.material.key };
                            if resolver.candidate_allowed(&input, &entry.material.tags,
                                selection.filter.as_deref(), &selection.schemes, selection.version)? {
                                return Ok(Some(entry.clone()));
                            }
                        }
                    }
                    Ok(None)
                }).await?;
            let Some(entry) = entry else { return Ok(None); };
            if !self.import_shared_entry(epoch.clone(), entry.clone(), cancel.clone()).await? {
                continue;
            }
            if let Some(resident) = self.on_demand.resident_if(name, |resident|
                resident.cache_entry.as_ref().is_some_and(|cached| Arc::ptr_eq(cached, &entry))
                    && resident.usable(now().unwrap_or(i64::MAX))) {
                return Ok(Some(AcquiredCertificate { subject: name.to_owned(),
                    receipt: resident.receipt.clone(), slot: resident.binding.slot.clone(), external: None }));
            }
        }
        Err(super::super::resident_cache::CacheChanged.into())
    }
    async fn shared_entry(
        &self,
        epoch: Arc<super::super::resident_cache::Epoch>,
        name: &str,
        cancel: CancellationToken,
    ) -> Result<Option<Arc<super::super::resident_cache::CacheEntry>>> {
        let cache = self.context.resources.resident_cache.clone();
        let name = name.to_owned();
        super::super::loaders::blocking(self.context.resources.cpu.clone(), cancel, move || {
            cache.find(&epoch, &name)
        })
        .await
    }
    async fn import_shared_entry(
        &self,
        epoch: Arc<super::super::resident_cache::Epoch>,
        entry: Arc<super::super::resident_cache::CacheEntry>,
        cancel: CancellationToken,
    ) -> Result<bool> {
        let gate_owner = entry.clone();
        let _import = tokio::select! {biased;
            _=cancel.cancelled()=>return Err(anyhow!("certificate cache import cancelled")),
            _=gate_owner.revision.retired()=>return Ok(false),
            guard=gate_owner.import_gate.lock()=>guard,
        };
        if self
            .on_demand
            .resident_if(&entry.material.names[0], |resident| {
                resident
                    .cache_entry
                    .as_ref()
                    .is_some_and(|cached| Arc::ptr_eq(cached, &entry))
                    && resident.usable(now().unwrap_or(i64::MAX))
            })
            .is_some()
        {
            return Ok(true);
        }
        let cache = self.context.resources.resident_cache.clone();
        if let Err(error) = cache.valid_import(&epoch, &entry) {
            if error.is::<super::super::resident_cache::CacheChanged>() {
                return Ok(false);
            }
            return Err(error);
        }
        entry.material.register_key(self.context.leaf_guard.key_deny())?;
        if let Err(error) = self.context.leaf_guard.key_deny().check_spki_der(&entry.material.spki_der) {
            if !error.is::<crate::key_compromise::KeyCompromised>() { return Err(error); }
            let cleanup = cache.clone(); let stale = entry.clone(); let view = epoch.clone();
            super::super::loaders::blocking(self.context.resources.cpu.clone(), cancel.clone(),
                move || { cleanup.remove(&view, &stale)?; Ok(()) }).await?;
            return Ok(false);
        }
        self.prime_material_status(entry.material.clone(), false, cancel.clone()).await?;
        let material = entry.material.clone();
        let guard = self.context.leaf_guard.clone();
        let resolver = self.context.resolver.clone();
        let state = self.on_demand.clone();
        let retain = material.clone();
        let origin = entry.origin.clone();
        let pending_entry = entry.clone();
        let publication_cancel = cancel.clone();
        let capacity = self.plan.cache_capacity;
        let changed = self.maintenance_changed.clone();
        let imported = super::super::loaders::blocking(
            self.context.resources.cpu.clone(),
            cancel.clone(),
            move || {
                use super::super::material::Validity;
                let at = now()?;
                let Ok(validity) = material.classify_at(at) else {
                    return Ok(SharedImport::Drop);
                };
                match guard.key_deny().check_spki_der(&material.spki_der) {
                    Ok(()) => {},
                    Err(error) if error.is::<crate::key_compromise::KeyCompromised>() =>
                        return Ok(SharedImport::Drop),
                    Err(error) => return Err(error),
                }
                let (_, expiry) = material.times()?;
                let leaf = guard.intern(material.leaf_id, expiry)?;
                if let Some(revoked) = leaf.revocation()? {
                    return Ok(SharedImport::Pending(if revoked.withdrawn {
                        PendingKind::Withdrawn
                    } else {
                        PendingKind::Revoked
                    }));
                }
                match validity {
                    Validity::Expired => return Ok(SharedImport::Pending(PendingKind::Expired)),
                    Validity::Future(nb) => {
                        return Ok(SharedImport::Pending(PendingKind::Future(nb)));
                    }
                    Validity::Current => {}
                }
                let scope = CertificateScope::new();
                let binding = state
                    .resident_if(&material.names[0], |resident| {
                        resident.material.names == material.names
                            && resident.binding.projects(&entry)
                    })
                    .map_or_else(
                        || ResidencyBinding::shared(&entry),
                        |resident| resident.binding.clone(),
                    );
                let receipt = match resolver.upsert_resident(
                    &CertificateInput {
                        names: &material.names,
                        certificate_pem: &material.certificate,
                        private_key_pem: &material.key,
                    },
                    &scope,
                    &binding.slot,
                    &publication_cancel,
                    || {
                        if state
                            .capacity
                            .admit(&material.names, &binding, None, capacity, |victim| {
                                guard.key_deny().check_spki_der(&material.spki_der)?;
                                cache.commit_import(&epoch, &entry, shared_victim(victim))
                            })?
                        {
                            state.cleanup_changed.notify_one();
                        }
                        Ok(())
                    },
                ) {
                    Ok(receipt) => receipt,
                    Err(error) if error.is::<crate::key_compromise::KeyCompromised>() =>
                        return Ok(SharedImport::Drop),
                    Err(error)
                        if error.is::<super::super::resident_cache::CacheChanged>()
                            || publication_displaced(&error, &binding.slot) =>
                    {
                        return Ok(SharedImport::Superseded);
                    }
                    Err(error) => return Err(error),
                };
                let resident = Arc::new(Resident {
                    material: material.clone(),
                    binding: binding.clone(),
                    leaf,
                    group: std::sync::OnceLock::new(),
                    receipt,
                    scope,
                    cache_entry: Some(entry.clone()),
                    renew_at: entry.renew_at,
                    ari_after: entry.ari_after,
                    next_check: AtomicI64::new(entry.renew_at.min(entry.ari_after)),
                    retry_after: AtomicI64::new(0),
                    origin: entry.origin.clone(),
                    kind:entry.kind,
                });
                state.index(&resident);
                changed.notify_one();
                if !binding.slot.live() {
                    // The retirement event can arrive before the resident
                    // index sees this import; make the recheck explicit.
                    state.cleanup_changed.notify_one();
                    return Ok(SharedImport::Superseded);
                }
                state.attach_changed.notify_one();
                Ok(SharedImport::Ready)
            },
        )
        .await?;
        match imported {
            SharedImport::Superseded => Ok(false),
            SharedImport::Ready => {
                let mut state = self.state.lock().await;
                if self
                    .on_demand
                    .bound_material(&retain.names, retain.identity)
                    .is_none_or(|current| !Arc::ptr_eq(&current, &retain))
                {
                    return Ok(false);
                }
                state.material.retain(|item| {
                    item.identity || item.material.identity != retain.identity
                });
                state.material.push(RetainedMaterial {
                    managed_names: Some(retain.names.clone()),
                    material: retain,
                    identity: false,
                    origin: origin.clone(),
                    renew_at: pending_entry.renew_at,
                    ari_after: pending_entry.ari_after,
                    kind:Some(pending_entry.kind),
                });
                Ok(true)
            }
            SharedImport::Pending(kind) => {
                if self.restore.is_none()
                    && (!self.policy_for_origin(&origin)?.on_demand
                        || matches!(kind, PendingKind::Withdrawn))
                {
                    let mut queue = self
                        .on_demand
                        .pending
                        .lock()
                        .map_err(|_| anyhow!("certificate pending restoration unavailable"))?;
                    ensure!(
                        queue.len() < crate::tls_resolver::MAX_CERTIFICATES
                            || queue.contains_key(&retain.identity),
                        "certificate pending restoration capacity exceeded"
                    );
                    queue.insert(
                        retain.identity,
                        PendingRestore {
                            entry: pending_entry,
                            kind,
                        },
                    );
                    drop(queue);
                    self.on_demand.pending_changed.notify_one();
                }
                Ok(false)
            }
            SharedImport::Drop => {
                let _ = self.events.send(CertificateEvent {
                    kind: "cached_certificate_invalid_purpose",
                    names: retain.names.clone(),
                });
                Ok(false)
            }
        }
    }
    pub fn certificate_provider(self: &Arc<Self>) -> Arc<dyn ScopedCertificateProvider> {
        Arc::new(Provider {
            service: Arc::downgrade(self),
            state: self.on_demand.clone(),
        })
    }
    pub(super) async fn run_cache_evictions(self: Arc<Self>) {
        let Some(mut receiver) = self.on_demand.cache_receiver.lock().await.take() else {
            return;
        };
        let mut jobs = futures_util::stream::FuturesUnordered::new();
        let mut active = std::collections::HashSet::new();
        loop {
            let changed = self.on_demand.cleanup_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let entries = self
                    .on_demand
                    .resident
                    .read()
                    .unwrap_or_else(|error| error.into_inner());
                for resident in entries.values().flatten() {
                    if jobs.len() >= 8 {
                        break;
                    }
                    let id = Arc::as_ptr(resident) as usize;
                    if resident.binding.slot.live() || !active.insert(id) {
                        continue;
                    }
                    let this = self.clone();
                    let resident = resident.clone();
                    jobs.push(async move {
                        (
                            id,
                            this.evict_resident(resident, this.context.cancel.child_token())
                                .await,
                        )
                    });
                }
            }
            tokio::select! {biased;
                _=self.context.cancel.cancelled()=>break,
                Some((id,result))=jobs.next(),if !jobs.is_empty()=>{
                    active.remove(&id);
                    if result.is_err() {
                        let _=self.events.send(CertificateEvent{kind:"certificate_cleanup_failed",names:Vec::new()});
                        tokio::select!{biased;_=self.context.cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(50))=>{}}
                    }
                },
                event=receiver.recv()=>if matches!(event,Err(broadcast::error::RecvError::Closed)){break},
                _=&mut changed=>{},
            }
        }
        while jobs.next().await.is_some() {}
    }

    pub(super) async fn attach_shared_maintenance(self: Arc<Self>) {
        let bound = self.state.lock().await.bound.clone().unwrap_or_default();
        let mut failures = 0u32;
        loop {
            let changed = self.on_demand.attach_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let pending = {
                let entries = self
                    .on_demand
                    .resident
                    .read()
                    .unwrap_or_else(|error| error.into_inner());
                let mut seen = std::collections::HashSet::new();
                entries
                    .values()
                    .flatten()
                    .filter(|resident| {
                        resident.binding.source.is_some()
                            && resident.binding.slot.live()
                            && resident.group.get().is_none()
                            && seen.insert(Arc::as_ptr(resident) as usize)
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let results = stream::iter(pending)
                .map(|resident| {
                    let this = self.clone();
                    let bound = &bound;
                    async move {
                        if !this.on_demand.indexed(&resident) {
                            return Ok(());
                        }
                        this.attach_resident_group(resident, bound)
                            .await
                            .map(|_| ())
                    }
                })
                .buffer_unordered(8)
                .collect::<Vec<_>>()
                .await;
            if results.into_iter().any(|result| result.is_err()) {
                failures = failures.saturating_add(1);
                let _ = self.events.send(CertificateEvent {
                    kind: "certificate_maintenance_failed",
                    names: Vec::new(),
                });
                let delay =
                    cert_automation::retry_backoff(failures, &["resident-maintenance".into()]);
                tokio::select! {biased;_=self.context.cancel.cancelled()=>break,_=tokio::time::sleep(delay)=>{}}
            } else {
                failures = 0;
                tokio::select! {biased;_=self.context.cancel.cancelled()=>break,_=&mut changed=>{}}
            }
        }
    }
    pub(super) async fn restore_pending_cache(self: Arc<Self>) {
        let mut jobs = futures_util::stream::FuturesUnordered::new();
        let mut active = std::collections::HashSet::new();
        loop {
            let changed = self.on_demand.pending_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            while jobs.len() < 4096 {
                let pending = {
                    let mut queue = self
                        .on_demand
                        .pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let key = queue
                        .iter()
                        .find(|(_, pending)| !active.contains(&pending.entry.id))
                        .map(|(key, _)| *key);
                    key.and_then(|key| queue.remove(&key))
                };
                let Some(pending) = pending else {
                    break;
                };
                active.insert(pending.entry.id);
                let this = self.clone();
                jobs.push(async move {
                    let id = pending.entry.id;
                    let result = this.restore_pending_entry(pending).await;
                    (id, result)
                });
            }
            tokio::select! {biased;
                _=self.context.cancel.cancelled()=>break,
                Some((id,result))=jobs.next(),if !jobs.is_empty()=>{active.remove(&id);if result.is_err() && !self.context.cancel.is_cancelled(){let _=self.events.send(CertificateEvent{kind:"cached_certificate_restore_failed",names:Vec::new()});}},
                _=&mut changed=>{},
            }
        }
        while jobs.next().await.is_some() {}
    }
    async fn restore_pending_entry(self: Arc<Self>, pending: PendingRestore) -> Result<()> {
        let entry = pending.entry;
        let mut kind = pending.kind;
        loop {
            let Some(epoch) = self.cache_epoch.get().cloned() else {
                return Ok(());
            };
            let cache = self.context.resources.resident_cache.clone();
            let checking = entry.clone();
            let current = super::super::loaders::blocking(
                self.context.resources.cpu.clone(),
                self.context.cancel.clone(),
                move || cache.current(&epoch, &checking),
            )
            .await?;
            if !current {
                return Ok(());
            }
            if matches!(kind, PendingKind::Withdrawn) {
                let cache = self.context.resources.resident_cache.clone();
                let epoch = self.cache_epoch.get().unwrap().clone();
                let entry = entry.clone();
                super::super::loaders::blocking(
                    self.context.resources.cpu.clone(),
                    self.context.cancel.clone(),
                    move || {
                        cache.remove(&epoch, &entry)?;
                        Ok(())
                    },
                )
                .await?;
                return Ok(());
            }
            if self.policy_for_origin(&entry.origin)?.on_demand {
                return Ok(());
            }
            if let PendingKind::Future(not_before) = kind {
                let seconds = not_before.saturating_sub(now()?).clamp(0, 3600) as u64;
                if seconds > 0 {
                    tokio::select! {biased;
                        _=self.context.cancel.cancelled()=>return Ok(()),
                        _=entry.slot.retired()=>return Ok(()),
                        _=tokio::time::sleep(Duration::from_secs(seconds))=>{}
                    }
                    continue;
                }
                // Revalidate time/Guard locally before any publication or CA work.
                let material = entry.material.clone();
                let guard = self.context.leaf_guard.clone();
                kind = super::super::loaders::blocking(
                    self.context.resources.cpu.clone(),
                    self.context.cancel.clone(),
                    move || {
                        if let Some(revoked) = guard
                            .intern(material.leaf_id, material.times()?.1)?
                            .revocation()?
                        {
                            return Ok(if revoked.withdrawn {
                                PendingKind::Withdrawn
                            } else {
                                PendingKind::Revoked
                            });
                        }
                        Ok(match material.classify_at(now()?)? {
                            super::super::material::Validity::Current => PendingKind::Future(0),
                            super::super::material::Validity::Future(nb) => PendingKind::Future(nb),
                            super::super::material::Validity::Expired => PendingKind::Expired,
                        })
                    },
                )
                .await?;
                if matches!(kind, PendingKind::Future(0)) {
                    if self
                        .import_shared_entry(
                            self.cache_epoch.get().unwrap().clone(),
                            entry.clone(),
                            self.context.cancel.clone(),
                        )
                        .await?
                        && let Some(resident) = self.on_demand.resident(&entry.material.names[0])
                    {
                        let bound = self.state.lock().await.bound.clone().unwrap_or_default();
                        self.attach_resident_group(resident, &bound).await?;
                    }
                    return Ok(());
                }
                continue;
            }
            let bound = {
                let state = self.state.lock().await;
                if state.groups.values().any(|g| {
                    g.background.load(Ordering::Acquire)
                        && g.names.iter().any(|n| entry.material.names.contains(n))
                }) {
                    return Ok(());
                }
                state.bound.clone().unwrap_or_default()
            };
            let revoked = matches!(kind, PendingKind::Revoked);
            let group = self
                .seeded_group(entry.clone(), &bound, self.context.cancel.clone(), !revoked)
                .await?;
            if !revoked {
                return Ok(());
            }
            // A revoked cached leaf gets one forced replacement attempt; on
            // failure ensure_group marks the exact revocation withdrawn. Do not
            // keep a background retry alive for a certificate Go removed.
            match self
                .ensure_group(group.clone(), false, self.context.cancel.clone())
                .await
            {
                Ok(_) => {
                    group.restoring.store(false, Ordering::Release);
                    self.maintenance_changed.notify_one();
                    self.ocsp_manager(&group).await?;
                }
                Err(error) => {
                    group.cancel.cancel();
                    self.discard_failed_restore(group).await?;
                    let cache = self.context.resources.resident_cache.clone();
                    let epoch = self.cache_epoch.get().unwrap().clone();
                    let old = entry.clone();
                    super::super::loaders::blocking(
                        self.context.resources.cpu.clone(),
                        self.context.cancel.clone(),
                        move || {
                            cache.remove(&epoch, &old)?;
                            Ok(())
                        },
                    )
                    .await?;
                    return Err(error);
                }
            }
            return Ok(());
        }
    }
    async fn attach_resident_group(
        &self,
        resident: Arc<Resident>,
        bound: &[StagedAddress],
    ) -> Result<Arc<Group>> {
        let group = match resident.group.get() {
            Some(group) => group.clone(),
            None => {
                let group = self
                    .group_with_origin(
                        resident.material.names.clone(),
                        false,
                        bound,
                        self.context.cancel.child_token(),
                        resident.origin.clone(),
                    )
                    .await?;
                let _gate = tokio::select! {biased;
                    _=self.context.cancel.cancelled()=>return Err(anyhow!("certificate scope retired")),
                    guard=group.gate.lock()=>guard,
                };
                ensure!(
                    resident.binding.slot.live() && !group.cancel.is_cancelled(),
                    "certificate cache slot retired"
                );
                let mut binding = group
                    .residency
                    .lock()
                    .map_err(|_| anyhow!("certificate residency unavailable"))?;
                if let Some(actual) = binding.as_ref() {
                    ensure!(
                        Arc::ptr_eq(&actual.slot, &resident.binding.slot),
                        super::super::resident_cache::CacheChanged
                    );
                } else {
                    *binding = Some(resident.binding.clone());
                    group.renew_at.store(resident.renew_at, Ordering::Release);
                    group.ari_after.store(resident.ari_after, Ordering::Release);
                    *group.spki.lock().map_err(|_| anyhow!("certificate key state unavailable"))? =
                        Some(resident.material.spki_der.clone());
                    *group
                        .leaf_state
                        .lock()
                        .map_err(|_| anyhow!("certificate leaf state unavailable"))? =
                        Some(resident.leaf.clone());
                }
                drop(binding);
                drop(_gate);
                group
            }
        };
        self.ocsp_manager(&group).await?;
        let _ = resident.group.set(group.clone());
        Ok(group)
    }
    pub(super) async fn prepare_permission(&self, cancel: CancellationToken) -> Result<()> {
        self.permission
            .get_or_try_init(|| async {
                let setting = self.restore.as_ref().map_or_else(
                    || self.plan.permission.clone(),
                    |retained| retained.permission.clone(),
                );
                let Some(mut setting) = setting else {
                    return Ok(None);
                };
                if setting.legacy {
                    setting.endpoint = super::super::permission::HttpPermission::expand_legacy(
                        setting.endpoint,
                        self.context.resources.issuance.clone(),
                        cancel,
                    )
                    .await?;
                }
                Ok(Some(Arc::new(
                    super::super::permission::HttpPermission::new(
                        setting.endpoint,
                        self.context.resources.issuance.clone(),
                    )?,
                )))
            })
            .await
            .map(|_| ())
    }
    async fn on_demand_ensure(
        self: Arc<Self>,
        name: String,
        caller: CancellationToken,
    ) -> Result<()> {
        let name = cert_automation::normalize_names(&[name])?.remove(0);
        self.on_demand_ensure_request(name.clone(), name, false, None, None, None, caller)
            .await.map(|_| ())
    }
    async fn on_demand_ensure_request(
        self: Arc<Self>,
        origin: String,
        name: String,
        force_lookup: bool,
        cached: Option<AcquiredCertificate>,
        selection: Option<crate::http_runtime::WarmSelection>,
        hello: Option<crate::http_runtime::CertificateHello>,
        caller: CancellationToken,
    ) -> Result<Option<AcquiredCertificate>> {
        let name = match name.parse::<std::net::IpAddr>() {
            Ok(ip) => crate::tls_resolver::canonical_certificate_ip(ip),
            Err(_) => cert_automation::normalize_names(&[name])?.remove(0),
        };
        ensure!(
            !name.contains('*'),
            "wildcard is not a TLS client server name"
        );
        let policy = self.policy_for_origin(&origin)?;
        let typed = origin.is_empty() || name.parse::<std::net::IpAddr>().is_ok();
        let typed_allowed = self.policy_index(&origin)?.is_some()
            && policy.on_demand
            && policy.issuers.iter().any(|issuer|matches!(issuer,Issuer::Internal{..}));
        let at = now()?;
        if !force_lookup && cached.is_none() && self.on_demand.manual(&name, at) {
            return Ok(None);
        }
        let selected = if let Some(cached) = &cached {
            self.on_demand.resident_receipt(cached)
        } else {
            self.on_demand.resident_if(&name, |resident| resident.usable(at))
        };
        if !force_lookup
            && let Some(resident) = selected
        {
            let due = self.current_maintenance_at(&origin, &resident)?;
            let scheduled = resident.retry_after.load(Ordering::Acquire);
            let pending = resident.leaf.needs_renewal();
            if policy.on_demand
                && (!typed || typed_allowed)
                && (due <= at || pending)
                && scheduled <= at
                && resident
                    .retry_after
                    .compare_exchange(
                        scheduled,
                        at.saturating_add(1),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                && self.on_demand.active.load(Ordering::Acquire)
                && !self.context.cancel.is_cancelled()
            {
                // A valid resident certificate is returned immediately; ask is
                // only performed if a renewal becomes necessary in this job.
                let _ = self.start_flight(
                    name,
                    origin.clone(),
                    false,
                    Action::Maintenance,
                    true,
                    Some(resident.clone()),
                    selection.clone(),
                );
            }
            return Ok(None);
        }
        if !policy.managers.is_empty() {
            ensure!(self.on_demand.active.load(Ordering::Acquire), "certificate generation is not committed");
            let hello = hello.ok_or_else(|| anyhow!("external certificate manager requires ClientHello"))?;
            if let Some(certificate) = self.acquire_external(policy.clone(), name.clone(), hello,
                selection.clone(), caller.clone()).await? { return Ok(Some(certificate)); }
            let subjects=policy.subjects.get()?.names();
            let tailscale_only=!subjects.is_empty() && policy.issuers.is_empty()
                && subjects.iter().all(|name|name.to_ascii_lowercase().ends_with(".ts.net"))
                && policy.managers.iter().any(|manager|matches!(manager,super::super::external::Manager::Tailscale));
            ensure!(!tailscale_only,"Tailscale manager yielded no certificate and this policy has no issuer");
        }
        if typed {
            ensure!(
                typed_allowed,
                "typed on-demand acquisition requires an internal issuer policy"
            );
        }
        ensure!(
            self.on_demand.active.load(Ordering::Acquire),
            "certificate generation is not committed"
        );
        let permit = self
            .on_demand
            .waiters
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("on-demand waiter capacity exceeded"))?;
        self.owned(caller, move |this, token| {
            Box::pin(async move {
                let _permit = permit;
                let (flight, leader) =
                    this.start_flight(name, origin, force_lookup, Action::Miss, false, None, selection)?;
                let mut waiter = Waiter {
                    flight: flight.clone(),
                    state: this.on_demand.clone(),
                    released: false,
                };
                let result = tokio::select! { biased;
                    _=token.cancelled()=>None,
                    _=tokio::time::sleep(Duration::from_secs(if leader {180} else {120}))=>None,
                    result=flight_result(&flight)=>Some(result),
                };
                let cancelled_last = waiter.release();
                match result {
                    Some(result) => result.map_err(|error| anyhow!("{error}")),
                    None => {
                        // Last waiter stops and joins the actual leader. A cancelled
                        // follower leaves work needed by other handshakes running.
                        if cancelled_last {
                            let _ = flight_result(&flight).await;
                        }
                        Err(anyhow!("on-demand certificate wait cancelled or timed out"))
                    }
                }
            })
        })
        .await
    }
    fn start_flight(
        self: &Arc<Self>,
        name: String,
        origin: String,
        force_lookup: bool,
        action: Action,
        background: bool,
        target: Option<Arc<Resident>>,
        selection: Option<crate::http_runtime::WarmSelection>,
    ) -> Result<(Arc<Flight>, bool)> {
        let mut previous_owner:Option<(Arc<Flight>,bool)>=None;
        let mut admitted_task=None;
        let result=(|| {
        let _admission = self
            .admission
            .lock()
            .map_err(|_| anyhow!("certificate service admission unavailable"))?;
        ensure!(
            !*_admission && !self.context.cancel.is_cancelled(),
            "certificate services stopped"
        );
        let policy = self.policy_index(&origin)?;
        let mut flights = self
            .on_demand
            .flights
            .lock()
            .map_err(|_| anyhow!("on-demand flight state unavailable"))?;
        let predecessor = flights.get(&name).cloned();
        let stale=predecessor.as_ref().is_some_and(|p|p.residency.as_ref().is_some_and(|slot|!slot.live()));
        // Preserve the real last owner until admission/map guards are gone.
        previous_owner=predecessor.as_ref().map(|previous|(previous.clone(),stale));
        if let Some(flight) = &predecessor
            && !stale
            && match (&flight.target, &target) {
                (Some(previous), Some(current)) => previous.receipt.same_instance(&current.receipt),
                (None, None) => true,
                _ => false,
            }
            && flight.policy_index == policy
            && (!force_lookup || (flight.force_lookup && matches!(flight.action, Action::Miss)))
            && !flight.cancel.is_cancelled()
            && flight
                .result
                .lock()
                .map_err(|_| anyhow!("on-demand result unavailable"))?
                .is_none()
        {
            if !background {
                flight.waiters.fetch_add(1, Ordering::AcqRel);
            }
            return Ok((flight.clone(), false));
        }
        ensure!(
            predecessor.is_some() || flights.len() < 256,
            "on-demand queue capacity exceeded"
        );
        let admission = self
            .on_demand
            .flight_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("on-demand live flight capacity exceeded"))?;
        let target = if matches!(action, Action::Maintenance) {
            Some(target.or_else(|| self.on_demand.resident_if(&name,
                |resident| resident.usable(now().unwrap_or(i64::MAX))))
                .ok_or(super::super::resident_cache::CacheChanged)?)
        } else { None };
        // Warm replacement can itself retire its observed old slot (Merged).
        // It remains generation-owned through commit; the physical receipt CAS
        // rejects external displacement without cancelling our own publication.
        let residency = None;
        let flight = Arc::new(Flight {
            action,
            policy_index: policy,
            force_lookup,
            _admission: admission,
            residency,
            target,
            selection,
            cancel: self.context.cancel.child_token(),
            quiet: CancellationToken::new(),
            result: Mutex::new(None),
            done: tokio::sync::Notify::new(),
            waiters: AtomicUsize::new(usize::from(!background)),
            background,
        });
        flights.insert(name.clone(), flight.clone());
        // 只持前驱的 quiet latch，不持 Arc<Flight>，链内存不累积
        let prior = predecessor.map(|p| p.quiet.clone());
        let this = self.clone();
        let worker = flight.clone();
        admitted_task=Some(self.tasks.track_future(async move {
            use super::super::resident_cache::CacheChanged;
            let timeout = if matches!(action, Action::Maintenance) {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(180)
            };
            let deadline = tokio::time::Instant::now() + timeout;
            let retired = async {
                match &worker.residency {
                    Some(slot) => slot.retired().await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(retired);
            let prior_quiet = async move {
                if let Some(t) = prior {
                    t.cancelled().await
                }
            };
            tokio::pin!(prior_quiet);
            // 阶段1：只等前驱 quiet，自己的 cancel/retired/deadline 可立即退出
            let waited: Result<()> = tokio::select! { biased;
                _ = worker.cancel.cancelled() => Err(anyhow!("on-demand operation cancelled")),
                _ = &mut retired => { worker.cancel.cancel(); Err(CacheChanged.into()) },
                _ = tokio::time::sleep_until(deadline) => {
                    worker.cancel.cancel();
                    Err(anyhow!("on-demand acquisition deadline exceeded"))
                },
                _ = &mut prior_quiet => Ok(()),
            };
            let started = waited.is_ok();
            // One operation belongs to this actual Flight, not its resident
            // cache history. Its elapsed time includes all waits and retries.
            let mut retry_operation=cert_automation::retry_operation::RetryOperation::default();
            let result: Result<ActionOutcome> = match waited {
                Err(error) => Err(error),
                Ok(()) => {
                    // 阶段2：前驱已 quiet，排空只受本操作响应 cancel 的速度约束
                    let operation = std::panic::AssertUnwindSafe(this.on_demand_action(
                        &name,
                        &origin,
                        force_lookup,
                        action,
                        worker.target.as_ref(),
                        worker.selection.as_ref(),
                        worker.cancel.clone(),
                        matches!(action,Action::Maintenance).then_some(&mut retry_operation),
                    ))
                    .catch_unwind();
                    tokio::pin!(operation);
                    tokio::select! { biased;
                        _ = worker.cancel.cancelled() => {
                            let _ = operation.await;
                            Err(anyhow!("on-demand operation cancelled"))
                        },
                        _ = &mut retired => {
                            worker.cancel.cancel();
                            let _ = operation.await;
                            Err(CacheChanged.into())
                        },
                        _ = tokio::time::sleep_until(deadline) => {
                            worker.cancel.cancel();
                            let _ = operation.await;
                            Err(anyhow!("on-demand acquisition deadline exceeded"))
                        },
                        result = &mut operation =>
                            result.unwrap_or_else(|_| Err(anyhow!("on-demand worker panicked"))),
                    }
                }
            };
            if result.is_err()&&!retry_operation.wait().is_zero()
                &&let Some(target)=&worker.target {
                let seconds=retry_operation.wait().as_secs().saturating_add(1);
                target.retry_after.fetch_max(now().unwrap_or(i64::MAX)
                    .saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX)),Ordering::AcqRel);
            }
            let maintain = result.as_ref().is_ok_and(|outcome| outcome.maintain);
            let maintain_target = result.as_ref().ok()
                .and_then(|outcome| outcome.acquired.as_ref())
                .and_then(|acquired| this.on_demand.resident_receipt(acquired));
            if result.is_err() {
                let _ = this.events.send(CertificateEvent {
                    kind: "on_demand_failed",
                    names: vec![name.clone()],
                });
            }
            let outcome = result
                .map(|outcome| outcome.acquired)
                .map_err(|e| Arc::<str>::from(e.to_string()));
            *worker.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
            worker.done.notify_waiters(); // waiter 立即拿到结果
            // 未启动：留在 map（不可 join）作为前驱代理，直到前驱链 quiet
            if !started {
                prior_quiet.await;
            }
            worker.quiet.cancel();
            {
                let mut flights = this
                    .on_demand
                    .flights
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if flights.get(&name).is_some_and(|c| Arc::ptr_eq(c, &worker)) {
                    flights.remove(&name);
                }
            }
            if maintain && maintain_target.is_some() {
                let _ = this.start_flight(
                    name.clone(),
                    origin.clone(),
                    false,
                    Action::Maintenance,
                    true,
                    maintain_target,
                    worker.selection.clone(),
                );
            }
        }));
        Ok((flight, true))
        })();
        if let Some(task)=admitted_task {tokio::spawn(task);}
        if let Some((previous,stale))=previous_owner {
            if stale { previous.cancel.cancel(); }
            drop(previous);
        }
        result
    }

    async fn on_demand_action(
        self: &Arc<Self>,
        name: &str,
        origin: &str,
        force_lookup: bool,
        action: Action,
        target: Option<&Arc<Resident>>,
        selection: Option<&crate::http_runtime::WarmSelection>,
        cancel: CancellationToken,
        retry_operation:Option<&mut cert_automation::retry_operation::RetryOperation>,
    ) -> Result<ActionOutcome> {
        let resident = if let Some(resident) = target {
            ensure!(resident.binding.slot.live(), super::super::resident_cache::CacheChanged);
            Some(resident.clone())
        } else { self.on_demand.resident(name) };
        if !force_lookup && matches!(action, Action::Miss) && self.on_demand.cached(name) {
            return Ok(ActionOutcome::cached());
        }
        if !force_lookup
            && matches!(action, Action::Miss)
            && self.import_shared_name(name, cancel.clone()).await?
        {
            return Ok(ActionOutcome::cached());
        }
        if force_lookup && matches!(action, Action::Miss)
            && let Some(selection) = selection
            && let Some(acquired) = self.import_shared_selected(name, selection, cancel.clone()).await?
        {
            return Ok(ActionOutcome { maintain: false, acquired: Some(acquired) });
        }
        let policy = self.policy_for_origin(origin)?;
        if !policy.on_demand {
            ensure!(
                matches!(action, Action::Miss)
                    && self.on_demand.almost_full(self.plan.cache_capacity),
                "certificate is not resident and on-demand acquisition is not enabled"
            );
            let bound = self
                .state
                .lock()
                .await
                .bound
                .clone()
                .ok_or_else(|| anyhow!("candidate listener plan missing"))?;
            let group = self
                .storage_probe_group(vec![name.to_owned()], &bound, cancel.clone())
                .await?;
            let loaded = self.probe_group(group.clone(), cancel.clone()).await;
            if loaded.is_err() || !self.on_demand.cached(name) {
                self.discard_storage_probe(group).await?;
                loaded?;
                return Err(anyhow!(
                    "certificate storage cache missed without on-demand issuance"
                ));
            }
            group.background.store(true, Ordering::Release);
            self.ocsp_manager(&group).await?;
            self.maintenance_changed.notify_one();
            return Ok(ActionOutcome { maintain: false,
                acquired: Some(self.acquired_group(&group, name, cancel.clone()).await?) });
        }
        if matches!(action, Action::Maintenance)
            && let Some(resident) = &resident
            && self.policy_index(&resident.origin)? == self.policy_index(origin)?
            && resident.group.get().is_none_or(|group|
                group.publication.lock().is_ok_and(|receipt| receipt.as_ref()
                    .is_some_and(|receipt| receipt.same_instance(&resident.receipt))))
        {
            let group = if let Some(group) = resident.group.get().cloned() {
                group
            } else {
                let bound = self
                    .state
                    .lock()
                    .await
                    .bound
                    .clone()
                    .ok_or_else(|| anyhow!("candidate listener plan missing"))?;
                self.attach_resident_group(resident.clone(), &bound).await?
            };
            if matches!(group.issuer, GroupIssuer::Acme(_)) {
                if let Some(renew_at) = self.refresh_cached_schedule(&group, cancel.clone()).await?
                {
                    let pending = group
                        .leaf_state
                        .lock()
                        .map_err(|_| anyhow!("certificate leaf state unavailable"))?
                        .as_ref()
                        .is_some_and(|leaf| leaf.needs_renewal());
                    if renew_at > now()? && !pending {
                        resident
                            .next_check
                            .store(next_check(&group, now()?), Ordering::Release);
                        return Ok(ActionOutcome::cached());
                    }
                }
            } else if !resident.leaf.needs_renewal()
                && self.current_renewal_time(&resident.material, &policy,resident.kind)? > now()? {
                resident
                    .next_check
                    .store(next_check(&group, now()?), Ordering::Release);
                return Ok(ActionOutcome::cached());
            }
        }
        if let Some(permission) = self
            .permission
            .get()
            .and_then(|permission| permission.as_ref())
            && let Err(error) = permission.check(name.to_owned(), cancel.clone()).await
        {
            if matches!(action, Action::Maintenance)
                && let Some(resident) = resident
            {
                self.evict_resident(resident, cancel.clone()).await?;
            }
            return Err(error);
        }
        ensure!(!cancel.is_cancelled(), "on-demand operation cancelled");
        let bound = self
            .state
            .lock()
            .await
            .bound
            .clone()
            .ok_or_else(|| anyhow!("candidate listener plan is missing"))?;
        let seed = if matches!(action, Action::Miss) && resident
            .as_ref()
            .is_none_or(|resident| resident.group.get().is_none())
        {
            if let Some(epoch) = self.cache_epoch.get() {
                if let Some(entry) = self
                    .shared_entry(epoch.clone(), name, cancel.clone())
                    .await?
                {
                    let leaf = self
                        .context
                        .leaf_guard
                        .intern(entry.material.leaf_id, entry.material.times()?.1)?;
                    leaf.pending_revocation()?.map(|_| entry)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let seeded = seed.is_some();
        let group = self
            .authorized_on_demand_group(
                vec![name.to_owned()],
                &bound,
                cancel.clone(),
                origin.to_owned(),
                seed,
            )
            .await?;
        let target=if matches!(action,Action::Maintenance){
            resident.as_ref().map(|resident|RenewalTarget{material:resident.material.clone(),receipt:resident.receipt.clone(),
                binding:resident.binding.clone(),leaf:resident.leaf.clone(),selection:selection.cloned()})
        }else{None};
        let acquired=if let Some(operation)=retry_operation {
            self.ensure_group_target_with_operation(group.clone(),false,target,cancel.clone(),operation).await
        }else{
            self.ensure_group_target(group.clone(),matches!(action,Action::Miss)&&!seeded,target,cancel.clone()).await
        };
        if let Err(error)=acquired
        {
            if seeded {
                self.discard_failed_restore(group).await?;
            } else {
                self.discard_failed_on_demand(group).await?;
            }
            return Err(error);
        }
        if seeded {
            group.restoring.store(false, Ordering::Release);
        }
        self.ocsp_manager(&group).await?;
        let due = group.renew_at.load(Ordering::Acquire) <= now()?;
        Ok(ActionOutcome {
            maintain: matches!(action, Action::Miss) && due,
            acquired: Some(self.acquired_group(&group, name, cancel).await?),
        })
    }
    async fn acquired_group(
        &self,
        group: &Arc<Group>,
        subject: &str,
        cancel: CancellationToken,
    ) -> Result<AcquiredCertificate> {
        let _gate = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(anyhow!("certificate acquisition cancelled")),
            _ = group.cancel.cancelled() => return Err(anyhow!("certificate scope retired")),
            gate = group.gate.lock() => gate,
        };
        let binding = group.residency.lock()
            .map_err(|_| anyhow!("certificate residency unavailable"))?.clone()
            .ok_or_else(|| anyhow!("acquired certificate residency missing"))?;
        let receipt = group.publication.lock()
            .map_err(|_| anyhow!("certificate publication unavailable"))?.clone()
            .ok_or_else(|| anyhow!("acquired certificate publication missing"))?;
        ensure!(binding.slot.live(), super::super::resident_cache::CacheChanged);
        ensure!(binding.receipt.as_ref().is_none_or(|physical| physical.chain == receipt.identity()),
            super::super::resident_cache::CacheChanged);
        Ok(AcquiredCertificate { subject: subject.to_owned(), receipt, slot: binding.slot, external: None })
    }

    async fn evict_resident(
        &self,
        resident: Arc<Resident>,
        cancel: CancellationToken,
    ) -> Result<()> {
        if !resident.binding.slot.live() {
            return self.sweep_resident(resident, cancel).await;
        }
        let group = {
            let state = self.state.lock().await;
            state.groups.values().find(|group| {
                resident.receipt.owned_by(&group.scope)
                    && group.publication.lock().is_ok_and(|publication|
                        publication.as_ref().is_some_and(|receipt| receipt.same_instance(&resident.receipt)))
                    && group.residency.lock().is_ok_and(|binding|
                        binding.as_ref().is_some_and(|binding|
                            Arc::ptr_eq(&binding.slot, &resident.binding.slot)))
            }).cloned()
        };
        let key = group.as_ref().map(|group| group.key.clone()).unwrap_or_default();
        // A concurrent renewal of this Group can replace the receipt. Wait
        // for its actual publication before checking any cleanup authority.
        let gate = if let Some(group) = &group {
            Some(tokio::select! { biased;
                _=cancel.cancelled()=>return Err(anyhow!("certificate removal cancelled")),
                gate=group.gate.lock()=>gate,
            })
        } else {
            None
        };
        let resolver = self.context.resolver.clone();
        let cache = self.context.resources.resident_cache.clone();
        let epoch = self.cache_epoch.get().cloned();
        let state = self.on_demand.clone();
        let evicted = resident.clone();
        ensure!(!cancel.is_cancelled(), "certificate removal cancelled");
        let (removed, cache_failed) = crate::cert_cpu::run_committed(
            self.context.resources.cpu.clone(),
            self.context.cancel.child_token(),
            move || {
                let removed = resolver.remove_scoped(&evicted.scope, &evicted.receipt)?;
                let cache_failed =
                    if removed && let (Some(epoch), Some(entry)) = (&epoch, &evicted.cache_entry) {
                        cache.remove(epoch, entry).is_err()
                    } else {
                        false
                    };
                if removed {
                    evicted.binding.slot.retire();
                    state
                        .capacity
                        .remove(&evicted.binding);
                }
                // The old exact receipt is now absent even if another scope
                // already replaced it. Retire only this local index entry; a
                // stale denial has no authority over the shared winner.
                state.unindex(&evicted);
                Ok((removed, cache_failed))
            },
        )
        .await?;
        if cache_failed {
            let _ = self.events.send(CertificateEvent {
                kind: "certificate_cache_remove_failed",
                names: resident.material.names.clone(),
            });
        }
        let (detached, ocsp) = {
            let mut state = self.state.lock().await;
            state
                .material
                .retain(|item| item.identity || !Arc::ptr_eq(&item.material, &resident.material));
            let owns = state.groups.get(&key).is_some_and(|current| {
                group
                    .as_ref()
                    .is_some_and(|group| Arc::ptr_eq(current, group))
                    && current.publication.lock().is_ok_and(|publication| {
                        publication
                            .as_ref()
                            .is_some_and(|receipt| receipt.same_instance(&resident.receipt))
                    })
            });
            if owns {
                if let Some(group) = state.groups.get(&key) {
                    group.cancel.cancel();
                }
                (state.groups.remove(&key), state.ocsp.remove(&key))
            } else {
                (None, None)
            }
        };
        drop(gate);
        let (a, b) = tokio::join!(
            async {
                if let Some(group) = detached {
                    self.stop_group(group).await
                } else {
                    Ok(())
                }
            },
            async {
                if let Some(scope) = ocsp {
                    scope.stop().await
                } else {
                    Ok(())
                }
            },
        );
        a?;
        b?;
        if !removed && !resident.binding.slot.live() {
            // The exact receipt may have changed while its slot was retired.
            // Join whichever Group still owns that dead slot before sweeping
            // either resolver owner, just as for a normal cache eviction.
            return self
                .sweep_resident(resident, self.context.cancel.child_token())
                .await;
        }
        Ok(())
    }

    async fn sweep_resident(
        &self,
        resident: Arc<Resident>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let slot = resident.binding.slot.clone();
        let names = resident.material.names.clone();
        let key = {
            let state = self.state.lock().await;
            state.groups.values().find(|group| {
                resident.receipt.owned_by(&group.scope)
                    && group.publication.lock().is_ok_and(|publication|
                        publication.as_ref().is_some_and(|receipt| receipt.same_instance(&resident.receipt)))
                    && group.residency.lock().is_ok_and(|binding|
                        binding.as_ref().is_some_and(|binding| Arc::ptr_eq(&binding.slot, &slot)))
            }).map(|group| group.key.clone()).unwrap_or_default()
        };
        let owner = resident.scope.clone();
        let (group, ocsp) = {
            let mut state = self.state.lock().await;
            state
                .material
                .retain(|item| item.identity || !Arc::ptr_eq(&item.material, &resident.material));
            let owns = state.groups.get(&key).is_some_and(|group| {
                group.residency.lock().is_ok_and(|binding| {
                    binding
                        .as_ref()
                        .is_some_and(|binding| Arc::ptr_eq(&binding.slot, &slot))
                })
            });
            if owns {
                if let Some(group) = state.groups.get(&key) {
                    group.cancel.cancel();
                }
                (state.groups.remove(&key), state.ocsp.remove(&key))
            } else {
                (None, None)
            }
        };
        let group_owner = group.as_ref().map(|group| group.scope.clone());
        let (a, b) = tokio::join!(
            async {
                if let Some(group) = group {
                    self.stop_group(group).await
                } else {
                    Ok(())
                }
            },
            async {
                if let Some(scope) = ocsp {
                    scope.stop().await
                } else {
                    Ok(())
                }
            },
        );
        a?;
        b?;
        let resolver = self.context.resolver.clone();
        super::super::loaders::blocking(self.context.resources.cpu.clone(), cancel, move || {
            resolver.sweep_retired(&owner, &slot, &names)?;
            if let Some(group_owner) = group_owner {
                // An import can transfer the slot to a Group just before it
                // is retired. Both owners are exact and the Group has joined.
                resolver.sweep_retired(&group_owner, &slot, &names)?;
            }
            Ok(())
        })
        .await?;
        self.on_demand.unindex(&resident);
        self.on_demand
            .capacity
            .remove(&resident.binding);
        self.maintenance_changed.notify_one();
        Ok(())
    }
    pub(super) async fn publish_group(
        &self,
        group: &Arc<Group>,
        material: Arc<Material>,
        renew_at: i64,
        ari_after: i64,
        intent: PublishIntent,
        cancel: CancellationToken,
        lease: Option<&crate::certstore::StorageLease>,
    ) -> Result<()> {
        let selected_class=group.selected_class()?;
        let selected_kind=group.selected_kind()?;
        self.prime_material_status(material.clone(), group.identity, cancel.clone()).await?;
        reject_revoked(&material, &self.context.leaf_guard, true)?;
        if let Some(lease) = lease {
            lease.check().await?;
        }
        // Candidate groups perform storage and crypto work in parallel. The
        // eventual snapshot write is one per resolver; avoiding speculative
        // duplicate whole-inventory copies here keeps large cold loads bounded.
        let _candidate_write = if self.on_demand.active.load(Ordering::Acquire) {
            None
        } else {
            Some(tokio::select! {biased;
                _=cancel.cancelled()=>return Err(anyhow!("candidate certificate publication cancelled")),
                lock=self.staged_publication.lock()=>lock,
            })
        };
        let lost = lease.map(crate::certstore::StorageLease::lost);
        let mut last = None;
        for attempt in 0..4 {
            let selected_class = selected_class.clone();
            let work_group = group.clone();
            let material = material.clone();
            let work_intent = intent.clone();
            let lost = lost.clone();
            let state = self.on_demand.clone();
            let cache = self.context.resources.resident_cache.clone();
            let epoch = self.cache_epoch.get().cloned();
            let capacity = self.plan.cache_capacity;
            let leaf_guard = self.context.leaf_guard.clone();
            let publication_cancel = cancel.clone();
            let changed = self.maintenance_changed.clone();
            let result = crate::cert_cpu::run_committed(
                self.context.resources.cpu.clone(),
                cancel.clone(),
                move || {
                    let selected_class=selected_class;
                    // Must outlive every resolver/capacity/cache lock in this
                    // publication, including an unwinding post-commit error.
                    let mut preparation_publication =
                        super::super::resident_cache::PreparationPublication::default();
                    let group = work_group;
                    material.validate_at(now()?, false)?;
                    leaf_guard.key_deny().check_spki_der(&material.spki_der)?;
                    let leaf = leaf_guard.intern(material.leaf_id, material.times()?.1)?;
                    ensure!(
                        leaf.revocation()?.is_none(),
                        "managed certificate is revoked"
                    );
                    let active = || {
                        !publication_cancel.is_cancelled()
                            && !group.cancel.is_cancelled()
                            && lost.as_ref().is_none_or(|lease| !lease.is_cancelled())
                    };
                    ensure!(active(), "certificate publication cancelled");
                    let input = CertificateInput {
                        names: &material.names,
                        certificate_pem: &material.certificate,
                        private_key_pem: &material.key,
                    };
                    let warm_selection = match &work_intent {
                        PublishIntent::ReplaceTarget { selection, .. }
                        | PublishIntent::WarmInsert { selection } => selection.as_ref(),
                        _ => None,
                    };
                    if let Some(selection) = warm_selection {
                        ensure!(group.resolver.candidate_allowed(&input, &material.tags,
                            selection.filter.as_deref(), &selection.schemes, selection.version)?,
                            "managed warm certificate does not satisfy connection selection");
                    }
                    if group.identity {
                        let result = group.resolver.upsert_checked(&input, &publication_cancel, || {
                            ensure!(active(), "certificate publication cancelled");
                            Ok(())
                        });
                        if result.is_ok() {
                            preparation_publication.accepted(material.preparation.as_ref());
                            changed.notify_one();
                        }
                        return result;
                    }
                    let previous = group
                        .residency
                        .lock()
                        .map_err(|_| anyhow!("certificate residency unavailable"))?
                        .clone();
                    ensure!(
                        previous.as_ref().is_none_or(|binding| binding.slot.live()),
                        super::super::resident_cache::CacheChanged
                    );
                    let physical_previous = match &work_intent {
                        PublishIntent::Insert | PublishIntent::WarmInsert { .. } => None,
                        PublishIntent::Renew { old } | PublishIntent::ReplaceTarget { old, .. } => Some(old),
                    };
                    let ledger_previous = match &work_intent {
                        PublishIntent::ReplaceTarget { binding, .. } => Some(binding),
                        PublishIntent::Renew { .. } => previous.as_ref(),
                        PublishIntent::Insert | PublishIntent::WarmInsert { .. } => None,
                    };
                    let cache_binding = match &work_intent {
                        PublishIntent::ReplaceTarget { binding, .. } => Some(binding),
                        _ => previous.as_ref(),
                    };
                    let plan = if let Some(epoch) = &epoch
                        && cache_binding.is_none_or(|binding| binding.source.is_some())
                    {
                        cache.plan(
                            epoch,
                            super::super::resident_cache::Revision {
                                material: material.clone(),
                                issuer: selected_class.text.clone(),
                                kind:selected_kind,
                                renew_at,
                                ari_after,
                                origin: group.origin.clone(),
                            },
                            crate::tls_resolver::MAX_CERTIFICATES,
                        physical_previous,
                        )?
                    } else {
                        None
                    };
                    let cached = plan.as_ref().map(|plan| plan.entry.clone());
                    let target_exists = match plan.as_ref() {
                        Some(plan) => match plan.effect() {
                            super::super::resident_cache::Effect::Same => true,
                            super::super::resident_cache::Effect::Merged { retired } => {
                                ensure!(retired != plan.entry.id, super::super::resident_cache::CacheChanged);
                                true
                            }
                            _ => false,
                        },
                        None => false,
                    };
                    let physical_receipt = plan.as_ref().map(|plan| plan.receipt());
                    let material = cached.as_ref().map_or(material, |entry| entry.material.clone());
                    let (renew_at, ari_after) = cached.as_ref()
                        .map_or((renew_at, ari_after), |entry| (entry.renew_at, entry.ari_after));
                    let borrowed = if target_exists {
                        cached.as_ref().and_then(|entry| state.resident_if(&material.names[0], |resident| {
                            resident.material.identity == material.identity
                                && resident.receipt.identity() == material.identity
                                && resident.binding.receipt.as_ref().is_some_and(|receipt| receipt.is(entry))
                        }))
                    } else { None };
                    let mut binding = borrowed.as_ref().map(|resident| resident.binding.clone())
                        .or_else(|| cached.as_ref().map(|entry| {
                            previous.as_ref().filter(|binding| binding.projects(&entry))
                                .cloned().unwrap_or_else(|| ResidencyBinding::shared(entry))
                        }))
                        .or_else(|| previous.clone()).unwrap_or_else(ResidencyBinding::local);
                    if physical_receipt.is_some() { binding.receipt = physical_receipt; }
                    let receipt = if let Some(borrowed) = &borrowed {
                        let receipt = group.resolver.with_current_receipt(
                            &borrowed.receipt, &binding.slot, &publication_cancel,
                            || {
                                ensure!(active(), "certificate acquisition cancelled");
                                let plan = plan.ok_or_else(|| anyhow!("missing borrowed cache plan"))?;
                                if ledger_previous.is_none() {
                                    return state.capacity.reuse(&binding, || {
                                        cache.commit_prepared(plan, None, &mut preparation_publication)
                                    });
                                }
                                if state.capacity.admit(&material.names, &binding, ledger_previous,
                                    capacity, |victim| {
                                        cache.commit_prepared(plan, shared_victim(victim),
                                            &mut preparation_publication)
                                    })? {
                                    state.cleanup_changed.notify_one();
                                }
                                Ok(true)
                            },
                        )?;
                        receipt.ok_or(super::super::resident_cache::CacheChanged)?
                    } else {
                        let input = CertificateInput {
                            names: &material.names,
                            certificate_pem: &material.certificate,
                            private_key_pem: &material.key,
                        };
                        group.resolver.upsert_resident(
                            &input, &group.scope, &binding.slot, &publication_cancel,
                            || {
                                ensure!(active(), "certificate acquisition cancelled");
                                if state.capacity.admit(&material.names, &binding, ledger_previous,
                                    capacity, |victim| {
                                        let victim = shared_victim(victim);
                                        if let Some(plan) = plan {
                                            cache.commit_prepared(plan, victim,
                                                &mut preparation_publication)?;
                                        } else if let Some(epoch) = &epoch {
                                            cache.retire_projection(epoch, victim)?;
                                        }
                                        Ok(())
                                    })? {
                                    state.cleanup_changed.notify_one();
                                }
                                Ok(())
                            },
                        ).map_err(|error| {
                            if active() && publication_displaced(&error, &binding.slot) {
                                super::super::resident_cache::CacheChanged.into()
                            } else { error }
                        })?
                    };
                    // A local projection has no physical-cache commit hook.
                    // Reaching this point means the resolver accepted this
                    // exact material; retained deduplicated candidates are not
                    // marked merely because they shared a chain identity.
                    preparation_publication.accepted(material.preparation.as_ref());
                    *group
                        .residency
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = Some(binding.clone());
                    *group
                        .publication
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = Some(receipt.clone());
                    group.renew_at.store(renew_at, Ordering::Release);
                    group.ari_after.store(ari_after, Ordering::Release);
                    // Same/Merged target already has one exact resident projection.
                    // Preserve its original receipt, schedule, index order and OCSP context.
                    if borrowed.is_none() {
                        state.record(group.clone(), material, receipt, cached, binding.clone(), leaf,selected_kind);
                    }
                    changed.notify_one();
                    if !binding.slot.live() {
                        state.cleanup_changed.notify_one();
                        return Err(super::super::resident_cache::CacheChanged.into());
                    }
                    Ok(())
                },
            )
            .await;
            match result {
                Err(error)
                    if error.is::<super::super::resident_cache::CacheChanged>()
                        && group.residency.lock().is_ok_and(|binding| {
                            binding.as_ref().is_some_and(|binding| !binding.slot.live())
                        }) =>
                {
                    // A retired projection cannot win a retry. Preserve the
                    // typed displacement for precommit/maintenance callers.
                    return Err(error);
                }
                Err(error)
                    if error.is::<CertificatePublicationConflict>()
                        || error.is::<super::super::resident_cache::CacheChanged>() =>
                {
                    last = Some(error);
                }
                Ok(()) => {
                    if let PublishIntent::Renew { old } | PublishIntent::ReplaceTarget { old, .. } = &intent {
                        self.state.lock().await.material.retain(|item|
                            item.identity || item.material.identity != old.chain);
                    }
                    if !group.identity && !group.cache_event_emitted.swap(true,Ordering::AcqRel) {
                        crate::cert_events::cached(self.context.events.as_ref(),true,&group.names,&cancel).await;
                    }
                    return Ok(());
                }
                result => return result,
            }
            if attempt < 3 {
                tokio::select! {biased;
                    _=cancel.cancelled()=>return Err(anyhow!("certificate publication cancelled")),
                    _=tokio::time::sleep(Duration::from_millis(5_u64 << attempt))=>{},
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("certificate publication retry budget exhausted")))
    }
}
fn publication_displaced(error: &anyhow::Error, slot: &CertificateResidency) -> bool {
    !slot.live()
        && (error.is::<CertificateResidencyRetired>()
            || error.is::<CertificatePublicationConflict>())
}
fn shared_victim<'a>(
    victim: Option<(&'a [String], &'a ResidencyBinding)>,
) -> Option<(&'a [String], &'a Arc<CertificateResidency>)> {
    victim.and_then(|(names, binding)| binding.source.as_ref().map(|source| (names, source)))
}
fn next_check(group: &Group, at: i64) -> i64 {
    group
        .renew_at
        .load(Ordering::Acquire)
        .min(group.ari_after.load(Ordering::Acquire))
        .max(at.saturating_add(1))
}
async fn flight_result(flight: &Flight) -> Outcome {
    loop {
        let changed = flight.done.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if let Some(result) = flight
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
        {
            return result;
        }
        changed.await;
    }
}

fn issuer_class(policy: &Policy) -> String {
    match policy.issuers.as_slice() {
        [Issuer::Internal { ca, .. }] => ca.clone(),
        _ => String::new(),
    }
}

// Payloads precede their temporary-copy allowance, including unpolled work.
struct RegistrationInput {
    names:Vec<Vec<String>>,
    plan:Arc<CertificatePlan>,
    cancel:CancellationToken,
    _memory:crate::acme_wire::chain_memory::Scratch,
}
impl RegistrationInput {
    fn execute(self)->Result<super::super::resident_cache::RegisteredIssuerClasses> {
        use super::super::resident_cache::{IssuerClasses,RegisteredIssuerClasses};
        let input=self;
        let policies=input.plan.policies.len();
        let _slots=crate::cert_transient::reserve((policies+2)*std::mem::size_of::<Arc<IssuerClasses>>()+128)?;
        let mut sets=Vec::new();sets.try_reserve_exact(policies).map_err(|_|crate::cert_transient::ResourceDenied)?;
        for policy in &input.plan.policies {
            ensure!(!input.cancel.is_cancelled(),"certificate registration cancelled");
            let mut values=["";16];let mut n=0;
            if policy.issuers.is_empty(){n=1}else{
                ensure!(policy.issuers.len()<=16,"issuer class count exceeds bounds");
                for issuer in &policy.issuers {values[n]=match issuer{Issuer::Acme(_)=>"",Issuer::Internal{ca,..}=>ca};n+=1;}
            }
            sets.push(IssuerClasses::new(&values[..n])?);
        }
        let public=IssuerClasses::new(&[""])?;let internal=IssuerClasses::new(&["local"])?;
        let mut count=0usize;let mut text=0usize;let mut longest_name=0usize;
        for name in input.names.iter().flatten(){count=count.checked_add(1).ok_or(crate::cert_transient::ResourceDenied)?;
            text=text.checked_add(name.len()).ok_or(crate::cert_transient::ResourceDenied)?;longest_name=longest_name.max(name.len());}
        let mut longest_pattern=0usize;
        for policy in &input.plan.policies {
            longest_pattern=longest_pattern.max(policy.subjects.get()?.names().iter().map(String::len).max().unwrap_or(0));
        }
        let _matcher=crate::cert_transient::reserve(longest_name.checked_add(longest_pattern)
            .and_then(|n|n.checked_mul(32)).and_then(|n|n.checked_add(16384)).ok_or(crate::cert_transient::ResourceDenied)?)?;
        let bytes=count.checked_next_power_of_two().unwrap_or(1).max(4)
            .checked_mul(2*(std::mem::size_of::<String>()+std::mem::size_of::<Arc<IssuerClasses>>()+16))
            .and_then(|n|n.checked_add(text)).and_then(|n|n.checked_add(256)).ok_or(crate::cert_transient::ResourceDenied)?;
        let memory=crate::cert_transient::reserve(bytes)?;
        let mut map=HashMap::new();map.try_reserve(count).map_err(|_|crate::cert_transient::ResourceDenied)?;
        for (i,name) in input.names.iter().flatten().enumerate(){
            if i%128==0{ensure!(!input.cancel.is_cancelled(),"certificate registration cancelled");}
            let mut index=None;
            for (i,policy) in input.plan.policies.iter().enumerate() {
                let subjects=policy.subjects.get()?.names();
                if subjects.is_empty() || subjects.iter().any(|pattern|matches_subject(name,pattern)) { index=Some(i); break; }
            }
            let set=if let Some(index)=index{sets[index].clone()}
                else if super::group::internal_name(name){internal.clone()}else{public.clone()};
            map.insert(name.clone(),set);
        }
        Ok(RegisteredIssuerClasses{map,memory})
    }
}
