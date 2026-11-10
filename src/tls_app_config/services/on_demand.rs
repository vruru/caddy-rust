//! Generation-owned on-demand acquisition. Admission is separate from CA and
//! CPU budgets, so queued handshakes cannot consume a permit needed by proofs.
use super::*;
use crate::http_runtime::ScopedCertificateProvider;
use futures_util::{FutureExt, future::BoxFuture};
use std::sync::{Weak, atomic::AtomicUsize};

type Outcome = std::result::Result<(), Arc<str>>;
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
    _admission: tokio::sync::OwnedSemaphorePermit,
    residency: Option<Arc<CertificateResidency>>,
    cancel: CancellationToken,
    result: Mutex<Option<Outcome>>,
    done: tokio::sync::Notify,
    waiters: AtomicUsize,
    background: bool,
}
pub(super) struct OnDemand {
    pub(super) active: AtomicBool,
    pending: Mutex<HashMap<[u8; 32], PendingRestore>>,
    pending_changed: tokio::sync::Notify,
    resident: arc_swap::ArcSwap<HashMap<String, Vec<Arc<Resident>>>>,
    manual: arc_swap::ArcSwap<HashMap<String, Vec<Arc<Material>>>>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    flight_slots: Arc<tokio::sync::Semaphore>,
    waiters: Arc<tokio::sync::Semaphore>,
    cleanup_changed: tokio::sync::Notify,
    cache_receiver: AsyncMutex<Option<broadcast::Receiver<u64>>>,
    local_slots: Mutex<HashMap<Vec<String>, Arc<CertificateResidency>>>,
    attach_changed: tokio::sync::Notify,
}
impl OnDemand {
    pub(super) fn new(receiver: broadcast::Receiver<u64>) -> Self {
        Self {
            active: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            pending_changed: tokio::sync::Notify::new(),
            cleanup_changed: tokio::sync::Notify::new(),
            cache_receiver: AsyncMutex::new(Some(receiver)),
            local_slots: Mutex::new(HashMap::new()),
            attach_changed: tokio::sync::Notify::new(),
            resident: arc_swap::ArcSwap::from_pointee(HashMap::new()),
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
        let entries = self.resident.load();
        let select = |name: &str| {
            entries.get(name).and_then(|residents| {
                residents
                    .iter()
                    .rev()
                    .find(|resident| resident.binding.slot.live() && predicate(resident))
                    .cloned()
            })
        };
        select(name).or_else(|| {
            name.split_once('.')
                .and_then(|(_, rest)| select(&format!("*.{rest}")))
        })
    }
    fn index(&self, resident: &Arc<Resident>) {
        self.resident.rcu(|previous| {
            let mut next = previous.as_ref().clone();
            for name in &resident.material.names {
                let candidates = next.entry(name.clone()).or_default();
                candidates
                    .retain(|prior| !Arc::ptr_eq(&prior.binding.slot, &resident.binding.slot));
                candidates.push(resident.clone());
            }
            Arc::new(next)
        });
    }
    fn unindex(&self, resident: &Arc<Resident>) {
        self.resident.rcu(|previous| {
            let mut next = previous.as_ref().clone();
            for name in &resident.material.names {
                if let Some(candidates) = next.get_mut(name) {
                    candidates.retain(|current| !Arc::ptr_eq(current, resident));
                    if candidates.is_empty() {
                        next.remove(name);
                    }
                }
            }
            Arc::new(next)
        });
    }
    fn indexed(&self, resident: &Arc<Resident>) -> bool {
        self.resident
            .load()
            .get(&resident.material.names[0])
            .is_some_and(|candidates| {
                candidates
                    .iter()
                    .any(|current| Arc::ptr_eq(current, resident))
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
            || name
                .split_once('.')
                .is_some_and(|(_, rest)| valid(entries.get(&format!("*.{rest}"))))
    }
    pub(super) fn references_group(&self, group: &Arc<Group>) -> bool {
        self.resident.load().values().flatten().any(|resident| {
            resident
                .group
                .get()
                .is_some_and(|actual| Arc::ptr_eq(actual, group))
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
    fn cached(&self, name: &str) -> bool {
        let Ok(at) = now() else { return false };
        self.manual(name, at)
            || self
                .resident_if(name, |resident| resident.usable(at))
                .is_some()
    }
    fn admit_local(
        &self,
        names: &[String],
        slot: &Arc<CertificateResidency>,
        capacity: usize,
    ) -> Result<()> {
        let mut slots = self
            .local_slots
            .lock()
            .map_err(|_| anyhow!("local certificate cache unavailable"))?;
        ensure!(
            slot.live() && capacity > 0,
            "invalid local certificate admission"
        );
        slots.retain(|_, old| old.live());
        if let Some(previous) = slots.get(names) {
            ensure!(
                Arc::ptr_eq(previous, slot),
                "local certificate cache slot changed"
            );
            return Ok(());
        }
        if slots.len() >= capacity {
            let mut keys = slots.keys().cloned().collect::<Vec<_>>();
            let at = super::super::resident_cache::random_index(keys.len())?;
            if let Some(victim) = slots.remove(&keys.swap_remove(at)) {
                victim.retire();
            }
        }
        slots.insert(names.to_vec(), slot.clone());
        self.cleanup_changed.notify_one();
        Ok(())
    }
    fn almost_full(&self, capacity: usize) -> bool {
        let target = capacity.saturating_sub(1);
        if target == 0 {
            return true;
        }
        let entries = self.resident.load();
        let managed = entries
            .values()
            .flatten()
            .filter(|entry| entry.binding.slot.live())
            .map(|entry| Arc::as_ptr(entry) as usize)
            .collect::<std::collections::HashSet<_>>()
            .len();
        let manual = self.manual.load();
        let manual = manual
            .values()
            .flatten()
            .map(|material| Arc::as_ptr(material) as usize)
            .collect::<std::collections::HashSet<_>>()
            .len();
        managed.saturating_add(manual) >= target
    }
    pub(super) fn imported_binding(
        &self,
        names: &[String],
    ) -> Option<(
        CertificateScope,
        ScopedCertificate,
        i64,
        i64,
        ResidencyBinding,
    )> {
        let resident = self.resident_if(names.first()?, |resident| {
            resident.material.names == names && resident.group.get().is_none()
        })?;
        Some((
            resident.scope.clone(),
            resident.receipt.clone(),
            resident.renew_at,
            resident.ari_after,
            resident.binding.clone(),
        ))
    }
    pub(super) fn install_manual(&self, material: &[Arc<Material>]) {
        let mut entries: HashMap<String, Vec<Arc<Material>>> = HashMap::new();
        for material in material {
            for name in &material.names {
                entries
                    .entry(name.clone())
                    .or_default()
                    .push(material.clone());
            }
        }
        self.manual.store(Arc::new(entries));
    }
    fn restore_resident(
        &self,
        material: Arc<Material>,
        binding: ResidencyBinding,
        leaf: Arc<crate::leaf_guard::LeafState>,
        scope: CertificateScope,
        receipt: ScopedCertificate,
        schedule: (i64, i64),
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
    fn cached_name(&self, name: &str) -> bool {
        self.state.cached(name)
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
    pub(super) async fn publish_restored_resident(
        &self,
        retained: RetainedMaterial,
        cancel: CancellationToken,
    ) -> Result<()> {
        let resolver = self.context.resolver.clone();
        let guard = self.context.leaf_guard.clone();
        let state = self.on_demand.clone();
        let publication_cancel = cancel.clone();
        let capacity = self.plan.cache_capacity.min(4096);
        super::super::loaders::blocking(self.context.resources.cpu.clone(), cancel, move || {
            let material = retained.material;
            material.validate_at(now()?, false)?;
            let leaf = guard.intern(material.leaf_id, material.times()?.1)?;
            ensure!(
                leaf.revocation()?.is_none(),
                "retained certificate is revoked"
            );
            let scope = CertificateScope::new();
            let slot = Arc::new(CertificateResidency::default());
            let receipt = resolver.upsert_resident(
                &CertificateInput {
                    names: &material.names,
                    certificate_pem: &material.certificate,
                    private_key_pem: &material.key,
                },
                &scope,
                &slot,
                &publication_cancel,
                || state.admit_local(&material.names, &slot, capacity),
            )?;
            state.restore_resident(
                material,
                ResidencyBinding {
                    slot,
                    shared: false,
                },
                leaf,
                scope,
                receipt,
                (retained.renew_at, retained.ari_after),
            );
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
                let registered = names
                    .iter()
                    .flat_map(|names| names.iter())
                    .map(|name| (name.clone(), issuer_class(&self.policy(name))))
                    .collect();
                let cache = self.context.resources.resident_cache.clone();
                let enabled = self.effective_tls.load(Ordering::Acquire);
                let (epoch, entries) = super::super::loaders::blocking(
                    self.context.resources.cpu.clone(),
                    cancel.clone(),
                    move || cache.prepare(registered, enabled),
                )
                .await?;
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
        let Some(epoch) = self.cache_epoch.get().cloned() else {
            return Ok(false);
        };
        let entry = self
            .shared_entry(epoch.clone(), name, cancel.clone())
            .await?;
        if let Some(entry) = entry {
            return self.import_shared_entry(epoch, entry, cancel).await;
        }
        Ok(false)
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
            _=gate_owner.slot.retired()=>return Ok(false),
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
        let material = entry.material.clone();
        let guard = self.context.leaf_guard.clone();
        let resolver = self.context.resolver.clone();
        let state = self.on_demand.clone();
        let retain = material.clone();
        let pending_entry = entry.clone();
        let publication_cancel = cancel.clone();
        let imported = super::super::loaders::blocking(
            self.context.resources.cpu.clone(),
            cancel.clone(),
            move || {
                use super::super::material::Validity;
                let at = now()?;
                let Ok(validity) = material.classify_at(at) else {
                    return Ok(SharedImport::Drop);
                };
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
                let receipt = match resolver.upsert_resident(
                    &CertificateInput {
                        names: &material.names,
                        certificate_pem: &material.certificate,
                        private_key_pem: &material.key,
                    },
                    &scope,
                    &entry.slot,
                    &publication_cancel,
                    || cache.valid_import(&epoch, &entry),
                ) {
                    Ok(receipt) => receipt,
                    Err(error)
                        if error.is::<super::super::resident_cache::CacheChanged>()
                            || !entry.slot.live() =>
                    {
                        return Ok(SharedImport::Superseded);
                    }
                    Err(error) => return Err(error),
                };
                let resident = Arc::new(Resident {
                    material: material.clone(),
                    binding: ResidencyBinding {
                        slot: entry.slot.clone(),
                        shared: true,
                    },
                    leaf,
                    group: std::sync::OnceLock::new(),
                    receipt,
                    scope,
                    cache_entry: Some(entry.clone()),
                    renew_at: entry.renew_at,
                    ari_after: entry.ari_after,
                    next_check: AtomicI64::new(entry.renew_at.min(entry.ari_after)),
                });
                state.index(&resident);
                if !entry.slot.live() {
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
                    item.identity || item.managed_names.as_ref() != Some(&retain.names)
                });
                state.material.push(RetainedMaterial {
                    managed_names: Some(retain.names.clone()),
                    material: retain,
                    identity: false,
                    renew_at: pending_entry.renew_at,
                    ari_after: pending_entry.ari_after,
                });
                Ok(true)
            }
            SharedImport::Pending(kind) => {
                if self.restore.is_none()
                    && (!self.policy(&retain.names[0]).on_demand
                        || matches!(kind, PendingKind::Withdrawn))
                {
                    let mut queue = self
                        .on_demand
                        .pending
                        .lock()
                        .map_err(|_| anyhow!("certificate pending restoration unavailable"))?;
                    ensure!(
                        queue.len() < 4096 || queue.contains_key(&retain.identity),
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
                let entries = self.on_demand.resident.load();
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
                let entries = self.on_demand.resident.load();
                let mut seen = std::collections::HashSet::new();
                entries
                    .values()
                    .flatten()
                    .filter(|resident| {
                        resident.binding.shared
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
            if self.policy(&entry.material.names[0]).on_demand {
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
                    .group(
                        resident.material.names.clone(),
                        false,
                        bound,
                        self.context.cancel.child_token(),
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
        ensure!(
            !name.contains('*'),
            "wildcard is not a TLS client server name"
        );
        let at = now()?;
        if self.on_demand.manual(&name, at) {
            return Ok(());
        }
        if let Some(resident) = self
            .on_demand
            .resident_if(&name, |resident| resident.usable(at))
        {
            let scheduled = resident.next_check.load(Ordering::Acquire);
            let pending = resident.leaf.needs_renewal();
            if self.policy(&name).on_demand
                && (scheduled <= at || pending)
                && resident
                    .next_check
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
                let _ = self.start_flight(name, Action::Maintenance, true);
            }
            return Ok(());
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
                let (flight, leader) = this.start_flight(name, Action::Miss, false)?;
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
        action: Action,
        background: bool,
    ) -> Result<(Arc<Flight>, bool)> {
        let _admission = self
            .admission
            .lock()
            .map_err(|_| anyhow!("certificate service admission unavailable"))?;
        ensure!(
            !self.context.cancel.is_cancelled(),
            "certificate services stopped"
        );
        let mut flights = self
            .on_demand
            .flights
            .lock()
            .map_err(|_| anyhow!("on-demand flight state unavailable"))?;
        let predecessor = flights.get(&name).cloned();
        if let Some(previous) = &predecessor
            && previous.residency.as_ref().is_some_and(|slot| !slot.live())
        {
            previous.cancel.cancel();
        }
        if let Some(flight) = &predecessor
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
        // Count every real leader, including cancelled predecessors whose
        // cleanup is still joining; map replacement cannot grow an unbounded
        // successor chain for a single repeatedly-aborted SNI.
        let admission = self
            .on_demand
            .flight_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("on-demand live flight capacity exceeded"))?;
        let residency = if matches!(action, Action::Maintenance) {
            Some(
                self.on_demand
                    .resident_if(&name, |resident| resident.usable(now().unwrap_or(i64::MAX)))
                    .ok_or(super::super::resident_cache::CacheChanged)?
                    .binding
                    .slot
                    .clone(),
            )
        } else {
            None
        };
        let flight = Arc::new(Flight {
            _admission: admission,
            residency,
            cancel: self.context.cancel.child_token(),
            result: Mutex::new(None),
            done: tokio::sync::Notify::new(),
            waiters: AtomicUsize::new(usize::from(!background)),
            background,
        });
        flights.insert(name.clone(), flight.clone());
        let this = self.clone();
        let worker = flight.clone();
        self.tasks.spawn(async move {
            let retired=async {
                match &worker.residency {
                    Some(slot)=>slot.retired().await,
                    None=>std::future::pending::<()>().await,
                }
            };
            let operation=async {
                // A successor may be admitted while its cancelled predecessor
                // drains, but cannot overlap its actual storage/CA operation.
                if let Some(previous)=predecessor {let _=flight_result(&previous).await;}
                this.on_demand_action(&name,action,worker.residency.as_ref(),worker.cancel.clone()).await
            };
            let operation=std::panic::AssertUnwindSafe(operation).catch_unwind();tokio::pin!(operation);
            let timeout=if matches!(action,Action::Maintenance){Duration::from_secs(300)}else{Duration::from_secs(180)};
            let result=tokio::select! {biased;
                _=worker.cancel.cancelled()=>{let _=operation.await;Err(anyhow!("on-demand operation cancelled"))},
                _=retired=>{worker.cancel.cancel();let _=operation.await;Err(super::super::resident_cache::CacheChanged.into())},
                _=tokio::time::sleep(timeout)=>{worker.cancel.cancel();let _=operation.await;Err(anyhow!("on-demand acquisition deadline exceeded"))},
                result=&mut operation=>result.unwrap_or_else(|_|Err(anyhow!("on-demand worker panicked"))),
            };
            let maintain=result.as_ref().is_ok_and(|maintain|*maintain);
            if result.is_err() {let _=this.events.send(CertificateEvent {kind:"on_demand_failed",names:vec![name.clone()]});}
            let outcome=result.map(|_|()).map_err(|error|Arc::<str>::from(error.to_string()));
            *worker.result.lock().unwrap_or_else(|error|error.into_inner())=Some(outcome);
            {let mut flights=this.on_demand.flights.lock().unwrap_or_else(|e|e.into_inner());if flights.get(&name).is_some_and(|current|Arc::ptr_eq(current,&worker)){flights.remove(&name);}}
            worker.done.notify_waiters();
            if maintain {let _=this.start_flight(name.clone(),Action::Maintenance,true);}
        });
        Ok((flight, true))
    }
    async fn on_demand_action(
        self: &Arc<Self>,
        name: &str,
        action: Action,
        residency: Option<&Arc<CertificateResidency>>,
        cancel: CancellationToken,
    ) -> Result<bool> {
        let resident = if let Some(slot) = residency {
            Some(
                self.on_demand
                    .resident_if(name, |resident| Arc::ptr_eq(slot, &resident.binding.slot))
                    .ok_or(super::super::resident_cache::CacheChanged)?,
            )
        } else {
            self.on_demand.resident(name)
        };
        if matches!(action, Action::Miss) && self.on_demand.cached(name) {
            return Ok(false);
        }
        if matches!(action, Action::Miss) && self.import_shared_name(name, cancel.clone()).await? {
            return Ok(false);
        }
        let policy = self.policy(name);
        if !policy.on_demand {
            ensure!(
                matches!(action, Action::Miss)
                    && self
                        .on_demand
                        .almost_full(self.plan.cache_capacity.min(4096)),
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
            let loaded = self.probe_group(group.clone(), cancel).await;
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
            return Ok(false);
        }
        if matches!(action, Action::Maintenance)
            && let Some(resident) = &resident
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
                        return Ok(false);
                    }
                }
            } else if group.renew_at.load(Ordering::Acquire) > now()? {
                resident
                    .next_check
                    .store(next_check(&group, now()?), Ordering::Release);
                return Ok(false);
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
        let mut seeded = false;
        let group = match &resident {
            Some(resident) if resident.group.get().is_some() => {
                resident.group.get().unwrap().clone()
            }
            _ => {
                let seed = if let Some(epoch) = self.cache_epoch.get() {
                    let entry = self
                        .shared_entry(epoch.clone(), name, cancel.clone())
                        .await?;
                    if let Some(entry) = entry {
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
                };
                if let Some(seed) = seed {
                    seeded = true;
                    self.seeded_group(seed, &bound, cancel.clone(), false)
                        .await?
                } else {
                    self.group(vec![name.to_owned()], false, &bound, cancel.clone())
                        .await?
                }
            }
        };
        if let Err(error) = self
            .ensure_group(
                group.clone(),
                matches!(action, Action::Miss) && !seeded,
                cancel.clone(),
            )
            .await
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
        Ok(matches!(action, Action::Miss) && due)
    }
    async fn evict_resident(
        &self,
        resident: Arc<Resident>,
        cancel: CancellationToken,
    ) -> Result<()> {
        if !resident.binding.slot.live() {
            return self.sweep_resident(resident, cancel).await;
        }
        let key = group_key(&resident.material.names, false);
        let group = {
            let state = self.state.lock().await;
            state
                .groups
                .get(&key)
                .filter(|group| {
                    group.residency.lock().is_ok_and(|binding| {
                        binding.as_ref().is_some_and(|binding| {
                            Arc::ptr_eq(&binding.slot, &resident.binding.slot)
                        })
                    })
                })
                .cloned()
        };
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
                if removed && !evicted.binding.shared {
                    evicted.binding.slot.retire();
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
        let key = group_key(&names, false);
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
        Ok(())
    }
    pub(super) async fn publish_group(
        &self,
        group: &Arc<Group>,
        material: Arc<Material>,
        renew_at: i64,
        ari_after: i64,
        cancel: CancellationToken,
        lease: Option<&crate::certstore::StorageLease>,
    ) -> Result<()> {
        if let Some(lease) = lease {
            lease.check().await?;
        }
        let lost = lease.map(crate::certstore::StorageLease::lost);
        let mut last = None;
        for attempt in 0..4 {
            let group = group.clone();
            let material = material.clone();
            let lost = lost.clone();
            let state = self.on_demand.clone();
            let cache = self.context.resources.resident_cache.clone();
            let epoch = self.cache_epoch.get().cloned();
            let capacity = self.plan.cache_capacity.min(4096);
            let leaf_guard = self.context.leaf_guard.clone();
            let publication_cancel = cancel.clone();
            let result = crate::cert_cpu::run_committed(
                self.context.resources.cpu.clone(),
                cancel.clone(),
                move || {
                    material.validate_at(now()?, false)?;
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
                    if group.identity {
                        return group
                            .resolver
                            .upsert_checked(&input, &publication_cancel, || {
                                ensure!(active(), "certificate publication cancelled");
                                Ok(())
                            });
                    }
                    let previous = group
                        .residency
                        .lock()
                        .map_err(|_| anyhow!("certificate residency unavailable"))?
                        .clone();
                    ensure!(
                        previous.as_ref().is_none_or(|binding| binding.slot.live()),
                        "certificate cache slot retired"
                    );
                    let plan = if let Some(epoch) = &epoch
                        && previous.as_ref().is_none_or(|binding| binding.shared)
                    {
                        cache.plan(
                            epoch,
                            super::super::resident_cache::Revision {
                                material: material.clone(),
                                issuer: issuer_class(&group.policy),
                                renew_at,
                                ari_after,
                            },
                            capacity,
                            previous.as_ref().map(|binding| &binding.slot),
                        )?
                    } else {
                        None
                    };
                    let cached = plan.as_ref().map(|plan| plan.entry.clone());
                    let binding = cached
                        .as_ref()
                        .map(|entry| ResidencyBinding {
                            slot: entry.slot.clone(),
                            shared: true,
                        })
                        .or(previous)
                        .unwrap_or_else(|| ResidencyBinding {
                            slot: Arc::new(CertificateResidency::default()),
                            shared: false,
                        });
                    let receipt = group.resolver.upsert_resident(
                        &input,
                        &group.scope,
                        &binding.slot,
                        &publication_cancel,
                        || {
                            ensure!(active(), "certificate acquisition cancelled");
                            if let Some(plan) = plan {
                                cache.commit(plan)?;
                            } else if !binding.shared {
                                state.admit_local(&material.names, &binding.slot, capacity)?;
                            }
                            Ok(())
                        },
                    )?;
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
                    state.record(
                        group.clone(),
                        material,
                        receipt,
                        cached,
                        binding.clone(),
                        leaf,
                    );
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
                    if error.is::<crate::tls_resolver::CertificatePublicationConflict>()
                        || error.is::<super::super::resident_cache::CacheChanged>() =>
                {
                    last = Some(error);
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
