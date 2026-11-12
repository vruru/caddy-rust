//! A reserved candidate owns every listener and resource until a synchronous
//! publication. Cancellation drops that ownership; it never edits old routes.
use super::*;
use std::sync::{Mutex, MutexGuard, Weak};
use tokio::sync::Notify;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    StopRequested,
    Stopped,
    Forced,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ListenerKind {
    Http,
    Tls,
}
impl ListenerKind {
    fn of(server: &ActiveServer) -> Self {
        if server.tls.is_some() {
            Self::Tls
        } else {
            Self::Http
        }
    }
}
struct Pending {
    identity: Arc<()>,
    cancel: CancellationToken,
    bindings: HashMap<SocketAddr, ListenerKind>,
    retirement: HttpRetirement,
}
struct ListenerControl {
    admission: Arc<connection_budget::ListenerBudget>,
    cancel: CancellationToken,
    actual: SocketAddr,
    proof: Arc<ArcSwap<ProofListener>>,
}
impl Drop for ListenerControl {
    fn drop(&mut self) {
        // Invariant: never acquire the lifecycle mutex in this destructor.
        self.cancel.cancel();
    }
}
struct PoolSlot {
    owner: Weak<ListenerControl>,
    actual: SocketAddr,
    cancel: CancellationToken,
    finished: CancellationToken,
}
struct LeaseRecord {
    identity: Arc<()>,
    bindings: Vec<(SocketAddr, ListenerKind)>,
}
/// The completion token is signalled only after the actual descriptor closes,
/// including an unpolled or unwinding accept task.
pub(super) struct ListenerSocket {
    pub(super) admission: Arc<connection_budget::ListenerBudget>,
    socket: Option<TcpListener>,
    finished: CancellationToken,
}
impl ListenerSocket {
    pub(super) fn socket(&self) -> &TcpListener {
        self.socket.as_ref().expect("live listener socket")
    }
}
impl Drop for ListenerSocket {
    fn drop(&mut self) {
        drop(self.socket.take());
        self.finished.cancel();
    }
}
struct Control {
    phase: Phase,
    pending: Option<Pending>,
    generation: u64,
    listeners: HashMap<SocketAddr, Arc<ListenerControl>>,
    pool: HashMap<SocketAddr, PoolSlot>,
    quic_pool: h3::Pool,
    leases: Vec<LeaseRecord>,
    retirements: HashMap<u64, Arc<RetirementOwner>>,
    stop: Option<HttpRetirement>,
}
pub(super) struct Lifecycle {
    state: Mutex<Control>,
    changed: Notify,
}
impl Lifecycle {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(Control {
                phase: Phase::Running,
                pending: None,
                generation: 0,
                listeners: HashMap::new(),
                pool: HashMap::new(),
                quic_pool: HashMap::new(),
                leases: Vec::new(),
                retirements: HashMap::new(),
                stop: None,
            }),
            changed: Notify::new(),
        }
    }
    fn lock(&self) -> MutexGuard<'_, Control> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}
struct PendingGuard {
    control: Arc<Lifecycle>,
    identity: Arc<()>,
    cancel: CancellationToken,
    armed: bool,
    retirement: HttpRetirement,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancel.cancel();
        self.retirement.complete(RetirementOutcome::Aborted);
        let cleared = {
            let mut control = self.control.lock();
            if control
                .pending
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(&p.identity, &self.identity))
            {
                control.pending = None;
                true
            } else {
                false
            }
        };
        if cleared {
            self.control.changed.notify_waiters();
        }
    }
}
/// A removed binding retains only its own shared socket ownership. Closing it
/// never cancels a descriptor still owned by a lease or a newer generation.
pub(super) struct RetiringBinding {
    pub server: Arc<ActiveServer>,
    pub activity: Arc<BusinessGeneration>,
    group: Arc<retirement::AdmissionGroup>,
    accepting: std::sync::atomic::AtomicBool,
    owner: Mutex<Option<Arc<ListenerControl>>>,
}
impl RetiringBinding {
    pub(super) fn is_accepting(&self) -> bool {
        self.accepting.load(std::sync::atomic::Ordering::Acquire)
    }
    fn close(&self) {
        if self
            .accepting
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            let owner = self.owner.lock().unwrap_or_else(|e| e.into_inner()).take();
            drop(owner);
            self.group.member_closed();
        }
    }
}
struct RetirementOwner {
    group: Arc<retirement::AdmissionGroup>,
    bindings: Vec<Arc<RetiringBinding>>,
}
impl RetirementOwner {
    fn close(&self) {
        for binding in &self.bindings {
            binding.close();
        }
    }
}
/// Executor cancellation cannot strand a published retirement or leave its
/// admission open. An unpublished actor must never modify the old generation.
struct RetirementTaskGuard(Option<Arc<RetirementOwner>>);
impl Drop for RetirementTaskGuard {
    fn drop(&mut self) {
        let Some(owner) = self.0.take() else {
            return;
        };
        if owner.group.signal.is_published() {
            owner.close();
            owner.group.activity.force();
        } else {
            owner.group.signal.complete(RetirementOutcome::Aborted);
        }
    }
}
async fn retire_generation(
    inner: Weak<Inner>,
    control: Weak<Lifecycle>,
    owner: Arc<RetirementOwner>,
    mut safety: RetirementTaskGuard,
) {
    if !owner.group.signal.activated().await {
        return;
    }
    if let Some(inner) = inner.upgrade() {
        tokio::select! { biased;
            _ = inner.stopped.cancelled() => {},
            _ = owner.group.activity.wait_delay() => {},
        }
    }
    owner.close();
    owner.group.activity.drain.cancel();
    let activity = &owner.group.activity;
    if let Some(grace) = activity.policy.grace_period {
        tokio::select! { biased;
            _ = activity.hard_stop.cancelled() => {},
            _ = activity.wait_idle() => {},
            _ = tokio::time::sleep(grace) => activity.force(),
        }
    } else {
        activity.wait_idle().await;
    }
    if let Some(control) = control.upgrade() {
        let removed = {
            let mut state = control.lock();
            if state
                .retirements
                .get(&activity.id)
                .is_some_and(|r| Arc::ptr_eq(r, &owner))
            {
                state.retirements.remove(&activity.id)
            } else {
                None
            }
        };
        drop(removed);
        control.changed.notify_waiters();
    }
    // Successful completion must not force an otherwise completed generation.
    safety.0 = None;
}

/// Candidate listener capabilities. `declared` remains the configuration key;
/// `actual` records the OS-selected port when the declared port was zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedAddress {
    pub declared: SocketAddr,
    pub actual: SocketAddr,
    pub reused: bool,
    pub http01: bool,
    pub tls_alpn01: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    Published { generation: u64 },
    Discarded,
}
/// Non-cloneable, runtime-bound publication right. Dropping it aborts only this
/// candidate. A forced shutdown is the sole normal reason commit discards it.
pub struct HttpStage {
    inner: Arc<Inner>,
    guard: PendingGuard,
    next: Option<Arc<Generation>>,
    listeners: Option<HashMap<SocketAddr, Arc<ListenerControl>>>,
    addresses: Vec<StagedAddress>,
    retirement: Arc<RetirementOwner>,
    overridden: Vec<Arc<RetiringBinding>>,
}
impl HttpStage {
    pub fn retirement(&self) -> HttpRetirement {
        self.guard.retirement.clone()
    }
    pub fn managed_names(&self) -> Vec<Vec<String>> {
        self.next
            .as_ref()
            .map(|g| g.managed_names.clone())
            .unwrap_or_default()
    }
    pub fn bound_addresses(&self) -> Vec<StagedAddress> {
        self.addresses.clone()
    }
    /// Every fallible preparation and task spawn completed in stage. Neither a
    /// client disconnect nor an async cancellation can interrupt this commit.
    pub fn commit(self) -> CommitOutcome {
        self.commit_with_tickets(None)
    }
    pub(crate) fn commit_with_tickets(
        mut self,
        tickets: Option<crate::stek::Activation>,
    ) -> CommitOutcome {
        // A destroyed executor also destroys its accept tasks. Publishing a
        // ready ticket on another executor must not resurrect dead listeners.
        if self.guard.retirement.is_aborted() {
            HttpRuntime {
                inner: self.inner.clone(),
                control: self.guard.control.clone(),
            }
            .force_shutdown();
            return CommitOutcome::Discarded;
        }
        let Some(next) = self.next.take() else {
            return CommitOutcome::Discarded;
        };
        let Some(listeners) = self.listeners.take() else {
            return CommitOutcome::Discarded;
        };
        let generation = next.id;
        if tickets
            .as_ref()
            .is_some_and(|activation| activation.generation() != generation)
        {
            return CommitOutcome::Discarded;
        }
        let (previous, old_listeners) = {
            let mut control = self.guard.control.lock();
            if !control
                .pending
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(&p.identity, &self.guard.identity))
                || !matches!(control.phase, Phase::Running | Phase::StopRequested)
                || self.inner.stopped.is_cancelled()
            {
                return CommitOutcome::Discarded;
            }
            if !self.guard.retirement.reserve_publication() {
                drop(control);
                HttpRuntime {
                    inner: self.inner.clone(),
                    control: self.guard.control.clone(),
                }
                .force_shutdown();
                return CommitOutcome::Discarded;
            }
            // Every discard check has passed, and the exact generation is
            // about to become eligible for TCP handshakes. Publish the
            // precomputed ticket view here; this operation is memory only.
            if let Some(tickets) = tickets {
                tickets.commit();
            }
            let previous = self.inner.current.swap(next);
            if let Some(cleanup) = &previous.proxy_cleanup {
                cleanup.retire(&self.inner.resources.proxy_cleanup);
            }
            let old_listeners = std::mem::replace(&mut control.listeners, listeners);
            control
                .retirements
                .insert(previous.id, self.retirement.clone());
            if !self.retirement.bindings.is_empty() {
                previous
                    .activity
                    .start_delay(previous.activity.policy.shutdown_delay);
            }
            self.retirement.group.publish();
            for binding in &self.overridden {
                binding.close();
            }
            if previous.activity.policy.shutdown_delay.is_zero() {
                self.retirement.close();
            }
            control.generation = generation;
            control.pending = None;
            self.guard.armed = false;
            (previous, old_listeners)
        };
        self.guard.control.changed.notify_waiters();
        previous.activity.superseded.cancel();
        drop(previous);
        drop(old_listeners);
        CommitOutcome::Published { generation }
    }
}

impl HttpRuntime {
    pub async fn validate_prepared(&self, config: &PreparedConfig) -> Result<()> {
        let prepared = prepare_servers(
            config,
            &self.inner.registry,
            &self.inner.managed,
            &self.inner.challenge_resolver,
            ServingMaterial {
                manual: None,
                provider: None,
                logging: None,
                tickets: None,
                validate_only: true,
            },
            &self.inner.resources,
        );
        tokio::select! {
            biased;
            _ = self.inner.stopped.cancelled() => anyhow::bail!("HTTP runtime is stopping"),
            result = prepared => { let _ = result?; }
        }
        Ok(())
    }
    pub async fn validate_prepared_with_certificates(
        &self,
        config: &PreparedConfig,
        managed: &Arc<HotCertificateResolver>,
        manual: &ManualCertificates,
    ) -> Result<()> {
        self.prepared_managed_names_with_certificates(config, managed, manual)
            .await
            .map(|_| ())
    }
    /// Run the exact provision-only server path used by stage, including tag,
    /// manual-inventory and loaded-name exclusions. No socket is bound, solver
    /// lease acquired, certificate requested or configuration published here.
    pub async fn prepared_managed_names_with_certificates(
        &self,
        config: &PreparedConfig,
        managed: &Arc<HotCertificateResolver>,
        manual: &ManualCertificates,
    ) -> Result<Vec<Vec<String>>> {
        ensure!(
            Arc::ptr_eq(&self.inner.managed.leaf_guard(), &managed.leaf_guard()),
            "HTTP candidate must share the runtime leaf guard"
        );
        let prepared = prepare_servers(
            config,
            &self.inner.registry,
            managed,
            &self.inner.challenge_resolver,
            ServingMaterial {
                manual: Some(manual),
                provider: None,
                logging: None,
                tickets: None,
                validate_only: true,
            },
            &self.inner.resources,
        );
        tokio::select! {
            biased;
            _ = self.inner.stopped.cancelled() => anyhow::bail!("HTTP runtime is stopping"),
            result = prepared => result.map(|(_,names)|names)
        }
    }
    /// Compatibility wrapper for standalone callers. Integrated reloads supply
    /// a fresh per-generation managed resolver directly to `stage`.
    pub async fn apply(&self, config: PreparedConfig) -> Result<()> {
        match self
            .stage(config, self.inner.managed.clone())
            .await?
            .commit()
        {
            CommitOutcome::Published { .. } => Ok(()),
            CommitOutcome::Discarded => anyhow::bail!("HTTP runtime stopped before publication"),
        }
    }
    pub async fn stage(
        &self,
        config: PreparedConfig,
        managed: Arc<HotCertificateResolver>,
    ) -> Result<HttpStage> {
        self.stage_inner(config, managed, None, None, None, None)
            .await
    }
    /// The supplied inventory is already provisioned by the TLS app. Raw
    /// load_files must have been consumed there, not silently ignored here.
    /// Chain identities and tags are immutable for the lifetime of this staged
    /// generation; replacing certificate material requires a fresh inventory
    /// and stage. Only OCSP/staple and shared leaf-admission state may change.
    pub async fn stage_with_certificates(
        &self,
        config: PreparedConfig,
        managed: Arc<HotCertificateResolver>,
        manual: ManualCertificates,
    ) -> Result<HttpStage> {
        self.stage_inner(config, managed, Some(manual), None, None, None)
            .await
    }
    /// Attach this generation's immutable automation-policy capability. It is
    /// never consulted by tagged manual selection or ACME proof handshakes.
    pub async fn stage_with_certificates_and_provider(
        &self,
        config: PreparedConfig,
        managed: Arc<HotCertificateResolver>,
        manual: ManualCertificates,
        provider: Arc<dyn ScopedCertificateProvider>,
    ) -> Result<HttpStage> {
        self.stage_inner(config, managed, Some(manual), Some(provider), None, None)
            .await
    }
    pub async fn stage_with_generation_resources(
        &self,
        config: PreparedConfig,
        managed: Arc<HotCertificateResolver>,
        manual: ManualCertificates,
        provider: Arc<dyn ScopedCertificateProvider>,
        logging: Arc<crate::logging::Logging>,
    ) -> Result<HttpStage> {
        self.stage_inner(
            config,
            managed,
            Some(manual),
            Some(provider),
            Some(logging),
            None,
        )
        .await
    }
    #[cfg(feature = "native-run")]
    pub(crate) async fn stage_with_native_tickets(
        &self,
        config: PreparedConfig,
        managed: Arc<HotCertificateResolver>,
        manual: ManualCertificates,
        provider: Arc<dyn ScopedCertificateProvider>,
        logging: Arc<crate::logging::Logging>,
        tickets: crate::stek::TicketRuntime,
    ) -> Result<HttpStage> {
        self.stage_inner(
            config,
            managed,
            Some(manual),
            Some(provider),
            Some(logging),
            Some(tickets),
        )
        .await
    }
    async fn stage_inner(
        &self,
        config: PreparedConfig,
        managed: Arc<HotCertificateResolver>,
        manual: Option<ManualCertificates>,
        provider: Option<Arc<dyn ScopedCertificateProvider>>,
        logging: Option<Arc<crate::logging::Logging>>,
        tickets: Option<crate::stek::TicketRuntime>,
    ) -> Result<HttpStage> {
        ensure!(
            Arc::ptr_eq(&self.inner.managed.leaf_guard(), &managed.leaf_guard()),
            "HTTP candidate must share the runtime leaf guard"
        );
        // The guard is constructed under the same short lock as reservation:
        // dropping this future at any await cannot strand a pending ticket.
        let (guard, generation) = {
            let mut control = self.control.lock();
            ensure!(control.phase == Phase::Running, "HTTP runtime is stopping");
            ensure!(control.pending.is_none(), "HTTP candidate already pending");
            let generation = control
                .generation
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("HTTP generation exhausted"))?;
            ensure!(
                control.retirements.len() < 4096,
                "HTTP retirement capacity exhausted"
            );
            control
                .retirements
                .try_reserve(1)
                .map_err(|_| anyhow::anyhow!("HTTP retirement allocation failed"))?;
            let retirement = HttpRetirement::staged(control.generation, Some(generation));
            let identity = Arc::new(());
            let cancel = CancellationToken::new();
            let guard = PendingGuard {
                control: self.control.clone(),
                identity: identity.clone(),
                cancel: cancel.clone(),
                armed: true,
                retirement: retirement.clone(),
            };
            control.pending = Some(Pending {
                identity,
                cancel,
                bindings: HashMap::new(),
                retirement,
            });
            (guard, generation)
        };
        let prepared = prepare_servers(
            &config,
            &self.inner.registry,
            &managed,
            &self.inner.challenge_resolver,
            ServingMaterial {
                manual: manual.as_ref(),
                provider: provider.as_ref(),
                logging: logging.as_ref(),
                tickets: tickets.as_ref(),
                validate_only: false,
            },
            &self.inner.resources,
        );
        let (servers, managed_names) = tokio::select! {
            biased;
            _ = guard.cancel.cancelled() => anyhow::bail!("HTTP candidate was stopped"),
            result = prepared => result?,
        };
        ensure!(!guard.cancel.is_cancelled(), "HTTP candidate was stopped");
        if servers.values().any(|server| server.tls.is_some()) {
            ensure_tls_executor(&self.inner).await?;
        }
        // Proof uses only the runtime registry resolver, never a candidate's
        // ordinary certificates. Building TLS state is outside the control lock.
        let proof_tls = proof_tls_config(self.inner.challenge_resolver.clone())?;
        let bindings = servers
            .iter()
            .filter(|(_, server)| h3::tcp_enabled(server))
            .map(|(address, server)| (*address, ListenerKind::of(server)))
            .collect::<HashMap<_, _>>();
        let (listeners, mut addresses) = loop {
            let waiting = {
                let mut control = self.control.lock();
                ensure!(
                    matches!(control.phase, Phase::Running | Phase::StopRequested)
                        && control
                            .pending
                            .as_ref()
                            .is_some_and(|pending| Arc::ptr_eq(&pending.identity, &guard.identity))
                        && !guard.cancel.is_cancelled(),
                    "HTTP candidate was stopped"
                );
                prune_pool(&mut control);
                let (_pins, closing) = pin_pool(&control, bindings.keys().copied(), false)?;
                if let Some(finished) = closing {
                    Some(finished)
                } else {
                    for (address, kind) in &bindings {
                        ensure!(
                            control.leases.iter().all(|record| record
                                .bindings
                                .iter()
                                .all(|(key, owned)| key != address || owned == kind)),
                            "HTTP candidate conflicts with a challenge listener lease"
                        );
                    }
                    // Validate every shared proof policy before changing any owner.
                    for address in bindings.keys(){
                        if control.leases.iter().any(|record|record.bindings.iter().any(|(key,_)|key==address)){
                            let owner=control.pool.get(address).and_then(|slot|slot.owner.upgrade())
                                .ok_or_else(||anyhow::anyhow!("challenge listener owner unavailable"))?;
                            ensure!(*owner.proof.load().listener_stack==*servers[address].plan.listener_stack,
                                "HTTP candidate changes wrappers used by a challenge listener lease");
                        }
                    }
                    let mut listeners = HashMap::with_capacity(bindings.len());
                    let mut addresses = Vec::with_capacity(bindings.len());
                    let mut launches = Vec::new();
                    let current = self.inner.current.load_full();
                    for (address, kind) in &bindings {
                        let (listener, reused) = own_socket(
                            &mut control,
                            *address,
                            *kind,
                            &proof_tls,
                            false,
                            &mut launches,
                            &self.inner.connections,
                        )?;
                        let stack=servers[address].plan.listener_stack.clone();
                        configure_proof(&listener, *kind, &proof_tls,Some(stack));
                        let capability = current
                            .servers
                            .get(address)
                            .map(|server| ListenerKind::of(server))
                            .unwrap_or(*kind);
                        addresses.push(StagedAddress {
                            declared: *address,
                            actual: listener.actual,
                            reused,
                            http01: capability == ListenerKind::Http,
                            tls_alpn01: capability == ListenerKind::Tls,
                        });
                        listeners.insert(*address, listener);
                    }
                    control
                        .pending
                        .as_mut()
                        .expect("reservation checked")
                        .bindings = bindings.clone();
                    launch_listeners(&self.inner, launches);
                    break (listeners, addresses);
                }
            };
            if let Some(finished) = waiting {
                tokio::select! { biased;
                    _ = guard.cancel.cancelled() => anyhow::bail!("HTTP candidate was stopped"),
                    _ = self.inner.stopped.cancelled() => anyhow::bail!("HTTP runtime is stopped"),
                    _ = finished.cancelled() => {},
                }
            }
        };
        let quic = {
            let mut state = self.control.lock();
            ensure!(!guard.cancel.is_cancelled(), "HTTP candidate was stopped");
            h3::stage(&self.inner, &mut state.quic_pool, &servers, &addresses)?
        };
        for (&declared, listener) in &quic {
            if !bindings.contains_key(&declared) {
                addresses.push(StagedAddress {
                    declared,
                    actual: listener.binding.actual,
                    reused: self
                        .inner
                        .current
                        .load()
                        .quic
                        .get(&declared)
                        .is_some_and(|old| Arc::ptr_eq(&old.binding, &listener.binding)),
                    http01: false,
                    tls_alpn01: false,
                });
            }
        }
        let activity = BusinessGeneration::new(generation, config.shutdown_policy());
        let current = self.inner.current.load_full();
        let (retirement, retiring, overridden) = {
            let state = self.control.lock();
            ensure!(!guard.cancel.is_cancelled(), "HTTP candidate was stopped");
            let mut retiring = HashMap::new();
            let mut overridden = Vec::new();
            for (address, weak) in &current.retiring {
                if let Some(binding) = weak.upgrade().filter(|r| r.is_accepting()) {
                    if servers.contains_key(address) {
                        overridden.push(binding);
                    } else {
                        retiring.insert(*address, Arc::downgrade(&binding));
                    }
                }
            }
            let removed = state
                .listeners
                .iter()
                .filter(|(addr, _)| !bindings.contains_key(addr))
                .collect::<Vec<_>>();
            let group = retirement::AdmissionGroup::new(
                guard.retirement.clone(),
                current.activity.clone(),
                removed.len(),
            );
            let mut bindings = Vec::new();
            for (address, listener) in removed {
                let binding = Arc::new(RetiringBinding {
                    server: current.servers[address].clone(),
                    activity: current.activity.clone(),
                    group: group.clone(),
                    accepting: std::sync::atomic::AtomicBool::new(true),
                    owner: Mutex::new(Some(listener.clone())),
                });
                retiring.insert(*address, Arc::downgrade(&binding));
                bindings.push(binding);
            }
            (
                Arc::new(RetirementOwner { group, bindings }),
                retiring,
                overridden,
            )
        };
        self.inner.tasks.spawn(retire_generation(
            Arc::downgrade(&self.inner),
            Arc::downgrade(&self.control),
            retirement.clone(),
            RetirementTaskGuard(Some(retirement.clone())),
        ));
        let owners = proxy_cleanup::dedup_owners(
            servers
                .values()
                .flat_map(|server| server.clients.values())
                .filter_map(|client| client.passive.as_ref()),
        );
        let proxy_cleanup = self.inner.resources.proxy_cleanup.reserve(owners).await?;
        let next = Arc::new(Generation {
            id: generation,
            activity: activity.clone(),
            servers,
            quic,
            retiring,
            drain: activity.drain.clone(),
            managed_names,
            proxy_cleanup,
        });
        proxy::prepare_health(&self.inner, &next, guard.retirement.clone()).await?;
        Ok(HttpStage {
            inner: self.inner.clone(),
            guard,
            next: Some(next),
            listeners: Some(listeners),
            addresses,
            retirement,
            overridden,
        })
    }
    /// Currently owned accepting descriptors. Old streams remain in global counts.
    pub fn listener_connection_diagnostics(
        &self,
    ) -> Vec<(SocketAddr, SocketAddr, ConnectionDiagnostics)> {
        let state = self.control.lock();
        let mut rows = state
            .pool
            .iter()
            .filter_map(|(key, slot)| {
                slot.owner
                    .upgrade()
                    .map(|owner| (*key, slot.actual, owner.admission.snapshot()))
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|row| row.0);
        rows
    }
    pub async fn bound_addresses(&self) -> Vec<SocketAddr> {
        self.control
            .lock()
            .listeners
            .values()
            .map(|listener| listener.actual)
            .collect()
    }
    /// Normal stop never upgrades itself to force. Pending stage ownership must
    /// resolve first; a deadline leaves StopRequested and old listeners intact.
    pub async fn shutdown(&self, deadline: Duration) -> Result<()> {
        self.shutdown_wait(Some(deadline)).await
    }
    /// Stop accepts and join owned work. None has no wait deadline. A deadline
    /// only bounds this caller's wait; it never silently forces active streams.
    /// Configured positive grace and delayed retirement are separate policy.
    pub async fn shutdown_wait(&self, deadline: Option<Duration>) -> Result<()> {
        match deadline {
            Some(deadline) => tokio::time::timeout(deadline, self.drain_owned_work())
                .await
                .map_err(|_| anyhow::anyhow!("HTTP shutdown deadline elapsed with pending work"))?,
            None => self.drain_owned_work().await,
        }
    }
    /// Fence new candidates immediately and start an owned stop transition.
    /// Pending candidates retain their right to publish; the actor then applies
    /// that final generation's policy. The receipt's from id is the stop fence,
    /// not a promise that an already reserved candidate cannot still commit.
    pub fn begin_shutdown(&self) -> Result<HttpRetirement> {
        let mut state = self.control.lock();
        if let Some(stop) = &state.stop {
            return Ok(stop.clone());
        }
        let signal = HttpRetirement::staged(state.generation, None);
        if state.phase == Phase::Forced {
            signal.complete(RetirementOutcome::Forced);
            state.stop = Some(signal.clone());
            return Ok(signal);
        }
        state.phase = Phase::StopRequested;
        state.stop = Some(signal.clone());
        let inner = self.inner.clone();
        let control = self.control.clone();
        let receipt = signal.clone();
        self.inner.tasks.spawn(async move {
            stop_runtime(inner, control, receipt).await;
        });
        Ok(signal)
    }
    async fn drain_owned_work(&self) -> Result<()> {
        let _ = self.begin_shutdown()?;
        self.inner.tasks.wait().await;
        self.inner.upgrades.wait().await;
        self.inner.resources.wait().await;
        if let Some(executor) = self.inner.tls_executor.get() {
            executor.shutdown().await?;
        }
        Ok(())
    }
    pub fn force_shutdown(&self) {
        let (listeners, pending, retired, stop) = {
            let mut control = self.control.lock();
            control.phase = Phase::Forced;
            for slot in control.pool.values() {
                slot.cancel.cancel();
            }
            let pending = control
                .pending
                .as_ref()
                .map(|p| (p.cancel.clone(), p.retirement.clone()));
            let retired = std::mem::take(&mut control.retirements);
            (
                std::mem::take(&mut control.listeners),
                pending,
                retired,
                control.stop.clone(),
            )
        };
        if let Some((cancel, signal)) = pending {
            signal.complete(RetirementOutcome::Forced);
            cancel.cancel();
        }
        if let Some(stop) = stop {
            stop.complete(RetirementOutcome::Forced);
        }
        for retirement in retired.values() {
            retirement.group.signal.complete(RetirementOutcome::Forced);
            retirement.close();
            retirement.group.activity.force();
        }
        for listener in listeners.values() {
            listener.cancel.cancel();
        }
        self.stop_connections();
        self.inner.current.load().activity.force();
        self.control.changed.notify_waiters();
    }
    fn stop_connections(&self) {
        // The accept-side snapshot retry must observe stop before a current
        // generation can become drained without a published successor.
        self.inner.stopped.cancel();
        if let Some(executor) = self.inner.tls_executor.get() {
            executor.close();
        }
        let current = self.inner.current.load_full();
        if let Some(cleanup) = &current.proxy_cleanup {
            cleanup.retire(&self.inner.resources.proxy_cleanup);
        }
        current.drain.cancel();
        self.inner.tasks.close();
        self.inner.upgrades.close();
        self.inner.resources.close();
    }
}

async fn stop_runtime(inner: Arc<Inner>, lifecycle: Arc<Lifecycle>, signal: HttpRetirement) {
    // Unlike a caller's timeout, this actor owns the transition to completion.
    loop {
        let notified = lifecycle.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let done = {
            let state = lifecycle.lock();
            state.pending.is_none() || state.phase == Phase::Forced
        };
        if done {
            break;
        }
        notified.await;
    }
    let current = inner.current.load_full();
    // Earlier generations already own independent delay/grace clocks. Keep
    // their registry visible to Force and wait their admission concurrently;
    // neither an empty current app nor its shorter policy truncates them.
    let previous = {
        let state = lifecycle.lock();
        state
            .retirements
            .values()
            .map(|owner| owner.group.signal.clone())
            .collect::<Vec<_>>()
    };
    if !current.servers.is_empty() {
        current
            .activity
            .start_delay(current.activity.policy.shutdown_delay);
    }
    signal.published();
    tokio::select! {biased;
        _=inner.stopped.cancelled()=>{},
        _=current.activity.wait_delay()=>{},
    }
    current.activity.close_admission();
    current.drain.cancel();
    let listeners = {
        let mut state = lifecycle.lock();
        std::mem::take(&mut state.listeners)
    };
    // Dropping this generation's owner cannot close a socket still held by an
    // older retirement, a pending proof exchange or another legitimate lease.
    drop(listeners);
    let finish_admission = async {
        let _ =
            futures_util::future::join_all(previous.iter().map(HttpRetirement::acceptance_closed))
                .await;
        let forced = {
            let mut state = lifecycle.lock();
            let forced = state.phase == Phase::Forced;
            if !forced {
                state.phase = Phase::Stopped;
            }
            for slot in state.pool.values() {
                slot.cancel.cancel();
            }
            if let Some(cleanup) = &current.proxy_cleanup {
                cleanup.retire(&inner.resources.proxy_cleanup);
            }
            forced
        };
        inner.stopped.cancel();
        if let Some(executor) = inner.tls_executor.get() {
            executor.close();
        }
        inner.tasks.close();
        inner.upgrades.close();
        inner.resources.close();
        signal.complete(if forced {
            RetirementOutcome::Forced
        } else {
            RetirementOutcome::AcceptanceClosed
        });
        lifecycle.changed.notify_waiters();
    };
    let drain_current = async {
        let activity = &current.activity;
        if let Some(grace) = activity.policy.grace_period {
            tokio::select! {biased;
                _=activity.hard_stop.cancelled()=>{},
                _=activity.wait_idle()=>{},
                _=tokio::time::sleep(grace)=>activity.force(),
            }
        } else {
            activity.wait_idle().await;
        }
    };
    tokio::join!(finish_admission, drain_current);
}

type Launch = (
    SocketAddr,
    ListenerSocket,
    CancellationToken,
    Arc<ArcSwap<ProofListener>>,
);
fn prune_pool(control: &mut Control) {
    control
        .pool
        .retain(|_, slot| slot.owner.strong_count() != 0 || !slot.finished.is_cancelled());
}
fn covers(bound: SocketAddr, requested: SocketAddr) -> bool {
    bound == requested
        || bound.port() == requested.port()
            && bound.ip().is_unspecified()
            && (bound.is_ipv6() || requested.is_ipv4())
}
fn pool_key(control: &Control, address: SocketAddr, coverage: bool) -> Option<SocketAddr> {
    if control.pool.contains_key(&address) {
        return Some(address);
    }
    if coverage {
        control
            .pool
            .iter()
            .find_map(|(key, slot)| covers(slot.actual, address).then_some(*key))
    } else {
        None
    }
}
fn pin_pool(
    control: &Control,
    addresses: impl IntoIterator<Item = SocketAddr>,
    coverage: bool,
) -> Result<(Vec<Arc<ListenerControl>>, Option<CancellationToken>)> {
    let mut pins = Vec::new();
    for address in addresses {
        if let Some(key) = pool_key(control, address, coverage) {
            let slot = &control.pool[&key];
            ensure!(
                !slot.finished.is_cancelled(),
                "shared HTTP listener closed unexpectedly"
            );
            if let Some(owner) = slot.owner.upgrade() {
                pins.push(owner);
            } else {
                return Ok((pins, Some(slot.finished.clone())));
            }
        }
    }
    Ok((pins, None))
}
fn configure_proof(owner: &ListenerControl, kind: ListenerKind, tls: &Arc<rustls::ServerConfig>, stack:Option<Arc<listener_stack::Stack>>) {
    // A challenge lease reuses the candidate's transport, it must not reset it.
    let listener_stack=stack.unwrap_or_else(||owner.proof.load().listener_stack.clone());
    owner.proof.store(Arc::new(ProofListener {
        listener_stack,
        tls: (kind == ListenerKind::Tls).then(|| tls.clone()),
        cancel: owner.cancel.clone(),
    }));
}
fn own_socket(
    control: &mut Control,
    address: SocketAddr,
    kind: ListenerKind,
    tls: &Arc<rustls::ServerConfig>,
    coverage: bool,
    launches: &mut Vec<Launch>,
    connections: &Arc<connection_budget::Budgets>,
) -> Result<(Arc<ListenerControl>, bool)> {
    if let Some(key) = pool_key(control, address, coverage) {
        ensure!(
            !control.pool[&key].finished.is_cancelled(),
            "shared HTTP listener closed unexpectedly"
        );
        let owner = control.pool[&key]
            .owner
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("listener closing after admission"))?;
        return Ok((owner, true));
    }
    ensure!(
        !control.pool.values().any(|slot| address.port() != 0
            && (covers(slot.actual, address) || covers(address, slot.actual))),
        "HTTP listener binding scope overlaps an existing shared listener"
    );
    let socket =
        bind_listener(address).map_err(|_| anyhow::anyhow!("HTTP listener bind failed"))?;
    let finished = CancellationToken::new();
    let admission = connections.listener();
    let socket = ListenerSocket {
        admission: admission.clone(),
        socket: Some(socket),
        finished: finished.clone(),
    };
    let actual = socket
        .socket()
        .local_addr()
        .map_err(|_| anyhow::anyhow!("HTTP listener address unavailable"))?;
    let cancel = CancellationToken::new();
    let proof = Arc::new(ArcSwap::from_pointee(ProofListener {
        listener_stack:Arc::default(),
        tls: (kind == ListenerKind::Tls).then(|| tls.clone()),
        cancel: cancel.clone(),
    }));
    let owner = Arc::new(ListenerControl {
        admission,
        cancel: cancel.clone(),
        actual,
        proof: proof.clone(),
    });
    control.pool.insert(
        address,
        PoolSlot {
            owner: Arc::downgrade(&owner),
            actual,
            cancel: cancel.clone(),
            finished,
        },
    );
    launches.push((address, socket, cancel, proof));
    Ok((owner, false))
}
fn launch_listeners(inner: &Arc<Inner>, launches: Vec<Launch>) {
    for (key, socket, cancel, proof) in launches {
        let task_inner = inner.clone();
        inner.tasks.spawn(async move {
            accept_loop(task_inner, socket, key, cancel, proof).await;
        });
    }
}
struct RuntimeChallengeProvider {
    inner: Weak<Inner>,
    control: Weak<Lifecycle>,
}
struct RuntimeChallengeLease {
    control: Arc<Lifecycle>,
    identity: Arc<()>,
    owners: Vec<Arc<ListenerControl>>,
    addresses: Vec<StagedAddress>,
    keys: Vec<SocketAddr>,
}
impl Drop for RuntimeChallengeLease {
    fn drop(&mut self) {
        {
            let mut control = self.control.lock();
            control
                .leases
                .retain(|record| !Arc::ptr_eq(&record.identity, &self.identity));
        }
        // Last-owner Drop is deliberately outside the control lock.
        self.owners.clear();
        self.control.changed.notify_waiters();
    }
}
impl ChallengeListenerLease for RuntimeChallengeLease {
    fn addresses(&self) -> &[StagedAddress] {
        &self.addresses
    }
    fn release(self: Box<Self>) -> futures_util::future::BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            let control = self.control.clone();
            let keys = self.keys.clone();
            drop(self);
            let closing = {
                let state = control.lock();
                keys.iter()
                    .filter_map(|key| state.pool.get(key))
                    .filter(|slot| slot.owner.strong_count() == 0)
                    .map(|slot| slot.finished.clone())
                    .collect::<Vec<_>>()
            };
            for finished in closing {
                finished.cancelled().await;
            }
            Ok(())
        })
    }
}
impl HttpRuntime {
    pub fn challenge_listener_provider(&self) -> Arc<dyn ChallengeListenerProvider> {
        Arc::new(RuntimeChallengeProvider {
            inner: Arc::downgrade(&self.inner),
            control: Arc::downgrade(&self.control),
        })
    }
}
fn requested_bindings(
    requests: Vec<ChallengeBindingRequest>,
) -> Result<Vec<(SocketAddr, ListenerKind)>> {
    ensure!(
        !requests.is_empty() && requests.len() <= 32,
        "challenge binding count outside bounds"
    );
    let mut bindings = Vec::new();
    for request in requests {
        let ip = if request.bind_host.is_empty() {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        } else {
            request
                .bind_host
                .parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("hostname challenge binding is not yet supported"))?
        };
        for (port, kind) in [
            (request.http_port, ListenerKind::Http),
            (request.tls_alpn_port, ListenerKind::Tls),
        ] {
            if let Some(port) = port {
                ensure!(port != 0, "challenge port must be explicit");
                let address = SocketAddr::new(ip, port);
                if let Some((_, other)) = bindings.iter().find(|(bound, _)| *bound == address) {
                    ensure!(
                        *other == kind,
                        "challenge protocols conflict on one address"
                    );
                } else {
                    bindings.push((address, kind));
                }
            }
        }
    }
    ensure!(
        !bindings.is_empty() && bindings.len() <= 32,
        "challenge binding count outside bounds"
    );
    Ok(bindings)
}
impl ChallengeListenerProvider for RuntimeChallengeProvider {
    fn acquire(
        &self,
        requests: Vec<ChallengeBindingRequest>,
        cancel: CancellationToken,
    ) -> futures_util::future::BoxFuture<'static, Result<Box<dyn ChallengeListenerLease>>> {
        let weak_inner = self.inner.clone();
        let weak_control = self.control.clone();
        Box::pin(async move {
            let bindings = requested_bindings(requests)?;
            let inner = weak_inner
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("HTTP runtime unavailable"))?;
            let control = weak_control
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("HTTP runtime unavailable"))?;
            if bindings.iter().any(|(_, kind)| *kind == ListenerKind::Tls) {
                ensure_tls_executor(&inner).await?;
            }
            let tls = proof_tls_config(inner.challenge_resolver.clone())?;
            loop {
                ensure!(
                    !cancel.is_cancelled(),
                    "challenge listener request cancelled"
                );
                let outcome = {
                    let mut state = control.lock();
                    ensure!(
                        matches!(state.phase, Phase::Running | Phase::StopRequested),
                        "HTTP runtime is stopping"
                    );
                    ensure!(
                        state.leases.len() < 4096,
                        "challenge listener lease capacity exceeded"
                    );
                    prune_pool(&mut state);
                    let (_pins, closing) =
                        pin_pool(&state, bindings.iter().map(|(a, _)| *a), true)?;
                    if let Some(finished) = closing {
                        Err(finished)
                    } else {
                        let current = inner.current.load_full();
                        // All compatibility checks and ownership publication use
                        // the same short lock as stage registration and commit.
                        for (address, kind) in &bindings {
                            let key = pool_key(&state, *address, true).unwrap_or(*address);
                            if let Some((server, _)) = current.business(&key) {
                                ensure!(
                                    ListenerKind::of(&server) == *kind,
                                    "challenge protocol conflicts with published listener"
                                );
                            }
                            if let Some(pending) = &state.pending
                                && let Some(prepared) = pending.bindings.get(&key)
                            {
                                ensure!(
                                    *prepared == *kind,
                                    "challenge protocol conflicts with pending listener"
                                );
                            }
                            ensure!(
                                state.leases.iter().all(|record| record
                                    .bindings
                                    .iter()
                                    .all(|(owned, mode)| *owned != key || *mode == *kind)),
                                "challenge protocol conflicts with another lease"
                            );
                        }
                        let mut owners = Vec::new();
                        let mut addresses = Vec::new();
                        let mut keys = Vec::new();
                        let mut modes = Vec::new();
                        let mut launches = Vec::new();
                        for (address, kind) in &bindings {
                            let (owner, reused) = own_socket(
                                &mut state,
                                *address,
                                *kind,
                                &tls,
                                true,
                                &mut launches,
                                &inner.connections,
                            )?;
                            let key =
                                pool_key(&state, *address, true).expect("new or pinned listener");
                            // Separate input addresses can resolve to one wildcard
                            // socket; they must not request conflicting protocols.
                            if let Some((_, mode)) = modes.iter().find(|(owned, _)| *owned == key) {
                                ensure!(
                                    *mode == *kind,
                                    "challenge protocols conflict on shared listener"
                                );
                            } else {
                                modes.push((key, *kind));
                                keys.push(key);
                            }
                            configure_proof(&owner, *kind, &tls,None);
                            addresses.push(StagedAddress {
                                declared: *address,
                                actual: owner.actual,
                                reused,
                                http01: *kind == ListenerKind::Http,
                                tls_alpn01: *kind == ListenerKind::Tls,
                            });
                            owners.push(owner);
                        }
                        let identity = Arc::new(());
                        state.leases.push(LeaseRecord {
                            identity: identity.clone(),
                            bindings: modes,
                        });
                        launch_listeners(&inner, launches);
                        Ok(RuntimeChallengeLease {
                            control: control.clone(),
                            identity,
                            owners,
                            addresses,
                            keys,
                        })
                    }
                };
                match outcome {
                    Ok(lease) => {
                        if cancel.is_cancelled() {
                            drop(lease);
                            anyhow::bail!("challenge listener request cancelled");
                        }
                        return Ok(Box::new(lease) as Box<dyn ChallengeListenerLease>);
                    }
                    Err(finished) => tokio::select! { biased;
                        _=cancel.cancelled()=>anyhow::bail!("challenge listener request cancelled"),
                        _=inner.stopped.cancelled()=>anyhow::bail!("HTTP runtime is stopped"),
                        _=finished.cancelled()=>{},
                    },
                }
            }
        })
    }
}
