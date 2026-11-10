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
}
struct ListenerControl {
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
    leases: Vec<LeaseRecord>,
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
                leases: Vec::new(),
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
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancel.cancel();
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
}
impl HttpStage {
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
    pub fn commit(mut self) -> CommitOutcome {
        let Some(next) = self.next.take() else {
            return CommitOutcome::Discarded;
        };
        let Some(listeners) = self.listeners.take() else {
            return CommitOutcome::Discarded;
        };
        let generation = next.id;
        let (previous, old_listeners) = {
            let mut control = self.guard.control.lock();
            if !control
                .pending
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(&p.identity, &self.guard.identity))
                || !matches!(control.phase, Phase::Running | Phase::StopRequested)
            {
                return CommitOutcome::Discarded;
            }
            let previous = self.inner.current.swap(next);
            let old_listeners = std::mem::replace(&mut control.listeners, listeners);
            control.generation = generation;
            control.pending = None;
            self.guard.armed = false;
            (previous, old_listeners)
        };
        self.guard.control.changed.notify_waiters();
        previous.drain.cancel();
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
            None,
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
        ensure!(
            Arc::ptr_eq(&self.inner.managed.leaf_guard(), &managed.leaf_guard()),
            "HTTP candidate must share the runtime leaf guard"
        );
        let prepared = prepare_servers(
            config,
            &self.inner.registry,
            managed,
            &self.inner.challenge_resolver,
            Some(manual),
            &self.inner.resources,
        );
        tokio::select! {
            biased;
            _ = self.inner.stopped.cancelled() => anyhow::bail!("HTTP runtime is stopping"),
            result = prepared => { let _ = result?; }
        }
        Ok(())
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
        self.stage_inner(config, managed, None).await
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
        self.stage_inner(config, managed, Some(manual)).await
    }
    async fn stage_inner(
        &self,
        config: PreparedConfig,
        managed: Arc<HotCertificateResolver>,
        manual: Option<ManualCertificates>,
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
            let identity = Arc::new(());
            let cancel = CancellationToken::new();
            let guard = PendingGuard {
                control: self.control.clone(),
                identity: identity.clone(),
                cancel: cancel.clone(),
                armed: true,
            };
            control.pending = Some(Pending {
                identity,
                cancel,
                bindings: HashMap::new(),
            });
            (guard, generation)
        };
        let prepared = prepare_servers(
            &config,
            &self.inner.registry,
            &managed,
            &self.inner.challenge_resolver,
            manual.as_ref(),
            &self.inner.resources,
        );
        let (servers, managed_names) = tokio::select! {
            biased;
            _ = guard.cancel.cancelled() => anyhow::bail!("HTTP candidate was stopped"),
            result = prepared => result?,
        };
        ensure!(!guard.cancel.is_cancelled(), "HTTP candidate was stopped");
        // Proof uses only the runtime registry resolver, never a candidate's
        // ordinary certificates. Building TLS state is outside the control lock.
        let proof_tls = proof_tls_config(self.inner.challenge_resolver.clone())?;
        let bindings = servers
            .iter()
            .map(|(address, server)| (*address, ListenerKind::of(server)))
            .collect::<HashMap<_, _>>();
        let (listeners, addresses) = loop {
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
                        )?;
                        configure_proof(&listener, *kind, &proof_tls);
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
        Ok(HttpStage {
            inner: self.inner.clone(),
            guard,
            next: Some(Arc::new(Generation {
                id: generation,
                servers,
                drain: CancellationToken::new(),
                managed_names,
            })),
            listeners: Some(listeners),
            addresses,
        })
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
        tokio::time::timeout(deadline, async {
            loop {
                let notified = self.control.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let stopped = {
                    let mut control = self.control.lock();
                    if control.phase == Phase::Running {
                        control.phase = Phase::StopRequested;
                    }
                    if control.pending.is_none() || control.phase == Phase::Forced {
                        if control.phase != Phase::Forced {
                            control.phase = Phase::Stopped;
                        }
                        for slot in control.pool.values() {
                            slot.cancel.cancel();
                        }
                        Some(std::mem::take(&mut control.listeners))
                    } else {
                        None
                    }
                };
                if let Some(listeners) = stopped {
                    for listener in listeners.values() {
                        listener.cancel.cancel();
                    }
                    self.stop_connections();
                    break;
                }
                notified.await;
            }
            self.inner.tasks.wait().await;
            self.inner.upgrades.wait().await;
            self.inner.resources.wait().await;
        })
        .await
        .map_err(|_| anyhow::anyhow!("HTTP shutdown deadline elapsed with pending work"))?;
        Ok(())
    }
    pub fn force_shutdown(&self) {
        let (listeners, pending) = {
            let mut control = self.control.lock();
            control.phase = Phase::Forced;
            for slot in control.pool.values() {
                slot.cancel.cancel();
            }
            (
                std::mem::take(&mut control.listeners),
                control.pending.as_ref().map(|p| p.cancel.clone()),
            )
        };
        if let Some(cancel) = pending {
            cancel.cancel();
        }
        for listener in listeners.values() {
            listener.cancel.cancel();
        }
        self.stop_connections();
        self.control.changed.notify_waiters();
    }
    fn stop_connections(&self) {
        // The accept-side snapshot retry must observe stop before a current
        // generation can become drained without a published successor.
        self.inner.stopped.cancel();
        let current = self.inner.current.load_full();
        current.drain.cancel();
        self.inner.tasks.close();
        self.inner.upgrades.close();
        self.inner.resources.close();
    }
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
fn configure_proof(owner: &ListenerControl, kind: ListenerKind, tls: &Arc<rustls::ServerConfig>) {
    owner.proof.store(Arc::new(ProofListener {
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
    let socket = ListenerSocket {
        socket: Some(socket),
        finished: finished.clone(),
    };
    let actual = socket
        .socket()
        .local_addr()
        .map_err(|_| anyhow::anyhow!("HTTP listener address unavailable"))?;
    let cancel = CancellationToken::new();
    let proof = Arc::new(ArcSwap::from_pointee(ProofListener {
        tls: (kind == ListenerKind::Tls).then(|| tls.clone()),
        cancel: cancel.clone(),
    }));
    let owner = Arc::new(ListenerControl {
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
            let tls = proof_tls_config(inner.challenge_resolver.clone())?;
            loop {
                ensure!(
                    !cancel.is_cancelled(),
                    "challenge listener request cancelled"
                );
                let outcome = {
                    let mut state = control.lock();
                    ensure!(state.phase == Phase::Running, "HTTP runtime is stopping");
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
                            if let Some(server) = current.servers.get(&key) {
                                ensure!(
                                    ListenerKind::of(server) == *kind,
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
                            let (owner, reused) =
                                own_socket(&mut state, *address, *kind, &tls, true, &mut launches)?;
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
                            configure_proof(&owner, *kind, &tls);
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
