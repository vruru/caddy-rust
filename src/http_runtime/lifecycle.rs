//! A reserved candidate owns every listener and resource until a synchronous
//! publication. Cancellation drops that ownership; it never edits old routes.
use super::*;
use std::sync::{Mutex, MutexGuard};
use tokio::sync::Notify;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    StopRequested,
    Stopped,
    Forced,
}
struct Pending {
    identity: Arc<()>,
    cancel: CancellationToken,
}
struct ListenerControl {
    cancel: CancellationToken,
    actual: SocketAddr,
}
struct Control {
    phase: Phase,
    pending: Option<Pending>,
    generation: u64,
    listeners: HashMap<SocketAddr, Arc<ListenerControl>>,
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
    retire: Vec<Arc<ListenerControl>>,
    new_listeners: Vec<Arc<ListenerControl>>,
    addresses: Vec<StagedAddress>,
    proof_cancel: CancellationToken,
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
        for listener in &self.retire {
            listener.cancel.cancel();
        }
        self.new_listeners.clear();
        self.proof_cancel.cancel();
        drop(previous);
        drop(old_listeners);
        CommitOutcome::Published { generation }
    }
}
impl Drop for HttpStage {
    fn drop(&mut self) {
        for listener in &self.new_listeners {
            listener.cancel.cancel();
        }
        self.proof_cancel.cancel();
    }
}

impl HttpRuntime {
    pub async fn validate_prepared(&self, config: &PreparedConfig) -> Result<()> {
        let _ = prepare_servers(config, &self.inner.registry, &self.inner.managed).await?;
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
        ensure!(
            Arc::ptr_eq(&self.inner.managed.leaf_guard(), &managed.leaf_guard()),
            "HTTP candidate must share the runtime leaf guard"
        );
        // The guard is constructed under the same short lock as reservation:
        // dropping this future at any await cannot strand a pending ticket.
        let (guard, generation, existing, base) = {
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
            let existing = control.listeners.clone();
            control.pending = Some(Pending { identity, cancel });
            (guard, generation, existing, self.inner.current.load_full())
        };
        let (servers, managed_names) =
            prepare_servers(&config, &self.inner.registry, &managed).await?;
        ensure!(!guard.cancel.is_cancelled(), "HTTP candidate was stopped");
        let proof_cancel = guard.cancel.child_token();
        let mut listeners = HashMap::with_capacity(servers.len());
        let mut new_listeners = Vec::new();
        let mut addresses = Vec::with_capacity(servers.len());
        let mut launches = Vec::new();
        let proof_tls = if servers.values().any(|s| s.tls.is_some()) {
            Some(proof_tls_config(managed)?)
        } else {
            None
        };
        for (declared, server) in &servers {
            ensure!(!guard.cancel.is_cancelled(), "HTTP candidate was stopped");
            let (listener, reused) = if let Some(listener) = existing.get(declared) {
                (listener.clone(), true)
            } else {
                let socket = bind_listener(*declared)
                    .map_err(|_| anyhow::anyhow!("candidate HTTP listener bind failed"))?;
                let actual = socket
                    .local_addr()
                    .map_err(|_| anyhow::anyhow!("candidate HTTP listener address unavailable"))?;
                let listener = Arc::new(ListenerControl {
                    cancel: CancellationToken::new(),
                    actual,
                });
                launches.push((
                    *declared,
                    socket,
                    listener.clone(),
                    ProofListener {
                        tls: if server.tls.is_some() {
                            proof_tls.clone()
                        } else {
                            None
                        },
                        cancel: proof_cancel.clone(),
                    },
                ));
                new_listeners.push(listener.clone());
                (listener, false)
            };
            let proof_server = if reused {
                base.servers.get(declared).unwrap_or(server)
            } else {
                server
            };
            addresses.push(StagedAddress {
                declared: *declared,
                actual: listener.actual,
                reused,
                http01: proof_server.tls.is_none(),
                tls_alpn01: proof_server.tls.is_some(),
            });
            listeners.insert(*declared, listener);
        }
        let retire = existing
            .into_iter()
            .filter_map(|(addr, listener)| (!listeners.contains_key(&addr)).then_some(listener))
            .collect();
        let stage = HttpStage {
            inner: self.inner.clone(),
            guard,
            next: Some(Arc::new(Generation {
                id: generation,
                servers,
                drain: CancellationToken::new(),
                managed_names,
            })),
            listeners: Some(listeners),
            retire,
            new_listeners,
            addresses,
            proof_cancel,
        };
        // Stop cannot close the trackers while a reservation exists. Force can;
        // every pre-launched task checks stopped/cancel before serving anything.
        ensure!(
            !stage.guard.cancel.is_cancelled(),
            "HTTP candidate was stopped"
        );
        for (declared, socket, listener, proof) in launches {
            let inner = self.inner.clone();
            self.inner.tasks.spawn(async move {
                accept_loop(
                    inner,
                    socket,
                    declared,
                    listener.cancel.clone(),
                    Some(proof),
                )
                .await;
            });
        }
        Ok(stage)
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
