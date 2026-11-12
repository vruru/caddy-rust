//! Independent connection classes retain real socket ownership through upgrades.
use anyhow::Result;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};
use std::task::{Context, Poll};
use std::{future::Future, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionClass {
    Classifying,
    Business,
    Proof,
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectionLimits {
    pub global_classifying: usize,
    pub listener_classifying: usize,
    pub global_business: usize,
    pub listener_business: usize,
    pub global_proof: usize,
    pub listener_proof: usize,
}

impl ConnectionLimits {
    /// Counts are CPU-adaptive resource budgets, not CPU worker counts.
    pub fn automatic() -> Self {
        Self::for_parallelism(std::thread::available_parallelism().map_or(1, |n| n.get()))
            .with_descriptor_limit(super::descriptor_budget::descriptor_limit())
    }
    pub fn for_parallelism(cpu: usize) -> Self {
        let cpu = cpu.max(1);
        Self {
            global_classifying: cpu.saturating_mul(128).clamp(512, 8192),
            listener_classifying: cpu.saturating_mul(64).clamp(128, 2048),
            global_business: cpu.saturating_mul(2048).clamp(4096, 65536),
            listener_business: cpu.saturating_mul(512).clamp(1024, 16384),
            global_proof: cpu.saturating_mul(64).clamp(256, 4096),
            listener_proof: cpu.saturating_mul(16).clamp(64, 1024),
        }
    }
    /// For soft limits of at least 32, the default incoming quotas sum to
    /// at most one quarter of that limit. Very small limits retain nonzero
    /// minimum pools. Other descriptors are not reserved by this module;
    /// upstreams, files, listeners and other features also use them.
    /// Explicit native limits remain the caller's policy and are not clamped.
    pub fn with_descriptor_limit(mut self, soft: Option<usize>) -> Self {
        if let Some(soft) = soft {
            let per_class_socket_budget = (soft / 32).max(1);
            self.global_classifying = self.global_classifying.min(per_class_socket_budget);
            self.global_proof = self.global_proof.min(per_class_socket_budget);
            self.global_business = self
                .global_business
                .min(per_class_socket_budget.saturating_mul(6));
            self.listener_classifying = self
                .listener_classifying
                .min(self.global_classifying.div_ceil(4));
            self.listener_proof = self.listener_proof.min(self.global_proof.div_ceil(4));
            self.listener_business = self.listener_business.min(self.global_business.div_ceil(4));
        }
        self
    }
    pub fn validate(&self) -> Result<()> {
        let max = Semaphore::MAX_PERMITS;

        // Check non-zero
        if self.global_classifying == 0 || self.listener_classifying == 0 {
            return Err(anyhow::anyhow!("Classifying limits must be non-zero"));
        }
        if self.global_business == 0 || self.listener_business == 0 {
            return Err(anyhow::anyhow!("Business limits must be non-zero"));
        }
        if self.global_proof == 0 || self.listener_proof == 0 {
            return Err(anyhow::anyhow!("Proof limits must be non-zero"));
        }

        // Check <= MAX_PERMITS
        if self.global_classifying > max || self.listener_classifying > max {
            return Err(anyhow::anyhow!("Classifying limits exceed max permits"));
        }
        if self.global_business > max || self.listener_business > max {
            return Err(anyhow::anyhow!("Business limits exceed max permits"));
        }
        if self.global_proof > max || self.listener_proof > max {
            return Err(anyhow::anyhow!("Proof limits exceed max permits"));
        }

        // Check listener <= global
        if self.listener_classifying > self.global_classifying {
            return Err(anyhow::anyhow!("Listener classifying limit exceeds global"));
        }
        if self.listener_business > self.global_business {
            return Err(anyhow::anyhow!("Listener business limit exceeds global"));
        }
        if self.listener_proof > self.global_proof {
            return Err(anyhow::anyhow!("Listener proof limit exceeds global"));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ConnectionPoolSnapshot {
    pub limit: usize,
    pub in_use: usize,
    pub rejected: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ConnectionDiagnostics {
    pub classifying: ConnectionPoolSnapshot,
    pub business: ConnectionPoolSnapshot,
    pub proof: ConnectionPoolSnapshot,
    pub replacement_waiters: ConnectionPoolSnapshot,
}

struct Pool {
    semaphore: Arc<Semaphore>,
    limit: usize,
    rejected: AtomicU64,
    live: Arc<super::pressure::Registry>,
}

impl Pool {
    fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
            limit,
            rejected: AtomicU64::new(0),
            live: super::pressure::Registry::new(),
        }
    }

    fn snapshot(&self) -> ConnectionPoolSnapshot {
        let available = self.semaphore.available_permits();
        ConnectionPoolSnapshot {
            limit: self.limit,
            in_use: self.limit - available,
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }

    fn record_rejection(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct Budgets {
    limits: ConnectionLimits,
    global: [Pool; 3],
    replacement: Pool,
}

impl Budgets {
    pub(crate) fn new(limits: ConnectionLimits) -> Result<Arc<Self>> {
        limits.validate()?;

        let global = [
            Pool::new(limits.global_classifying),
            Pool::new(limits.global_business),
            Pool::new(limits.global_proof),
        ];

        Ok(Arc::new(Self {
            limits,
            global,
            replacement: Pool::new(
                std::thread::available_parallelism()
                    .map_or(1, |cpu| cpu.get())
                    .saturating_mul(2)
                    .clamp(2, 64),
            ),
        }))
    }

    /// Read each independent pool; this is not one atomic multi-pool snapshot.
    pub(crate) fn snapshot(&self) -> ConnectionDiagnostics {
        ConnectionDiagnostics {
            classifying: self.global[0].snapshot(),
            business: self.global[1].snapshot(),
            proof: self.global[2].snapshot(),
            replacement_waiters: self.replacement.snapshot(),
        }
    }

    pub(crate) fn listener(self: &Arc<Self>) -> Arc<ListenerBudget> {
        let limits = self.limits;

        let listener = [
            Pool::new(limits.listener_classifying),
            Pool::new(limits.listener_business),
            Pool::new(limits.listener_proof),
        ];

        Arc::new(ListenerBudget {
            budgets: self.clone(),
            listener,
            replacement: Pool::new(1),
        })
    }
}

pub(crate) struct ListenerBudget {
    budgets: Arc<Budgets>,
    listener: [Pool; 3],
    replacement: Pool,
}

#[derive(Debug)]
struct Capacity(&'static str);
impl std::fmt::Display for Capacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Capacity {}

impl ListenerBudget {
    fn try_held(&self, class: ConnectionClass) -> Result<Held> {
        let idx = class_index(class);

        // A full local listener must not borrow even a transient global slot.
        let local_permit = self.listener[idx]
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.listener[idx].record_rejection();
                Capacity("Connection rejected: listener capacity")
            })?;
        let global_permit = self.budgets.global[idx]
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.budgets.global[idx].record_rejection();
                Capacity("Connection rejected: global capacity")
            })?;

        Ok(Held {
            _global: global_permit,
            _local: local_permit,
        })
    }
    pub(crate) fn admit(self: &Arc<Self>, class: ConnectionClass) -> Result<Arc<Admission>> {
        self.prepare_admission(class, self.try_held(class)?)
    }
    fn prepare_admission(
        self: &Arc<Self>,
        class: ConnectionClass,
        held: Held,
    ) -> Result<Arc<Admission>> {
        let admission = Arc::new_cyclic(|weak| Admission {
            listener_budget: self.clone(),
            weak: weak.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            state: Mutex::new(State {
                class,
                held: Some(held),
                membership: None,
                evicted: false,
                service_entered: false,
            }),
        });
        let membership = admission.membership(class)?;
        admission
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Connection admission unavailable"))?
            .membership = membership;
        Ok(admission)
    }
    /// At most one replacement waits per listener, under a separate global cap.
    /// Cancellation only asks a victim to close; real IO releases both permits.
    pub(crate) async fn admit_with_pressure(
        self: &Arc<Self>,
        class: ConnectionClass,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Arc<Admission>> {
        anyhow::ensure!(!cancel.is_cancelled(), "Connection admission stopped");
        match self.admit(class) {
            Ok(admission) => Ok(admission),
            Err(error) if class != ConnectionClass::Business && error.is::<Capacity>() => {
                self.prepare_admission(class, self.recover_held(class, cancel, None).await?)
            }
            Err(error) => Err(error),
        }
    }
    async fn recover_held(
        &self,
        class: ConnectionClass,
        cancel: &tokio_util::sync::CancellationToken,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Held> {
        anyhow::ensure!(
            class != ConnectionClass::Business,
            "Business admission cannot replace connections"
        );
        check_admission_live(cancel, deadline)?;
        let _local = self
            .replacement
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.replacement.record_rejection();
                anyhow::anyhow!("Listener replacement queue full")
            })?;
        let _global = self
            .budgets
            .replacement
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.budgets.replacement.record_rejection();
                anyhow::anyhow!("Global replacement queue full")
            })?;
        let idx = class_index(class);
        let local_pool = &self.listener[idx];
        let global_pool = &self.budgets.global[idx];
        // Queue both halves before cancelling one victim. Its real socket drop
        // returns global and local permits in separate operations; a new peer
        // on another listener cannot intercept the already queued global half.
        let mut local = Box::pin(tokio::task::unconstrained(
            local_pool.semaphore.clone().acquire_owned(),
        ));
        let mut global = Box::pin(tokio::task::unconstrained(
            global_pool.semaphore.clone().acquire_owned(),
        ));
        let (first_local, first_global) = std::future::poll_fn(|cx| {
            Poll::Ready((local.as_mut().poll(cx), global.as_mut().poll(cx)))
        })
        .await;
        let first_local = ready_permit(first_local)?;
        let first_global = ready_permit(first_global)?;
        check_admission_live(cancel, deadline)?;
        let victim_pool = if first_local.is_none() {
            Some(local_pool)
        } else if first_global.is_none() {
            Some(global_pool)
        } else {
            None
        };
        if let Some(pool) = victim_pool {
            anyhow::ensure!(
                pool.live.evict_oldest(),
                "Connection queue full; no reclaimable connection"
            );
        }
        tokio::select! {biased;
            _=cancel.cancelled()=>anyhow::bail!("Connection admission stopped"),
            _=wait_admission_deadline(deadline)=>anyhow::bail!("Connection admission deadline elapsed"),
            result=async {
                let local=match first_local{Some(p)=>p,None=>local.await?};
                let global=match first_global{Some(p)=>p,None=>global.await?};
                Ok(Held{_global:global,_local:local})
            }=>result,
        }
    }

    pub(crate) fn snapshot(&self) -> ConnectionDiagnostics {
        ConnectionDiagnostics {
            classifying: self.listener[0].snapshot(),
            business: self.listener[1].snapshot(),
            proof: self.listener[2].snapshot(),
            replacement_waiters: self.replacement.snapshot(),
        }
    }
}

fn ready_permit(
    value: Poll<Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError>>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    match value {
        Poll::Pending => Ok(None),
        Poll::Ready(result) => Ok(Some(result?)),
    }
}
fn check_admission_live(
    cancel: &tokio_util::sync::CancellationToken,
    deadline: Option<tokio::time::Instant>,
) -> Result<()> {
    anyhow::ensure!(!cancel.is_cancelled(), "Connection admission stopped");
    anyhow::ensure!(
        deadline.is_none_or(|deadline| deadline > tokio::time::Instant::now()),
        "Connection admission deadline elapsed"
    );
    Ok(())
}
async fn wait_admission_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

struct Held {
    _global: tokio::sync::OwnedSemaphorePermit,
    _local: tokio::sync::OwnedSemaphorePermit,
}

struct State {
    class: ConnectionClass,
    held: Option<Held>,
    membership: Option<Membership>,
    evicted: bool,
    // Once a service call starts, listener removal must use the established
    // request/body retirement policy, never this initial-head reclaim path.
    service_entered: bool,
}

pub(crate) struct Admission {
    listener_budget: Arc<ListenerBudget>,
    state: Mutex<State>,
    weak: Weak<Admission>,
    cancel: tokio_util::sync::CancellationToken,
}

struct Membership {
    _victim: Arc<dyn super::pressure::Victim>,
    _local: super::pressure::Registration,
    _global: super::pressure::Registration,
}
struct SocketVictim {
    owner: Weak<Admission>,
    class: ConnectionClass,
}
impl super::pressure::Victim for SocketVictim {
    fn try_cancel(&self) -> bool {
        let Some(owner) = self.owner.upgrade() else {
            return false;
        };
        let Ok(mut state) = owner.state.lock() else {
            return false;
        };
        if state.held.is_none()
            || state.evicted
            || state.class != self.class
            || state.class == ConnectionClass::Business
        {
            return false;
        }
        // Serialize eviction against successful business classification. A late
        // registry entry cannot cancel a connection that already became business.
        state.evicted = true;
        drop(state);
        owner.cancel.cancel();
        true
    }
}
impl Admission {
    /// Serialize the first service call against physical listener retirement.
    /// This changes no class or permits; proof classification remains separate.
    pub(crate) fn enter_service(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.evicted || state.held.is_none() { return false; }
        state.service_entered = true;
        true
    }
    /// Only a genuinely removed listener may call this. TLS can already hold
    /// a Business slot before its first HTTP service call, so that class alone
    /// is not evidence of an active request. Proof ownership remains separate.
    /// Cancellation never refunds a still-owned descriptor permit.
    pub(crate) fn cancel_before_service(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.evicted || state.held.is_none()
            || state.class == ConnectionClass::Proof || state.service_entered {
            return false;
        }
        state.evicted = true;
        drop(state);
        self.cancel.cancel();
        true
    }
    fn membership(&self, class: ConnectionClass) -> Result<Option<Membership>> {
        if class == ConnectionClass::Business {
            return Ok(None);
        }
        let idx = class_index(class);
        let victim: Arc<dyn super::pressure::Victim> = Arc::new(SocketVictim {
            owner: self.weak.clone(),
            class,
        });
        let local = self.listener_budget.listener[idx].live.register(&victim)?;
        let global = self.listener_budget.budgets.global[idx]
            .live
            .register(&victim)?;
        Ok(Some(Membership {
            _victim: victim,
            _local: local,
            _global: global,
        }))
    }

    fn needs_transition(state: &State, target: ConnectionClass) -> Result<bool> {
        // A temporary control reference cannot reacquire after real IO closed.
        anyhow::ensure!(
            state.held.is_some() && !state.evicted,
            "Connection is closed"
        );
        if state.class == target
            || (state.class == ConnectionClass::Business && target == ConnectionClass::Proof)
        {
            return Ok(false);
        }
        anyhow::ensure!(
            target != ConnectionClass::Classifying,
            "Invalid class transition"
        );
        Ok(true)
    }
    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Connection admission unavailable"))
    }
    fn publish_transition(
        &self,
        mut state: std::sync::MutexGuard<'_, State>,
        target: ConnectionClass,
        held: Held,
    ) -> Result<()> {
        let membership = self.membership(target)?;
        let old_membership = std::mem::replace(&mut state.membership, membership);
        let old_held = state.held.replace(held);
        state.class = target;
        drop(state);
        drop(old_membership);
        drop(old_held);
        Ok(())
    }
    pub(crate) fn classify(&self, target: ConnectionClass) -> Result<()> {
        let state = self.lock_state()?;
        if !Self::needs_transition(&state, target)? {
            return Ok(());
        }
        let held = self.listener_budget.try_held(target)?;
        self.publish_transition(state, target, held)
    }
    async fn classify_proof(&self, deadline: Option<tokio::time::Instant>) -> Result<()> {
        check_admission_live(&self.cancel, deadline)?;
        let target = ConnectionClass::Proof;
        {
            let state = self.lock_state()?;
            if !Self::needs_transition(&state, target)? {
                return Ok(());
            }
            if let Ok(held) = self.listener_budget.try_held(target) {
                return self.publish_transition(state, target, held);
            }
        }
        // Keep the source Classifying credits and the real IO while waiting.
        // Do not hold the phase lock; another H2 stream can migrate to Business.
        let held = self
            .listener_budget
            .recover_held(target, &self.cancel, deadline)
            .await?;
        let state = self.lock_state()?;
        if !Self::needs_transition(&state, target)? {
            return Ok(());
        }
        self.publish_transition(state, target, held)
    }
    fn close(&self) {
        // This lock contains only permit bookkeeping. Even a poisoned lock must
        // release the real descriptor's admission once its IO is gone.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let held = state.held.take();
        let membership = state.membership.take();
        drop(state);
        drop(membership);
        drop(held);
        self.cancel.cancel();
    }
}

fn class_index(c: ConnectionClass) -> usize {
    match c {
        ConnectionClass::Classifying => 0,
        ConnectionClass::Business => 1,
        ConnectionClass::Proof => 2,
    }
}

pub(crate) struct AdmittedIo<I> {
    inner: Option<I>,
    admission: Arc<Admission>,
}

impl<I> AdmittedIo<I> {
    pub(crate) fn new(inner: I, admission: Arc<Admission>) -> Self {
        Self {
            inner: Some(inner),
            admission,
        }
    }

    pub(crate) fn eviction_token(&self) -> tokio_util::sync::CancellationToken {
        self.admission.cancel.clone()
    }

    pub(crate) fn admission(&self) -> Weak<Admission> {
        Arc::downgrade(&self.admission)
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for AdmittedIo<I> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Unpin required, get pin to inner
        let me = self.get_mut();
        std::pin::Pin::new(me.inner.as_mut().expect("live admitted IO")).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for AdmittedIo<I> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        std::pin::Pin::new(me.inner.as_mut().expect("live admitted IO")).poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(me.inner.as_mut().expect("live admitted IO")).poll_flush(cx)
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(me.inner.as_mut().expect("live admitted IO")).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner
            .as_ref()
            .expect("live admitted IO")
            .is_write_vectored()
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        std::pin::Pin::new(me.inner.as_mut().expect("live admitted IO"))
            .poll_write_vectored(cx, bufs)
    }
}

impl<I> Drop for AdmittedIo<I> {
    fn drop(&mut self) {
        // Close the actual socket/upgrade IO before making its quota available.
        drop(self.inner.take());
        self.admission.close();
    }
}

pub(crate) fn classify(admission: &Weak<Admission>, target: ConnectionClass) -> Result<()> {
    admission
        .upgrade()
        .ok_or_else(|| anyhow::anyhow!("Connection is closed"))?
        .classify(target)
}

pub(crate) async fn classify_proof(
    admission: &Weak<Admission>,
    deadline: Option<tokio::time::Instant>,
) -> Result<()> {
    admission
        .upgrade()
        .ok_or_else(|| anyhow::anyhow!("Connection is closed"))?
        .classify_proof(deadline)
        .await
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.close();
    }
}
