use super::{
    AdminBackend, AdminError, AdminOptions, AdminTransaction, StopMode,
    activation::transact_admin,
    byte_budget::{Buffer, CONFIG_EGRESS},
    files,
    ids::Indexed,
    policy::LocalPolicy,
    server::{AdminServerHandle, PermissionPublication, Prepared, Running},
};
use arc_swap::ArcSwap;
use futures_util::FutureExt;
use hyper::body::Bytes;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{mpsc, oneshot};
tokio::task_local! { static ADMIN_TRANSACTION: (); }
pub(super) async fn transaction_scope<F: std::future::Future>(work: F) -> F::Output {
    ADMIN_TRANSACTION.scope((), work).await
}
fn reject_reentrant() -> Result<(), AdminError> {
    if ADMIN_TRANSACTION.try_with(|_| ()).is_ok() {
        Err(AdminError::new(409, "admin_txn_reentrant"))
    } else {
        Ok(())
    }
}

#[derive(Clone)]
pub struct AdminController {
    pub(super) inner: Arc<Inner>,
    _lifetime: Option<Arc<ControllerLifetime>>,
}
struct ControllerLifetime(tokio_util::sync::CancellationToken);
impl Drop for ControllerLifetime {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
pub(super) struct Published {
    pub indexed: Indexed,
    pub generation: u64,
    pub access: Option<Arc<super::remote::RemoteAccess>>,
}
impl std::ops::Deref for Published {
    type Target = Indexed;
    fn deref(&self) -> &Indexed {
        &self.indexed
    }
}
impl Published {
    pub(super) fn authorize(
        &self,
        grant: &super::remote::Grant,
        target: Option<&str>,
    ) -> Result<(), AdminError> {
        let access = self
            .access
            .as_ref()
            .ok_or_else(|| AdminError::new(403, "remote_admin_authorization_revoked"))?;
        let indices = access
            .verified_grants(&grant.chain)
            .map_err(|_| AdminError::new(403, "remote_admin_authorization_revoked"))?;
        access.check(&indices, &grant.method, &grant.path)?;
        if grant.path.starts_with("/id/")
            && let Some(target) = target
        {
            access.check(&indices, &grant.method, target)?;
        }
        Ok(())
    }
}
pub(super) struct Inner {
    pub state: ArcSwap<Published>,
    pub options: AdminOptions,
    pub backend: Arc<dyn AdminBackend>,
    sender: mpsc::Sender<Job>,
    admission: Mutex<Admission>,
    sequence: std::sync::atomic::AtomicU64,
    draining: std::sync::atomic::AtomicBool,
    pub(super) halted: std::sync::atomic::AtomicBool,
    pub listener: tokio::sync::Mutex<Option<Running>>,
    pub remote_listener: tokio::sync::Mutex<Option<Running>>,
    pub requests: Arc<tokio::sync::Semaphore>,
    pub controls: Arc<tokio::sync::Semaphore>,
    pub ingress: super::byte_budget::Pool,
    pub adapt_egress: super::byte_budget::Pool,
    pub adapted_configs: super::byte_budget::Pool,
    config_egress: super::byte_budget::Pool,
    pub bulk_cpu: Arc<tokio::sync::Semaphore>,
    pub cpu: Arc<tokio::sync::Semaphore>,
    pub cancel: tokio_util::sync::CancellationToken,
    stop_events: tokio::sync::watch::Sender<Option<super::AdminStopOutcome>>,
    force_join: tokio::sync::watch::Sender<Option<Result<(), AdminError>>>,
    source: Option<super::source::Tracked>,
    pub loader: Mutex<Option<tokio_util::sync::CancellationToken>>,
    reply_slots: Arc<tokio::sync::Semaphore>,
    responses: tokio_util::task::TaskTracker,
}
enum Admission {
    Open,
    StopPending(u64),
    Closed,
}
pub(super) enum ChangeBody {
    Loaded(super::loader::Loaded),
    HttpJson(Box<Buffer>, JsonRoute),
    AdaptedJson(Box<Buffer>),
}

#[derive(Clone, Copy)]
pub(super) enum JsonRoute {
    Load,
    Mutation,
}

impl JsonRoute {
    fn error(self, error: crate::admin_json::ConfigError) -> AdminError {
        let status = match (self, error.category) {
            (_, "configuration_materialization_limit") => 413,
            (Self::Load, _) | (_, "configuration_depth_limit") => 400,
            (Self::Mutation, _) => 500,
        };
        AdminError::new(status, error.category)
    }
}

struct Change {
    method: String,
    path: String,
    body: Option<ChangeBody>,
    if_match: Option<String>,
    force: bool,
    grant: Option<super::remote::Grant>,
    local: Option<super::local_access::LocalAdmission>,
    expected_generation: Option<u64>,
    loader_budget: u8,
    source: super::source::Action,
    // Retain the upload's accounting through queueing and accepted apply,
    // even if the HTTP reply waiter has disconnected.
    body_credit: Option<super::byte_budget::Credit>,
}
pub(super) struct Authorization {
    pub grant: Option<super::remote::Grant>,
    pub local: Option<super::local_access::LocalAdmission>,
}
pub(super) struct ChangeAdmission {
    pub authorization: Authorization,
    pub source: super::source::Action,
    pub body_credit: Option<super::byte_budget::Credit>,
}
enum Work {
    Change(Change),
    Stop(Authorization),
    Drain,
}
struct Job {
    id: u64,
    work: Work,
    reply: oneshot::Sender<Result<bool, AdminError>>,
    reply_slot: Option<tokio::sync::OwnedSemaphorePermit>,
}
struct Applied {
    changed: bool,
    completion: Option<super::AdminFuture<()>>,
}
fn unavailable() -> AdminError {
    AdminError::new(503, "admin_write_queue_unavailable")
}
fn dom(e: crate::admin_json::ConfigError) -> AdminError {
    AdminError::new(e.status, e.category)
}

impl AdminController {
    pub(super) fn borrowed(inner: Arc<Inner>) -> Self {
        Self {
            inner,
            _lifetime: None,
        }
    }
    pub fn new(
        initial: Value,
        options: AdminOptions,
        backend: Arc<dyn AdminBackend>,
    ) -> Result<Self, AdminError> {
        Self::new_with_source(initial, options, backend, None)
    }
    /// The path is captured by the executable, never adopted from HTTP.
    pub fn new_with_source(
        initial: Value,
        options: AdminOptions,
        backend: Arc<dyn AdminBackend>,
        source: Option<(std::path::PathBuf, std::path::PathBuf, Option<String>)>,
    ) -> Result<Self, AdminError> {
        options.validate()?;
        let encoded = crate::admin_json::encoded(&initial).map_err(dom)?;
        drop(initial);
        let initial = crate::admin_json::decode_canonical(&encoded).map_err(dom)?;
        drop(encoded);
        LocalPolicy::parse(&initial)?;
        let indexed = Indexed::new(initial)?;
        // Changes are independently bounded by reply_slots. Reserve one
        // channel position for stop and one for the drain barrier.
        let (sender, receiver) = mpsc::channel(options.queue_capacity + 3);
        let requests = Arc::new(tokio::sync::Semaphore::new(options.max_requests));
        let controls = Arc::new(tokio::sync::Semaphore::new(options.max_requests.min(8)));
        let ingress = super::byte_budget::Pool::new(
            super::byte_budget::DEFAULT_INGRESS.max(options.body_limit * 2),
            "admin_ingress_capacity_exceeded",
        );
        let adapt_egress = super::byte_budget::Pool::new(
            super::byte_budget::ADAPT_EGRESS,
            "admin_adapt_egress_capacity_exceeded",
        );
        let adapted_configs = super::byte_budget::Pool::new(
            super::byte_budget::ADAPTED_CONFIG,
            "admin_adapted_config_capacity_exceeded",
        );
        let config_egress =
            super::byte_budget::Pool::new(CONFIG_EGRESS, "admin_config_egress_capacity_exceeded");
        let cpu_count = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(1, 4));
        let (stop_events, _) = tokio::sync::watch::channel(None);
        let (force_join, _) = tokio::sync::watch::channel(None);
        let reply_slots = Arc::new(tokio::sync::Semaphore::new(options.queue_capacity + 1));
        let inner = Arc::new(Inner {
            state: ArcSwap::from_pointee(Published {
                indexed,
                generation: 0,
                access: None,
            }),
            options,
            backend,
            sender,
            admission: Mutex::new(Admission::Open),
            sequence: std::sync::atomic::AtomicU64::new(1),
            draining: std::sync::atomic::AtomicBool::new(false),
            halted: std::sync::atomic::AtomicBool::new(false),
            listener: tokio::sync::Mutex::new(None),
            remote_listener: tokio::sync::Mutex::new(None),
            requests,
            controls,
            ingress,
            adapt_egress,
            adapted_configs,
            config_egress,
            bulk_cpu: Arc::new(tokio::sync::Semaphore::new(cpu_count)),
            cpu: Arc::new(tokio::sync::Semaphore::new(cpu_count)),
            cancel: tokio_util::sync::CancellationToken::new(),
            stop_events,
            force_join,
            source: source
                .map(|(cwd, path, adapter)| super::source::Tracked::new(cwd, path, adapter)),
            loader: Mutex::new(None),
            reply_slots,
            responses: tokio_util::task::TaskTracker::new(),
        });
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            worker(weak, receiver).await;
        });
        let lifetime = Arc::new(ControllerLifetime(inner.cancel.clone()));
        Ok(Self {
            inner,
            _lifetime: Some(lifetime),
        })
    }
    pub fn stop_events(&self) -> tokio::sync::watch::Receiver<Option<super::AdminStopOutcome>> {
        self.inner.stop_events.subscribe()
    }
    pub fn source_active(&self) -> bool {
        self.inner
            .source
            .as_ref()
            .is_some_and(super::source::Tracked::active)
    }
    pub async fn reload_from_source(&self, body: Value, force: bool) -> Result<(), AdminError> {
        self.inner
            .enqueue(Work::Change(Change {
                method: "POST".into(),
                path: "/config".into(),
                body: Some(ChangeBody::Loaded(super::loader::Loaded::Adapted(body))),
                if_match: None,
                force,
                grant: None,
                local: None,
                expected_generation: None,
                loader_budget: 16,
                body_credit: None,
                source: super::source::Action::ProcessFile,
            }))
            .await
    }
    /// Drain Admin ingress and accepted response owners. The executable also
    /// drains its application backend, independently of Admin being enabled.
    pub async fn shutdown(&self) -> Result<(), AdminError> {
        self.inner.shutdown().await
    }
    pub async fn force_shutdown(&self) -> Result<(), AdminError> {
        reject_reentrant()?;
        let mut joined = self.inner.force_join.subscribe();
        self.inner.halt();
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                if let Some(outcome) = *joined.borrow_and_update() {
                    return outcome;
                }
                joined.changed().await.map_err(|_| unavailable())?;
            }
        })
        .await
        .map_err(|_| AdminError::new(503, "admin_forced_shutdown_incomplete"))?
    }
    pub async fn remote_address(&self) -> Option<String> {
        self.inner
            .remote_listener
            .lock()
            .await
            .as_ref()
            .map(|r| r.address.clone())
    }
    pub fn snapshot(&self) -> Result<Arc<Value>, AdminError> {
        self.inner.check_readable()?;
        let value = self.inner.state.load().raw.clone();
        self.inner.check_readable()?;
        Ok(value)
    }
    pub async fn start(&self) -> Result<Option<AdminServerHandle>, AdminError> {
        reject_reentrant()?;
        // Startup owns its critical section just like an accepted queue write.
        // Dropping a caller's wait cannot discard a Root commit observation.
        let owned = Self::borrowed(self.inner.clone());
        tokio::spawn(async move { owned.start_owned().await })
            .await
            .map_err(|_| AdminError::new(500, "admin_start_task_failed"))?
    }
    async fn start_owned(&self) -> Result<Option<AdminServerHandle>, AdminError> {
        self.inner.check_readable()?;
        if self
            .inner
            .draining
            .load(std::sync::atomic::Ordering::Acquire)
            || self.inner.cancel.is_cancelled()
        {
            return Err(AdminError::new(503, "admin_controller_shut_down"));
        }
        let mut local = self.inner.listener.lock().await;
        let mut remote = self.inner.remote_listener.lock().await;
        self.inner.check_readable()?;
        let previous = self.inner.state.load_full();
        if previous.generation > 0 {
            return Ok(local
                .as_ref()
                .or(remote.as_ref())
                .map(|r| AdminServerHandle::new(Arc::downgrade(&self.inner), r.address.clone())));
        }
        let raw = previous.raw.clone();
        let policy = self.inner.offload(move || LocalPolicy::parse(&raw)).await?;
        let prepared = if policy.disabled {
            None
        } else {
            Some(Prepared::prepare(&policy, &self.inner.options).await?)
        };
        let previous_copy = previous.clone();
        let runtime = self
            .inner
            .offload(move || Ok(previous_copy.runtime()))
            .await?;
        let (committed, mut guard) = transact_admin(
            &self.inner,
            AdminTransaction {
                config: runtime,
                force: false,
                expected_generation: Some(0),
                restore_only: false,
            },
            policy.clone(),
            prepared,
            false,
            Vec::new(),
        )
        .await?;
        if committed.generation == 0 {
            return Err(AdminError::new(500, "admin_backend_generation_invalid"));
        }
        self.inner.state.store(Arc::new(Published {
            indexed: previous.indexed.clone(),
            generation: committed.generation,
            access: guard.stage.access.clone(),
        }));
        if policy.persist
            && let Some(path) = self.inner.options.autosave.clone()
        {
            let raw = previous.raw.clone();
            if self
                .inner
                .offload(move || files::save(&path, &raw))
                .await
                .is_err()
            {
                eprintln!("admin event=autosave_failed category=admin_file_operation_failed");
            }
        }
        let accepting = !self.inner.cancel.is_cancelled() && !committed.stop_pending;
        if accepting {
            if let Some(ready) = guard.stage.local.take() {
                *local = Some(ready.start(Arc::downgrade(&self.inner)));
            }
            if let Some(ready) = guard.stage.remote.take() {
                *remote = Some(ready.start(Arc::downgrade(&self.inner)));
            }
        }
        let stage = guard.complete(PermissionPublication::Candidate);
        if accepting {
            super::loader::restart(
                &self.inner,
                policy.loader,
                stage.loaded,
                committed.generation,
                16,
            );
        }
        Ok(local
            .as_ref()
            .or(remote.as_ref())
            .map(|r| AdminServerHandle::new(Arc::downgrade(&self.inner), r.address.clone())))
    }
    pub async fn submit(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        if_match: Option<&str>,
        force: bool,
    ) -> Result<(), AdminError> {
        self.inner
            .enqueue(Work::Change(Change {
                method: method.to_owned(),
                path: path.to_owned(),
                body: body.map(|value| ChangeBody::Loaded(super::loader::Loaded::Adapted(value))),
                if_match: if_match.map(str::to_owned),
                force,
                grant: None,
                local: None,
                expected_generation: None,
                loader_budget: 16,
                body_credit: None,
                source: super::source::Action::None,
            }))
            .await
    }
    pub(super) async fn submit_authorized(
        &self,
        method: &str,
        path: &str,
        body: Option<ChangeBody>,
        if_match: Option<&str>,
        force: bool,
        admission: ChangeAdmission,
    ) -> Result<(), AdminError> {
        let ChangeAdmission {
            authorization: Authorization { grant, local },
            source,
            body_credit,
        } = admission;
        if let Some(local) = &local {
            local.check()?;
        }
        self.inner
            .enqueue(Work::Change(Change {
                method: method.to_owned(),
                path: path.to_owned(),
                body,
                if_match: if_match.map(str::to_owned),
                force,
                local,
                expected_generation: None,
                loader_budget: 16,
                source,
                grant,
                body_credit,
            }))
            .await
    }
    pub(super) async fn stop(
        &self,
        grant: Option<super::remote::Grant>,
        local: Option<super::local_access::LocalAdmission>,
    ) -> Result<(), AdminError> {
        if let Some(local) = &local {
            local.check()?;
        }
        self.inner
            .enqueue(Work::Stop(Authorization { grant, local }))
            .await
    }
    pub(super) async fn read_authorized(
        &self,
        path: &str,
        grant: Option<super::remote::Grant>,
        local: Option<super::local_access::LocalAdmission>,
    ) -> Result<(Bytes, String), AdminError> {
        self.inner.check_readable()?;
        let inner = self.inner.clone();
        let path = path.to_owned();
        self.inner
            .offload(move || {
                inner.check_readable()?;
                if let Some(local) = &local {
                    local.check()?;
                }
                let current = inner.state.load_full();
                let path = current.rewrite(&path)?;
                if let Some(grant) = grant {
                    current.authorize(&grant, Some(&path))?;
                }
                let value = crate::admin_json::read_config(&current.raw, &path)
                    .map_err(|e| AdminError::new(400, e.category))?;
                let body = if let Some(value) = value {
                    let (data, credit) =
                        crate::admin_json::encoded_reserved(value, CONFIG_EGRESS, |size| {
                            inner.config_egress.reserve(size).map_err(|e| {
                                crate::admin_json::ConfigError {
                                    status: e.status,
                                    category: e.category,
                                }
                            })
                        })
                        .map_err(dom)?;
                    Buffer::into_bytes(data, credit)
                } else {
                    Bytes::new()
                };
                let etag = crate::admin_json::etag_encoded(&path, &body);
                inner.check_readable()?;
                if let Some(local) = &local {
                    local.check()?;
                }
                Ok((body, etag))
            })
            .await
    }
}
impl Inner {
    pub(super) fn check_readable(&self) -> Result<(), AdminError> {
        self.backend.check_available()?;
        if self.halted.load(std::sync::atomic::Ordering::Acquire) {
            Err(AdminError::new(503, "admin_runtime_halted"))
        } else {
            Ok(())
        }
    }
    pub(super) fn halt(self: &Arc<Self>) {
        if self.halted.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        *self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Admission::Closed;
        self.cancel.cancel();
        let stop = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.backend.stop(StopMode::Force)
        }));
        self.stop_events
            .send_replace(Some(super::AdminStopOutcome::TransactionFailed));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = self.clone();
            runtime.spawn(async move {
                let remote = async {
                    if let Some(running) = inner.remote_listener.lock().await.take() {
                        running.force_shutdown().await;
                    }
                };
                let local = async {
                    if let Some(running) = inner.listener.lock().await.take() {
                        running.force_shutdown().await;
                    }
                };
                let backend = async {
                    match stop {
                        Ok(stop) => std::panic::AssertUnwindSafe(stop)
                            .catch_unwind()
                            .await
                            .unwrap_or_else(|_| {
                                Err(AdminError::new(503, "admin_forced_backend_shutdown_failed"))
                            }),
                        Err(_) => Err(AdminError::new(503, "admin_forced_backend_shutdown_failed")),
                    }
                };
                let (_, _, result) = tokio::join!(remote, local, backend);
                inner.force_join.send_replace(Some(result));
            });
        }
    }
    pub(super) async fn offload<
        T: Send + 'static,
        F: FnOnce() -> Result<T, AdminError> + Send + 'static,
    >(
        &self,
        work: F,
    ) -> Result<T, AdminError> {
        Self::offload_on(&self.cpu, work).await
    }
    pub(super) async fn offload_bulk<
        T: Send + 'static,
        F: FnOnce() -> Result<T, AdminError> + Send + 'static,
    >(
        &self,
        work: F,
    ) -> Result<T, AdminError> {
        Self::offload_on(&self.bulk_cpu, work).await
    }
    async fn offload_on<
        T: Send + 'static,
        F: FnOnce() -> Result<T, AdminError> + Send + 'static,
    >(
        lane: &Arc<tokio::sync::Semaphore>,
        work: F,
    ) -> Result<T, AdminError> {
        let permit = lane
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| unavailable())?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|_| AdminError::new(500, "admin_cpu_task_failed"))?
    }
    async fn enqueue(&self, work: Work) -> Result<(), AdminError> {
        reject_reentrant()?;
        self.check_readable()?;
        let reply_slot = if matches!(&work, Work::Change(_)) {
            Some(
                self.reply_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| unavailable())?,
            )
        } else {
            None
        };
        let (reply, wait) = oneshot::channel();
        {
            let mut admission = self.admission.lock().map_err(|_| unavailable())?;
            if !matches!(*admission, Admission::Open) {
                return Err(unavailable());
            }
            let closing = matches!(work, Work::Stop(_));
            let id = self
                .sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.sender
                .try_send(Job {
                    id,
                    work,
                    reply,
                    reply_slot,
                })
                .map_err(|_| unavailable())?;
            if closing {
                *admission = Admission::StopPending(id);
            }
        }
        wait.await.map_err(|_| unavailable())?.map(|_| ())
    }
    pub(super) async fn enqueue_loader(
        &self,
        value: super::loader::Loaded,
        generation: u64,
        budget: u8,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<bool, AdminError> {
        self.check_readable()?;
        let reply_slot = tokio::select! {biased;
            _=cancel.cancelled()=>return Err(unavailable()),
            slot=self.reply_slots.clone().acquire_owned()=>slot.map_err(|_|unavailable())?,
        };
        let permit = tokio::select! {_ = cancel.cancelled()=>return Err(unavailable()), p=self.sender.reserve()=>p.map_err(|_|unavailable())?};
        let (reply, wait) = oneshot::channel();
        {
            let admission = self.admission.lock().map_err(|_| unavailable())?;
            if !matches!(*admission, Admission::Open) || cancel.is_cancelled() {
                return Err(unavailable());
            }
            let id = self
                .sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            permit.send(Job {
                id,
                work: Work::Change(Change {
                    method: "POST".into(),
                    path: "/config".into(),
                    body: Some(ChangeBody::Loaded(value)),
                    if_match: None,
                    force: false,
                    grant: None,
                    local: None,
                    expected_generation: Some(generation),
                    loader_budget: budget,
                    body_credit: None,
                    source: super::source::Action::None,
                }),
                reply,
                reply_slot: Some(reply_slot),
            });
        }
        wait.await.map_err(|_| unavailable())?
    }
    pub(super) async fn shutdown(&self) -> Result<(), AdminError> {
        reject_reentrant()?;
        {
            let mut admission = self.admission.lock().map_err(|_| unavailable())?;
            *admission = Admission::Closed;
            self.draining
                .store(true, std::sync::atomic::Ordering::Release);
        }
        self.cancel.cancel();
        let (reply, wait) = oneshot::channel();
        let draining = async {
            self.sender
                .send(Job {
                    id: 0,
                    work: Work::Drain,
                    reply,
                    reply_slot: None,
                })
                .await
                .map_err(|_| unavailable())?;
            wait.await.map_err(|_| unavailable())?.map(|_| ())
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(35), draining)
            .await
            .map_err(|_| AdminError::new(503, "admin_shutdown_incomplete"));
        let teardown = async {
            let remote = async {
                if let Some(running) = self.remote_listener.lock().await.take() {
                    running.shutdown().await;
                }
            };
            let local = async {
                if let Some(running) = self.listener.lock().await.take() {
                    running.shutdown().await;
                }
            };
            tokio::join!(remote, local);
        };
        let closed = tokio::time::timeout(std::time::Duration::from_secs(36), teardown).await;
        if closed.is_err() {
            return Err(AdminError::new(503, "admin_shutdown_incomplete"));
        }
        outcome??;
        Ok(())
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
async fn worker(weak: Weak<Inner>, mut receiver: mpsc::Receiver<Job>) {
    while let Some(job) = receiver.recv().await {
        let Some(inner) = weak.upgrade() else {
            break;
        };
        if inner.check_readable().is_err() {
            let result = if matches!(job.work, Work::Stop(_) | Work::Drain) {
                Ok(false)
            } else {
                Err(AdminError::new(503, "admin_runtime_halted"))
            };
            let _ = job.reply.send(result);
            continue;
        }
        match job.work {
            Work::Drain => {
                inner.responses.close();
                inner.responses.wait().await;
                let _ = job.reply.send(Ok(false));
            }
            Work::Stop(Authorization { grant, local }) => {
                let current = inner.state.load_full();
                let authorization =
                    if let Some(error) = local.as_ref().and_then(|l| l.check().err()) {
                        Err(error)
                    } else if let Some(g) = &grant {
                        current.authorize(g, None)
                    } else if LocalPolicy::parse(&current.raw).is_ok_and(|p| p.disabled) {
                        Err(AdminError::new(403, "local_admin_authorization_revoked"))
                    } else {
                        Ok(())
                    };
                if let Err(error) = authorization {
                    if let Ok(mut admission) = inner.admission.lock()
                        && matches!(*admission,Admission::StopPending(id)if id==job.id)
                    {
                        *admission = Admission::Open;
                    }
                    let _ = job.reply.send(Err(error));
                    continue;
                }
                if let Ok(mut admission) = inner.admission.lock() {
                    *admission = Admission::Closed;
                }
                let _ = job.reply.send(Ok(false));
                let backend = inner.backend.clone();
                tokio::spawn(async move {
                    if inner.shutdown().await.is_err() {
                        inner
                            .stop_events
                            .send_replace(Some(super::AdminStopOutcome::DrainIncomplete));
                        eprintln!("admin event=stop_failed category=admin_shutdown_incomplete");
                        return;
                    }
                    let result = std::panic::AssertUnwindSafe(backend.stop_unbounded())
                        .catch_unwind()
                        .await;
                    match result {
                        Ok(Ok(())) => {
                            inner
                                .stop_events
                                .send_replace(Some(super::AdminStopOutcome::Complete));
                        }
                        _ => {
                            inner
                                .stop_events
                                .send_replace(Some(super::AdminStopOutcome::BackendStopFailed));
                            eprintln!("admin event=stop_failed category=admin_backend_stop_failed");
                        }
                    }
                });
            }
            Work::Change(change) => {
                let result = std::panic::AssertUnwindSafe(apply(&inner, change))
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| Err(AdminError::new(500, "admin_internal_error")));
                match result {
                    Ok(Applied {
                        changed,
                        completion: Some(completion),
                    }) => {
                        let waiting = inner.clone();
                        inner.responses.spawn(async move {
                            let _slot = job.reply_slot;
                            let mut reply = job.reply;
                            // Publication and its cleanup are already owned by
                            // Root. Cancelling only this response wait cannot
                            // roll back or cancel an accepted configuration.
                            let result = tokio::select! {biased;
                                _=waiting.cancel.cancelled()=>Err(AdminError::new(503,"admin_configuration_published_wait_interrupted")),
                                _=reply.closed()=>return,
                                result=std::panic::AssertUnwindSafe(completion).catch_unwind()=>
                                    result.unwrap_or_else(|_|Err(AdminError::new(500,"admin_completion_failed"))),
                            };
                            let _ = reply.send(result.map(|_| changed));
                        });
                    }
                    Ok(Applied {
                        changed,
                        completion: None,
                    }) => {
                        let _ = job.reply.send(Ok(changed));
                    }
                    Err(error) => {
                        let _ = job.reply.send(Err(error));
                    }
                }
            }
        }
    }
}
fn match_etag(
    current: &Published,
    condition: &str,
    grant: Option<&super::remote::Grant>,
) -> Result<(), AdminError> {
    if condition.len() < 2 || !condition.starts_with('"') || !condition.ends_with('"') {
        return Err(AdminError::new(400, "malformed_if_match"));
    }
    let fields = condition[1..condition.len() - 1]
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() != 2 {
        return Err(AdminError::new(400, "malformed_if_match"));
    }
    let path = current.rewrite(fields[0])?;
    if let Some(grant) = grant {
        let read = super::remote::Grant {
            chain: grant.chain.clone(),
            method: "GET".into(),
            path: fields[0].into(),
        };
        current.authorize(&read, Some(&path))?;
    }
    let value = crate::admin_json::read_config(&current.raw, &path).map_err(dom)?;
    let actual = crate::admin_json::etag(fields[0], value).map_err(dom)?;
    if actual != condition {
        return Err(AdminError::new(412, "configuration_precondition_failed"));
    }
    Ok(())
}
struct Candidate {
    previous: Arc<Published>,
    candidate: Indexed,
    policy: LocalPolicy,
    path: String,
    change: Change,
    runtime: Value,
}
fn prepare_change(
    previous: Arc<Published>,
    mut change: Change,
) -> Result<Option<Candidate>, AdminError> {
    if change
        .expected_generation
        .is_some_and(|g| g != previous.generation)
    {
        return Err(AdminError::new(409, "config_loader_stale_generation"));
    }
    if let Some(grant) = &change.grant {
        previous.authorize(grant, None)?;
    }
    if let Some(local) = &change.local {
        local.check()?;
    }
    let path = previous.rewrite(&change.path)?;
    if let Some(grant) = &change.grant {
        previous.authorize(grant, Some(&path))?;
    } else if change.local.is_some() && LocalPolicy::parse(&previous.raw)?.disabled {
        return Err(AdminError::new(403, "local_admin_authorization_revoked"));
    }
    if let Some(tag) = change.if_match.as_deref() {
        match_etag(&previous, tag, change.grant.as_ref())?;
    }
    if path != "/config" && !path.starts_with("/config/") {
        return Err(AdminError::new(404, "admin_route_not_found"));
    }
    // Keep only the raw, charged body in the queue. Once selected, decode
    // before traversing/editing the candidate. If-Match is checked first.
    let body = match change.body.take() {
        Some(ChangeBody::HttpJson(bytes, route)) => {
            let bytes = *bytes;
            let value = crate::admin_json::decoded_typed(bytes.as_ref())
                .map_err(|error| route.error(error))?;
            change.body_credit = Some(bytes.release_data());
            Some(value)
        }
        Some(ChangeBody::AdaptedJson(bytes)) => {
            let bytes = *bytes;
            Some(crate::admin_json::decode_canonical(bytes.as_ref()).map_err(dom)?)
        }
        Some(ChangeBody::Loaded(value)) => Some(value.decode()?),
        None => None,
    };
    if change.expected_generation.is_some() && body.as_ref().is_none_or(|value| !value.is_object())
    {
        return Err(AdminError::new(400, "config_loader_requires_object"));
    }
    let mut wrapper = Value::Object(
        std::iter::once(("config".to_owned(), previous.raw.as_ref().clone())).collect(),
    );
    crate::admin_json::access(&mut wrapper, &change.method, &path, body).map_err(dom)?;
    let raw = wrapper
        .as_object_mut()
        .and_then(|map| map.remove("config"))
        .unwrap_or(Value::Null);
    let encoded = crate::admin_json::encoded(&raw).map_err(dom)?;
    drop(raw);
    let normalized = crate::admin_json::decode_canonical(&encoded).map_err(dom)?;
    let candidate = Indexed::new(normalized)?;
    let policy = LocalPolicy::parse(&candidate.raw)?;

    if !change.force && crate::admin_json::encoded_matches(&previous.raw, &encoded).map_err(dom)? {
        return Ok(None);
    }
    drop(encoded);
    let runtime = candidate.runtime();
    Ok(Some(Candidate {
        previous,
        candidate,
        policy,
        path,
        change,
        runtime,
    }))
}
async fn apply(inner: &Arc<Inner>, change: Change) -> Result<Applied, AdminError> {
    inner.check_readable()?;
    let previous = inner.state.load_full();
    let source_action = change.source.clone();
    if matches!(&source_action, super::source::Action::ProcessFile)
        && inner.source.as_ref().is_none_or(|source| !source.active())
    {
        return Err(AdminError::new(409, "process_config_source_changed"));
    }
    let Some(Candidate {
        previous,
        candidate,
        policy,
        path,
        change,
        runtime,
    }) = inner
        .offload(move || prepare_change(previous, change))
        .await?
    else {
        if let Some(source) = &inner.source {
            source.accepted(&source_action);
        }
        return Ok(Applied {
            changed: false,
            completion: None,
        });
    };
    let mut local = inner.listener.lock().await;
    let mut remote = inner.remote_listener.lock().await;
    inner.check_readable()?;
    if inner.cancel.is_cancelled() {
        return Err(unavailable());
    }
    if inner.state.load().generation != previous.generation {
        return Err(AdminError::new(409, "admin_configuration_stale_generation"));
    }
    if let Some(grant) = &change.grant {
        previous.authorize(grant, Some(&path))?;
    }
    if let Some(local) = &change.local {
        local.check()?;
    }
    let same = local
        .as_ref()
        .is_some_and(|r| r.same_local_endpoint(&policy));
    let remote_same = policy.remote.as_ref().is_some_and(|p| {
        remote
            .as_ref()
            .is_some_and(|r| r.same_remote_endpoint(&p.listen))
    });
    let local_policy = if same && !policy.disabled {
        local
            .as_ref()
            .map(|r| r.prepare_policy(&policy))
            .transpose()?
    } else {
        None
    };
    let mut modes = Vec::new();
    if same
        && !policy.disabled
        && let Some(running) = local.as_ref()
        && let Some(mode) = running.mode_change(&policy)?
    {
        modes.push(mode);
    }
    if remote_same && let (Some(running), Some(config)) = (remote.as_ref(), policy.remote.as_ref())
    {
        let p = LocalPolicy::parse(&json!({"admin":{"listen":config.listen}}))?;
        if let Some(mode) = running.mode_change(&p)? {
            modes.push(mode);
        }
    }
    let prepared = if !policy.disabled && !same {
        Some(Prepared::prepare(&policy, &inner.options).await?)
    } else {
        None
    };
    let (committed, mut guard) = transact_admin(
        inner,
        AdminTransaction {
            config: runtime,
            force: change.force,
            expected_generation: Some(previous.generation),
            restore_only: false,
        },
        policy.clone(),
        prepared,
        remote_same,
        modes,
    )
    .await?;
    if committed.generation <= previous.generation {
        return Err(AdminError::new(500, "admin_backend_generation_invalid"));
    }
    let mode_error = guard
        .stage
        .modes
        .iter_mut()
        .filter(|m| !m.restrictive())
        .find_map(|m| m.commit().err());
    if let Some(error) = mode_error {
        for mode in &mut guard.stage.modes {
            mode.retighten()?;
        }
        // The old Admin listeners/access are still bound and unchanged. Root
        // restages the predecessor once using its retained verified material;
        // no identity acquisition, fetch, or Admin bind occurs in this finisher.
        if let Some(running) = local.as_ref() {
            running.validate_retained()?;
        }
        if let Some(running) = remote.as_ref() {
            running.validate_retained()?;
        }
        let old = previous.clone();
        let runtime = inner.offload(move || Ok(old.runtime())).await?;
        let old_policy = LocalPolicy::parse(&previous.raw)?;
        let restored = transaction_scope(inner.backend.transact(
            AdminTransaction {
                config: runtime,
                force: true,
                expected_generation: Some(committed.generation),
                restore_only: true,
            },
            Box::new(|_| Box::pin(async { Ok(()) })),
        ))
        .await
        .map_err(|_| AdminError::new(500, "admin_runtime_rollback_failed"))?;
        if restored.generation <= committed.generation {
            return Err(AdminError::new(500, "admin_backend_generation_invalid"));
        }
        for mode in &mut guard.stage.modes {
            mode.restore()?;
        }
        if let Some(running) = local.as_ref() {
            running.validate_retained()?;
        }
        if let Some(running) = remote.as_ref() {
            running.validate_retained()?;
        }
        inner.state.store(Arc::new(Published {
            indexed: previous.indexed.clone(),
            generation: restored.generation,
            access: previous.access.clone(),
        }));
        let _discarded = guard.complete(PermissionPublication::Predecessor);
        if !restored.stop_pending && !inner.cancel.is_cancelled() {
            super::loader::restart(
                inner,
                old_policy.loader,
                None,
                restored.generation,
                change.loader_budget,
            );
        }
        return Err(error);
    }
    let raw = candidate.raw.clone();
    inner.state.store(Arc::new(Published {
        indexed: candidate,
        generation: committed.generation,
        access: guard.stage.access.clone(),
    }));
    if let Some(source) = &inner.source {
        source.accepted(&source_action);
    }
    let mut retired = Vec::new();
    let accepting = !committed.stop_pending && !inner.cancel.is_cancelled();
    if policy.disabled {
        if let Some(old) = local.take() {
            retired.push(old);
        }
    } else if let Some(ready) = guard.stage.local.take() {
        if accepting && let Some(old) = local.replace(ready.start(Arc::downgrade(inner))) {
            retired.push(old);
        }
    } else if let (Some(running), Some(prepared_policy)) = (local.as_ref(), local_policy) {
        running.install_policy(prepared_policy);
    }
    if let Some(ready) = guard.stage.remote.take() {
        if accepting && let Some(old) = remote.replace(ready.start(Arc::downgrade(inner))) {
            retired.push(old);
        }
    } else if let Some(access) = guard.stage.access.take() {
        if let Some(running) = remote.as_ref() {
            running.update_remote(access);
        }
    } else if let Some(old) = remote.take() {
        retired.push(old);
    }
    let stage = guard.complete(PermissionPublication::Candidate);
    drop(remote);
    drop(local);
    for old in retired {
        old.retire().await;
    }
    if accepting {
        super::loader::restart(
            inner,
            policy.loader,
            stage.loaded,
            committed.generation,
            change.loader_budget,
        );
    }
    if policy.persist
        && let Some(path) = inner.options.autosave.clone()
    {
        let result = inner.offload(move || files::save(&path, &raw)).await;
        if result.is_err() {
            eprintln!("admin event=autosave_failed category=admin_file_operation_failed");
        }
    }
    Ok(Applied {
        changed: true,
        completion: stage.completion,
    })
}
