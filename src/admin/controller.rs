use super::{
    AdminBackend, AdminError, AdminOptions, files,
    ids::Indexed,
    policy::LocalPolicy,
    server::{AdminServerHandle, Prepared, Running},
};
use arc_swap::ArcSwap;
use futures_util::FutureExt;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{mpsc, oneshot};

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
    pub listener: tokio::sync::Mutex<Option<Running>>,
    pub remote_listener: tokio::sync::Mutex<Option<Running>>,
    pub requests: Arc<tokio::sync::Semaphore>,
    pub cpu: Arc<tokio::sync::Semaphore>,
    pub cancel: tokio_util::sync::CancellationToken,
    stop_events: tokio::sync::watch::Sender<Option<super::AdminStopOutcome>>,
    pub loader: Mutex<Option<tokio_util::sync::CancellationToken>>,
}
enum Admission {
    Open,
    StopPending(u64),
    Closed,
}
struct Change {
    method: String,
    path: String,
    body: Option<super::loader::Loaded>,
    if_match: Option<String>,
    force: bool,
    grant: Option<super::remote::Grant>,
    local_http: bool,
    expected_generation: Option<u64>,
    loader_budget: u8,
}
enum Work {
    Change(Change),
    Stop(Option<super::remote::Grant>),
    Drain,
}
struct Job {
    id: u64,
    work: Work,
    reply: oneshot::Sender<Result<bool, AdminError>>,
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
        options.validate()?;
        let initial =
            crate::admin_json::decoded(&crate::admin_json::encoded(&initial).map_err(dom)?)
                .map_err(dom)?;
        LocalPolicy::parse(&initial)?;
        let indexed = Indexed::new(initial)?;
        let (sender, receiver) = mpsc::channel(options.queue_capacity);
        let requests = Arc::new(tokio::sync::Semaphore::new(options.max_requests));
        let (stop_events, _) = tokio::sync::watch::channel(None);
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
            listener: tokio::sync::Mutex::new(None),
            remote_listener: tokio::sync::Mutex::new(None),
            requests,
            cpu: Arc::new(tokio::sync::Semaphore::new(
                std::thread::available_parallelism().map_or(2, |n| n.get().clamp(1, 4)),
            )),
            cancel: tokio_util::sync::CancellationToken::new(),
            stop_events,
            loader: Mutex::new(None),
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
    pub async fn remote_address(&self) -> Option<String> {
        self.inner
            .remote_listener
            .lock()
            .await
            .as_ref()
            .map(|r| r.address.clone())
    }
    pub fn snapshot(&self) -> Arc<Value> {
        self.inner.state.load().raw.clone()
    }
    pub async fn start(&self) -> Result<AdminServerHandle, AdminError> {
        if self
            .inner
            .draining
            .load(std::sync::atomic::Ordering::Acquire)
            || self.inner.cancel.is_cancelled()
        {
            return Err(AdminError::new(503, "admin_controller_shut_down"));
        }
        let mut current = self.inner.listener.lock().await;
        if let Some(running) = current.as_ref() {
            return Ok(AdminServerHandle::new(
                Arc::downgrade(&self.inner),
                running.address.clone(),
            ));
        }
        let raw = self.inner.state.load().raw.as_ref().clone();
        let policy = LocalPolicy::parse(&raw)?;
        let mut remote_current = self.inner.remote_listener.lock().await;
        if let Some(running) = remote_current.as_ref() {
            return Ok(AdminServerHandle::new(
                Arc::downgrade(&self.inner),
                running.address.clone(),
            ));
        }
        if self.inner.cancel.is_cancelled() {
            return Err(AdminError::new(503, "admin_controller_shut_down"));
        }
        let resolver = if policy.identity.is_some() {
            Some(self.inner.backend.identity(raw).await?)
        } else {
            None
        };
        let remote_access = if let Some(remote) = &policy.remote {
            Some(super::remote::RemoteAccess::new(
                remote,
                resolver
                    .clone()
                    .ok_or_else(|| AdminError::new(400, "remote_admin_requires_identity"))?,
            )?)
        } else {
            None
        };
        let remote_ready = if let (Some(remote), Some(access)) = (&policy.remote, &remote_access) {
            Some(Prepared::prepare_remote(remote, access.clone(), &self.inner.options).await?)
        } else {
            None
        };
        let local_ready = if policy.disabled {
            None
        } else {
            Some(Prepared::prepare(&policy, &self.inner.options).await?)
        };
        let address = local_ready
            .as_ref()
            .or(remote_ready.as_ref())
            .map(|p| p.address.clone())
            .ok_or_else(|| AdminError::new(400, "admin_disabled"))?;
        let initial = self.inner.state.load().raw.clone();
        let initial_loaded = finish_load(&self.inner, &policy, initial.clone(), false).await?;
        self.inner.state.store(Arc::new(Published {
            indexed: self.inner.state.load().indexed.clone(),
            generation: 0,
            access: remote_access,
        }));
        if let Some(ready) = local_ready {
            *current = Some(ready.start(Arc::downgrade(&self.inner)));
        }
        if let Some(ready) = remote_ready {
            *remote_current = Some(ready.start(Arc::downgrade(&self.inner)));
        }
        super::loader::restart(&self.inner, policy.loader, initial_loaded, 0, 16);
        Ok(AdminServerHandle::new(Arc::downgrade(&self.inner), address))
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
                body: body.map(super::loader::Loaded::Adapted),
                if_match: if_match.map(str::to_owned),
                force,
                grant: None,
                local_http: false,
                expected_generation: None,
                loader_budget: 16,
            }))
            .await
    }
    pub(super) async fn submit_authorized(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        if_match: Option<&str>,
        force: bool,
        grant: Option<super::remote::Grant>,
    ) -> Result<(), AdminError> {
        self.inner
            .enqueue(Work::Change(Change {
                method: method.to_owned(),
                path: path.to_owned(),
                body: body.map(super::loader::Loaded::Adapted),
                if_match: if_match.map(str::to_owned),
                force,
                local_http: grant.is_none(),
                expected_generation: None,
                loader_budget: 16,
                grant,
            }))
            .await
    }
    pub(super) async fn stop(&self, grant: Option<super::remote::Grant>) -> Result<(), AdminError> {
        self.inner.enqueue(Work::Stop(grant)).await
    }
    pub(super) async fn read_authorized(
        &self,
        path: &str,
        grant: Option<super::remote::Grant>,
    ) -> Result<(Vec<u8>, String), AdminError> {
        let inner = self.inner.clone();
        let path = path.to_owned();
        self.inner
            .offload(move || {
                let current = inner.state.load_full();
                let path = current.rewrite(&path)?;
                if let Some(grant) = grant {
                    current.authorize(&grant, Some(&path))?;
                }
                let value = crate::admin_json::read_config(&current.raw, &path)
                    .map_err(|e| AdminError::new(400, e.category))?;
                let body = value
                    .map(crate::admin_json::encoded)
                    .transpose()
                    .map_err(dom)?
                    .unwrap_or_default();
                let etag = crate::admin_json::etag_encoded(&path, &body);
                Ok((body, etag))
            })
            .await
    }
}
impl Inner {
    pub(super) async fn offload<
        T: Send + 'static,
        F: FnOnce() -> Result<T, AdminError> + Send + 'static,
    >(
        &self,
        work: F,
    ) -> Result<T, AdminError> {
        let permit = self
            .cpu
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
                .try_send(Job { id, work, reply })
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
                    body: Some(value),
                    if_match: None,
                    force: false,
                    grant: None,
                    local_http: false,
                    expected_generation: Some(generation),
                    loader_budget: budget,
                }),
                reply,
            });
        }
        wait.await.map_err(|_| unavailable())?
    }
    pub(super) async fn shutdown(&self) -> Result<(), AdminError> {
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
                })
                .await
                .map_err(|_| unavailable())?;
            wait.await.map_err(|_| unavailable())?.map(|_| ())
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(35), draining)
            .await
            .map_err(|_| AdminError::new(503, "admin_shutdown_incomplete"));
        let teardown = async {
            if let Some(running) = self.remote_listener.lock().await.take() {
                running.shutdown().await;
            }
            if let Some(running) = self.listener.lock().await.take() {
                running.shutdown().await;
            }
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
        match job.work {
            Work::Drain => {
                let _ = job.reply.send(Ok(false));
            }
            Work::Stop(grant) => {
                let current = inner.state.load_full();
                let authorization = if let Some(g) = &grant {
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
                    let result = std::panic::AssertUnwindSafe(backend.stop())
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
                let _ = job.reply.send(result);
            }
        }
    }
}
fn match_etag(current: &Indexed, condition: &str) -> Result<(), AdminError> {
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
    let value = crate::admin_json::read_config(&current.raw, &path).map_err(dom)?;
    let bytes = value
        .map(crate::admin_json::encoded)
        .transpose()
        .map_err(dom)?
        .unwrap_or_default();
    let actual = crate::admin_json::etag_encoded(fields[0], &bytes);
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
    if let Some(tag) = change.if_match.as_deref() {
        match_etag(&previous, tag)?;
    }
    let path = previous.rewrite(&change.path)?;
    if let Some(grant) = &change.grant {
        previous.authorize(grant, Some(&path))?;
    } else if change.local_http && LocalPolicy::parse(&previous.raw)?.disabled {
        return Err(AdminError::new(403, "local_admin_authorization_revoked"));
    }
    if path != "/config" && !path.starts_with("/config/") {
        return Err(AdminError::new(404, "admin_route_not_found"));
    }
    let mut wrapper = json!({"config":previous.raw.as_ref()});
    let body = change
        .body
        .take()
        .map(super::loader::Loaded::decode)
        .transpose()?;
    if change.expected_generation.is_some() && body.as_ref().is_none_or(|value| !value.is_object())
    {
        return Err(AdminError::new(400, "config_loader_requires_object"));
    }
    crate::admin_json::access(&mut wrapper, &change.method, &path, body).map_err(dom)?;
    let raw = wrapper.get("config").cloned().unwrap_or(Value::Null);
    let normalized =
        crate::admin_json::decoded(&crate::admin_json::encoded(&raw).map_err(dom)?).map_err(dom)?;
    let candidate = Indexed::new(normalized)?;
    let policy = LocalPolicy::parse(&candidate.raw)?;

    if !change.force
        && crate::admin_json::encoded(&candidate.raw).map_err(dom)?
            == crate::admin_json::encoded(&previous.raw).map_err(dom)?
    {
        return Ok(None);
    }
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
async fn apply(inner: &Arc<Inner>, change: Change) -> Result<bool, AdminError> {
    let previous = inner.state.load_full();
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
        return Ok(false);
    };
    let mut listener = inner.listener.lock().await;
    let mut remote_listener = inner.remote_listener.lock().await;
    let resolver = if policy.identity.is_some() {
        let raw = candidate.raw.clone();
        let copy = inner.offload(move || Ok(raw.as_ref().clone())).await?;
        Some(inner.backend.identity(copy).await?)
    } else {
        None
    };
    let remote_access = if policy.remote.is_some() {
        let raw = candidate.raw.clone();
        let resolver =
            resolver.ok_or_else(|| AdminError::new(400, "remote_admin_requires_identity"))?;
        Some(
            inner
                .offload(move || {
                    let remote = LocalPolicy::parse(&raw)?
                        .remote
                        .ok_or_else(|| AdminError::new(400, "remote_admin_requires_identity"))?;
                    super::remote::RemoteAccess::new(&remote, resolver)
                })
                .await?,
        )
    } else {
        None
    };
    let remote_same = policy.remote.as_ref().is_some_and(|p| {
        remote_listener
            .as_ref()
            .is_some_and(|r| r.same_remote_endpoint(&p.listen))
    });
    let remote_prepared = if let (Some(config), Some(access)) = (&policy.remote, &remote_access) {
        if !remote_same {
            Some(Prepared::prepare_remote(config, access.clone(), &inner.options).await?)
        } else {
            None
        }
    } else {
        None
    };

    let same = listener
        .as_ref()
        .is_some_and(|r| r.same_local_endpoint(&policy));
    let prepared = if !policy.disabled && !same {
        Some(Prepared::prepare(&policy, &inner.options).await?)
    } else {
        None
    };
    if !policy.disabled
        && same
        && let Some(running) = listener.as_ref()
    {
        running.validate_policy(&policy)?;
    }
    let mut mode_changes = Vec::new();
    if same
        && !policy.disabled
        && let Some(running) = listener.as_ref()
        && let Some(mode) = running.mode_change(&policy)?
    {
        mode_changes.push(mode);
    }
    if remote_same
        && let (Some(running), Some(remote)) = (remote_listener.as_ref(), policy.remote.as_ref())
    {
        let local = LocalPolicy::parse(&json!({"admin":{"listen":remote.listen}}))?;
        if let Some(mode) = running.mode_change(&local)? {
            mode_changes.push(mode);
        }
    }
    for mode in &mut mode_changes {
        if mode.restrictive() {
            mode.commit()?;
        }
    }
    if let Some(grant) = &change.grant {
        previous.authorize(grant, Some(&path))?;
    }
    let loaded = if policy.loader.as_ref().is_some_and(|p| p.delay.is_zero()) {
        finish_load_with_runtime(inner, &policy, candidate.raw.clone(), runtime, change.force)
            .await?
    } else {
        inner.backend.apply(runtime, change.force).await?;
        None
    };
    for mode in &mut mode_changes {
        if !mode.restrictive()
            && let Err(error) = mode.commit()
        {
            let saved = previous.clone();
            let runtime = inner.offload(move || Ok(saved.runtime())).await?;
            if inner.backend.apply(runtime, true).await.is_err() {
                return Err(AdminError::new(500, "admin_runtime_rollback_failed"));
            }
            return Err(error);
        }
    }

    let raw = candidate.raw.clone();
    inner.state.store(Arc::new(Published {
        indexed: candidate,
        generation: previous.generation.wrapping_add(1),
        access: remote_access.clone(),
    }));
    if policy.disabled {
        if let Some(old) = listener.take() {
            old.retire().await;
        }
    } else if let Some(ready) = prepared {
        let new = ready.start(Arc::downgrade(inner));
        if let Some(old) = listener.replace(new) {
            old.retire().await;
        }
    } else if same && let Some(running) = listener.as_ref() {
        running.update_policy(&policy)?;
    }
    if let Some(ready) = remote_prepared {
        if let Some(old) = remote_listener.replace(ready.start(Arc::downgrade(inner))) {
            old.retire().await;
        }
    } else if let Some(access) = remote_access {
        if let Some(running) = remote_listener.as_ref() {
            running.update_remote(access);
        }
    } else if let Some(old) = remote_listener.take() {
        old.retire().await;
    }
    for mode in mode_changes {
        mode.finish();
    }
    drop(remote_listener);
    drop(listener);
    super::loader::restart(
        inner,
        policy.loader.clone(),
        loaded,
        previous.generation.wrapping_add(1),
        change.loader_budget,
    );
    if policy.persist
        && let Some(path) = inner.options.autosave.clone()
    {
        let result = tokio::task::spawn_blocking(move || files::save(&path, &raw)).await;
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("admin event=autosave_failed category=admin_file_operation_failed");
        }
    }
    Ok(true)
}

async fn finish_load(
    inner: &Arc<Inner>,
    policy: &LocalPolicy,
    candidate: Arc<Value>,
    force: bool,
) -> Result<Option<super::loader::Loaded>, AdminError> {
    if !policy.loader.as_ref().is_some_and(|p| p.delay.is_zero()) {
        return Ok(None);
    }
    let raw = candidate.clone();
    let runtime = inner
        .offload(move || Ok(Indexed::new((*raw).clone())?.runtime()))
        .await?;
    finish_load_with_runtime(inner, policy, candidate, runtime, force).await
}
async fn finish_load_with_runtime(
    inner: &Arc<Inner>,
    policy: &LocalPolicy,
    candidate: Arc<Value>,
    runtime: Value,
    force: bool,
) -> Result<Option<super::loader::Loaded>, AdminError> {
    let Some(plan) = policy.loader.clone().filter(|p| p.delay.is_zero()) else {
        return Ok(None);
    };
    let slot = Arc::new(Mutex::new(None));
    let output = slot.clone();
    let owned = inner.clone();
    let cancel = inner.cancel.child_token();
    let finish: super::AdminFinisher = Box::new(move || {
        Box::pin(async move {
            let value = super::loader::load(&owned, plan, candidate, cancel).await?;
            *output
                .lock()
                .map_err(|_| AdminError::new(500, "config_loader_checkpoint_failed"))? =
                Some(value);
            Ok(())
        })
    });
    inner
        .backend
        .apply_with_finisher(runtime, force, finish)
        .await?;
    let loaded = slot
        .lock()
        .map_err(|_| AdminError::new(500, "config_loader_checkpoint_failed"))?
        .take();
    if loaded.is_none() {
        return Err(AdminError::new(500, "config_loader_finisher_not_run"));
    }
    Ok(loaded)
}
