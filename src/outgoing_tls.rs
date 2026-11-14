//! Root-owned default-client connection scheduling and actual IO lifetimes.
//! CPU/handshake admission belongs to the existing executor. These loans are
//! only additional wrapper metadata. Certificate callers also charge their total
//! pool; observability has a separate, independent pool.
use crate::http_runtime::tls_executor::{ClientTlsExecutor, TlsExecutor};
use anyhow::Result;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::{
    sync::CancellationToken,
    task::{TaskTracker, task_tracker::TaskTrackerToken},
};
use tower_layer::Layer;
use tower_service::Service;
type Error = Box<dyn std::error::Error + Send + Sync>;
type Connection = reqwest::tls::ScopedConnection;
/// Confirmed local connection control failure, never a remote-issuer failure.
/// The original resource/scheduler error remains in the source chain.
#[derive(Debug)]
pub(crate) enum ConnectionControl {
    Admission(Error),
    Stopped,
    Scheduling(Error),
}
impl std::fmt::Display for ConnectionControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admission(_) => f.write_str("outgoing TLS admission refused"),
            Self::Stopped => f.write_str("outgoing TLS scope stopped"),
            Self::Scheduling(_) => f.write_str("outgoing TLS scheduling failed"),
        }
    }
}
impl std::error::Error for ConnectionControl {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(e) | Self::Scheduling(e) => Some(e.as_ref()),
            Self::Stopped => None,
        }
    }
}

const WRAPPER_BYTES: usize = 8 << 20;
// Separate, finite reserves for pinned runtime control primitives. No claim
// about original profile backing allocations, provider heap or process RSS.
const MASTER_PRIMITIVES: usize = 8192;
const CHILD_PRIMITIVES: usize = 2048;
const EXECUTOR_HANDOFF: usize = 1024;

// Pinned tokio-util 0.7.20 TreeNode retains children Vec capacity. Its
// own parent loan pays that high-water until real destruction. Child loans
// may not pay it and then refund while the parent Vec remains allocated.
fn metadata_sum(values: &[usize]) -> Result<usize> {
    values.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| crate::cert_transient::ResourceDenied.into())
    })
}
fn maximum_children(minimum_loan: usize) -> Result<usize> {
    WRAPPER_BYTES
        .checked_div(minimum_loan)
        .ok_or_else(|| crate::cert_transient::ResourceDenied.into())
}
fn minimum_connection_payload() -> Result<usize> {
    // Every execute child is created only after both admission stages succeed.
    // Ignore positive Call/service/request/future/result sizes for this lower
    // bound, including calls that have not yet acquired an executor queue slot.
    metadata_sum(&[
        std::mem::size_of::<Life>(),
        std::mem::size_of::<ScopedIo>(),
        std::mem::size_of::<tokio_util::sync::WaitForCancellationFutureOwned>(),
        reqwest::tls::scoped_connector_clone_bound(),
        128,
        EXECUTOR_HANDOFF,
    ])
}
fn physical_work_bytes() -> Result<usize> {
    metadata_sum(&[
        std::mem::size_of::<PhysicalWork>(),
        2 * std::mem::size_of::<usize>(), // new physical Arc control block
        2 * std::mem::size_of::<Option<ConnectionLease>>(), // input + tracked executor receipt
    ])
}
fn minimum_connection_loan() -> Result<usize> {
    metadata_sum(&[minimum_connection_payload()?, physical_work_bytes()?])
}
fn cancellation_children_bytes(children: usize) -> Result<usize> {
    // Rust 1.100 RawVec::grow_amortized: before growth oldcap < required <= N;
    // newcap <= 2N, including reserve() jumps in TreeNode::move_children_to_parent.
    // Old+new peak is <3N (minimum four Arc slots), not a guessed fixed allowance.
    children
        .max(4)
        .checked_next_power_of_two()
        .and_then(|capacity| capacity.checked_mul(std::mem::size_of::<Arc<()>>()))
        .and_then(|bytes| bytes.checked_mul(3))
        .ok_or_else(|| crate::cert_transient::ResourceDenied.into())
}
fn scope_fixed_metadata_bytes() -> Result<usize> {
    metadata_sum(&[
        std::mem::size_of::<Scope>(),
        std::mem::size_of::<ScopeOwner>(),
        CHILD_PRIMITIVES,
        physical_tracker_bytes()?,
    ])
}
// Only two scope roles exist: a generation may create issuer legs; a leg
// cannot create another scope. Each leg's children are actual connection jobs.
fn leg_metadata_bytes() -> Result<usize> {
    metadata_sum(&[
        scope_fixed_metadata_bytes()?,
        cancellation_children_bytes(maximum_children(minimum_connection_loan()?)?)?,
    ])
}
fn scope_metadata_bytes() -> Result<usize> {
    let children=metadata_sum(&[
        maximum_children(minimum_connection_loan()?)?,
        maximum_children(leg_metadata_bytes()?)?,
    ])?;
    metadata_sum(&[scope_fixed_metadata_bytes()?, cancellation_children_bytes(children)?])
}
// Pinned tokio-util 0.7.20 TaskTrackerInner is AtomicUsize + Notify;
// include its Arc control block and maximum field alignment padding. This
// second tracker has no task-spawn or cancellation-tree allocation of its own.
fn physical_tracker_bytes() -> Result<usize> {
    metadata_sum(&[
        std::mem::size_of::<std::sync::atomic::AtomicUsize>(),
        std::mem::size_of::<tokio::sync::Notify>(),
        2 * std::mem::size_of::<usize>(),
        std::mem::align_of::<tokio::sync::Notify>(),
    ])
}
fn master_metadata_bytes() -> Result<usize> {
    // cancel() can temporarily adopt grandchildren. Charge the master for
    // all live call nodes plus scopes, independently of every scope's own Vec.
    let nodes = metadata_sum(&[
        maximum_children(minimum_connection_loan()?)?,
        maximum_children(leg_metadata_bytes()?)?,
    ])?;
    metadata_sum(&[
        std::mem::size_of::<Master>(),
        std::mem::size_of::<Resources>(),
        std::mem::size_of::<ScopeFactory>(),
        MASTER_PRIMITIVES,
        cancellation_children_bytes(nodes)?,
    ])
}
struct Loan {
    total: Option<OwnedSemaphorePermit>,
    local: OwnedSemaphorePermit,
}
struct Master {
    closed: Mutex<bool>,
    stop: CancellationToken,
    tasks: TaskTracker,
    executor: ClientTlsExecutor,
    sign: SignSlot,
    total: Option<Arc<Semaphore>>,
    local: Arc<Semaphore>,
    _metadata: Loan,
}
/// This external owner is never retained by an IO object. Drop can therefore
/// cancel independently of IO->scope->runtime references and break idle cycles.
pub(crate) struct Resources {
    inner: Arc<Master>,
}
impl Resources {
    pub(crate) fn new(total: Arc<Semaphore>) -> Result<Self> {
        // Preserve certificate total-pool preadmission before constructing its
        // local semaphore/Arc. Observability passes its existing Process pool.
        let bytes = master_metadata_bytes()?;
        let total_credit = total.clone().try_acquire_many_owned(u32::try_from(bytes)?)
            .map_err(|_| crate::cert_transient::ResourceDenied)?;
        Self::new_pool(Some(total), Arc::new(Semaphore::new(WRAPPER_BYTES)), Some(total_credit), bytes)
    }
    /// Observability owns an independent pool; it never borrows certificate or
    /// metric-label credits for a connection's lifetime.
    pub(crate) fn independent(local: Arc<Semaphore>) -> Result<Self> {
        let bytes = master_metadata_bytes()?;
        Self::new_pool(None, local, None, bytes)
    }
    fn new_pool(total: Option<Arc<Semaphore>>, local: Arc<Semaphore>, total_credit: Option<OwnedSemaphorePermit>, bytes: usize) -> Result<Self> {
        let local_credit = local
            .clone()
            .try_acquire_many_owned(u32::try_from(bytes)?)
            .map_err(|_| crate::cert_transient::ResourceDenied)?;
        Ok(Self {
            inner: Arc::new(Master {
                closed: Mutex::new(false),
                stop: CancellationToken::new(),
                tasks: TaskTracker::new(),
                executor: ClientTlsExecutor::new(),
                sign: SignSlot::default(),
                total,
                local,
                _metadata: Loan {
                    total: total_credit,
                    local: local_credit,
                },
            }),
        })
    }
    pub(crate) fn scope(&self) -> Result<ScopeOwner> {
        self.inner.scope()
    }
    /// Runtime construction is confined to the existing configuration CPU lane.
    /// The returned factory is not an external resource owner.
    pub(crate) fn factory(&self) -> Result<ScopeFactory> {
        Ok(ScopeFactory {
            inner: self.inner.clone(),
            executor: self.inner.executor.prepare()?,
        })
    }
    pub(crate) fn close(&self) {
        self.inner.close(true);
    }
    pub(crate) async fn shutdown(&self) -> Result<()> {
        self.inner.close(false);
        self.inner.tasks.wait().await;
        self.inner.executor.shutdown().await
    }
}
impl Drop for Resources {
    fn drop(&mut self) {
        self.inner.close(true);
    }
}
impl Master {
    fn scope(self: &Arc<Self>) -> Result<ScopeOwner> {
        let loan = self.loan(scope_metadata_bytes()?)?;
        let scope = Scope {
            master: self.clone(),
            parent: None,
            closed: Mutex::new(false),
            stop: self.stop.child_token(),
            tasks: TaskTracker::new(),
            physical: TaskTracker::new(),
            _metadata: loan,
        };
        if self.stop.is_cancelled() {
            return Err(io::Error::other("outgoing TLS resources stopped").into());
        }
        Ok(ScopeOwner { inner: Arc::new(scope), cancel_on_drop: None })
    }

    fn loan(&self, bytes: usize) -> Result<Loan> {
        let bytes = u32::try_from(bytes)?;
        let total = self.total.as_ref().map(|total| {
            total.clone().try_acquire_many_owned(bytes)
                .map_err(|_| crate::cert_transient::ResourceDenied)
        }).transpose()?;
        let local = self
            .local
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| crate::cert_transient::ResourceDenied)?;
        Ok(Loan { total, local })
    }
    fn close(&self, force: bool) {
        {
            *self.closed.lock().unwrap_or_else(|e| e.into_inner()) = true;
        }
        self.sign_notify(true);
        self.stop.cancel();
        self.tasks.close();
        if force {
            self.executor.close();
        }
    }
}
/// Shared runtime and pool handle without external abandonment authority.
#[derive(Clone)]
pub(crate) struct ScopeFactory {
    inner: Arc<Master>,
    executor: Arc<TlsExecutor>,
}
impl ScopeFactory {
    pub(crate) fn scope(&self) -> Result<ScopeOwner> { self.inner.scope() }
    pub(crate) fn executor(&self) -> Arc<TlsExecutor> { self.executor.clone() }
}
pub(crate) struct ScopeOwner {
    inner: Arc<Scope>,
    cancel_on_drop: Option<CancellationToken>,
}
impl ScopeOwner {
    pub(crate) fn with_owner_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel_on_drop = Some(cancel);
        self
    }
    pub(crate) fn scope(&self) -> Arc<Scope> {
        self.inner.clone()
    }
    pub(crate) fn close(&self) {
        self.inner.close();
    }
    pub(crate) async fn wait(&self) {
        self.inner.tasks.wait().await;
    }
}
impl Drop for ScopeOwner {
    fn drop(&mut self) {
        self.inner.close();
        if let Some(cancel) = &self.cancel_on_drop {
            cancel.cancel();
        }
    }
}
pub(crate) struct Scope {
    master: Arc<Master>,
    // Keep the generation's child-vector high-water loan until every actual
    // descendant scope, retained error and connection has retired.
    parent: Option<Arc<Scope>>,
    closed: Mutex<bool>,
    stop: CancellationToken,
    tasks: TaskTracker,
    physical: TaskTracker,
    _metadata: Loan,
}
impl Scope {
    /// Closed generation -> issuer-leg edge, never an arbitrary recursive tree.
    /// Closing this external handle affects its leg only. Closing the accepted
    /// generation still cancels every leg, including an in-flight DNS worker.
    pub(crate) fn issuer_leg(self:&Arc<Self>) -> Result<ScopeOwner> {
        if self.parent.is_some() { return Err(io::Error::other("issuer leg cannot create another scope").into()); }
        let loan=self.master.loan(leg_metadata_bytes()?)?;
        let scope={
            let master=self.master.closed.lock().map_err(|_|io::Error::other("outgoing TLS admission failed"))?;
            let generation=self.closed.lock().map_err(|_|io::Error::other("outgoing TLS admission failed"))?;
            if *master || *generation || self.stop.is_cancelled() {return Err(ConnectionControl::Stopped.into());}
            Scope {
                master:self.master.clone(), parent:Some(self.clone()),
                closed:Mutex::new(false), stop:self.stop.child_token(),
                tasks:TaskTracker::new(), physical:TaskTracker::new(), _metadata:loan,
            }
        };
        // Any concurrent parent close is represented by this real child token.
        // Never destroy a scope/cancellation node under either admission lock.
        if scope.stop.is_cancelled() {return Err(ConnectionControl::Stopped.into());}
        Ok(ScopeOwner{inner:Arc::new(scope),cancel_on_drop:None})
    }
    pub(crate) fn close(&self) {
        {
            *self.closed.lock().unwrap_or_else(|e| e.into_inner()) = true;
        }
        self.stop.cancel();
        self.master.sign_notify(false);
        self.tasks.close();
        self.physical.close();
    }
    /// Tested native Unix connector/DNS/result/IO work only. The scope must
    /// first be closed; metadata-only retained errors intentionally do not
    /// keep this fence alive. Existing wait() remains the full owner fence.
    #[cfg(unix)]
    pub(crate) async fn wait_physical(&self) {
        self.physical.wait().await;
    }
    pub(crate) async fn wait(&self) {
        self.tasks.wait().await;
    }
    pub(crate) fn layer(self: &Arc<Self>) -> Result<ConnectLayer> {
        // Invoked by configuration CPU preparation, not by the request reactor.
        let executor = self.master.executor.prepare()?;
        Ok(ConnectLayer {
            scope: self.clone(),
            executor,
            issuer_owner:Default::default(),
        })
    }
    pub(crate) fn connection(self: &Arc<Self>, bytes: usize) -> Result<ConnectionLease> {
        self.connection_with_issuer_owner(bytes, Default::default())
    }
    pub(crate) fn client_bytes(&self, bytes: usize) -> Result<ConnectionBytes> {
        Ok(ConnectionBytes { loan: self.master.loan(bytes)?, master: self.master.clone() })
    }
    pub(crate) fn connection_with_issuer_owner(self: &Arc<Self>, bytes: usize, owner: crate::acme_wire::ClientOwner) -> Result<ConnectionLease> {
        // Every scope child pays this checked minimum, including callers that
        // have not entered the executor queue. Parent Vec bounds rely on it.
        self.admit(metadata_sum(&[bytes, minimum_connection_payload()?])?,owner)
    }
    fn admit(self: &Arc<Self>, bytes: usize,issuer_owner:crate::acme_wire::ClientOwner) -> Result<ConnectionLease> {
        // Both connector and DNS callers use this same preallocation fence.
        let loan = self.master.loan(metadata_sum(&[bytes, physical_work_bytes()?])?)?;
        let (global, local, physical, parent, parent_physical) = {
            let master = self
                .master
                .closed
                .lock()
                .map_err(|_| io::Error::other("outgoing TLS admission failed"))?;
            // Parent close and descendant admission share this fence: merely
            // testing its cancellation token could race a closed+empty wait.
            let parent=self.parent.as_ref().map(|parent|parent.closed.lock()
                .map_err(|_|io::Error::other("outgoing TLS admission failed"))).transpose()?;
            let child = self
                .closed
                .lock()
                .map_err(|_| io::Error::other("outgoing TLS admission failed"))?;
            if *master || *child || parent.as_deref().is_some_and(|closed|*closed) || self.stop.is_cancelled() {
                return Err(ConnectionControl::Stopped.into());
            }
            (self.master.tasks.token(), self.tasks.token(), self.physical.token(),
                self.parent.as_ref().map(|parent|parent.tasks.token()),
                self.parent.as_ref().map(|parent|parent.physical.token()))
        };
        let life = Arc::new(Life {
            scope: self.clone(),
            input: loan,
            extra: Mutex::new(None),
            _issuer_owner:issuer_owner,
            _global: global,
            _local: local,
            _parent: parent,
        });
        let work = Arc::new(PhysicalWork { _life: life.clone(), _token: physical, _parent:parent_physical });
        Ok(ConnectionLease { life, work })
    }
}
struct Life {
    // Resource/runtime remains alive independently of external owner handles.
    scope: Arc<Scope>,
    input: Loan,
    extra: Mutex<Option<Loan>>,
    _issuer_owner:crate::acme_wire::ClientOwner,
    _global: TaskTrackerToken,
    _local: TaskTrackerToken,
    _parent: Option<TaskTrackerToken>,
}
impl Life {
    fn grow(&self, bytes: usize) -> Result<()> {
        let added = self.scope.master.loan(bytes)?;
        let mut slot = self
            .extra
            .lock()
            .map_err(|_| io::Error::other("outgoing TLS metadata state failed"))?;
        if slot.is_some() {
            drop(slot);
            drop(added);
            return Err(io::Error::other("outgoing TLS metadata already admitted").into());
        }
        *slot = Some(added);
        Ok(())
    }
    fn error(self: &Arc<Self>, error: Error) -> Error {
        Box::new(RetainedError {
            inner: error,
            _life: self.clone(),
        })
    }
}
/// Concrete, finite connection credit and task residency. No Process or arbitrary
/// callback is retained. Clones share the same actual allocation/credit owner.
// Metadata is kept separately: errors own Life but never PhysicalWork.
// Each real worker/result/IO keeps this complete lease until actual destruction.
struct PhysicalWork {
    _life: Arc<Life>,
    _token: TaskTrackerToken,
    _parent: Option<TaskTrackerToken>,
}
#[derive(Clone)]
pub(crate) struct ConnectionLease {
    life: Arc<Life>,
    work: Arc<PhysicalWork>,
}
/// A completed operation's error data may retain its original metadata loan.
/// It cannot be used to start work, poll IO or fabricate a physical receipt.
pub(crate) struct ConnectionMetadata(Arc<Life>);
impl ConnectionLease {
    pub(crate) fn grow(&self, bytes: usize) -> Result<()> { self.life.grow(bytes) }
    pub(crate) fn cancellation(&self) -> CancellationToken { self.life.scope.stop.clone() }
    pub(crate) fn error(&self, error: Error) -> Error { self.life.error(error) }
    pub(crate) fn lifetime(&self) -> Lifetime { Lifetime::new(self.clone()) }
    pub(crate) fn bytes(&self, bytes: usize) -> Result<ConnectionBytes> {
        Ok(ConnectionBytes { loan: self.life.scope.master.loan(bytes)?, master: self.life.scope.master.clone() })
    }
    // Closed DNS completion path only; call after the real blocking Job joins.
    pub(crate) fn into_metadata(self) -> ConnectionMetadata {
        let Self { life, work } = self;
        drop(work);
        ConnectionMetadata(life)
    }
}
/// Mutable owned-buffer credit: only an exclusively owned worker grows it.
/// It shares the existing scope pool and never introduces another quota.
pub(crate) struct ConnectionBytes { loan: Loan, master: Arc<Master> }
impl ConnectionBytes {
    pub(crate) fn grow(&mut self, bytes: usize) -> Result<()> {
        let added = self.master.loan(bytes)?;
        self.loan.local.merge(added.local);
        if let Some(extra) = added.total {
            self.loan.total.as_mut().expect("same connection pool").merge(extra);
        }
        Ok(())
    }
}
struct RetainedError {
    inner: Error,
    _life: Arc<Life>,
}
impl std::fmt::Debug for RetainedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}
impl std::fmt::Display for RetainedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}
impl std::error::Error for RetainedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}
pub(crate) struct Lifetime {
    stopped: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    _lease: ConnectionLease,
}
impl Lifetime {
    fn new(lease: ConnectionLease) -> Self {
        Self {
            stopped: Box::pin(lease.life.scope.stop.clone().cancelled_owned()),
            _lease: lease,
        }
    }
    pub(crate) fn poll_stopped(&mut self, cx: &mut Context<'_>) -> bool {
        self.stopped.as_mut().poll(cx).is_ready()
    }
}

#[derive(Clone)]
pub(crate) struct ConnectLayer {
    scope: Arc<Scope>,
    executor: Arc<TlsExecutor>,
    issuer_owner:crate::acme_wire::ClientOwner,
}
impl ConnectLayer {
    pub(crate) fn with_issuer_owner(mut self,owner:crate::acme_wire::ClientOwner)->Self {self.issuer_owner=owner;self}
}
impl<S> Layer<S> for ConnectLayer {
    type Service = ConnectService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ConnectService {
            inner,
            scope: self.scope.clone(),
            executor: self.executor.clone(),
            issuer_owner:self.issuer_owner.clone(),
        }
    }
}
#[derive(Clone)]
pub(crate) struct ConnectService<S> {
    inner: S,
    scope: Arc<Scope>,
    executor: Arc<TlsExecutor>,
    issuer_owner:crate::acme_wire::ClientOwner,
}
struct Call<S, R> {
    service: Option<S>,
    request: Option<R>,
    life: ConnectionLease,
}
impl<S, R> Drop for Call<S, R> {
    fn drop(&mut self) {}
}
impl<S, R> Call<S, R>
where
    S: Service<R, Response = Connection, Error = Error>,
{
    async fn run(mut self) -> Result<Connection, Error> {
        if self.life.life.scope.stop.is_cancelled() {
            return Err(self.life.error(Box::new(ConnectionControl::Stopped)));
        }
        // Readiness belongs to this exact owned clone. Both poll_ready and
        // call run on the dedicated worker, including stateful outer layers.
        let service = self.service.as_mut().expect("owned service");
        let result = match std::future::poll_fn(|cx| service.poll_ready(cx)).await {
            Ok(()) => {
                service
                    .call(self.request.take().expect("owned request"))
                    .await
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(connection) => {
                let life = self.life.clone();
                Ok(connection.map_io(move |inner| {
                    Box::new(ScopedIo {
                        inner,
                        life: Lifetime::new(life),
                    })
                }))
            }
            Err(error) => Err(self.life.error(error)),
        }
    }
}
type LayerFuture = futures_util::future::Either<
    std::future::Ready<Result<Connection, Error>>,
    Pin<Box<dyn Future<Output = Result<Connection, Error>> + Send>>,
>;
impl<S, R> Service<R> for ConnectService<S>
where
    S: Service<R, Response = Connection, Error = Error> + Clone + Send + 'static,
    S::Future: Send + 'static,
    R: AsRef<http::Uri> + Send + 'static,
{
    type Response = Connection;
    type Error = Error;
    type Future = LayerFuture;
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        // Existing bounded executor/byte admission is attempted by call. Never
        // poll an underlying service (or its TLS construction) on the reactor.
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: R) -> Self::Future {
        let uri = request.as_ref();
        let input = metadata_sum(&[
            std::mem::size_of::<Call<S, R>>(),
            std::mem::size_of::<Life>(),
            std::mem::size_of::<ScopedIo>(),
            std::mem::size_of::<tokio_util::sync::WaitForCancellationFutureOwned>(),
            reqwest::tls::scoped_connector_clone_bound(),
            uri.scheme_str().map_or(0, str::len),
            uri.authority().map_or(0, |s| s.as_str().len()),
            uri.path_and_query().map_or(0, |s| s.as_str().len()),
            3,
            128,
        ]);
        let life = match input.and_then(|bytes| self.scope.admit(bytes,self.issuer_owner.clone())) {
            Ok(life) => life,
            Err(error) => {
                return futures_util::future::Either::Left(std::future::ready(Err(Box::new(
                    ConnectionControl::Admission(
                        error.reallocate_into_boxed_dyn_error_without_backtrace(),
                    ),
                ))));
            }
        };
        let future = Call {
            service: Some(self.inner.clone()),
            request: Some(request),
            life: life.clone(),
        }
        .run();
        let worker_size = std::mem::size_of_val(&future);
        let executor = self.executor.clone();
        let stop = self.scope.stop.clone();
        let retained = life.life.clone();
        let retirement = life.clone();
        let outcome = async move {
            // Preserve inner network/readiness errors as values. Only the
            // outer Err can originate in our local executor admission/control.
            match executor
                .execute_connector(async move { Ok(future.await) }, stop, retirement)
                .await
            {
                Ok(result) => result,
                Err(error) => Err(retained.error(Box::new(ConnectionControl::Scheduling(
                    error.reallocate_into_boxed_dyn_error_without_backtrace(),
                )))),
            }
        };
        let bytes = metadata_sum(&[
            worker_size,
            std::mem::size_of_val(&outcome),
            std::mem::size_of::<Result<Result<Connection, Error>, anyhow::Error>>(),
            std::mem::size_of::<LayerFuture>(),
            EXECUTOR_HANDOFF,
        ]);
        if let Err(error) = bytes.and_then(|bytes| life.grow(bytes)) {
            drop(outcome);
            return futures_util::future::Either::Left(std::future::ready(Err(life.error(
                Box::new(ConnectionControl::Admission(
                    error.reallocate_into_boxed_dyn_error_without_backtrace(),
                )),
            ))));
        }
        futures_util::future::Either::Right(Box::pin(outcome))
    }
}

// The standard IO delegation below is intentionally local and concrete. It
// retains actual scope/runtime ownership, never an arbitrary Any/Drop payload.
struct ScopedIo {
    inner: Box<dyn reqwest::tls::ConnectionIo>,
    life: Lifetime,
}
impl ScopedIo {
    fn live(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.life.poll_stopped(cx) {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                ConnectionControl::Stopped,
            ))
        } else {
            Ok(())
        }
    }
}
impl hyper_util::client::legacy::connect::Connection for ScopedIo {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        self.inner.connected()
    }
}
impl reqwest::tls::ConnectionTlsInfo for ScopedIo {
    fn tls_info(&self) -> Option<reqwest::tls::TlsInfo> {
        self.inner.tls_info()
    }
}
impl hyper::rt::Read for ScopedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.live(cx)?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl hyper::rt::Write for ScopedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.live(cx)?;
        Pin::new(&mut this.inner).poll_write(cx, data)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.live(cx)?;
        Pin::new(&mut this.inner).poll_write_vectored(cx, data)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.live(cx)?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.live(cx)?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// Fixed native JWS CPU driver. This capability has no connection/IO methods.
#[derive(Default)]
struct SignSlot {
    state: std::sync::Mutex<SignSlotState>,
    changed: std::sync::Condvar,
}
#[derive(Default)]
struct SignSlotState {
    preparing: bool,
    driver: Option<Arc<crate::cert_cpu::sign::Shared>>,
}
pub(crate) struct CpuMetadata {
    _loan: Loan,
}
pub(crate) struct CpuLease {
    scope: Arc<Scope>,
    tokens: Option<CpuTokens>,
    metadata: Arc<CpuMetadata>,
}
struct CpuTokens {
    _global: TaskTrackerToken,
    _local: TaskTrackerToken,
    _physical: TaskTrackerToken,
    _parent: Option<TaskTrackerToken>,
    _parent_physical: Option<TaskTrackerToken>,
}
impl CpuLease {
    pub(crate) fn stopped(&self) -> bool {
        self.scope.stop.is_cancelled()
    }
    pub(crate) fn matches(&self, scope: &Arc<Scope>) -> bool {
        Arc::ptr_eq(&self.scope, scope)
    }
    pub(crate) fn metadata(&self) -> Arc<CpuMetadata> {
        self.metadata.clone()
    }
    // Only the closed resident controller calls this after actual data/permit /
    // blocking join disposition. Metadata cannot recreate a work capability.
    pub(crate) fn finish(mut self) {
        drop(self.tokens.take());
    }
}
impl Master {
    fn sign_notify(&self, close: bool) {
        let driver = self
            .sign
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .driver
            .clone();
        if let Some(driver) = driver {
            if close {
                driver.close();
            } else {
                driver.notify();
            }
        }
    }
    fn prepare_sign(self: &Arc<Self>, slots: Arc<Semaphore>) -> Result<()> {
        {
            let mut state = self
                .sign
                .state
                .lock()
                .map_err(|_| io::Error::other("certificate CPU state failed"))?;
            while state.preparing {
                state = self
                    .sign
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("certificate CPU state failed"))?;
            }
            if let Some(driver) = &state.driver {
                return driver.check_slots(&slots);
            }
            if self.stop.is_cancelled() {
                return Err(ConnectionControl::Stopped.into());
            }
            state.preparing = true;
        }
        struct Preparing<'a>(&'a SignSlot);
        impl Drop for Preparing<'_> {
            fn drop(&mut self) {
                {
                    lock_sign(&self.0.state).preparing = false;
                }
                self.0.changed.notify_all();
            }
        }
        let preparing = Preparing(&self.sign);
        // Runtime construction / startup ack, credit return and drop are never
        // executed under the Master/SignSlot admission fences.
        let result = (|| {
            let bytes = crate::cert_cpu::sign::control_layout()?;
            let metadata = Arc::new(CpuMetadata {
                _loan: self.loan(bytes)?,
            });
            let driver = crate::cert_cpu::sign::Shared::new(slots, metadata);
            let executor = self.executor.prepare()?;
            executor.register_sign_driver(driver.clone())?;
            Ok::<_, anyhow::Error>(driver)
        })();
        let closing =
            *self.closed.lock().unwrap_or_else(|e| e.into_inner()) || self.stop.is_cancelled();
        {
            let mut state = self.sign.state.lock().unwrap_or_else(|e| e.into_inner());
            state.preparing = false;
            if let Ok(driver) = &result {
                state.driver = Some(driver.clone());
            }
        }
        drop(preparing);
        if closing {
            if let Ok(driver) = &result {
                driver.close();
            }
        }
        result?;
        if closing {
            return Err(ConnectionControl::Stopped.into());
        }
        Ok(())
    }
}
impl Scope {
    pub(crate) fn prepare_sign_driver(self: &Arc<Self>, slots: Arc<Semaphore>) -> Result<()> {
        if self.stop.is_cancelled() {
            return Err(ConnectionControl::Stopped.into());
        }
        self.master.prepare_sign(slots)?;
        if self.stop.is_cancelled() {
            return Err(ConnectionControl::Stopped.into());
        }
        Ok(())
    }
    pub(crate) fn sign_ticket(
        self: &Arc<Self>,
        slots: &Arc<Semaphore>,
    ) -> Result<crate::cert_cpu::sign::Ticket> {
        let driver = self
            .master
            .sign
            .state
            .lock()
            .map_err(|_| io::Error::other("certificate CPU state failed"))?
            .driver
            .clone()
            .ok_or_else(|| io::Error::other("certificate CPU driver not prepared"))?;
        driver.check_slots(slots)?;
        let bytes = crate::cert_cpu::sign::cell_layout()?;
        let loan = self.master.loan(bytes)?;
        let tokens = {
            let master = self
                .master
                .closed
                .lock()
                .map_err(|_| io::Error::other("certificate CPU admission failed"))?;
            let parent = self
                .parent
                .as_ref()
                .map(|p| {
                    p.closed
                        .lock()
                        .map_err(|_| io::Error::other("certificate CPU admission failed"))
                })
                .transpose()?;
            let local = self
                .closed
                .lock()
                .map_err(|_| io::Error::other("certificate CPU admission failed"))?;
            if *master
                || *local
                || parent.as_deref().is_some_and(|v| *v)
                || self.stop.is_cancelled()
            {
                return Err(ConnectionControl::Stopped.into());
            }
            CpuTokens {
                _global: self.master.tasks.token(),
                _local: self.tasks.token(),
                _physical: self.physical.token(),
                _parent: self.parent.as_ref().map(|p| p.tasks.token()),
                _parent_physical: self.parent.as_ref().map(|p| p.physical.token()),
            }
        };
        let lease = CpuLease {
            scope: self.clone(),
            tokens: Some(tokens),
            metadata: Arc::new(CpuMetadata { _loan: loan }),
        };
        driver.register(lease)
    }
}

fn lock_sign<T>(value: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}
