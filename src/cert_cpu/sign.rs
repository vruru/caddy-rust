//! Closed native JWS residence; only small handles cross asynchronous edges.
use crate::{
    acme_wire::{AccountSigner, chain_memory},
    outgoing_tls::{ConnectionControl, CpuLease, CpuMetadata, Scope},
};
use anyhow::{Result, anyhow, ensure};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

type Panic = Box<dyn std::any::Any + Send + 'static>; // standard unwind only, not registration API
pub(crate) struct Shared {
    head: Mutex<Option<Arc<Cell>>>,
    slots: Arc<Semaphore>,
    wake: Arc<Signal>,
    closed: AtomicBool,
    panic: Mutex<[Option<Panic>; 2]>,
    cleanup: Mutex<CleanupState>,
    recovering: AtomicBool,
    _metadata: Arc<CpuMetadata>,
}
#[derive(Default)]
struct CleanupState {
    active: bool,
    join: Option<tokio::task::JoinHandle<()>>,
}
struct CleanupJoinPoll {
    shared: Arc<Shared>,
    handle: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for CleanupJoinPoll {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            lock(&self.shared.cleanup).join = Some(handle);
        }
    }
}
struct Signal {notify:Notify,_metadata:Arc<CpuMetadata>}
impl std::task::Wake for Signal {fn wake(self:Arc<Self>){self.notify.notify_one();}fn wake_by_ref(self:&Arc<Self>){self.notify.notify_one();}}
struct WeakDriver {inner:Weak<Shared>,_metadata:Arc<CpuMetadata>}
impl WeakDriver {fn upgrade(&self)->Option<Arc<Shared>>{self.inner.upgrade()}}
struct JoinPoll {cell:Arc<Cell>,handle:Option<tokio::task::JoinHandle<()>>}
impl Drop for JoinPoll {fn drop(&mut self){if let Some(handle)=self.handle.take(){lock(&self.cell.state).join=Some(handle);}}}
struct Cell {
    state: Mutex<State>,
    shared: WeakDriver,
    wake: Notify,
    metadata: Arc<CpuMetadata>,
}
struct State {
    data: Data,
    work: Option<CpuLease>,
    next: Option<Arc<Cell>>,
    submitting: bool,
    abandoned: bool,
    active: bool,
    joined: bool,
    readers: usize,
    join: Option<tokio::task::JoinHandle<()>>,
}
#[derive(Default)]
struct Data {
    input: Option<Input>,
    output: Option<Output>,
}
struct Input {
    nonce: String,
    url: String,
    kid: Option<String>,
    payload: Option<serde_json::Value>,
    signer: Arc<AccountSigner>,
    loan: Option<chain_memory::Scratch>,
}
enum Output {
    Body(BodyData),
    Error(Arc<ErrorData>),
    Failed,
}
struct BodyData {
    bytes: Vec<u8>,
    loan: chain_memory::Scratch,
}
struct ErrorData {
    error: anyhow::Error,
}
struct OwnedJwsBody {
    data: BodyData,
    _metadata: Arc<CpuMetadata>,
}
impl AsRef<[u8]> for OwnedJwsBody {
    fn as_ref(&self) -> &[u8] {
        &self.data.bytes
    }
}
pub(crate) struct Ticket {
    cell: Arc<Cell>,
    submitted: bool,
}
pub(crate) struct ReadyBody {
    cell: Arc<Cell>,
    handed: bool,
}
struct ErrorView {
    error: Option<Arc<ErrorData>>,
    cell: Arc<Cell>,
}
impl std::fmt::Debug for ErrorView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.as_ref().expect("live sign error").error.fmt(f)
    }
}
impl std::fmt::Display for ErrorView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.as_ref().expect("live sign error").error.fmt(f)
    }
}
impl std::error::Error for ErrorView {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref().expect("live sign error").error.as_ref())
    }
}
impl Drop for ErrorView {
    fn drop(&mut self) {
        drop(self.error.take());
        {
            let mut s = lock(&self.cell.state);
            s.readers = 0;
            s.abandoned = true;
        }
        self.cell.notify();
    }
}
fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}
fn resource() -> anyhow::Error {
    crate::cert_transient::ResourceDenied.into()
}
pub(crate) fn control_layout() -> Result<usize> {
    std::mem::size_of::<Shared>()
        .checked_add(16384)
        .ok_or_else(resource)
}
pub(crate) fn cell_layout() -> Result<usize> {
    std::mem::size_of::<Cell>()
        .checked_add(std::mem::size_of::<State>())
        .and_then(|n| n.checked_add(std::mem::size_of::<OwnedJwsBody>()))
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(resource)
}
impl Cell {
    fn notify(&self) {
        self.wake.notify_waiters();
        if let Some(shared) = self.shared.upgrade() {
            shared.notify();
        }
    }
}
impl Shared {
    pub(crate) fn new(slots: Arc<Semaphore>, metadata: Arc<CpuMetadata>) -> Arc<Self> {
        Arc::new(Self {
            head: Mutex::new(None),
            slots,
            wake: Arc::new(Signal{notify:Notify::new(),_metadata:metadata.clone()}),
            closed: AtomicBool::new(false),
            panic: Mutex::new([None, None]),
            cleanup: Mutex::new(CleanupState::default()),
            recovering: AtomicBool::new(false),
            _metadata: metadata,
        })
    }
    pub(crate) fn check_slots(&self, slots: &Arc<Semaphore>) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.slots, slots),
            "certificate CPU driver pool identity mismatch"
        );
        Ok(())
    }
    pub(crate) fn notify(&self) {
        self.wake.notify.notify_one();
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify();
    }
    pub(crate) fn register(self: &Arc<Self>, work: CpuLease) -> Result<Ticket> {
        let metadata = work.metadata();
        let cell = Arc::new(Cell {
            state: Mutex::new(State {
                data: Data::default(),
                work: Some(work),
                next: None,
                submitting: true,
                abandoned: false,
                active: false,
                joined: false,
                readers: 0,
                join: None,
            }),
            shared: WeakDriver{inner:Arc::downgrade(self),_metadata:self._metadata.clone()},
            wake: Notify::new(),
            metadata,
        });
        let accepted = {
            let mut head = lock(&self.head);
            if self.closed.load(Ordering::Acquire) {
                false
            } else {
                lock(&cell.state).next = head.take();
                *head = Some(cell.clone());
                true
            }
        };
        if !accepted {
            return Err(ConnectionControl::Stopped.into());
        }
        self.notify();
        Ok(Ticket {
            cell,
            submitted: false,
        })
    }
    fn first(&self) -> Option<Arc<Cell>> {
        lock(&self.head).clone()
    }
    fn unlink(&self, target: &Arc<Cell>) {
        let mut removed = None;
        {
            let mut head = lock(&self.head);
            if head.as_ref().is_some_and(|v| Arc::ptr_eq(v, target)) {
                removed = head.take();
                *head = lock(&target.state).next.take();
            } else {
                let mut p = head.clone();
                while let Some(cell) = p {
                    let mut s = lock(&cell.state);
                    if s.next.as_ref().is_some_and(|v| Arc::ptr_eq(v, target)) {
                        removed = s.next.take();
                        s.next = lock(&target.state).next.take();
                        break;
                    }
                    p = s.next.clone();
                }
            }
        }
        drop(removed);
    }
    fn abandon(&self) {
        let mut p = self.first();
        while let Some(cell) = p {
            let mut s = lock(&cell.state);
            p = s.next.clone();
            if self.closed.load(Ordering::Acquire) || s.work.as_ref().is_some_and(CpuLease::stopped)
            {
                s.abandoned = true;
            }
            drop(s);
            cell.wake.notify_waiters();
        }
    }
    fn candidate(&self) -> Option<Arc<Cell>> {
        let mut p = self.first();
        let mut oldest = None;
        while let Some(cell) = p {
            let take = {
                let s = lock(&cell.state);
                p = s.next.clone();
                !s.submitting
                    && !s.active
                    && s.join.is_none()
                    && ((s.abandoned && s.readers == 0) || s.data.input.is_some())
            };
            if take {
                oldest = Some(cell);
            }
        }
        oldest
    }
    fn join_and_remove(self: &Arc<Self>) {
        // A completed Tokio task may contain an opaque panic. Admit no second
        // such result while the first is resident or its cleanup is in flight.
        if self.cleanup_pending() || self.cleanup_busy() { return; }
        let mut p = self.first();
        while let Some(cell) = p {
            let join = {let mut state=lock(&cell.state);p=state.next.clone();state.join.take()};
            if let Some(join)=join {
                let mut guarded=JoinPoll{cell:cell.clone(),handle:Some(join)};
                let result={let waker=std::task::Waker::from(self.wake.clone());
                    let mut cx=std::task::Context::from_waker(&waker);
                    Pin::new(guarded.handle.as_mut().expect("live closed worker join")).poll(&mut cx)};
                if let std::task::Poll::Ready(result)=result {
                    drop(guarded.handle.take());
                    if let Err(error)=result {
                        if error.is_panic(){self.put_panic(error.into_panic());}
                        lock(&cell.state).abandoned=true;
                    }
                    lock(&cell.state).joined=true;
                    cell.notify();
                }
                drop(guarded);
            }
            let work = {
                let mut s = lock(&cell.state);
                if !s.submitting
                    && !s.active
                    && s.join.is_none()
                    && s.data.input.is_none()
                    && s.data.output.is_none()
                {
                    s.work.take()
                } else {
                    None
                }
            };
            if let Some(work) = work {
                work.finish();
                self.unlink(&cell);
                cell.notify();
            }
            if self.cleanup_pending() { break; }
        }
    }
    fn put_panic(&self, payload: Panic) {
        // At most one failed Sign submission and one failed cleanup submission
        // can be outstanding. No new submission is made while cleanup is active.
        let mut slots = lock(&self.panic);
        let slot = slots.iter_mut().find(|slot| slot.is_none())
            .expect("closed Sign panic intake invariant");
        *slot = Some(payload);
        drop(slots);
        self.recovering.store(true, Ordering::Release);
        self.notify();
    }
    fn unjoined_active(&self) -> bool {
        let mut p = self.first();
        while let Some(cell) = p {
            let state = lock(&cell.state);
            p = state.next.clone();
            if state.active && state.join.is_none() { return true; }
        }
        false
    }
    fn cleanup_pending(&self) -> bool {
        lock(&self.panic).iter().any(Option::is_some)
    }
    fn cleanup_busy(&self) -> bool {
        let cleanup = lock(&self.cleanup);
        cleanup.active || cleanup.join.is_some()
    }
    fn poll_cleanup(self: &Arc<Self>) {
        let join = lock(&self.cleanup).join.take();
        if let Some(join) = join {
            let mut guarded = CleanupJoinPoll { shared: self.clone(), handle: Some(join) };
            let result = {
                let waker = std::task::Waker::from(self.wake.clone());
                let mut cx = std::task::Context::from_waker(&waker);
                Pin::new(guarded.handle.as_mut().expect("live cleanup join")).poll(&mut cx)
            };
            if let std::task::Poll::Ready(result) = result {
                drop(guarded.handle.take());
                if let Err(error) = result {
                    if error.is_panic() { self.put_panic(error.into_panic()); }
                }
            }
            drop(guarded);
        }
    }
    fn start_cleanup(self: &Arc<Self>, permit: OwnedSemaphorePermit) {
        lock(&self.cleanup).active = true;
        let job = CleanupScheduled { shared: self.clone(), permit: Some(permit) };
        // If Tokio panics after enqueue, the actual queued job still owns its
        // permit and active receipt. The no-enqueue recovery path drives it.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tokio::task::spawn_blocking(move || job.run())
        })) {
            Ok(join) => lock(&self.cleanup).join = Some(join),
            Err(payload) => self.put_panic(payload),
        }
    }
    fn start(&self, cell: Arc<Cell>, permit: OwnedSemaphorePermit) {
        {
            let mut s = lock(&cell.state);
            s.active = true;
            s.joined = false;
        }
        let job = Scheduled {
            cell: cell.clone(),
            permit: Some(permit),
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tokio::task::spawn_blocking(move || job.run())
        })) {
            Ok(join) => lock(&cell.state).join = Some(join),
            Err(payload) => {
                // Only this submission failed. Its already queued envelope
                // owns its permit; retire its resident input on the CPU lane.
                // Do not permanently close the process-wide Sign driver.
                lock(&cell.state).abandoned = true;
                cell.notify();
                self.put_panic(payload);
            }
        }
    }
    async fn drive(self: &Arc<Self>, host_stop: &CancellationToken) {
        type Acquire = Pin<
            Box<
                dyn Future<
                        Output = std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError>,
                    > + Send,
            >,
        >;
        let mut acquire: Option<Acquire> = None;
        let mut retry_delay = std::time::Duration::from_millis(10);
        let retry = tokio::time::sleep(retry_delay);
        tokio::pin!(retry);
        loop {
            let wake = self.wake.notify.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            self.abandon();
            self.poll_cleanup();
            self.join_and_remove();
            let busy = self.cleanup_busy();
            let pending = self.cleanup_pending();
            if self.recovering.load(Ordering::Acquire) && !busy && !pending
                && !self.unjoined_active()
            {
                self.recovering.store(false, Ordering::Release);
                retry_delay = std::time::Duration::from_millis(10);
            }
            if self.closed.load(Ordering::Acquire) && self.first().is_none() && !busy && !pending {
                return;
            }
            let wants_permit = !busy && (pending || self.candidate().is_some());
            if wants_permit && acquire.is_none() {
                acquire = Some(Box::pin(self.slots.clone().acquire_owned()));
            } else if !wants_permit {
                drop(acquire.take());
            }
            tokio::select! {biased;
                permit=async {acquire.as_mut().expect("fixed CPU acquisition").await}, if wants_permit => {
                    acquire=None;
                    if let Ok(permit)=permit {
                        if self.cleanup_pending() && !self.cleanup_busy() {
                            self.start_cleanup(permit);
                        } else if let Some(cell)=self.candidate() {
                            self.start(cell,permit);
                        }
                    }
                },
                _=host_stop.cancelled(),if !self.closed.load(Ordering::Acquire)=>self.close(),
                _=&mut retry, if self.recovering.load(Ordering::Acquire) => {
                    // This never enqueues a retry task or allocates another panic
                    // payload on OS failure. Existing jobs retain all ownership.
                    let _ = tokio::runtime::Handle::current().try_wake_blocking_queue();
                    retry_delay=(retry_delay*2).min(std::time::Duration::from_millis(250));
                    retry.as_mut().reset(tokio::time::Instant::now()+retry_delay);
                },
                _=&mut wake=>{},
            }
        }
    }
    pub(crate) async fn host(
        self: Arc<Self>,
        stop: CancellationToken,
        started: std::sync::mpsc::SyncSender<bool>,
    ) {
        use futures_util::FutureExt;
        if stop.is_cancelled() {
            self.close();
            let _ = started.send(false);
        } else {
            let _ = started.send(true);
        }
        loop {
            let result = std::panic::AssertUnwindSafe(self.drive(&stop)).catch_unwind().await;
            match result {
                Ok(()) => break,
                Err(payload) => {
                    // Unexpected driver invariant failures stay fatal; known
                    // blocking submissions are caught at their own seam.
                    self.close();
                    self.put_panic(payload);
                },
            }
        }
    }
}
struct CleanupScheduled {
    shared: Arc<Shared>,
    permit: Option<OwnedSemaphorePermit>,
}
impl CleanupScheduled {
    fn run(self) {
        let payloads = {
            let mut slots = lock(&self.shared.panic);
            [slots[0].take(), slots[1].take()]
        };
        for payload in payloads.into_iter().flatten() {
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)));
            // The caught panic payload is also destroyed before the CPU permit.
            drop(caught);
        }
    }
}
impl Drop for CleanupScheduled {
    fn drop(&mut self) {
        drop(self.permit.take());
        lock(&self.shared.cleanup).active = false;
        self.shared.notify();
    }
}

struct Scheduled {
    cell: Arc<Cell>,
    permit: Option<OwnedSemaphorePermit>,
}
impl Scheduled {
    fn run(mut self) {
        let mut data = {
            let mut s = lock(&self.cell.state);
            std::mem::take(&mut s.data)
        };
        let abandoned = {
            let s = lock(&self.cell.state);
            s.abandoned || s.work.as_ref().is_some_and(CpuLease::stopped)
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if abandoned {
                drop(std::mem::take(&mut data));
            } else if let Some(input) = data.input.take() {
                data.output = Some(match assemble(input) {
                    Ok(body) => Output::Body(body),
                    Err(error) => Output::Error(Arc::new(ErrorData { error })),
                });
            }
        }));
        if let Err(payload) = result {
            drop(data);
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)));
            drop(caught);
            data = Data {
                input: None,
                output: Some(Output::Failed),
            };
        }
        {
            let mut s = lock(&self.cell.state);
            s.data = data;
        }
        drop(self.permit.take());
    }
}
impl Drop for Scheduled {
    fn drop(&mut self) {
        drop(self.permit.take());
        {
            let mut s = lock(&self.cell.state);
            s.active = false;
            if s.data.input.is_some() {
                s.abandoned = true;
            }
        }
        self.cell.notify();
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.submitted {
            {
                let mut s = lock(&self.cell.state);
                s.submitting = false;
                s.abandoned = true;
            }
            self.cell.notify();
        }
    }
}
impl Ticket {
    pub(crate) fn submit_jws(
        mut self,
        signer: Arc<AccountSigner>,
        nonce: &mut Option<String>,
        url: &str,
        kid: Option<&str>,
        payload: Option<&serde_json::Value>,
        cancel: CancellationToken,
    ) -> Result<impl Future<Output = Result<ReadyBody>> + Send + 'static + use<>> {
        let stopped = || {
            let state = lock(&self.cell.state);
            state.work.as_ref().is_none_or(CpuLease::stopped)
        };
        if cancel.is_cancelled() || stopped() { return Err(ConnectionControl::Stopped.into()); }
        let nonce_capacity = nonce.as_ref().ok_or_else(resource)?.capacity();
        let payload_cost = payload.map(crate::cert_json_shape::clone_cost).transpose()?.unwrap_or(0);
        let bytes = [nonce_capacity, url.len(), kid.map_or(0, str::len), payload_cost]
            .into_iter().try_fold(0usize, |n, v| n.checked_add(v).ok_or_else(resource))?;
        let loan = chain_memory::try_scratch(bytes)?;
        // No new input buffer exists until both this loan and the final stop
        // check succeed. Closed String/Value Clone has no user callback or
        // ordinary error; allocator/stack abort is not a recoverable path.
        if cancel.is_cancelled() || stopped() { return Err(ConnectionControl::Stopped.into()); }
        let input = Input {
            nonce: nonce.take().expect("preflighted JWS nonce"),
            url: url.to_owned(),
            kid: kid.map(str::to_owned),
            payload: payload.cloned(),
            signer,
            loan: Some(loan),
        };
        {
            let mut state = lock(&self.cell.state);
            state.data.input = Some(input);
            state.submitting = false;
        }
        self.submitted = true;
        self.cell.notify();
        let cell = self.cell.clone();
        let guard = ReadyBody {
            cell: cell.clone(),
            handed: false,
        };
        Ok(async move {
            let mut guard = guard;
            loop {
                let wake = cell.wake.notified();
                tokio::pin!(wake);
                wake.as_mut().enable();
                let mut error = None;
                let mut failed = false;
                let ready = {
                    let mut s = lock(&cell.state);
                    if s.abandoned || s.work.as_ref().is_some_and(CpuLease::stopped) {
                        failed = true;
                        false
                    } else if s.joined && !s.active {
                        match &s.data.output {
                            Some(Output::Body(_)) => true,
                            Some(Output::Error(e)) => {
                                error = Some(e.clone());
                                s.readers = 1;
                                false
                            }
                            Some(Output::Failed) => {
                                failed = true;
                                false
                            }
                            None => false,
                        }
                    } else {
                        false
                    }
                };
                if let Some(error) = error {
                    guard.handed = true;
                    return Err(anyhow::Error::new(ErrorView {
                        error: Some(error),
                        cell: cell.clone(),
                    }));
                }
                if failed {
                    return Err(ConnectionControl::Stopped.into());
                }
                if ready {
                    return Ok(guard);
                }
                tokio::select! {biased;_=cancel.cancelled()=>return Err(anyhow!("certificate signing cancelled")),_=&mut wake=>{}}
            }
        })
    }
}

impl ReadyBody {
    pub(crate) fn handoff_http(mut self, scope: &Arc<Scope>) -> Result<bytes::Bytes> {
        let (data, metadata) = {
            let mut s = lock(&self.cell.state);
            ensure!(
                s.joined
                    && !s.active
                    && !s.abandoned
                    && s.work
                        .as_ref()
                        .is_some_and(|w| w.matches(scope) && !w.stopped()),
                "JWS CPU handoff owner mismatch"
            );
            ensure!(matches!(s.data.output,Some(Output::Body(_))),"JWS CPU result kind mismatch");
            let Some(Output::Body(body)) = s.data.output.take() else {
                return Err(anyhow!("JWS CPU body unavailable"));
            };
            (body, self.cell.metadata.clone())
        };
        self.handed = true;
        self.cell.notify();
        Ok(bytes::Bytes::from_owner(OwnedJwsBody {
            data,
            _metadata: metadata,
        }))
    }
}
impl Drop for ReadyBody {
    fn drop(&mut self) {
        if !self.handed {
            {
                let mut s = lock(&self.cell.state);
                s.abandoned = true;
            }
            self.cell.notify();
        }
    }
}

// Explicit struct drop order protects all input/temporary allocations before
// their loan, including any ordinary error/unwind inside the closed producer.
struct Assembly {
    input: Option<Input>,
    protected_json: Option<serde_json::Value>,
    protected_bytes: Option<Vec<u8>>,
    payload_bytes: Option<Vec<u8>>,
    protected: Option<String>,
    payload: Option<String>,
    signed: Option<String>,
    signature: Option<Vec<u8>>,
    encoded: Option<String>,
    body: Option<Vec<u8>>,
    json: Option<serde_json::Value>,
    loan: Option<chain_memory::Scratch>,
}
fn checked_sum(values: &[usize]) -> Result<usize> {
    values.iter().try_fold(0usize, |n, v| n.checked_add(*v).ok_or_else(resource))
}
fn b64_bound(bytes: usize) -> Result<usize> {
    bytes.checked_add(2).and_then(|n| n.checked_div(3))
        .and_then(|n| n.checked_mul(4)).ok_or_else(resource)
}
fn json_len(value: &serde_json::Value) -> Result<usize> {
    struct Counter { bytes: usize, overflow: bool }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let Some(next) = self.bytes.checked_add(bytes.len()) else {
                self.overflow = true;
                return Err(std::io::Error::other("JWS JSON length overflow"));
            };
            self.bytes = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let mut count = Counter { bytes: 0, overflow: false };
    let result = serde_json::to_writer(&mut count, value);
    if count.overflow { return Err(resource()); }
    result?;
    Ok(count.bytes)
}
fn encoded_json(value: &serde_json::Value, bytes: &mut Option<Vec<u8>>, text: &mut Option<String>, bound: usize) -> Result<()> {
    use base64::Engine as _;
    *bytes = Some(Vec::new());
    let raw = bytes.as_mut().expect("admitted JSON buffer");
    raw.try_reserve_exact(bound)?;
    ensure!(raw.capacity() == bound, "unexpected JWS JSON capacity");
    serde_json::to_writer(&mut *raw, value)?;
    ensure!(raw.len() <= bound, "JWS JSON exceeded preflight");
    *text = Some(String::new());
    let encoded = text.as_mut().expect("admitted base64 buffer");
    encoded.try_reserve_exact(b64_bound(bound)?)?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(raw, encoded);
    Ok(())
}
fn assemble(mut input: Input) -> Result<BodyData> {
    use base64::Engine as _;
    let loan = input.loan.take().expect("prepaid raw JWS input");
    let input_bytes = loan.bytes();
    let mut a = Assembly {
        input: Some(input), protected_json: None, protected_bytes: None, payload_bytes: None,
        protected: None, payload: None, signed: None, signature: None, encoded: None,
        body: None, json: None, loan: Some(loan),
    };
    let i = a.input.as_ref().expect("closed raw JWS input");
    let max = i.signer.max_signature_len();
    // Public JWK only: <=2 RSA integers of <=max bytes, their base64 and
    // temporary byte vectors; EC/OKP are smaller. Two <=4-member BTree roots,
    // short fixed keys/algorithm/curve text fit within the fixed 8192 suffix.
    // Existing nonce/url/kid storage is moved into the DOM, not cloned.
    let prelude = max.checked_mul(16).and_then(|n| n.checked_add(8192)).ok_or_else(resource)?;
    a.loan.as_mut().expect("input credit").grow_to(checked_sum(&[input_bytes, prelude])?)?;
    let i = a.input.as_mut().expect("closed raw JWS input");
    // json! passes arbitrary expressions through to_value(&expr), so even a
    // mem::take String would be cloned. Insert owned Values directly instead.
    let mut protected = serde_json::Map::new();
    protected.insert("alg".into(), serde_json::Value::String(i.signer.algorithm().into()));
    protected.insert("nonce".into(), serde_json::Value::String(std::mem::take(&mut i.nonce)));
    protected.insert("url".into(), serde_json::Value::String(std::mem::take(&mut i.url)));
    if let Some(kid) = i.kid.take() { protected.insert("kid".into(), serde_json::Value::String(kid)); }
    else { protected.insert("jwk".into(), i.signer.jwk()); }
    a.protected_json = Some(serde_json::Value::Object(protected));
    let protected_bytes = json_len(a.protected_json.as_ref().expect("protected fields"))?;
    let payload_bytes = a.input.as_ref().expect("raw payload").payload.as_ref().map(json_len).transpose()?.unwrap_or(0);
    let protected_encoded = b64_bound(protected_bytes)?;
    let payload_encoded = b64_bound(payload_bytes)?;
    let signature_encoded = b64_bound(max)?;
    let signed = checked_sum(&[protected_encoded, payload_encoded, 1])?;
    // All three strings are base64url and require no JSON escaping.
    let body = checked_sum(&[protected_encoded, payload_encoded, signature_encoded, 128])?;
    let peak = checked_sum(&[input_bytes, prelude, protected_bytes, payload_bytes,
        protected_encoded, payload_encoded, signed, max, signature_encoded, body, 8192])?;
    a.loan.as_mut().expect("input credit").grow_to(peak)?;
    encoded_json(a.protected_json.as_ref().expect("protected fields"), &mut a.protected_bytes, &mut a.protected, protected_bytes)?;
    if let Some(value) = a.input.as_ref().expect("raw payload").payload.as_ref() {
        encoded_json(value, &mut a.payload_bytes, &mut a.payload, payload_bytes)?;
    } else { a.payload = Some(String::new()); }
    a.signed = Some(String::new());
    let text = a.signed.as_mut().expect("admitted signed bytes");
    text.try_reserve_exact(signed)?;
    text.push_str(a.protected.as_ref().expect("encoded protected"));text.push('.');
    text.push_str(a.payload.as_ref().expect("encoded payload"));
    a.signature = Some(a.input.as_ref().expect("signer").signer.sign(text.as_bytes())?);
    ensure!(a.signature.as_ref().expect("signature").len() <= max, "account signature exceeded its actual key bound");
    a.encoded = Some(String::new());
    let text = a.encoded.as_mut().expect("admitted signature text");text.try_reserve_exact(signature_encoded)?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(a.signature.as_ref().expect("signature"), text);
    let mut object=serde_json::Map::new();
    object.insert("protected".into(),serde_json::Value::String(a.protected.take().expect("encoded protected")));
    object.insert("payload".into(),serde_json::Value::String(a.payload.take().expect("encoded payload")));
    object.insert("signature".into(),serde_json::Value::String(a.encoded.take().expect("encoded signature")));
    a.json=Some(serde_json::Value::Object(object));
    a.body=Some(Vec::new());let bytes=a.body.as_mut().expect("admitted JWS body");bytes.try_reserve_exact(body)?;
    serde_json::to_writer(&mut *bytes,a.json.as_ref().expect("closed JWS fields"))?;
    ensure!(bytes.len()<=body,"JWS body exceeded preflight");
    let mut ready=BodyData {bytes:a.body.take().expect("JWS body"),loan:a.loan.take().expect("JWS body credit")};
    drop(a);
    ready.loan.shrink_to(ready.bytes.capacity())?;
    Ok(ready)
}
