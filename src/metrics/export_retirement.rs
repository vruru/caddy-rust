//! Closed observability retirement domains. No callback/Any registration API.
mod control;
use super::distributed_trace::processor;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Domain {
    Trace,
    Metrics,
}
#[derive(Clone)]
pub(super) enum ControlCredit {
    Trace(Arc<processor::Credit>),
    Metrics(control::MetricCredit),
}
#[derive(Clone)]
pub(super) enum Admission {
    Trace(Arc<processor::Process>),
    Metrics(Arc<control::MetricAdmission>),
}
impl Admission {
    pub(super) fn metrics(parent: Arc<Semaphore>) -> Result<Self> {
        Ok(Self::Metrics(control::MetricAdmission::new(parent)?))
    }
    pub(super) fn domain(&self) -> Domain {
        match self {
            Self::Trace(_) => Domain::Trace,
            Self::Metrics(_) => Domain::Metrics,
        }
    }
    pub(super) fn reserve(&self, bytes: usize) -> Result<ControlCredit> {
        match self {
            Self::Trace(source) => Ok(ControlCredit::Trace(source.metadata(bytes)?)),
            Self::Metrics(source) => Ok(ControlCredit::Metrics(source.reserve(bytes)?)),
        }
    }
    pub(super) fn trace_source(&self) -> Result<&Arc<processor::Process>> {
        match self {
            Self::Trace(source) => Ok(source),
            Self::Metrics(_) => Err(anyhow!(
                "observability input used in metrics retirement domain"
            )),
        }
    }
    pub(super) fn control_inner_layout(&self) -> usize {
        match self {
            Self::Trace(_) => {
                std::mem::size_of::<processor::Credit>() + 4 * std::mem::size_of::<usize>()
            }
            Self::Metrics(_) => control::MetricAdmission::credit_layout(),
        }
    }
}

// CORE BELOW — closed shared state; domain adapters cannot register arbitrary data.
pub(in crate::metrics) mod resident;
use crate::metrics::transport::Memory;
use resident::Resident;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Condvar, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use tokio::sync::Notify;
use tokio_util::task::task_tracker::TaskTrackerToken;
pub(in crate::metrics) struct WakeSignal {
    pub(in crate::metrics) notify: Notify,
    pub(in crate::metrics) _credit: ControlCredit,
}
impl Wake for WakeSignal {
    fn wake(self: Arc<Self>) {
        self.notify.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify.notify_one();
    }
}

pub(in crate::metrics) struct State {
    pub(in crate::metrics) data: Resident,
    pub(in crate::metrics) polling: bool,
    pub(in crate::metrics) retiring: bool,
    pub(in crate::metrics) retire: bool,
    pub(in crate::metrics) closed: bool,
    pub(in crate::metrics) submitters: usize,
    pub(in crate::metrics) epoch: u64,
    pub(in crate::metrics) readers: usize,
    pub(in crate::metrics) cpu_thread: Option<std::thread::ThreadId>,
    pub(in crate::metrics) local_done: bool,
    pub(in crate::metrics) local_failed: bool,
    pub(in crate::metrics) token: Option<TaskTrackerToken>,
    pub(in crate::metrics) next: Option<Arc<Cell>>,
}
pub(in crate::metrics) struct Cell {
    pub(in crate::metrics) state: Mutex<State>,
    pub(in crate::metrics) wake: Arc<WakeSignal>,
    pub(in crate::metrics) closed_notify: Notify,
    pub(in crate::metrics) _credit: ControlCredit,
}

/// Last external handle only signals. The registry remains the strong data owner.
pub(in crate::metrics) struct ActorCell {
    pub(in crate::metrics) cell: Arc<Cell>,
    pub(in crate::metrics) shared: WeakOwner,
}
#[derive(Clone)]
pub(in crate::metrics) struct CellRef {
    pub(in crate::metrics) cell: Arc<Cell>,
    pub(in crate::metrics) shared: WeakOwner,
}
pub(in crate::metrics) struct SubmitTicket {
    pub(in crate::metrics) cell: Arc<Cell>,
    pub(in crate::metrics) shared: WeakOwner,
    pub(in crate::metrics) active: bool,
}
#[derive(Clone, Copy, Debug)]
pub(in crate::metrics) enum WorkError {
    Busy,
    Stopped,
    Worker,
    Workspace,
}
pub(in crate::metrics) enum Step {
    Started,
    Pending,
    Complete(bool),
    Console {
        writer: Arc<crate::metrics::console_writer::Writer>,
        deadline: tokio::time::Instant,
    },
}
pub(in crate::metrics) enum Command {
    Metrics(crate::metrics::export::MetricInputs),
    Trace(crate::metrics::distributed_trace::export_work::TraceCommand),
    Poll,
}
/// Cancelling a small waiter must request retirement independently of the
/// Provider's still-live external ActorCell handle.
pub(in crate::metrics) struct BatchGuard {
    pub(in crate::metrics) reference: CellRef,
    pub(in crate::metrics) active: bool,
    pub(in crate::metrics) final_close: bool,
}
impl BatchGuard {
    pub(in crate::metrics) fn disarm(&mut self) {
        self.active = false;
    }
}
impl Drop for BatchGuard {
    fn drop(&mut self) {
        if self.active {
            self.reference.retire(self.final_close);
        }
    }
}
pub(in crate::metrics) struct StoredSignal {
    pub(in crate::metrics) cell: Arc<Cell>,
    pub(in crate::metrics) shared: WeakOwner,
}
impl Drop for StoredSignal {
    fn drop(&mut self) {
        signal(&self.shared, &self.cell.wake);
    }
}
pub(in crate::metrics) struct PollGuard<'a> {
    pub(in crate::metrics) data: Option<Resident>,
    pub(in crate::metrics) cell: Arc<Cell>,
    pub(in crate::metrics) shared: WeakOwner,
    pub(in crate::metrics) _permit: &'a tokio::sync::OwnedSemaphorePermit,
}

impl ActorCell {
    /// Only the whole worker owns this guard. An undisarmed Drop means no
    /// future batch will consume overflow, so final close retires pending too.
    pub(in crate::metrics) fn worker_batch_guard(&self) -> BatchGuard {
        BatchGuard {
            reference: self.cell_ref(),
            active: true,
            final_close: true,
        }
    }
    /// A cancelled individual CPU step leaves its still-running worker able
    /// to continue with overflow after ordinary batch retirement.
    fn step_guard(&self) -> BatchGuard {
        BatchGuard {
            reference: self.cell_ref(),
            active: true,
            final_close: false,
        }
    }
    pub(in crate::metrics) async fn poll_export(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(budget, Command::Poll).await
    }
    pub(in crate::metrics) async fn execute(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        command: Command,
    ) -> std::result::Result<Step, WorkError> {
        use crate::http_runtime::resource_budget::run_owned;
        let shared = self.shared.upgrade().ok_or(WorkError::Stopped)?;
        if !Arc::ptr_eq(&shared.running, &budget.retirement_running()) {
            return Err(WorkError::Stopped);
        }
        drop(shared);
        let mut cancelled = self.step_guard();
        let reference = self.cell_ref();
        let cpu = budget.clone();
        let permit = budget.acquire().await.map_err(|_| WorkError::Busy)?;
        let result = run_owned(budget.tasks(), (), move || {
            let _permit = permit;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Some(mut guard) = reference.claim_poll(&_permit) else {
                    return Err(WorkError::Stopped);
                };
                apply_command(guard.data_mut(), &reference, &cpu, command)
            }));
            match result {
                Ok(result) => result,
                Err(payload) => {
                    drop(payload);
                    Err(WorkError::Worker)
                }
            }
        })
        .await
        .map_err(|_| WorkError::Worker)?;
        cancelled.active = false;
        result
    }
    pub(in crate::metrics) async fn wait_wake(&self, deadline: tokio::time::Instant) -> bool {
        tokio::time::timeout_at(deadline, self.cell.wake.notify.notified())
            .await
            .is_ok()
    }
    pub(in crate::metrics) async fn finish_batch(&self) {
        let epoch = {
            let state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed
                && state.data.is_empty()
                && !state.polling
                && !state.retiring
                && state.submitters == 0
                && state.token.is_none()
            {
                return;
            }
            state.epoch
        };
        self.retire(false);
        loop {
            let ready = self.cell.wake.notify.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if self.epoch() != epoch {
                return;
            }
            ready.await;
        }
    }
    pub(in crate::metrics) fn trace_context(&self) -> Result<Arc<ExportContext>> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("observability retirement stopped"))?;
        let credit = shared.source.reserve(
            std::mem::size_of::<ExportContext>()
                + std::mem::size_of::<Mutex<Option<ByteReceipt>>>()
                + 6 * std::mem::size_of::<usize>(),
        )?;
        Ok(Arc::new(ExportContext {
            parent: Arc::downgrade(&self.cell),
            shared: self.shared.clone(),
            previous: Arc::new(Mutex::new(None)),
            _parent_credit: self.cell._credit.clone(),
            _credit: credit,
        }))
    }
    pub(in crate::metrics) fn submission_ticket(&self) -> Result<SubmitTicket> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("observability retirement stopped"))?;
        {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if shared.closed.load(Ordering::Acquire)
                || state.closed
                || state.retire
                || state.retiring
                || state.polling
                || state.submitters != 0
                || state.readers != 0
                || state.data.has_ingress()
            {
                return Err(anyhow!("observability source residence unavailable"));
            }
            state.submitters = 1;
        }
        Ok(SubmitTicket {
            cell: self.cell.clone(),
            shared: self.shared.clone(),
            active: true,
        })
    }
    pub(in crate::metrics) fn cell_ref(&self) -> CellRef {
        CellRef {
            cell: self.cell.clone(),
            shared: self.shared.clone(),
        }
    }
    pub(in crate::metrics) fn attach_token(&self, token: TaskTrackerToken) -> Result<()> {
        let mut incoming = Some(token);
        let accepted = {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed || state.retire || state.token.is_some() {
                false
            } else {
                state.token = incoming.take();
                true
            }
        };
        drop(incoming);
        if accepted {
            Ok(())
        } else {
            Err(anyhow!("observability task residence stopped"))
        }
    }
    pub(in crate::metrics) fn retire(&self, final_close: bool) {
        self.cell_ref().retire(final_close);
    }
    pub(in crate::metrics) fn is_empty(&self) -> bool {
        let state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        state.data.is_empty() && !state.polling && !state.retiring && state.submitters == 0
    }
    pub(in crate::metrics) fn epoch(&self) -> u64 {
        self.cell
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .epoch
    }
}
impl Drop for ActorCell {
    fn drop(&mut self) {
        self.retire(true);
    }
}

impl Drop for SubmitTicket {
    fn drop(&mut self) {
        if self.active {
            {
                let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
                state.submitters = 0;
            }
            signal(&self.shared, &self.cell.wake);
        }
    }
}
impl CellRef {
    pub(in crate::metrics) fn retire(&self, final_close: bool) {
        {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            state.closed |= final_close;
            state.retire = true;
        }
        if final_close {
            self.cell.closed_notify.notify_waiters();
        }
        signal(&self.shared, &self.cell.wake);
    }
    /// Private callers must already hold the same trace CPU running permit.
    pub(in crate::metrics) fn claim_poll<'a>(
        &self,
        permit: &'a tokio::sync::OwnedSemaphorePermit,
    ) -> Option<PollGuard<'a>> {
        if self
            .shared
            .upgrade()
            .is_none_or(|shared| shared.closed.load(Ordering::Acquire))
        {
            return None;
        }
        let owner = self.shared.upgrade()?;
        if !Arc::ptr_eq(&owner.running, permit.semaphore()) {
            return None;
        }
        drop(owner);
        let data = {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed
                || state.retire
                || state.retiring
                || state.polling
                || state.submitters != 0
                || state.readers != 0
            {
                return None;
            }
            state.polling = true;
            state.cpu_thread = Some(std::thread::current().id());
            {
                let domain = state.data.domain();
                std::mem::replace(&mut state.data, Resident::empty(domain))
            }
        };
        Some(PollGuard {
            data: Some(data),
            cell: self.cell.clone(),
            shared: self.shared.clone(),
            _permit: permit,
        })
    }
}
impl PollGuard<'_> {
    pub(in crate::metrics) fn data_mut(&mut self) -> &mut Resident {
        self.data.as_mut().expect("live private CPU poll guard")
    }
}
impl Drop for PollGuard<'_> {
    fn drop(&mut self) {
        // The only constructor runs inside the CPU operation; both unwind and
        // success put the data back before releasing that actual CPU operation.
        let unwinding = std::thread::panicking();
        let retiring = {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            debug_assert!(state.data.is_empty());
            state.data = self.data.take().expect("live private CPU poll guard");
            state.polling = false;
            state.cpu_thread = None;
            state.retire |= unwinding;
            state.retire || state.closed
        };
        // A normal Pending poll must not wake itself and busy-spin on network
        // waits. Only actual SDK IO/timers or a retirement transition wake it.
        if retiring
            || self
                .shared
                .upgrade()
                .is_none_or(|shared| shared.closed.load(Ordering::Acquire))
        {
            signal(&self.shared, &self.cell.wake);
        }
    }
}
fn signal(shared: &WeakOwner, wake: &WakeSignal) {
    if let Some(shared) = shared.upgrade() {
        shared.signal();
    }
    wake.notify.notify_one();
}

pub(in crate::metrics) struct Shared {
    pub(in crate::metrics) registry: Mutex<Option<Arc<Cell>>>,
    pub(in crate::metrics) sequence: Mutex<u64>,
    pub(in crate::metrics) condition: Condvar,
    pub(in crate::metrics) closed: AtomicBool,
    pub(in crate::metrics) running: Arc<Semaphore>,
    pub(in crate::metrics) source: Admission,
    pub(in crate::metrics) done: tokio::sync::watch::Sender<bool>,
    pub(in crate::metrics) _credit: ControlCredit,
}
/// Weak capabilities carry the small control allocation's credit until the
/// actual Weak control-block reference is dropped. They never retain a batch.
#[derive(Clone)]
pub(in crate::metrics) struct WeakOwner {
    pub(in crate::metrics) shared: Weak<Shared>,
    pub(in crate::metrics) _credit: ControlCredit,
}
impl std::fmt::Debug for WeakOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservabilityOwnerIdentity")
    }
}
impl WeakOwner {
    pub(in crate::metrics) fn same_owner(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.shared, &other.shared)
    }

    fn new(shared: &Arc<Shared>) -> Self {
        Self {
            shared: Arc::downgrade(shared),
            _credit: shared._credit.clone(),
        }
    }
    pub(in crate::metrics) fn upgrade(&self) -> Option<Arc<Shared>> {
        self.shared.upgrade()
    }
}
impl Shared {
    fn new(source: Admission, running: Arc<Semaphore>, credit: ControlCredit) -> Self {
        Self {
            registry: Mutex::new(None),
            sequence: Mutex::new(0),
            condition: Condvar::new(),
            closed: AtomicBool::new(false),
            running,
            source,
            done: tokio::sync::watch::channel(false).0,
            _credit: credit,
        }
    }
    fn signal(&self) {
        {
            let mut sequence = self.sequence.lock().unwrap_or_else(|e| e.into_inner());
            *sequence = sequence.wrapping_add(1);
        }
        self.condition.notify_one();
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        // O(1) on the caller/reactor. Registry traversal belongs to the
        // already-existing retirement thread, including a large empty backlog.
        self.signal();
    }
    fn register(self: &Arc<Self>) -> Result<Arc<ActorCell>> {
        let bytes = std::mem::size_of::<Cell>()
            .checked_add(std::mem::size_of::<ActorCell>())
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<processor::Credit>()))
            .and_then(|n| n.checked_add(8 * std::mem::size_of::<usize>()))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Command>() + std::mem::size_of::<Step>() + 4096)
            })
            .ok_or_else(|| anyhow!("observability cell layout overflow"))?;
        let credit = self.source.reserve(bytes)?;
        let wake_credit = self
            .source
            .reserve(std::mem::size_of::<WakeSignal>() + 2 * std::mem::size_of::<usize>())?;
        let cell = Arc::new(Cell {
            state: Mutex::new(State {
                data: Resident::empty(self.source.domain()),
                polling: false,
                retiring: false,
                retire: false,
                closed: false,
                submitters: 0,
                epoch: 0,
                readers: 0,
                cpu_thread: None,
                local_done: false,
                local_failed: false,
                token: None,
                next: None,
            }),
            wake: Arc::new(WakeSignal {
                notify: Notify::new(),
                _credit: wake_credit,
            }),
            closed_notify: Notify::new(),
            _credit: credit,
        });
        let accepted = {
            let mut head = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            if self.closed.load(Ordering::Acquire) {
                false
            } else {
                cell.state.lock().unwrap_or_else(|e| e.into_inner()).next = head.take();
                *head = Some(cell.clone());
                true
            }
        };
        if !accepted {
            return Err(anyhow!("observability retirement stopped"));
        }
        Ok(Arc::new(ActorCell {
            cell,
            shared: WeakOwner::new(self),
        }))
    }
    fn candidate(&self) -> Option<(Arc<Cell>, Resident)> {
        let mut cursor = self
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        while let Some(cell) = cursor {
            let closing = self.closed.load(Ordering::Acquire);
            let data = {
                let mut state = cell.state.lock().unwrap_or_else(|e| e.into_inner());
                cursor = state.next.clone();
                if closing {
                    state.closed = true;
                    state.retire = true;
                }
                if state.retire
                    && !state.polling
                    && !state.retiring
                    && state.submitters == 0
                    && state.readers == 0
                {
                    state.retiring = true;
                    let closed = state.closed;
                    let data = state.data.take_for_retirement(closed);
                    Some(data)
                } else {
                    None
                }
            };
            if closing {
                cell.closed_notify.notify_waiters();
            }
            if let Some(data) = data {
                return Some((cell, data));
            }
        }
        None
    }
    fn unlink(&self, target: &Arc<Cell>) {
        let mut removed = None;
        {
            let mut head = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            if head.as_ref().is_some_and(|v| Arc::ptr_eq(v, target)) {
                removed = head.take();
                *head = target
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .next
                    .take();
            } else {
                let mut cursor = head.clone();
                while let Some(cell) = cursor {
                    let mut state = cell.state.lock().unwrap_or_else(|e| e.into_inner());
                    if state.next.as_ref().is_some_and(|v| Arc::ptr_eq(v, target)) {
                        removed = state.next.take();
                        state.next = target
                            .state
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .next
                            .take();
                        break;
                    }
                    cursor = state.next.clone();
                }
            }
        }
        drop(removed);
    }
    fn reap_loop(&self) {
        loop {
            let observed = *self.sequence.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((cell, data)) = self.candidate() {
                // No runtime, timer, registry or cell lock is needed here.
                let permit = acquire_cpu(self.running.clone());
                let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(data)));
                let failed = dropped.is_err();
                // A panic's erased payload may itself own a large allocation.
                // Retire it under the same CPU permit as the original data.
                drop(dropped);
                drop(permit);
                let (token, remove) = {
                    let mut state = cell.state.lock().unwrap_or_else(|e| e.into_inner());
                    state.retiring = false;
                    state.retire = false;
                    state.closed |= failed;
                    state.epoch = state.epoch.wrapping_add(1);
                    let remove = state.closed && state.data.is_empty();
                    if state.closed && !remove {
                        state.retire = true;
                    }
                    (state.token.take(), remove)
                };
                drop(token);
                cell.wake.notify.notify_one();
                if remove {
                    self.unlink(&cell);
                }
                continue;
            }
            if self.closed.load(Ordering::Acquire)
                && self
                    .registry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_none()
            {
                break;
            }
            let mut sequence = self.sequence.lock().unwrap_or_else(|e| e.into_inner());
            while *sequence == observed {
                sequence = self
                    .condition
                    .wait(sequence)
                    .unwrap_or_else(|e| e.into_inner());
            }
        }
        self.done.send_replace(true);
    }
}

struct Unpark(std::thread::Thread);
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}
fn acquire_cpu(running: Arc<Semaphore>) -> tokio::sync::OwnedSemaphorePermit {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut future = std::pin::pin!(running.acquire_owned());
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(Ok(permit)) => return permit,
            Poll::Ready(Err(_)) => unreachable!("observability running semaphore is never closed"),
            Poll::Pending => std::thread::park(),
        }
    }
}

struct JoinState {
    pub(in crate::metrics) handle: Option<std::thread::JoinHandle<()>>,
    pub(in crate::metrics) stack: Option<ControlCredit>,
    pub(in crate::metrics) joining: bool,
    pub(in crate::metrics) result: Option<bool>,
    pub(in crate::metrics) _credit: ControlCredit,
}
struct JoinJob {
    pub(in crate::metrics) handle: Option<std::thread::JoinHandle<()>>,
    pub(in crate::metrics) stack: Option<ControlCredit>,
    pub(in crate::metrics) state: Arc<Mutex<JoinState>>,
    pub(in crate::metrics) changed: Arc<Notify>,
}
impl JoinJob {
    fn run(mut self) {
        let handle = self.handle.take().expect("unique retirement join handle");
        let joined = handle.join().is_ok();
        // The external share survives business-done AND the actual OS join.
        drop(self.stack.take());
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.joining = false;
            state.result = Some(joined);
        }
        self.changed.notify_waiters();
    }
}
impl Drop for JoinJob {
    fn drop(&mut self) {
        // A stopped runtime may discard an unstarted join operation. Restore
        // its small handle/credit rather than reporting a join or refunding it.
        if let Some(handle) = self.handle.take() {
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                debug_assert!(state.handle.is_none());
                state.handle = Some(handle);
                state.stack = self.stack.take();
                state.joining = false;
            }
            self.changed.notify_waiters();
        }
    }
}

/// This external owner is not retained by the thread, cells or export Plans.
pub(crate) struct RetirementOwner {
    pub(in crate::metrics) shared: Arc<Shared>,
    pub(in crate::metrics) join: Arc<Mutex<JoinState>>,
    pub(in crate::metrics) changed: Arc<Notify>,
    pub(in crate::metrics) _credit: ControlCredit,
}
impl RetirementOwner {
    pub(crate) fn new(source: Arc<processor::Process>, running: Arc<Semaphore>) -> Result<Self> {
        Self::with_admission(Admission::Trace(source), running)
    }
    pub(in crate::metrics) fn new_metrics(
        parent: Arc<Semaphore>,
        running: Arc<Semaphore>,
    ) -> Result<Self> {
        Self::with_admission(Admission::metrics(parent)?, running)
    }
    fn with_admission(source: Admission, running: Arc<Semaphore>) -> Result<Self> {
        const STACK: usize = 2 << 20;
        let control = std::mem::size_of::<Shared>()
            .checked_add(std::mem::size_of::<Self>())
            .and_then(|n| n.checked_add(std::mem::size_of::<JoinState>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<JoinJob>()))
            .and_then(|n| n.checked_add(16384))
            .ok_or_else(|| anyhow!("observability retirement control layout overflow"))?;
        let credit = source.reserve(control)?;
        let stack_credit = source.reserve(STACK + 8192)?;
        let shared = Arc::new(Shared::new(source, running, credit.clone()));
        let thread_shared = shared.clone();
        let thread_credit = stack_credit.clone();
        // Starting this thread is a prepare operation, before accepting data.
        let thread = std::thread::Builder::new()
            .name(
                match shared.source.domain() {
                    Domain::Trace => "trace-retirement",
                    Domain::Metrics => "metric-retirement",
                }
                .into(),
            )
            .stack_size(STACK)
            .spawn(move || {
                let _through_function_exit = thread_credit;
                thread_shared.reap_loop();
            })?;
        Ok(Self {
            shared,
            join: Arc::new(Mutex::new(JoinState {
                handle: Some(thread),
                stack: Some(stack_credit),
                joining: false,
                result: None,
                _credit: credit.clone(),
            })),
            changed: Arc::new(Notify::new()),
            _credit: credit,
        })
    }
    pub(in crate::metrics) fn register(&self) -> Result<Arc<ActorCell>> {
        self.shared.register()
    }
    pub(crate) fn close(&self) {
        self.shared.close();
    }
    pub(crate) async fn shutdown(&self) -> Result<()> {
        self.close();
        let mut done = self.shared.done.subscribe();
        while !*done.borrow_and_update() {
            done.changed()
                .await
                .map_err(|_| anyhow!("observability retirement completion unavailable"))?;
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow!("observability retirement join requires an active executor"))?;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let job = {
                let mut state = self.join.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(joined) = state.result {
                    return if joined {
                        Ok(())
                    } else {
                        Err(anyhow!("observability retirement thread failed"))
                    };
                }
                if state.joining {
                    None
                } else {
                    let handle = state.handle.take().ok_or_else(|| {
                        anyhow!("observability retirement join handle unavailable")
                    })?;
                    let stack = state.stack.take();
                    state.joining = true;
                    Some(JoinJob {
                        handle: Some(handle),
                        stack,
                        state: self.join.clone(),
                        changed: self.changed.clone(),
                    })
                }
            };
            if let Some(job) = job {
                // Dropping this waiter cannot abort the running actual join.
                runtime
                    .spawn_blocking(move || job.run())
                    .await
                    .map_err(|_| anyhow!("observability retirement join executor unavailable"))?;
            } else {
                changed.await;
            }
        }
    }
}
impl Drop for RetirementOwner {
    fn drop(&mut self) {
        // No-runtime abandonment does not pretend to perform an async join.
        // The existing thread retains its stack credit through function exit;
        // only explicit shutdown retains the external share through OS join.
        self.close();
    }
}

/// Immutable storage has no Plan, Driver, Process or external owner edge.
pub(in crate::metrics) struct Backing {
    pub(in crate::metrics) data: bytes::Bytes,
    pub(in crate::metrics) _output: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(in crate::metrics) _memory: Memory,
    pub(in crate::metrics) _credit: ControlCredit,
}
struct ReaderLease {
    pub(in crate::metrics) backing: Option<Arc<Backing>>,
    pub(in crate::metrics) cell: Weak<Cell>,
    pub(in crate::metrics) shared: WeakOwner,
    // The from_owner allocation and Weak control blocks remain paid until the
    // last actual Bytes owner is destroyed, rather than just reader0.
    pub(in crate::metrics) _cell_credit: ControlCredit,
    pub(in crate::metrics) _credit: ControlCredit,
}
impl AsRef<[u8]> for ReaderLease {
    fn as_ref(&self) -> &[u8] {
        &self
            .backing
            .as_ref()
            .expect("live immutable byte reader")
            .data
    }
}
impl Drop for ReaderLease {
    fn drop(&mut self) {
        // Registry cannot take its primary while readers != 0. Release our
        // actual backing reference BEFORE publishing reader0.
        drop(self.backing.take());
        if let Some(cell) = self.cell.upgrade() {
            {
                let mut state = cell.state.lock().unwrap_or_else(|e| e.into_inner());
                debug_assert_eq!(state.readers, 1);
                state.readers = 0;
            }
            signal(&self.shared, &cell.wake);
        }
    }
}
#[derive(Clone)]
pub(in crate::metrics) struct ByteReceipt {
    pub(in crate::metrics) cell: Weak<Cell>,
    pub(in crate::metrics) _credit: ControlCredit,
}
impl ByteReceipt {
    fn readers_live(&self) -> bool {
        self.cell
            .upgrade()
            .is_some_and(|cell| cell.state.lock().unwrap_or_else(|e| e.into_inner()).readers != 0)
    }
    async fn wait(&self) {
        loop {
            let Some(cell) = self.cell.upgrade() else {
                return;
            };
            let notified = cell.wake.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let retired = {
                let state = cell.state.lock().unwrap_or_else(|e| e.into_inner());
                state.epoch != 0
                    && state.data.backing_ref().is_none()
                    && !state.retiring
                    && state.readers == 0
            };
            if retired {
                return;
            }
            notified.await;
        }
    }
}

/// Fixed trace caller capability. All back edges from a resident SDK future
/// remain Weak; neither the byte pin nor this capability owns MetricsProcess.
pub(crate) struct ExportContext {
    pub(in crate::metrics) parent: Weak<Cell>,
    pub(in crate::metrics) shared: WeakOwner,
    pub(in crate::metrics) previous: Arc<Mutex<Option<ByteReceipt>>>,
    pub(in crate::metrics) _parent_credit: ControlCredit,
    pub(in crate::metrics) _credit: ControlCredit,
}
#[derive(Clone, Copy)]
pub(crate) enum ByteKind {
    Http,
    Grpc,
    Console,
}
/// Whole-struct capture preserves data-before-output/memory destruction even
/// when a queued console handoff future is cancelled before its first poll.
pub(in crate::metrics) struct PinInput {
    pub(in crate::metrics) data: bytes::Bytes,
    pub(in crate::metrics) output: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(in crate::metrics) memory: Memory,
}
impl ExportContext {
    fn bound_to(&self, cell: &CellRef) -> Result<Arc<Self>> {
        anyhow::ensure!(
            self.shared.same_owner(&cell.shared),
            "observability owner identity mismatch"
        );
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("observability retirement stopped"))?;
        let credit = shared
            .source
            .reserve(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())?;
        Ok(Arc::new(Self {
            parent: Arc::downgrade(&cell.cell),
            shared: self.shared.clone(),
            previous: self.previous.clone(),
            _parent_credit: cell.cell._credit.clone(),
            _credit: credit,
        }))
    }
    fn on_cpu(&self) -> bool {
        self.parent.upgrade().is_some_and(|cell| {
            let state = cell.state.lock().unwrap_or_else(|e| e.into_inner());
            state.polling && state.cpu_thread == Some(std::thread::current().id())
        })
    }
    /// Await only this completed body pin. Live actual DATA is never waited
    /// away to make the original retained-DATA retry predicate become true.
    pub(crate) async fn finish_body_if_idle(&self) -> bool {
        let previous = self
            .previous
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(previous) = previous {
            if previous.readers_live() {
                return false;
            }
            previous.wait().await;
        }
        true
    }
    /// Called only by a registered trace export future's actual CPU poll.
    pub(crate) async fn pin_bytes(
        &self,
        kind: ByteKind,
        body: bytes::Bytes,
        memory: Memory,
    ) -> Result<bytes::Bytes> {
        self.pin_input(
            kind,
            PinInput {
                data: body,
                output: None,
                memory,
            },
        )
        .await
    }
    pub(in crate::metrics) async fn pin_input(
        &self,
        kind: ByteKind,
        input: PinInput,
    ) -> Result<bytes::Bytes> {
        anyhow::ensure!(
            self.on_cpu(),
            "observability byte handoff outside its CPU poll"
        );
        anyhow::ensure!(
            self.shared
                .upgrade()
                .is_some_and(|shared| shared.source.domain() == input.memory.domain()
                    && input.memory.belongs_to(&self.shared)),
            "observability byte memory domain mismatch"
        );
        let limit = match kind {
            ByteKind::Http => 32 << 20,
            ByteKind::Grpc => (32 << 20) + 5,
            ByteKind::Console => 64 << 20,
        };
        anyhow::ensure!(
            input.data.len() <= limit,
            "observability encoded body exceeds its existing limit"
        );
        anyhow::ensure!(
            self.finish_body_if_idle().await,
            "previous trace DATA remains owned"
        );
        // A poll can migrate to another real CPU worker after the await.
        anyhow::ensure!(
            self.on_cpu(),
            "observability byte handoff resumed outside its CPU poll"
        );
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("observability retirement stopped"))?;
        let child = shared.register()?;
        let mut ticket = child.submission_ticket()?;
        let layout = std::mem::size_of::<Backing>()
            .checked_add(std::mem::size_of::<ReaderLease>())
            .and_then(|n| n.checked_add(std::mem::size_of::<ByteReceipt>()))
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<processor::Credit>()
                        + 10 * std::mem::size_of::<usize>()
                        + std::mem::align_of::<ReaderLease>(),
                )
            })
            .ok_or_else(|| anyhow!("observability byte ownership layout overflow"))?;
        let credit = shared.source.reserve(layout)?;
        let backing = Arc::new(Backing {
            data: input.data,
            _output: input.output,
            _memory: input.memory,
            _credit: credit.clone(),
        });
        {
            let mut state = child.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            debug_assert!(state.data.backing_ref().is_none() && state.submitters == 1);
            *state.data.backing_mut() = Some(backing.clone());
            state.readers = 1;
            state.submitters = 0;
            ticket.active = false;
        }
        let receipt = ByteReceipt {
            cell: Arc::downgrade(&child.cell),
            _credit: child.cell._credit.clone(),
        };
        let reader = ReaderLease {
            backing: Some(backing),
            cell: Arc::downgrade(&child.cell),
            shared: self.shared.clone(),
            _cell_credit: child.cell._credit.clone(),
            _credit: credit,
        };
        let bytes = bytes::Bytes::from_owner(reader);
        let old = {
            let mut previous = self.previous.lock().unwrap_or_else(|e| e.into_inner());
            previous.replace(receipt)
        };
        drop(old);
        // Byte cells have no Driver token. Only Process retirement owns their
        // physical lifetime, so Plan.shutdown can still close the actor's IO.
        child.retire(true);
        Ok(bytes)
    }

    /// Only the generated unary request body enters this closed child owner.
    /// The supervisor captures small handles, never the unencoded Body.
    pub(crate) async fn prepare_unary(
        self: &Arc<Self>,
        request: http::Request<tonic::body::Body>,
        memory: Memory,
        budget: crate::http_runtime::resource_budget::BlockingBudget,
    ) -> std::result::Result<http::Request<tonic::body::Body>, tonic::Status> {
        use crate::http_runtime::resource_budget::run_owned;
        let failed =
            || tonic::Status::resource_exhausted("observability unary preparation unavailable");
        if !self.on_cpu() {
            return Err(tonic::Status::internal(
                "observability unary handoff outside CPU poll",
            ));
        }
        if !self.finish_body_if_idle().await {
            return Err(tonic::Status::resource_exhausted(
                "previous trace DATA remains owned",
            ));
        }
        let shared = self.shared.upgrade().ok_or_else(failed)?;
        if shared.source.domain() != memory.domain() || !memory.belongs_to(&self.shared) {
            return Err(failed());
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| failed())?;
        if !Arc::ptr_eq(&shared.running, &budget.retirement_running()) {
            return Err(failed());
        }
        let child = shared.register().map_err(|_| failed())?;
        let mut ticket = child.submission_ticket().map_err(|_| failed())?;
        let token = self.parent.upgrade().and_then(|cell| {
            cell.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .token
                .clone()
        });
        if let Some(token) = token {
            child.attach_token(token).map_err(|_| failed())?;
        }
        {
            let mut state = child.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            *state.data.unary_mut() = Some(request);
            *state.data.memory_mut() = Some(memory);
            state.submitters = 0;
            ticket.active = false;
        }
        let reference = child.cell_ref();
        let parent = self.clone();
        let notify_parent = self.clone();
        let tasks = budget.tasks();
        tasks.spawn_on(
            async move {
                let permit = budget.acquire().await;
                let work = if let Ok(permit) = permit {
                    let worker = reference.clone();
                    run_owned(budget.tasks(), (), move || {
                        let _permit = permit;
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let Some(mut guard) = worker.claim_poll(&_permit) else {
                                return false;
                            };
                            let result = encode_unary_local(guard.data_mut(), &parent, &worker);
                            if let Err(status) = result {
                                *guard.data_mut().encode_error_mut() = Some(status);
                            }
                            true
                        }));
                        let done = result.as_ref().is_ok_and(|v| *v);
                        drop(result); // panic payload also retires under _permit
                        done
                    })
                    .await
                    .unwrap_or(false)
                } else {
                    false
                };
                {
                    let mut state = reference
                        .cell
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    state.local_done = true;
                    state.local_failed = !work;
                }
                signal(&reference.shared, &reference.cell.wake);
                if let Some(cell) = notify_parent.parent.upgrade() {
                    cell.wake.notify.notify_one();
                }
            },
            &runtime,
        );
        loop {
            let notified = child.cell.wake.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let done = child
                .cell
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .local_done;
            if done {
                break;
            }
            notified.await;
        }
        if !self.on_cpu() {
            return Err(tonic::Status::internal(
                "observability unary result outside CPU poll",
            ));
        }
        let (mut data, failed) = {
            let mut state = child.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.polling || state.retiring || state.retire || state.closed {
                return Err(tonic::Status::cancelled(
                    "observability unary preparation stopped",
                ));
            }
            (
                {
                    let domain = state.data.domain();
                    std::mem::replace(&mut state.data, Resident::empty(domain))
                },
                state.local_failed,
            )
        };
        let result = if let Some(status) = data.encode_error_mut().take() {
            Err(status)
        } else if failed {
            Err(failed_status())
        } else {
            data.prepared_mut().take().ok_or_else(failed_status)
        };
        // The outer poll already holds the same CPU capacity. Clear temporary
        // encoder credit before any original gRPC strong-count retry check.
        drop(data);
        child.retire(true);
        result
    }
}

fn failed_status() -> tonic::Status {
    tonic::Status::resource_exhausted("observability unary encoding worker unavailable")
}

impl CellRef {
    pub(in crate::metrics) fn context(&self) -> Result<Arc<ExportContext>> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("observability retirement stopped"))?;
        let credit = shared.source.reserve(
            std::mem::size_of::<ExportContext>()
                + std::mem::size_of::<Mutex<Option<ByteReceipt>>>()
                + 6 * std::mem::size_of::<usize>(),
        )?;
        Ok(Arc::new(ExportContext {
            parent: Arc::downgrade(&self.cell),
            shared: self.shared.clone(),
            previous: Arc::new(Mutex::new(None)),
            _parent_credit: self.cell._credit.clone(),
            _credit: credit,
        }))
    }
}

fn encode_unary_local(
    data: &mut Resident,
    context: &ExportContext,
    cell: &CellRef,
) -> std::result::Result<(), tonic::Status> {
    use hyper::body::Body as _;
    let request = data.unary_mut().take().ok_or_else(failed_status)?;
    let (parts, mut body) = request.into_parts();
    let waker = Waker::from(cell.cell.wake.clone());
    let mut cx = Context::from_waker(&waker);
    let mut encoded = None;
    loop {
        match Pin::new(&mut body).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let bytes = frame
                    .into_data()
                    .map_err(|_| tonic::Status::internal("unexpected unary request trailers"))?;
                if encoded.is_some() {
                    return Err(tonic::Status::internal(
                        "unexpected multiple unary DATA frames",
                    ));
                }
                encoded = Some(bytes);
            }
            Poll::Ready(Some(Err(status))) => return Err(status),
            Poll::Ready(None) => break,
            Poll::Pending => {
                return Err(tonic::Status::internal(
                    "unexpected pending local unary codec",
                ));
            }
        }
    }
    drop(body);
    let context = context.bound_to(cell).map_err(|_| failed_status())?;
    let memory = data.memory_ref().ok_or_else(failed_status)?.clone();
    let mut pin =
        std::pin::pin!(context.pin_bytes(ByteKind::Grpc, encoded.unwrap_or_default(), memory));
    let bytes = match pin.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(bytes)) => bytes,
        Poll::Ready(Err(_)) => return Err(failed_status()),
        Poll::Pending => {
            return Err(tonic::Status::internal(
                "unexpected pending completed unary body pin",
            ));
        }
    };
    *data.prepared_mut() = Some(http::Request::from_parts(
        parts,
        tonic::body::Body::new(http_body_util::Full::new(bytes)),
    ));
    Ok(())
}

fn apply_command(
    data: &mut Resident,
    reference: &CellRef,
    cpu: &crate::http_runtime::resource_budget::BlockingBudget,
    command: Command,
) -> std::result::Result<Step, WorkError> {
    match command {
        Command::Metrics(inputs) => {
            crate::metrics::export::apply_command(data.metric_mut()?, reference, cpu, inputs)
        }
        Command::Trace(command) => crate::metrics::distributed_trace::export_work::apply_command(
            data.trace_mut()?,
            reference,
            cpu,
            command,
        ),
        Command::Poll => {
            let waker = Waker::from(reference.cell.wake.clone());
            let mut cx = Context::from_waker(&waker);
            match data
                .future_mut()
                .as_mut()
                .ok_or(WorkError::Stopped)?
                .as_mut()
                .poll(&mut cx)
            {
                Poll::Pending => Ok(Step::Pending),
                Poll::Ready(result) => {
                    let success = result.is_ok();
                    drop(result);
                    data.clear_completed();
                    Ok(Step::Complete(success))
                }
            }
        }
    }
}

impl std::fmt::Debug for ControlCredit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Trace(_) => "TraceControlCredit",
            Self::Metrics(_) => "MetricsControlCredit",
        })
    }
}
