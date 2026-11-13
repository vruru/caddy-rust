//! Concrete trace-export residence and CPU retirement. No user callback API.
use super::processor;
use anyhow::{Result, anyhow};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use tokio::sync::{Notify, Semaphore};
use tokio_util::task::task_tracker::TaskTrackerToken;

// Only the private trace Plan may construct the future/body variants. Pending
// output never transfers this data to an asynchronous caller.
#[derive(Default)]
pub(super) struct ResidentData {
    future: Option<Pin<Box<dyn Future<Output = Result<()>> + Send>>>,
    unary: Option<http::Request<tonic::body::Body>>,
    prepared: Option<http::Request<tonic::body::Body>>,
    console: Option<crate::metrics::console_writer::Batch>,
    items: Vec<processor::Item>,
    source_weight: usize,
    pending: Option<processor::Item>,
    ingress: Option<processor::Item>,
    receiver: Option<processor::Receiver>,
    result: Option<Result<()>>,
    encode_error: Option<tonic::Status>,
    backing: Option<Arc<Backing>>,
    owners: Vec<Arc<processor::Credit>>,
    batch_credit: Option<Arc<processor::Credit>>,
    future_credit: Option<Arc<processor::Credit>>,
    transport_credit: Option<Arc<crate::metrics::transport::Credit>>,
    memory: Option<Arc<crate::metrics::transport::BatchMemory>>,
}
impl ResidentData {
    fn is_empty(&self) -> bool {
        self.future.is_none()
            && self.unary.is_none()
            && self.prepared.is_none()
            && self.console.is_none()
            && self.items.capacity() == 0
            && self.pending.is_none()
            && self.ingress.is_none()
            && self.receiver.is_none()
            && self.result.is_none()
            && self.encode_error.is_none()
            && self.backing.is_none()
            && self.owners.capacity() == 0
            && self.batch_credit.is_none()
            && self.future_credit.is_none()
            && self.transport_credit.is_none()
            && self.memory.is_none()
    }
}

pub(super) struct WakeSignal {
    pub(super) notify: Notify,
    _credit: Arc<processor::Credit>,
}
impl Wake for WakeSignal {
    fn wake(self: Arc<Self>) {
        self.notify.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify.notify_one();
    }
}

struct State {
    data: ResidentData,
    polling: bool,
    retiring: bool,
    retire: bool,
    closed: bool,
    submitters: usize,
    epoch: u64,
    readers: usize,
    cpu_thread: Option<std::thread::ThreadId>,
    local_done: bool,
    local_failed: bool,
    token: Option<TaskTrackerToken>,
    next: Option<Arc<Cell>>,
}
struct Cell {
    state: Mutex<State>,
    wake: Arc<WakeSignal>,
    closed_notify: Notify,
    _credit: Arc<processor::Credit>,
}

/// Last external handle only signals. The registry remains the strong data owner.
pub(super) struct ActorCell {
    cell: Arc<Cell>,
    shared: WeakOwner,
}
#[derive(Clone)]
pub(super) struct CellRef {
    cell: Arc<Cell>,
    shared: WeakOwner,
}
pub(super) struct SubmitTicket {
    cell: Arc<Cell>,
    shared: WeakOwner,
    active: bool,
}
pub(super) struct ItemSummary {
    pub(super) weight: usize,
}
#[derive(Clone, Copy)]
pub(super) struct BatchSummary {
    pub(super) len: usize,
    pub(super) weight: usize,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum WorkError {
    Busy,
    Stopped,
    Worker,
    Workspace,
}
pub(super) enum Step {
    Started,
    Pending,
    Complete(bool),
    Console {
        writer: Arc<crate::metrics::console_writer::Writer>,
        deadline: tokio::time::Instant,
    },
}
pub(super) struct ExportInputs {
    pub(super) plan: Weak<super::export::Plan>,
    pub(super) metadata: Arc<crate::metrics::Metadata>,
    pub(super) scratch: tokio::sync::OwnedSemaphorePermit,
    pub(super) timer: tokio::sync::OwnedSemaphorePermit,
    pub(super) output: Arc<Semaphore>,
    pub(super) created: tokio::time::Instant,
}
enum Command {
    Begin(usize),
    Export(ExportInputs),
    Console {
        plan: Weak<super::export::Plan>,
        output: Arc<Semaphore>,
        serial: tokio::sync::OwnedSemaphorePermit,
    },
    Poll,
}
/// Cancelling a small waiter must request retirement independently of the
/// Provider's still-live external ActorCell handle.
pub(super) struct BatchGuard {
    reference: CellRef,
    active: bool,
    final_close: bool,
}
impl BatchGuard {
    pub(super) fn disarm(&mut self) {
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
pub(super) struct StoredSignal {
    cell: Arc<Cell>,
    shared: WeakOwner,
}
impl Drop for StoredSignal {
    fn drop(&mut self) {
        signal(&self.shared, &self.cell.wake);
    }
}
pub(super) struct PollGuard<'a> {
    data: Option<ResidentData>,
    cell: Arc<Cell>,
    shared: WeakOwner,
    _permit: &'a tokio::sync::OwnedSemaphorePermit,
}

impl ActorCell {
    /// Only the whole worker owns this guard. An undisarmed Drop means no
    /// future batch will consume overflow, so final close retires pending too.
    pub(super) fn worker_batch_guard(&self) -> BatchGuard {
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
    pub(super) fn promote_pending(&self) -> Option<ItemSummary> {
        let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed
            || state.retire
            || state.polling
            || state.retiring
            || state.data.ingress.is_some()
        {
            return None;
        }
        let item = state.data.pending.take()?;
        let summary = ItemSummary {
            weight: item.credit.held(),
        };
        state.data.ingress = Some(item);
        Some(summary)
    }
    pub(super) fn pending_count(&self) -> usize {
        usize::from(
            self.cell
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .data
                .pending
                .is_some(),
        )
    }
    pub(super) fn source_summary(&self) -> BatchSummary {
        let state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        BatchSummary {
            len: state.data.items.len(),
            weight: state.data.source_weight,
        }
    }
    /// Only ownership moves into an already-prepaid Vec occur here. No heap
    /// growth, large drop, formatting, callback or await under this fence.
    pub(super) fn append_ingress(
        &self,
        weight_limit: usize,
    ) -> std::result::Result<bool, WorkError> {
        let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.retire || state.polling || state.retiring {
            return Err(WorkError::Stopped);
        }
        let current = state.data.source_weight;
        let weight = state
            .data
            .ingress
            .as_ref()
            .ok_or(WorkError::Stopped)?
            .credit
            .held();
        if current
            .checked_add(weight)
            .is_none_or(|value| value > weight_limit)
        {
            debug_assert!(state.data.pending.is_none());
            state.data.pending = state.data.ingress.take();
            return Ok(false);
        }
        if state.data.items.len() == state.data.items.capacity() {
            return Err(WorkError::Busy);
        }
        let item = state.data.ingress.take().ok_or(WorkError::Stopped)?;
        state.data.items.push(item);
        state.data.source_weight = current + weight;
        Ok(true)
    }
    pub(super) async fn begin_source(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        count: usize,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(budget, Command::Begin(count)).await
    }
    pub(super) async fn begin_export(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        inputs: ExportInputs,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(budget, Command::Export(inputs)).await
    }
    pub(super) async fn begin_console(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        plan: Weak<super::export::Plan>,
        output: Arc<Semaphore>,
        serial: tokio::sync::OwnedSemaphorePermit,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(
            budget,
            Command::Console {
                plan,
                output,
                serial,
            },
        )
        .await
    }
    pub(super) async fn poll_export(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
    ) -> std::result::Result<Step, WorkError> {
        self.execute(budget, Command::Poll).await
    }
    async fn execute(
        &self,
        budget: &crate::http_runtime::resource_budget::BlockingBudget,
        command: Command,
    ) -> std::result::Result<Step, WorkError> {
        use crate::http_runtime::resource_budget::run_owned;
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
    pub(super) async fn wait_wake(&self, deadline: tokio::time::Instant) -> bool {
        tokio::time::timeout_at(deadline, self.cell.wake.notify.notified())
            .await
            .is_ok()
    }
    pub(super) async fn finish_batch(&self) {
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
    pub(super) fn trace_context(&self) -> Result<Arc<TraceContext>> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("trace retirement stopped"))?;
        let credit = shared.source.metadata(
            std::mem::size_of::<TraceContext>()
                + std::mem::size_of::<Mutex<Option<ByteReceipt>>>()
                + 6 * std::mem::size_of::<usize>(),
        )?;
        Ok(Arc::new(TraceContext {
            parent: Arc::downgrade(&self.cell),
            shared: self.shared.clone(),
            previous: Arc::new(Mutex::new(None)),
            _parent_credit: self.cell._credit.clone(),
            _credit: credit,
        }))
    }
    /// The async output is small. A dequeued Item cannot be suspended between
    /// Receiver::poll_recv and residence, including a concurrent close.
    pub(super) async fn receive(
        &self,
        input: &Arc<tokio::sync::Mutex<OwnedReceiver>>,
        try_only: bool,
    ) -> Result<Option<ItemSummary>> {
        let mut ticket = Some(self.ticket()?);
        // A dedicated close notification is never consumed by normal step
        // wakes. notify_waiters also covers a close between construction and
        // first poll without allocating a cancellation-token tree.
        let closed = self.cell.closed_notify.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        let mut input = Some(input.lock().await);
        std::future::poll_fn(|cx| {
            let globally_closed = self
                .shared
                .upgrade()
                .is_none_or(|shared| shared.closed.load(Ordering::Acquire));
            if globally_closed || closed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(anyhow!("trace source residence stopped")));
            }
            let next = if try_only {
                match input.as_mut().expect("resident input lock").receiver_mut() {
                    Some(receiver) => match receiver.inner.try_recv() {
                        Ok(item) => Poll::Ready(Some(item)),
                        Err(_) => Poll::Ready(None),
                    },
                    None => Poll::Ready(None),
                }
            } else {
                match input.as_mut().expect("resident input lock").receiver_mut() {
                    Some(receiver) => receiver.inner.poll_recv(cx),
                    None => Poll::Ready(None),
                }
            };
            match next {
                Poll::Ready(Some(item)) => {
                    let summary = ItemSummary {
                        weight: item.credit.held(),
                    };
                    let signal = ticket
                        .take()
                        .expect("one resident source receipt")
                        .store_quiet(item);
                    // The Item is resident before unlocking; signal only after
                    // releasing even the asynchronous receiver mutex.
                    drop(input.take());
                    drop(signal);
                    Poll::Ready(Ok(Some(summary)))
                }
                Poll::Ready(None) => Poll::Ready(Ok(None)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
    pub(super) fn ticket(&self) -> Result<SubmitTicket> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("trace retirement stopped"))?;
        {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if shared.closed.load(Ordering::Acquire)
                || state.closed
                || state.retire
                || state.retiring
                || state.polling
                || state.submitters != 0
                || state.readers != 0
                || state.data.ingress.is_some()
            {
                return Err(anyhow!("trace source residence unavailable"));
            }
            state.submitters = 1;
        }
        Ok(SubmitTicket {
            cell: self.cell.clone(),
            shared: self.shared.clone(),
            active: true,
        })
    }
    pub(super) fn cell_ref(&self) -> CellRef {
        CellRef {
            cell: self.cell.clone(),
            shared: self.shared.clone(),
        }
    }
    pub(super) fn attach_token(&self, token: TaskTrackerToken) -> Result<()> {
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
            Err(anyhow!("trace task residence stopped"))
        }
    }
    pub(super) fn retire(&self, final_close: bool) {
        self.cell_ref().retire(final_close);
    }
    pub(super) fn is_empty(&self) -> bool {
        let state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
        state.data.is_empty() && !state.polling && !state.retiring && state.submitters == 0
    }
    pub(super) fn epoch(&self) -> u64 {
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

impl SubmitTicket {
    /// Receiver polling must store a Ready item synchronously before returning.
    /// A pre-registered ticket still accepts its item after close, for retirement.
    pub(super) fn store(self, item: processor::Item) {
        drop(self.store_quiet(item));
    }
    fn store_quiet(mut self, item: processor::Item) -> StoredSignal {
        {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            // There is exactly one ticket, ingress was empty at admission and
            // poll/reap cannot take data while submitters != 0.
            debug_assert!(state.data.ingress.is_none());
            state.data.ingress = Some(item);
            state.submitters = 0;
            self.active = false;
        }
        StoredSignal {
            cell: self.cell.clone(),
            shared: self.shared.clone(),
        }
    }
    fn store_receiver(mut self, receiver: processor::Receiver) -> StoredSignal {
        {
            let mut state = self.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            debug_assert!(state.data.receiver.is_none());
            state.data.receiver = Some(receiver);
            state.submitters = 0;
            self.active = false;
        }
        StoredSignal {
            cell: self.cell.clone(),
            shared: self.shared.clone(),
        }
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
    pub(super) fn retire(&self, final_close: bool) {
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
    pub(super) fn claim_poll<'a>(
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
            std::mem::take(&mut state.data)
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
    pub(super) fn data_mut(&mut self) -> &mut ResidentData {
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

struct Shared {
    registry: Mutex<Option<Arc<Cell>>>,
    sequence: Mutex<u64>,
    condition: Condvar,
    closed: AtomicBool,
    running: Arc<Semaphore>,
    source: Arc<processor::Process>,
    done: tokio::sync::watch::Sender<bool>,
    _credit: Arc<processor::Credit>,
}
/// Weak capabilities carry the small control allocation's credit until the
/// actual Weak control-block reference is dropped. They never retain a batch.
#[derive(Clone)]
struct WeakOwner {
    shared: Weak<Shared>,
    _credit: Arc<processor::Credit>,
}
impl WeakOwner {
    fn new(shared: &Arc<Shared>) -> Self {
        Self {
            shared: Arc::downgrade(shared),
            _credit: shared._credit.clone(),
        }
    }
    fn upgrade(&self) -> Option<Arc<Shared>> {
        self.shared.upgrade()
    }
}
impl Shared {
    fn new(
        source: Arc<processor::Process>,
        running: Arc<Semaphore>,
        credit: Arc<processor::Credit>,
    ) -> Self {
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
            .ok_or_else(|| anyhow!("trace cell layout overflow"))?;
        let credit = self.source.metadata(bytes)?;
        let wake_credit = self
            .source
            .metadata(std::mem::size_of::<WakeSignal>() + 2 * std::mem::size_of::<usize>())?;
        let cell = Arc::new(Cell {
            state: Mutex::new(State {
                data: ResidentData::default(),
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
            return Err(anyhow!("trace retirement stopped"));
        }
        Ok(Arc::new(ActorCell {
            cell,
            shared: WeakOwner::new(self),
        }))
    }
    fn candidate(&self) -> Option<(Arc<Cell>, ResidentData)> {
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
                    let mut data = std::mem::take(&mut state.data);
                    // The overflow source item belongs to the next batch, just
                    // as in the original actor. Only final close discards it.
                    if !state.closed {
                        state.data.pending = data.pending.take();
                    }
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
            Poll::Ready(Err(_)) => unreachable!("trace running semaphore is never closed"),
            Poll::Pending => std::thread::park(),
        }
    }
}

struct JoinState {
    handle: Option<std::thread::JoinHandle<()>>,
    stack: Option<Arc<processor::Credit>>,
    joining: bool,
    result: Option<bool>,
    _credit: Arc<processor::Credit>,
}
struct JoinJob {
    handle: Option<std::thread::JoinHandle<()>>,
    stack: Option<Arc<processor::Credit>>,
    state: Arc<Mutex<JoinState>>,
    changed: Arc<Notify>,
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
pub(crate) struct TraceRetirementOwner {
    shared: Arc<Shared>,
    join: Arc<Mutex<JoinState>>,
    changed: Arc<Notify>,
    _credit: Arc<processor::Credit>,
}
impl TraceRetirementOwner {
    pub(crate) fn new(source: Arc<processor::Process>, running: Arc<Semaphore>) -> Result<Self> {
        const STACK: usize = 2 << 20;
        let control = std::mem::size_of::<Shared>()
            .checked_add(std::mem::size_of::<Self>())
            .and_then(|n| n.checked_add(std::mem::size_of::<JoinState>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<JoinJob>()))
            .and_then(|n| n.checked_add(16384))
            .ok_or_else(|| anyhow!("trace retirement control layout overflow"))?;
        let credit = source.metadata(control)?;
        let stack_credit = source.metadata(STACK + 8192)?;
        let shared = Arc::new(Shared::new(source, running, credit.clone()));
        let thread_shared = shared.clone();
        let thread_credit = stack_credit.clone();
        // Starting this thread is a prepare operation, before accepting data.
        let thread = std::thread::Builder::new()
            .name("trace-retirement".into())
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
    pub(super) fn register(&self) -> Result<Arc<ActorCell>> {
        self.shared.register()
    }
    pub(super) fn receiver_slot(&self) -> Result<ReceiverSlot> {
        let cell = self.register()?;
        let ticket = cell.ticket()?;
        let layout = std::mem::size_of::<OwnedReceiver>()
            .checked_add(std::mem::size_of::<tokio::sync::Mutex<OwnedReceiver>>())
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<ReceiverSlot>() + 6 * std::mem::size_of::<usize>(),
                )
            })
            .ok_or_else(|| anyhow!("trace receiver owner layout overflow"))?;
        let credit = self.shared.source.metadata(layout)?;
        // The admitted ticket keeps this closed disposal cell pinned, including
        // when the external Process owner closes before the receiver is dropped.
        cell.retire(true);
        Ok(ReceiverSlot {
            ticket: Some(ticket),
            credit,
        })
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
                .map_err(|_| anyhow!("trace retirement completion unavailable"))?;
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow!("trace retirement join requires an active executor"))?;
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
                        Err(anyhow!("trace retirement thread failed"))
                    };
                }
                if state.joining {
                    None
                } else {
                    let handle = state
                        .handle
                        .take()
                        .ok_or_else(|| anyhow!("trace retirement join handle unavailable"))?;
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
                    .map_err(|_| anyhow!("trace retirement join executor unavailable"))?;
            } else {
                changed.await;
            }
        }
    }
}
impl Drop for TraceRetirementOwner {
    fn drop(&mut self) {
        // No-runtime abandonment does not pretend to perform an async join.
        // The existing thread retains its stack credit through function exit;
        // only explicit shutdown retains the external share through OS join.
        self.close();
    }
}

pub(super) struct ReceiverSlot {
    ticket: Option<SubmitTicket>,
    credit: Arc<processor::Credit>,
}
impl ReceiverSlot {
    pub(super) fn wrap(mut self, receiver: processor::Receiver) -> OwnedReceiver {
        OwnedReceiver {
            inner: Some(receiver),
            disposal: self.ticket.take(),
            _credit: self.credit.clone(),
        }
    }
}
pub(super) struct OwnedReceiver {
    inner: Option<processor::Receiver>,
    disposal: Option<SubmitTicket>,
    _credit: Arc<processor::Credit>,
}
impl OwnedReceiver {
    pub(super) fn receiver_mut(&mut self) -> Option<&mut processor::Receiver> {
        self.inner.as_mut()
    }
    /// Move the whole channel before waking. Callers drop the returned small
    /// signal after releasing the outer asynchronous receiver mutex.
    pub(super) fn retire_queue(&mut self) -> (usize, Option<StoredSignal>) {
        let Some(receiver) = self.inner.take() else {
            return (0, None);
        };
        let count = receiver.inner.len();
        let signal = self
            .disposal
            .take()
            .expect("registered receiver disposal ticket")
            .store_receiver(receiver);
        (count, Some(signal))
    }
}
impl Drop for OwnedReceiver {
    fn drop(&mut self) {
        let (_, signal) = self.retire_queue();
        drop(signal);
    }
}

/// Immutable storage has no Plan, Driver, Process or external owner edge.
struct Backing {
    data: bytes::Bytes,
    _output: Option<tokio::sync::OwnedSemaphorePermit>,
    _memory: Arc<crate::metrics::transport::BatchMemory>,
    _credit: Arc<processor::Credit>,
}
struct ReaderLease {
    backing: Option<Arc<Backing>>,
    cell: Weak<Cell>,
    shared: WeakOwner,
    // The from_owner allocation and Weak control blocks remain paid until the
    // last actual Bytes owner is destroyed, rather than just reader0.
    _cell_credit: Arc<processor::Credit>,
    _credit: Arc<processor::Credit>,
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
struct ByteReceipt {
    cell: Weak<Cell>,
    _credit: Arc<processor::Credit>,
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
                    && state.data.backing.is_none()
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
pub(crate) struct TraceContext {
    parent: Weak<Cell>,
    shared: WeakOwner,
    previous: Arc<Mutex<Option<ByteReceipt>>>,
    _parent_credit: Arc<processor::Credit>,
    _credit: Arc<processor::Credit>,
}
#[derive(Clone, Copy)]
pub(crate) enum ByteKind {
    Http,
    Grpc,
    Console,
}
/// Whole-struct capture preserves data-before-output/memory destruction even
/// when a queued console handoff future is cancelled before its first poll.
struct PinInput {
    data: bytes::Bytes,
    output: Option<tokio::sync::OwnedSemaphorePermit>,
    memory: Arc<crate::metrics::transport::BatchMemory>,
}
impl TraceContext {
    fn bound_to(&self, cell: &CellRef) -> Result<Arc<Self>> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("trace retirement stopped"))?;
        let credit = shared
            .source
            .metadata(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())?;
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
        memory: Arc<crate::metrics::transport::BatchMemory>,
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
    async fn pin_input(&self, kind: ByteKind, input: PinInput) -> Result<bytes::Bytes> {
        anyhow::ensure!(self.on_cpu(), "trace byte handoff outside its CPU poll");
        let limit = match kind {
            ByteKind::Http => 32 << 20,
            ByteKind::Grpc => (32 << 20) + 5,
            ByteKind::Console => 64 << 20,
        };
        anyhow::ensure!(
            input.data.len() <= limit,
            "trace encoded body exceeds its existing limit"
        );
        anyhow::ensure!(
            self.finish_body_if_idle().await,
            "previous trace DATA remains owned"
        );
        // A poll can migrate to another real CPU worker after the await.
        anyhow::ensure!(
            self.on_cpu(),
            "trace byte handoff resumed outside its CPU poll"
        );
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("trace retirement stopped"))?;
        let child = shared.register()?;
        let mut ticket = child.ticket()?;
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
            .ok_or_else(|| anyhow!("trace byte ownership layout overflow"))?;
        let credit = shared.source.metadata(layout)?;
        let backing = Arc::new(Backing {
            data: input.data,
            _output: input.output,
            _memory: input.memory,
            _credit: credit.clone(),
        });
        {
            let mut state = child.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            debug_assert!(state.data.backing.is_none() && state.submitters == 1);
            state.data.backing = Some(backing.clone());
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
        memory: Arc<crate::metrics::transport::BatchMemory>,
        budget: crate::http_runtime::resource_budget::BlockingBudget,
    ) -> std::result::Result<http::Request<tonic::body::Body>, tonic::Status> {
        use crate::http_runtime::resource_budget::run_owned;
        let failed = || tonic::Status::resource_exhausted("trace unary preparation unavailable");
        if !self.on_cpu() {
            return Err(tonic::Status::internal(
                "trace unary handoff outside CPU poll",
            ));
        }
        if !self.finish_body_if_idle().await {
            return Err(tonic::Status::resource_exhausted(
                "previous trace DATA remains owned",
            ));
        }
        let shared = self.shared.upgrade().ok_or_else(failed)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| failed())?;
        let child = shared.register().map_err(|_| failed())?;
        let mut ticket = child.ticket().map_err(|_| failed())?;
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
            state.data.unary = Some(request);
            state.data.memory = Some(memory);
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
                                guard.data_mut().encode_error = Some(status);
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
                "trace unary result outside CPU poll",
            ));
        }
        let (mut data, failed) = {
            let mut state = child.cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.polling || state.retiring || state.retire || state.closed {
                return Err(tonic::Status::cancelled("trace unary preparation stopped"));
            }
            (std::mem::take(&mut state.data), state.local_failed)
        };
        let result = if let Some(status) = data.encode_error.take() {
            Err(status)
        } else if failed {
            Err(failed_status())
        } else {
            data.prepared.take().ok_or_else(failed_status)
        };
        // The outer poll already holds the same CPU capacity. Clear temporary
        // encoder credit before any original gRPC strong-count retry check.
        drop(data);
        child.retire(true);
        result
    }
}

fn failed_status() -> tonic::Status {
    tonic::Status::resource_exhausted("trace unary encoding worker unavailable")
}

fn apply_command(
    data: &mut ResidentData,
    reference: &CellRef,
    cpu: &crate::http_runtime::resource_budget::BlockingBudget,
    command: Command,
) -> std::result::Result<Step, WorkError> {
    match command {
        Command::Begin(count) => {
            let shared = reference.shared.upgrade().ok_or(WorkError::Stopped)?;
            let bytes = count
                .checked_mul(std::mem::size_of::<processor::Item>() * 2 + 128)
                .and_then(|n| n.checked_add(4096))
                .ok_or(WorkError::Busy)?;
            data.batch_credit = Some(shared.source.metadata(bytes).map_err(|_| WorkError::Busy)?);
            data.items
                .try_reserve_exact(count)
                .map_err(|_| WorkError::Busy)?;
            let first = data.ingress.take().ok_or(WorkError::Stopped)?;
            data.source_weight = first.credit.held();
            data.items.push(first);
            Ok(Step::Started)
        }
        Command::Export(inputs) => {
            let shared = reference.shared.upgrade().ok_or(WorkError::Stopped)?;
            let plan = inputs.plan.upgrade().ok_or(WorkError::Stopped)?;
            let credit = Arc::new(
                crate::metrics::transport::Credit::trace(
                    inputs.scratch,
                    inputs.metadata,
                    inputs.timer,
                    &shared.source,
                    inputs.created,
                )
                .map_err(|_| WorkError::Busy)?,
            );
            data.memory = Some(credit.memory().map_err(|_| WorkError::Busy)?);
            if let Some(writer) = plan.console() {
                data.transport_credit = Some(credit);
                return Ok(Step::Console {
                    writer,
                    deadline: inputs
                        .created
                        .checked_add(plan.timeout)
                        .ok_or(WorkError::Busy)?,
                });
            }
            let context = reference.context().map_err(|_| WorkError::Busy)?;
            let (spans, parents, children) = take_spans(data)?;
            drop(parents);
            drop(children);
            let cpu = cpu.clone();
            let future = async move { plan.export_with_context(spans, credit, context, cpu).await };
            install_future(data, &shared.source, future)?;
            Ok(Step::Started)
        }
        Command::Console {
            plan,
            output,
            serial,
        } => {
            let shared = reference.shared.upgrade().ok_or(WorkError::Stopped)?;
            let plan = plan.upgrade().ok_or(WorkError::Stopped)?;
            let writer = plan.console().ok_or(WorkError::Stopped)?;
            let context = reference.context().map_err(|_| WorkError::Busy)?;
            let credit = data.transport_credit.take().ok_or(WorkError::Stopped)?;
            let memory = data.memory.as_ref().ok_or(WorkError::Stopped)?.clone();
            let output = output
                .try_acquire_many_owned(64 << 20)
                .map_err(|_| WorkError::Busy)?;
            let (spans, parents, children) = take_spans(data)?;
            let bytes = super::console::encode(&spans, &parents, &children, plan.resource())
                .map_err(|_| WorkError::Busy)?;
            drop(spans);
            drop(parents);
            drop(children);
            let timeout = plan.timeout;
            let input = PinInput {
                data: bytes.into(),
                output: Some(output),
                memory,
            };
            let future = async move {
                let bytes = context.pin_input(ByteKind::Console, input).await?;
                writer
                    .send(
                        crate::metrics::console_writer::Batch {
                            bytes,
                            output: None,
                            credit,
                            serial,
                        },
                        timeout,
                    )
                    .await
            };
            install_future(data, &shared.source, future)?;
            Ok(Step::Started)
        }
        Command::Poll => {
            let waker = Waker::from(reference.cell.wake.clone());
            let mut cx = Context::from_waker(&waker);
            let future = data.future.as_mut().ok_or(WorkError::Stopped)?;
            match future.as_mut().poll(&mut cx) {
                Poll::Pending => Ok(Step::Pending),
                Poll::Ready(result) => {
                    let success = result.is_ok();
                    drop(result);
                    // All actual SDK future / source containers retire before
                    // their workspace, metadata and source owner credits.
                    drop(data.future.take());
                    drop(std::mem::take(&mut data.items));
                    drop(std::mem::take(&mut data.owners));
                    drop(data.future_credit.take());
                    drop(data.batch_credit.take());
                    drop(data.transport_credit.take());
                    drop(data.memory.take());
                    Ok(Step::Complete(success))
                }
            }
        }
    }
}

fn take_spans(
    data: &mut ResidentData,
) -> std::result::Result<
    (
        Vec<opentelemetry_sdk::trace::SpanData>,
        Vec<opentelemetry::trace::SpanContext>,
        Vec<u64>,
    ),
    WorkError,
> {
    let count = data.items.len();
    let mut spans = Vec::new();
    let mut parents = Vec::new();
    let mut children = Vec::new();
    spans
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    parents
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    children
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    data.owners
        .try_reserve_exact(count)
        .map_err(|_| WorkError::Busy)?;
    for item in std::mem::take(&mut data.items) {
        spans.push(item.span);
        parents.push(item.parent);
        children.push(item.children);
        data.owners.push(item.credit);
    }
    Ok((spans, parents, children))
}

// Private constructors above are the only callers; this does not expose a
// generic future scheduler or user callback surface.
fn install_future<F: Future<Output = Result<()>> + Send + 'static>(
    data: &mut ResidentData,
    source: &Arc<processor::Process>,
    future: F,
) -> std::result::Result<(), WorkError> {
    let layout = std::mem::size_of_val(&future)
        .checked_add(std::mem::size_of::<processor::Credit>() + 6 * std::mem::size_of::<usize>())
        .ok_or(WorkError::Busy)?;
    data.future_credit = Some(source.metadata(layout).map_err(|_| WorkError::Busy)?);
    data.future = Some(Box::pin(future));
    Ok(())
}

impl CellRef {
    fn context(&self) -> Result<Arc<TraceContext>> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow!("trace retirement stopped"))?;
        let credit = shared.source.metadata(
            std::mem::size_of::<TraceContext>()
                + std::mem::size_of::<Mutex<Option<ByteReceipt>>>()
                + 6 * std::mem::size_of::<usize>(),
        )?;
        Ok(Arc::new(TraceContext {
            parent: Arc::downgrade(&self.cell),
            shared: self.shared.clone(),
            previous: Arc::new(Mutex::new(None)),
            _parent_credit: self.cell._credit.clone(),
            _credit: credit,
        }))
    }
}

fn encode_unary_local(
    data: &mut ResidentData,
    context: &TraceContext,
    cell: &CellRef,
) -> std::result::Result<(), tonic::Status> {
    use hyper::body::Body as _;
    let request = data.unary.take().ok_or_else(failed_status)?;
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
    let memory = data.memory.as_ref().ok_or_else(failed_status)?.clone();
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
    data.prepared = Some(http::Request::from_parts(
        parts,
        tonic::body::Body::new(http_body_util::Full::new(bytes)),
    ));
    Ok(())
}
