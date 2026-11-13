// continue_flow.rs

use hyper::ext::ResponseWriteControl as Control;
use native_write_policy::{Lease, Pool};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};

// ---------------------------------------------------------------------------
// Independent fixed metadata quota; it is not a CPU/throughput limit.
// ---------------------------------------------------------------------------

static POOL: OnceLock<Pool> = OnceLock::new();

fn get_pool() -> &'static Pool {
    POOL.get_or_init(|| Pool::new(2 * 1024 * 1024)) // 2 MiB
}

const CREDIT: usize = 1024;

// Fixed scalar allowance covers Flow/Arc, Incoming metadata, alignment, and
// 256 bytes mutex slack. It is not a bound on all channel/network allocations.
// Interpretation: Native waker registration causes no new heap allocation in this pool;
// the task itself is not counted against this pool's credit.
const _: () = assert!(
    CREDIT >= std::mem::size_of::<Flow>()
        + std::mem::size_of::<super::stream::Incoming>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::align_of::<Flow>()
        + std::mem::align_of::<super::stream::Incoming>()
        + 256,
    "CREDIT insufficient for Flow layout"
);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Unasked,
    Requested,
    Done,
    Failed,
}

#[derive(Debug)]
struct State {
    bound: Option<Control>,
    delivered: bool,
    expected: bool,
    status: Status,
    closed: bool,
    driver: Option<Waker>,
    read: Option<Waker>,
}

impl State {
    fn new() -> Self {
        Self {
            bound: None,
            delivered: false,
            expected: false,
            status: Status::Unasked,
            closed: false,
            driver: None,
            read: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

pub(super) struct Flow {
    state: Mutex<State>,
    _credit: Lease,
}

impl Flow {
    /// Reserve credit from the native pool before allocating the Arc<Flow>.
    /// Returns None if reservation fails (no spawn, no queue).
    pub(super) fn new() -> Option<Arc<Self>> {
        let pool = get_pool();
        let lease = pool.reserve(CREDIT).ok()?;
        // Reservation succeeded; now allocate.
        let flow = Arc::new(Flow {
            state: Mutex::new(State::new()),
            _credit: lease,
        });
        Some(flow)
    }

    /// Enable automatic continuation for a nonempty or unknown request body.
    pub(super) fn set_expected(&self, value: bool) {
        if value {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.expected = true;
        }
    }

    /// Bind a Control object.
    /// - Same identity (control.same_control) is idempotent.
    /// - Different control is rejected.
    /// - If closed, rejected.
    pub(super) fn bind(&self, control: Control) -> Result<(), &'static str> {
        let (result, wake) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed { (Err("HTTP/3 response stream closed"), None) }
            else if let Some(existing) = state.bound.as_ref() {
                (if existing.same_control(&control) { Ok(()) } else { Err("HTTP/3 write control changed") }, None)
            } else {
                state.bound = Some(control.clone());
                (Ok(()), state.driver.take())
            }
        };
        if let Some(waker) = wake { waker.wake(); }
        // The argument's possible retained destructor is outside the mutex.
        drop(control);
        result
    }

    pub(super) fn poll_event(&self, cx: &mut Context<'_>) -> Poll<Event> {
        let mut incoming = Some(cx.waker().clone());
        let (result, old) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let result = if state.closed { Poll::Pending }
                else if !state.delivered && state.bound.is_some() {
                    state.delivered = true;
                    Poll::Ready(Event::Bind(state.bound.as_ref().unwrap().clone()))
                } else if state.status == Status::Requested { Poll::Ready(Event::Continue) }
                else { Poll::Pending };
            let old = state.driver.take();
            if result.is_pending() && !state.closed { state.driver = incoming.take(); }
            (result, old)
        };
        drop(old);
        drop(incoming);
        result
    }

    /// Poll to continue the flow.
    ///
    /// Logic:
    /// 1. Clone incoming reader waker outside lock.
    /// 2. If !expected or status == Done: return Poll::Ready(Ok(())).
    /// 3. If closed or status == Failed: return Poll::Ready(Err(...)).
    /// 4. Else:
    ///    - If status == Unasked: change to Requested.
    ///    - Register reader waker.
    ///    - Take driver waker.
    ///    - Drop lock.
    ///    - Wake driver (outside lock).
    ///    - Return Poll::Pending.
    ///
    /// If Ready, the cloned waker (incoming reader) must be dropped outside lock.
    pub(super) fn poll_continue(&self, cx: &mut Context<'_>) -> Poll<Result<(), &'static str>> {
        let mut incoming = Some(cx.waker().clone());
        let (result, old, driver) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !state.expected || state.status == Status::Done { (Poll::Ready(Ok(())), None, None) }
            else if state.closed || state.status == Status::Failed { (Poll::Ready(Err("HTTP/3 continue stream closed")), None, None) }
            else {
                if state.status == Status::Unasked { state.status = Status::Requested; }
                let old = state.read.take(); state.read = incoming.take();
                (Poll::Pending, old, state.driver.take())
            }
        };
        drop(old);
        drop(incoming);
        if let Some(waker) = driver { waker.wake(); }
        result
    }

    pub(super) fn retire_reader(&self) {
        let (read, driver) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.status == Status::Requested { state.status = Status::Failed; }
            (state.read.take(), state.driver.take())
        };
        drop(read);
        if let Some(waker) = driver { waker.wake(); }
    }

    /// Mark the flow as continued.
    ///
    /// Inside lock:
    /// - Set status to Done.
    /// - Take reader waker.
    ///
    /// Outside lock:
    /// - Wake reader waker.
    pub(super) fn continued(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if !state.closed && state.status != Status::Failed { state.status = Status::Done; }
        let reader_waker = state.read.take();

        drop(state);

        if let Some(w) = reader_waker {
            w.wake();
        }
    }

    /// Check if the flow is considered continued.
    /// Returns true iff expected && status == Done.
    pub(super) fn is_continued(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.expected && state.status == Status::Done
    }

    /// Close the flow.
    ///
    /// Inside lock:
    /// - Mark closed.
    /// - If status is not Done, set to Failed.
    /// - Take both wakers (driver, read).
    /// - Take bound (Control).
    ///
    /// Outside lock:
    /// - Wake taken wakers.
    /// - Drop taken Control.
    pub(super) fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        state.closed = true;

        if state.status != Status::Done {
            state.status = Status::Failed;
        }

        let driver_waker = state.driver.take();
        let reader_waker = state.read.take();
        let bound = state.bound.take();

        drop(state);

        // Wake outside lock
        if let Some(w) = driver_waker {
            w.wake();
        }
        if let Some(w) = reader_waker {
            w.wake();
        }

        // Drop bound (Control) outside lock.
        // Control's foreign retained destruction must happen outside lock.
        drop(bound);
    }
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) enum Event {
    Bind(Control),
    Continue,
}
