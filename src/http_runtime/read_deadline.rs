//! Scoped pending-read deadlines. Each original body remains in its actual owner chain.
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use std::{future::Future, io, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll, Waker}, time::{Duration, Instant}};
use tokio::time::Sleep;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy)]
pub(crate) struct ReadPolicy {
    pub(crate) idle: Option<Duration>,
    pub(crate) minimum_rate: u64,
    pub(crate) installed: Instant,
    pub(crate) hard: Option<Instant>,
}
struct State { policy: ReadPolicy, generation: u64, bytes: u64, failed: bool, deadline_expired: bool, finished: bool, waiter: Option<Waker>, _credit: Option<native_write_policy::Lease> }
#[derive(Clone)]
pub(crate) struct SharedRead(Arc<Mutex<State>>);
#[derive(Clone, Copy)]
struct Snapshot { policy: ReadPolicy, generation: u64, bytes: u64 }
fn invalid() -> io::Error { io::Error::other("request read deadline state invalid or exhausted") }
fn expired() -> io::Error { io::Error::new(io::ErrorKind::TimedOut, "request read deadline exceeded") }

impl SharedRead {
    pub(crate) fn with_budget(policy: ReadPolicy, pool: &native_write_policy::Pool) -> io::Result<Self> {
        let bytes=std::mem::size_of::<Mutex<State>>()+2*std::mem::size_of::<usize>()+128;
        let credit=pool.reserve(bytes).map_err(io::Error::other)?;
        Ok(Self(Arc::new(Mutex::new(State {policy,generation:0,bytes:0,failed:false,deadline_expired:false,finished:false,waiter:None,_credit:Some(credit)}))))
    }
    pub(crate) fn disable(&self)->io::Result<()> {
        let (waiter,result)={
            let mut state=self.0.lock().map_err(|_|invalid())?;
            let result=if let Some(generation)=state.generation.checked_add(1){state.generation=generation;state.policy.idle=None;state.policy.minimum_rate=0;Ok(())}else{state.failed=true;Err(invalid())};
            (state.waiter.take(),result)
        };
        if let Some(waiter)=waiter{waiter.wake();}result
    }
    pub(crate) fn deadline_expired(&self)->bool {self.0.lock().map(|state|state.deadline_expired).unwrap_or(true)}
    pub(crate) fn finished(&self)->bool {self.0.lock().map(|state|state.finished).unwrap_or(false)}
    fn mark_deadline_expired(&self) {
        let waiter=if let Ok(mut state)=self.0.lock(){state.failed=true;state.deadline_expired=true;state.waiter.take()}else{None};
        if let Some(waiter)=waiter {waiter.wake();}
    }
    fn mark_finished(&self) {
        let waiter=if let Ok(mut state)=self.0.lock(){state.finished=true;state.waiter.take()}else{None};
        drop(waiter);
    }
    fn snapshot(&self, cx: &Context<'_>) -> io::Result<Snapshot> {
        let incoming = cx.waker().clone();
        let (old, result) = {
            let mut state = self.0.lock().map_err(|_| invalid())?;
            let result = if state.failed { Err(invalid()) } else {
                Ok(Snapshot { policy: state.policy, generation: state.generation, bytes: state.bytes })
            };
            (state.waiter.replace(incoming), result)
        };
        drop(old); result
    }
    fn progress(&self, bytes: usize) -> io::Result<()> {
        let mut state = self.0.lock().map_err(|_| invalid())?;
        if state.failed { return Err(invalid()); }
        let next = u64::try_from(bytes).ok().and_then(|bytes| state.bytes.checked_add(bytes));
        if let Some(next) = next { state.bytes = next; Ok(()) }
        else { state.failed = true; Err(invalid()) }
    }
    fn retire_waiter(&self) {
        let waiter = self.0.lock().ok().and_then(|mut state| state.waiter.take());
        drop(waiter);
    }
}

fn deadline(snapshot: Snapshot, operation: Instant) -> io::Result<Option<Instant>> {
    let ReadPolicy { idle, minimum_rate, installed, hard } = snapshot.policy;
    let Some(idle) = idle.filter(|duration| !duration.is_zero()) else { return Ok(hard); };
    let candidate = if minimum_rate == 0 {
        operation.checked_add(idle).ok_or_else(invalid)?
    } else {
        let nanos = u128::from(snapshot.bytes).checked_mul(1_000_000_000).ok_or_else(invalid)? / u128::from(minimum_rate);
        let seconds = u64::try_from(nanos / 1_000_000_000).map_err(|_| invalid())?;
        let duration = Duration::new(seconds, (nanos % 1_000_000_000) as u32);
        installed.checked_add(idle).and_then(|at| at.checked_add(duration)).ok_or_else(invalid)?
    };
    Ok(Some(hard.map_or(candidate, |hard| candidate.min(hard))))
}

pub(crate) struct ReadBody<B> {
    inner: Pin<Box<B>>, shared: SharedRead,
    timer: Option<Pin<Box<Sleep>>>, generation: Option<u64>,
    operation: Option<Instant>, done: bool,
    _credit: Option<native_write_policy::Lease>,
}
impl<B> ReadBody<B> {
    pub(crate) fn with_budget(inner:B,shared:SharedRead,pool:&native_write_policy::Pool)->io::Result<Self> {
        let bytes=std::mem::size_of::<B>().checked_add(std::mem::size_of::<Self>()).and_then(|n|n.checked_add(std::mem::size_of::<Sleep>())).and_then(|n|n.checked_add(256)).ok_or_else(invalid)?;
        let credit=pool.reserve(bytes).map_err(io::Error::other)?;
        Ok(Self{inner:Box::pin(inner),shared,timer:None,generation:None,operation:None,done:false,_credit:Some(credit)})
    }
    fn terminal(&mut self) { self.done = true; self.timer = None; self.operation = None; self.shared.mark_finished(); }
    fn fail(&mut self, error: impl Into<BoxError>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.terminal(); Poll::Ready(Some(Err(error.into())))
    }
    fn wait(&mut self, at: Option<Instant>, cx: &mut Context<'_>) -> bool {
        if self.timer.is_none() && let Some(at) = at {
            self.timer = Some(Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(at))));
        }
        self.timer.as_mut().is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
    }
}
impl<B> Drop for ReadBody<B> { fn drop(&mut self) { self.shared.retire_waiter(); } }
impl<B> Body for ReadBody<B>
where B: Body<Data = Bytes>, B::Error: Into<BoxError> {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.done { return Poll::Ready(None); }
        let snapshot = match this.shared.snapshot(cx) { Ok(value) => value, Err(error) => return this.fail(error) };
        if this.generation != Some(snapshot.generation) {
            this.timer = None; this.operation = None; this.generation = Some(snapshot.generation);
        }
        let now = Instant::now();
        let operation = *this.operation.get_or_insert(now);
        let at = match deadline(snapshot, operation) { Ok(value) => value, Err(error) => return this.fail(error) };
        if at.is_some_and(|at| at <= now)
            || this.timer.as_mut().is_some_and(|timer| timer.as_mut().poll(cx).is_ready()) {
            this.shared.mark_deadline_expired(); return this.fail(expired());
        }
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                match frame.data_ref() {
                    Some(data) if !data.is_empty() => {
                        if let Err(error) = this.shared.progress(data.len()) { return this.fail(error); }
                        this.timer = None; this.operation = None;
                        // A content-length body can signal END_STREAM on its
                        // last DATA without a subsequent poll returning None.
                        // Preserve reuse after a fully consumed upload.
                        if this.inner.is_end_stream(){this.terminal();}
                    }
                    Some(_) => { if this.wait(at, cx) { this.shared.mark_deadline_expired(); return this.fail(expired()); } }
                    None => this.terminal(),
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => this.fail(error),
            Poll::Ready(None) => { this.terminal(); Poll::Ready(None) }
            Poll::Pending => {
                if this.wait(at, cx) { this.shared.mark_deadline_expired(); this.fail(expired()) } else { Poll::Pending }
            }
        }
    }
    fn is_end_stream(&self) -> bool { self.done || self.inner.is_end_stream() }
    fn size_hint(&self) -> SizeHint { if self.done { SizeHint::with_exact(0) } else { self.inner.size_hint() } }
}
