use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use crate::body::Incoming;
use http::{Request, Response, StatusCode};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug)]
pub(crate) struct InformationalLimits {
    max_count: u16,
    max_header_bytes: usize,
}

impl InformationalLimits {
    pub(crate) fn new(max_count: u16, max_header_bytes: usize) -> Option<Self> {
        if max_count == 0 || max_header_bytes == 0 {
            None
        } else {
            Some(Self {
                max_count,
                max_header_bytes,
            })
        }
    }
}

/// A failure to submit or deliver an informational response.
#[derive(Debug, Clone, Copy)]
pub struct InformationalError(ErrorKind);

#[derive(Debug, Clone, Copy)]
enum ErrorKind {
    InvalidStatus,
    InvalidHeader,
    Closed,
    Busy,
    Limit,
}

impl InformationalError {
    /// Returns true if this request has exhausted an informational response limit.
    pub fn is_limit(&self) -> bool {
        matches!(self.0, ErrorKind::Limit)
    }
}

impl fmt::Display for InformationalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ErrorKind::InvalidStatus => "invalid informational response status",
            ErrorKind::InvalidHeader => "invalid informational response header",
            ErrorKind::Closed => "informational response is no longer writable",
            ErrorKind::Busy => "an informational response is already pending",
            ErrorKind::Limit => "informational response budget exhausted",
        })
    }
}

impl std::error::Error for InformationalError {}

const CLOSED: u8 = 1;
const TOUCHED: u8 = 2;

#[derive(Default)]
struct State {
    count: u16,
    bytes: usize,
    waker: Option<Waker>,
    pending: Option<InformationalHead>,
    write_control: Option<crate::ext::ResponseWriteControl>,
    write_control_delivered: bool,
}

struct Shared {
    flags: AtomicU8,
    state: Mutex<State>,
    limits: InformationalLimits,
    emit_interims: bool,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn touch(&self) -> bool {
        self.flags.fetch_or(TOUCHED, Ordering::AcqRel) & CLOSED == 0
    }

    fn closed(&self) -> bool {
        self.flags.load(Ordering::Acquire) & CLOSED != 0
    }
}

struct CancelPending<'a> {
    shared: &'a Shared,
    id: u16,
}

impl Drop for CancelPending<'_> {
    fn drop(&mut self) {
        let head = {
            let mut state = self.shared.state();
            if state.pending.as_ref().map(|head| head.id) == Some(self.id) {
                state.pending.take()
            } else {
                None
            }
        };
        drop(head);
    }
}

/// The single writer for interim HTTP responses of one server request.
pub struct InformationalSender(Arc<Shared>);

impl fmt::Debug for InformationalSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InformationalSender")
            .finish_non_exhaustive()
    }
}

impl InformationalSender {
    /// Claim the interim writer from the original incoming request body.
    /// Take it before replacing the body; each request has only one writer.
    pub fn take(request: &mut Request<Incoming>) -> Option<Self> {
        request.body_mut().take_informational()
    }

    /// Whether the peer protocol permits informational heads. A HTTP/1.0
    /// writer may still carry non-wire deadline metadata without sending 1xx.
    pub fn allows_informational(&self)->bool{self.0.emit_interims}

    /// Bind an existing response scope before an automatic 100 response is
    /// demanded by the first request-body read. This writes no headers and
    /// starts no pending-output clock. Rebinding a different scope is rejected.
    pub fn bind_write_control(&mut self,control:crate::ext::ResponseWriteControl)->Result<(),InformationalError>{
        if !self.0.touch(){return Err(InformationalError(ErrorKind::Closed))}
        let (result,waker)={
            let mut state=self.0.state();
            if self.0.closed(){(Err(InformationalError(ErrorKind::Closed)),None)}
            else if let Some(current)=&state.write_control {
                (if current.same_control(&control){Ok(())}else{Err(InformationalError(ErrorKind::Busy))},None)
            }else{state.write_control=Some(control.clone());(Ok(()),state.waker.take())}
        };
        if let Some(waker)=waker{waker.wake();}
        result
    }

    /// Write a 1xx response (excluding 101). HTTP/1 completes after IO flush;
    /// Controlled HTTP/2 completes after the actual header-block IO flush;
    /// ordinary HTTP/2 completes when the connection accepts the header frame.
    /// A duplicate 100 for the same Expect exchange may be suppressed.
    ///
    /// Dropping the future withdraws an unconsumed head. A head already taken
    /// by the protocol writer can still be sent. Submission uses budget even
    /// if a later cancellation withdraws it.
    pub async fn send(&mut self, response: Response<()>) -> Result<(), InformationalError> {
        if !response.status().is_informational()
            || response.status() == StatusCode::SWITCHING_PROTOCOLS
        {
            return Err(InformationalError(ErrorKind::InvalidStatus));
        }

        if !self.0.emit_interims{return Ok(())}

        let limit = InformationalError(ErrorKind::Limit);
        let mut bytes = 48usize; // status line and HTTP/2 pseudo-header overhead
        #[cfg(feature = "http1")]
        if let Some(phrase) = response.extensions().get::<crate::ext::ReasonPhrase>() {
            bytes = bytes.checked_add(phrase.as_bytes().len()).ok_or(limit)?;
        }
        for (name, value) in response.headers() {
            bytes = bytes
                .checked_add(name.as_str().len())
                .and_then(|n| n.checked_add(value.as_bytes().len()))
                .and_then(|n| n.checked_add(32))
                .filter(|n| *n <= self.0.limits.max_header_bytes)
                .ok_or(limit)?;
            // Typed safe values cannot contain these bytes, but a caller can
            // also construct HeaderValue through its unchecked API.
            if value.as_bytes().iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
                return Err(InformationalError(ErrorKind::InvalidHeader));
            }
        }

        if !self.0.touch() {
            return Err(InformationalError(ErrorKind::Closed));
        }
        let (ack, delivered) = oneshot::channel();
        let (id, waker) = {
            let mut state = self.0.state();
            if self.0.closed() {
                return Err(InformationalError(ErrorKind::Closed));
            }
            let id = state
                .count
                .checked_add(1)
                .filter(|count| *count <= self.0.limits.max_count)
                .ok_or(limit)?;
            let total = state
                .bytes
                .checked_add(bytes)
                .filter(|total| *total <= self.0.limits.max_header_bytes)
                .ok_or(limit)?;
            if state.pending.is_some() {
                return Err(InformationalError(ErrorKind::Busy));
            }
            state.count = id;
            state.bytes = total;
            state.pending = Some(InformationalHead { response, ack, id });
            // Keep the receiver's registration: an acknowledgment may
            // wake a different task holding the sender, which can submit
            // another head before the receiver has been polled again.
            (id, state.waker.clone())
        };
        let _pending = CancelPending {
            shared: &self.0,
            id,
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        delivered
            .await
            .map_err(|_| InformationalError(ErrorKind::Closed))
    }
}

pub(crate) struct InformationalHead {
    pub(crate) response: Response<()>,
    pub(crate) ack: oneshot::Sender<()>,
    id: u16,
}

pub(crate) struct InformationalReceiver(Arc<Shared>);

impl InformationalReceiver {
    pub(crate) fn poll_write_control(&mut self,cx:&mut Context<'_>)->Option<crate::ext::ResponseWriteControl>{
        if !self.0.touch(){return None}
        let incoming=cx.waker().clone();
        let (control,old)={
            let mut state=self.0.state();
            if self.0.closed(){(None,None)}else{
                let old=state.waker.replace(incoming);
                let control=if state.write_control_delivered{None}else{
                    let control=state.write_control.clone();
                    if control.is_some(){state.write_control_delivered=true;}
                    control
                };
                (control,old)
            }
        };
        drop(old);control
    }
    pub(crate) fn poll_take(&mut self, cx: &mut Context<'_>) -> Poll<InformationalHead> {
        if !self.0.touch() {
            return Poll::Pending;
        }
        let (head, old_waker) = {
            let mut state = self.0.state();
            if self.0.closed() {
                return Poll::Pending;
            }
            // Even the Ready path registers the protocol task. A cross-task
            // sender can be ready before the receiver's first poll.
            let old = if state
                .waker
                .as_ref()
                .map_or(false, |waker| waker.will_wake(cx.waker()))
            {
                None
            } else {
                state.waker.replace(cx.waker().clone())
            };
            (state.pending.take(), old)
        };
        drop(old_waker);
        head.map_or(Poll::Pending, Poll::Ready)
    }

    pub(crate) fn close_take(&mut self) -> Option<InformationalHead> {
        // Setting CLOSED first is the final-response publication point. Any
        // sender that could have filled the slot set TOUCHED before locking.
        // Ordinary immediately-ready requests do not acquire this mutex.
        let flags = self.0.flags.fetch_or(CLOSED, Ordering::AcqRel);
        if flags & CLOSED != 0 || flags & TOUCHED == 0 {
            return None;
        }
        let (pending, waker) = {
            let mut state = self.0.state();
            (state.pending.take(), state.waker.take())
        };
        drop(waker);
        pending
    }
}

impl Drop for InformationalReceiver {
    fn drop(&mut self) {
        drop(self.close_take());
    }
}

pub(crate) fn install(
    request: &mut Request<Incoming>,
    limits: InformationalLimits,
    recycled: Option<InformationalReceiver>,
) -> InformationalReceiver {
    let emit_interims=request.version()!=http::Version::HTTP_10;
    if let Some(mut previous) = recycled {
        if let Some(shared) = Arc::get_mut(&mut previous.0) {
            // Only a closed, completely unreferenced H1 request can reuse
            // storage. A detached writer cannot mutate the next request.
            debug_assert!(*shared.flags.get_mut() & CLOSED != 0);
            *shared = Shared {
                flags: AtomicU8::new(0),
                state: Mutex::new(State::default()),
                limits,
                emit_interims,
            };
            request
                .body_mut()
                .set_informational(InformationalSender(previous.0.clone()));
            return previous;
        }
    }
    let (sender,receiver)=channel(limits,emit_interims);
    request.body_mut().set_informational(sender);
    receiver
}

pub(crate) fn channel(limits:InformationalLimits,emit_interims:bool)->(InformationalSender,InformationalReceiver){
    let shared=Arc::new(Shared{flags:AtomicU8::new(0),state:Mutex::new(State::default()),limits,emit_interims});
    (InformationalSender(shared.clone()),InformationalReceiver(shared))
}
