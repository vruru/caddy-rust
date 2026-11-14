//! One bounded request/response bridge to the actual async request-body owner.
//! The renderer never owns a second body or waits for an entire upload for Read.
use super::super::{Control, RenderResult, arity, error};
use bytes::Bytes;
use gotmpl::{Object, Value, ValueFunc};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
};
use tokio::sync::{mpsc, oneshot};

pub(crate) enum Operation {
    All,
    Read(usize),
    Close,
}
pub(crate) struct Request {
    pub operation: Operation,
    pub reply: oneshot::Sender<RenderResult<BodyRead>>,
}
pub(crate) enum BodyRead {
    Bytes(Vec<u8>, bool),
    Io(String),
    TooLarge,
}
#[derive(Default)]
pub(crate) struct Reader {
    sender: OnceLock<mpsc::Sender<Request>>,
}
impl Reader {
    pub(crate) fn attach(&self, control: &Arc<Control>) -> RenderResult<mpsc::Receiver<Request>> {
        control.reserve_host_bytes(4096)?;
        let (sender, receiver) = mpsc::channel(1);
        self.sender
            .set(sender)
            .map_err(|_| error("template body owner was already attached"))?;
        Ok(receiver)
    }
    pub(crate) fn request(
        &self,
        operation: Operation,
        control: &Arc<Control>,
    ) -> RenderResult<BodyRead> {
        control.reserve_host_bytes(256)?;
        let sender = self
            .sender
            .get()
            .ok_or_else(|| error("template body owner was not attached"))?;
        let (reply, receiver) = oneshot::channel();
        sender
            .blocking_send(Request { operation, reply })
            .map_err(|_| error("template body owner retired"))?;
        receiver
            .blocking_recv()
            .map_err(|_| error("template body owner retired"))?
    }
}

/// Borrow the current typed byte window. Writes use its existing COW cell, so
/// aliases see mutations but the original certificate/host backing is immutable.
pub(crate) struct ByteBuffer<'a> {
    slice: Option<&'a gotmpl::TypedSlice>,
}
impl<'a> ByteBuffer<'a> {
    pub(crate) fn new(value: &'a Value) -> RenderResult<Self> {
        match value {
            Value::Nil | Value::NilError => Ok(Self { slice: None }),
            Value::Slice(slice) if slice.byte_backing_len().is_some() => {
                Ok(Self { slice: Some(slice) })
            }
            _ => Err(error("expected []uint8 buffer")),
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.slice.map_or(0, |s| s.len())
    }
    pub(crate) fn prepay(&self, control: &Arc<Control>, copied: bool) -> RenderResult<()> {
        let backing = self.slice.and_then(|s| s.byte_backing_len()).unwrap_or(0);
        let bytes = backing
            .checked_mul(2)
            .and_then(|n| n.checked_add(if copied { self.len() } else { 0 }))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| error("reader buffer allocation overflow"))?;
        control.reserve_host_bytes(bytes)
    }
    pub(crate) fn write(&self, bytes: &[u8]) -> RenderResult<usize> {
        match self.slice {
            Some(slice) => slice.write_range(0, bytes),
            None if bytes.is_empty() => Ok(0),
            _ => Err(error("nil reader buffer")),
        }
    }
}

pub(crate) fn value(form: &Arc<super::Form>, control: &Arc<Control>) -> RenderResult<Value> {
    control.reserve_host_bytes(2048)?;
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    for name in ["Read", "Close"] {
        let form = form.clone();
        let control = Arc::downgrade(control);
        methods.insert(
            name.into(),
            Arc::new(move |args: &[Value]| {
                let control = control
                    .upgrade()
                    .ok_or_else(|| error("template body control retired"))?;
                control.charge(1)?;
                if name == "Close" {
                    arity(args, 0, 0)?;
                    return match form.reader.request(Operation::Close, &control)? {
                        BodyRead::Bytes(_, _) => Ok(Value::NilError),
                        BodyRead::Io(message) => Err(error(message)),
                        BodyRead::TooLarge => Err(error("template body close failed")),
                    };
                }
                arity(args, 1, 1)?;
                let buffer = ByteBuffer::new(&args[0])?;
                // Both the reply copy and any COW backing allocation are paid
                // before asking the async owner to consume a byte.
                buffer.prepay(&control, true)?;
                match form
                    .reader
                    .request(Operation::Read(buffer.len()), &control)?
                {
                    BodyRead::Bytes(bytes, eof) => {
                        let n = buffer.write(&bytes)?;
                        if eof {
                            Err(error("EOF"))
                        } else {
                            Ok(Value::Int(n as i64))
                        }
                    }
                    BodyRead::Io(message) => Err(error(message)),
                    BodyRead::TooLarge => Err(error("template body read exceeded its limit")),
                }
            }),
        );
    }
    Ok(Value::Object(Arc::new(Object {
        go_type: Some("*http.body"),
        pointer_identity: Some(Arc::as_ptr(form) as usize),
        methods,
        method_signatures: BTreeMap::from([(
            "Read".into(),
            gotmpl::Signature::new(vec![gotmpl::ArgKind::Any], None),
        )]),
        ..Object::default()
    })))
}

/// The unread DATA prefix belongs to the actual Body, independently of the
/// render future. A failed/cancelled renderer never has to restore this prefix.
/// Each render installs one owner (not one per Read/frame). A later render may
/// wrap the existing Body; unlike a request extension this cannot accidentally
/// attach a parent's prefix to a replacement or virtual request Body.
struct Pending(Mutex<Bytes>);
impl Pending {
    fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn put(&self, bytes: Bytes) {
        let old = std::mem::replace(
            &mut *self.0.lock().unwrap_or_else(|p| p.into_inner()),
            bytes,
        );
        drop(old);
    }
    fn take(&self) -> Bytes {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }
    fn copy_into(&self, out: &mut Vec<u8>, n: usize) {
        let consumed = {
            let mut bytes = self.0.lock().unwrap_or_else(|p| p.into_inner());
            // The destination capacity and CPU budget were admitted first.
            out.extend_from_slice(&bytes[..n]);
            bytes.split_to(n)
        };
        drop(consumed);
    }
}
struct PrefixBody {
    // Actual source IO is retired before the shared unread DATA owner.
    inner: crate::http_runtime::Body,
    pending: Arc<Pending>,
}
impl hyper::body::Body for PrefixBody {
    type Data = Bytes;
    type Error = crate::http_runtime::BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let bytes = self.pending.take();
        if !bytes.is_empty() {
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.pending.is_empty() && self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        let n = self.pending.len() as u64;
        let source = self.inner.size_hint();
        let mut hint = hyper::body::SizeHint::new();
        hint.set_lower(source.lower().saturating_add(n));
        if let Some(upper) = source.upper().and_then(|upper| upper.checked_add(n)) {
            hint.set_upper(upper);
        }
        hint
    }
}

/// The cursor owns no unread bytes exclusively: PrefixBody remains in Context
/// through normal completion, template errors and cancellation alike.
pub(crate) struct Cursor {
    pending: Arc<Pending>,
    remaining: Option<u64>,
    source_end: bool,
    eof: bool,
    closed: bool,
    eager_eof: bool,
}
impl Cursor {
    pub(crate) fn new(
        body: &mut crate::http_runtime::Body,
        h1: bool,
        control: &Arc<Control>,
    ) -> RenderResult<Self> {
        // Arc/Mutex, erased wrapper and cursor metadata; frame payload retains
        // its original Bytes owner and is never copied by this wrapper.
        control.reserve_host_bytes(1024)?;
        let remaining = body.size_hint().exact();
        let eof = body.is_end_stream();
        let pending = Arc::new(Pending(Mutex::new(Bytes::new())));
        let inner = std::mem::replace(body, crate::http_runtime::full(Bytes::new()));
        *body = PrefixBody {
            inner,
            pending: pending.clone(),
        }
        .boxed_unsync();
        Ok(Self {
            pending,
            remaining,
            source_end: false,
            eof,
            closed: false,
            eager_eof: h1,
        })
    }
    fn consume(&mut self, n: usize) {
        if let Some(left) = &mut self.remaining {
            *left = left.saturating_sub(n as u64);
        }
        if self.pending.is_empty()
            && ((self.eager_eof && self.remaining == Some(0)) || self.source_end)
        {
            self.eof = true;
        }
    }
    async fn fill(&mut self, body: &mut crate::http_runtime::Body) -> Result<(), String> {
        while self.pending.is_empty() && !self.eof {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.source_end = body.is_end_stream();
                        // This follows the Ready frame in the same poll, before any
                        // fallible charge/allocation or another await.
                        self.pending.put(data);
                        if self.pending.is_empty() && self.source_end {
                            self.eof = true;
                        }
                    }
                }
                Some(Err(cause)) => {
                    return Err(
                        if crate::http_runtime::request_body::limit_error(cause.as_ref()) {
                            "http: request body too large".into()
                        } else {
                            cause.to_string()
                        },
                    );
                }
                None => {
                    self.eof = true;
                    if self.remaining.is_some_and(|n| n != 0) {
                        return Err("unexpected EOF".into());
                    }
                }
            }
        }
        Ok(())
    }
    async fn perform(
        &mut self,
        body: &mut crate::http_runtime::Body,
        control: &Arc<Control>,
        operation: Operation,
    ) -> RenderResult<BodyRead> {
        control.check()?;
        if matches!(operation, Operation::Close) {
            self.closed = true;
            drop(self.pending.take());
            // Retire the real read half here, on its original async owner.
            // Do not download an unbounded source merely to implement Close.
            let old = std::mem::replace(body, crate::http_runtime::full(Bytes::new()));
            drop(old);
            return Ok(BodyRead::Bytes(Vec::new(), false));
        }
        if self.closed {
            return Ok(BodyRead::Io("http: invalid Read on closed Body".into()));
        }
        if let Operation::Read(length) = operation {
            if self.eof && self.pending.is_empty() {
                return Ok(BodyRead::Bytes(Vec::new(), true));
            }
            if length == 0 {
                return Ok(BodyRead::Bytes(Vec::new(), false));
            }
            if let Err(message) = self.fill(body).await {
                return Ok(BodyRead::Io(message));
            }
            if self.pending.is_empty() {
                return Ok(BodyRead::Bytes(Vec::new(), true));
            }
            let n = length.min(self.pending.len());
            control.charge_bytes(n)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(n)
                .map_err(|_| error("template body read allocation failed"))?;
            self.pending.copy_into(&mut bytes, n);
            self.consume(n);
            // H1's declared-length body can return its last data with EOF.
            // H2/H3 buffered readers finish that read before the next EOF read.
            return Ok(BodyRead::Bytes(
                bytes,
                self.eager_eof && self.remaining == Some(0),
            ));
        }
        let mut bytes = Vec::new();
        loop {
            if let Err(message) = self.fill(body).await {
                return Ok(BodyRead::Io(message));
            }
            if self.pending.is_empty() {
                return Ok(BodyRead::Bytes(bytes, true));
            }
            let n = self.pending.len();
            control.charge_bytes(n)?;
            if n > crate::http_runtime::templates::BODY_LIMIT.saturating_sub(bytes.len()) {
                return Ok(BodyRead::TooLarge);
            }
            if bytes.capacity().saturating_sub(bytes.len()) < n {
                control.reserve_host_bytes(
                    bytes
                        .len()
                        .checked_add(n)
                        .and_then(|n| n.checked_add(128))
                        .ok_or_else(|| error("template form body allocation overflow"))?,
                )?;
                bytes
                    .try_reserve_exact(n)
                    .map_err(|_| error("template form body allocation failed"))?;
            }
            self.pending.copy_into(&mut bytes, n);
            self.consume(n);
        }
    }
    pub(crate) async fn respond(
        &mut self,
        body: &mut crate::http_runtime::Body,
        control: &Arc<Control>,
        operation: Operation,
    ) -> RenderResult<BodyRead> {
        tokio::select! {
            result = self.perform(body, control, operation) => result,
            _ = control.cancel.cancelled() => Err(error("template body read cancelled")),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(control.deadline())) => {
                control.cancel.cancel(); Err(error("template body read timed out"))
            }
        }
    }
}
