//! One bounded request/response bridge to the actual async request-body owner.
//! The renderer never owns a second body or waits for an entire upload for Read.
use super::super::{Control, RenderResult, arity, error};
use bytes::Bytes;
use gotmpl::{Object, Value, ValueFunc};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
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

/// Owned by the same async future that owns Context. Only an unconsumed piece
/// of a real DATA Bytes frame is retained. No new IO task or secondary stream.
pub(crate) struct Cursor {
    pending: Bytes,
    remaining: Option<u64>,
    source_end: bool,
    eof: bool,
    closed: bool,
    eager_eof: bool,
}
impl Cursor {
    pub(crate) fn new(body: &crate::http_runtime::Body, h1: bool) -> Self {
        Self {
            pending: Bytes::new(),
            remaining: body.size_hint().exact(),
            source_end: false,
            eof: body.is_end_stream(),
            closed: false,
            eager_eof: h1,
        }
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
                        self.pending = data;
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
            self.pending = Bytes::new();
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
            bytes.extend_from_slice(&self.pending.split_to(n));
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
                self.pending = Bytes::new();
                self.consume(n);
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
            bytes.extend_from_slice(&self.pending.split_to(n));
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
