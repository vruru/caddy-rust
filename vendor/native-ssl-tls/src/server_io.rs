//! Async network owner for the complete SSL stepping engine. A write accepts
//! its bounded plaintext buffer before returning Ready, so cancellation never
//! confuses completion of an old CPU write with a different caller's bytes.
use crate::{
    VerificationScope,
    server_engine::{
        EncryptedInput, Operation, OwnedWrite, Progress, ServerEngine, Step, StepData,
    },
};
use futures_util::task::AtomicWaker;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::task::task_tracker::TaskTrackerToken;
const FRAME_LIMIT: usize = 2;
struct WakeBoth {
    read: AtomicWaker,
    write: AtomicWaker,
}
impl Wake for WakeBoth {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref()
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.read.wake();
        self.write.wake();
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Handshake,
    Read,
    Write,
    Shutdown,
}
struct Frame {
    data: StepData,
    wire: usize,
    plain: usize,
}
struct Job {
    kind: Kind,
    future: Pin<Box<dyn Future<Output = io::Result<Step>> + Send>>,
}
/// Only one owned SSL CPU step exists. Up to two separately prepaid output
/// frames permit reading peer records while the socket's write side blocks.
pub struct ServerStream<I> {
    io: I,
    admission: crate::server_engine::Admission,
    engine: Option<ServerEngine>,
    job: Option<Job>,
    frames: VecDeque<Frame>,
    returned: [Option<crate::server_engine::ReturnedCredit>; 2],
    encrypted: Option<EncryptedInput>,
    queued_write: Option<OwnedWrite>,
    write_wait: Option<Progress>,
    read_wait: Option<Progress>,
    handshake_wait: Option<Progress>,
    shutdown_wait: Option<Progress>,
    handshake_done: bool,
    shutdown_done: bool,
    read_closed: bool,
    failure: Option<Arc<io::Error>>,
    scope: Arc<VerificationScope>,
    wake: Arc<WakeBoth>,
    // First created admission, last destroyed data owner. Released at the actual
    // successful handshake handoff; established IO has per-step task ownership.
    entry: Option<TaskTrackerToken>,
}
impl<I: AsyncRead + AsyncWrite + Unpin> ServerStream<I> {
    /// Prepare the complete SSL object on the same bounded CPU lane, with an
    /// early admission covering construction and the subsequent handshake.
    /// The factory must not perform socket/file/provider-source IO.
    pub async fn prepare(
        io: I,
        scope: Arc<VerificationScope>,
        factory: impl FnOnce() -> io::Result<ServerEngine> + Send + 'static,
    ) -> io::Result<Self> {
        struct Preparing<I> {
            io: Option<I>,
            _entry: TaskTrackerToken,
        }
        let mut preparing = Preparing {
            io: Some(io),
            _entry: scope.enter()?,
        };
        let engine = scope.run(factory).await??;
        Self::accept(
            engine,
            preparing.io.take().expect("owned prepare IO"),
            scope,
        )
        .await
    }
    pub async fn accept(
        engine: ServerEngine,
        io: I,
        scope: Arc<VerificationScope>,
    ) -> io::Result<Self> {
        let entry = scope.enter()?;
        let admission = engine.admission();
        let mut frames = VecDeque::new();
        frames
            .try_reserve_exact(FRAME_LIMIT)
            .map_err(io::Error::other)?;
        let mut stream = Self {
            io,
            admission,
            engine: Some(engine),
            job: None,
            frames,
            returned: [None, None],
            encrypted: None,
            queued_write: None,
            write_wait: None,
            read_wait: None,
            handshake_wait: None,
            shutdown_wait: None,
            handshake_done: false,
            shutdown_done: false,
            read_closed: false,
            failure: None,
            scope,
            wake: Arc::new(WakeBoth {
                read: AtomicWaker::new(),
                write: AtomicWaker::new(),
            }),
            entry: Some(entry),
        };
        std::future::poll_fn(|cx| stream.poll_handshake(cx)).await?;
        drop(stream.entry.take());
        Ok(stream)
    }
    /// Available immediately after accept and while no CPU step owns the SSL.
    /// The HTTP owner captures its immutable facts before starting application IO.
    pub fn ssl(&self) -> Option<&openssl::ssl::SslRef> {
        self.engine.as_ref().map(ServerEngine::ssl)
    }
    /// Consume the stream while capturing owned facts on the bounded CPU lane.
    /// Network IO remains here; cancelling the future closes it while the real
    /// worker retains SSL and any unconsumed result until destruction.
    pub async fn inspect<T: Send + 'static>(
        mut self,
        operation: impl FnOnce(&openssl::ssl::SslRef) -> T + Send + 'static,
    ) -> io::Result<(Self, T)> {
        if self.job.is_some() || self.queued_write.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "SSL busy during fact capture",
            ));
        }
        let engine = self
            .engine
            .take()
            .ok_or_else(|| io::Error::other("SSL unavailable for facts"))?;
        let (engine, value) = self
            .scope
            .run(move || {
                engine
                    .ssl()
                    .is_init_finished()
                    .then_some(())
                    .ok_or_else(|| io::Error::other("SSL handshake incomplete"))?;
                if !engine.admitted() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SSL certificate withdrawn",
                    ));
                }
                let value = operation(engine.ssl());
                if !engine.admitted() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SSL certificate withdrawn",
                    ));
                }
                Ok::<_, io::Error>((engine, value))
            })
            .await??;
        self.engine = Some(engine);
        Ok((self, value))
    }
    pub fn get_ref(&self) -> &I {
        &self.io
    }
    fn error(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|e| io::Error::new(e.kind(), e.clone()))
    }
    fn fail(&mut self, error: io::Error) -> io::Error {
        let error = Arc::new(error);
        let out = io::Error::new(error.kind(), error.clone());
        self.failure.get_or_insert(error);
        out
    }
    fn admitted(&self) -> io::Result<()> {
        if (self.admission)() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSL certificate admission withdrawn",
            ))
        }
    }
    fn live(&self) -> io::Result<()> {
        self.admitted()?;
        if let Some(error) = self.error() {
            return Err(error);
        }
        Ok(())
    }
    fn wire_pending(&self) -> bool {
        self.frames.iter().any(|f| f.wire < f.data.wire().len())
    }
    fn retire_frames(&mut self) {
        let mut i = 0;
        while i < self.frames.len() {
            let f = &self.frames[i];
            if f.wire == f.data.wire().len() && f.plain == f.data.plaintext().len() {
                let frame = self.frames.remove(i).expect("frame index checked");
                if let Some(engine) = self.engine.as_mut().filter(|e| e.can_recycle()) {
                    engine.recycle(frame.data).expect("recycle checked");
                } else {
                    // A CPU step may own SSL while the other side consumes a
                    // previous frame. Keep that real reservation instead of
                    // returning it for a new connection to steal.
                    let credit = crate::server_engine::retire(frame.data);
                    if let Some(slot) = self.returned.iter_mut().find(|slot| slot.is_none()) {
                        *slot = Some(credit)
                    } else {
                        drop(credit)
                    }
                }
            } else {
                i += 1
            }
        }
    }
    fn poll_wire(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.admitted()?;
        for f in &mut self.frames {
            while f.wire < f.data.wire().len() {
                let n = match Pin::new(&mut self.io).poll_write(cx, &f.data.wire()[f.wire..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                f.wire += n;
                self.wake.write.wake();
            }
        }
        self.retire_frames();
        Poll::Ready(Ok(()))
    }
    fn poll_job(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(job) = self.job.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let waker: Waker = self.wake.clone().into();
        let mut fan = Context::from_waker(&waker);
        let kind = job.kind;
        let step = match job.future.as_mut().poll(&mut fan) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => {
                self.job = None;
                match result {
                    Ok(value) => value,
                    Err(e) => return Poll::Ready(Err(self.fail(e))),
                }
            }
        };
        let Step {
            engine,
            progress,
            transferred: _,
            error,
            data,
        } = step;
        self.engine = Some(engine);
        for credit in &mut self.returned {
            if let Some(credit) = credit.take() {
                if let Err(error) = self
                    .engine
                    .as_mut()
                    .expect("engine just restored")
                    .restore(credit)
                {
                    return Poll::Ready(Err(self.fail(error)));
                }
            }
        }
        if self.frames.len() >= FRAME_LIMIT {
            return Poll::Ready(Err(io::Error::other("SSL output frame bound violated")));
        }
        let mut frame = Frame {
            data,
            wire: 0,
            plain: 0,
        };
        let retry = frame.data.take_retry();
        match kind {
            Kind::Handshake => {
                self.handshake_done = progress == Progress::Complete;
                self.handshake_wait = Some(progress);
            }
            Kind::Read => {
                self.read_wait = Some(progress);
                if progress == Progress::Closed {
                    self.read_closed = true;
                }
            }
            Kind::Write => {
                self.queued_write = retry;
                self.write_wait = Some(progress);
                self.wake.write.wake();
            }
            Kind::Shutdown => {
                self.shutdown_done = progress == Progress::Complete || progress == Progress::Closed;
                self.shutdown_wait = Some(progress);
            }
        }
        self.frames.push_back(frame);
        self.retire_frames();
        self.wake.read.wake();
        self.wake.write.wake();
        if let Some(error) = error {
            // Retain OpenSSL's generated fatal alert for the outer flush/close path;
            // no plaintext can be exposed once failure has been recorded.
            self.failure = Some(Arc::new(error));
        }
        let _ = cx;
        Poll::Ready(Ok(()))
    }
    fn poll_input(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.encrypted.is_some() {
            return Poll::Ready(Ok(()));
        }
        let Some(engine) = self.engine.as_ref() else {
            return Poll::Pending;
        };
        let mut bytes = [0; 16384];
        let cap = engine.input_capacity().min(bytes.len());
        if cap == 0 {
            return Poll::Ready(Err(io::Error::other("SSL input made no progress")));
        }
        let mut buf = ReadBuf::new(&mut bytes[..cap]);
        match Pin::new(&mut self.io).poll_read(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS peer closed without close_notify",
                    )));
                }
                self.encrypted = Some(EncryptedInput::new(buf.filled())?);
                Poll::Ready(Ok(()))
            }
        }
    }
    fn start(&mut self, kind: Kind, op: Operation) -> io::Result<()> {
        if self.job.is_some() || self.frames.len() >= FRAME_LIMIT {
            return Err(io::Error::other("SSL CPU step started without output slot"));
        }
        let engine = self
            .engine
            .take()
            .ok_or_else(|| io::Error::other("SSL engine not available"))?;
        let input = self
            .encrypted
            .take()
            .map(Ok)
            .unwrap_or_else(|| EncryptedInput::new(&[]))?;
        let scope = self.scope.clone();
        self.job = Some(Job {
            kind,
            future: Box::pin(engine.step(scope, op, input)),
        });
        Ok(())
    }
    fn retry_ready(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Progress>,
    ) -> Poll<io::Result<()>> {
        match wait {
            Some(Progress::Read) => self.poll_input(cx),
            Some(Progress::Write) if self.wire_pending() => self.poll_wire(cx),
            Some(Progress::Fatal) => Poll::Ready(Err(self
                .error()
                .unwrap_or_else(|| io::Error::other("SSL fatal alert")))),
            _ => Poll::Ready(Ok(())),
        }
    }
    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wake.read.register(cx.waker());
        self.wake.write.register(cx.waker());
        for _ in 0..16 {
            if self.failure.is_some() {
                match self.poll_wire(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(value) => value?,
                }
                return Poll::Ready(Err(self.error().expect("failure checked")));
            }
            self.live()?;
            match self.poll_job(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(value) => value?,
            }
            match self.poll_wire(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(value) => value?,
            }
            if self.wire_pending() {
                return Poll::Pending;
            }
            self.live()?;
            if self.handshake_done {
                return Poll::Ready(Ok(()));
            }
            match self.retry_ready(cx, self.handshake_wait) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            }
            self.start(Kind::Handshake, Operation::Handshake)?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn poll_drive(&mut self, cx: &mut Context<'_>, prefer_read: bool) -> Poll<io::Result<()>> {
        self.admitted()?;
        if self.failure.is_some() {
            match self.poll_wire(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(value) => value?,
            }
            return Poll::Ready(Err(self.error().expect("failure checked")));
        }
        self.live()?;
        match self.poll_job(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(v) => v?,
        }
        // A blocked write does not suppress reads of peer records. Two bounded
        // frames permit full-duplex progress without an unbounded ciphertext queue.
        let wire_blocked = match self.poll_wire(cx) {
            Poll::Ready(value) => {
                value?;
                false
            }
            Poll::Pending if self.failure.is_some() => return Poll::Pending,
            Poll::Pending => true,
        };
        self.retire_frames();
        self.live()?;
        // Give an actual reader a chance to consume already buffered or
        // ready peer records before another outgoing crypto step. A continuous
        // writer must not starve control frames/pings until the socket fills.
        if prefer_read
            && self.queued_write.is_some()
            && self.frames.len() < FRAME_LIMIT
            && !matches!(self.write_wait, Some(Progress::Read | Progress::Write))
        {
            let readable = match self.read_wait {
                Some(Progress::Read) => match self.poll_input(cx) {
                    Poll::Pending => false,
                    Poll::Ready(value) => {
                        value?;
                        true
                    }
                },
                Some(Progress::Closed) => false,
                _ => true,
            };
            if readable {
                return Poll::Ready(Ok(()));
            }
        }
        if self.queued_write.is_some() && self.frames.len() < FRAME_LIMIT && !self.wire_pending() {
            match self.retry_ready(cx, self.write_wait) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            }
            let bytes = self.queued_write.take().expect("queued write checked");
            self.start(Kind::Write, Operation::Write(bytes))?;
            return self.poll_job(cx);
        }
        if wire_blocked {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
impl<I: AsyncRead + AsyncWrite + Unpin> AsyncRead for ServerStream<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.wake.read.register(cx.waker());
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..16 {
            let drive = this.poll_drive(cx, true);
            if let Poll::Ready(Err(e)) = drive {
                return Poll::Ready(Err(this.fail(e)));
            }
            if this.failure.is_some() {
                return Poll::Pending;
            }
            for frame in &mut this.frames {
                let available = &frame.data.plaintext()[frame.plain..];
                if !available.is_empty() {
                    let n = available.len().min(buf.remaining());
                    let old = buf.filled().len();
                    buf.put_slice(&available[..n]);
                    frame.plain += n;
                    if let Err(e) = this.live() {
                        buf.filled_mut()[old..].fill(0);
                        buf.set_filled(old);
                        return Poll::Ready(Err(this.fail(e)));
                    }
                    this.retire_frames();
                    return Poll::Ready(Ok(()));
                }
            }
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            if this.job.is_some() {
                return Poll::Pending;
            }
            if this.frames.len() >= FRAME_LIMIT {
                return Poll::Pending;
            }
            if this.queued_write.is_some()
                && matches!(this.write_wait, Some(Progress::Read | Progress::Write))
            {
                return Poll::Pending;
            }
            match this.retry_ready(cx, this.read_wait) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            }
            this.start(Kind::Read, Operation::Read)?;
            // Poll a newly created CPU future once before returning Pending. It owns
            // task registration and must install the fanout Waker even on first poll.
            match this.poll_job(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(value) => value?,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<I: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ServerStream<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.wake.write.register(cx.waker());
        this.admitted()?;
        if this.shutdown_done {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Poll::Ready(Err(e)) = this.poll_drive(cx, false) {
            return Poll::Ready(Err(this.fail(e)));
        }
        if this.failure.is_some() {
            return Poll::Pending;
        }
        if this.queued_write.is_some() || this.job.as_ref().is_some_and(|j| j.kind == Kind::Write) {
            return Poll::Pending;
        }
        let n = bytes.len().min(16384);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        // Ready means ownership of exactly these bytes was accepted. SSL CPU or
        // socket failure is subsequently surfaced by flush/read/next write.
        this.queued_write = Some(OwnedWrite::new(&bytes[..n])?);
        this.write_wait = None;
        cx.waker().wake_by_ref();
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.wake.write.register(cx.waker());
        for _ in 0..16 {
            match this.poll_drive(cx, false) {
                Poll::Pending => {
                    if this.job.is_some() {
                        match this.poll_job(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(value) => value?,
                        }
                        continue;
                    }
                    return Poll::Pending;
                }
                Poll::Ready(v) => v?,
            }
            if this.job.is_none() && this.queued_write.is_none() && !this.wire_pending() {
                return Pin::new(&mut this.io).poll_flush(cx);
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.wake.write.register(cx.waker());
        for _ in 0..16 {
            match this.poll_drive(cx, false) {
                Poll::Pending => {
                    if this.job.is_some() {
                        match this.poll_job(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(value) => value?,
                        }
                        continue;
                    }
                    return Poll::Pending;
                }
                Poll::Ready(v) => v?,
            }
            if this.job.is_some() || this.queued_write.is_some() || this.wire_pending() {
                return Poll::Pending;
            }
            if this.shutdown_done {
                return Pin::new(&mut this.io).poll_shutdown(cx);
            }
            match this.retry_ready(cx, this.shutdown_wait) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            }
            this.start(Kind::Shutdown, Operation::Shutdown)?;
            match this.poll_job(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(value) => value?,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
