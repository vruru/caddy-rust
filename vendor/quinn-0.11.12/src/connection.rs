use std::{
    any::Any,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
};

use bytes::Bytes;
use pin_project_lite::pin_project;
use rustc_hash::FxHashMap;
use thiserror::Error;
use tokio::sync::{Notify, futures::Notified, mpsc, oneshot};
use tracing::{Instrument, Span, debug_span};

use crate::{
    ConnectionEvent, Duration, Instant, VarInt,
    mutex::Mutex,
    recv_stream::RecvStream,
    runtime::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller},
    send_stream::SendStream,
    udp_transmit,
};
use proto::{
    ConnectionError, ConnectionHandle, ConnectionStats, Dir, EndpointEvent, Side, StreamEvent,
    StreamId, congestion::Controller,
};

// Registered only while the owning HTTP request is active. Existing Quinn
// waiters retain their own Arc, so abandoning this observer cannot orphan them.
#[cfg(feature = "native-stream-observer")]
struct SendStopObservation {
    conn: ConnectionRef,
    stream: StreamId,
}
#[cfg(feature = "native-stream-observer")]
impl Drop for SendStopObservation {
    fn drop(&mut self) {
        let mut state = self.conn.state.lock("observe_send_stopped::drop");
        if state.stopped.get(&self.stream).is_some_and(|notify| Arc::strong_count(notify) == 1) {
            state.stopped.remove(&self.stream);
        }
    }
}

/// Cumulative stream offsets accepted by this connection's actual UDP socket.
/// This is local transmission, not peer acknowledgement or an allocation fence.
#[cfg(feature = "native-stream-observer")]
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamTransmitSnapshot {
    /// Greatest observed stream offset. Arm before the stream's first write;
    /// callers must map HTTP/3 framing offsets to their own logical payload.
    pub end: u64,
    /// Whether a FIN-containing packet was locally transmitted.
    pub fin: bool,
    /// Monotonic local time of the latest new offset or FIN progress.
    pub last_transmit: Option<Instant>,
    /// Current concrete HTTP writer boundary, if one is armed.
    pub operation: Option<crate::StreamWriteSnapshot>,
}
#[cfg(feature = "native-stream-observer")]
#[derive(Debug, Default)]
struct StreamTransmitState {
    snapshot: StreamTransmitSnapshot,
    operation: Option<crate::transmit_operation::Operation>,
    waiter: Option<Waker>,
}
/// Read-only, bounded observation for a peer bidirectional server stream.
/// It never keeps a connection alive or waits in Drop. Dead weak cache entries
/// are pruned by the driver or the next registration, and bounded to 128.
#[cfg(feature = "native-stream-observer")]
#[derive(Debug)]
pub struct StreamTransmitObservation {
    state: Arc<std::sync::Mutex<StreamTransmitState>>,
    // Drop the actual strong cell before its concrete allocation credit. The
    // cache independently retains the same credit through its last Weak tail.
    _credit:Option<Arc<native_write_policy::Lease>>,
}
#[cfg(feature = "native-stream-observer")]
struct TransmitEntry {
    id:StreamId,
    state:std::sync::Weak<std::sync::Mutex<StreamTransmitState>>,
    _credit:Option<Arc<native_write_policy::Lease>>,
}
#[cfg(feature = "native-stream-observer")]
#[derive(Default)]
struct TransmitObservers {
    entries:Vec<TransmitEntry>,
    progress:Vec<proto::StreamTransmitProgress>,
    pool:Option<native_write_policy::Pool>,
    // Both actual Vec allocations are destroyed before this lease is retired.
    _table_credit:Option<native_write_policy::Lease>,
}
#[cfg(feature = "native-stream-observer")]
impl TransmitObservers {
    const LIMIT:usize=128;
    fn allocation_upper_bytes()->Option<usize>{
        Some(StreamTransmitObservation::TABLE_ALLOCATION_UPPER_BYTES)
    }
    fn prepare(&mut self,pool:Option<&native_write_policy::Pool>)->Result<(),io::Error>{
        if self.entries.capacity()!=0 {
            if let Some(pool)=pool {
                if !self.pool.as_ref().is_some_and(|existing|existing.same_owner(pool)) {
                    return Err(io::Error::other("transmit observer allocation pool changed"));
                }
            }
            return Ok(());
        }
        let credit=pool.map(|pool|pool.reserve(Self::allocation_upper_bytes().ok_or_else(||io::Error::other("transmit table layout overflow"))?)
            .map_err(|_|io::Error::other("transmit observer allocation budget exhausted"))).transpose()?;
        // Exact preallocation makes the named Rust Vec layouts measurable;
        // neither packet transmission nor a later insert grows these buffers.
        let mut entries=Vec::new();
        let mut progress=Vec::new();
        entries.try_reserve_exact(Self::LIMIT).map_err(|_|io::Error::other("transmit table allocation failed"))?;
        progress.try_reserve_exact(Self::LIMIT).map_err(|_|io::Error::other("transmit progress allocation failed"))?;
        if entries.capacity()!=Self::LIMIT||progress.capacity()!=Self::LIMIT {
            return Err(io::Error::other("transmit table capacity exceeds prepaid layout"));
        }
        self.entries=entries;self.progress=progress;self.pool=pool.cloned();self._table_credit=credit;Ok(())
    }
    fn cell_credit(&self)->Result<Option<Arc<native_write_policy::Lease>>,io::Error>{
        self.pool.as_ref().map(|pool|pool.reserve(StreamTransmitObservation::ALLOCATION_UPPER_BYTES)
            .map(Arc::new).map_err(|_|io::Error::other("transmit cell allocation budget exhausted"))).transpose()
    }
    fn prune(&mut self){self.entries.retain(|entry|entry.state.strong_count()!=0);}
    fn get(&self,id:&StreamId)->Option<&TransmitEntry>{self.entries.binary_search_by_key(id,|entry|entry.id).ok().map(|index|&self.entries[index])}
    fn insert(&mut self,entry:TransmitEntry)->Result<(),io::Error>{
        let index=match self.entries.binary_search_by_key(&entry.id,|entry|entry.id){Ok(_)=>return Err(io::Error::new(io::ErrorKind::AlreadyExists,"stream transmit observation occupied")),Err(index)=>index};
        if self.entries.len()>=Self::LIMIT||self.entries.len()==self.entries.capacity(){return Err(io::Error::other("stream transmit observation limit"))}
        self.entries.insert(index,entry);Ok(())
    }
    fn prepare_progress(&mut self)->Result<(),io::Error>{
        if self.progress.capacity()<self.entries.len(){return Err(io::Error::other("transmit progress exceeded prepaid layout"))}
        self.progress.clear();
        self.progress.extend(self.entries.iter().map(|entry|proto::StreamTransmitProgress{id:entry.id,end:0,fin:false}));Ok(())
    }
}
#[cfg(feature = "native-stream-observer")]
impl StreamTransmitObservation {
    /// Read only already accepted UDP progress. This is not a completion future;
    /// connection failure/stream reset remains the caller's independent signal.
    pub fn snapshot(&self) -> StreamTransmitSnapshot {
        let state=self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mut snapshot=state.snapshot;
        snapshot.operation=state.operation.as_ref().map(|op|op.snapshot());
        snapshot
    }
    /// Register a single progress waiter without calling or dropping a foreign
    /// Waker inside the observation/connection locks. Connection failure and
    /// STOP_SENDING remain separate signals, as with snapshot-only observation.
    pub fn poll_progress(&self,cx:&mut Context<'_>,end:u64,fin:bool)->Poll<StreamTransmitSnapshot> {
        let mut incoming=Some(cx.waker().clone());
        let (old,result)={
            let mut state=self.state.lock().unwrap_or_else(|e|e.into_inner());
            let mut snapshot=state.snapshot;
            snapshot.operation=state.operation.as_ref().map(|op|op.snapshot());
            if snapshot.end!=end || snapshot.fin!=fin {
                (state.waiter.take(),Poll::Ready(snapshot))
            } else {
                (std::mem::replace(&mut state.waiter,incoming.take()),Poll::Pending)
            }
        };
        drop(old);drop(incoming);result
    }
    /// Fixed sorted observation/progress Vec layouts, prepaid once for the real
    /// connection. Scalar cells have their independent allowance below.
    pub const TABLE_ALLOCATION_UPPER_BYTES:usize=128*(std::mem::size_of::<TransmitEntry>()+std::mem::size_of::<proto::StreamTransmitProgress>())+128;
    /// Conservative cell, credit Arc and short teardown-overlap allowance;
    /// fixed connection table storage is prepaid separately.
    pub const ALLOCATION_UPPER_BYTES: usize = 2 * (
        std::mem::size_of::<std::sync::Mutex<StreamTransmitState>>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::align_of::<std::sync::Mutex<StreamTransmitState>>()) + 128;
    fn begin(&self, policy: crate::StreamWritePolicy, payload: Option<(u64,usize)>, scoped:Option<native_write_policy::Boundary>) -> Result<(), io::Error> {
        let mut state=self.state.lock().unwrap_or_else(|error|error.into_inner());
        if state.operation.as_ref().is_some_and(|op| {let s=op.snapshot(); !s.completed || s.expired}) {
            return Err(io::Error::other("previous transmit boundary incomplete or expired"));
        }
        let before=state.snapshot.end;
        let operation=match (payload,scoped) {
            (None,None)=>crate::transmit_operation::Operation::wire(before,policy),
            (None,Some(scope))=>crate::transmit_operation::Operation::wire_scoped(before,policy,scope),
            (Some((start,length)),None)=>crate::transmit_operation::Operation::data(start,length,before,policy)
                .map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,"invalid payload transmit boundary"))?,
            (Some((start,length)),Some(scope))=>crate::transmit_operation::Operation::data_scoped(start,length,before,policy,scope)
                .map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,"invalid payload transmit boundary"))?,
        };
        state.operation=Some(operation);Ok(())
    }
    /// Arm before handing encoded headers/trailers/FIN to the transport.
    pub fn begin_wire(&self, policy: crate::StreamWritePolicy)->Result<(),io::Error> {
        self.begin(policy,None,None)
    }
    /// Arm before DATA acceptance. `start` excludes the HTTP frame header.
    pub fn begin_data(&self,start:u64,length:usize,policy:crate::StreamWritePolicy)->Result<(),io::Error> {
        self.begin(policy,Some((start,length)),None)
    }
    /// Arm exact server/route constraints with their actual prepaid owner.
    pub fn begin_wire_scoped(&self,policy:crate::StreamWritePolicy,scope:native_write_policy::Boundary)->Result<(),io::Error> {
        self.begin(policy,None,Some(scope))
    }
    /// Arm DATA with the same exact, independently anchored constraints.
    pub fn begin_data_scoped(&self,start:u64,length:usize,policy:crate::StreamWritePolicy,scope:native_write_policy::Boundary)->Result<(),io::Error> {
        self.begin(policy,Some((start,length)),Some(scope))
    }
    /// Withdraw only a header encoding rejected before accepting any wire
    /// bytes. The caller supplies the actual current accepted writer offset;
    /// it must equal this unsealed operation's original observed boundary.
    pub fn discard_unwritten_wire(&self,accepted:u64)->Result<(),io::Error>{
        let mut state=self.state.lock().unwrap_or_else(|error|error.into_inner());
        if !state.operation.as_ref().is_some_and(|op|op.is_unwritten_wire(accepted)) {
            return Err(io::Error::other("transmit boundary already accepted or flushed"));
        }
        state.operation=None;Ok(())
    }
    /// Accepted offsets identify the boundary only; this earns no progress.
    pub fn seal_wire(&self,end:u64,fin:bool)->Result<(),io::Error> {
        let mut state=self.state.lock().unwrap_or_else(|error|error.into_inner());
        state.operation.as_mut().ok_or_else(||io::Error::other("no transmit boundary armed"))?
            .seal_wire(end,fin).map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,"invalid wire transmit boundary"))
    }
}

#[cfg(feature = "native-stream-observer")]
impl Drop for StreamTransmitObservation {
    fn drop(&mut self) {
        // The receiver keeps its Arc alive until the last foreign waiter has
        // left the cell. A driver's temporary Arc can then only drop scalars.
        let waiter=self.state.lock().unwrap_or_else(|e|e.into_inner()).waiter.take();
        drop(waiter);
    }
}
#[cfg(feature = "native-stream-observer")]
struct TransmitWakeBatch { wakes:[Option<Waker>;128],len:usize }
#[cfg(feature = "native-stream-observer")]
impl TransmitWakeBatch {
    fn new()->Self {Self{wakes:std::array::from_fn(|_|None),len:0}}
    fn push(&mut self,waker:Waker) {
        assert!(self.len<self.wakes.len(),"one bounded observer pass");
        self.wakes[self.len]=Some(waker);self.len+=1;
    }
}
#[cfg(feature = "native-stream-observer")]
impl Drop for TransmitWakeBatch {
    fn drop(&mut self) {
        for wake in self.wakes.iter_mut().take(self.len) {
            if let Some(wake)=wake.take(){wake.wake()}
        }
    }
}

/// In-progress connection attempt future
#[derive(Debug)]
pub struct Connecting {
    conn: Option<ConnectionRef>,
    connected: oneshot::Receiver<bool>,
    handshake_data_ready: Option<oneshot::Receiver<()>>,
}

impl Connecting {
    pub(crate) fn new(
        handle: ConnectionHandle,
        conn: proto::Connection,
        endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        let (on_handshake_data_send, on_handshake_data_recv) = oneshot::channel();
        let (on_connected_send, on_connected_recv) = oneshot::channel();
        let conn = ConnectionRef::new(
            handle,
            conn,
            endpoint_events,
            conn_events,
            on_handshake_data_send,
            on_connected_send,
            socket,
            runtime.clone(),
        );

        let driver = ConnectionDriver::new(conn.clone());
        runtime.spawn(Box::pin(
            async {
                if let Err(e) = driver.await {
                    tracing::error!("I/O error: {e}");
                }
            }
            .instrument(Span::current()),
        ));

        Self {
            conn: Some(conn),
            connected: on_connected_recv,
            handshake_data_ready: Some(on_handshake_data_recv),
        }
    }

    /// Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened security
    ///
    /// Returns `Ok` immediately if the local endpoint is able to attempt sending 0/0.5-RTT data.
    /// If so, the returned [`Connection`] can be used to send application data without waiting for
    /// the rest of the handshake to complete, at the cost of weakened cryptographic security
    /// guarantees. The returned [`ZeroRttAccepted`] future resolves when the handshake does
    /// complete, at which point subsequently opened streams and written data will have full
    /// cryptographic protection.
    ///
    /// ## Outgoing
    ///
    /// For outgoing connections, the initial attempt to convert to a [`Connection`] which sends
    /// 0-RTT data will proceed if the [`crypto::ClientConfig`][crate::crypto::ClientConfig]
    /// attempts to resume a previous TLS session. However, **the remote endpoint may not actually
    /// _accept_ the 0-RTT data**--yet still accept the connection attempt in general. This
    /// possibility is conveyed through the [`ZeroRttAccepted`] future--when the handshake
    /// completes, it resolves to true if the 0-RTT data was accepted and false if it was rejected.
    /// If it was rejected, the existence of streams opened and other application data sent prior
    /// to the handshake completing will not be conveyed to the remote application, and local
    /// operations on them will return `ZeroRttRejected` errors.
    ///
    /// A server may reject 0-RTT data at its discretion, but accepting 0-RTT data requires the
    /// relevant resumption state to be stored in the server, which servers may limit or lose for
    /// various reasons including not persisting resumption state across server restarts.
    ///
    /// If manually providing a [`crypto::ClientConfig`][crate::crypto::ClientConfig], check your
    /// implementation's docs for 0-RTT pitfalls.
    ///
    /// ## Incoming
    ///
    /// For incoming connections, conversion to 0.5-RTT will always fully succeed. `into_0rtt` will
    /// always return `Ok` and the [`ZeroRttAccepted`] will always resolve to true.
    ///
    /// If manually providing a [`crypto::ServerConfig`][crate::crypto::ServerConfig], check your
    /// implementation's docs for 0-RTT pitfalls.
    ///
    /// ## Security
    ///
    /// On outgoing connections, this enables transmission of 0-RTT data, which is vulnerable to
    /// replay attacks, and should therefore never invoke non-idempotent operations.
    ///
    /// On incoming connections, this enables transmission of 0.5-RTT data, which may be sent
    /// before TLS client authentication has occurred, and should therefore not be used to send
    /// data for which client authentication is being used.
    pub fn into_0rtt(mut self) -> Result<(Connection, ZeroRttAccepted), Self> {
        // This lock borrows `self` and would normally be dropped at the end of this scope, so we'll
        // have to release it explicitly before returning `self` by value.
        let conn = (self.conn.as_mut().unwrap()).state.lock("into_0rtt");

        let is_ok = conn.inner.has_0rtt() || conn.inner.side().is_server();
        drop(conn);

        if is_ok {
            let conn = self.conn.take().unwrap();
            Ok((Connection(conn), ZeroRttAccepted(self.connected)))
        } else {
            Err(self)
        }
    }

    /// Parameters negotiated during the handshake
    ///
    /// The dynamic type returned is determined by the configured
    /// [`Session`](proto::crypto::Session). For the default `rustls` session, the return value can
    /// be [`downcast`](Box::downcast) to a
    /// [`crypto::rustls::HandshakeData`](crate::crypto::rustls::HandshakeData).
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError> {
        // Taking &mut self allows us to use a single oneshot channel rather than dealing with
        // potentially many tasks waiting on the same event. It's a bit of a hack, but keeps things
        // simple.
        if let Some(x) = self.handshake_data_ready.take() {
            let _ = x.await;
        }
        let conn = self.conn.as_ref().unwrap();
        let inner = conn.state.lock("handshake");
        inner
            .inner
            .crypto_session()
            .handshake_data()
            .ok_or_else(|| {
                inner
                    .error
                    .clone()
                    .expect("spurious handshake data ready notification")
            })
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients, or when the platform does not expose this
    /// information. See [`quinn_udp::RecvMeta::dst_ip`](udp::RecvMeta::dst_ip) for a list of
    /// supported platforms when using [`quinn_udp`](udp) for I/O, which is the default.
    ///
    /// Will panic if called after `poll` has returned `Ready`.
    pub fn local_ip(&self) -> Option<IpAddr> {
        let conn = self.conn.as_ref().unwrap();
        let inner = conn.state.lock("local_ip");

        inner.inner.local_ip()
    }

    /// The peer's UDP address
    ///
    /// Will panic if called after `poll` has returned `Ready`.
    pub fn remote_address(&self) -> SocketAddr {
        let conn_ref: &ConnectionRef = self.conn.as_ref().expect("used after yielding Ready");
        conn_ref.state.lock("remote_address").inner.remote_address()
    }
}

impl Future for Connecting {
    type Output = Result<Connection, ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.connected).poll(cx).map(|_| {
            let conn = self.conn.take().unwrap();
            let inner = conn.state.lock("connecting");
            if inner.connected {
                drop(inner);
                Ok(Connection(conn))
            } else {
                Err(inner
                    .error
                    .clone()
                    .expect("connected signaled without connection success or error"))
            }
        })
    }
}

/// Future that completes when a connection is fully established
///
/// For clients, the resulting value indicates if 0-RTT was accepted. For servers, the resulting
/// value is meaningless.
pub struct ZeroRttAccepted(oneshot::Receiver<bool>);

impl Future for ZeroRttAccepted {
    type Output = bool;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|x| x.unwrap_or(false))
    }
}

/// A future that drives protocol logic for a connection
///
/// This future handles the protocol logic for a single connection, routing events from the
/// `Connection` API object to the `Endpoint` task and the related stream-related interfaces.
/// It also keeps track of outstanding timeouts for the `Connection`.
///
/// If the connection encounters an error condition, this future will yield an error. It will
/// terminate (yielding `Ok(())`) if the connection was closed without error. Unlike other
/// connection-related futures, this waits for the draining period to complete to ensure that
/// packets still in flight from the peer are handled gracefully.
#[must_use = "connection drivers must be spawned for their connections to function"]
#[derive(Debug)]
struct ConnectionDriver {
    conn: ConnectionRef,
    span: Span,
}

impl ConnectionDriver {
    fn new(conn: ConnectionRef) -> Self {
        let span = {
            let conn = &mut conn.state.lock("poll");
            debug_span!("drive", id = conn.handle.0)
        };

        Self { conn, span }
    }
}

impl Future for ConnectionDriver {
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // Declared before the connection guard: callbacks run after that
        // guard has dropped on every return, including errors/unwinding.
        #[cfg(feature = "native-stream-observer")]
        let mut transmit_wakes=TransmitWakeBatch::new();
        let conn = &mut *self.conn.state.lock("poll");
        let _guard = self.span.enter();

        if let Err(e) = conn.process_conn_events(&self.conn.shared, cx) {
            conn.terminate(e, &self.conn.shared);
            return Poll::Ready(Ok(()));
        }
        let mut keep_going = conn.drive_transmit(cx,
            #[cfg(feature = "native-stream-observer")] &mut transmit_wakes)?;
        // If a timer expires, there might be more to transmit. When we transmit something, we
        // might need to reset a timer. Hence, we must loop until neither happens.
        keep_going |= conn.drive_timer(cx);
        conn.forward_endpoint_events();
        conn.forward_app_events(&self.conn.shared);

        if !conn.inner.is_drained() {
            if keep_going {
                // If the connection hasn't processed all tasks, schedule it again
                cx.waker().wake_by_ref();
            } else {
                conn.driver = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        if conn.error.is_none() {
            unreachable!("drained connections always have an error");
        }
        Poll::Ready(Ok(()))
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the `Connection` handle, streams of
/// incoming streams, and the various stream types) have been dropped, then the connection will be
/// automatically closed with an `error_code` of 0 and an empty `reason`. You can also close the
/// connection explicitly by calling [`Connection::close()`].
///
/// Closing the connection immediately abandons efforts to deliver data to the peer.  Upon
/// receiving CONNECTION_CLOSE the peer *may* drop any stream data not yet delivered to the
/// application. [`Connection::close()`] describes in more detail how to gracefully close a
/// connection without losing application data.
///
/// May be cloned to obtain another handle to the same connection.
///
/// [`Connection::close()`]: Connection::close
#[derive(Debug, Clone)]
pub struct Connection(ConnectionRef);

impl Connection {
    /// Initiate a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub fn open_uni(&self) -> OpenUni<'_> {
        OpenUni {
            conn: &self.0,
            notify: self.0.shared.stream_budget_available[Dir::Uni as usize].notified(),
        }
    }

    /// Initiate a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used. Calling [`open_bi()`] then waiting on the [`RecvStream`] without writing
    /// anything to [`SendStream`] will never succeed.
    ///
    /// [`open_bi()`]: crate::Connection::open_bi
    /// [`SendStream`]: crate::SendStream
    /// [`RecvStream`]: crate::RecvStream
    pub fn open_bi(&self) -> OpenBi<'_> {
        OpenBi {
            conn: &self.0,
            notify: self.0.shared.stream_budget_available[Dir::Bi as usize].notified(),
        }
    }

    /// Accept the next incoming uni-directional stream
    pub fn accept_uni(&self) -> AcceptUni<'_> {
        AcceptUni {
            conn: &self.0,
            notify: self.0.shared.stream_incoming[Dir::Uni as usize].notified(),
        }
    }

    /// Accept the next incoming bidirectional stream
    ///
    /// **Important Note**: The `Connection` that calls [`open_bi()`] must write to its [`SendStream`]
    /// before the other `Connection` is able to `accept_bi()`. Calling [`open_bi()`] then
    /// waiting on the [`RecvStream`] without writing anything to [`SendStream`] will never succeed.
    ///
    /// [`accept_bi()`]: crate::Connection::accept_bi
    /// [`open_bi()`]: crate::Connection::open_bi
    /// [`SendStream`]: crate::SendStream
    /// [`RecvStream`]: crate::RecvStream
    pub fn accept_bi(&self) -> AcceptBi<'_> {
        AcceptBi {
            conn: &self.0,
            notify: self.0.shared.stream_incoming[Dir::Bi as usize].notified(),
        }
    }

    /// Receive an application datagram
    pub fn read_datagram(&self) -> ReadDatagram<'_> {
        ReadDatagram {
            conn: &self.0,
            notify: self.0.shared.datagram_received.notified(),
        }
    }

    /// Wait for the connection to be closed for any reason
    ///
    /// Despite the return type's name, closed connections are often not an error condition at the
    /// application layer. Cases that might be routine include [`ConnectionError::LocallyClosed`]
    /// and [`ConnectionError::ApplicationClosed`].
    pub async fn closed(&self) -> ConnectionError {
        {
            let conn = self.0.state.lock("closed");
            if let Some(error) = conn.error.as_ref() {
                return error.clone();
            }
            // Construct the future while the lock is held to ensure we can't miss a wakeup if
            // the `Notify` is signaled immediately after we release the lock. `await` it after
            // the lock guard is out of scope.
            self.0.shared.closed.notified()
        }
        .await;
        self.0
            .state
            .lock("closed")
            .error
            .as_ref()
            .expect("closed without an error")
            .clone()
    }

    /// Observe termination of the send side of an accepted peer-initiated
    /// bidirectional stream without creating or owning another stream handle.
    ///
    /// This server-side API is intended for HTTP request cancellation while
    /// the application is not writing. It never finishes or resets a stream.
    /// Like `SendStream::stopped`, completion means peer STOP_SENDING, an
    /// acknowledged local FIN, or a lost connection. Only established server
    /// connections are accepted: this observer does not authorize early data.
    #[cfg(feature = "native-stream-observer")]
    pub fn observe_send_stopped(
        &self,
        stream: StreamId,
    ) -> Result<
        impl Future<Output = Result<Option<VarInt>, crate::StoppedError>> + Send + Sync + 'static,
        std::io::Error,
    > {
        {
            let state = self.0.state.lock("observe_send_stopped::validate");
            if !state.connected || state.inner.side() != Side::Server
                || stream.dir() != Dir::Bi || stream.initiator() != Side::Client
            {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    "stream observation requires an established server peer-bidi stream"));
            }
        }
        let conn = self.0.clone();
        let guard = SendStopObservation { conn: conn.clone(), stream };
        Ok(async move {
            let _guard = guard;
            loop {
                let notify;
                {
                    let mut state = conn.state.lock("observe_send_stopped");
                    if let Some(result) = crate::send_stream::send_stream_stopped(&mut state, stream, false) {
                        return result;
                    }
                    // Create Notified under the connection lock, as stopped()
                    // does, so STOP_SENDING cannot be lost between check/wait.
                    notify = state.stopped.entry(stream).or_default().clone();
                    notify.notified()
                }.await
            }
        })
    }

    /// Observe actual UDP transmission for one established peer-bidi stream.
    /// Arm before writing its response. This opt-in prototype exposes snapshots
    /// only; it does not claim logical HTTP payload progress, ACK or ownership
    /// release. At most 128 live stream observations are admitted per connection.
    #[cfg(feature = "native-stream-observer")]
    pub fn observe_stream_transmit(&self,stream:StreamId)->Result<StreamTransmitObservation,io::Error>{
        self.observe_stream_transmit_owned(stream,None)
    }

    /// Prepay the exact fixed observation/progress Vec layouts and each live
    /// scalar cell before allocation. A pool cannot replace one already bound
    /// to this connection. Actual strong and Weak cell owners retain credits;
    /// cancellation and wire completion are not allocation-release fences.
    #[cfg(feature="native-stream-observer")]
    pub fn observe_stream_transmit_with_budget(&self,stream:StreamId,pool:&native_write_policy::Pool)->Result<StreamTransmitObservation,io::Error>{
        self.observe_stream_transmit_owned(stream,Some(pool))
    }
    #[cfg(feature="native-stream-observer")]
    fn observe_stream_transmit_owned(&self,stream:StreamId,pool:Option<&native_write_policy::Pool>)->Result<StreamTransmitObservation,io::Error>{
        let mut connection=self.0.state.lock("observe_stream_transmit");
        if !connection.connected||connection.inner.side()!=Side::Server||stream.dir()!=Dir::Bi||stream.initiator()!=Side::Client {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,"transmit observation requires an established server peer-bidi stream"));
        }
        let table=&mut connection.transmit_observers;
        table.prune();
        if table.get(&stream).is_some(){return Err(io::Error::new(io::ErrorKind::AlreadyExists,"stream transmit observation occupied"))}
        if table.entries.len()==TransmitObservers::LIMIT{return Err(io::Error::other("stream transmit observation limit"))}
        table.prepare(pool)?;
        let credit=table.cell_credit()?;
        let observation=Arc::new(std::sync::Mutex::new(StreamTransmitState::default()));
        table.insert(TransmitEntry{id:stream,state:Arc::downgrade(&observation),_credit:credit.clone()})?;
        Ok(StreamTransmitObservation{state:observation,_credit:credit})
    }

    /// Accepted writer offset, used only to map application framing to the
    /// independently observed socket-transmission offsets. No progress or
    /// ownership release is implied by this value.
    #[cfg(feature = "native-stream-observer")]
    pub fn stream_written_offset(&self, stream: StreamId) -> Result<u64, io::Error> {
        let mut connection = self.0.state.lock("stream_written_offset");
        if stream.dir() != Dir::Bi && stream.initiator() != connection.inner.side() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "receive-only stream"));
        }
        connection.inner.send_stream(stream).written_offset()
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "closed send stream"))
    }

    /// Cancel an observed server response without manufacturing a new stream
    /// owner. Only an established peer-bidi response can be addressed here.
    #[cfg(feature = "native-stream-observer")]
    pub fn reset_observed_stream(&self,stream:StreamId,code:VarInt)->Result<(),io::Error> {
        let (wake,result)={
            let mut state=self.0.state.lock("reset_observed_stream");
            if !state.connected || state.inner.side()!=Side::Server || stream.dir()!=Dir::Bi || stream.initiator()!=Side::Client {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,"not a server response stream"));
            }
            let result=state.inner.send_stream(stream).reset(code)
                .map_err(|_|io::Error::new(io::ErrorKind::NotFound,"closed send stream"));
            (state.driver.take(),result)
        };
        if let Some(wake)=wake{wake.wake()}
        result
    }

    /// Stop the receive half of an established server peer-bidirectional stream.
    ///
    /// This addresses the real protocol state even when an adapter has moved
    /// its receive handle into a pending read future. No synthetic stream is
    /// created. The first stop/error disposition is retained. Driver and reader
    /// wakers are taken under the connection lock and woken/dropped outside it.
    #[cfg(feature = "native-stream-observer")]
    pub fn stop_receive_stream(&self, stream: StreamId, code: VarInt) -> Result<(), io::Error> {
        let (status, reader, driver) = {
            let mut state = self.0.state.lock("stop_receive_stream");
            if !state.connected || state.inner.side() != Side::Server
                || stream.dir() != Dir::Bi || stream.initiator() != Side::Client
            {
                (0u8, None, None)
            } else {
                let status = if state.inner.recv_stream(stream).stop(code).is_ok() { 1 } else { 2 };
                let reader = state.blocked_readers.remove(&stream);
                let driver = if status == 1 { state.driver.take() } else { None };
                (status, reader, driver)
            }
        };
        if let Some(reader) = reader { reader.wake(); }
        if let Some(driver) = driver { driver.wake(); }
        match status {
            1 => Ok(()),
            2 => Err(io::Error::new(io::ErrorKind::NotFound, "receive stream already closed or stopped")),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput,
                "receive stop requires an established server peer-bidi stream")),
        }
    }

    /// If the connection is closed, the reason why.
    ///
    /// Returns `None` if the connection is still open.
    pub fn close_reason(&self) -> Option<ConnectionError> {
        self.0.state.lock("close_reason").error.clone()
    }

    /// Close the connection immediately.
    ///
    /// Pending operations will fail immediately with [`ConnectionError::LocallyClosed`]. No
    /// more data is sent to the peer and the peer may drop buffered data upon receiving
    /// the CONNECTION_CLOSE frame.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    ///
    /// # Gracefully closing a connection
    ///
    /// Only the peer last receiving application data can be certain that all data is
    /// delivered. The only reliable action it can then take is to close the connection,
    /// potentially with a custom error code. The delivery of the final CONNECTION_CLOSE
    /// frame is very likely if both endpoints stay online long enough, and
    /// [`Endpoint::wait_idle()`] can be used to provide sufficient time. Otherwise, the
    /// remote peer will time out the connection, provided that the idle timeout is not
    /// disabled.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote
    /// application. It only knows the data is delivered to the QUIC stack of the remote
    /// endpoint. Once the local side sends a CONNECTION_CLOSE frame in response to calling
    /// [`close()`] the remote endpoint may drop any data it received but is as yet
    /// undelivered to the application, including data that was acknowledged as received to
    /// the local endpoint.
    ///
    /// [`ConnectionError::LocallyClosed`]: crate::ConnectionError::LocallyClosed
    /// [`Endpoint::wait_idle()`]: crate::Endpoint::wait_idle
    /// [`close()`]: Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let conn = &mut *self.0.state.lock("close");
        conn.close(error_code, Bytes::copy_from_slice(reason), &self.0.shared);
    }

    /// Transmit `data` as an unreliable, unordered application datagram
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out of order,
    /// and `data` must both fit inside a single QUIC packet and be smaller than the maximum
    /// dictated by the peer.
    ///
    /// Previously queued datagrams which are still unsent may be discarded to make space for this
    /// datagram, in order of oldest to newest.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        let conn = &mut *self.0.state.lock("send_datagram");
        if let Some(ref x) = conn.error {
            return Err(SendDatagramError::ConnectionLost(x.clone()));
        }
        use proto::SendDatagramError::*;
        match conn.inner.datagrams().send(data, true) {
            Ok(()) => {
                conn.wake();
                Ok(())
            }
            Err(e) => Err(match e {
                Blocked(..) => unreachable!(),
                UnsupportedByPeer => SendDatagramError::UnsupportedByPeer,
                Disabled => SendDatagramError::Disabled,
                TooLarge => SendDatagramError::TooLarge,
            }),
        }
    }

    /// Transmit `data` as an unreliable, unordered application datagram
    ///
    /// Unlike [`send_datagram()`], this method will wait for buffer space during congestion
    /// conditions, which effectively prioritizes old datagrams over new datagrams.
    ///
    /// See [`send_datagram()`] for details.
    ///
    /// [`send_datagram()`]: Connection::send_datagram
    pub fn send_datagram_wait(&self, data: Bytes) -> SendDatagram<'_> {
        SendDatagram {
            conn: &self.0,
            data: Some(data),
            notify: self.0.shared.datagrams_unblocked.notified(),
        }
    }

    /// Compute the maximum size of datagrams that may be passed to [`send_datagram()`].
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// [`send_datagram()`]: Connection::send_datagram
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.0
            .state
            .lock("max_datagram_size")
            .inner
            .datagrams()
            .max_size()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, calling [`send_datagram()`](Self::send_datagram) with a datagram of
    /// at most this size is guaranteed not to cause older datagrams to be dropped.
    pub fn datagram_send_buffer_space(&self) -> usize {
        self.0
            .state
            .lock("datagram_send_buffer_space")
            .inner
            .datagrams()
            .send_buffer_space()
    }

    /// The side of the connection (client or server)
    pub fn side(&self) -> Side {
        self.0.state.lock("side").inner.side()
    }

    /// The peer's UDP address
    ///
    /// If `ServerConfig::migration` is `true`, clients may change addresses at will, e.g. when
    /// switching to a cellular internet connection.
    pub fn remote_address(&self) -> SocketAddr {
        self.0.state.lock("remote_address").inner.remote_address()
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients, or when the platform does not expose this
    /// information. See [`quinn_udp::RecvMeta::dst_ip`](udp::RecvMeta::dst_ip) for a list of
    /// supported platforms when using [`quinn_udp`](udp) for I/O, which is the default.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.0.state.lock("local_ip").inner.local_ip()
    }

    /// Current best estimate of this connection's latency (round-trip-time)
    pub fn rtt(&self) -> Duration {
        self.0.state.lock("rtt").inner.rtt()
    }

    /// Minimum RTT seen on this path, ignoring ack delay
    pub fn min_rtt(&self) -> Duration {
        self.0.state.lock("min_rtt").inner.min_rtt()
    }

    /// Returns connection statistics
    pub fn stats(&self) -> ConnectionStats {
        self.0.state.lock("stats").inner.stats()
    }

    /// Current state of the congestion control algorithm, for debugging purposes
    pub fn congestion_state(&self) -> Box<dyn Controller> {
        self.0
            .state
            .lock("congestion_state")
            .inner
            .congestion_state()
            .clone_box()
    }

    /// Parameters negotiated during the handshake
    ///
    /// Guaranteed to return `Some` on fully established connections or after
    /// [`Connecting::handshake_data()`] succeeds. See that method's documentations for details on
    /// the returned value.
    ///
    /// [`Connection::handshake_data()`]: crate::Connecting::handshake_data
    pub fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.0
            .state
            .lock("handshake_data")
            .inner
            .crypto_session()
            .handshake_data()
    }

    /// Cryptographic identity of the peer
    ///
    /// The dynamic type returned is determined by the configured
    /// [`Session`](proto::crypto::Session). For the default `rustls` session, the return value can
    /// be [`downcast`](Box::downcast) to a <code>Vec<[rustls::pki_types::CertificateDer]></code>
    pub fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.0
            .state
            .lock("peer_identity")
            .inner
            .crypto_session()
            .peer_identity()
    }

    /// A stable identifier for this connection
    ///
    /// Peer addresses and connection IDs can change, but this value will remain
    /// fixed for the lifetime of the connection.
    pub fn stable_id(&self) -> usize {
        self.0.stable_id()
    }

    /// Update traffic keys spontaneously
    ///
    /// This primarily exists for testing purposes.
    pub fn force_key_update(&self) {
        self.0
            .state
            .lock("force_key_update")
            .inner
            .force_key_update()
    }

    /// Derive keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), proto::crypto::ExportKeyingMaterialError> {
        self.0
            .state
            .lock("export_keying_material")
            .inner
            .crypto_session()
            .export_keying_material(output, label, context)
    }

    /// Modify the number of remotely initiated unidirectional streams that may be concurrently open
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already open. Large
    /// `count`s increase both minimum and worst-case memory consumption.
    pub fn set_max_concurrent_uni_streams(&self, count: VarInt) {
        let mut conn = self.0.state.lock("set_max_concurrent_uni_streams");
        conn.inner.set_max_concurrent_streams(Dir::Uni, count);
        // May need to send MAX_STREAMS to make progress
        conn.wake();
    }

    /// See [`proto::TransportConfig::send_window()`]
    pub fn set_send_window(&self, send_window: u64) {
        let mut conn = self.0.state.lock("set_send_window");
        conn.inner.set_send_window(send_window);
        conn.wake();
    }

    /// See [`proto::TransportConfig::receive_window()`]
    pub fn set_receive_window(&self, receive_window: VarInt) {
        let mut conn = self.0.state.lock("set_receive_window");
        conn.inner.set_receive_window(receive_window);
        conn.wake();
    }

    /// Modify the number of remotely initiated bidirectional streams that may be concurrently open
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already open. Large
    /// `count`s increase both minimum and worst-case memory consumption.
    pub fn set_max_concurrent_bi_streams(&self, count: VarInt) {
        let mut conn = self.0.state.lock("set_max_concurrent_bi_streams");
        conn.inner.set_max_concurrent_streams(Dir::Bi, count);
        // May need to send MAX_STREAMS to make progress
        conn.wake();
    }
}

pin_project! {
    /// Future produced by [`Connection::open_uni`]
    pub struct OpenUni<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for OpenUni<'_> {
    type Output = Result<SendStream, ConnectionError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_open(ctx, this.conn, this.notify, Dir::Uni))?;
        Poll::Ready(Ok(SendStream::new(conn, id, is_0rtt)))
    }
}

pin_project! {
    /// Future produced by [`Connection::open_bi`]
    pub struct OpenBi<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for OpenBi<'_> {
    type Output = Result<(SendStream, RecvStream), ConnectionError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_open(ctx, this.conn, this.notify, Dir::Bi))?;

        Poll::Ready(Ok((
            SendStream::new(conn.clone(), id, is_0rtt),
            RecvStream::new(conn, id, is_0rtt),
        )))
    }
}

fn poll_open<'a>(
    ctx: &mut Context<'_>,
    conn: &'a ConnectionRef,
    mut notify: Pin<&mut Notified<'a>>,
    dir: Dir,
) -> Poll<Result<(ConnectionRef, StreamId, bool), ConnectionError>> {
    let mut state = conn.state.lock("poll_open");
    if let Some(ref e) = state.error {
        return Poll::Ready(Err(e.clone()));
    } else if let Some(id) = state.inner.streams().open(dir) {
        let is_0rtt = state.inner.side().is_client() && state.inner.is_handshaking();
        drop(state); // Release the lock so clone can take it
        return Poll::Ready(Ok((conn.clone(), id, is_0rtt)));
    }
    loop {
        match notify.as_mut().poll(ctx) {
            // `state` lock ensures we didn't race with readiness
            Poll::Pending => return Poll::Pending,
            // Spurious wakeup, get a new future
            Poll::Ready(()) => {
                notify.set(conn.shared.stream_budget_available[dir as usize].notified())
            }
        }
    }
}

pin_project! {
    /// Future produced by [`Connection::accept_uni`]
    pub struct AcceptUni<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for AcceptUni<'_> {
    type Output = Result<RecvStream, ConnectionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_accept(ctx, this.conn, this.notify, Dir::Uni))?;
        Poll::Ready(Ok(RecvStream::new(conn, id, is_0rtt)))
    }
}

pin_project! {
    /// Future produced by [`Connection::accept_bi`]
    pub struct AcceptBi<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for AcceptBi<'_> {
    type Output = Result<(SendStream, RecvStream), ConnectionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_accept(ctx, this.conn, this.notify, Dir::Bi))?;
        Poll::Ready(Ok((
            SendStream::new(conn.clone(), id, is_0rtt),
            RecvStream::new(conn, id, is_0rtt),
        )))
    }
}

fn poll_accept<'a>(
    ctx: &mut Context<'_>,
    conn: &'a ConnectionRef,
    mut notify: Pin<&mut Notified<'a>>,
    dir: Dir,
) -> Poll<Result<(ConnectionRef, StreamId, bool), ConnectionError>> {
    let mut state = conn.state.lock("poll_accept");
    // Check for incoming streams before checking `state.error` so that already-received streams,
    // which are necessarily finite, can be drained from a closed connection.
    if let Some(id) = state.inner.streams().accept(dir) {
        let is_0rtt = state.inner.is_handshaking();
        state.wake(); // To send additional stream ID credit
        drop(state); // Release the lock so clone can take it
        return Poll::Ready(Ok((conn.clone(), id, is_0rtt)));
    } else if let Some(ref e) = state.error {
        return Poll::Ready(Err(e.clone()));
    }
    loop {
        match notify.as_mut().poll(ctx) {
            // `state` lock ensures we didn't race with readiness
            Poll::Pending => return Poll::Pending,
            // Spurious wakeup, get a new future
            Poll::Ready(()) => notify.set(conn.shared.stream_incoming[dir as usize].notified()),
        }
    }
}

pin_project! {
    /// Future produced by [`Connection::read_datagram`]
    pub struct ReadDatagram<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for ReadDatagram<'_> {
    type Output = Result<Bytes, ConnectionError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut state = this.conn.state.lock("ReadDatagram::poll");
        // Check for buffered datagrams before checking `state.error` so that already-received
        // datagrams, which are necessarily finite, can be drained from a closed connection.
        if let Some(x) = state.inner.datagrams().recv() {
            return Poll::Ready(Ok(x));
        } else if let Some(ref e) = state.error {
            return Poll::Ready(Err(e.clone()));
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.conn.shared.datagram_received.notified()),
            }
        }
    }
}

pin_project! {
    /// Future produced by [`Connection::send_datagram_wait`]
    pub struct SendDatagram<'a> {
        conn: &'a ConnectionRef,
        data: Option<Bytes>,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for SendDatagram<'_> {
    type Output = Result<(), SendDatagramError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut state = this.conn.state.lock("SendDatagram::poll");
        if let Some(ref e) = state.error {
            return Poll::Ready(Err(SendDatagramError::ConnectionLost(e.clone())));
        }
        use proto::SendDatagramError::*;
        match state
            .inner
            .datagrams()
            .send(this.data.take().unwrap(), false)
        {
            Ok(()) => {
                state.wake();
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(match e {
                Blocked(data) => {
                    this.data.replace(data);
                    loop {
                        match this.notify.as_mut().poll(ctx) {
                            Poll::Pending => return Poll::Pending,
                            // Spurious wakeup, get a new future
                            Poll::Ready(()) => this
                                .notify
                                .set(this.conn.shared.datagrams_unblocked.notified()),
                        }
                    }
                }
                UnsupportedByPeer => SendDatagramError::UnsupportedByPeer,
                Disabled => SendDatagramError::Disabled,
                TooLarge => SendDatagramError::TooLarge,
            })),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionRef(Arc<ConnectionInner>);

impl ConnectionRef {
    #[allow(clippy::too_many_arguments)]
    fn new(
        handle: ConnectionHandle,
        conn: proto::Connection,
        endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
        on_handshake_data: oneshot::Sender<()>,
        on_connected: oneshot::Sender<bool>,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        Self(Arc::new(ConnectionInner {
            state: Mutex::new(State {
                inner: conn,
                driver: None,
                handle,
                on_handshake_data: Some(on_handshake_data),
                on_connected: Some(on_connected),
                connected: false,
                timer: None,
                timer_deadline: None,
                conn_events,
                endpoint_events,
                blocked_writers: FxHashMap::default(),
                blocked_readers: FxHashMap::default(),
                stopped: FxHashMap::default(),
                error: None,
                io_poller: socket.clone().create_io_poller(),
                socket,
                runtime,
                send_buffer: Vec::new(),
                buffered_transmit: None,
                #[cfg(feature = "native-stream-observer")]
                transmit_observers: TransmitObservers::default(),
            }),
            shared: Shared::default(),
        }))
    }

    fn stable_id(&self) -> usize {
        &*self.0 as *const _ as usize
    }
}

impl Clone for ConnectionRef {
    fn clone(&self) -> Self {
        self.shared.ref_count.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl Drop for ConnectionRef {
    fn drop(&mut self) {
        if self.shared.ref_count.fetch_sub(1, Ordering::Relaxed) > 1 {
            return;
        }

        let conn = &mut *self.state.lock("drop");

        if !conn.inner.is_closed() {
            // If the driver is alive, it's just it and us, so we'd better shut it down. If it's
            // not, we can't do any harm. If there were any streams being opened, then either
            // the connection will be closed for an unrelated reason or a fresh reference will
            // be constructed for the newly opened stream.
            conn.implicit_close(&self.shared);
        }
    }
}

impl std::ops::Deref for ConnectionRef {
    type Target = ConnectionInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

#[derive(Debug, Default)]
pub(crate) struct Shared {
    /// Notified when new streams may be locally initiated due to an increase in stream ID flow
    /// control budget
    stream_budget_available: [Notify; 2],
    /// Notified when the peer has initiated a new stream
    stream_incoming: [Notify; 2],
    datagram_received: Notify,
    datagrams_unblocked: Notify,
    closed: Notify,
    /// Number of live handles that can used to initiate or handle I/O; excludes the driver
    ref_count: AtomicUsize,
}

pub(crate) struct State {
    pub(crate) inner: proto::Connection,
    driver: Option<Waker>,
    handle: ConnectionHandle,
    on_handshake_data: Option<oneshot::Sender<()>>,
    on_connected: Option<oneshot::Sender<bool>>,
    connected: bool,
    timer: Option<Pin<Box<dyn AsyncTimer>>>,
    timer_deadline: Option<Instant>,
    conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    pub(crate) blocked_writers: FxHashMap<StreamId, Waker>,
    pub(crate) blocked_readers: FxHashMap<StreamId, Waker>,
    pub(crate) stopped: FxHashMap<StreamId, Arc<Notify>>,
    /// Always set to Some before the connection becomes drained
    pub(crate) error: Option<ConnectionError>,
    socket: Arc<dyn AsyncUdpSocket>,
    io_poller: Pin<Box<dyn UdpPoller>>,
    runtime: Arc<dyn Runtime>,
    send_buffer: Vec<u8>,
    /// We buffer a transmit when the underlying I/O would block
    buffered_transmit: Option<proto::Transmit>,
    #[cfg(feature = "native-stream-observer")]
    transmit_observers: TransmitObservers,
}

impl State {
    fn next_transmit(&mut self, now: Instant, max_datagrams: usize) -> io::Result<Option<proto::Transmit>> {
        #[cfg(feature = "native-stream-observer")]
        {
            self.transmit_observers.prune();
            self.transmit_observers.prepare_progress()?;
            return self.inner.poll_transmit_observed(now, max_datagrams, &mut self.send_buffer, &mut self.transmit_observers.progress)
                .map_err(|_| io::Error::other("invalid transmit observation shape"));
        }
        #[cfg(not(feature = "native-stream-observer"))]
        Ok(self.inner.poll_transmit(now, max_datagrams, &mut self.send_buffer))
    }
    #[cfg(feature = "native-stream-observer")]
    fn publish_transmit_progress(&mut self,wakes:&mut TransmitWakeBatch) {
        let now = Instant::now();
        for progress in &self.transmit_observers.progress {
            let Some(owner) = self.transmit_observers.get(&progress.id).and_then(|entry|entry.state.upgrade()) else { continue; };
            let mut state = owner.lock().unwrap_or_else(|error| error.into_inner());
            if progress.end > state.snapshot.end || (progress.fin && !state.snapshot.fin) {
                if let Some(operation)=&mut state.operation {
                    operation.report(progress.end,progress.fin,now);
                }
                state.snapshot.end = state.snapshot.end.max(progress.end);
                state.snapshot.fin |= progress.fin;
                state.snapshot.last_transmit = Some(now);
                if let Some(waiter)=state.waiter.take() {wakes.push(waiter);}
            }
            // Wakers are moved, never invoked/dropped here. The receiver's
            // Drop clears its waiter before its Arc can become last-owned.
        }
    }
    fn drive_transmit(&mut self, cx: &mut Context,
        #[cfg(feature = "native-stream-observer")] wakes:&mut TransmitWakeBatch,
    ) -> io::Result<bool> {
        let now = self.runtime.now();
        let mut transmits = 0;

        let max_datagrams = self
            .socket
            .max_transmit_segments()
            .min(MAX_TRANSMIT_SEGMENTS);

        loop {
            // Retry the last transmit, or get a new one.
            let t = match self.buffered_transmit.take() {
                Some(t) => t,
                None => {
                    self.send_buffer.clear();
                    self.send_buffer.reserve(self.inner.current_mtu() as usize);
                    match self.next_transmit(now, max_datagrams)? {
                        Some(t) => {
                            transmits += match t.segment_size {
                                None => 1,
                                Some(s) => t.size.div_ceil(s), // round up
                            };
                            t
                        }
                        None => break,
                    }
                }
            };

            if self.io_poller.as_mut().poll_writable(cx)?.is_pending() {
                // Retry after a future wakeup
                self.buffered_transmit = Some(t);
                return Ok(false);
            }

            let len = t.size;
            let retry = match self
                .socket
                .try_send(&udp_transmit(&t, &self.send_buffer[..len]))
            {
                Ok(()) => false,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                Err(e) => return Err(e),
            };
            if retry {
                // We thought the socket was writable, but it wasn't. Retry so that either another
                // `poll_writable` call determines that the socket is indeed not writable and
                // registers us for a wakeup, or the send succeeds if this really was just a
                // transient failure.
                self.buffered_transmit = Some(t);
                continue;
            }

            // Packetization is not a successful send. Retain the exact slots
            // through both poll_writable Pending and try_send WouldBlock above.
            #[cfg(feature = "native-stream-observer")]
            {
                self.publish_transmit_progress(wakes);
                // One snapshot pass has at most128 observers. Return before a
                // second pass can encounter newly registered foreign waiters;
                // callbacks run outside the connection lock, then poll again.
                if wakes.len!=0 {return Ok(true)}
            }

            if transmits >= MAX_TRANSMIT_DATAGRAMS {
                // TODO: What isn't ideal here yet is that if we don't poll all
                // datagrams that could be sent we don't go into the `app_limited`
                // state and CWND continues to grow until we get here the next time.
                // See https://github.com/quinn-rs/quinn/issues/1126
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn forward_endpoint_events(&mut self) {
        while let Some(event) = self.inner.poll_endpoint_events() {
            // If the endpoint driver is gone, noop.
            let _ = self.endpoint_events.send((self.handle, event));
        }
    }

    /// If this returns `Err`, the endpoint is dead, so the driver should exit immediately.
    fn process_conn_events(
        &mut self,
        shared: &Shared,
        cx: &mut Context,
    ) -> Result<(), ConnectionError> {
        loop {
            match self.conn_events.poll_recv(cx) {
                Poll::Ready(Some(ConnectionEvent::Rebind(socket))) => {
                    self.socket = socket;
                    self.io_poller = self.socket.clone().create_io_poller();
                    self.inner.local_address_changed();
                }
                Poll::Ready(Some(ConnectionEvent::Proto(event))) => {
                    self.inner.handle_event(event);
                }
                Poll::Ready(Some(ConnectionEvent::Close { reason, error_code })) => {
                    self.close(error_code, reason, shared);
                }
                Poll::Ready(None) => {
                    return Err(ConnectionError::TransportError(proto::TransportError {
                        code: proto::TransportErrorCode::INTERNAL_ERROR,
                        frame: None,
                        reason: "endpoint driver future was dropped".to_string(),
                    }));
                }
                Poll::Pending => {
                    return Ok(());
                }
            }
        }
    }

    fn forward_app_events(&mut self, shared: &Shared) {
        while let Some(event) = self.inner.poll() {
            use proto::Event::*;
            match event {
                HandshakeDataReady => {
                    if let Some(x) = self.on_handshake_data.take() {
                        let _ = x.send(());
                    }
                }
                Connected => {
                    self.connected = true;
                    if let Some(x) = self.on_connected.take() {
                        // We don't care if the on-connected future was dropped
                        let _ = x.send(self.inner.accepted_0rtt());
                    }
                    if self.inner.side().is_client() && !self.inner.accepted_0rtt() {
                        // Wake up rejected 0-RTT streams so they can fail immediately with
                        // `ZeroRttRejected` errors.
                        wake_all(&mut self.blocked_writers);
                        wake_all(&mut self.blocked_readers);
                        wake_all_notify(&mut self.stopped);
                    }
                }
                ConnectionLost { reason } => {
                    self.terminate(reason, shared);
                }
                Stream(StreamEvent::Writable { id }) => wake_stream(id, &mut self.blocked_writers),
                Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    shared.stream_incoming[Dir::Uni as usize].notify_waiters();
                }
                Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                    shared.stream_incoming[Dir::Bi as usize].notify_waiters();
                }
                DatagramReceived => {
                    shared.datagram_received.notify_waiters();
                }
                DatagramsUnblocked => {
                    shared.datagrams_unblocked.notify_waiters();
                }
                Stream(StreamEvent::Readable { id }) => wake_stream(id, &mut self.blocked_readers),
                Stream(StreamEvent::Available { dir }) => {
                    // Might mean any number of streams are ready, so we wake up everyone
                    shared.stream_budget_available[dir as usize].notify_waiters();
                }
                Stream(StreamEvent::Finished { id }) => wake_stream_notify(id, &mut self.stopped),
                Stream(StreamEvent::Stopped { id, .. }) => {
                    wake_stream_notify(id, &mut self.stopped);
                    wake_stream(id, &mut self.blocked_writers);
                }
            }
        }
    }

    fn drive_timer(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(deadline) = self.inner.poll_timeout() else {
            self.timer_deadline = None;
            return false;
        };

        // Use the clock rather than the async timer to detect expiry: Sleep::poll
        // respects Tokio's cooperative budget and can return Pending for elapsed
        // deadlines.
        let now = self.runtime.now();
        if now >= deadline {
            self.inner.handle_timeout(now);
            self.timer_deadline = None;
            return true;
        }

        match &mut self.timer {
            // Avoid resetting the timer when the deadline is unchanged.
            Some(delay) if self.timer_deadline != Some(deadline) => {
                delay.as_mut().reset(deadline);
            }
            None => {
                self.timer = Some(self.runtime.new_timer(deadline));
            }
            _ => {}
        }
        self.timer_deadline = Some(deadline);

        let delay = self
            .timer
            .as_mut()
            .expect("timer must exist in this state")
            .as_mut();
        if delay.poll(cx).is_pending() {
            return false;
        }

        // The deadline elapsed in the window between the clock check and poll.
        self.inner.handle_timeout(self.runtime.now());
        self.timer_deadline = None;
        true
    }

    /// Transfer a driver registration to a caller which retires/wakes it only
    /// after releasing this state lock.
    pub(crate) fn take_driver_waker(&mut self) -> Option<Waker> {
        self.driver.take()
    }

    /// Wake up a blocked `Driver` task to process I/O
    pub(crate) fn wake(&mut self) {
        if let Some(x) = self.driver.take() {
            x.wake();
        }
    }

    /// Used to wake up all blocked futures when the connection becomes closed for any reason
    fn terminate(&mut self, reason: ConnectionError, shared: &Shared) {
        self.error = Some(reason.clone());
        if let Some(x) = self.on_handshake_data.take() {
            let _ = x.send(());
        }
        wake_all(&mut self.blocked_writers);
        wake_all(&mut self.blocked_readers);
        shared.stream_budget_available[Dir::Uni as usize].notify_waiters();
        shared.stream_budget_available[Dir::Bi as usize].notify_waiters();
        shared.stream_incoming[Dir::Uni as usize].notify_waiters();
        shared.stream_incoming[Dir::Bi as usize].notify_waiters();
        shared.datagram_received.notify_waiters();
        shared.datagrams_unblocked.notify_waiters();
        if let Some(x) = self.on_connected.take() {
            let _ = x.send(false);
        }
        wake_all_notify(&mut self.stopped);
        shared.closed.notify_waiters();
    }

    fn close(&mut self, error_code: VarInt, reason: Bytes, shared: &Shared) {
        self.inner.close(self.runtime.now(), error_code, reason);
        self.terminate(ConnectionError::LocallyClosed, shared);
        self.wake();
    }

    /// Close for a reason other than the application's explicit request
    pub(crate) fn implicit_close(&mut self, shared: &Shared) {
        self.close(0u32.into(), Bytes::new(), shared);
    }

    pub(crate) fn check_0rtt(&self) -> Result<(), ()> {
        if self.inner.is_handshaking()
            || self.inner.accepted_0rtt()
            || self.inner.side().is_server()
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if !self.inner.is_drained() {
            // Ensure the endpoint can tidy up
            let _ = self
                .endpoint_events
                .send((self.handle, proto::EndpointEvent::drained()));
        }
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("State").field("inner", &self.inner).finish()
    }
}

fn wake_stream(stream_id: StreamId, wakers: &mut FxHashMap<StreamId, Waker>) {
    if let Some(waker) = wakers.remove(&stream_id) {
        waker.wake();
    }
}

fn wake_all(wakers: &mut FxHashMap<StreamId, Waker>) {
    wakers.drain().for_each(|(_, waker)| waker.wake())
}

fn wake_stream_notify(stream_id: StreamId, wakers: &mut FxHashMap<StreamId, Arc<Notify>>) {
    if let Some(notify) = wakers.remove(&stream_id) {
        notify.notify_waiters()
    }
}

fn wake_all_notify(wakers: &mut FxHashMap<StreamId, Arc<Notify>>) {
    wakers
        .drain()
        .for_each(|(_, notify)| notify.notify_waiters())
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
}

/// The maximum amount of datagrams which will be produced in a single `drive_transmit` call
///
/// This limits the amount of CPU resources consumed by datagram generation,
/// and allows other tasks (like receiving ACKs) to run in between.
const MAX_TRANSMIT_DATAGRAMS: usize = 20;

/// The maximum amount of datagrams that are sent in a single transmit
///
/// This can be lower than the maximum platform capabilities, to avoid excessive
/// memory allocations when calling `poll_transmit()`. Benchmarks have shown
/// that numbers around 10 are a good compromise.
const MAX_TRANSMIT_SEGMENTS: usize = 10;
