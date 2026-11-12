use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::ready;
use h2::server::{Connection, Handshake, SendResponse};
use h2::{Reason, RecvStream};
use http::{Method, Request};
use pin_project_lite::pin_project;

use super::{ping, PipeToSendStream, SendBuf};
use crate::body::{Body, Incoming as IncomingBody};
use crate::common::date;
use crate::common::io::Compat;
use crate::common::time::Time;
use crate::ext::Protocol;
use crate::headers;
use crate::proto::h2::ping::Recorder;
use crate::proto::Dispatched;
use crate::rt::bounds::{Http2ServerConnExec, Http2UpgradedExec};
use crate::rt::{Read, Sleep, Write};
use crate::service::HttpService;

use crate::upgrade::{OnUpgrade, Pending, Upgraded};
use crate::Response;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
//
// At the same time, a server more often has multiple clients connected, and
// so is more likely to use more resources than a client would.
const DEFAULT_CONN_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 400; // 400kb
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) adaptive_window: bool,
    pub(crate) initial_conn_window_size: u32,
    pub(crate) initial_stream_window_size: u32,
    pub(crate) max_frame_size: u32,
    pub(crate) enable_connect_protocol: bool,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    pub(crate) max_local_error_reset_streams: Option<usize>,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) keep_alive_timeout: Duration,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) max_send_buffer_size: usize,
    pub(crate) header_table_size: Option<u32>,
    pub(crate) max_header_list_size: u32,
    pub(crate) date_header: bool,
    pub(crate) informational: Option<crate::ext::InformationalLimits>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            adaptive_window: false,
            initial_conn_window_size: DEFAULT_CONN_WINDOW,
            initial_stream_window_size: DEFAULT_STREAM_WINDOW,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            enable_connect_protocol: false,
            max_concurrent_streams: Some(200),
            max_pending_accept_reset_streams: None,
            max_local_error_reset_streams: Some(DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS),
            header_table_size: None,
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            idle_timeout: None,
            max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
            max_header_list_size: DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE,
            date_header: true,
            informational: None,
        }
    }
}

pin_project! {
    pub(crate) struct Server<T, S, B, E>
    where
        S: HttpService<IncomingBody>,
        B: Body,
    {
        exec: E,
        timer: Time,
        service: S,
        state: State<T, B>,
        date_header: bool,
        informational: Option<crate::ext::InformationalLimits>,
        close_pending: bool,
        idle_timeout: Option<Duration>,
    }
}

//#[expect(clippy::large_enum_variant, reason = "the whole future is boxed")]
#[allow(clippy::large_enum_variant)]
enum State<T, B>
where
    B: Body,
{
    Handshaking {
        ping_config: ping::Config,
        hs: Handshake<Compat<T>, SendBuf<B::Data>>,
    },
    Serving(Serving<T, B>),
}

struct Serving<T, B>
where
    B: Body,
{
    ping: Option<(ping::Recorder, ping::Ponger)>,
    conn: Connection<Compat<T>, SendBuf<B::Data>>,
    closing: Option<crate::Error>,
    timer: Time,
    idle_timeout: Option<Duration>,
    idle: Option<Pin<Box<dyn Sleep>>>,
    idle_closing: Option<Pin<Box<dyn Sleep>>>,
    date_header: bool,
    informational: Option<crate::ext::InformationalLimits>,
}

impl<T, S, B, E> Server<T, S, B, E>
where
    T: Read + Write + Unpin,
    S: HttpService<IncomingBody, ResBody = B>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    B: Body + 'static,
    E: Http2ServerConnExec<S::Future, B>,
{
    pub(crate) fn new(
        io: T,
        service: S,
        config: &Config,
        exec: E,
        timer: Time,
    ) -> Server<T, S, B, E> {
        let mut builder = h2::server::Builder::default();
        builder
            .initial_window_size(config.initial_stream_window_size)
            .initial_connection_window_size(config.initial_conn_window_size)
            .max_frame_size(config.max_frame_size)
            .max_header_list_size(config.max_header_list_size)
            .max_local_error_reset_streams(config.max_local_error_reset_streams)
            .max_send_buffer_size(config.max_send_buffer_size);
        if let Some(max) = config.max_concurrent_streams {
            builder.max_concurrent_streams(max);
        }
        if let Some(max) = config.max_pending_accept_reset_streams {
            builder.max_pending_accept_reset_streams(max);
        }
        if let Some(size) = config.header_table_size {
            builder.header_table_size(size);
        }
        if config.enable_connect_protocol {
            builder.enable_connect_protocol();
        }
        let handshake = builder.handshake(Compat::new(io));

        let bdp = if config.adaptive_window {
            Some(config.initial_stream_window_size)
        } else {
            None
        };

        let ping_config = ping::Config {
            bdp_initial_window: bdp,
            keep_alive_interval: config.keep_alive_interval,
            keep_alive_timeout: config.keep_alive_timeout,
            // If keep-alive is enabled for servers, always enabled while
            // idle, so it can more aggressively close dead connections.
            keep_alive_while_idle: true,
        };

        Server {
            exec,
            timer,
            state: State::Handshaking {
                ping_config,
                hs: handshake,
            },
            service,
            date_header: config.date_header,
            informational: config.informational,
            close_pending: false,
            idle_timeout: config.idle_timeout,
        }
    }

    pub(crate) fn graceful_shutdown(&mut self) {
        trace!("graceful_shutdown");
        match &mut self.state {
            State::Handshaking { .. } => {
                self.close_pending = true;
            }
            State::Serving(srv) => {
                if srv.closing.is_none() {
                    srv.conn.graceful_shutdown();
                }
            }
        }
    }
}

impl<T, S, B, E> Future for Server<T, S, B, E>
where
    T: Read + Write + Unpin,
    S: HttpService<IncomingBody, ResBody = B>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    B: Body + 'static,
    E: Http2ServerConnExec<S::Future, B>,
{
    type Output = crate::Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            let next = match &mut me.state {
                State::Handshaking { hs, ping_config } => {
                    let mut conn = ready!(Pin::new(hs).poll(cx).map_err(crate::Error::new_h2))?;
                    let ping = if ping_config.is_enabled() {
                        let pp = conn.ping_pong().expect("conn.ping_pong");
                        Some(ping::channel(pp, ping_config.clone(), me.timer.clone()))
                    } else {
                        None
                    };
                    State::Serving(Serving {
                        ping,
                        conn,
                        closing: None,
                        timer: me.timer.clone(),
                        idle_timeout: me.idle_timeout,
                        idle: None,
                        idle_closing: None,
                        date_header: me.date_header,
                        informational: me.informational,
                    })
                }
                State::Serving(srv) => {
                    // graceful_shutdown was called before handshaking finished,
                    if me.close_pending && srv.closing.is_none() {
                        srv.conn.graceful_shutdown();
                    }
                    ready!(srv.poll_server(cx, &mut me.service, &mut me.exec))?;
                    return Poll::Ready(Ok(Dispatched::Shutdown));
                }
            };
            me.state = next;
        }
    }
}

impl<T, B> Serving<T, B>
where
    T: Read + Write + Unpin,
    B: Body + 'static,
{
    fn poll_server<S, E>(
        &mut self,
        cx: &mut Context<'_>,
        service: &mut S,
        exec: &mut E,
    ) -> Poll<crate::Result<()>>
    where
        S: HttpService<IncomingBody, ResBody = B>,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        E: Http2ServerConnExec<S::Future, B>,
    {
        if let Some(closing) = &mut self.idle_closing {
            if self
                .conn
                .poll_closed(cx)
                .map_err(crate::Error::new_h2)?
                .is_ready()
                || closing.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(Ok(()));
            }
            return Poll::Pending;
        }
        if self.closing.is_none() {
            loop {
                self.poll_ping(cx);

                let next = match self.conn.poll_accept(cx) {
                    Poll::Ready(next) => {
                        self.idle = None;
                        next
                    }
                    Poll::Pending => {
                        if self.conn.has_active_streams() {
                            self.idle = None;
                        } else if let Some(duration) = self.idle_timeout {
                            let sleep = self.idle.get_or_insert_with(|| self.timer.sleep(duration));
                            if sleep.as_mut().poll(cx).is_ready() {
                                self.conn.graceful_shutdown();
                                // Give GOAWAY its usual bounded drain. An idle
                                // peer which ignores the shutdown PING cannot
                                // retain the connection indefinitely.
                                self.idle_closing = Some(self.timer.sleep(Duration::from_secs(1)));
                                self.idle = None;
                                cx.waker().wake_by_ref();
                            }
                        }
                        return Poll::Pending;
                    }
                };
                match next {
                    Some(Ok((req, mut respond))) => {
                        trace!("incoming request");
                        let content_length = headers::content_length_parse_all(req.headers());
                        let ping = self
                            .ping
                            .as_ref()
                            .map_or_else(ping::disabled, |ping| ping.0.clone());

                        // Record the headers received
                        ping.record_non_data();

                        let is_connect = req.method() == Method::CONNECT;
                        let (mut parts, stream) = req.into_parts();
                        let (mut req, connect_parts, continue_demand) = if !is_connect {
                            let expects_continue = self.informational.is_some()
                                && !stream.is_end_stream()
                                && content_length != Some(0)
                                && parts
                                    .headers
                                    .get_all(::http::header::EXPECT)
                                    .iter()
                                    .filter_map(|value| value.to_str().ok())
                                    .flat_map(|value| value.split(','))
                                    .any(|token| token.trim().eq_ignore_ascii_case("100-continue"));
                            let mut body = IncomingBody::h2(stream, content_length.into(), ping);
                            let continue_demand = if expects_continue {
                                let (send, receive) = tokio::sync::oneshot::channel();
                                body.h2_continue_on_read(send);
                                Some(receive)
                            } else {
                                None
                            };
                            (Request::from_parts(parts, body), None, continue_demand)
                        } else {
                            if content_length.map_or(false, |len| len != 0) {
                                warn!("h2 connect request with non-zero body not supported");
                                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                                return Poll::Ready(Ok(()));
                            }
                            let (pending, upgrade) = crate::upgrade::pending();
                            debug_assert!(parts.extensions.get::<OnUpgrade>().is_none());
                            parts.extensions.insert(upgrade);
                            (
                                Request::from_parts(parts, IncomingBody::empty()),
                                Some(ConnectParts {
                                    pending,
                                    ping,
                                    recv_stream: stream,
                                }),
                                None,
                            )
                        };

                        if let Some(protocol) = req.extensions_mut().remove::<h2::ext::Protocol>() {
                            req.extensions_mut().insert(Protocol::from_inner(protocol));
                        }

                        let informational = self.informational.map(|limits| {
                            crate::ext::install_informational(&mut req, limits, None)
                        });
                        let fut = H2Stream::new(
                            service.call(req),
                            connect_parts,
                            respond,
                            self.date_header,
                            exec.clone(),
                            informational,
                            ContinueOnRead::new(continue_demand),
                            self.timer.clone(),
                        );

                        exec.execute_h2stream(fut);
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(Err(crate::Error::new_h2(e)));
                    }
                    None => {
                        // no more incoming streams...
                        if let Some((ping, _)) = &self.ping {
                            ping.ensure_not_timed_out()?;
                        }

                        trace!("incoming connection complete");
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }

        debug_assert!(
            self.closing.is_some(),
            "poll_server broke loop without closing"
        );

        ready!(self.conn.poll_closed(cx).map_err(crate::Error::new_h2))?;

        Poll::Ready(Err(self.closing.take().expect("polled after error")))
    }

    fn poll_ping(&mut self, cx: &mut Context<'_>) {
        if let Some((_, estimator)) = &mut self.ping {
            match estimator.poll(cx) {
                Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                    self.conn.set_target_window_size(wnd);
                    let _ = self.conn.set_initial_window_size(wnd);
                }
                Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                    debug!("keep-alive timed out, closing connection");
                    self.conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                }
                Poll::Pending => {}
            }
        }
    }
}

pin_project! {
    #[allow(missing_debug_implementations)]
    pub struct H2Stream<F, B, E>
    where
        B: Body,
    {
        reply: SendResponse<SendBuf<B::Data>>,
        #[pin]
        state: H2StreamState<F, B>,
        response_head: Option<h2::ext::SendCompletion>,
        write_timer: Time,
        interim_write: Option<Box<super::response_write::Controlled<B::Data>>>,
        interim_ack: Option<tokio::sync::oneshot::Sender<()>>,
        ready_response: Option<Box<Response<B>>>,
        date_header: bool,
        exec: E,
    }
}

pin_project! {
    #[project = H2StreamStateProj]
    enum H2StreamState<F, B>
    where
        B: Body,
    {
        Service {
            #[pin]
            fut: F,
            connect_parts: Option<ConnectParts>,
            informational: Option<crate::ext::InformationalReceiver>,
            continue_on_read: ContinueOnRead,
        },
        Body {
            #[pin]
            pipe: PipeToSendStream<B>,
        },
        FlushingResponseHead,
    }
}

struct ConnectParts {
    pending: Pending,
    ping: Recorder,
    recv_stream: RecvStream,
}

impl<F, B, E> H2Stream<F, B, E>
where
    B: Body,
{
    fn new(
        fut: F,
        connect_parts: Option<ConnectParts>,
        respond: SendResponse<SendBuf<B::Data>>,
        date_header: bool,
        exec: E,
        informational: Option<crate::ext::InformationalReceiver>,
        continue_on_read: ContinueOnRead,
        write_timer: Time,
    ) -> H2Stream<F, B, E> {
        H2Stream {
            reply: respond,
            state: H2StreamState::Service {
                fut,
                connect_parts,
                informational,
                continue_on_read,
            },
            response_head: None,
            interim_write: None,
            interim_ack: None,
            ready_response: None,
            write_timer,
            date_header,
            exec,
        }
    }
}

struct ContinueOnRead {
    demand: Option<tokio::sync::oneshot::Receiver<()>>,
    expected: bool,
    sent: bool,
}

impl ContinueOnRead {
    fn new(demand: Option<tokio::sync::oneshot::Receiver<()>>) -> Self {
        Self {
            expected: demand.is_some(),
            demand,
            sent: false,
        }
    }

    fn poll_take(&mut self, cx: &mut Context<'_>) -> Option<Response<()>> {
        let demand = self.demand.as_mut()?;
        if let Poll::Ready(result) = Pin::new(demand).poll(cx) {
            self.demand = None;
            if result.is_ok() && !self.sent {
                let mut response = Response::new(());
                *response.status_mut() = ::http::StatusCode::CONTINUE;
                return Some(response);
            }
        }
        None
    }

}

fn install_control<D: bytes::Buf + 'static>(
    slot: &mut Option<Box<super::response_write::Controlled<D>>>,
    control: crate::ext::ResponseWriteControl, timer: &Time,
    reply: &mut SendResponse<SendBuf<D>>,
) -> crate::Result<()> {
    let result = (|| {
    if let Some(active) = slot.as_ref() {
        if active.owner().same_control(&control) { return Ok(()); }
        return Err(crate::Error::new_body_write("HTTP/2 write control already installed"));
    }
    if std::any::TypeId::of::<D>() != std::any::TypeId::of::<Bytes>() {
        return Err(crate::Error::new_body_write("HTTP/2 controlled response requires Bytes data"));
    }
    let owner = control.claim().map_err(crate::Error::new_body_write)?;
    *slot = Some(Box::new(super::response_write::Controlled::new(owner, timer.clone(), None, false)));
    Ok(())
    })();
    if result.is_err() { reply.send_reset(Reason::CANCEL); }
    result
}

fn send_informational<D: bytes::Buf + 'static>(
    reply: &mut SendResponse<SendBuf<D>>, mut response: Response<()>,
    ack: Option<tokio::sync::oneshot::Sender<()>>, continuation: &mut ContinueOnRead,
    controlled: &mut Option<Box<super::response_write::Controlled<D>>>,
    pending_ack: &mut Option<tokio::sync::oneshot::Sender<()>>, timer: &Time,
) -> crate::Result<()> {
    if let Some(control) = response.extensions_mut().remove::<crate::ext::ResponseWriteControl>() {
        install_control(controlled, control, timer, reply)?;
    }
    let is_continue = response.status() == ::http::StatusCode::CONTINUE;
    if is_continue && continuation.expected && continuation.sent {
        if let Some(ack) = ack { let _ = ack.send(()); }
        return Ok(());
    }
    let fields = response.headers_mut();
    // Remove every Connection nomination, not just the first field value.
    // The map is bounded by the per-stream informational header budget.
    let nominated: Vec<_> = fields
        .get_all(::http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| ::http::header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        fields.remove(name);
    }
    super::strip_connection_headers(fields, super::MessageKind::Response);
    fields.remove(::http::header::TE);
    fields.remove(::http::header::CONTENT_LENGTH);
    fields.remove(::http::header::TRANSFER_ENCODING);
    if let Some(writer) = controlled.as_mut() {
        writer.owner().start_boundary(0, timer.now()).map_err(crate::Error::new_body_write)?;
        let receipt = reply.send_informational_observed_with_policy(
            response, writer.owner().retention(),
            Some(super::response_write::compiled_policy(writer.owner()).map_err(crate::Error::new_body_write)?),
        ).map_err(crate::Error::new_h2)?;
        writer.set_header(receipt, false);
        *pending_ack = ack;
    } else {
        reply.send_informational(response).map_err(crate::Error::new_h2)?;
        if let Some(ack) = ack { let _ = ack.send(()); }
    }
    continuation.sent |= is_continue;
    Ok(())
}

macro_rules! reply {
    ($me:expr, $res:expr, $eos:expr) => {{
        match $me.reply.send_response($res, $eos) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("send response error: {}", e);
                $me.reply.send_reset(Reason::INTERNAL_ERROR);
                return Poll::Ready(Err(crate::Error::new_h2(e)));
            }
        }
    }};
}

impl<F, B, Ex, E> H2Stream<F, B, Ex>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Ex: Http2UpgradedExec<B::Data>,
    E: Into<Box<dyn StdError + Send + Sync>>,
{
    fn poll2(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        let mut me = self.as_mut().project();
        loop {
            if let Some(completion) = me.response_head.as_ref() {
                match completion.poll_outcome(cx) {
                    Poll::Ready(h2::ext::SendOutcome::Flushed(_)) => {
                        *me.response_head = None;
                    }
                    Poll::Ready(h2::ext::SendOutcome::Abandoned) => {
                        return Poll::Ready(Err(crate::Error::new_body_write(
                            "HTTP/2 response head flush abandoned",
                        )));
                    }
                    Poll::Pending => {}
                }
            }
            let next = match me.state.as_mut().project() {
                H2StreamStateProj::Service {
                    fut: h,
                    connect_parts,
                    informational,
                    continue_on_read,
                } => {
                    if let Some(writer) = me.interim_write.as_mut() {
                        if let Poll::Ready(reason) = me.reply.poll_reset(cx).map_err(crate::Error::new_h2)? {
                            return Poll::Ready(Err(crate::Error::new_h2(reason.into())));
                        }
                        match writer.poll_header(cx) {
                            Poll::Ready(Ok(())) => {
                                if let Some(ack) = me.interim_ack.take() { let _ = ack.send(()); }
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    // Binding is metadata only; it never starts a write boundary.
                    if let Some(control) = informational.as_mut().and_then(|rx| rx.poll_write_control(cx)) {
                        install_control(me.interim_write, control, me.write_timer, me.reply)?;
                        continue;
                    }
                    let res = match me.ready_response.take().map(|response| Poll::Ready(Ok(*response)))
                        .unwrap_or_else(|| h.poll(cx)) {
                        Poll::Ready(Ok(r)) => r,
                        Poll::Pending => {
                            if let Some(control) = informational.as_mut().and_then(|rx| rx.poll_write_control(cx)) {
                                install_control(me.interim_write, control, me.write_timer, me.reply)?;
                                // Arm even hard-only policy without an information head.
                                continue;
                            }
                            // Response is not yet ready, so we want to check if the client has sent a
                            // RST_STREAM frame which would cancel the current request.
                            if let Poll::Ready(reason) =
                                me.reply.poll_reset(cx).map_err(crate::Error::new_h2)?
                            {
                                debug!("stream received RST_STREAM: {:?}", reason);
                                return Poll::Ready(Err(crate::Error::new_h2(reason.into())));
                            }
                            if let Some(rx) = informational {
                                if let Poll::Ready(crate::ext::InformationalHead { response, ack, .. }) = rx.poll_take(cx) {
                                    send_informational(me.reply, response, Some(ack), continue_on_read,
                                        me.interim_write, me.interim_ack, me.write_timer)?;
                                    if me.interim_write.is_some() { continue; }
                                }
                            }
                            if let Some(response) = continue_on_read.poll_take(cx) {
                                send_informational(me.reply, response, None, continue_on_read,
                                    me.interim_write, me.interim_ack, me.write_timer)?;
                                if me.interim_write.is_some() { continue; }
                            }
                            // The application may add a nested scoped policy while
                            // being polled. Re-read after it returns Pending, too.
                            if let Some(writer) = me.interim_write.as_mut() {
                                if let Poll::Ready(Err(e)) = writer.poll_header(cx) {
                                    return Poll::Ready(Err(e));
                                }
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            let err = crate::Error::new_user_service(e);
                            warn!("http2 service errored: {}", err);
                            me.reply.send_reset(err.h2_reason());
                            return Poll::Ready(Err(err));
                        }
                    };

                    if let Some(control) = informational.as_mut().and_then(|rx| rx.poll_write_control(cx)) {
                        install_control(me.interim_write, control, me.write_timer, me.reply)?;
                    }
                    if let Some(writer) = me.interim_write.as_mut() {
                        if let Poll::Ready(Err(e)) = writer.poll_header(cx) {
                            return Poll::Ready(Err(e));
                        }
                    }
                    if let Some(mut rx) = informational.take() {
                        if let Some(crate::ext::InformationalHead { response, ack, .. }) = rx.close_take() {
                            send_informational(me.reply, response, Some(ack), continue_on_read,
                                me.interim_write, me.interim_ack, me.write_timer)?;
                            if me.interim_write.is_some() {
                                *me.ready_response = Some(Box::new(res));
                                continue;
                            }
                        }
                    }
                    if let Some(response) = continue_on_read.poll_take(cx) {
                        send_informational(me.reply, response, None, continue_on_read,
                            me.interim_write, me.interim_ack, me.write_timer)?;
                        if me.interim_write.is_some() {
                            *me.ready_response = Some(Box::new(res));
                            continue;
                        }
                    }

                    let (head, body) = res.into_parts();
                    let mut res = ::http::Response::from_parts(head, ());
                    super::strip_connection_headers(
                        res.headers_mut(),
                        super::MessageKind::Response,
                    );

                    // set Date header if it isn't already set if instructed
                    if *me.date_header {
                        res.headers_mut()
                            .entry(::http::header::DATE)
                            .or_insert_with(date::update_and_header_value);
                    }

                    if let Some(connect_parts) = connect_parts.take() {
                        if res.status().is_success() {
                            if me.interim_write.is_some() || res.extensions().get::<crate::ext::ResponseWriteControl>().is_some() {
                                me.reply.send_reset(Reason::CANCEL);
                                return Poll::Ready(Err(crate::Error::new_body_write("HTTP/2 controlled CONNECT tunnel is not supported")));
                            }
                            if headers::content_length_parse_all(res.headers())
                                .map_or(false, |len| len != 0)
                            {
                                warn!("h2 successful response to CONNECT request with body not supported");
                                me.reply.send_reset(h2::Reason::INTERNAL_ERROR);
                                return Poll::Ready(Err(crate::Error::new_user_header()));
                            }
                            if res
                                .headers_mut()
                                .remove(::http::header::CONTENT_LENGTH)
                                .is_some()
                            {
                                warn!("successful response to CONNECT request disallows content-length header");
                            }
                            let send_stream = reply!(me, res, false);
                            let (h2_up, up_task) = super::upgrade::pair(
                                send_stream,
                                connect_parts.recv_stream,
                                connect_parts.ping,
                            );
                            connect_parts
                                .pending
                                .fulfill(Upgraded::new(h2_up, Bytes::new()));
                            self.exec.execute_upgrade(up_task);
                            return Poll::Ready(Ok(()));
                        }
                    }

                    if let Some(control) = res
                        .extensions_mut()
                        .remove::<crate::ext::ResponseWriteControl>()
                    {
                        install_control(me.interim_write, control, me.write_timer, me.reply)?;
                    }
                    if let Some(mut writer) = me.interim_write.take() {
                        let owner = writer.owner();
                        let ended = body.is_end_stream();
                        if !ended {
                            if let Some(len) = body.size_hint().exact() {
                                headers::set_content_length_if_missing(res.headers_mut(), len);
                            }
                        }
                        owner
                            .start_boundary(0, me.write_timer.now())
                            .map_err(crate::Error::new_body_write)?;
                        let (body_tx, head) = me
                            .reply
                            .send_response_observed_with_policy(
                                res,
                                ended,
                                owner.retention(),
                                Some(super::response_write::compiled_policy(owner).map_err(crate::Error::new_body_write)?),
                            )
                            .map_err(crate::Error::new_h2)?;
                        writer.set_header(head, ended);
                        me.state.set(H2StreamState::Body {
                            pipe: PipeToSendStream::with_controlled(body, body_tx, writer),
                        });
                        continue;
                    }
                    if !res.status().is_informational()
                        && res
                            .extensions_mut()
                            .remove::<crate::ext::AwaitResponseHeadFlush>()
                            .is_some()
                    {
                        let completion = h2::ext::SendCompletion::new();
                        res.extensions_mut().insert(completion.clone());
                        *me.response_head = Some(completion);
                    }
                    if !body.is_end_stream() {
                        // automatically set Content-Length from body...
                        if let Some(len) = body.size_hint().exact() {
                            headers::set_content_length_if_missing(res.headers_mut(), len);
                        }

                        let body_tx = reply!(me, res, false);
                        H2StreamState::Body {
                            pipe: PipeToSendStream::new(body, body_tx),
                        }
                    } else {
                        reply!(me, res, true);
                        if me.response_head.is_none() {
                            return Poll::Ready(Ok(()));
                        }
                        H2StreamState::FlushingResponseHead
                    }
                }
                H2StreamStateProj::Body { pipe } => match pipe.poll(cx) {
                    Poll::Ready(Ok(())) if me.response_head.is_some() => {
                        H2StreamState::FlushingResponseHead
                    }
                    result => return result,
                },
                H2StreamStateProj::FlushingResponseHead => {
                    // The existing reply handle keeps the stream referenced
                    // even after the response body and its send handle finish.
                    return if me.response_head.is_some() {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(()))
                    };
                }
            };
            me.state.set(next);
        }
    }
}

impl<F, B, Ex, E> Future for H2Stream<F, B, Ex>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Ex: Http2UpgradedExec<B::Data>,
    E: Into<Box<dyn StdError + Send + Sync>>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().poll2(cx) {
            Poll::Ready(Err(_e)) => {
                let me = self.project();
                if me.interim_write.is_some() { me.reply.send_reset(Reason::CANCEL); }
                debug!("stream error: {}", _e);
                Poll::Ready(())
            }
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}
