// Portions derived from Go net/dnsclient_unix.go and dnsmessage, BSD-3-Clause.
// See LICENSES/Go-BSD-3-Clause.txt.
//! Go `tryOneName`/`exchange` per Hickory question behind the framed stream API.
use super::proxy_dns_socket::DnsSocket;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::{Stream, stream::FuturesUnordered};
use hickory_resolver::net::runtime::{
    DnsTcpStream, DnsUdpSocket, RuntimeProvider, TokioRuntimeProvider,
};
use hickory_resolver::proto::op::{Message, ResponseCode};
use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub(super) type Dial = Arc<
    dyn Fn(Option<Instant>) -> Pin<Box<dyn Future<Output = io::Result<DnsSocket>> + Send>>
        + Send
        + Sync,
>;

/// Go `dnsConfig` subset driving `tryOneName`, plus Caddy's optional Dial.
pub(super) struct Source {
    /// Go `cfg.servers`. A custom Dial ignores the address, but Go still
    /// iterates it, so it always defines the per-attempt round size.
    pub(super) servers: Arc<[SocketAddr]>,
    pub(super) dial: Option<Dial>,
    pub(super) attempts: usize,
    pub(super) use_tcp: bool,
    pub(super) rotate: Option<Arc<AtomicU32>>,
}
pub(super) type Exchange = Arc<Source>;

type Job = Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>;
struct WakeOnDrop(Option<Waker>);
impl Drop for WakeOnDrop {
    fn drop(&mut self) {
        if let Some(waker) = self.0.take() {
            waker.wake();
        }
    }
}
const CAPACITY: usize = 4;
const MAX_FRAME: usize = 65537;

struct State {
    write: Vec<u8>,
    jobs: FuturesUnordered<Job>,
    ready: VecDeque<io::Result<Vec<u8>>>,
    read: Vec<u8>,
    position: usize,
    reader: Option<Waker>,
    closed: bool,
}
pub(super) struct ExchangeStream {
    state: Mutex<State>,
    source: Exchange,
    logical: SocketAddr,
    timeout: Duration,
    stop: CancellationToken,
}

impl ExchangeStream {
    pub(super) fn new(
        source: Exchange,
        logical: SocketAddr,
        timeout: Duration,
        stop: CancellationToken,
    ) -> Self {
        Self {
            state: Mutex::new(State {
                write: Vec::new(),
                jobs: FuturesUnordered::new(),
                ready: VecDeque::new(),
                read: Vec::new(),
                position: 0,
                reader: None,
                closed: false,
            }),
            source,
            logical,
            timeout,
            stop,
        }
    }
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("DNS exchange state unavailable"))
    }
    fn enqueue(&self, state: &mut State) -> io::Result<Option<Waker>> {
        if state.write.len() < 2 {
            return Ok(None);
        }
        let length = usize::from(u16::from_be_bytes([state.write[0], state.write[1]])) + 2;
        if state.write.len() != length {
            return Ok(None);
        }
        let outstanding =
            state.jobs.len() + state.ready.len() + usize::from(state.position < state.read.len());
        if outstanding >= CAPACITY {
            return Err(io::Error::other("custom DNS query capacity exceeded"));
        }
        let mut query = std::mem::take(&mut state.write);
        query.drain(..2);
        let request = Message::from_vec(&query)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut failure = Message::error_msg(
            request.metadata.id,
            request.metadata.op_code,
            ResponseCode::ServFail,
        );
        failure.metadata.recursion_desired = request.metadata.recursion_desired;
        failure.queries = request.queries;
        failure.edns = request.edns;
        let failure = failure
            .to_vec()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let source = self.source.clone();
        let (logical, timeout, stop) = (self.logical, self.timeout, self.stop.clone());
        state.jobs.push(Box::pin(async move {
            tokio::select! { biased;
                _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "DNS runtime stopped")),
                response = try_one_name(&source, query, failure, timeout, logical) => Ok(response),
            }
        }));
        Ok(state.reader.take())
    }
}
impl AsyncRead for ExchangeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.lock()?;
        if state.closed {
            return Poll::Ready(Ok(0));
        }
        if state.position == state.read.len() {
            state.reader = Some(cx.waker().clone());
            if state.ready.is_empty() {
                match Pin::new(&mut state.jobs).poll_next(cx) {
                    Poll::Ready(Some(response)) => state.ready.push_back(response),
                    Poll::Ready(None) | Poll::Pending => return Poll::Pending,
                }
            }
            let response = state
                .ready
                .pop_front()
                .ok_or_else(|| io::Error::other("DNS response ownership unavailable"))??;
            let length = u16::try_from(response.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS response exceeds 65535 bytes",
                )
            })?;
            state.read.clear();
            state.read.extend_from_slice(&length.to_be_bytes());
            state.read.extend_from_slice(&response);
            state.position = 0;
        }
        let length = out.len().min(state.read.len() - state.position);
        out[..length].copy_from_slice(&state.read[state.position..state.position + length]);
        state.position += length;
        Poll::Ready(Ok(length))
    }
}

impl AsyncWrite for ExchangeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut wake = WakeOnDrop(None);
        let mut state = self.lock()?;
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "DNS exchange closed",
            )));
        }
        wake.0 = self.enqueue(&mut state)?;
        let mut consumed = 0;
        for _ in 0..2 {
            if consumed == input.len() {
                break;
            }
            let target = if state.write.len() < 2 {
                2
            } else {
                usize::from(u16::from_be_bytes([state.write[0], state.write[1]])) + 2
            };
            let length = (target - state.write.len()).min(input.len() - consumed);
            state
                .write
                .extend_from_slice(&input[consumed..consumed + length]);
            consumed += length;
            if target > MAX_FRAME {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS frame exceeds limit",
                )));
            }
            if state.write.len() == target && target >= 2 && (target != 2 || state.write == [0, 0])
            {
                break;
            }
        }
        Poll::Ready(Ok(consumed))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut wake = WakeOnDrop(None);
        let mut state = self.lock()?;
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "DNS exchange closed",
            )));
        }
        wake.0 = self.enqueue(&mut state)?;
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut wake = WakeOnDrop(None);
        let mut state = self.lock()?;
        let partial = !state.write.is_empty();
        state.closed = true;
        state.jobs = FuturesUnordered::new();
        state.ready.clear();
        state.write.clear();
        state.read.clear();
        state.position = 0;
        wake.0 = state.reader.take();
        if partial {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS exchange closed with an incomplete frame",
            )));
        }
        Poll::Ready(Ok(()))
    }
}
impl DnsTcpStream for ExchangeStream {
    type Time = <TokioRuntimeProvider as RuntimeProvider>::Timer;
}
/// Go `tryOneName`: the only retry loop. Hickory sends once and must stop on
/// each of the three possible outputs (answer, no-such-host, SERVFAIL).
async fn try_one_name(
    source: &Source,
    query: Vec<u8>,
    failure: Vec<u8>,
    timeout: Duration,
    logical: SocketAddr,
) -> Vec<u8> {
    let Some(question) = wire::Question::parse(&query) else {
        return failure;
    };
    let count = source.servers.len() as u32;
    if count == 0 {
        return failure;
    }
    let offset = source
        .rotate
        .as_ref()
        .map_or(0, |next| next.fetch_add(1, Ordering::Relaxed));
    for _ in 0..source.attempts {
        for j in 0..count {
            let server = source.servers[(offset.wrapping_add(j) % count) as usize];
            let Ok(mut response) =
                exchange(source, server, &query, &question, timeout, logical).await
            else {
                continue;
            };
            match wire::verdict(&response, question.qtype) {
                wire::Verdict::Next => {}
                wire::Verdict::Answer => {
                    response[..2].copy_from_slice(&query[..2]);
                    // Hickory would re-send a truncated reply (pool push_front).
                    response[2] &= !0x02;
                    return response;
                }
                wire::Verdict::NoSuchHost => {
                    return wire::no_such_host(&query, &response, question.end);
                }
            }
        }
    }
    failure
}

/// Go `Resolver.exchange`: fresh ID per call, a fresh deadline per leg; a
/// truncated reply only advances past the logical UDP leg.
async fn exchange(
    source: &Source,
    server: SocketAddr,
    query: &[u8],
    question: &wire::Question,
    timeout: Duration,
    logical: SocketAddr,
) -> io::Result<Vec<u8>> {
    let id = super::proxy_policy::random_below(1 << 16)
        .map_err(|error| io::Error::other(format!("random source: {error}")))?;
    let id = u16::try_from(id)
        .map_err(|_| io::Error::other("random source out of range"))?
        .to_be_bytes();
    let mut query = query.to_vec();
    query[..2].copy_from_slice(&id);
    let legs: &[bool] = if source.use_tcp {
        &[true]
    } else {
        &[false, true]
    };
    for &tcp in legs {
        let deadline = Instant::now().checked_add(timeout);
        let leg = async {
            let socket = match &source.dial {
                Some(dial) => dial(deadline).await?,
                None => {
                    super::proxy_dns_dial::connect(vec![server], tcp, None, 0, deadline, logical)
                        .await?
                }
            };
            round_trip(&socket, &query, question, id, logical).await
        };
        let response = tokio::time::timeout(timeout, leg)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS exchange leg timed out"))??;
        if !tcp && response[2] & 0x02 != 0 {
            continue;
        }
        return Ok(response);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no answer from DNS server",
    ))
}

/// Go `dnsPacketRoundTrip`/`dnsStreamRoundTrip` + `SkipQuestion` check.
async fn round_trip(
    socket: &DnsSocket,
    query: &[u8],
    question: &wire::Question,
    id: [u8; 2],
    logical: SocketAddr,
) -> io::Result<Vec<u8>> {
    let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_owned());
    if socket.send_to(query, logical).await? != query.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short DNS question write",
        ));
    }
    let mut response = vec![0; usize::from(u16::MAX)];
    for _ in 0..32 {
        let (length, peer) = socket.recv_from(&mut response).await?;
        if peer != logical {
            return Err(invalid("DNS peer mismatch"));
        }
        match question.answered_by(&response[..length], id) {
            Some(1) => {
                response.truncate(length);
                return Ok(response);
            }
            Some(_) => return Err(invalid("DNS response carries extra questions")),
            None if socket.is_stream() => {
                return Err(invalid("DNS response does not match question"));
            }
            None => {}
        }
    }
    Err(invalid("DNS response did not match question"))
}

/// Go `golang.org/x/net/dns/dnsmessage` subset used by checkHeader/skipToAnswer.
mod wire {
    const OPT: u16 = 41;

    pub(super) enum Verdict {
        Answer,
        NoSuchHost,
        Next,
    }

    pub(super) struct Question {
        lower: Vec<u8>,
        pub(super) qtype: u16,
        qclass: u16,
        pub(super) end: usize,
    }

    impl Question {
        pub(super) fn parse(query: &[u8]) -> Option<Self> {
            if query.len() < 12 || be16(query, 4)? == 0 {
                return None;
            }
            let (lower, qtype, qclass, end) = question(query, 12)?;
            Some(Self {
                lower,
                qtype,
                qclass,
                end,
            })
        }
        /// Go `p.Start` + `p.Question` + `checkResponse`; QDCOUNT on match.
        pub(super) fn answered_by(&self, msg: &[u8], id: [u8; 2]) -> Option<u16> {
            if msg.len() < 12 || msg[..2] != id || msg[2] & 0x80 == 0 {
                return None;
            }
            let count = be16(msg, 4)?;
            if count == 0 {
                return None;
            }
            let (lower, qtype, qclass, _) = question(msg, 12)?;
            (qtype == self.qtype && qclass == self.qclass && lower == self.lower).then_some(count)
        }
    }

    /// Go `checkHeader` followed by `skipToAnswer`.
    pub(super) fn verdict(msg: &[u8], qtype: u16) -> Verdict {
        let Some(start) = name(msg, 12, None).map(|end| end + 4) else {
            return Verdict::Next;
        };
        let (Some(an), Some(ns), Some(ar)) = (be16(msg, 6), be16(msg, 8), be16(msg, 10)) else {
            return Verdict::Next;
        };
        let (aa, ra) = (msg[2] & 0x04 != 0, msg[3] & 0x80 != 0);
        let (rcode, has_add) = extended_rcode(msg, start, an, ns, ar, u16::from(msg[3] & 0x0F));
        if rcode == 3 {
            return Verdict::NoSuchHost;
        }
        if an > 0 && header(msg, start).is_none() {
            return Verdict::Next; // errCannotUnmarshalDNSMessage
        }
        if rcode == 0 && !aa && !ra && an == 0 && !has_add {
            return Verdict::Next; // errLameReferral
        }
        if rcode != 0 {
            return Verdict::Next; // errServer(Temporarily)Misbehaving
        }
        let mut off = start;
        for _ in 0..an {
            let Some(rr) = header(msg, off) else {
                return Verdict::Next;
            };
            if rr.rtype == qtype {
                return Verdict::Answer;
            }
            off = rr.data + rr.len;
            if off > msg.len() {
                return Verdict::Next;
            }
        }
        Verdict::NoSuchHost
    }

    /// Header + question only, so Hickory has nothing to chase (e.g. CNAME).
    pub(super) fn no_such_host(query: &[u8], response: &[u8], end: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(end);
        out.extend_from_slice(&query[..2]);
        out.extend_from_slice(&[response[2] & !0x02, response[3], 0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&query[12..end]);
        out
    }

    fn extended_rcode(
        msg: &[u8],
        mut off: usize,
        an: u16,
        ns: u16,
        ar: u16,
        rcode: u16,
    ) -> (u16, bool) {
        for _ in 0..u32::from(an) + u32::from(ns) {
            match skip_rr(msg, off) {
                Some(next) => off = next,
                None => return (rcode, false),
            }
        }
        let mut has_add = false;
        for _ in 0..ar {
            let Some(rr) = header(msg, off) else {
                return (rcode, has_add);
            };
            has_add = true;
            if rr.rtype == OPT {
                return ((((rr.ttl >> 24) << 4) as u16) | rcode, true);
            }
            off = rr.data + rr.len;
            if off > msg.len() {
                return (rcode, true);
            }
        }
        (rcode, has_add)
    }

    struct Rr {
        rtype: u16,
        ttl: u32,
        data: usize,
        len: usize,
    }

    /// Go `ResourceHeader.unpack` (rdata bounds are checked by the caller).
    fn header(msg: &[u8], off: usize) -> Option<Rr> {
        let off = name(msg, off, None)?;
        Some(Rr {
            rtype: be16(msg, off)?,
            ttl: be32(msg, off + 4)?,
            len: usize::from(be16(msg, off + 8)?),
            data: off + 10,
        })
    }

    /// Go `skipResource`.
    fn skip_rr(msg: &[u8], off: usize) -> Option<usize> {
        let off = skip_name(msg, off)?;
        let end = off + 10 + usize::from(be16(msg, off + 8)?);
        (end <= msg.len()).then_some(end)
    }

    fn question(msg: &[u8], off: usize) -> Option<(Vec<u8>, u16, u16, usize)> {
        let mut lower = Vec::new();
        let off = name(msg, off, Some(&mut lower))?;
        Some((lower, be16(msg, off)?, be16(msg, off + 2)?, off + 4))
    }

    /// Go `Name.unpack`: <=10 pointers, no reserved labels, no '.' in labels, <=255.
    fn name(msg: &[u8], off: usize, mut lower: Option<&mut Vec<u8>>) -> Option<usize> {
        let (mut cur, mut next, mut ptrs, mut len) = (off, None, 0u8, 0usize);
        loop {
            let c = usize::from(*msg.get(cur)?);
            cur += 1;
            match c & 0xC0 {
                0x00 if c == 0 => break,
                0x00 => {
                    let label = msg.get(cur..cur + c)?;
                    len += c + 1;
                    if label.contains(&b'.') || len > 255 {
                        return None;
                    }
                    if let Some(out) = lower.as_deref_mut() {
                        out.push(c as u8);
                        out.extend(label.iter().map(u8::to_ascii_lowercase));
                    }
                    cur += c;
                }
                0xC0 => {
                    let low = usize::from(*msg.get(cur)?);
                    cur += 1;
                    next.get_or_insert(cur);
                    ptrs += 1;
                    if ptrs > 10 {
                        return None;
                    }
                    cur = ((c & 0x3F) << 8) | low;
                }
                _ => return None,
            }
        }
        Some(next.unwrap_or(cur))
    }

    /// Go `skipName`.
    fn skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
        loop {
            let c = usize::from(*msg.get(off)?);
            off += 1;
            match c & 0xC0 {
                0x00 if c == 0 => return Some(off),
                0x00 => {
                    off += c;
                    if off > msg.len() {
                        return None;
                    }
                }
                0xC0 => return Some(off + 1),
                _ => return None,
            }
        }
    }

    fn be16(msg: &[u8], off: usize) -> Option<u16> {
        Some(u16::from_be_bytes(msg.get(off..off + 2)?.try_into().ok()?))
    }
    fn be32(msg: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_be_bytes(msg.get(off..off + 4)?.try_into().ok()?))
    }
}
