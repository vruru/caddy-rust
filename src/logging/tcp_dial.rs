// Copyright 2009 The Go Authors. BSD-3-Clause.
//! Caddy uses Go net.DialTimeout. Keep its per-family serial attempts and
//! 300 ms dual-stack fallback while the writer actor owns both sockets.
use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use std::{
    io,
    net::SocketAddr,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

const FALLBACK_DELAY: Duration = Duration::from_millis(300);
const MIN_PARTIAL: Duration = Duration::from_secs(2);
const TCP_KEEPALIVE: Duration = Duration::from_secs(15);

pub(super) fn partial_deadline(
    now: Instant,
    overall: Option<Instant>,
    remaining_addresses: usize,
) -> io::Result<Option<Instant>> {
    let Some(overall) = overall else {
        return Ok(None);
    };
    let remaining = overall
        .checked_duration_since(now)
        .filter(|time| !time.is_zero())
        .ok_or(io::ErrorKind::TimedOut)?;
    let share = remaining / u32::try_from(remaining_addresses.max(1)).unwrap_or(u32::MAX);
    Ok(Some(now + share.max(MIN_PARTIAL).min(remaining)))
}

pub(super) fn dial_tcp(
    mut addresses: Vec<SocketAddr>,
    dual_stack: bool,
    overall: Option<Instant>,
) -> io::Result<Socket> {
    let mut fallback = Vec::new();
    if dual_stack && let Some(first) = addresses.first() {
        let first_is_v4 = first.is_ipv4();
        addresses.retain(|address| {
            if address.is_ipv4() == first_is_v4 {
                true
            } else {
                fallback.push(*address);
                false
            }
        });
    }
    let fallback_at = Instant::now() + FALLBACK_DELAY;
    let mut racers = [Racer::new(addresses), Racer::new(fallback)];
    let mut fallback_started = racers[1].finished();

    loop {
        if expired(overall) {
            return Err(racers[0].take_error(io::ErrorKind::TimedOut));
        }
        if let Some(winner) = racers[0].advance(overall) {
            return Ok(winner);
        }
        fallback_started |= racers[0].finished() || Instant::now() >= fallback_at;
        if fallback_started && let Some(winner) = racers[1].advance(overall) {
            return Ok(winner);
        }
        if racers.iter().all(Racer::finished) {
            return Err(racers[0].take_error(io::ErrorKind::AddrNotAvailable));
        }
        let mut until = overall;
        if !fallback_started {
            until = min_deadline(until, Some(fallback_at));
        }
        let mut pollfds = [libc::pollfd {
            fd: -1,
            events: libc::POLLOUT,
            revents: 0,
        }; 2];
        for (racer, pollfd) in racers.iter().zip(&mut pollfds) {
            if let Some(active) = &racer.active {
                pollfd.fd = active.socket.as_raw_fd();
                until = min_deadline(until, active.deadline);
            }
        }
        // SAFETY: both initialized pollfd elements are writable; the racers
        // own the descriptors for this whole call, and -1 is ignored by poll.
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, poll_millis(until)) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // If both become ready in one syscall, use the primary deterministically.
        // Returning drops both racers, immediately closing any losing socket.
        for (racer, pollfd) in racers.iter_mut().zip(pollfds) {
            if let Some(winner) = racer.ready(pollfd.revents) {
                return Ok(winner);
            }
        }
    }
}

struct Racer {
    addrs: std::vec::IntoIter<SocketAddr>,
    current: Option<Candidate>,
    active: Option<Pending>,
    first_error: Option<io::Error>,
}
#[derive(Clone, Copy)]
struct Candidate {
    address: SocketAddr,
    retries: u8,
    deadline: Option<Instant>,
}
struct Pending {
    socket: Socket,
    deadline: Option<Instant>,
}
enum Attempt {
    Connected(Socket),
    Pending(Socket),
}
impl Racer {
    fn new(addresses: Vec<SocketAddr>) -> Self {
        Self {
            addrs: addresses.into_iter(),
            current: None,
            active: None,
            first_error: None,
        }
    }
    fn finished(&self) -> bool {
        self.current.is_none() && self.addrs.len() == 0
    }
    fn take_error(&mut self, otherwise: io::ErrorKind) -> io::Error {
        self.first_error.take().unwrap_or_else(|| otherwise.into())
    }
    fn failed(&mut self, error: io::Error) {
        self.first_error.get_or_insert(error);
        self.current = None;
    }
    fn retry(&mut self) -> bool {
        let Some(current) = &mut self.current else {
            return false;
        };
        if current.retries == 2 || expired(current.deadline) {
            return false;
        }
        current.retries += 1;
        true
    }
    fn advance(&mut self, overall: Option<Instant>) -> Option<Socket> {
        while self.active.is_none() {
            if self.current.is_none() {
                let count = self.addrs.len();
                let address = self.addrs.next()?;
                let deadline = match partial_deadline(Instant::now(), overall, count) {
                    Ok(deadline) => deadline,
                    Err(error) => {
                        self.failed(error);
                        return None;
                    }
                };
                self.current = Some(Candidate {
                    address,
                    retries: 0,
                    deadline,
                });
            }
            let candidate = self.current?;
            if expired(candidate.deadline) {
                self.failed(io::ErrorKind::TimedOut.into());
                continue;
            }
            match start(candidate.address) {
                Ok(Attempt::Pending(socket)) => {
                    self.active = Some(Pending {
                        socket,
                        deadline: candidate.deadline,
                    });
                }
                Ok(Attempt::Connected(socket)) => {
                    if let Some(winner) = self.connected(socket, candidate) {
                        return Some(winner);
                    }
                }
                Err(error) => self.connect_error(error),
            }
        }
        None
    }
    fn ready(&mut self, events: libc::c_short) -> Option<Socket> {
        let candidate = self.current?;
        let active = self.active.as_ref()?;
        if expired(active.deadline) {
            self.active.take();
            self.failed(io::ErrorKind::TimedOut.into());
            return None;
        }
        if events == 0 {
            return None;
        }
        let active = self.active.take()?;
        if events & libc::POLLNVAL != 0 {
            self.failed(io::Error::from_raw_os_error(libc::EBADF));
            return None;
        }
        match active.socket.take_error() {
            Ok(None) => self.connected(active.socket, candidate),
            Ok(Some(error)) | Err(error) => {
                self.connect_error(error);
                None
            }
        }
    }
    fn connect_error(&mut self, error: io::Error) {
        if error.raw_os_error() != Some(libc::EADDRNOTAVAIL) || !self.retry() {
            self.failed(error);
        }
    }
    fn connected(&mut self, socket: Socket, candidate: Candidate) -> Option<Socket> {
        let result = (|| {
            if expired(candidate.deadline) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let peer = socket
                .peer_addr()?
                .as_socket()
                .ok_or(io::ErrorKind::NotConnected)?;
            let local = socket
                .local_addr()?
                .as_socket()
                .ok_or(io::ErrorKind::AddrNotAvailable)?;
            if local.ip() == peer.ip() && local.port() == peer.port() && self.retry() {
                return Ok(None);
            }
            socket.set_nonblocking(false)?;
            #[cfg(target_os = "macos")]
            socket.set_nosigpipe(true)?;
            // Go does not discard an established stream when its socket-option
            // defaults fail. Caddy config does not set these options itself.
            let _ = socket.set_tcp_nodelay(true);
            let _ = socket.set_tcp_keepalive(
                &TcpKeepalive::new()
                    .with_time(TCP_KEEPALIVE)
                    .with_interval(TCP_KEEPALIVE)
                    .with_retries(9),
            );
            if expired(candidate.deadline) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Ok(Some(socket))
        })();
        match result {
            Ok(socket) => socket,
            Err(error) => {
                self.connect_error(error);
                None
            }
        }
    }
}

fn start(address: SocketAddr) -> io::Result<Attempt> {
    connect_start(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
        &SockAddr::from(address),
    )
}
fn connect_start(
    domain: Domain,
    kind: Type,
    protocol: Option<Protocol>,
    address: &SockAddr,
) -> io::Result<Attempt> {
    let socket = Socket::new(domain, kind, protocol)?;
    socket.set_nonblocking(true)?;
    match socket.connect(address) {
        Ok(()) => Ok(Attempt::Connected(socket)),
        Err(error) => match error.raw_os_error() {
            Some(libc::EISCONN) => Ok(Attempt::Connected(socket)),
            Some(libc::EINPROGRESS | libc::EALREADY | libc::EINTR) => Ok(Attempt::Pending(socket)),
            _ => Err(error),
        },
    }
}

/// Go uses nonblocking connect even for DialTimeout(..., 0). In particular,
/// Linux AF_UNIX EAGAIN means a full backlog, not a dial to wait on indefinitely.
pub(super) fn connect_socket(
    domain: Domain,
    kind: Type,
    protocol: Option<Protocol>,
    address: &SockAddr,
    deadline: Option<Instant>,
) -> io::Result<Socket> {
    if expired(deadline) {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let socket = match connect_start(domain, kind, protocol, address)? {
        Attempt::Connected(socket) => socket,
        Attempt::Pending(socket) => loop {
            if expired(deadline) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let mut pfd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: initialized caller-owned pollfd; the socket remains
            // live and exclusively owned across the poll call.
            let ready = unsafe { libc::poll(&mut pfd, 1, poll_millis(deadline)) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            if pfd.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            if let Some(error) = socket.take_error()? {
                return Err(error);
            }
            socket.peer_addr()?;
            break socket;
        },
    };
    if expired(deadline) {
        return Err(io::ErrorKind::TimedOut.into());
    }
    socket.set_nonblocking(false)?;
    Ok(socket)
}

fn expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}
fn min_deadline(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}
fn poll_millis(deadline: Option<Instant>) -> i32 {
    deadline.map_or(-1, |deadline| {
        let nanos = deadline
            .saturating_duration_since(Instant::now())
            .as_nanos();
        nanos.div_ceil(1_000_000).min(i32::MAX as u128) as i32
    })
}
