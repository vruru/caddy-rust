//! Native resolver jobs own their actual getaddrinfo concurrency permits.
//! A dial timeout only ends the waiter; it never detaches an uncharged job.
use super::{
    cpu::{Cpu, Rejected},
    writer_pool::Error,
};
use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    ffi::CString,
    fs::OpenOptions,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    os::unix::fs::OpenOptionsExt,
    ptr,
    sync::{Arc, OnceLock, mpsc},
    time::Instant,
};
use tokio::sync::{Semaphore, TryAcquireError};
const MAX_HOST: usize = 4096;
const MAX_ADDRS: usize = 256;
const MAX_PROTOCOL_NAME: usize = "RSVP-E2E-IGNORE".len() + 10;
const MAX_PROTOCOL_FILE: u64 = 1 << 20;
static PROTOCOLS: OnceLock<HashMap<Vec<u8>, i32>> = OnceLock::new();
#[derive(Clone, Copy)]
pub(super) enum Family {
    Any,
    V4,
    V6,
}
impl Family {
    pub(super) fn network(network: &str) -> Self {
        match network.as_bytes().last() {
            Some(b'4') => Self::V4,
            Some(b'6') => Self::V6,
            _ => Self::Any,
        }
    }
    fn raw(self) -> libc::c_int {
        match self {
            Self::Any => libc::AF_UNSPEC,
            Self::V4 => libc::AF_INET,
            Self::V6 => libc::AF_INET6,
        }
    }
}
pub(super) struct Resolver {
    workers: Arc<Cpu>,
    jobs: Arc<Semaphore>,
}
impl Resolver {
    pub(super) fn new(max_pending: usize) -> Result<Arc<Self>> {
        ensure!(
            max_pending > 0 && max_pending <= Semaphore::MAX_PERMITS,
            "invalid log DNS work limit"
        );
        Ok(Arc::new(Self {
            workers: Cpu::new_named(max_pending, "caddy-log-dns")?,
            jobs: Arc::new(Semaphore::new(max_pending)),
        }))
    }
    pub(super) fn lookup(
        &self,
        host: &str,
        port: u16,
        family: Family,
        deadline: Option<Instant>,
    ) -> std::result::Result<Vec<SocketAddr>, Error> {
        check_deadline(deadline)?;
        if host.is_empty() || host.len() > MAX_HOST || host.as_bytes().contains(&0) {
            return Err(Error::Open);
        }
        if self.jobs.is_closed() {
            return Err(Error::Closed);
        }
        if let Some(address) = literal(host, port) {
            check_deadline(deadline)?;
            return Ok(vec![address]);
        }
        // Acquire before cloning the host and keep the permit in the job.
        let permit = self.permit()?;
        let host = host.to_owned();
        self.submit(deadline, move || {
            let _permit = permit;
            system_lookup(host.as_str(), port, family)
        })
    }
    pub(super) fn protocol(
        &self,
        name: &str,
        deadline: Option<Instant>,
    ) -> std::result::Result<i32, Error> {
        check_deadline(deadline)?;
        if self.jobs.is_closed() {
            return Err(Error::Closed);
        }
        if let Some(number) = decimal_prefix(name.as_bytes())
            && name.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Ok(number);
        }
        if name.is_empty() || name.len() > MAX_PROTOCOL_NAME {
            return Err(Error::Open);
        }
        let name = name.as_bytes().to_ascii_lowercase();
        match name.as_slice() {
            b"icmp" => return Ok(libc::IPPROTO_ICMP),
            b"igmp" => return Ok(libc::IPPROTO_IGMP),
            b"tcp" => return Ok(libc::IPPROTO_TCP),
            b"udp" => return Ok(libc::IPPROTO_UDP),
            b"ipv6-icmp" => return Ok(libc::IPPROTO_ICMPV6),
            _ => {}
        }
        if let Some(protocols) = PROTOCOLS.get() {
            return protocols.get(&name).copied().ok_or(Error::Open);
        }
        let permit = self.permit()?;
        self.submit(deadline, move || {
            let _permit = permit;
            // Never wait on another worker's OnceLock initializer. At most the
            // bounded number of DNS jobs can read concurrently on cold start.
            if PROTOCOLS.get().is_none() {
                // Go's readProtocolsOnce also commits an empty supplement
                // when /etc/protocols is missing or unreadable. Cache that
                // negative lookup instead of burning a DNS slot on each use.
                let _ = PROTOCOLS.set(read_protocols().unwrap_or_default());
            }
            PROTOCOLS
                .get()
                .and_then(|p| p.get(&name))
                .copied()
                .ok_or(Error::Open)
        })
    }
    fn permit(&self) -> std::result::Result<tokio::sync::OwnedSemaphorePermit, Error> {
        self.jobs.clone().try_acquire_owned().map_err(|e| match e {
            TryAcquireError::NoPermits => Error::Full,
            TryAcquireError::Closed => Error::Closed,
        })
    }
    fn submit<T: Send + 'static>(
        &self,
        deadline: Option<Instant>,
        resolve: impl FnOnce() -> std::result::Result<T, Error> + Send + 'static,
    ) -> std::result::Result<T, Error> {
        check_deadline(deadline)?;
        let (send, receive) = mpsc::sync_channel(1);
        let completion = self
            .workers
            .try_submit(move || {
                let result = check_deadline(deadline).and_then(|()| resolve());
                let _ = send.try_send(result);
                Ok(())
            })
            .map_err(|e| match e {
                Rejected::Full => Error::Full,
                Rejected::Closed => Error::Closed,
            })?;
        drop(completion);
        let result = if let Some(deadline) = deadline {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Open)?;
            receive.recv_timeout(remaining).map_err(|_| Error::Open)?
        } else {
            receive.recv().map_err(|_| Error::Open)?
        };
        check_deadline(deadline)?;
        result
    }
    pub(super) fn close(&self) {
        self.jobs.close();
        self.workers.close();
    }
    pub(super) async fn shutdown(&self) -> Result<()> {
        self.close();
        self.workers.shutdown().await
    }
    pub(super) fn quiesced(&self) -> bool {
        self.workers.quiesced()
    }
}
fn system_lookup(
    host: &str,
    port: u16,
    family: Family,
) -> std::result::Result<Vec<SocketAddr>, Error> {
    let host = CString::new(host).map_err(|_| Error::Open)?;
    // SAFETY: addrinfo is a C struct of integers and pointers; its hints
    // contract requires these pointer fields initialized to null.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family.raw();
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut head = ptr::null_mut();
    // SAFETY: host is NUL-terminated, hints and out pointer are valid for
    // this call, and the service is deliberately null (numeric port below).
    let status = unsafe { libc::getaddrinfo(host.as_ptr(), ptr::null(), &hints, &mut head) };
    if status != 0 || head.is_null() {
        return Err(Error::Open);
    }
    struct Addresses(*mut libc::addrinfo);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: successful getaddrinfo allocated this list; exactly
            // this owner frees it, with no borrowed entry escaping.
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
    let owner = Addresses(head);
    let mut node = owner.0;
    let mut results = Vec::new();
    for _ in 0..=MAX_ADDRS {
        // SAFETY: node is null or a list entry owned by owner (live above).
        let Some(info) = (unsafe { node.as_ref() }) else {
            return if results.is_empty() {
                Err(Error::Open)
            } else {
                Ok(results)
            };
        };
        if results.len() == MAX_ADDRS {
            return Err(Error::Full);
        }
        if !info.ai_addr.is_null() {
            let len = info.ai_addrlen as usize;
            let address = match info.ai_family {
                libc::AF_INET if len >= std::mem::size_of::<libc::sockaddr_in>() => {
                    // SAFETY: getaddrinfo supplies the initialized sockaddr
                    // of this family and checked length, read without assuming alignment.
                    let v4 = unsafe { info.ai_addr.cast::<libc::sockaddr_in>().read_unaligned() };
                    Some(SocketAddr::new(
                        Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes()).into(),
                        port,
                    ))
                }
                libc::AF_INET6 if len >= std::mem::size_of::<libc::sockaddr_in6>() => {
                    // SAFETY: same ownership/length guarantee as AF_INET.
                    let v6 = unsafe { info.ai_addr.cast::<libc::sockaddr_in6>().read_unaligned() };
                    Some(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(v6.sin6_addr.s6_addr),
                        port,
                        0,
                        v6.sin6_scope_id,
                    )))
                }
                _ => None,
            };
            if let Some(address) = address {
                results.push(normalize(address));
            }
        }
        node = info.ai_next;
    }
    Err(Error::Full)
}
pub(super) fn check_deadline(deadline: Option<Instant>) -> std::result::Result<(), Error> {
    if deadline.is_some_and(|d| Instant::now() >= d) {
        Err(Error::Open)
    } else {
        Ok(())
    }
}
fn literal(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(normalize(SocketAddr::new(ip, port)));
    }
    let (ip, scope) = host.rsplit_once('%')?;
    let ip = ip.parse::<Ipv6Addr>().ok()?;
    let scope = (scope.bytes().all(|b| b.is_ascii_digit()))
        .then(|| scope.parse::<u32>().ok())
        .flatten()
        .unwrap_or_else(|| {
            let Ok(name) = CString::new(scope) else {
                return 0;
            };
            // SAFETY: CString supplies a valid NUL-terminated name for the duration of
            // this POSIX call; no pointer or ownership escapes it.
            unsafe { libc::if_nametoindex(name.as_ptr()) }
        });
    Some(normalize(SocketAddr::V6(SocketAddrV6::new(
        ip, port, 0, scope,
    ))))
}
fn normalize(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(address, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
        _ => address,
    }
}

// Go's net/lookup_unix.go uses the local protocols file to supplement the
// five built-in names. Bound reads, do not open a FIFO as a blocking stream,
// and use the original first-entry and numeric prefix rules.
fn read_protocols() -> Option<HashMap<Vec<u8>, i32>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/etc/protocols")
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut input = Vec::new();
    file.take(MAX_PROTOCOL_FILE + 1)
        .read_to_end(&mut input)
        .ok()?;
    if input.len() as u64 > MAX_PROTOCOL_FILE {
        return None;
    }
    Some(parse_protocols(&input))
}
fn parse_protocols(input: &[u8]) -> HashMap<Vec<u8>, i32> {
    let mut protocols = HashMap::new();
    for line in input.split(|b| *b == b'\n') {
        let line = line.split(|b| *b == b'#').next().unwrap_or_default();
        let mut fields = line
            .split(|b| matches!(b, b' ' | b'\t' | b'\r'))
            .filter(|s| !s.is_empty());
        let Some(name) = fields.next() else { continue };
        let Some(number) = fields.next().and_then(decimal_prefix) else {
            continue;
        };
        for alias in std::iter::once(name).chain(fields) {
            if alias.len() <= MAX_PROTOCOL_NAME && !protocols.contains_key(alias) {
                protocols.insert(alias.to_vec(), number);
            }
        }
    }
    protocols
}
fn decimal_prefix(input: &[u8]) -> Option<i32> {
    let mut number = 0;
    let mut seen = false;
    for byte in input.iter().copied().take_while(u8::is_ascii_digit) {
        seen = true;
        number = number * 10 + i32::from(byte - b'0');
        if number >= 0xFF_FFFF {
            return None;
        }
    }
    seen.then_some(number)
}
