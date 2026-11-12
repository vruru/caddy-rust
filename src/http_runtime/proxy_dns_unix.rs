//! Unframed Unix DNS, matching Go UnixConn's PacketConn classification.
//! Owned nonblocking sockets close on cancellation; no filesystem client socket.
use std::{
    io,
    net::SocketAddr,
    path::Path,
    sync::Mutex,
    task::{Context, Poll, ready},
};
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Stream,
    Datagram,
    Packet,
}
#[cfg(unix)]
use {
    socket2::{Domain, SockAddr, Socket, Type},
    std::{
        io::{Read, Write},
        os::unix::ffi::OsStringExt,
    },
    tokio::io::unix::AsyncFd,
};
#[cfg(unix)]
pub(super) struct Connection {
    socket: AsyncFd<Socket>,
    kind: Kind,
    write: Mutex<Pending>,
    #[cfg(not(target_os = "linux"))]
    _local: Option<LocalEndpoint>,
}
// BSD/macOS have no abstract Unix addresses. A private filesystem endpoint
// supplies the return address without leaving socket files after cancellation.
#[cfg(all(unix, not(target_os = "linux")))]
struct LocalEndpoint {
    directory: Option<tempfile::TempDir>,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
}
#[cfg(all(unix, not(target_os = "linux")))]
impl Drop for LocalEndpoint {
    fn drop(&mut self) {
        let directory = self.directory.take();
        let slot = self.slot.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn_blocking(move || {
                drop(directory);
                drop(slot);
            }));
        } else {
            drop(directory);
            drop(slot);
        }
    }
}
#[cfg(unix)]
#[derive(Default)]
struct Pending {
    bytes: Vec<u8>,
    sent: usize,
    failed: bool,
}
#[cfg(unix)]
fn address(path: &str) -> io::Result<SockAddr> {
    let bytes = if cfg!(target_os = "linux") && path.starts_with('@') {
        let mut v = path.as_bytes().to_vec();
        v[0] = 0;
        v
    } else {
        path.as_bytes().to_vec()
    };
    SockAddr::unix(Path::new(&std::ffi::OsString::from_vec(bytes)))
}
#[cfg(unix)]
impl Connection {
    pub(super) async fn connect(path: &str, kind: Kind) -> io::Result<Self> {
        let ty = match kind {
            Kind::Stream => Type::STREAM,
            Kind::Datagram => Type::DGRAM,
            Kind::Packet => Type::SEQPACKET,
        };
        let socket = Socket::new(Domain::UNIX, ty, None)?;
        socket.set_nonblocking(true)?;
        #[cfg(not(target_os = "linux"))]
        let mut local = None;
        let socket = if matches!(kind, Kind::Datagram) {
            #[cfg(target_os = "linux")]
            {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                socket.bind(&address(&format!(
                    "@caddy-dns-{}-{id}",
                    std::process::id()
                ))?)?;
                socket
            }
            #[cfg(not(target_os = "linux"))]
            {
                static SLOTS: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
                    std::sync::OnceLock::new();
                let slot = SLOTS
                    .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(128)))
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "Unix DNS local endpoint capacity exceeded",
                        )
                    })?;
                let (socket, endpoint) = tokio::task::spawn_blocking(move || -> io::Result<_> {
                    // /tmp keeps the full pathname below sockaddr_un's short
                    // platform limit, regardless of a long per-user TMPDIR.
                    use std::os::unix::fs::PermissionsExt;
                    let directory = tempfile::Builder::new()
                        .prefix(".caddy-dns-")
                        .permissions(std::fs::Permissions::from_mode(0o700))
                        .tempdir_in("/tmp")?;
                    socket.bind(&SockAddr::unix(directory.path().join("s"))?)?;
                    Ok((
                        socket,
                        LocalEndpoint {
                            directory: Some(directory),
                            slot: Some(slot),
                        },
                    ))
                })
                .await
                .map_err(|_| io::Error::other("Unix DNS endpoint worker stopped"))??;
                local = Some(endpoint);
                socket
            }
        } else {
            socket
        };
        let peer = address(path)?;
        // SAFETY: Socket owns one open descriptor. Connection never exposes a
        // mutable Socket or replaces/closes its descriptor while registered;
        // AsyncFd owns it until deregistration and drop, including cancellation.
        let socket = unsafe { AsyncFd::register(socket)? };
        loop {
            match socket.get_ref().connect(&peer) {
                Ok(()) => break,
                Err(e) if e.raw_os_error() == Some(libc::EISCONN) => break,
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINPROGRESS | libc::EALREADY)) => {
                    let mut guard = socket.writable().await?;
                    guard.clear_ready();
                    if let Some(error) = socket.get_ref().take_error()? {
                        return Err(error);
                    }
                    if socket.get_ref().peer_addr().is_ok() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // AF_UNIX backlog exhaustion returns EAGAIN without queuing
                    // the connection. Retry under the caller's dial/query deadline.
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Self {
            socket,
            kind,
            write: Mutex::new(Pending::default()),
            #[cfg(not(target_os = "linux"))]
            _local: local,
        })
    }
    pub(super) fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.socket.poll_read_ready(cx))?;
            match guard.try_io(|fd| {
                let mut socket = fd.get_ref();
                socket.read(out)
            }) {
                Ok(Ok(0)) if !matches!(self.kind, Kind::Datagram) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Unix DNS peer closed",
                    )));
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(result) => return Poll::Ready(result),
                Err(_) => {}
            }
        }
    }
    pub(super) fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.len() > u16::MAX as usize {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS message exceeds 65535 bytes",
            )));
        }
        let mut st = self
            .write
            .lock()
            .map_err(|_| io::Error::other("Unix DNS write lock poisoned"))?;
        if st.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Unix DNS write closed",
            )));
        }
        let mut staged = false;
        loop {
            if st.bytes.is_empty() {
                st.bytes.extend_from_slice(buf);
                st.sent = 0;
                staged = true;
            }
            while st.sent < st.bytes.len() {
                let mut guard = ready!(self.socket.poll_write_ready(cx))?;
                let result = guard.try_io(|fd| {
                    let mut socket = fd.get_ref();
                    socket.write(&st.bytes[st.sent..])
                });
                match result {
                    Ok(Ok(0)) => {
                        st.failed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Unix DNS write returned zero",
                        )));
                    }
                    Ok(Ok(n)) => {
                        st.sent += n;
                        if !matches!(self.kind, Kind::Stream) && st.sent != st.bytes.len() {
                            st.failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "short Unix DNS packet write",
                            )));
                        }
                    }
                    Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                    Ok(Err(e)) => {
                        st.failed = true;
                        return Poll::Ready(Err(e));
                    }
                    Err(_) => {}
                }
            }
            let ours = staged || st.bytes == buf;
            st.bytes.clear();
            st.sent = 0;
            if ours {
                return Poll::Ready(Ok(buf.len()));
            }
        }
    }
}
// Keep the API available to the parser on non-Unix targets; platform support is
// explicit at dial time and never substitutes a different transport.
pub(super) async fn connect(
    path: &str,
    kind: Kind,
    logical: SocketAddr,
) -> io::Result<super::proxy_dns_socket::DnsSocket> {
    #[cfg(unix)]
    {
        Ok(super::proxy_dns_socket::DnsSocket::unix(
            Connection::connect(path, kind).await?,
            logical,
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, kind, logical);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix DNS unavailable on this platform",
        ))
    }
}
