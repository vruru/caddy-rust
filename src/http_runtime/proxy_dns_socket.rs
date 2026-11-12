//! 已连接 socket 到 hickory `DnsUdpSocket` 的适配层。
//!
//! 物理对端由 Dial callback 固定：UDP 已 `connect`，TCP 是已建立的流。
//! hickory 只看到逻辑占位地址（如 127.0.0.1:53），收包来源始终报告为该地址。
//! TCP 以 2 字节长度前缀成帧，向 hickory 提供“一次 recv = 一条完整 DNS 消息”的 datagram 语义。

use std::io;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, ready};

use hickory_resolver::net::runtime::DnsUdpSocket;
use hickory_resolver::net::runtime::{RuntimeProvider, TokioRuntimeProvider};
use tokio::io::ReadBuf;
use tokio::net::{TcpStream, UdpSocket};

/// 已连接的 DNS 传输。Drop 即关闭底层 fd 并注销 reactor 注册，无后台任务。
pub(crate) struct DnsSocket {
    logical: SocketAddr,
    transport: Transport,
}

enum Transport {
    Udp(UdpSocket),
    #[cfg(unix)]
    Unix(super::proxy_dns_unix::Connection),
    Tcp(TcpConn),
}

/// 读、写各自持锁，互不阻塞（full-duplex）。
/// `TcpStream` 的 `poll_*_ready` / `try_*` 只需 `&self`，因此流本身不进锁。
struct TcpConn {
    stream: TcpStream,
    read: Mutex<ReadState>,
    write: Mutex<WriteState>,
}

/// 不变式：`hdr_filled == 2` 时 `body.len()` 等于本帧长度（<= 65535）。
#[derive(Default)]
struct ReadState {
    hdr: [u8; 2],
    hdr_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    failed: Option<io::ErrorKind>,
}

/// `frame` 非空表示有一帧（长度前缀 + 消息，<= 65537 字节）正在写出。
#[derive(Default)]
struct WriteState {
    frame: Vec<u8>,
    written: usize,
    failed: Option<io::ErrorKind>,
}

impl DnsSocket {
    pub(crate) fn is_stream(&self) -> bool {
        matches!(self.transport, Transport::Tcp(_))
    }
    /// `socket` 必须已 `connect` 到管理员配置的 DNS 地址；内核据此过滤其它来源。
    pub(crate) fn udp(socket: UdpSocket, logical: SocketAddr) -> Self {
        Self {
            logical,
            transport: Transport::Udp(socket),
        }
    }

    /// `stream` 必须已连接到管理员配置的 DNS 地址。
    pub(crate) fn tcp(stream: TcpStream, logical: SocketAddr) -> Self {
        // 尽力而为：流水线查询时避免 Nagle 延迟；失败不影响正确性。
        let _ = stream.set_nodelay(true);
        Self {
            logical,
            transport: Transport::Tcp(TcpConn {
                stream,
                read: Mutex::new(ReadState::default()),
                write: Mutex::new(WriteState::default()),
            }),
        }
    }

    #[cfg(unix)]
    pub(super) fn unix(connection: super::proxy_dns_unix::Connection, logical: SocketAddr) -> Self {
        Self { logical, transport: Transport::Unix(connection) }
    }

    fn check_target(&self, target: SocketAddr) -> io::Result<()> {
        if target == self.logical {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS send target is not the logical server address",
            ))
        }
    }
}

impl DnsUdpSocket for DnsSocket {
    type Time = <TokioRuntimeProvider as RuntimeProvider>::Timer;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let n = match &self.transport {
            Transport::Udp(sock) => {
                // 已连接 UDP：内核只交付来自固定 peer 的报文；超长报文按平台 UDP 语义截断。
                let mut rb = ReadBuf::new(buf);
                ready!(sock.poll_recv(cx, &mut rb))?;
                rb.filled().len()
            }
            Transport::Tcp(conn) => ready!(conn.poll_recv(cx, buf))?,
            #[cfg(unix)]
            Transport::Unix(conn) => ready!(conn.poll_recv(cx, buf))?,
        };
        Poll::Ready(Ok((n, self.logical)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.check_target(target)?;
        match &self.transport {
            Transport::Udp(sock) => sock.poll_send(cx, buf),
            Transport::Tcp(conn) => conn.poll_send(cx, buf),
            #[cfg(unix)]
            Transport::Unix(conn) => conn.poll_send(cx, buf),
        }
    }
}

impl TcpConn {
    fn poll_recv(&self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut guard = lock(&self.read)?;
        let st = &mut *guard;
        if let Some(kind) = st.failed {
            return Poll::Ready(Err(io::Error::new(kind, "DNS TCP read side is closed")));
        }
        let res = read_frame(&self.stream, cx, st, out);
        if let Poll::Ready(Err(e)) = &res {
            // 帧边界已不可信：此后读端持续报错，不再交付任何数据。
            st.failed = Some(e.kind());
        }
        res
    }

    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let len = u16::try_from(buf.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS message exceeds 65535 bytes",
            )
        })?;
        let mut guard = lock(&self.write)?;
        let st = &mut *guard;
        if let Some(kind) = st.failed {
            return Poll::Ready(Err(io::Error::new(kind, "DNS TCP write side is closed")));
        }
        let res = send_frame(&self.stream, cx, st, buf, len);
        if let Poll::Ready(Err(e)) = &res {
            st.failed = Some(e.kind());
        }
        res
    }
}

/// 读出一条完整帧后交付；`out` 不足时截断，但整条消息都会被消费，下一次 recv 从下一帧开始。
/// 只读取当前帧所需字节，不预读，内存上限为单帧 65535 字节。
fn read_frame(
    stream: &TcpStream,
    cx: &mut Context<'_>,
    st: &mut ReadState,
    out: &mut [u8],
) -> Poll<io::Result<usize>> {
    while st.hdr_filled < 2 {
        let dst = st.hdr.get_mut(st.hdr_filled..).ok_or_else(internal)?;
        let n = ready!(poll_read_some(stream, cx, dst))?;
        if n == 0 {
            return Poll::Ready(Err(eof(st.hdr_filled == 0)));
        }
        st.hdr_filled += n;
        if st.hdr_filled == 2 {
            let len = usize::from(u16::from_be_bytes(st.hdr));
            st.body.clear();
            st.body.resize(len, 0);
            st.body_filled = 0;
        }
    }
    while st.body_filled < st.body.len() {
        let dst = st.body.get_mut(st.body_filled..).ok_or_else(internal)?;
        let n = ready!(poll_read_some(stream, cx, dst))?;
        if n == 0 {
            return Poll::Ready(Err(eof(false)));
        }
        st.body_filled += n;
    }
    let copied = copy_truncated(out, &st.body);
    st.hdr_filled = 0;
    st.body_filled = 0;
    st.body.clear();
    Poll::Ready(Ok(copied))
}

/// 整帧写完才返回 `Ok(buf.len())`。
/// 若上一次调用在半帧时被取消（future 被 drop），先补完那一帧以保持流上的帧边界；
/// 若残留帧的消息与本次 `buf` 相同，即视为同一次发送的续写。
fn send_frame(
    stream: &TcpStream,
    cx: &mut Context<'_>,
    st: &mut WriteState,
    buf: &[u8],
    len: u16,
) -> Poll<io::Result<usize>> {
    let mut staged_now = false;
    loop {
        if st.frame.is_empty() {
            st.frame.reserve(buf.len() + 2);
            st.frame.extend_from_slice(&len.to_be_bytes());
            st.frame.extend_from_slice(buf);
            st.written = 0;
            staged_now = true;
        }
        ready!(write_staged(stream, cx, st))?;
        let ours = staged_now || st.frame.get(2..) == Some(buf);
        st.frame.clear();
        st.written = 0;
        if ours {
            return Poll::Ready(Ok(buf.len()));
        }
        // 残留帧属于已取消的调用；已补完，下一轮写本次消息。
    }
}

fn write_staged(
    stream: &TcpStream,
    cx: &mut Context<'_>,
    st: &mut WriteState,
) -> Poll<io::Result<()>> {
    while st.written < st.frame.len() {
        ready!(stream.poll_write_ready(cx))?;
        let src = st.frame.get(st.written..).ok_or_else(internal)?;
        match stream.try_write(src) {
            Ok(0) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "DNS TCP write returned 0 bytes",
                )));
            }
            Ok(n) => st.written += n,
            Err(e) if retryable(&e) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
    Poll::Ready(Ok(()))
}

/// readiness 被 `try_read` 的 WouldBlock 清除后，再次 poll 会返回 Pending 并登记 waker。
fn poll_read_some(
    stream: &TcpStream,
    cx: &mut Context<'_>,
    dst: &mut [u8],
) -> Poll<io::Result<usize>> {
    loop {
        ready!(stream.poll_read_ready(cx))?;
        match stream.try_read(dst) {
            Err(e) if retryable(&e) => {}
            res => return Poll::Ready(res),
        }
    }
}

fn copy_truncated(out: &mut [u8], msg: &[u8]) -> usize {
    let n = out.len().min(msg.len());
    for (d, s) in out.iter_mut().zip(msg) {
        *d = *s;
    }
    n
}

fn retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn lock<T>(m: &Mutex<T>) -> io::Result<MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| io::Error::other("DNS socket state lock poisoned"))
}

fn eof(at_boundary: bool) -> io::Error {
    let msg = if at_boundary {
        "DNS TCP peer closed the connection"
    } else {
        "DNS TCP connection closed mid-message"
    };
    io::Error::new(io::ErrorKind::UnexpectedEof, msg)
}

fn internal() -> io::Error {
    io::Error::other("DNS TCP framing state out of range")
}
