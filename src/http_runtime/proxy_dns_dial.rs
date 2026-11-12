//! Go net.Dialer ordering and Happy Eyeballs for a configured DNS peer.
use super::proxy_dns_socket::DnsSocket;
use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::net::{TcpStream, UdpSocket};

pub(super) fn family(address: SocketAddr, version: Option<u8>) -> Option<SocketAddr> {
    let address = match address {
        SocketAddr::V6(v) => match v.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(ip.into(), v.port()),
            None => address,
        },
        _ => address,
    };
    match version {
        Some(4) if !address.is_ipv4() => None,
        Some(6) if !address.is_ipv6() => None,
        _ => Some(address),
    }
}

pub(super) async fn connect(
    addresses: Vec<SocketAddr>,
    tcp: bool,
    version: Option<u8>,
    fallback_ns: i64,
    deadline: Option<Instant>,
    logical: SocketAddr,
) -> io::Result<DnsSocket> {
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "DNS server has no suitable address",
        ));
    }
    if !tcp {
        let mut first = None;
        for (index, address) in addresses.into_iter().enumerate() {
            let operation = async {
                let local = if address.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = UdpSocket::bind(local).await?;
                socket.connect(address).await?;
                Ok::<_, io::Error>(DnsSocket::udp(socket, logical))
            };
            let result = match remaining(deadline)? {
                Some(left) => tokio::time::timeout(left, operation)
                    .await
                    .map_err(|_| timed_out())?,
                None => operation.await,
            };
            match result {
                Ok(socket) => return Ok(socket),
                Err(error) => {
                    first.get_or_insert(error);
                }
            }
            if index % 32 == 31 {
                tokio::task::yield_now().await;
            }
        }
        return Err(first.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "DNS UDP connect failed")
        }));
    }
    if version.is_some() || fallback_ns < 0 {
        return serial(&addresses, deadline)
            .await
            .map(|socket| DnsSocket::tcp(socket, logical));
    }
    let first_v4 = addresses[0].is_ipv4();
    let (primary, fallback): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv4() == first_v4);
    if fallback.is_empty() {
        return serial(&primary, deadline)
            .await
            .map(|socket| DnsSocket::tcp(socket, logical));
    }
    let primary = serial(&primary, deadline);
    tokio::pin!(primary);
    let delay = if fallback_ns == 0 {
        Duration::from_millis(300)
    } else {
        Duration::from_nanos(fallback_ns as u64)
    };
    let early = tokio::select! {
        result=&mut primary=>match result {Ok(socket)=>return Ok(DnsSocket::tcp(socket,logical)),Err(error)=>Some(error)},
        _=tokio::time::sleep(delay)=>None,
    };
    let fallback = serial(&fallback, deadline);
    tokio::pin!(fallback);
    let socket = if let Some(error) = early {
        fallback.await.map_err(|_| error)
    } else {
        tokio::select! {
            result=&mut primary=>match result {Ok(socket)=>Ok(socket),Err(error)=>fallback.await.map_err(|_|error)},
            result=&mut fallback=>match result {Ok(socket)=>Ok(socket),Err(_)=>primary.await},
        }
    }?;
    Ok(DnsSocket::tcp(socket, logical))
}

async fn serial(addresses: &[SocketAddr], deadline: Option<Instant>) -> io::Result<TcpStream> {
    let mut first = None;
    for (index, address) in addresses.iter().enumerate() {
        let timeout = remaining(deadline)?.map(|left| {
            let per = left / (addresses.len() - index) as u32;
            if per >= Duration::from_secs(2) {
                per
            } else {
                left.min(Duration::from_secs(2))
            }
        });
        let connect = TcpStream::connect(address);
        let result = match timeout {
            Some(timeout) => tokio::time::timeout(timeout, connect)
                .await
                .map_err(|_| timed_out())
                .and_then(|r| r),
            None => connect.await,
        };
        match result {
            Ok(socket) => {
                socket.set_nodelay(true)?;
                return Ok(socket);
            }
            Err(error) => {
                first.get_or_insert(error);
            }
        }
        if index % 32 == 31 {
            tokio::task::yield_now().await;
        }
    }
    Err(first.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "DNS TCP connect failed")
    }))
}
fn remaining(deadline: Option<Instant>) -> io::Result<Option<Duration>> {
    match deadline {
        Some(deadline) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                Err(timed_out())
            } else {
                Ok(Some(left))
            }
        }
        None => Ok(None),
    }
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "dial DNS server: i/o timeout")
}
