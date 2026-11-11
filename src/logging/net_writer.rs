// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
//! A serial actor owns each physical connection. Timed DNS waits do not detach
//! uncharged resolver jobs. A write has no artificial deadline; shutdown can
//! report an incomplete writer while the kernel is still handling its output.
use super::{
    net_address::Address,
    resolver_lane::{Family, Resolver, check_deadline},
    tcp_dial::{connect_socket, dial_tcp, partial_deadline},
    writer_pool::{Error, WriterIo, Written},
    writer_spec::NetSpec,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

const REDIAL_DELAY: Duration = Duration::from_secs(10);

pub(super) struct NetWriter {
    spec: NetSpec,
    resolver: Arc<Resolver>,
    connection: Option<Connection>,
    last_redial: Option<Instant>,
}

struct Connection {
    socket: Socket,
    message: bool,
}

impl NetWriter {
    pub(super) fn open(spec: NetSpec, resolver: Arc<Resolver>) -> Result<Self, Error> {
        let connection = match dial(&spec, &resolver) {
            Ok(connection) => Some(connection),
            Err(_) if spec.soft_start => {
                // Like the source writer, soft-start logs even if the normal
                // log destination is still being provisioned. Avoid config/host
                // data in this diagnostic; failed frames use intentional fallback.
                let _ = io::stderr().lock().write_all(
                    b"[ERROR] net log writer failed to connect (will retry connection and print errors here in the meantime)\n",
                );
                None
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            spec,
            resolver,
            connection,
            last_redial: None,
        })
    }
}

impl WriterIo for NetWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<Written, Error> {
        if let Some(connection) = &self.connection
            && (connection.write(bytes).is_ok() || connection.write(bytes).is_ok())
        {
            return Ok(Written::Bytes(bytes.len()));
        }
        let now = Instant::now();
        if self
            .last_redial
            .is_none_or(|last| now.duration_since(last) > REDIAL_DELAY)
        {
            self.last_redial = Some(now);
            if let Ok(candidate) = dial(&self.spec, &self.resolver) {
                // The original returns this write error without stderr fallback.
                // Unlike its error branch, the owned candidate closes here.
                candidate.write(bytes).map_err(|_| Error::Write)?;
                self.connection = Some(candidate);
                return Ok(Written::Bytes(bytes.len()));
            }
        }
        io::stderr()
            .lock()
            .write_all(bytes)
            .map_err(|_| Error::Write)?;
        Ok(Written::Fallback(bytes.len()))
    }

    fn flush(&mut self) -> Result<(), Error> {
        // A network flush is a writer-actor barrier, not remote delivery ACK.
        Ok(())
    }
}

impl Connection {
    fn write(&self, mut bytes: &[u8]) -> io::Result<()> {
        if self.message {
            // Datagram and sequence-packet transports preserve the entire frame.
            if send(&self.socket, bytes)? != bytes.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            return Ok(());
        }
        while !bytes.is_empty() {
            let written = send(&self.socket, bytes)?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }
}

fn send(socket: &Socket, bytes: &[u8]) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    const FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    const FLAGS: libc::c_int = 0;
    loop {
        match socket.send_with_flags(bytes, FLAGS) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn dial(spec: &NetSpec, resolver: &Resolver) -> Result<Connection, Error> {
    let now = Instant::now();
    let timeout = u64::try_from(spec.dial_timeout).map_err(|_| Error::Open)?;
    let deadline = (timeout != 0)
        .then(|| {
            now.checked_add(Duration::from_nanos(timeout))
                .ok_or(Error::Open)
        })
        .transpose()?;
    let address = &spec.address;
    let network = address.network.as_str();
    let socket = match network {
        "unix" | "unixgram" | "unixpacket" => {
            let kind = match network {
                "unix" => Type::STREAM,
                "unixgram" => Type::DGRAM,
                _ => Type::SEQPACKET,
            };
            if address.host.is_empty() {
                return Err(Error::Open);
            }
            let address = unix_address(&address.host).map_err(|_| Error::Open)?;
            connect_one(Domain::UNIX, kind, None, &address, deadline).map(|socket| Connection {
                socket,
                message: network != "unix",
            })
        }
        "tcp" | "tcp4" | "tcp6" => {
            let addresses = internet_addresses(address, network, resolver, deadline)?;
            dial_tcp(addresses, network == "tcp", deadline).map(|socket| Connection {
                socket,
                message: false,
            })
        }
        "udp" | "udp4" | "udp6" => {
            let addresses = internet_addresses(address, network, resolver, deadline)?;
            connect_internet(addresses, Type::DGRAM, Protocol::UDP, deadline).map(|socket| {
                Connection {
                    socket,
                    message: true,
                }
            })
        }
        _ => return dial_raw(address, resolver, deadline),
    }
    .map_err(|_| Error::Open)?;
    check_deadline(deadline)?;
    Ok(socket)
}

fn dial_raw(
    address: &Address,
    resolver: &Resolver,
    deadline: Option<Instant>,
) -> Result<Connection, Error> {
    let (family, name) = address.network.rsplit_once(':').ok_or(Error::Open)?;
    if !matches!(family, "ip" | "ip4" | "ip6") {
        return Err(Error::Open);
    }
    let number = resolver.protocol(name, deadline)?;
    // Go receives JoinHostPort(0) even for raw-IP networks, and hands that
    // whole string (including its port) to the resolver, not Address::host.
    let addresses = resolver.lookup(
        &address.join_host_port(),
        0,
        Family::network(family),
        deadline,
    )?;
    let addresses = choose_family(addresses, family);
    let socket = connect_internet(addresses, Type::RAW, Protocol::from(number), deadline)
        .map_err(|_| Error::Open)?;
    check_deadline(deadline)?;
    Ok(Connection {
        socket,
        message: true,
    })
}

fn internet_addresses(
    address: &Address,
    network: &str,
    resolver: &Resolver,
    deadline: Option<Instant>,
) -> Result<Vec<SocketAddr>, Error> {
    check_deadline(deadline)?;
    if address.host.is_empty() {
        let ip = if network.ends_with('6') {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        return Ok(vec![SocketAddr::new(ip, address.port)]);
    }
    let addresses = resolver.lookup(
        &address.host,
        address.port,
        Family::network(network),
        deadline,
    )?;
    Ok(choose_family(addresses, network))
}

fn choose_family(mut addresses: Vec<SocketAddr>, network: &str) -> Vec<SocketAddr> {
    if let [SocketAddr::V6(address)] = addresses.as_slice()
        && address.ip().is_unspecified()
    {
        addresses.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            address.port(),
        ));
    }
    if network.ends_with('4') {
        addresses.retain(SocketAddr::is_ipv4);
    } else if network.ends_with('6') {
        addresses.retain(SocketAddr::is_ipv6);
    }
    for address in &mut addresses {
        // Go dials wildcard destinations as the same family's loopback.
        if address.ip().is_unspecified() {
            address.set_ip(if address.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            });
        }
    }
    addresses
}

fn connect_internet(
    addresses: Vec<SocketAddr>,
    kind: Type,
    protocol: Protocol,
    deadline: Option<Instant>,
) -> io::Result<Socket> {
    let mut first_error = None;
    let count = addresses.len();
    for (index, address) in addresses.into_iter().enumerate() {
        let attempt_deadline = partial_deadline(Instant::now(), deadline, count - index)?;
        match connect_one(
            Domain::for_address(address),
            kind,
            Some(protocol),
            &address.into(),
            attempt_deadline,
        ) {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    Err(first_error.unwrap_or_else(|| io::ErrorKind::AddrNotAvailable.into()))
}

fn connect_one(
    domain: Domain,
    kind: Type,
    protocol: Option<Protocol>,
    address: &SockAddr,
    deadline: Option<Instant>,
) -> io::Result<Socket> {
    let socket = connect_socket(domain, kind, protocol, address, deadline)?;
    #[cfg(target_os = "macos")]
    socket.set_nosigpipe(true)?;
    Ok(socket)
}

fn unix_address(host: &str) -> io::Result<SockAddr> {
    // Go interprets a leading @ as Linux abstract namespace; elsewhere @ is
    // an ordinary path byte. Keep any literal |mode suffix on the dial path.
    #[cfg(target_os = "linux")]
    if let Some(name) = host.strip_prefix('@') {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        if name.len() > 107 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut bytes = Vec::with_capacity(1 + name.len());
        bytes.push(0);
        bytes.extend_from_slice(name.as_bytes());
        return SockAddr::unix(OsString::from_vec(bytes));
    }
    SockAddr::unix(host)
}
