use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Socket { address: SocketAddr, datagram: bool },
    Unix { path: Vec<u8>, datagram: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub source: Option<Address>,
    pub destination: Option<Address>,
}

fn parse_port(bytes: &[u8]) -> Result<u16, ()> {
    if bytes.is_empty() || bytes.len() > 5 || (bytes.len() > 1 && bytes[0] == b'0') {
        return Err(());
    }
    bytes.iter().try_fold(0u16, |value, byte| {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(byte - b'0')))
            .ok_or(())
    })
}
pub fn v1(line: &[u8]) -> Result<Parsed, ()> {
    if line.len() > 107 || !line.ends_with(b"\r\n") {
        return Err(());
    }
    let mut parts = line[..line.len() - 2].split(|byte| *byte == b' ');
    if parts.next() != Some(b"PROXY".as_slice()) {
        return Err(());
    }
    let protocol = parts.next().ok_or(())?;
    if protocol == b"UNKNOWN" {
        return Ok(Parsed {
            source: None,
            destination: None,
        });
    }
    if protocol != b"TCP4" && protocol != b"TCP6" {
        return Err(());
    }
    let source = parts.next().ok_or(())?;
    let destination = parts.next().ok_or(())?;
    let source_port = parse_port(parts.next().ok_or(())?)?;
    let destination_port = parse_port(parts.next().ok_or(())?)?;
    if parts.next().is_some() {
        return Err(());
    }
    let source = std::str::from_utf8(source)
        .map_err(|_| ())?
        .parse::<IpAddr>()
        .map_err(|_| ())?;
    let destination = std::str::from_utf8(destination)
        .map_err(|_| ())?
        .parse::<IpAddr>()
        .map_err(|_| ())?;
    let v4 = protocol == b"TCP4";
    if source.is_ipv4() != v4 || destination.is_ipv4() != v4 {
        return Err(());
    }
    Ok(Parsed {
        source: Some(Address::Socket {
            address: SocketAddr::new(source, source_port),
            datagram: false,
        }),
        destination: Some(Address::Socket {
            address: SocketAddr::new(destination, destination_port),
            datagram: false,
        }),
    })
}

pub fn v2(frame: &[u8]) -> Result<Parsed, ()> {
    let signature = b"\r\n\r\n\0\r\nQUIT\n";
    if frame.len() < 16 {
        return Err(());
    }
    if &frame[..12] != signature {
        return Err(());
    }

    let command = frame[12];
    if command != 0x20 && command != 0x21 {
        return Err(());
    }

    let family_proto = frame[13];

    // Check valid family/protocol
    // 0x00: Local
    // 0x11: TCP4
    // 0x12: UDP4
    // 0x21: TCP6
    // 0x22: UDP6
    // 0x31: Unix Stream
    // 0x32: Unix Datagram

    // Check if PROXY command has valid address family
    if command == 0x21 {
        if family_proto == 0x00 {
            return Err(());
        }
    }

    if !matches!(family_proto, 0x00 | 0x11 | 0x12 | 0x21 | 0x22 | 0x31 | 0x32) {
        return Err(());
    }

    let length = u16::from_be_bytes([frame[14], frame[15]]) as usize;
    // The frame contains 16 bytes header + length bytes
    if frame.len() != 16 + length {
        return Err(());
    }

    let data = &frame[16..];

    if command == 0x20 {
        // LOCAL
        return Ok(Parsed {
            source: None,
            destination: None,
        });
    }

    // PROXY
    match family_proto {
        0x11 | 0x12 => {
            // IPv4: 4+4+2+2 = 12
            if length < 12 {
                return Err(());
            }
            let datagram = (family_proto & 0x0F) == 0x02;

            let mut src_ip = [0u8; 4];
            src_ip.copy_from_slice(&data[0..4]);
            let mut dst_ip = [0u8; 4];
            dst_ip.copy_from_slice(&data[4..8]);

            let src_port = u16::from_be_bytes([data[8], data[9]]);
            let dst_port = u16::from_be_bytes([data[10], data[11]]);

            let src_addr = SocketAddr::new(IpAddr::from(src_ip), src_port);
            let dst_addr = SocketAddr::new(IpAddr::from(dst_ip), dst_port);

            Ok(Parsed {
                source: Some(Address::Socket {
                    address: src_addr,
                    datagram,
                }),
                destination: Some(Address::Socket {
                    address: dst_addr,
                    datagram,
                }),
            })
        }
        0x21 | 0x22 => {
            // IPv6: 16+16+2+2 = 36
            if length < 36 {
                return Err(());
            }
            let datagram = (family_proto & 0x0F) == 0x02;

            let mut src_ip = [0u8; 16];
            src_ip.copy_from_slice(&data[0..16]);
            let mut dst_ip = [0u8; 16];
            dst_ip.copy_from_slice(&data[16..32]);

            let src_port = u16::from_be_bytes([data[32], data[33]]);
            let dst_port = u16::from_be_bytes([data[34], data[35]]);

            let src_addr = SocketAddr::new(IpAddr::from(src_ip), src_port);
            let dst_addr = SocketAddr::new(IpAddr::from(dst_ip), dst_port);

            Ok(Parsed {
                source: Some(Address::Socket {
                    address: src_addr,
                    datagram,
                }),
                destination: Some(Address::Socket {
                    address: dst_addr,
                    datagram,
                }),
            })
        }
        0x31 | 0x32 => {
            // Unix: 108+108 = 216
            if length < 216 {
                return Err(());
            }
            let datagram = (family_proto & 0x0F) == 0x02;

            let mut src_path = Vec::new();
            for &b in &data[0..108] {
                if b == 0 {
                    break;
                }
                src_path.push(b);
            }

            let mut dst_path = Vec::new();
            for &b in &data[108..216] {
                if b == 0 {
                    break;
                }
                dst_path.push(b);
            }

            Ok(Parsed {
                source: Some(Address::Unix {
                    path: src_path,
                    datagram,
                }),
                destination: Some(Address::Unix {
                    path: dst_path,
                    datagram,
                }),
            })
        }
        _ => Err(()),
    }
}
