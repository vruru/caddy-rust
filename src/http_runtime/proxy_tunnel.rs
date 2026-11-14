//! Bounded protocol handshakes, before any origin application bytes are sent.
use http::Uri;
use std::{io, net::IpAddr};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(super) async fn socks5<I: AsyncRead + AsyncWrite + Unpin>(
    io: &mut I,
    target: &Uri,
    auth: Option<(&[u8], &[u8])>,
) -> io::Result<()> {
    if auth.is_some() {
        io.write_all(&[5, 2, 0, 2]).await?;
    } else {
        io.write_all(&[5, 1, 0]).await?;
    }
    io.flush().await?;
    let mut choice = [0; 2];
    io.read_exact(&mut choice).await?;
    if choice[0] != 5 {
        return Err(bad("invalid SOCKS version"));
    }
    match choice[1] {
        0 => {}
        2 => {
            let (user, password) =
                auth.ok_or_else(|| bad("SOCKS authentication was not offered"))?;
            if user.len() > 255 || password.len() > 255 {
                return Err(bad("SOCKS credentials exceed protocol limits"));
            }
            let mut packet = [0u8; 513];
            packet[0] = 1;
            packet[1] = user.len() as u8;
            packet[2..2 + user.len()].copy_from_slice(user);
            packet[2 + user.len()] = password.len() as u8;
            packet[3 + user.len()..3 + user.len() + password.len()].copy_from_slice(password);
            io.write_all(&packet[..3 + user.len() + password.len()])
                .await?;
            io.flush().await?;
            let mut reply = [0; 2];
            io.read_exact(&mut reply).await?;
            if reply != [1, 0] {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS authentication rejected",
                ));
            }
        }
        _ => {
            return Err(bad(
                "SOCKS proxy selected an unsupported authentication method",
            ));
        }
    }
    let host = target
        .host()
        .ok_or_else(|| bad("SOCKS target has no host"))?
        .trim_matches(['[', ']']);
    let port = target
        .port_u16()
        .unwrap_or(if target.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let mut packet = [0u8; 262];
    packet[..3].copy_from_slice(&[5, 1, 0]);
    let end = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            packet[3] = 1;
            packet[4..8].copy_from_slice(&ip.octets());
            8
        }
        Ok(IpAddr::V6(ip)) => {
            packet[3] = 4;
            packet[4..20].copy_from_slice(&ip.octets());
            20
        }
        Err(_) => {
            if host.is_empty() || host.len() > 255 {
                return Err(bad("SOCKS target exceeds protocol limits"));
            }
            packet[3] = 3;
            packet[4] = host.len() as u8;
            packet[5..5 + host.len()].copy_from_slice(host.as_bytes());
            5 + host.len()
        }
    };
    packet[end..end + 2].copy_from_slice(&port.to_be_bytes());
    io.write_all(&packet[..end + 2]).await?;
    io.flush().await?;
    let mut reply = [0u8; 4];
    io.read_exact(&mut reply).await?;
    if reply[0] != 5 || reply[2] != 0 {
        return Err(bad("invalid SOCKS CONNECT reply"));
    }
    if reply[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "SOCKS CONNECT rejected",
        ));
    }
    let length = match reply[3] {
        1 => 6,
        4 => 18,
        3 => io.read_u8().await? as usize + 2,
        _ => return Err(bad("invalid SOCKS address family")),
    };
    let mut rest = [0u8; 257];
    io.read_exact(&mut rest[..length]).await?;
    Ok(())
}
pub(super) async fn http_connect<I: AsyncRead + AsyncWrite + Unpin>(
    mut io: I,
    target: &Uri,
    auth: Option<&http::HeaderValue>,
    limit: usize,
) -> io::Result<BufReader<I>> {
    let authority = target
        .authority()
        .ok_or_else(|| bad("CONNECT target has no authority"))?;
    let authority = if target.port().is_some() {
        if target.port_u16().is_none() {
            return Err(bad("CONNECT target port out of range"));
        }
        authority.as_str().to_owned()
    } else {
        format!(
            "{}:{}",
            authority,
            if target.scheme_str() == Some("https") {
                443
            } else {
                80
            }
        )
    };
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = auth {
        head.push_str("Proxy-Authorization: ");
        head.push_str(
            auth.to_str()
                .map_err(|_| bad("invalid proxy authentication header"))?,
        );
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    io.write_all(head.as_bytes()).await?;
    io.flush().await?;
    drop(head);
    let mut reader = BufReader::new(io);
    let mut head = Vec::new();
    loop {
        let bytes = reader.fill_buf().await?;
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy response ended before headers",
            ));
        }
        let count = bytes
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |n| n + 1);
        if count > limit.saturating_sub(head.len()) {
            return Err(bad("proxy response headers exceed configured limit"));
        }
        head.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
    }
    let mut lines = head.split(|&b| b == b'\n');
    let line = lines.next().ok_or_else(|| bad("missing proxy status"))?;
    let mut words = line.split(|&b| b == b' ');
    let version = words.next().unwrap_or_default();
    let status = words.next().unwrap_or_default();
    if !matches!(version, b"HTTP/1.1" | b"HTTP/1.0") {
        return Err(bad("invalid proxy HTTP version"));
    }
    if status != b"200" {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "HTTP proxy CONNECT rejected",
        ));
    }
    let mut previous = false;
    for raw in lines {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            break;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if !previous {
                return Err(bad("invalid proxy header continuation"));
            }
            continue;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| bad("invalid proxy response header"))?;
        if colon == 0
            || !line[..colon]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
            || line[colon + 1..]
                .iter()
                .any(|&b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(bad("invalid proxy response header"));
        }
        previous = true;
    }
    Ok(reader)
}
