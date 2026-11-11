// Copyright 2009 The Go Authors.
// SPDX-License-Identifier: BSD-3-Clause
//! Go's initial record-header rejection before Rustls consumes the TLS stream.
use super::http_redirect::ReplayIo;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The caller retains its original absolute deadline and cancellation owner.
/// Only the header is required; a claimed record body is never awaited here.
pub(super) async fn prepare<I: AsyncRead + AsyncWrite + Unpin>(
    mut io: I,
    reply_http: bool,
) -> io::Result<ReplayIo<I>> {
    // Go's initial bytes.Buffer Grow(5 + bytes.MinRead) gets a 576-byte
    // allocation class. Preserve this bounded read-ahead and replay all bytes.
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(576)
        .map_err(|_| io::Error::other("TLS prefix allocation failed"))?;
    prefix.resize(576, 0);
    let mut read = 0;
    while read < 5 {
        let count = io.read(&mut prefix[read..]).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete TLS record header",
            ));
        }
        read += count;
    }
    prefix.truncate(read);
    let kind = prefix[0];
    let version = u16::from_be_bytes([prefix[1], prefix[2]]);
    let length = u16::from_be_bytes([prefix[3], prefix[4]]);
    let alert = if kind == 0x80 {
        Some(70)
    } else if !matches!(kind, 21 | 22) || version >= 0x1000 {
        // net/http sends this only while its accepted outer connection exposes
        // TLS state/handshake; a post-TLS listener wrapper hides that interface.
        if reply_http
            && matches!(
                &prefix[..5],
                b"GET /" | b"HEAD " | b"POST " | b"PUT /" | b"OPTIO"
            )
        {
            io.write_all(b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n").await?;
            io.flush().await?;
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid initial TLS record",
        ));
    } else if length > 18432 {
        Some(22)
    } else if length == 0 {
        Some(10)
    } else {
        None
    };
    if let Some(description) = alert {
        // No version is negotiated yet: Go writes these alerts as TLS 1.0.
        io.write_all(&[21, 3, 1, 0, 2, 2, description]).await?;
        io.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rejected initial TLS record",
        ));
    }
    Ok(ReplayIo::new(io, prefix))
}
