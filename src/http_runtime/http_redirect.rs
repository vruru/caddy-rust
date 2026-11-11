// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Listener HTTP detection and replay before or after TLS, as configured.

#[path = "http_redirect/replay.rs"]
mod replay;
#[path = "http_redirect/request.rs"]
mod request;
#[path = "http_redirect/url.rs"]
mod url;
pub(super) use replay::ReplayIo;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid listener HTTP request")
}

pub(super) async fn prepare<I: AsyncRead + AsyncWrite + Unpin>(
    io: I,
    maximum: Option<i64>,
    deadline: tokio::time::Instant,
    cancel: CancellationToken,
) -> io::Result<ReplayIo<I>> {
    let Some(maximum) = maximum else {
        return Ok(ReplayIo::plain(io));
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "listener stopped")),
        output = tokio::time::timeout_at(deadline, inspect(io, maximum)) => {
            output.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "listener header timeout"))?
        }
    }
}

async fn inspect<I: AsyncRead + AsyncWrite + Unpin>(
    mut io: I,
    maximum: i64,
) -> io::Result<ReplayIo<I>> {
    // bufio.Reader.Peek(5) starts with a 4096-byte read-ahead. Replaying only
    // five bytes would lose the rest of a fragmented/pipelined ClientHello
    // and change connection-close behavior for small configured limits.
    let mut prefix = Vec::new();
    prefix.try_reserve_exact(4096).map_err(|_| invalid())?;
    prefix.resize(4096, 0);
    let mut read = 0;
    while read < 5 {
        let count = io.read(&mut prefix[read..]).await?;
        if count == 0 {
            return Err(invalid());
        }
        read += count;
    }
    prefix.truncate(read);
    if !matches!(
        &prefix[..5],
        b"GET /" | b"HEAD " | b"POST " | b"PUT /" | b"OPTIO"
    ) {
        return Ok(ReplayIo::new(io, prefix));
    }
    let limit = if maximum == 0 { 1024 * 1024 } else { maximum };
    let limit = usize::try_from(limit).map_err(|_| invalid())?;
    if limit < 5 {
        return Err(invalid());
    }
    prefix.truncate(limit.min(prefix.len()));
    let mut header = prefix;
    let mut scan = 0;
    let mut line_start = 0;
    let end = loop {
        let mut completed = None;
        while scan < header.len() {
            if header[scan] == b'\n' {
                let end = if scan > line_start && header[scan - 1] == b'\r' {
                    scan - 1
                } else {
                    scan
                };
                if end == line_start {
                    completed = Some(scan + 1);
                    break;
                }
                line_start = scan + 1;
            }
            scan += 1;
        }
        if let Some(end) = completed {
            break end;
        }
        let count = limit.saturating_sub(header.len()).min(4096);
        if count == 0 {
            return Err(invalid());
        }
        let mut block = [0; 4096];
        let read = io.read(&mut block[..count]).await?;
        if read == 0 {
            return Err(invalid());
        }
        header.try_reserve(read).map_err(|_| invalid())?;
        header.extend_from_slice(&block[..read]);
    };
    let location = request::location(&header[..end]).map_err(|_| invalid())?;
    drop(header);
    io.write_all(b"HTTP/1.0 308 Permanent Redirect\r\nLocation: ")
        .await?;
    io.write_all(&location).await?;
    io.write_all(b"\r\nContent-Length: 0\r\n\r\n").await?;
    io.flush().await?;
    Err(io::Error::other(
        "redirected HTTP request on HTTPS listener",
    ))
}
