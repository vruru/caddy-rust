// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Bounded CGI response header parsing and streaming over FastCGI records.
use super::wire::{Event, Responses};
use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use std::io;
use tokio::io::AsyncRead;

const HEADER_BYTES: usize = 1024 * 1024;
const HEADER_FIELDS: usize = 8192;
const STDERR_BYTES: usize = 16 * 1024;
const CHUNK_LINE_BYTES: usize = 4096;

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn incomplete() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete FastCGI response")
}
fn trim(mut input: &[u8]) -> &[u8] {
    while matches!(input.first(), Some(b' ' | b'\t')) {
        input = &input[1..];
    }
    while matches!(input.last(), Some(b' ' | b'\t')) {
        input = &input[..input.len() - 1];
    }
    input
}

pub type StderrSink = Box<dyn FnOnce(StatusCode, &[u8], bool) + Send>;

pub struct Reader<R> {
    wire: Responses<R>,
    buffered: Bytes,
    stderr: Vec<u8>,
    stderr_truncated: bool,
    report_stderr: Option<StderrSink>,
    status: StatusCode,
}

pub struct Reply<R> {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: ReplyBody<R>,
}

pub struct ReplyBody<R> {
    reader: Reader<R>,
    mode: Mode,
    finished: bool,
    chunk_overhead: u64,
}

enum Mode {
    Raw(Option<u64>),
    Chunked(Chunk),
}

enum Chunk {
    Size,
    Data(u64),
    Delimiter,
}

impl<R> Drop for Reader<R> {
    fn drop(&mut self) {
        if (!self.stderr.is_empty() || self.stderr_truncated)
            && let Some(sink) = self.report_stderr.take()
        {
            sink(self.status, &self.stderr, self.stderr_truncated);
        }
    }
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(wire: Responses<R>, report_stderr: Option<StderrSink>) -> Self {
        Self {
            wire,
            buffered: Bytes::new(),
            stderr: Vec::new(),
            stderr_truncated: false,
            report_stderr,
            status: StatusCode::BAD_GATEWAY,
        }
    }

    async fn available(&mut self) -> io::Result<bool> {
        while self.buffered.is_empty() {
            match self.wire.next().await? {
                Some(Event::Stdout(bytes)) => self.buffered = bytes,
                Some(Event::Stderr(bytes)) => {
                    if self.report_stderr.is_some() {
                        let n = (STDERR_BYTES - self.stderr.len()).min(bytes.len());
                        self.stderr.extend_from_slice(&bytes[..n]);
                        self.stderr_truncated |= n != bytes.len();
                    }
                    tokio::task::consume_budget().await;
                }
                Some(Event::End {
                    application_status: _,
                    protocol_status: 0,
                })
                | None => return Ok(false),
                Some(Event::End { .. }) => {
                    return Err(bad("FastCGI responder did not complete the request"));
                }
            }
        }
        Ok(true)
    }

    async fn line(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            if !self.available().await? {
                return Err(incomplete());
            }
            let newline = self.buffered.iter().position(|&b| b == b'\n');
            let take = newline.map_or(self.buffered.len(), |n| n + 1);
            if take > limit.saturating_sub(result.len()) {
                return Err(bad("FastCGI response line exceeds byte budget"));
            }
            result.extend_from_slice(&self.buffered.split_to(take));
            if newline.is_some() {
                return Ok(result);
            }
        }
    }

    pub async fn headers(mut self) -> io::Result<Reply<R>> {
        let mut headers = HeaderMap::new();
        let mut left = HEADER_BYTES;
        let mut seen = 0;
        let mut field: Option<(Option<HeaderName>, Vec<u8>)> = None;
        loop {
            let line = self.line(left).await?;
            left -= line.len();
            let line = &line[..line.len() - 1];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if matches!(line.first(), Some(b' ' | b'\t')) {
                let (_, value) = field
                    .as_mut()
                    .ok_or_else(|| bad("FastCGI response header starts with continuation"))?;
                let rest = trim(line);
                if !rest.is_empty() {
                    value.push(b' ');
                    value.extend_from_slice(rest);
                }
                continue;
            }
            if let Some((name, value)) = field.take() {
                let value = HeaderValue::from_bytes(&value)
                    .map_err(|_| bad("invalid FastCGI response header value"))?;
                if let Some(name) = name {
                    headers.append(name, value);
                }
            }
            if line.is_empty() {
                break;
            }
            seen += 1;
            if seen > HEADER_FIELDS {
                return Err(bad("FastCGI response header count exceeds budget"));
            }
            let colon = line
                .iter()
                .position(|&b| b == b':')
                .ok_or_else(|| bad("malformed FastCGI response header"))?;
            if colon == 0 {
                return Err(bad("empty FastCGI response header name"));
            }
            // Go MIME accepts a space in an old-style name but net/http does
            // not put that invalid name on the client wire.
            let name = &line[..colon];
            if !name
                .iter()
                .all(|b| *b == b' ' || HeaderName::from_bytes(std::slice::from_ref(b)).is_ok())
            {
                return Err(bad("invalid FastCGI response header name"));
            }
            field = Some((
                HeaderName::from_bytes(name).ok(),
                trim(&line[colon + 1..]).to_vec(),
            ));
        }
        self.status = match headers.get("status").filter(|v| !v.is_empty()) {
            Some(value) => {
                let first = value
                    .as_bytes()
                    .split(|&b| b == b' ')
                    .next()
                    .unwrap_or_default();
                let number = std::str::from_utf8(first)
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                    .and_then(|n| StatusCode::from_u16(n).ok())
                    .ok_or_else(|| bad("invalid FastCGI response status"))?;
                if number.is_informational() {
                    return Err(bad("FastCGI response status must be final"));
                }
                number
            }
            None => StatusCode::OK,
        };
        let chunked = headers
            .get(header::TRANSFER_ENCODING)
            .is_some_and(|v| v.as_bytes() == b"chunked");
        headers.remove(header::TRANSFER_ENCODING);
        let size = if chunked {
            None
        } else {
            normalized_length(&headers)?
        };
        headers.remove(header::CONTENT_LENGTH);
        if let Some(size) = size {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
        }
        let mode = if chunked {
            Mode::Chunked(Chunk::Size)
        } else {
            Mode::Raw(size)
        };
        Ok(Reply {
            status: self.status,
            headers,
            body: ReplyBody {
                reader: self,
                mode,
                finished: false,
                chunk_overhead: 0,
            },
        })
    }
}

fn normalized_length(headers: &HeaderMap) -> io::Result<Option<u64>> {
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(first) = lengths.next() else {
        return Ok(None);
    };
    let Some(length) = first.to_str().ok().and_then(|s| {
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse::<i64>().ok()
        } else {
            None
        }
    }) else {
        return Ok(None);
    };
    if lengths.any(|other| other != first) {
        return Err(bad("conflicting FastCGI Content-Length fields"));
    }
    Ok(Some(length as u64))
}

impl<R: AsyncRead + Unpin> ReplyBody<R> {
    pub async fn next(&mut self) -> io::Result<Option<Bytes>> {
        if self.finished {
            return Ok(None);
        }
        // An error or cancelled mid-record read makes the cursor single-use.
        self.finished = true;
        let value = self.next_inner().await?;
        self.finished = value.is_none();
        Ok(value)
    }

    async fn next_inner(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            match &mut self.mode {
                Mode::Raw(remaining) => {
                    if !self.reader.available().await? {
                        return match remaining {
                            Some(1..) => Err(incomplete()),
                            _ => Ok(None),
                        };
                    }
                    let bytes = std::mem::take(&mut self.reader.buffered);
                    if let Some(remaining) = remaining {
                        let len = bytes.len() as u64;
                        if len > *remaining {
                            return Err(bad("FastCGI body exceeds Content-Length"));
                        }
                        *remaining -= len;
                    }
                    return Ok(Some(bytes));
                }
                Mode::Chunked(Chunk::Size) => {
                    let line = self.reader.line(CHUNK_LINE_BYTES).await?;
                    let line = line
                        .strip_suffix(b"\r\n")
                        .ok_or_else(|| bad("malformed FastCGI chunk size line"))?;
                    if line.contains(&b'\r') {
                        return Err(bad("invalid CR in FastCGI chunk size line"));
                    }
                    let overhead = line.len() as u64 + 2;
                    let mut line = line;
                    while matches!(line.last(), Some(b' ' | b'\t')) {
                        line = &line[..line.len() - 1];
                    }
                    let size = line.split(|&b| b == b';').next().unwrap_or_default();
                    if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit)
                    {
                        return Err(bad("invalid FastCGI chunk size"));
                    }
                    let size =
                        u64::from_str_radix(std::str::from_utf8(size).expect("hex is ASCII"), 16)
                            .map_err(|_| bad("invalid FastCGI chunk size"))?;
                    self.chunk_overhead = self
                        .chunk_overhead
                        .saturating_add(overhead)
                        .saturating_sub(16u64.saturating_add(size.saturating_mul(2)));
                    if self.chunk_overhead > 16 * 1024 {
                        return Err(bad("FastCGI chunks contain excessive framing overhead"));
                    }
                    if size == 0 {
                        return Ok(None);
                    } // Go's chunked reader leaves trailers unread.
                    self.mode = Mode::Chunked(Chunk::Data(size));
                }
                Mode::Chunked(Chunk::Data(remaining)) => {
                    if !self.reader.available().await? {
                        return Err(incomplete());
                    }
                    let n = (*remaining).min(self.reader.buffered.len() as u64) as usize;
                    let bytes = self.reader.buffered.split_to(n);
                    *remaining -= n as u64;
                    if *remaining == 0 {
                        self.mode = Mode::Chunked(Chunk::Delimiter);
                    }
                    return Ok(Some(bytes));
                }
                Mode::Chunked(Chunk::Delimiter) => {
                    for wanted in b"\r\n" {
                        if !self.reader.available().await? {
                            return Err(incomplete());
                        }
                        if self.reader.buffered.get_u8() != *wanted {
                            return Err(bad("invalid FastCGI chunk delimiter"));
                        }
                    }
                    self.mode = Mode::Chunked(Chunk::Size);
                }
            }
        }
    }
}
