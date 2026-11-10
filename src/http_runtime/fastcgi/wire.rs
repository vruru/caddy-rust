// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! FastCGI responder framing. The exchange owner keeps deadlines, body and
//! socket ownership; this module does not spawn detached work.
use bytes::Bytes;
use std::{collections::BTreeMap, future::Future, io};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};

const MAX_WRITE: usize = 65_500;
const MAX_PARAMS: usize = 1024 * 1024;
const BEGIN_REQUEST: u8 = 1;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const STDERR: u8 = 7;
const ID: [u8; 2] = [0, 1];

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
async fn within<T>(
    deadline: Option<Instant>,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let elapsed = || io::Error::new(io::ErrorKind::TimedOut, "FastCGI exchange deadline");
    match deadline {
        Some(limit) => {
            if limit <= Instant::now() {
                return Err(elapsed());
            }
            tokio::time::timeout_at(limit, operation)
                .await
                .map_err(|_| elapsed())?
        }
        None => operation.await,
    }
}
async fn record<W: AsyncWrite + Unpin>(writer: &mut W, kind: u8, bytes: &[u8]) -> io::Result<()> {
    let length = u16::try_from(bytes.len()).map_err(|_| invalid_input("FastCGI record length"))?;
    let [high, low] = length.to_be_bytes();
    let padding = (8 - bytes.len() % 8) % 8;
    let header = [1, kind, ID[0], ID[1], high, low, padding as u8, 0];
    writer.write_all(&header).await?;
    writer.write_all(bytes).await?;
    writer.write_all(&[0; 7][..padding]).await
}
fn length_width(length: usize) -> usize {
    if length < 128 { 1 } else { 4 }
}
fn append_length(buffer: &mut Vec<u8>, length: usize) {
    if length < 128 {
        buffer.push(length as u8);
    } else {
        // Both lengths are validated before this operation; no value is
        // larger than the configured single-record byte ceiling.
        buffer.extend_from_slice(&((length as u32) | 0x8000_0000).to_be_bytes());
    }
}
fn clipped_value(name: &str, value_len: usize) -> io::Result<usize> {
    // Caddy sends each pair in one PARAMS record. Reserve the maximum eight
    // length-prefix bytes, and clip values using the same byte rule. Reject a
    // name that cannot fit instead of panicking on a negative Go slice bound.
    let value_room = (MAX_WRITE - 8)
        .checked_sub(name.len())
        .filter(|_| !name.is_empty())
        .ok_or_else(|| invalid_input("FastCGI parameter name length"))?;
    Ok(value_room.min(value_len))
}
pub struct Parameters<'a> {
    fields: &'a BTreeMap<String, Vec<u8>>,
    size: usize,
}
impl<'a> Parameters<'a> {
    pub fn new(fields: &'a BTreeMap<String, Vec<u8>>) -> io::Result<Self> {
        let mut size = 0usize;
        for (name, value) in fields {
            let take = clipped_value(name, value.len())?;
            let next = name.len() + take + length_width(name.len()) + length_width(take);
            size = size
                .checked_add(next)
                .filter(|bytes| *bytes <= MAX_PARAMS)
                .ok_or_else(|| invalid_input("FastCGI parameters exceed aggregate byte budget"))?;
        }
        Ok(Self { fields, size })
    }
    pub async fn send<W: AsyncWrite + Unpin>(
        self,
        writer: &mut W,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        within(deadline, async {
            let mut packet = Vec::with_capacity(self.size.min(MAX_WRITE));
            for (name, value) in self.fields {
                let take = clipped_value(name, value.len())?;
                let next = name.len() + take + length_width(name.len()) + length_width(take);
                if packet.len() + next > MAX_WRITE {
                    record(writer, PARAMS, &packet).await?;
                    packet.clear();
                }
                append_length(&mut packet, name.len());
                append_length(&mut packet, take);
                packet.extend_from_slice(name.as_bytes());
                packet.extend_from_slice(&value[..take]);
            }
            if !packet.is_empty() {
                record(writer, PARAMS, &packet).await?;
            }
            record(writer, PARAMS, &[]).await
        })
        .await
    }
}
pub async fn begin<W: AsyncWrite + Unpin>(
    writer: &mut W,
    deadline: Option<Instant>,
) -> io::Result<()> {
    within(
        deadline,
        record(writer, BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]),
    )
    .await
}
pub async fn send_stdin<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    within(deadline, async {
        for data in bytes.chunks(MAX_WRITE) {
            record(writer, STDIN, data).await?;
        }
        Ok(())
    })
    .await
}
pub async fn finish_stdin<W: AsyncWrite + Unpin>(
    writer: &mut W,
    deadline: Option<Instant>,
) -> io::Result<()> {
    within(deadline, async {
        record(writer, STDIN, &[]).await?;
        writer.flush().await
    })
    .await
}

#[derive(Debug, Eq, PartialEq)]
pub enum Event {
    Stdout(Bytes),
    Stderr(Bytes),
    End {
        application_status: u32,
        protocol_status: u8,
    },
}
pub struct Responses<R> {
    input: R,
    deadline: Option<Instant>,
    state: ReadState,
}
#[derive(Clone, Copy)]
enum ReadState {
    Open,
    Finished,
    Poisoned,
}

impl<R: AsyncRead + Unpin> Responses<R> {
    pub fn new(input: R, deadline: Option<Instant>) -> Self {
        Self {
            input,
            deadline,
            state: ReadState::Open,
        }
    }
    pub async fn next(&mut self) -> io::Result<Option<Event>> {
        match self.state {
            ReadState::Finished => return Ok(None),
            ReadState::Poisoned => {
                return Err(invalid_data("FastCGI response cursor cannot be reused"));
            }
            ReadState::Open => {}
        }
        // Cancellation after a partial record must never make the next read
        // reinterpret the remaining bytes as a fresh record header.
        self.state = ReadState::Poisoned;
        let event = within(self.deadline, read_event(&mut self.input)).await?;
        self.state = if matches!(event, Event::End { .. }) {
            ReadState::Finished
        } else {
            ReadState::Open
        };
        Ok(Some(event))
    }
}

async fn read_event<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Event> {
    loop {
        let mut header = [0u8; 8];
        input.read_exact(&mut header).await?;
        if header[0] != 1 || header[2..4] != ID {
            return Err(invalid_data("FastCGI response version or request ID"));
        }
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        let kind = header[1];
        if !matches!(kind, STDOUT | STDERR | END_REQUEST) || kind == END_REQUEST && length != 8 {
            return Err(invalid_data("FastCGI response record type or length"));
        }
        let mut body = vec![0; length];
        input.read_exact(&mut body).await?;
        if header[6] != 0 {
            let mut pad = [0; 255];
            input.read_exact(&mut pad[..header[6] as usize]).await?;
        }
        match kind {
            STDOUT if !body.is_empty() => return Ok(Event::Stdout(body.into())),
            STDERR if !body.is_empty() => return Ok(Event::Stderr(body.into())),
            END_REQUEST => {
                return Ok(Event::End {
                    application_status: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                    protocol_status: body[4],
                });
            }
            _ => tokio::task::consume_budget().await,
        }
    }
}
