// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Dedicated FastCGI responder exchanges with owned sockets and bounded work.
pub(super) mod admission;
mod env;
mod reply;
pub(super) mod spool;
mod wire;

use super::{
    Body, BoxError, Bytes, Response, StatusCode, full, proxy,
    request::{Context, budget_failure, failure},
    resource_budget::BudgetError,
};
use crate::http_config::types::{FastCgiConfig, ProxyConfig};
use anyhow::{Result, ensure};
use futures_util::stream;
use http::{HeaderValue, Method, Request, Version, header};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body as _, Frame};
use std::{
    collections::BTreeMap,
    io,
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context as PollContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::OwnedSemaphorePermit,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
pub(super) struct TlsDetails {
    version: &'static str,
    cipher: Option<rustls::CipherSuite>,
}

impl TlsDetails {
    pub(super) fn from_metadata(m:&super::connection_snapshot::ConnectionMetadata)->Self{Self{version:match m.version{0x303=>"TLSv1.2",0x304=>"TLSv1.3",_=>""},cipher:Some(m.cipher_suite.into())}}
    pub(super) fn of(connection: &rustls::ServerConnection) -> Self {
        Self {
            version: match connection.protocol_version() {
                Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
                Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
                _ => "",
            },
            cipher: connection.negotiated_cipher_suite().map(|s| s.suite()),
        }
    }

    fn cipher_name(self) -> std::borrow::Cow<'static, str> {
        use rustls::CipherSuite::*;
        let name = match self.cipher {
            Some(TLS13_AES_128_GCM_SHA256) => "TLS_AES_128_GCM_SHA256",
            Some(TLS13_AES_256_GCM_SHA384) => "TLS_AES_256_GCM_SHA384",
            Some(TLS13_CHACHA20_POLY1305_SHA256) => "TLS_CHACHA20_POLY1305_SHA256",
            Some(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) => {
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            }
            Some(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) => {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            }
            Some(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256) => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            Some(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            Some(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            Some(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256) => {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            Some(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)=>"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            Some(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)=>"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            Some(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)=>"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            Some(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)=>"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            Some(suite) => return format!("0x{:04X}", u16::from(suite)).into(),
            None => "",
        };
        name.into()
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Socket {
    io: Box<dyn Io>,
    _business: Arc<super::BusinessGuard>,
    // Declaration order keeps admission held until actual I/O destruction.
    _permit: (OwnedSemaphorePermit, OwnedSemaphorePermit),
}
impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut PollContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Socket {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool { self.io.is_write_vectored() }
    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.io).poll_write_vectored(cx, bufs)
    }
}

/// The connected exchange may have emitted a partial BEGIN/PARAMS record.
/// A failed non-idempotent request must not be replayed on another backend.
#[derive(Debug)]
pub(super) struct ExchangeStarted;
impl std::fmt::Display for ExchangeStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FastCGI exchange may have started")
    }
}
impl std::error::Error for ExchangeStarted {}

enum Target {
    Tcp {
        host: String,
        port: u16,
        ipv6: Option<bool>,
        network: &'static str,
    },
    Unix(String),
}
impl Target {
    fn parse(dial: &str) -> Result<Self> {
        ensure!(!dial.contains(['\0', '\r', '\n']), "invalid FastCGI target");
        let (network, address) = dial.split_once('/').unwrap_or(("tcp", dial));
        if network == "unix" {
            ensure!(!address.is_empty(), "FastCGI Unix path is empty");
            return Ok(Self::Unix(address.to_owned()));
        }
        let (network, ipv6) = match network {
            "tcp" => ("tcp", None),
            "tcp4" => ("tcp4", Some(false)),
            "tcp6" => ("tcp6", Some(true)),
            _ => anyhow::bail!("unknown FastCGI network"),
        };
        let authority = address.parse::<http::uri::Authority>()?;
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        ensure!(
            !host.is_empty() && !address.contains('@'),
            "invalid FastCGI host"
        );
        Ok(Self::Tcp {
            host: host.to_owned(),
            port: authority.port_u16().unwrap_or(0),
            ipv6,
            network,
        })
    }

    fn key(&self) -> String {
        match self {
            Self::Tcp { host, port, .. } => format!("tcp/{host}:{port}").to_ascii_lowercase(),
            Self::Unix(path) => format!("unix/{path}"),
        }
    }

    fn set_placeholders(&self, ctx: &mut Context) {
        let (address, hostport, host, port) = match self {
            Self::Tcp {
                host,
                port,
                network,
                ..
            } => {
                let hostport = if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                };
                (
                    format!("{network}/{hostport}"),
                    hostport,
                    host.clone(),
                    port.to_string(),
                )
            }
            Self::Unix(path) => (
                format!("unix/{path}"),
                path.clone(),
                path.clone(),
                String::new(),
            ),
        };
        for (key, value) in [
            ("address", address),
            ("hostport", hostport),
            ("host", host),
            ("port", port),
        ] {
            ctx.values
                .insert(format!("http.reverse_proxy.upstream.{key}"), value);
        }
    }

    async fn connect(self, ctx: &mut Context, timeout: Duration) -> Result<Box<dyn Io>> {
        let stop = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure(StatusCode::BAD_GATEWAY))?;
        let operation = async {
            match self {
                Self::Unix(path) => unix_connect(path).await,
                Self::Tcp {
                    host, port, ipv6, ..
                } => {
                    let candidates = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        vec![SocketAddr::new(ip, port)]
                    } else {
                        let dns = ctx.resources.fastcgi_dns.clone();
                        dns.run(super::map_runtime::text_job(ctx.text_owner(),move || {
                            (host.as_str(), port)
                                .to_socket_addrs()
                                .map(|addrs| addrs.take(64).collect::<Vec<_>>())
                        })?)
                        .await
                        .map_err(|error| budget_failure(ctx, error))?.into_context(ctx)??
                    };
                    let (primary, fallback) = split_families(candidates, ipv6);
                    let socket = if fallback.is_empty() {
                        dial_family(primary).await?
                    } else {
                        let primary = dial_family(primary);
                        let fallback = dial_family(fallback);
                        tokio::pin!(primary, fallback);
                        let first = tokio::select! {
                            result = &mut primary => Some(result),
                            _ = tokio::time::sleep(Duration::from_millis(300)) => None,
                        };
                        match first {
                            Some(Ok(stream)) => stream,
                            Some(Err(_)) => fallback.await?,
                            None => tokio::select! {
                                result = &mut primary => match result { Ok(stream) => stream, Err(_) => fallback.await? },
                                result = &mut fallback => match result { Ok(stream) => stream, Err(_) => primary.await? },
                            },
                        }
                    };
                    let _ = socket.set_nodelay(true);
                    Ok(Box::new(socket) as Box<dyn Io>)
                }
            }
        };
        match tokio::time::timeout_at(stop, operation).await {
            Err(_) => Err(failure(StatusCode::BAD_GATEWAY)),
            Ok(Err(error))
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(super::request::descriptor_exhausted) =>
            {
                Err(budget_failure(ctx, BudgetError::Overloaded))
            }
            Ok(result) => result,
        }
    }
}

fn split_families(
    addresses: Vec<SocketAddr>,
    ipv6: Option<bool>,
) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let mut addresses = addresses
        .into_iter()
        .filter(|address| ipv6.is_none_or(|family| address.is_ipv6() == family));
    let Some(first) = addresses.next() else {
        return (Vec::new(), Vec::new());
    };
    let family = first.is_ipv6();
    let mut primary = vec![first];
    let mut fallback = Vec::new();
    for address in addresses {
        if address.is_ipv6() == family {
            primary.push(address);
        } else {
            fallback.push(address);
        }
    }
    (primary, fallback)
}

async fn dial_family(addresses: Vec<SocketAddr>) -> io::Result<TcpStream> {
    let mut last = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no FastCGI target addresses",
    );
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) if super::request::descriptor_exhausted(&error) => return Err(error),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(unix)]
async fn unix_connect(path: String) -> Result<Box<dyn Io>> {
    // Tokio handles the leading NUL representation for Linux abstract
    // addresses. macOS and other Unix platforms use filesystem paths.
    let path = if cfg!(target_os = "linux") && path.starts_with('@') {
        format!("\0{}", &path[1..])
    } else {
        path
    };
    Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
}
#[cfg(not(unix))]
async fn unix_connect(_path: String) -> Result<Box<dyn Io>> {
    anyhow::bail!("Unix FastCGI socket unavailable on this platform")
}

async fn root(ctx: &mut Context, config: &FastCgiConfig) -> Result<PathBuf> {
    let expanded=ctx.root_resolved(config.root.as_deref().unwrap_or("{http.vars.root}")).await?;
    let path = PathBuf::from(if expanded.is_empty() {
        ".".into()
    } else {
        expanded
    });
    let canonicalize = config.resolve_root_symlink;
    if path.is_absolute() && !canonicalize {
        return Ok(clean_absolute(path));
    }
    let metadata = ctx.resources.metadata.clone();
    ctx.reserve_text_copy(path.as_os_str().len().saturating_mul(8).saturating_add(8192))?;
    Ok(metadata
        .run(super::map_runtime::text_job(ctx.text_owner(),move || {
            let absolute = clean_absolute(if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            });
            if canonicalize {
                std::fs::canonicalize(absolute)
            } else {
                Ok(absolute)
            }
        })?)
        .await
        .map_err(|e| budget_failure(ctx, e))?.into_context(ctx)??)
}

fn clean_absolute(path: PathBuf) -> PathBuf {
    use std::path::Component;
    let mut result = PathBuf::new();
    for item in path.components() {
        match item {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            _ => result.push(item.as_os_str()),
        }
    }
    result
}

fn deadline(duration: Option<Duration>) -> Result<Option<Instant>> {
    duration
        .map(|value| {
            Instant::now()
                .checked_add(value)
                .ok_or_else(|| failure(StatusCode::BAD_GATEWAY))
        })
        .transpose()
}

fn has_content(method: &Method, length: Option<u64>) -> bool {
    match length {
        Some(length) => length != 0,
        None => !matches!(
            *method,
            Method::GET
                | Method::HEAD
                | Method::OPTIONS
                | Method::DELETE
                | Method::TRACE
                | Method::CONNECT
        ),
    }
}

struct BodyPrefix {
    body: Body,
    buffered: Vec<Bytes>,
    prefix_credits: Vec<OwnedSemaphorePermit>,
    spool: Option<spool::Spool>,
    length: u64,
    content_length_override: Option<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct PreparedLength {
    config: usize,
    length: u64,
    content_length_override: Option<u64>,
}

/// Locally read prefix storage remains owned until the new one-shot body is
/// dropped. Merely creating it never upgrades its retry capability to Full.
struct PrefixedBody {
    prefix: BodyPrefix,
    spool_body: Option<Body>,
    buffered: std::collections::VecDeque<Bytes>,
    hint: hyper::body::SizeHint,
}

impl BodyPrefix {
    fn into_body(mut self) -> Body {
        let spool_reader = self.spool.take().map(|spool| spool.reader());
        let stored = spool_reader.as_ref().map_or(0, spool::SpoolReader::len)
            + self
                .buffered
                .iter()
                .map(|bytes| bytes.len() as u64)
                .sum::<u64>();
        let remaining = self.body.size_hint();
        let mut hint = hyper::body::SizeHint::new();
        if let Some(upper) = remaining.upper().and_then(|n| n.checked_add(stored)) {
            hint.set_upper(upper);
        }
        hint.set_lower(remaining.lower().saturating_add(stored));
        let buffered = std::mem::take(&mut self.buffered).into();
        PrefixedBody {
            prefix: self,
            spool_body: spool_reader.map(spool::SpoolReader::into_body),
            buffered,
            hint,
        }
        .boxed_unsync()
    }
}

impl hyper::body::Body for PrefixedBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut PollContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let output = if let Some(spool) = &mut this.spool_body {
            match Pin::new(spool).poll_frame(cx) {
                Poll::Ready(None) => {
                    this.spool_body = None;
                    None
                }
                output => Some(output),
            }
        } else {
            None
        };
        let output = output.unwrap_or_else(|| {
            if let Some(bytes) = this.buffered.pop_front() {
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            } else {
                this.prefix.prefix_credits.clear();
                Pin::new(&mut this.prefix.body).poll_frame(cx)
            }
        });
        if let Poll::Ready(Some(Ok(frame))) = &output {
            if let Some(bytes) = frame.data_ref() {
                let n = bytes.len() as u64;
                let mut hint = hyper::body::SizeHint::new();
                if let Some(upper) = this.hint.upper() {
                    hint.set_upper(upper.saturating_sub(n));
                }
                hint.set_lower(this.hint.lower().saturating_sub(n));
                this.hint = hint;
            }
        } else if matches!(output, Poll::Ready(None)) {
            this.hint = hyper::body::SizeHint::with_exact(0);
        }
        output
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.hint
    }
    fn is_end_stream(&self) -> bool {
        self.spool_body.is_none() && self.buffered.is_empty() && self.prefix.body.is_end_stream()
    }
}

pub(super) async fn prepare_source(
    ctx: &mut Context,
    config: &ProxyConfig,
    transport: &FastCgiConfig,
    body: Body,
) -> Result<super::proxy_replay::ReplaySource> {
    let replacement = ctx
        .req()
        .extensions()
        .get::<super::request_body::Replacement>()
        .map(|v| v.length);
    let known = replacement.or_else(|| body.size_hint().exact());
    let incremental = super::incremental::is_enabled(ctx.req().headers());
    let source = prefix(ctx, body, known, transport, incremental,&config.handler.proxy_status_name).await?;
    let length = PreparedLength {
        config: config as *const ProxyConfig as usize,
        length: source.length,
        content_length_override: source.content_length_override,
    };
    let body = source.into_body();
    ctx.req_mut().extensions_mut().insert(length);
    Ok(super::proxy_replay::ReplaySource::new(body))
}

async fn prefix(
    ctx: &mut Context,
    mut body: Body,
    mut length: Option<u64>,
    transport: &FastCgiConfig,
    incremental: bool,
    proxy_status_name:&str,
) -> Result<BodyPrefix> {
    let method = ctx.req().method().clone();
    let mut buffered = Vec::new();
    let mut spilled = None;
    let mut overwritten = None;
    let mut prefix_credits = Vec::new();
    if incremental {
        if has_content(&method, length) {
            if length.is_none() || transport.explicit_request_buffer {
                return Err(super::proxy_handler::refuse(ctx,proxy_status_name,None));
            }
        } else {
            length = Some(0);
        }
    } else if !body.is_end_stream() {
        let mut seen = 0u64;
        let mut in_memory = bytes::BytesMut::new();
        let mut memory_units = 0;
        while transport.request_buffer.is_none_or(|cap| seen < cap) {
            let frame = match body.frame().await {
                None => {
                    length = Some(seen);
                    overwritten = Some(seen);
                    break;
                }
                Some(Err(error)) => {
                    return Err(failure(
                        if super::request_body::limit_error(error.as_ref()) {
                            StatusCode::PAYLOAD_TOO_LARGE
                        } else {
                            StatusCode::BAD_REQUEST
                        },
                    ));
                }
                Some(Ok(frame)) => frame,
            };
            if let Ok(mut data) = frame.into_data() {
                let count = transport.request_buffer.map_or(data.len(), |cap| {
                    (cap - seen).min(data.len() as u64) as usize
                });
                let prefix = data.split_to(count);
                seen = seen
                    .checked_add(count as u64)
                    .ok_or_else(|| failure(StatusCode::PAYLOAD_TOO_LARGE))?;
                if spilled.is_none() && seen <= spool::MEMORY_PREFIX as u64 {
                    let units = (seen * 2).div_ceil(admission::MEMORY_UNIT);
                    if units > memory_units {
                        // BytesMut grows geometrically; charge twice the
                        // logical length without reserving for stalled bodies.
                        let memory = ctx.resources.fastcgi_admission.prefix_memory.clone();
                        let credit = memory
                            .try_acquire_many_owned((units - memory_units) as u32)
                            .map_err(|_| budget_failure(ctx, BudgetError::Overloaded))?;
                        prefix_credits.push(credit);
                        memory_units = units;
                    }
                    in_memory.extend_from_slice(&prefix);
                } else if !prefix.is_empty() {
                    let storage = match &mut spilled {
                        Some(storage) => storage,
                        None => {
                            let mut storage = spool::Spool::create(ctx).await?;
                            if !in_memory.is_empty() {
                                storage
                                    .append(ctx, std::mem::take(&mut in_memory).freeze())
                                    .await?;
                                prefix_credits.clear();
                            }
                            spilled.insert(storage)
                        }
                    };
                    storage.append(ctx, prefix).await?;
                }
                if !data.is_empty() {
                    buffered.push(data);
                }
            }
        }
        if !in_memory.is_empty() {
            buffered.insert(0, in_memory.freeze());
        }
    }
    let bodyless = matches!(method, Method::HEAD | Method::OPTIONS);
    let length = if bodyless {
        0
    } else {
        length.ok_or_else(|| failure(StatusCode::LENGTH_REQUIRED))?
    };
    Ok(BodyPrefix {
        body,
        buffered,
        prefix_credits,
        spool: spilled,
        length,
        content_length_override: overwritten,
    })
}

type ReadSocket = tokio::io::ReadHalf<Socket>;
type WriteSocket = tokio::io::WriteHalf<Socket>;

#[derive(Debug)]
struct UploadFailure {
    error: anyhow::Error,
    retry_after: bool,
}
impl std::fmt::Display for UploadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for UploadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}
impl UploadFailure {
    fn status(status: StatusCode) -> Self {
        Self { error: failure(status), retry_after: false }
    }
    fn source_error(error: BoxError) -> Self {
        let mut retry_after = false;
        let status = if let Some(spool) = error.downcast_ref::<spool::SpoolReadError>() {
            match spool {
                spool::SpoolReadError::Budget(BudgetError::Overloaded) => {
                    retry_after = true;
                    StatusCode::SERVICE_UNAVAILABLE
                }
                spool::SpoolReadError::Budget(BudgetError::WorkerFailed) => StatusCode::INTERNAL_SERVER_ERROR,
                spool::SpoolReadError::Io(error) if super::request::descriptor_exhausted(error) => {
                    retry_after = true;
                    StatusCode::SERVICE_UNAVAILABLE
                }
                spool::SpoolReadError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
                spool::SpoolReadError::Io(_) => StatusCode::BAD_GATEWAY,
            }
        } else if super::request_body::limit_error(error.as_ref()) {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        Self { error: failure(status), retry_after }
    }
    fn into_error(self, ctx: &mut Context) -> anyhow::Error {
        if self.retry_after {
            ctx.immediate.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        self.error
    }
}

enum UploadOutcome {
    Complete,
    Cancelled,
    Failed(UploadFailure),
}
struct UploadJob {
    writer: WriteSocket,
    source: Body,
    remaining: u64,
    bodyless: bool,
    deadline: Option<Instant>,
    cancel: CancellationToken,
    hard_stop: CancellationToken,
    _business: Arc<super::BusinessGuard>,
}
impl UploadJob {
    async fn write(&mut self) -> std::result::Result<(), UploadFailure> {
        if !self.bodyless {
            while let Some(frame) = self.source.frame().await {
                if let Ok(data) = frame.map_err(UploadFailure::source_error)?.into_data() {
                    self.remaining = send_checked(&mut self.writer, &data, self.remaining, self.deadline)
                        .await.map_err(|error| UploadFailure { error, retry_after: false })?;
                }
            }
            if self.remaining != 0 { return Err(UploadFailure::status(StatusCode::BAD_REQUEST)); }
        }
        wire::finish_stdin(&mut self.writer, self.deadline).await
            .map_err(|error| UploadFailure { error: error.into(), retry_after: false })
    }
    async fn execute(mut self) -> UploadOutcome {
        let cancel = self.cancel.clone();
        let hard_stop = self.hard_stop.clone();
        let outcome = {
            let writing = self.write();
            tokio::pin!(writing);
            tokio::select! { biased;
                _ = hard_stop.cancelled() => UploadOutcome::Cancelled,
                _ = cancel.cancelled() => UploadOutcome::Cancelled,
                result = &mut writing => match result {
                    Ok(()) => UploadOutcome::Complete,
                    Err(error) => UploadOutcome::Failed(error),
                },
            }
        };
        // The result/JoinHandle cannot retire the request before actual source,
        // write future and socket-half destruction. Spool workers additionally
        // retain the same request through their real Storage owner.
        drop(self);
        outcome
    }
}

struct UploadControl {
    job: Option<tokio::task::JoinHandle<UploadOutcome>>,
    cancel: CancellationToken,
    hard_stop: CancellationToken,
}
impl Drop for UploadControl {
    fn drop(&mut self) { self.cancel.cancel(); }
}
impl UploadControl {
    fn pending(&self) -> bool { self.job.is_some() }
    fn decode(result: std::result::Result<UploadOutcome, tokio::task::JoinError>, allow_cancel: bool)
        -> std::result::Result<(), UploadFailure>
    {
        match result {
            Ok(UploadOutcome::Complete) => Ok(()),
            Ok(UploadOutcome::Cancelled) if allow_cancel => Ok(()),
            Ok(UploadOutcome::Cancelled) => Err(UploadFailure::status(StatusCode::SERVICE_UNAVAILABLE)),
            Ok(UploadOutcome::Failed(error)) => Err(error),
            Err(_) => Err(UploadFailure::status(StatusCode::INTERNAL_SERVER_ERROR)),
        }
    }
    async fn during<F: Future>(&mut self, operation: F) -> std::result::Result<F::Output, UploadFailure> {
        tokio::pin!(operation);
        loop {
            if let Some(job) = self.job.as_mut() {
                tokio::select! { biased;
                    _ = self.hard_stop.cancelled() => return Err(UploadFailure::status(StatusCode::SERVICE_UNAVAILABLE)),
                    result = job => {
                        self.job = None;
                        Self::decode(result, false)?;
                        // Keep polling the SAME pinned parser future. Dropping
                        // a partially-read record after upload success poisons it.
                    },
                    result = &mut operation => return Ok(result),
                }
            } else {
                return tokio::select! { biased;
                    _ = self.hard_stop.cancelled() => Err(UploadFailure::status(StatusCode::SERVICE_UNAVAILABLE)),
                    result = &mut operation => Ok(result),
                };
            }
        }
    }
    async fn finish(&mut self) -> std::result::Result<(), UploadFailure> {
        self.cancel.cancel();
        if let Some(job) = self.job.take() { Self::decode(job.await, true)?; }
        Ok(())
    }

    // Known-length HTTP/1 consumers may discard a body immediately after its
    // last data frame. Hold at most that final FastCGI record until upload is
    // settled, while still reading the entire responder tail concurrently.
    async fn tail<F: Future>(&mut self, operation: F, diagnostic: bool)
        -> std::result::Result<Option<F::Output>, UploadFailure>
    {
        tokio::pin!(operation);
        let mut deadline = None;
        loop {
            if let Some(job) = self.job.as_mut() {
                tokio::select! { biased;
                    _ = self.hard_stop.cancelled() => return Err(UploadFailure::status(StatusCode::SERVICE_UNAVAILABLE)),
                    result = job => {
                        self.job = None;
                        Self::decode(result, false)?;
                        if diagnostic {
                            deadline = Some(Instant::now() + Duration::from_millis(250));
                        }
                    },
                    result = &mut operation => {
                        self.finish().await?;
                        return Ok(Some(result));
                    },
                }
            } else {
                if !diagnostic {
                    // STDIN flush completion is not END_REQUEST. In strict
                    // mode keep this exact parser alive through the real END.
                    return tokio::select! { biased;
                        _ = self.hard_stop.cancelled() => Err(UploadFailure::status(StatusCode::SERVICE_UNAVAILABLE)),
                        result = &mut operation => Ok(Some(result)),
                    };
                }
                let limit = *deadline.get_or_insert_with(|| Instant::now() + Duration::from_millis(250));
                return tokio::select! { biased;
                    _ = self.hard_stop.cancelled() => Err(UploadFailure::status(StatusCode::SERVICE_UNAVAILABLE)),
                    result = &mut operation => Ok(Some(result)),
                    _ = tokio::time::sleep_until(limit) => Ok(None),
                };
            }
        }
    }
}

pub(super) struct ExchangeState {
    pub(super) transport_started: bool,
    pub(super) complete_length: Option<u64>,
    pub(super) transport_began: Option<std::time::Instant>,
}
impl ExchangeState {
    pub(super) fn new(complete_length: Option<u64>) -> Self {
        Self {
            transport_started: false,
            complete_length,
            transport_began: None,
        }
    }
}

pub(super) async fn serve(
    ctx: &mut Context,
    config: &ProxyConfig,
    transport: &FastCgiConfig,
    dial: String,
    logging: Option<&std::sync::Arc<crate::logging::Logging>>,
    exchange: &mut ExchangeState,
) -> Result<proxy::PreparedResponse> {
    let probe = ctx.probe;
    ctx.reserve_text_copy(dial.len().saturating_mul(16).saturating_add(8192))?;
    let target = Target::parse(&dial)?;
    target.set_placeholders(ctx);
    let path = percent_encoding::percent_decode_str(ctx.req().uri().path()).collect::<Vec<_>>();
    if path.contains(&0) {
        return Err(failure(StatusCode::BAD_REQUEST));
    }
    let root = root(ctx, transport).await?;
    let split = env::SplitPath::new(&transport.split_path)?;
    let request = ctx
        .request
        .take()
        .ok_or_else(|| anyhow::anyhow!("FastCGI request body already consumed"))?;
    // Error routes can still inspect headers and serve a static response;
    // another proxy must never send an empty retry after consumption.
    ctx.fastcgi_body_claimed = true;
    ctx.body_limit = None;
    let (parts, body) = request.into_parts();
    let incoming_headers = parts.headers.clone();
    let replacement_length = parts
        .extensions
        .get::<super::request_body::Replacement>()
        .map(|body| body.length);
    let known_length = replacement_length.or_else(|| body.size_hint().exact());
    let prepared = parts
        .extensions
        .get::<PreparedLength>()
        .copied()
        .filter(|v| v.config == config as *const ProxyConfig as usize);
    ctx.request = Some(Request::from_parts(parts, full(Bytes::new())));
    let is_incremental = super::incremental::is_enabled(&incoming_headers);
    let source = if let Some(prepared) = prepared {
        BodyPrefix {
            body,
            buffered: Vec::new(),
            prefix_credits: Vec::new(),
            spool: None,
            length: prepared.length,
            content_length_override: prepared.content_length_override,
        }
    } else if let Some(length) = exchange.complete_length {
        if !probe
            && is_incremental
            && transport.explicit_request_buffer
            && has_content(ctx.req().method(), Some(length))
        {
            return Err(super::proxy_handler::refuse(ctx,&config.handler.proxy_status_name,None));
        }
        BodyPrefix {
            body,
            buffered: Vec::new(),
            prefix_credits: Vec::new(),
            spool: None,
            length: if matches!(*ctx.req().method(), Method::HEAD | Method::OPTIONS) {
                0
            } else {
                length
            },
            content_length_override: Some(length),
        }
    } else {
        prefix(ctx, body, known_length, transport, is_incremental,&config.handler.proxy_status_name).await?
    };
    let mut headers = incoming_headers;
    if !probe && let Some(size) = source.content_length_override.or(replacement_length) {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    }
    let headers = if probe {
        headers
    } else {
        proxy::proxy_headers(ctx, config, headers, false, true, None).await?
    };
    let target_permit = ctx
        .resources
        .fastcgi_admission
        .try_target(target.key())
        .ok_or_else(|| budget_failure(ctx, BudgetError::Overloaded))?;
    let budget = ctx.resources.fastcgi.clone();
    let permit = budget.acquire().await.map_err(|e| budget_failure(ctx, e))?;
    let method = ctx.req().method();
    if !is_incremental
        && super::incremental::is_enabled(&headers)
        && has_content(method, known_length)
    {
        return Err(super::proxy_handler::refuse(ctx,&config.handler.proxy_status_name,None));
    }
    let protocol = match ctx.req().version() {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };
    let tls = ctx.req().extensions().get::<TlsDetails>().copied();
    let cipher = tls.map(TlsDetails::cipher_name);
    let host = if probe {
        ctx.authority.as_ref()
    } else {
        headers
            .get(header::HOST)
            .map_or(ctx.authority.as_ref(), HeaderValue::as_bytes)
    };
    let request = env::Request {
        method: method.as_str(),
        path: &path,
        original_uri: ctx
            .original_uri
            .path_and_query()
            .map_or(b"/", |x| x.as_str().as_bytes()),
        query: ctx.req().uri().query().unwrap_or_default().as_bytes(),
        host,
        protocol,
        software: "Caddy/v2.11.7",
        remote: ctx.peer.clone(),
        local: ctx.local.clone(),
        tls: tls
            .zip(cipher.as_deref())
            .map(|(tls, cipher)| (tls.version, cipher)),
        authenticated_user: ctx
            .values
            .get("http.auth.user.id")
            .map_or(b"", |x| x.as_bytes()),
        remainder: ctx
            .values
            .get("http.matchers.file.remainder")
            .map_or(b"", |x| x.as_bytes()),
        headers: &headers,
        content_length: Some(source.length),
    };
    let mut overrides = BTreeMap::new();
    let mut env_size = 0usize;
    for (key, template) in &transport.env {
        let expanded=ctx.expand_resolved(template,true).await?;
        env_size = env_size
            .checked_add(key.len())
            .and_then(|n| n.checked_add(expanded.len()))
            .filter(|&n| n <= 1024 * 1024)
            .ok_or_else(|| failure(StatusCode::BAD_GATEWAY))?;
        let view=ctx.lookup_view();
        if !view.map_plans().is_empty(){view.retain_text(expanded.clone())?;view.reserve_text_copy(expanded.len().saturating_mul(8).saturating_add(key.len().saturating_mul(4)).saturating_add(2048))?;}
        overrides.insert(key.clone(),expanded.to_vec());
    }
    if probe {
        for name in ["REMOTE_ADDR", "REMOTE_HOST", "REMOTE_PORT"] {
            if !transport.env.contains_key(name) {
                overrides.insert(name.into(), Vec::new());
            }
        }
    }
    let fields_bytes=headers.iter().fold(0usize,|sum,(key,value)|sum.saturating_add(key.as_str().len()).saturating_add(value.len()));
    ctx.reserve_text_copy(root.as_os_str().len().saturating_add(path.len()).saturating_add(env_size).saturating_add(fields_bytes).saturating_mul(8).saturating_add(headers.len().saturating_add(overrides.len()).saturating_add(32).saturating_mul(2048)))?;
    let mut params = env::build(&root, &split, &request, &overrides)
        .map_err(|_| failure(StatusCode::BAD_REQUEST))?;
    if probe && !transport.env.contains_key("SERVER_ADDR") {
        params.remove("SERVER_ADDR");
    }
    let bodyless = matches!(*method, Method::HEAD | Method::OPTIONS) || source.length == 0;
    let capture = transport.capture_stderr;
    let stderr: Option<reply::StderrSink> = if capture {
        let logging = logging
            .cloned()
            .ok_or_else(|| failure(StatusCode::BAD_GATEWAY))?;
        Some(Box::new(move |status, body, truncated| {
            use crate::logging::{Event, Field, FieldValue, Level, Origin};
            let module = "http.reverse_proxy.transport.fastcgi";
            let level = if status.as_u16() >= 400 {
                Level::Error
            } else {
                Level::Warn
            };
            if let Ok(mut event) = Event::new(
                Origin::Module {
                    module_id: module.into(),
                },
                module,
                level,
                "stderr",
            ) {
                event
                    .fields
                    .push(Field::new("body", FieldValue::ByteString(body.to_vec())));
                if truncated {
                    event
                        .fields
                        .push(Field::new("stderr_truncated", FieldValue::Bool(true)));
                }
                let _ = logging.try_emit(event);
            }
        }))
    } else {
        None
    };
    let parameters = wire::Parameters::new(&params)?;
    exchange.transport_started = true;
    exchange.transport_began = Some(std::time::Instant::now());
    let mut socket = Socket {
        io: target
            .connect(ctx, config.dial_timeout)
            .await
            .map_err(|error| error.context(super::proxy_retry::DialFailure))?,
        _business: ctx.business.clone(),
        _permit: (permit, target_permit),
    };
    let read_limit = deadline(config.read_timeout)?;
    let write_limit = deadline(config.write_timeout)?;
    let starting = async {
        wire::begin(&mut socket.io, write_limit).await?;
        parameters.send(&mut socket.io, write_limit).await?;
        Ok::<_, io::Error>(())
    }.await;
    starting.map_err(|error| anyhow::Error::new(error).context(ExchangeStarted))?;
    drop(params);
    let remaining = source.length;
    let source = source.into_body();
    // Split the complete Socket: both halves retain its real IO and permits.
    let (reader, writer) = tokio::io::split(socket);
    let cancel = CancellationToken::new();
    let hard_stop = ctx.business.generation().hard_stop.clone();
    let job = UploadJob {
        writer, source, remaining, bodyless, deadline: write_limit,
        cancel: cancel.clone(), hard_stop: hard_stop.clone(),
        _business: ctx.business.clone(),
    };
    let job = ctx.resources.fastcgi.tasks().spawn(job.execute());
    let mut upload = UploadControl { job: Some(job), cancel, hard_stop };
    let reading = reply::Reader::new(wire::Responses::new(reader, read_limit), stderr).headers();
    let reply = match upload.during(reading).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => {
            let _ = upload.finish().await;
            return Err(anyhow::Error::new(error).context(ExchangeStarted));
        }
        Err(error) => {
            let error = error.into_error(ctx);
            let _ = upload.finish().await;
            return Err(error.context(ExchangeStarted));
        }
    };
    let response_headers = reply.headers;
    let no_body = ctx.req().method() == Method::HEAD
        || matches!(
            reply.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        )
        || response_headers
            .get(header::CONTENT_LENGTH)
            .is_some_and(|value| value == "0");
    let mut reply_body = reply.body;
    let sniff = !no_body
        && !response_headers.contains_key(header::CONTENT_TYPE)
        && !response_headers.contains_key(header::CONTENT_ENCODING)
        && !response_headers.contains_key(header::CONTENT_RANGE);
    let diagnostic_owner = capture.then(|| (ctx.resources.clone(), ctx.business.clone()));
    let body = if no_body {
        if upload.pending() || !capture {
            let captured = reply_body.captures_stderr();
            let result = upload.tail(reply_body.upload_tail(), captured).await;
            match result {
                Ok(Some(Ok(()))) => {},
                Ok(Some(Err(error))) => {
                    let _ = upload.finish().await;
                    return Err(anyhow::Error::new(error).context(ExchangeStarted));
                }
                Ok(None) => { if captured { reply_body.mark_diagnostic_limit(); } },
                Err(error) => {
                    let error = error.into_error(ctx);
                    let _ = upload.finish().await;
                    return Err(error.context(ExchangeStarted));
                }
            }
            drop(reply_body);
            upload.finish().await.map_err(|error| error.into_error(ctx).context(ExchangeStarted))?;
        } else if let Some(owner) = diagnostic_owner {
            handoff_diagnostics(reply_body, upload, &owner);
        } else {
            drop(reply_body);
            upload.finish().await.map_err(|error| error.into_error(ctx).context(ExchangeStarted))?;
        }
        full(Bytes::new())
    } else {
        let frames = stream::try_unfold(
            (Some(reply_body), Some(upload), diagnostic_owner),
            |(body, upload, owner)| async move {
                let (Some(mut body), Some(mut upload)) = (body, upload) else { return Ok(None); };
                let result = upload.during(body.next()).await
                    .map_err(|error| -> BoxError { Box::new(error) })?;
                if result.is_err() { tokio::task::yield_now().await; }
                let bytes = result?;
                if body.payload_complete() && (upload.pending() || !body.captures_stderr()) {
                    // Hold at most this final <=64KiB record, while both input
                    // and the responder tail continue to make real progress.
                    let captured = body.captures_stderr();
                    let result = upload.tail(body.upload_tail(), captured).await
                        .map_err(|error| -> BoxError { Box::new(error) })?;
                    match result {
                        Some(result) => result?,
                        None if captured => body.mark_diagnostic_limit(),
                        None => {},
                    }
                    drop(body);
                    upload.finish().await.map_err(|error| -> BoxError { Box::new(error) })?;
                    return Ok::<_, BoxError>(bytes.map(|bytes| (Frame::data(bytes), (None, None, owner))));
                }
                if let Some(ref owner) = owner && body.diagnostics_ready() {
                    handoff_diagnostics(body, upload, owner);
                    return Ok(bytes.map(|bytes| (Frame::data(bytes), (None, None, Some(owner.clone())))));
                }
                if bytes.is_none() {
                    drop(body);
                    upload.finish().await.map_err(|error| -> BoxError { Box::new(error) })?;
                    return Ok(None);
                }
                Ok(bytes.map(|bytes| (Frame::data(bytes), (Some(body), Some(upload), owner))))
            },
        );
        StreamBody::new(frames).boxed_unsync()
    };
    let mut response = Response::new(body);
    *response.status_mut() = reply.status;
    *response.version_mut() = ctx.req().version();
    *response.headers_mut() = response_headers;
    Ok(proxy::PreparedResponse::fastcgi(
        response,
        config.response_headers.clone(),
        sniff,
        config.flush_interval,
    ))
}

// A completed response does not wait for the FastCGI diagnostic tail. The
// exact socket (and its admission) moves to a bounded owned task; no retry
// or second request occurs. The generation remains live only for this budget.
fn handoff_diagnostics(
    mut body: reply::ReplyBody<ReadSocket>,
    mut upload: UploadControl,
    owner: &(
        Arc<super::resource_budget::Resources>,
        Arc<super::BusinessGuard>,
    ),
) {
    let (resources, business) = owner;
    let lane = &resources.fastcgi_admission;
    let Ok(permit) = lane.diagnostic_slots.clone().try_acquire_owned() else {
        body.mark_diagnostic_limit();
        // Upload is already settled at the handoff boundary. Drop still
        // cancels defensively; the real task remains tracked if ever pending.
        return;
    };
    let business = business.clone();
    lane.diagnostics.spawn(async move {
        if tokio::time::timeout(Duration::from_millis(250), body.drain_diagnostics())
            .await
            .is_err()
        {
            body.mark_diagnostic_limit();
        }
        drop(body);
        let _ = upload.finish().await;
        drop(business);
        drop(permit);
    });
}

async fn send_checked<W: AsyncWrite + Unpin>(
    socket: &mut W,
    data: &[u8],
    remaining: u64,
    limit: Option<Instant>,
) -> Result<u64> {
    let next = remaining
        .checked_sub(data.len() as u64)
        .ok_or_else(|| failure(StatusCode::BAD_REQUEST))?;
    wire::send_stdin(socket, data, limit).await?;
    Ok(next)
}

pub(super) async fn probe(
    request: Request<Body>,
    resources: Arc<super::resource_budget::Resources>,
    config: &ProxyConfig,
    transport: &FastCgiConfig,
    dial: String,
    logging: Option<&Arc<crate::logging::Logging>>,
) -> Result<Response<Body>> {
    let mut ctx = Context::for_probe(request, resources)?;
    let mut exchange = ExchangeState::new(ctx.req().body().size_hint().exact());
    let prepared = serve(&mut ctx, config, transport, dial, logging, &mut exchange).await?;
    Ok(prepared.response)
}
