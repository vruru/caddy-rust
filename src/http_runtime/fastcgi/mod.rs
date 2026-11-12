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

#[derive(Clone, Copy)]
pub(super) struct TlsDetails {
    version: &'static str,
    cipher: Option<rustls::CipherSuite>,
}

impl TlsDetails {
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
                        dns.run(move || {
                            (host.as_str(), port)
                                .to_socket_addrs()
                                .map(|addrs| addrs.take(64).collect::<Vec<_>>())
                        })
                        .await
                        .map_err(|error| budget_failure(ctx, error))??
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
    let expanded = crate::http_config::helpers::replace(
        config.root.as_deref().unwrap_or("{http.vars.root}"),
        true,
        |key| Some(ctx.lookup(key).unwrap_or_else(|| ".".to_owned())),
    )?;
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
    Ok(metadata
        .run(move || {
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
        })
        .await
        .map_err(|e| budget_failure(ctx, e))??)
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
    let mut source = prefix(ctx, body, known, transport, incremental).await?;
    let length = PreparedLength {
        config: config as *const ProxyConfig as usize,
        length: source.length,
        content_length_override: source.content_length_override,
    };
    let spool_reader = source.spool.take().map(|spool| spool.reader());
    let stored = spool_reader.as_ref().map_or(0, spool::SpoolReader::len)
        + source
            .buffered
            .iter()
            .map(|bytes| bytes.len() as u64)
            .sum::<u64>();
    let remaining = source.body.size_hint();
    let mut hint = hyper::body::SizeHint::new();
    if let Some(upper) = remaining.upper().and_then(|n| n.checked_add(stored)) {
        hint.set_upper(upper);
    }
    hint.set_lower(remaining.lower().saturating_add(stored));
    let buffered = std::mem::take(&mut source.buffered).into();
    let body = PrefixedBody {
        prefix: source,
        spool_body: spool_reader.map(spool::SpoolReader::into_body),
        buffered,
        hint,
    }
    .boxed_unsync();
    ctx.req_mut().extensions_mut().insert(length);
    Ok(super::proxy_replay::ReplaySource::new(body))
}

async fn prefix(
    ctx: &mut Context,
    mut body: Body,
    mut length: Option<u64>,
    transport: &FastCgiConfig,
    incremental: bool,
) -> Result<BodyPrefix> {
    let method = ctx.req().method().clone();
    let mut buffered = Vec::new();
    let mut spilled = None;
    let mut overwritten = None;
    let mut prefix_credits = Vec::new();
    if incremental {
        if has_content(&method, length) {
            if length.is_none() || transport.explicit_request_buffer {
                return Err(failure(StatusCode::NOT_IMPLEMENTED));
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
    let mut source = if let Some(prepared) = prepared {
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
            return Err(failure(StatusCode::NOT_IMPLEMENTED));
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
        prefix(ctx, body, known_length, transport, is_incremental).await?
    };
    let mut headers = incoming_headers;
    if !probe && let Some(size) = source.content_length_override.or(replacement_length) {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    }
    let headers = if probe {
        headers
    } else {
        proxy::proxy_headers(ctx, config, headers, false, true, None)?
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
        return Err(failure(StatusCode::NOT_IMPLEMENTED));
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
        ctx.authority.as_bytes()
    } else {
        headers
            .get(header::HOST)
            .map_or(ctx.authority.as_bytes(), HeaderValue::as_bytes)
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
        let value = ctx.expand_bytes(template)?;
        env_size = env_size
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .filter(|&n| n <= 1024 * 1024)
            .ok_or_else(|| failure(StatusCode::BAD_GATEWAY))?;
        overrides.insert(key.clone(), value);
    }
    if probe {
        for name in ["REMOTE_ADDR", "REMOTE_HOST", "REMOTE_PORT"] {
            if !transport.env.contains_key(name) {
                overrides.insert(name.into(), Vec::new());
            }
        }
    }
    let mut params = env::build(&root, &split, &request, &overrides)
        .map_err(|_| failure(StatusCode::BAD_REQUEST))?;
    if probe && !transport.env.contains_key("SERVER_ADDR") {
        params.remove("SERVER_ADDR");
    }
    let bodyless = matches!(*method, Method::HEAD | Method::OPTIONS) || source.length == 0;
    let parameters = wire::Parameters::new(&params)?;
    exchange.transport_started = true;
    exchange.transport_began = Some(std::time::Instant::now());
    let mut socket = Socket {
        io: target
            .connect(ctx, config.dial_timeout)
            .await
            .map_err(|error| error.context(super::proxy_retry::DialFailure))?,
        _permit: (permit, target_permit),
    };
    let read_limit = deadline(config.read_timeout)?;
    let write_limit = deadline(config.write_timeout)?;
    wire::begin(&mut socket.io, write_limit).await?;
    parameters.send(&mut socket.io, write_limit).await?;
    drop(params);
    if !bodyless {
        let mut remaining = source.length;
        if let Some(spool) = source.spool.take() {
            let mut offset = 0;
            while let Some(data) = spool.read(ctx, offset).await? {
                remaining = send_checked(&mut socket.io, &data, remaining, write_limit).await?;
                offset += data.len() as u64;
            }
        }
        for data in source.buffered {
            remaining = send_checked(&mut socket.io, &data, remaining, write_limit).await?;
        }
        source.prefix_credits.clear();
        while let Some(frame) = source.body.frame().await {
            if let Ok(data) = frame
                .map_err(|error| {
                    failure(if super::request_body::limit_error(error.as_ref()) {
                        StatusCode::PAYLOAD_TOO_LARGE
                    } else {
                        StatusCode::BAD_REQUEST
                    })
                })?
                .into_data()
            {
                remaining = send_checked(&mut socket.io, &data, remaining, write_limit).await?;
            }
        }
        if remaining != 0 {
            return Err(failure(StatusCode::BAD_REQUEST));
        }
    }
    wire::finish_stdin(&mut socket.io, write_limit).await?;
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
    let reply = reply::Reader::new(wire::Responses::new(socket, read_limit), stderr)
        .headers()
        .await?;
    let response_headers = reply.headers;
    let no_body = ctx.req().method() == Method::HEAD
        || matches!(
            reply.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        )
        || response_headers
            .get(header::CONTENT_LENGTH)
            .is_some_and(|value| value == "0");
    let reply_body = reply.body;
    let sniff = !no_body
        && !response_headers.contains_key(header::CONTENT_TYPE)
        && !response_headers.contains_key(header::CONTENT_ENCODING)
        && !response_headers.contains_key(header::CONTENT_RANGE);
    let diagnostic_owner = capture.then(|| (ctx.resources.clone(), ctx.business.clone()));
    let body = if no_body {
        if let Some(owner) = diagnostic_owner {
            handoff_diagnostics(reply_body, &owner);
        }
        full(Bytes::new())
    } else {
        let frames = stream::try_unfold(
            (Some(reply_body), diagnostic_owner),
            |(body, owner)| async move {
                let Some(mut body) = body else {
                    return Ok(None);
                };
                let result = body.next().await;
                if result.is_err() {
                    // Give Hyper one flush opportunity before closing an already
                    // started HTTP/1 response on an upstream framing failure.
                    tokio::task::yield_now().await;
                }
                let bytes = result?;
                let body = if let Some(ref owner) = owner
                    && body.diagnostics_ready()
                {
                    handoff_diagnostics(body, owner);
                    None
                } else {
                    Some(body)
                };
                Ok::<_, BoxError>(bytes.map(|bytes| (Frame::data(bytes), (body, owner))))
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
    mut body: reply::ReplyBody<Socket>,
    owner: &(
        Arc<super::resource_budget::Resources>,
        Arc<super::BusinessGuard>,
    ),
) {
    let (resources, business) = owner;
    let lane = &resources.fastcgi_admission;
    let Ok(permit) = lane.diagnostic_slots.clone().try_acquire_owned() else {
        body.mark_diagnostic_limit();
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
        drop(business);
        drop(permit);
    });
}

async fn send_checked(
    socket: &mut Box<dyn Io>,
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
