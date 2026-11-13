// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Nonblocking request records owned by the exact admitted HTTP generation.
use super::{Body, BoxError, Bytes};
use crate::{
    http_config::AccessLogConfig,
    logging::{Event, Field, FieldValue as V, Level, Logging, Origin},
};
use http::{HeaderMap, Request, Response, Version, header};
use http_body_util::BodyExt;
use hyper::body::{Body as HyperBody, Frame, SizeHint};
use std::{
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CAPTURE_UNIT: usize = 1024;
const MAX_CAPTURE_PART: usize = 128 * 1024;

/// Data copied while a response is still in flight has a separate process
/// budget from the completed records admitted by the writer registry.
pub(super) struct CaptureBudget {
    bytes: Arc<Semaphore>,
    minimal: Arc<Semaphore>,
    reduced: AtomicU64,
    dropped: AtomicU64,
    omitted: AtomicU64,
}
impl CaptureBudget {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes: Arc::new(Semaphore::new((16 * 1024 * 1024) / CAPTURE_UNIT)),
            minimal: Arc::new(Semaphore::new(2048)),
            reduced: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            omitted: AtomicU64::new(0),
        })
    }
    pub(super) fn reserve(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        if bytes > MAX_CAPTURE_PART {
            return None;
        }
        self.bytes
            .clone()
            .try_acquire_many_owned(bytes.max(1).div_ceil(CAPTURE_UNIT) as u32)
            .ok()
    }
    pub(super) fn record_omitted(&self) {
        self.omitted.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn stats(&self) -> (u64, u64, u64) {
        (
            self.dropped.load(Ordering::Relaxed),
            self.reduced.load(Ordering::Relaxed),
            self.omitted.load(Ordering::Relaxed),
        )
    }
}

fn credentials_header(name: &str) -> bool {
    matches!(
        name,
        "cookie" | "set-cookie" | "authorization" | "proxy-authorization"
    )
}
fn header_capture_cost(headers: &HeaderMap, credentials: bool) -> usize {
    headers.iter().fold(512usize, |sum, (name, value)| {
        let value_len = if !credentials && credentials_header(name.as_str()) {
            8
        } else {
            value.as_bytes().len()
        };
        sum.saturating_add(128)
            .saturating_add(name.as_str().len().saturating_mul(2))
            .saturating_add(value_len.saturating_mul(2))
    })
}

pub(super) struct Tls {
    version: u16,
    suite: u16,
    resumed: bool,
    protocol: Vec<u8>,
    server_name: String,
}
impl Tls {
    pub(super) fn from_metadata(m:&super::connection_snapshot::ConnectionMetadata)->Self { Self {version:m.version,suite:m.cipher_suite,resumed:m.did_resume,protocol:m.alpn.to_vec(),server_name:m.server_name.to_string()} }
    pub(super) fn of(connection: &rustls::ServerConnection, offered_name: &str) -> Self {
        Self {
            version: connection.protocol_version().map_or(0, u16::from),
            suite: connection
                .negotiated_cipher_suite()
                .map_or(0, |s| u16::from(s.suite())),
            resumed: connection.handshake_kind() == Some(rustls::HandshakeKind::Resumed),
            protocol: connection.alpn_protocol().unwrap_or_default().to_vec(),
            server_name: offered_name.to_owned(),
        }
    }
    fn fields(&self) -> Vec<Field> {
        vec![
            Field::new("resumed", V::Bool(self.resumed)),
            Field::new("version", V::U64(self.version.into())),
            Field::new("cipher_suite", V::U64(self.suite.into())),
            Field::new("proto", V::RawString(self.protocol.clone())),
            Field::new("server_name", V::String(self.server_name.clone())),
            Field::new("ech", V::Bool(false)),
        ]
    }
}

fn host_patterns(host: &str, mut check: impl FnMut(&str) -> bool) -> bool {
    if check(host) {
        return true;
    }
    if host.len() > 253 {
        return false;
    }
    let mut candidate = String::with_capacity(host.len().max(1));
    let mut labels = host.split('.').collect::<Vec<_>>();
    for index in 0..labels.len() {
        if labels[index].is_empty() {
            continue;
        }
        labels[index] = "*";
        candidate.clear();
        for (index, label) in labels.iter().enumerate() {
            if index != 0 {
                candidate.push('.');
            }
            candidate.push_str(label);
        }
        if check(&candidate) {
            return true;
        }
    }
    false
}
fn names(config: &AccessLogConfig, host: &str) -> Option<Vec<String>> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut mapped = None;
    host_patterns(&host, |pattern| {
        mapped = config.names.get(pattern);
        mapped.is_some()
    });
    if let Some(values) = mapped {
        return Some(values.clone());
    }
    if config.skip_unmapped
        || host_patterns(&host, |pattern| {
            config.skip_hosts.iter().any(|name| name == pattern)
        })
    {
        return None;
    }
    Some(vec![config.default_name.clone()])
}
fn prefix(value: &str, bytes: usize) -> String {
    let mut end = value.len().min(bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
fn title_case(name: &str) -> String {
    let mut first = true;
    name.bytes()
        .map(|byte| {
            let out = if first {
                byte.to_ascii_uppercase()
            } else {
                byte
            };
            first = byte == b'-';
            char::from(out)
        })
        .collect()
}
fn log_headers(headers: &HeaderMap, credentials: bool, omit_host: bool) -> V {
    V::Object(
        headers
            .keys()
            .filter(|&key| !omit_host || key != header::HOST)
            .map(|name| {
                let redact = !credentials && credentials_header(name.as_str());
                let values = headers
                    .get_all(name)
                    .iter()
                    .map(|value| {
                        if redact {
                            b"REDACTED".to_vec()
                        } else {
                            value.as_bytes().to_vec()
                        }
                    })
                    .collect();
                Field::new(title_case(name.as_str()), V::StringArray(values))
            })
            .collect(),
    )
}

#[derive(Default)]
pub(super) struct ExtraFields {
    pub(super) fields: Vec<Field>,
    pub(super) permits: Vec<OwnedSemaphorePermit>,
}

pub(super) struct Access {
    logging: Arc<Logging>,
    names: Vec<String>,
    request: Vec<Field>,
    pub(super) read: Arc<AtomicU64>,
    start: Instant,
    credentials: bool,
    reduced: bool,
    budget: Arc<CaptureBudget>,
    _request_capture: OwnedSemaphorePermit,
}

impl Access {
    pub(super) fn started_at(&self) -> Instant {
        self.start
    }

    pub(super) fn start<T>(
        logging: Arc<Logging>,
        config: &AccessLogConfig,
        request: &Request<T>,
        authority: &str,
        peer: &crate::net_address::NetAddress,
        client: Option<IpAddr>,
        budget: &Arc<CaptureBudget>,
    ) -> Option<Self> {
        let host = authority.parse::<http::uri::Authority>().ok();
        let names = names(config, host.as_ref().map_or(authority, |host| host.host()))?;
        let protocol = match request.version() {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        };
        let credentials = config.credentials;
        let estimate = header_capture_cost(request.headers(), credentials)
            .saturating_add(authority.len().saturating_mul(2))
            .saturating_add(
                request
                    .uri()
                    .path_and_query()
                    .map_or(0, |value| value.as_str().len())
                    .saturating_mul(2),
            )
            .saturating_add(names.iter().map(|name| name.len() + 32).sum::<usize>())
            .saturating_add(2048);
        let (permit, reduced) = if let Some(permit) = budget.reserve(estimate) {
            (permit, false)
        } else if let Ok(permit) = budget.minimal.clone().try_acquire_owned() {
            budget.reduced.fetch_add(1, Ordering::Relaxed);
            (permit, true)
        } else {
            budget.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let request_uri = request.uri().path_and_query().map_or("/", |v| v.as_str());
        let mut fields = vec![
            Field::new("remote_ip", V::RawString(peer.raw_host().into_owned())),
            Field::new("remote_port", V::RawString(peer.raw_port().into_owned())),
            Field::new("client_ip", V::String(client.map_or_else(String::new,|ip|ip.to_string()))),
            Field::new("proto", V::String(protocol.into())),
            Field::new(
                "method",
                V::String(prefix(
                    request.method().as_str(),
                    if reduced { 32 } else { usize::MAX },
                )),
            ),
            Field::new(
                "host",
                V::String(prefix(authority, if reduced { 256 } else { usize::MAX })),
            ),
            Field::new(
                "uri",
                V::String(prefix(request_uri, if reduced { 512 } else { usize::MAX })),
            ),
        ];
        if reduced {
            fields.push(Field::new("request_headers_omitted", V::Bool(true)));
        } else {
            fields.push(Field::new(
                "headers",
                log_headers(request.headers(), credentials, true),
            ));
            if let Some(tls) = request.extensions().get::<Arc<Tls>>() {
                fields.push(Field::new("tls", V::Object(tls.fields())));
            }
        }
        Some(Self {
            logging,
            names,
            request: fields,
            read: Arc::new(AtomicU64::new(0)),
            start: Instant::now(),
            credentials,
            reduced,
            budget: budget.clone(),
            _request_capture: permit,
        })
    }

    pub(super) fn attach(
        mut self,
        response: Response<Body>,
        override_names: Option<Vec<String>>,
        user_id: String,
        extra: ExtraFields,
    ) -> Response<Body> {
        if let Some(names) = override_names {
            self.names = names;
        }
        let status = response.status().as_u16();
        let permit = if self.reduced {
            None
        } else {
            self.budget
                .reserve(header_capture_cost(response.headers(), self.credentials))
        };
        let headers = if permit.is_some() {
            Some(log_headers(response.headers(), self.credentials, false))
        } else {
            self.budget.omitted.fetch_add(1, Ordering::Relaxed);
            None
        };
        let user_id = if self.reduced {
            prefix(&user_id, 128)
        } else {
            user_id
        };
        response.map(|body| {
            WriteCount {
                body,
                access: self,
                status,
                headers,
                _response_capture: permit,
                user_id,
                extra,
                bytes: 0,
                failed: false,
                ended: false,
            }
            .boxed_unsync()
        })
    }
}

pub(super) struct ReadCount<B> {
    pub body: B,
    pub bytes: Arc<AtomicU64>,
}
impl<B: HyperBody<Data = Bytes> + Unpin> HyperBody for ReadCount<B> {
    type Data = Bytes;
    type Error = B::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let polled = Pin::new(&mut self.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled
            && let Some(bytes) = frame.data_ref()
        {
            self.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        polled
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

struct WriteCount {
    body: Body,
    access: Access,
    status: u16,
    headers: Option<V>,
    _response_capture: Option<OwnedSemaphorePermit>,
    user_id: String,
    extra: ExtraFields,
    bytes: u64,
    failed: bool,
    ended: bool,
}
impl HyperBody for WriteCount {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let polled = Pin::new(&mut self.body).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) if frame.is_data() => {
                self.bytes = self
                    .bytes
                    .saturating_add(frame.data_ref().map_or(0, |v| v.len() as u64))
            }
            Poll::Ready(Some(Err(_))) => self.failed = true,
            Poll::Ready(None) => self.ended = true,
            _ => {}
        }
        polled
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
impl Drop for WriteCount {
    fn drop(&mut self) {
        let elapsed = self.access.start.elapsed().as_nanos().min(i64::MAX as u128) as i64;
        let level = if self.status >= 500 {
            Level::Error
        } else {
            Level::Info
        };
        for name in &self.access.names {
            let logger = if name.is_empty() {
                "http.log.access".to_owned()
            } else {
                format!("http.log.access.{name}")
            };
            let Ok(mut event) = Event::new(
                Origin::Module {
                    module_id: "http".into(),
                },
                logger,
                level,
                "handled request",
            ) else {
                continue;
            };
            event.fields = vec![
                Field::new("request", V::Object(self.access.request.clone())),
                Field::new(
                    "bytes_read",
                    V::U64(self.access.read.load(Ordering::Relaxed)),
                ),
                Field::new("user_id", V::String(self.user_id.clone())),
                Field::new("duration", V::Duration(elapsed)),
                Field::new("size", V::U64(self.bytes)),
                Field::new("status", V::U64(self.status.into())),
            ];
            if let Some(headers) = &self.headers {
                event
                    .fields
                    .push(Field::new("resp_headers", headers.clone()));
            } else {
                event
                    .fields
                    .push(Field::new("resp_headers_omitted", V::Bool(true)));
            }
            if self.failed || (!self.ended && !self.body.is_end_stream()) {
                event.fields.push(Field::new(
                    "write_error",
                    V::String("response body interrupted".into()),
                ));
            }
            event.fields.extend(self.extra.fields.iter().cloned());
            let _ = self.access.logging.try_emit(event);
        }
    }
}
