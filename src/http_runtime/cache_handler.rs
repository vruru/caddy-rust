//! Native Souin/OTTER HTTP caching; bounded streaming admission, never buffering
//! an uncacheable/oversized body before forwarding it to the client.
use super::{Body, BoxError, Bytes, full, request::Context};
use crate::cache_app::{Charge, Entry, FlightDecision, FlightLease, Runtime, Store};
use anyhow::{Result, ensure};
use futures_util::FutureExt;
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header};
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant, SystemTime},
};

#[derive(Clone, Debug)]
pub struct Plan;
pub fn parse(value: &serde_json::Value) -> Result<Plan> {
    let o = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("cache handler requires object"))?;
    ensure!(
        o.keys().all(|k| matches!(k.as_str(), "handler" | "@id"))
            && o.get("handler").and_then(|v| v.as_str()) == Some("cache"),
        "cache handler only supports app-inherited configuration"
    );
    Ok(Plan)
}
pub(super) enum Decision {
    Bypass,
    Hit(Response<Body>),
    Miss(Token),
}
pub(super) struct Token {
    key: String,
    display: String,
    request_headers: HeaderMap,
    method: Method,
    charge: Charge,
    request_cc: Directives,
    flight: Option<FlightLease>,
}
#[derive(Default)]
struct Directives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    min_fresh: u64,
    invalid: bool,
}
fn directives(headers: &HeaderMap) -> Directives {
    directives_named(headers, "cache-control")
}
fn directives_named(headers: &HeaderMap, name: &str) -> Directives {
    let mut d = Directives::default();
    for h in headers.get_all(name) {
        let Ok(h) = h.to_str() else {
            d.invalid = true;
            continue;
        };
        let mut quote = false;
        let mut start = 0;
        let mut pieces = Vec::new();
        for (i, c) in h.char_indices() {
            if c == '"' {
                quote = !quote;
            } else if c == ',' && !quote {
                pieces.push(&h[start..i]);
                start = i + 1;
            }
        }
        pieces.push(&h[start..]);
        if quote {
            d.invalid = true;
        }
        for item in pieces {
            let (name, arg) = item
                .trim()
                .split_once('=')
                .map_or((item.trim(), None), |(n, v)| {
                    (n.trim(), Some(v.trim().trim_matches('"')))
                });
            match name.to_ascii_lowercase().as_str() {
                "no-store" => d.no_store = true,
                "no-cache" => d.no_cache = true,
                "private" => d.private = true,
                "max-age" | "s-maxage" | "min-fresh" => {
                    let n = arg.and_then(|s| s.parse::<u64>().ok());
                    if n.is_none() {
                        d.invalid = true;
                    } else {
                        match name.to_ascii_lowercase().as_str() {
                            "max-age" => {
                                if d.max_age.replace(n.unwrap()).is_some() {
                                    d.invalid = true;
                                }
                            }
                            "s-maxage" => {
                                if d.s_maxage.replace(n.unwrap()).is_some() {
                                    d.invalid = true;
                                }
                            }
                            _ => d.min_fresh = n.unwrap(),
                        }
                    }
                }
                _ => {}
            }
        }
    }
    d
}
fn set_status(headers: &mut HeaderMap, value: String) {
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.insert("cache-status", v);
    }
}
fn metadata(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(n, v)| n.as_str().len() + v.as_bytes().len() + 256)
        .sum::<usize>()
        .saturating_mul(3)
}
fn bypass(ctx: &mut Context, runtime: &Runtime, reason: &str) -> Decision {
    runtime.log(0, "request bypass");
    set_status(
        &mut ctx.immediate,
        format!("{}; fwd=bypass; detail={reason}", runtime.config.cache_name),
    );
    Decision::Bypass
}
pub(super) async fn before(ctx: &mut Context, runtime: &Runtime, _plan: &Plan) -> Result<Decision> {
    let req = ctx.req();
    let method = req.method().clone();
    if !runtime
        .config
        .allowed_http_verbs
        .iter()
        .any(|m| m == method.as_str())
    {
        return Ok(bypass(ctx, runtime, "UNSUPPORTED-METHOD"));
    }
    if req.headers().contains_key(header::AUTHORIZATION)
        || req.headers().contains_key(header::COOKIE)
    {
        return Ok(bypass(ctx, runtime, "PRIVATE-REQUEST"));
    }
    if req.headers().contains_key(header::UPGRADE)
        || req.headers().get(header::ACCEPT).is_some_and(|v| {
            v.as_bytes()
                .windows(17)
                .any(|s| s.eq_ignore_ascii_case(b"text/event-stream"))
        })
    {
        return Ok(bypass(ctx, runtime, "STREAMING-REQUEST"));
    }
    if !req.body().is_end_stream()
        || req
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|v| v.as_bytes() != b"0")
    {
        return Ok(bypass(ctx, runtime, "REQUEST-BODY"));
    }
    let cc = directives(req.headers());
    if cc.no_store || cc.invalid {
        return Ok(bypass(ctx, runtime, "REQUEST-CACHE-CONTROL"));
    }
    let mut raw = format!(
        "{}-{}-{}-",
        method,
        if ctx.tls { "https" } else { "http" },
        String::from_utf8_lossy(&ctx.authority)
    )
    .into_bytes();
    raw.extend(percent_encoding::percent_decode_str(req.uri().path()));
    if let Some(query) = req.uri().query() {
        if !query.is_empty() {
            raw.push(b'?');
            raw.extend_from_slice(query.as_bytes());
        }
    }
    let key = if runtime.config.hash {
        xxhash_rust::xxh64::xxh64(&raw, 0).to_string()
    } else {
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let display = if runtime.config.hide {
        "*****".into()
    } else {
        String::from_utf8_lossy(&raw).into_owned()
    };
    // These independent request-owned allocations survive every flight await.
    // Reserve their actual capacities before either a hit or queued miss.
    let bytes = metadata(req.headers())
        .saturating_add(key.capacity())
        .saturating_add(display.capacity())
        .saturating_add(raw.capacity())
        .saturating_add(4096);
    let Some(charge) = runtime.store.reserve(bytes) else {
        return Ok(bypass(ctx, runtime, "CACHE-BUDGET"));
    };
    let allow_lookup = !cc.no_cache
        && !req
            .headers()
            .get_all(header::PRAGMA)
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(b"no-cache"));
    if allow_lookup
        && let Some(response) = cached(runtime, &key, &raw, req.headers(), &method, &cc, &display)?
    {
        return Ok(Decision::Hit(response));
    }
    let request_headers = req.headers().clone();
    let mut token = Token {
        key,
        display,
        request_headers,
        method,
        charge,
        request_cc: cc,
        flight: None,
    };
    if allow_lookup {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        for _ in 0..2 {
            if let Some(response) = cached(
                runtime,
                &token.key,
                &raw,
                &token.request_headers,
                &token.method,
                &token.request_cc,
                &token.display,
            )? {
                return Ok(Decision::Hit(response));
            }
            match runtime.store.flight(&token.key) {
                Some(FlightDecision::Leader(lease)) => {
                    token.flight = Some(lease);
                    if let Some(response) = cached(
                        runtime,
                        &token.key,
                        &raw,
                        &token.request_headers,
                        &token.method,
                        &token.request_cc,
                        &token.display,
                    )? {
                        return Ok(Decision::Hit(response));
                    }
                    return Ok(Decision::Miss(token));
                }
                Some(FlightDecision::Wait(mut waiter)) => {
                    if tokio::time::timeout_at(deadline, waiter.wait())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                None => break,
            }
        }
        if let Some(response) = cached(
            runtime,
            &token.key,
            &raw,
            &token.request_headers,
            &token.method,
            &token.request_cc,
            &token.display,
        )? {
            return Ok(Decision::Hit(response));
        }
    }
    Ok(Decision::Miss(token))
}
fn cached(
    runtime: &Runtime,
    key: &str,
    raw: &[u8],
    headers: &HeaderMap,
    method: &Method,
    cc: &Directives,
    display: &str,
) -> Result<Option<Response<Body>>> {
    if let Some(entry) = runtime.store.lookup(key, headers).or_else(|| {
        if *method != Method::HEAD {
            return None;
        }
        let mut get = raw.to_vec();
        get.splice(0..4, b"GET".iter().copied());
        let get = if runtime.config.hash {
            xxhash_rust::xxh64::xxh64(&get, 0).to_string()
        } else {
            get.iter().map(|b| format!("{b:02x}")).collect()
        };
        runtime.store.lookup(&get, headers)
    }) {
        let elapsed = entry.inserted.elapsed();
        let age = entry.initial_age.saturating_add(elapsed.as_secs());
        if cc.max_age.is_none_or(|max| age <= max)
            && elapsed.saturating_add(Duration::from_secs(cc.min_fresh)) < entry.lifetime
        {
            let amplification = if headers.contains_key(header::RANGE) {
                16
            } else {
                1
            };
            let overhead = metadata(&entry.headers)
                .saturating_mul(amplification)
                .saturating_add(entry.chunks.len().saturating_mul(256 * amplification))
                // Formatting Cache-Status and converting it to HeaderValue
                // temporarily coexist; neither is bounded by the fixed margin.
                .saturating_add(display.len().saturating_mul(2))
                .saturating_add(32768);
            if let Some(credit) = runtime.store.reserve(overhead) {
                return Ok(Some(hit(
                    &entry,
                    headers,
                    method,
                    runtime,
                    display,
                    Arc::new(credit),
                )?));
            }
        }
    }
    Ok(None)
}

fn miss(headers: &mut HeaderMap, runtime: &Runtime, token: &Token, detail: &str) {
    runtime.log(0, "response cache miss");
    set_status(
        headers,
        format!(
            "{}; fwd=uri-miss; key={}; detail={detail}",
            runtime.config.cache_name, token.display
        ),
    );
}
pub(super) async fn finish(
    _ctx: &mut Context,
    runtime: &Runtime,
    mut token: Token,
    mut response: Response<Body>,
) -> Result<Response<Body>> {
    if let Some(mut ranged) = cold_range(&token, &mut response)? {
        miss(ranged.headers_mut(), runtime, &token, "COLD-RANGE");
        return Ok(ranged);
    }
    let candidate = [
        "souin-cache-control",
        "surrogate-control",
        "cdn-cache-control",
        "cache-control",
    ]
    .into_iter()
    .find(|name| response.headers().get(*name).is_some_and(|v| !v.is_empty()));
    if candidate.is_none() && !runtime.config.default_cache_control.is_empty() {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_str(&runtime.config.default_cache_control)?,
        );
    }
    let headers = response.headers();
    let ordinary = directives(headers);
    let cc = directives_named(headers, candidate.unwrap_or("cache-control"));
    let status = response.status();
    let streaming = headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"))
        || headers.contains_key(header::UPGRADE)
        || status == StatusCode::SWITCHING_PROTOCOLS;
    let reason = if streaming {
        "STREAMING-RESPONSE"
    } else if !matches!(
        status.as_u16(),
        200 | 203 | 204 | 300 | 301 | 404 | 405 | 410 | 414 | 501
    ) {
        "UNCACHEABLE-STATUS-CODE"
    } else if cc.invalid {
        "INVALID-RESPONSE-CACHE-CONTROL"
    } else if cc.private || ordinary.private || headers.contains_key(header::SET_COOKIE) {
        "PRIVATE-OR-AUTHENTICATED-RESPONSE"
    } else if cc.no_store || ordinary.no_store || cc.no_cache || token.request_cc.no_store {
        "UNCACHEABLE-CACHE-CONTROL"
    } else if headers.contains_key(header::CONTENT_RANGE) {
        "PARTIAL-RESPONSE"
    } else {
        ""
    };
    if !reason.is_empty() {
        miss(response.headers_mut(), runtime, &token, reason);
        return Ok(response);
    }
    let length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    if length.is_some_and(|n| n > runtime.config.max_body_bytes) {
        miss(
            response.headers_mut(),
            runtime,
            &token,
            "UPSTREAM-RESPONSE-TOO-LARGE",
        );
        return Ok(response);
    }
    let now = SystemTime::now();
    let initial_age = headers
        .get(header::AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .max(
            headers
                .get(header::DATE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| httpdate::parse_http_date(v).ok())
                .and_then(|date| now.duration_since(date).ok())
                .map_or(0, |d| d.as_secs()),
        );
    let ttl = if let Some(n) = cc.s_maxage.or(cc.max_age) {
        Duration::from_secs(n)
    } else if let Some(v) = headers.get(header::EXPIRES) {
        let Some(expires) = v
            .to_str()
            .ok()
            .and_then(|s| httpdate::parse_http_date(s).ok())
        else {
            miss(response.headers_mut(), runtime, &token, "MALFORMED-EXPIRES");
            return Ok(response);
        };
        let date = headers
            .get(header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok())
            .unwrap_or(now);
        expires.duration_since(date).unwrap_or_default()
    } else {
        runtime.config.ttl
    };
    let lifetime = ttl.saturating_sub(Duration::from_secs(initial_age));
    if lifetime.is_zero() {
        miss(response.headers_mut(), runtime, &token, "STALE");
        return Ok(response);
    }
    if !token.charge.grow(metadata(headers).saturating_add(4096)) {
        miss(response.headers_mut(), runtime, &token, "CACHE-BUDGET");
        return Ok(response);
    }
    let mut vary = Vec::new();
    let mut varied = std::collections::HashSet::new();
    for value in headers.get_all(header::VARY) {
        let Ok(value) = value.to_str() else {
            miss(response.headers_mut(), runtime, &token, "INVALID-VARY");
            return Ok(response);
        };
        for name in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if name == "*" {
                miss(
                    response.headers_mut(),
                    runtime,
                    &token,
                    "UPSTREAM-VARY-STAR",
                );
                return Ok(response);
            }
            let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
                miss(response.headers_mut(), runtime, &token, "INVALID-VARY");
                return Ok(response);
            };
            if !varied.insert(name.clone()) {
                continue;
            }
            let vary_bytes = token
                .request_headers
                .get_all(&name)
                .iter()
                .map(|v| v.as_bytes().len() + 128)
                .sum::<usize>()
                .saturating_add(256);
            if !token.charge.grow(vary_bytes) {
                miss(response.headers_mut(), runtime, &token, "CACHE-BUDGET");
                return Ok(response);
            }
            let values = token
                .request_headers
                .get_all(&name)
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect();
            vary.push((name, values));
        }
    }
    let mut saved = headers.clone();
    strip_hop(&mut saved);
    saved.remove("cache-status");
    saved.remove("x-souin-stored-ttl");
    saved.remove("x-souin-stored-length");
    if !saved.contains_key(header::DATE) {
        saved.insert(
            header::DATE,
            HeaderValue::from_str(&httpdate::fmt_http_date(now))?,
        );
    }
    miss(response.headers_mut(), runtime, &token, "STORE-PENDING");
    let body = std::mem::replace(response.body_mut(), full(Bytes::new()));
    let entry = Entry {
        key: token.key,
        vary,
        headers: saved,
        status,
        chunks: Vec::new(),
        length: 0,
        inserted: Instant::now(),
        lifetime,
        initial_age,
        charge: token.charge,
    };
    let head = token.method == Method::HEAD;
    if body.is_end_stream() {
        let mut body = body;
        match body.frame().now_or_never() {
            Some(None) => {
                runtime.store.insert(entry);
                *response.body_mut() = body;
            }
            Some(Some(frame)) => {
                *response.body_mut() = Capture {
                    inner: body,
                    store: runtime.store.clone(),
                    entry: None,
                    maximum: 0,
                    expected: None,
                    done: false,
                    held: None,
                    queued: Some(frame),
                    flight: None,
                }
                .boxed_unsync();
            }
            None => {
                *response.body_mut() = body;
            }
        }
        return Ok(response);
    }
    if head {
        *response.body_mut() = body;
        return Ok(response);
    }
    *response.body_mut() = Capture {
        inner: body,
        store: runtime.store.clone(),
        entry: Some(entry),
        maximum: runtime.config.max_body_bytes,
        expected: if head { Some(0) } else { length },
        done: false,
        held: None,
        queued: None,
        flight: token.flight.take(),
    }
    .boxed_unsync();
    Ok(response)
}
fn strip_hop(h: &mut HeaderMap) {
    let names = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| http::HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for n in names {
        h.remove(n);
    }
    for n in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        h.remove(n);
    }
}
struct Capture {
    inner: Body,
    store: Arc<Store>,
    entry: Option<Entry>,
    maximum: usize,
    expected: Option<usize>,
    done: bool,
    held: Option<Frame<Bytes>>,
    queued: Option<std::result::Result<Frame<Bytes>, BoxError>>,
    flight: Option<FlightLease>,
}
impl Capture {
    fn complete(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        if let Some(mut e) = self.entry.take() {
            if self.expected.is_none_or(|n| n == e.length) && e.inserted.elapsed() < e.lifetime {
                if !e.headers.contains_key(header::CONTENT_LENGTH) {
                    if let Ok(v) = HeaderValue::from_str(&e.length.to_string()) {
                        e.headers.insert(header::CONTENT_LENGTH, v);
                    }
                }
                self.store.insert(e);
            }
        }
        self.flight.take();
    }
}
impl HttpBody for Capture {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        if let Some(frame) = self.queued.take() {
            return Poll::Ready(Some(frame));
        }
        loop {
            if self.held.is_some() {
                match Pin::new(&mut self.inner).poll_frame(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        self.complete();
                        return Poll::Ready(self.held.take().map(Ok));
                    }
                    Poll::Ready(Some(next)) => {
                        self.entry = None;
                        self.flight.take();
                        self.queued = Some(next);
                        return Poll::Ready(self.held.take().map(Ok));
                    }
                }
            }
            let result = Pin::new(&mut self.inner).poll_frame(cx);
            match result {
                Poll::Ready(Some(Ok(frame))) => {
                    let mut final_data = false;
                    if let Some(bytes) = frame.data_ref() {
                        let maximum = self.maximum;
                        let expected = self.expected;
                        if let Some(e) = self.entry.as_mut() {
                            if e.length.saturating_add(bytes.len()) > maximum
                                || !e.charge.grow(bytes.len().saturating_add(128))
                            {
                                self.entry = None;
                                self.flight.take();
                            } else {
                                e.length += bytes.len();
                                e.chunks.push(Bytes::copy_from_slice(bytes));
                                final_data = expected == Some(e.length);
                            }
                        }
                        if self.entry.is_some() && (final_data || self.inner.is_end_stream()) {
                            self.held = Some(frame);
                            continue;
                        }
                    } else {
                        self.entry = None;
                        self.flight.take();
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(e))) => {
                    self.entry = None;
                    self.flight.take();
                    self.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    self.complete();
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
    fn size_hint(&self) -> SizeHint {
        let buffered = self
            .held
            .as_ref()
            .and_then(Frame::data_ref)
            .map_or(0, Bytes::len)
            .saturating_add(
                self.queued
                    .as_ref()
                    .and_then(|f| f.as_ref().ok())
                    .and_then(Frame::data_ref)
                    .map_or(0, Bytes::len),
            ) as u64;
        let source = self.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(source.lower().saturating_add(buffered));
        if let Some(upper) = source.upper().and_then(|n| n.checked_add(buffered)) {
            hint.set_upper(upper);
        }
        hint
    }
}
struct OwnedSlice {
    entry: Arc<Entry>,
    bytes: Bytes,
    credit: Arc<Charge>,
}
impl AsRef<[u8]> for OwnedSlice {
    fn as_ref(&self) -> &[u8] {
        let _ = (&self.entry, &self.credit);
        self.bytes.as_ref()
    }
}
fn slices(
    entry: &Arc<Entry>,
    start: usize,
    end: usize,
    out: &mut Vec<Bytes>,
    _credit: &Arc<Charge>,
) {
    let mut position = 0;
    for bytes in &entry.chunks {
        let next = position + bytes.len();
        if next > start && position < end {
            let bytes =
                bytes.slice(start.saturating_sub(position)..(end - position).min(bytes.len()));
            out.push(bytes);
        }
        position = next;
        if position >= end {
            break;
        }
    }
}
fn range_list(value: &str, size: usize) -> Option<Vec<(usize, usize)>> {
    let raw = value.strip_prefix("bytes=")?;
    let mut out = Vec::new();
    for part in raw.split(',') {
        if part.trim().is_empty() {
            continue;
        }
        if out.len() >= 16 {
            return None;
        }
        let (a, b) = part.trim().split_once('-')?;
        let (a, b) = (a.trim(), b.trim());
        let (start, end) = if a.is_empty() {
            let suffix = b.parse::<usize>().ok()?;
            if suffix == 0 || size == 0 {
                continue;
            }
            (size.saturating_sub(suffix), size)
        } else {
            let start = a.parse::<usize>().ok()?;
            if start >= size {
                continue;
            }
            let end = if b.is_empty() {
                size
            } else {
                b.parse::<usize>().ok()?.saturating_add(1).min(size)
            };
            if end <= start {
                return None;
            }
            (start, end)
        };
        out.push((start, end));
    }
    out.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in out {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    Some(merged)
}
fn hit(
    entry: &Arc<Entry>,
    request: &HeaderMap,
    method: &Method,
    runtime: &Runtime,
    display: &str,
    credit: Arc<Charge>,
) -> Result<Response<Body>> {
    let mut response = Response::new(full(Bytes::new()));
    response.extensions_mut().insert(credit.clone());
    *response.status_mut() = entry.status;
    *response.headers_mut() = entry.headers.clone();
    let age = entry
        .initial_age
        .saturating_add(entry.inserted.elapsed().as_secs());
    response
        .headers_mut()
        .insert(header::AGE, HeaderValue::from_str(&age.to_string())?);
    set_status(
        response.headers_mut(),
        format!(
            "{}; hit; ttl={}; key={}; detail=OTTER",
            runtime.config.cache_name,
            entry
                .lifetime
                .saturating_sub(entry.inserted.elapsed())
                .as_secs(),
            display
        ),
    );
    let etag = entry
        .headers
        .get(header::ETAG)
        .map_or(&b""[..], |v| v.as_bytes());
    let modified = entry
        .headers
        .get(header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok());
    if entry.status.is_success()
        && let Some(code) = super::file_preconditions::evaluate(
            request,
            method,
            etag,
            modified.unwrap_or(SystemTime::UNIX_EPOCH),
            modified.is_some(),
        )
    {
        *response.status_mut() = code;
        response.headers_mut().remove(header::CONTENT_LENGTH);
        response.headers_mut().remove(header::CONTENT_RANGE);
        return Ok(response);
    }
    let mut chunks = Vec::new();
    let mut representation_length = entry.length;
    let requested = request
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            v.strip_prefix("bytes=")
                .is_none_or(|v| v.split(',').any(|s| !s.trim().is_empty()))
        })
        .filter(|_| {
            entry.length != 0
                && entry.status == StatusCode::OK
                && method != Method::HEAD
                && super::file_preconditions::range_allowed(
                    request,
                    method,
                    etag,
                    modified.unwrap_or(SystemTime::UNIX_EPOCH),
                    modified.is_some(),
                )
        });
    if let Some(raw) = requested {
        match range_list(raw, entry.length) {
            None => {
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{}", entry.length))?,
                );
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
                return Ok(response);
            }
            Some(ranges) if ranges.is_empty() => {
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{}", entry.length))?,
                );
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
                return Ok(response);
            }
            Some(ranges) if ranges.len() == 1 => {
                let (start, end) = ranges[0];
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!(
                        "bytes {}-{}/{}",
                        start,
                        end - 1,
                        entry.length
                    ))?,
                );
                representation_length = end - start;
                slices(entry, start, end, &mut chunks, &credit);
            }
            Some(ranges) if !ranges.is_empty() => {
                let boundary = format!(
                    "caddy-rust-{:016x}",
                    xxhash_rust::xxh64::xxh64(entry.key.as_bytes(), 0)
                );
                let mime = entry
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream");
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}"))?,
                );
                response.headers_mut().remove(header::CONTENT_RANGE);
                for (start, end) in ranges {
                    chunks.push(Bytes::from(format!("--{boundary}\r\nContent-Type: {mime}\r\nContent-Range: bytes {start}-{}/{}\r\n\r\n",end-1,entry.length)));
                    slices(entry, start, end, &mut chunks, &credit);
                    chunks.push(Bytes::from_static(b"\r\n"));
                }
                chunks.push(Bytes::from(format!("--{boundary}--\r\n")));
                representation_length = chunks.iter().map(Bytes::len).sum();
            }
            _ => {}
        }
    }
    if chunks.is_empty() {
        slices(entry, 0, entry.length, &mut chunks, &credit);
    }
    if method != Method::HEAD {
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&representation_length.to_string())?,
        );
        let entry = entry.clone();
        let stream = futures_util::stream::iter(chunks.into_iter().map(move |bytes| {
            Ok::<_, BoxError>(Frame::data(Bytes::from_owner(OwnedSlice {
                entry: entry.clone(),
                bytes,
                credit: credit.clone(),
            })))
        }));
        *response.body_mut() = http_body_util::StreamBody::new(stream).boxed_unsync();
    }
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    Ok(response)
}
// A cold Range reaches the origin unchanged. If it ignores a single byte range
// but supplies an exact representation length, slice its stream with bounded
// state. Unknown-length suffixes and cold multipart requests retain the legal
// origin 200 rather than pulling the entire entity into a cache buffer.
fn cold_range(token: &Token, response: &mut Response<Body>) -> Result<Option<Response<Body>>> {
    if token.method != Method::GET || response.status() != StatusCode::OK {
        return Ok(None);
    }
    let Some(raw) = token
        .request_headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
    else {
        return Ok(None);
    };
    let Some(size) = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    else {
        return Ok(None);
    };
    let etag = response
        .headers()
        .get(header::ETAG)
        .map_or(&b""[..], |v| v.as_bytes());
    let modified = response
        .headers()
        .get(header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok());
    if !super::file_preconditions::range_allowed(
        &token.request_headers,
        &token.method,
        etag,
        modified.unwrap_or(SystemTime::UNIX_EPOCH),
        modified.is_some(),
    ) {
        return Ok(None);
    }
    if size == 0
        || raw
            .strip_prefix("bytes=")
            .is_some_and(|v| v.split(',').all(|s| s.trim().is_empty()))
    {
        return Ok(None);
    }
    let parsed = range_list(raw, size);
    let mut out = Response::new(full(Bytes::new()));
    *out.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    *out.headers_mut() = response.headers().clone();
    let Some(ranges) = parsed.filter(|r| !r.is_empty()) else {
        out.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes */{size}"))?,
        );
        out.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        *out.extensions_mut() = std::mem::take(response.extensions_mut());
        return Ok(Some(out));
    };
    if ranges.len() > 1 {
        let boundary = format!(
            "caddy-rust-{:016x}",
            xxhash_rust::xxh64::xxh64(token.key.as_bytes(), 0)
        );
        let mime = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let total = ranges
            .iter()
            .map(|&(a, b)| part(&boundary, &mime, a, b, size).len() + b - a + 2)
            .sum::<usize>()
            + boundary.len()
            + 6;
        *out.status_mut() = StatusCode::PARTIAL_CONTENT;
        out.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}"))?,
        );
        out.headers_mut().remove(header::CONTENT_RANGE);
        out.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&total.to_string())?,
        );
        let body = std::mem::replace(response.body_mut(), full(Bytes::new()));
        *out.body_mut() = MultipartBody {
            inner: body,
            parts: ranges.into(),
            position: 0,
            buffer: None,
            boundary,
            mime,
            size,
            phase: 0,
            remaining: total,
        }
        .boxed_unsync();
        *out.extensions_mut() = std::mem::take(response.extensions_mut());
        return Ok(Some(out));
    }
    let (start, end) = ranges[0];
    *out.status_mut() = StatusCode::PARTIAL_CONTENT;
    out.headers_mut().insert(
        header::CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes {start}-{}/{size}", end - 1))?,
    );
    out.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&(end - start).to_string())?,
    );
    let body = std::mem::replace(response.body_mut(), full(Bytes::new()));
    *out.body_mut() = SliceBody {
        inner: body,
        skip: start,
        remaining: end - start,
    }
    .boxed_unsync();
    *out.extensions_mut() = std::mem::take(response.extensions_mut());
    Ok(Some(out))
}
struct SliceBody {
    inner: Body,
    skip: usize,
    remaining: usize,
}
impl HttpBody for SliceBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let mut work = 0;
        loop {
            match std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    let Ok(bytes) = frame.into_data() else {
                        continue;
                    };
                    let skip = self.skip.min(bytes.len());
                    self.skip -= skip;
                    let count = (bytes.len() - skip).min(self.remaining);
                    if count != 0 {
                        self.remaining -= count;
                        return Poll::Ready(Some(Ok(Frame::data(bytes.slice(skip..skip + count)))));
                    }
                    work += 1;
                    if work >= 16 {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => return Poll::Ready(None),
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining as u64)
    }
}
fn part(boundary: &str, mime: &str, start: usize, end: usize, size: usize) -> String {
    format!(
        "--{boundary}\r\nContent-Type: {mime}\r\nContent-Range: bytes {start}-{}/{size}\r\n\r\n",
        end - 1
    )
}
struct MultipartBody {
    inner: Body,
    parts: std::collections::VecDeque<(usize, usize)>,
    position: usize,
    buffer: Option<Bytes>,
    boundary: String,
    mime: String,
    size: usize,
    phase: u8,
    remaining: usize,
}
impl HttpBody for MultipartBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        let mut work = 0;
        loop {
            if self.phase == 3 {
                return Poll::Ready(None);
            }
            if self.parts.is_empty() {
                self.phase = 3;
                let bytes = Bytes::from(format!("--{}--\r\n", self.boundary));
                self.remaining = self.remaining.saturating_sub(bytes.len());
                return Poll::Ready(Some(Ok(Frame::data(bytes))));
            }
            let (start, end) = self.parts[0];
            if self.phase == 0 {
                self.phase = 1;
                let bytes = Bytes::from(part(&self.boundary, &self.mime, start, end, self.size));
                self.remaining = self.remaining.saturating_sub(bytes.len());
                return Poll::Ready(Some(Ok(Frame::data(bytes))));
            }
            if self.position >= end {
                self.parts.pop_front();
                self.phase = 0;
                self.remaining = self.remaining.saturating_sub(2);
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"\r\n")))));
            }
            let bytes = if let Some(bytes) = self.buffer.take() {
                bytes
            } else {
                match std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
                    Some(Ok(frame)) => {
                        let Ok(bytes) = frame.into_data() else {
                            continue;
                        };
                        bytes
                    }
                    Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                    None => {
                        return Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "range representation ended early",
                        )
                        .into())));
                    }
                }
            };
            let skip = start.saturating_sub(self.position).min(bytes.len());
            self.position += skip;
            let count = (bytes.len() - skip).min(end - self.position.min(end));
            self.position += count;
            if skip + count < bytes.len() {
                self.buffer = Some(bytes.slice(skip + count..));
            }
            if count != 0 {
                self.remaining = self.remaining.saturating_sub(count);
                return Poll::Ready(Some(Ok(Frame::data(bytes.slice(skip..skip + count)))));
            }
            work += 1;
            if work >= 16 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.phase == 3
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining as u64)
    }
}
