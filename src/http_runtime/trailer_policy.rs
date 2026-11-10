//! Trailer policy is applied before HTTP/1 or HTTP/2 serialization. Request
//! trailers follow the pinned Caddy clone behavior; response trailers exclude
//! fields that must not bypass framing, routing, authentication or header rules.
use super::{Body, BoxError};
use http::{HeaderMap, HeaderName, HeaderValue, Version};
use http_body_util::BodyExt;
use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use tokio_util::sync::CancellationToken;

static FILTERED_VALUES: AtomicU64 = AtomicU64::new(0);
static DROPPED_REQUEST_VALUES: AtomicU64 = AtomicU64::new(0);
pub(super) fn filtered_values() -> u64 {
    FILTERED_VALUES.load(Ordering::Relaxed)
}
pub(super) fn dropped_request_values() -> u64 {
    DROPPED_REQUEST_VALUES.load(Ordering::Relaxed)
}

fn forbidden_go(name: &str) -> bool {
    name.starts_with("if-")
        || matches!(
            name,
            "authorization"
                | "cache-control"
                | "connection"
                | "content-encoding"
                | "content-length"
                | "content-range"
                | "content-type"
                | "expect"
                | "host"
                | "keep-alive"
                | "max-forwards"
                | "pragma"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "range"
                | "realm"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "www-authenticate"
        )
}
#[derive(Clone, Default)]
pub(super) struct RequestMetadata {
    names: BTreeSet<String>,
    pub(super) invalid_upstream: bool,
    pub(super) fault: Option<CancellationToken>,
}
fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}
pub(super) fn prepare_request<B>(request: &mut http::Request<B>) -> Result<RequestMetadata, ()> {
    let h2 = request.version() == Version::HTTP_2;
    let chunked = request
        .headers()
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .any(|v| {
            v.as_bytes()
                .split(|b| *b == b',')
                .any(|v| trim_ows(v).eq_ignore_ascii_case(b"chunked"))
        });
    let mut metadata = RequestMetadata::default();
    if !h2 && !chunked {
        return Ok(metadata);
    }
    let mut declared = false;
    for value in request.headers().get_all(http::header::TRAILER) {
        for raw in value.as_bytes().split(|b| *b == b',') {
            let raw = trim_ows(raw);
            if !h2 && raw.is_empty() {
                continue;
            }
            let name = HeaderName::from_bytes(raw).ok();
            if name.as_ref().is_some_and(|n| {
                matches!(
                    n.as_str(),
                    "content-length" | "transfer-encoding" | "trailer"
                )
            }) {
                if h2 {
                    continue;
                } else {
                    return Err(());
                }
            }
            declared = true;
            if let Some(name) = name {
                // Go's CanonicalMIMEHeaderKey followed by sorted trailer keys.
                let mut upper = true;
                let canonical = name
                    .as_str()
                    .bytes()
                    .map(|b| {
                        let c = if upper { b.to_ascii_uppercase() } else { b };
                        upper = b == b'-';
                        c as char
                    })
                    .collect::<String>();
                metadata.names.insert(canonical);
            } else {
                metadata.invalid_upstream = true;
            }
        }
    }
    request.headers_mut().remove(http::header::TRAILER);
    if h2 && declared {
        metadata.fault = Some(CancellationToken::new());
    }
    Ok(metadata)
}
impl RequestMetadata {
    pub(super) fn is_empty(&self) -> bool {
        self.names.is_empty() && !self.invalid_upstream && self.fault.is_none()
    }
    pub(super) fn write_upstream_declaration(&self, headers: &mut HeaderMap) {
        headers.remove(http::header::TRAILER);
        if !self.names.is_empty() {
            let names = self
                .names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",");
            // Every stored name has already passed HeaderName validation.
            if let Ok(value) = HeaderValue::from_str(&names) {
                headers.insert(http::header::TRAILER, value);
            }
        }
    }
}
pub(super) fn validate_incoming<B>(body: B, metadata: &RequestMetadata) -> ValidateIncoming<B> {
    ValidateIncoming {
        body,
        fault: metadata.fault.clone(),
    }
}
pub(super) struct ValidateIncoming<B> {
    body: B,
    fault: Option<CancellationToken>,
}
impl<B> hyper::body::Body for ValidateIncoming<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = bytes::Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, BoxError>>> {
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame)))
                if self.fault.is_some()
                    && frame
                        .trailers_ref()
                        .is_some_and(|t| t.keys().any(|n| forbidden_go(n.as_str()))) =>
            {
                self.fault.as_ref().expect("declared H2 trailers").cancel();
                Poll::Ready(Some(Err(Box::new(h2::Error::from(
                    h2::Reason::PROTOCOL_ERROR,
                )))))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
pub(super) fn guard_response(body: Body, fault: Option<CancellationToken>) -> Body {
    match fault {
        Some(fault) => FaultGuard {
            body,
            wait: Box::pin(fault.clone().cancelled_owned()),
            fault,
        }
        .boxed_unsync(),
        None => body,
    }
}
struct FaultGuard {
    body: Body,
    wait: Pin<Box<dyn Future<Output = ()> + Send>>,
    fault: CancellationToken,
}
impl hyper::body::Body for FaultGuard {
    type Data = bytes::Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, BoxError>>> {
        if self.wait.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(Box::new(h2::Error::from(
                h2::Reason::PROTOCOL_ERROR,
            )))));
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        !self.fault.is_cancelled() && self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
pub(super) fn policy(body: Body, drop_all: bool) -> Body {
    body.map_frame(move |frame| match frame.into_trailers() {
        Err(frame) => frame,
        Ok(trailers) => {
            let mut output = HeaderMap::new();
            let mut filtered = 0;
            for (name, value) in &trailers {
                if drop_all || forbidden_go(name.as_str()) || name == http::header::SET_COOKIE {
                    filtered += 1;
                } else {
                    output.append(name.clone(), value.clone());
                }
            }
            if drop_all {
                DROPPED_REQUEST_VALUES.fetch_add(filtered, Ordering::Relaxed);
            } else {
                FILTERED_VALUES.fetch_add(filtered, Ordering::Relaxed);
            }
            hyper::body::Frame::trailers(output)
        }
    })
    .boxed_unsync()
}
