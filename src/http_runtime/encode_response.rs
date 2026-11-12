//! Per-route response transforms for Caddy's dynamic encode handler.
use super::accepted_encodings::{Coding, choose};
use super::encode_body::{CodecPlan, CompressionBudget, compressed, with_prefix};
use super::{Body, Bytes};
use crate::http_config::types::ResponseMatcher;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body as _, Frame};

#[derive(Clone)]
pub(crate) struct EncodePlan {
    pub(crate) encodings: Vec<CodecPlan>,
    pub(crate) prefer: Vec<Coding>,
    pub(crate) minimum_length: i64,
    pub(crate) matcher: Option<ResponseMatcher>,
}

impl EncodePlan {
    pub(super) fn select(&self, headers: &mut HeaderMap) -> Option<CodecPlan> {
        if !encoding_allowed(headers) {
            return None;
        }
        let coding = choose(headers, &self.prefer, |want| {
            self.encodings.iter().any(|entry| entry.coding() == want)
        })?;
        if let Some(etag) = headers.get(header::IF_NONE_MATCH)
            && !etag.as_bytes().starts_with(b"W/")
        {
            let name = coding.as_str().as_bytes();
            let bytes = etag.as_bytes();
            let suffix = bytes.len().checked_sub(name.len() + 2);
            if let Some(at) = suffix
                && bytes[at] == b'-'
                && bytes[at + 1..bytes.len() - 1] == *name
                && bytes.last() == Some(&b'"')
            {
                let mut updated = Vec::with_capacity(at + 1);
                updated.extend_from_slice(&bytes[..at]);
                updated.push(b'"');
                if let Ok(updated) = HeaderValue::from_bytes(&updated) {
                    headers.insert(header::IF_NONE_MATCH, updated);
                }
            }
        }
        self.encodings
            .iter()
            .find(|entry| entry.coding() == coding)
            .copied()
    }

    fn matches(&self, status: u16, headers: &HeaderMap) -> bool {
        if let Some(matcher) = &self.matcher {
            return matcher.matches(status, headers);
        }
        headers
            .get_all(header::CONTENT_TYPE)
            .iter()
            .any(|field| DEFAULT_TYPES.iter().any(|prefix| field.as_bytes().starts_with(prefix)))
    }
}

pub(super) const DEFAULT_TYPES: &[&[u8]] = &[
    b"application/atom+xml",
    b"application/eot",
    b"application/font",
    b"application/geo+json",
    b"application/graphql+json",
    b"application/graphql-response+json",
    b"application/javascript",
    b"application/json",
    b"application/ld+json",
    b"application/manifest+json",
    b"application/opentype",
    b"application/otf",
    b"application/rss+xml",
    b"application/truetype",
    b"application/ttf",
    b"application/vnd.api+json",
    b"application/vnd.ms-fontobject",
    b"application/wasm",
    b"application/x-httpd-cgi",
    b"application/x-javascript",
    b"application/x-opentype",
    b"application/x-otf",
    b"application/x-perl",
    b"application/x-protobuf",
    b"application/x-ttf",
    b"application/xhtml+xml",
    b"application/xml",
    b"font/ttf",
    b"font/otf",
    b"image/svg+xml",
    b"image/vnd.microsoft.icon",
    b"image/x-icon",
    b"multipart/bag",
    b"multipart/mixed",
    b"text/",
];

fn encoding_allowed(headers: &HeaderMap) -> bool {
    let forbidden = b"no-transform";
    headers.get(header::CACHE_CONTROL).is_none_or(|value| {
        !value
            .as_bytes()
            .windows(forbidden.len())
            .any(|window| window == forbidden)
    })
}

fn vary_encoding(headers: &mut HeaderMap) {
    let present = headers.get_all(header::VARY).iter().any(|field| {
        String::from_utf8_lossy(field.as_bytes())
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("accept-encoding"))
    });
    if !present {
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

fn set_encoding(headers: &mut HeaderMap, coding: Coding) {
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::ACCEPT_RANGES);
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding.as_str()));
    vary_encoding(headers);
    if let Some(etag) = headers.get(header::ETAG)
        && !etag.is_empty()
        && !etag.as_bytes().starts_with(b"W/")
    {
        let bytes = etag.as_bytes();
        let base = bytes.strip_suffix(b"\"").unwrap_or(bytes);
        let mut updated = Vec::with_capacity(base.len() + coding.as_str().len() + 2);
        updated.extend_from_slice(base);
        updated.push(b'-');
        updated.extend_from_slice(coding.as_str().as_bytes());
        updated.push(b'"');
        if let Ok(value) = HeaderValue::from_bytes(&updated) {
            headers.insert(header::ETAG, value);
        }
    }
}

fn is_sse(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE).map(HeaderValue::as_bytes) else {
        return false;
    };
    let media = b"text/event-stream";
    let Some(prefix) = content_type.get(..media.len()) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(media) {
        return false;
    }
    content_type[media.len()..]
        .iter()
        .find(|&&b| !matches!(b, b' ' | b'\t'))
        .is_none_or(|&b| b == b';')
}

pub(super) struct ResponseEncoding {
    pub(super) plan: std::sync::Arc<EncodePlan>,
    pub(super) codec: CodecPlan,
    pub(super) method: Method,
}

impl ResponseEncoding {
    pub(super) async fn finish(
        &self,
        status: StatusCode,
        preceding_static_interim: Option<u16>,
        headers: &mut HeaderMap,
        mut body: Body,
        compression: &CompressionBudget,
    ) -> Body {
        if status.is_informational() || (self.method == Method::CONNECT && status.is_success()) {
            return body;
        }
        if status == StatusCode::NOT_MODIFIED {
            vary_encoding(headers);
            return body;
        }
        let content_type_set = headers.get(header::CONTENT_TYPE).is_some_and(|v| !v.is_empty());
        let encoded = headers.get(header::CONTENT_ENCODING).is_some_and(|v| !v.is_empty());
        let protocol_body = !matches!(status, StatusCode::PARTIAL_CONTENT | StatusCode::NO_CONTENT);
        let allow_encoding = protocol_body && !encoded && encoding_allowed(headers);
        // A static 100/102 plus body is followed by net/http's implicit
        // final 200, but the encoding writer matches the status it observed.
        let matcher_status = preceding_static_interim.unwrap_or(status.as_u16());
        let incremental = super::incremental::is_enabled(headers);
        let eager = preceding_static_interim.is_none() && (incremental || is_sse(headers));
        let min = self.plan.minimum_length;
        let declared_large = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()?.parse::<i64>().ok())
            .is_some_and(|value| value > min);
        let attempt = if eager {
            true
        } else if content_type_set && (!allow_encoding || !self.plan.matches(matcher_status, headers)) {
            return body;
        } else if content_type_set && min > 0 && declared_large {
            true
        } else {
            let first = next_meaningful(&mut body).await;
            let first = match first {
                Some(Err(error)) => {
                    // Once the terminal handler has selected the response, an
                    // upstream body error must never turn into a complete empty
                    // encoded object or silently switch to an error route.
                    return StreamBody::new(futures_util::stream::once(async { Err(error) }))
                        .boxed_unsync();
                }
                Some(Ok(frame)) => Some(frame),
                None => {
                    // Never poll an upstream body again after observing EOS.
                    body = super::full(Bytes::new());
                    None
                }
            };
            let attempt = if let Some(data) = first.as_ref().and_then(Frame::data_ref) {
                let large = min > 0 && (declared_large || data.len() as u64 > min as u64);
                if large && !content_type_set {
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(super::sniff::detect_content_type(data)));
                }
                large
            } else {
                declared_large
            };
            body = with_prefix(body, first);
            attempt
        };
        if !attempt || !allow_encoding || !self.plan.matches(matcher_status, headers) {
            return body;
        }
        if self.method == Method::HEAD {
            // The representation can be negotiated without allocating an
            // encoder or knowing its encoded length.
            set_encoding(headers, self.codec.coding());
            return body;
        }
        let Some(admitted) = compression.admit(self.codec).await else {
            return body;
        };
        set_encoding(headers, self.codec.coding());
        compressed(admitted, body, eager)
    }
}

async fn next_meaningful(body: &mut Body) -> Option<Result<Frame<Bytes>, super::BoxError>> {
    if body.is_end_stream() {
        return None;
    }
    loop {
        let frame = body.frame().await?;
        if !frame.as_ref().is_ok_and(|value| value.data_ref().is_some_and(Bytes::is_empty)) {
            return Some(frame);
        }
        tokio::task::consume_budget().await;
    }
}
