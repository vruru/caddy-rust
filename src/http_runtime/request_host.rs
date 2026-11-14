//! HTTP Host facts are bytes. URL syntax and outgoing Host serialization are
//! separate operations; no lossy conversion is used for routing or forwarding.
use anyhow::{Context as _, Result};
use bytes::Bytes;
use http::{Request, Version};

pub(super) fn authority<B>(request: &Request<B>) -> Result<Bytes, ()> {
    // Go validates the literal wire Host header separately. Decoded URL.Host
    // may contain non-UTF-8, while an on-wire Host field must use the ASCII
    // HTTP host character set. Never broaden that header gate accidentally.
    if request
        .headers()
        .get_all(http::header::HOST)
        .iter()
        .any(|value| {
            !value
                .as_bytes()
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!$%&'()*+,-.:;=[]_~".contains(b))
        })
    {
        return Err(());
    }
    let authority = if let Some(authority) = request.uri().authority() {
        let raw = authority.as_str().as_bytes();
        if raw.contains(&b'@') {
            return Err(());
        }
        if request.version() < Version::HTTP_2 && request.uri().scheme().is_some() {
            Bytes::from(super::http_redirect::url::template_decode_host_bytes(
                request.uri().scheme_str().unwrap_or("").as_bytes(),
                raw,
            )?)
        } else {
            Bytes::copy_from_slice(raw)
        }
    } else {
        request
            .headers()
            .get(http::header::HOST)
            .map_or_else(Bytes::new, |v| Bytes::copy_from_slice(v.as_bytes()))
    };
    if request.version() != Version::HTTP_10 && authority.is_empty()
        || authority
            .iter()
            .any(|b| matches!(b, b'@' | b'/' | b'\r' | b'\n' | b' ' | b'\t'))
    {
        return Err(());
    }
    if request.headers().get_all(http::header::HOST).iter().count() > 1 {
        return Err(());
    }
    Ok(authority)
}

pub(super) fn split(raw: &[u8]) -> (&[u8], &[u8]) {
    if raw.first() == Some(&b'[') {
        if let Some(end) = raw.iter().position(|b| *b == b']') {
            if raw.get(end + 1) == Some(&b':') {
                return (&raw[1..end], &raw[end + 2..]);
            }
            if end + 1 == raw.len() {
                return (raw, b"");
            }
        }
        return (raw, b"");
    }
    if let Some(at) = raw.iter().rposition(|b| *b == b':') {
        if !raw[..at].contains(&b':') {
            return (&raw[..at], &raw[at + 1..]);
        }
    }
    (raw, b"")
}
pub(super) fn hostname(raw: &[u8]) -> &[u8] {
    split(raw).0
}
pub(super) fn port(raw: &[u8]) -> &[u8] {
    split(raw).1
}

/// Go's outgoing Host operation: valid Unicode becomes IDNA; invalid UTF-8 is
/// a real conversion error. X-Forwarded-Host must keep the original byte fact.
pub(super) fn wire_host(raw: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(raw).context("upstream Host is not UTF-8")?;
    let text = super::http_dial::wire_host(text);
    if text.is_ascii() {
        return Ok(text.as_bytes().to_vec());
    }
    let (host, port) = split(text.as_bytes());
    let host = std::str::from_utf8(host).context("upstream Host is not UTF-8")?;
    let ascii = idna::domain_to_ascii(host).context("upstream Host IDNA conversion failed")?;
    let mut out = ascii.into_bytes();
    if !port.is_empty() || text.ends_with(':') {
        out.push(b':');
        out.extend_from_slice(port);
    }
    Ok(out)
}

pub(super) fn request_target<B>(request: &Request<B>) -> &[u8] {
    if request.version() < Version::HTTP_2 {
        if let Some(raw) = request
            .extensions()
            .get::<hyper::ext::NativeRequestTarget>()
        {
            return &raw.0;
        }
    }
    request
        .uri()
        .path_and_query()
        .map_or(b"/".as_slice(), |p| p.as_str().as_bytes())
}

struct HostWork {
    input: http::HeaderValue,
    credit: native_write_policy::Lease,
}
struct HostBytes {
    bytes: Vec<u8>,
    _credit: native_write_policy::Lease,
}
impl AsRef<[u8]> for HostBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl HostWork {
    fn run(self) -> Result<http::HeaderValue> {
        let normalized = wire_host(self.input.as_bytes());
        drop(self.input);
        let bytes = normalized?;
        let owned = Bytes::from_owner(HostBytes {
            bytes,
            _credit: self.credit,
        });
        Ok(http::HeaderValue::from_maybe_shared(owned)?)
    }
}
pub(super) async fn normalize_header(
    input: http::HeaderValue,
    resources: &super::resource_budget::Resources,
) -> Result<http::HeaderValue> {
    if input.as_bytes().is_ascii() {
        let text = std::str::from_utf8(input.as_bytes()).expect("ASCII Host");
        return match super::http_dial::wire_host(text) {
            std::borrow::Cow::Borrowed(_) => Ok(input),
            std::borrow::Cow::Owned(text) => Ok(http::HeaderValue::from_str(&text)?),
        };
    }
    let fee = input
        .as_bytes()
        .len()
        .checked_mul(16)
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(|| {
            super::request::failure_with_cause(
                http::StatusCode::SERVICE_UNAVAILABLE,
                native_write_policy::Denied.into(),
            )
        })?;
    let credit = resources.header_replacements.reserve(fee).map_err(|e| {
        super::request::failure_with_cause(http::StatusCode::SERVICE_UNAVAILABLE, e.into())
    })?;
    let work = HostWork { input, credit };
    resources
        .metadata
        .run(move || work.run())
        .await
        .map_err(|e| {
            super::request::failure_with_cause(http::StatusCode::SERVICE_UNAVAILABLE, e.into())
        })?
        .map_err(|e| super::request::failure_with_cause(http::StatusCode::BAD_GATEWAY, e))
}
