//! net/url-compatible request-target serialization for configured permission URLs.
//! Keep authority validation separate from path/query; WHATWG normalization of
//! an encoded slash or dot segment must never select a different permission rule.
use super::{PermissionFailure, query};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderValue, uri::PathAndQuery};
use std::net::IpAddr;
use url::{Host, Url};

pub(super) struct Target {
    pub(super) origin: Url,
    pub(super) target: PathAndQuery,
    pub(super) host: HeaderValue,
    pub(super) auth: Option<HeaderValue>,
}
impl Target {
    pub(super) fn parse(input: &str, name: &str) -> Result<Self> {
        let (before_fragment, fragment) = input.split_once('#').unwrap_or((input, ""));
        if !fragment.is_empty() {
            unescape(fragment.as_bytes(), false)?;
        }
        ensure!(
            !before_fragment.bytes().any(|b| b.is_ascii_control()),
            PermissionFailure::Endpoint
        );
        let (scheme, rest) = before_fragment
            .split_once("://")
            .ok_or(PermissionFailure::Endpoint)?;
        let scheme = scheme.to_ascii_lowercase();
        ensure!(
            matches!(scheme.as_str(), "http" | "https"),
            PermissionFailure::Endpoint
        );
        let (authority_path, raw_query) = rest.split_once('?').unwrap_or((rest, ""));
        let split = authority_path.find('/').unwrap_or(authority_path.len());
        let (authority, path) = authority_path.split_at(split);
        let (userinfo, raw_host) = authority
            .rsplit_once('@')
            .map_or((None, authority), |(user, host)| (Some(user), host));
        let (host, port) = host_and_port(raw_host)?;
        let dial_host = if host.is_ascii() {
            host.to_owned()
        } else {
            idna::domain_to_ascii(&host).map_err(|_| PermissionFailure::Endpoint)?
        };
        let wire_host = match port {
            Some(port) if !port.is_empty() => format!("{dial_host}:{port}"),
            _ => dial_host.clone(),
        };
        let origin = Url::parse(&format!("{scheme}://{wire_host}/"))
            .map_err(|_| PermissionFailure::Endpoint)?;
        // WHATWG can reinterpret hex/octal/short numeric names as loopback,
        // or parse forbidden host characters as a second URL component. Never
        // send permission credentials to the resulting different host.
        let same_host = match origin.host() {
            Some(Host::Domain(parsed)) => parsed.eq_ignore_ascii_case(&dial_host),
            Some(Host::Ipv4(parsed)) => dial_host.parse::<IpAddr>() == Ok(IpAddr::V4(parsed)),
            Some(Host::Ipv6(parsed)) => {
                dial_host
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse::<IpAddr>().ok())
                    == Some(IpAddr::V6(parsed))
            }
            None => false,
        };
        ensure!(
            same_host
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.username().is_empty()
                && origin.password().is_none(),
            PermissionFailure::Endpoint
        );
        let path = escaped_path(path)?;
        let request_target = format!("{path}?{}", query::query_with_domain(raw_query, name));
        let target = PathAndQuery::from_bounded_origin_form(bytes::Bytes::from(request_target))
            .map_err(|_| PermissionFailure::Endpoint)?;
        let host = HeaderValue::from_str(&wire_host).map_err(|_| PermissionFailure::Endpoint)?;
        Ok(Self {
            origin,
            target,
            host,
            auth: userinfo.map(basic_auth).transpose()?,
        })
    }
}

fn host_and_port(raw: &str) -> Result<(String, Option<&str>)> {
    ensure!(!raw.is_empty(), PermissionFailure::Endpoint);
    let (host, port) = if raw.starts_with('[') {
        let close = raw.rfind(']').ok_or(PermissionFailure::Endpoint)?;
        let (host, suffix) = raw.split_at(close + 1);
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(PermissionFailure::Endpoint)?,
            )
        };
        (host, port)
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        ensure!(!host.contains(':'), PermissionFailure::Endpoint);
        (host, Some(port))
    } else {
        (raw, None)
    };
    ensure!(
        !host.is_empty() && port.is_none_or(|p| p.bytes().all(|b| b.is_ascii_digit())),
        PermissionFailure::Endpoint
    );
    let decoded = unescape(host.as_bytes(), true)?;
    let decoded = String::from_utf8(decoded).map_err(|_| PermissionFailure::Endpoint)?;
    ensure!(
        !decoded
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b' ' | b'\\' | b'/' | b'?' | b'#' | b'@')),
        PermissionFailure::Endpoint
    );
    Ok((decoded, port))
}

pub(super) fn basic_auth(raw: &str) -> Result<HeaderValue> {
    ensure!(
        raw.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&b)),
        PermissionFailure::Endpoint
    );
    let (user, password) = raw.split_once(':').unwrap_or((raw, ""));
    let mut credentials = zeroize::Zeroizing::new(unescape(user.as_bytes(), false)?);
    credentials.push(b':');
    credentials.extend_from_slice(&zeroize::Zeroizing::new(unescape(
        password.as_bytes(),
        false,
    )?));
    let encoded = zeroize::Zeroizing::new(format!("Basic {}", STANDARD.encode(&credentials)));
    let mut header = HeaderValue::from_str(&encoded).map_err(|_| PermissionFailure::Endpoint)?;
    header.set_sensitive(true);
    Ok(header)
}

fn unescape(bytes: &[u8], host: bool) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut bytes = bytes.iter().copied();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        let high = bytes
            .next()
            .and_then(|b| (b as char).to_digit(16))
            .ok_or(PermissionFailure::Endpoint)?;
        let low = bytes
            .next()
            .and_then(|b| (b as char).to_digit(16))
            .ok_or(PermissionFailure::Endpoint)?;
        let decoded = ((high << 4) | low) as u8;
        ensure!(
            !host || decoded >= 128 || decoded == b'%',
            PermissionFailure::Endpoint
        );
        out.push(decoded);
    }
    Ok(out)
}
fn escaped_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Ok("/".to_owned());
    }
    let default_safe = |b: u8| b.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(&b);
    let decoded = unescape(path.as_bytes(), false)?;
    if path
        .bytes()
        .all(|b| default_safe(b) || b"!'()*[]%".contains(&b))
    {
        return Ok(path.to_owned());
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for b in decoded {
        if default_safe(b) {
            output.push(b as char);
        } else {
            output.push('%');
            output.push(HEX[(b >> 4) as usize] as char);
            output.push(HEX[(b & 15) as usize] as char);
        }
    }
    Ok(output)
}
