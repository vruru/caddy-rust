//! Owned Go net/url views for certificate URI SANs. The parser retains decoded
//! Go string bytes and original RawPath/RawFragment independently.
use super::{Factory, RenderResult, arity, error};
use gotmpl::{Object, Value, ValueFunc};
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
#[derive(Clone)]
struct Url {
    scheme: String,
    opaque: String,
    user: Option<(Vec<u8>, Option<Vec<u8>>)>,
    host: String,
    path: Vec<u8>,
    raw_path: String,
    omit_host: bool,
    force_query: bool,
    query: String,
    fragment: Vec<u8>,
    raw_fragment: String,
}
fn decode(s: &str, plus: bool) -> RenderResult<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let a = bytes
                .get(i + 1)
                .and_then(|b| (*b as char).to_digit(16))
                .ok_or_else(|| error("invalid URL escape"))?;
            let b = bytes
                .get(i + 2)
                .and_then(|b| (*b as char).to_digit(16))
                .ok_or_else(|| error("invalid URL escape"))?;
            out.push((a * 16 + b) as u8);
            i += 3;
        } else {
            out.push(if plus && bytes[i] == b'+' {
                b' '
            } else {
                bytes[i]
            });
            i += 1;
        }
    }
    Ok(out)
}
fn allowed(b: u8, mode: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b"-_.~".contains(&b)
        || match mode {
            0 => b"$&+,/:;=@".contains(&b),
            1 => b"$&+,/:;=?@!()*".contains(&b),
            2 => b"$&+,;=".contains(&b),
            _ => false,
        }
}
fn valid_encoded(raw: &str, mode: u8) -> bool {
    raw.bytes()
        .all(|b| b"!$&'()*+,;=:@[]%".contains(&b) || allowed(b, mode))
}
fn escape(s: &[u8], mode: u8) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s {
        if allowed(*b, mode) {
            out.push(*b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn parse(raw: &str) -> RenderResult<Url> {
    if raw.bytes().any(|b| b < 32 || b == 127) {
        return Err(error("invalid control character in URL"));
    }
    let mut rest = raw;
    let mut scheme = String::new();
    for (i, b) in raw.bytes().enumerate() {
        if b == b':' {
            if i == 0 {
                return Err(error("missing protocol scheme"));
            }
            scheme = raw[..i].to_ascii_lowercase();
            rest = &raw[i + 1..];
            break;
        }
        if !(b.is_ascii_alphabetic()
            || i > 0 && (b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')))
        {
            break;
        }
    }
    let (fragment_raw, before) = if let Some((before, fragment)) = rest.split_once('#') {
        (fragment, before)
    } else {
        ("", rest)
    };
    let fragment = decode(fragment_raw, false)?;
    let raw_fragment = if escape(&fragment, 1) == fragment_raw {
        String::new()
    } else {
        fragment_raw.into()
    };
    rest = before;
    let (mut query, mut force_query) = (String::new(), false);
    if let Some((before, q)) = rest.split_once('?') {
        query = q.into();
        force_query = q.is_empty();
        rest = before;
    }
    let (mut opaque, mut host, mut user) = (String::new(), String::new(), None);
    let mut omit_host = false;
    if !scheme.is_empty() && !rest.starts_with('/') {
        opaque = rest.into();
        rest = "";
    } else if rest.starts_with("//") {
        let after = &rest[2..];
        let end = after.find('/').unwrap_or(after.len());
        let authority = &after[..end];
        rest = &after[end..];
        let authority = if let Some((u, h)) = authority.rsplit_once('@') {
            let (u, p) = if let Some((u, p)) = u.split_once(':') {
                (u, Some(decode(p, false)?))
            } else {
                (u, None)
            };
            user = Some((decode(u, false)?, p));
            h
        } else {
            authority
        };
        // URI SANs are IA5 strings. The shared Go host parser preserves raw
        // bytes through validation; crypto/x509 then rejects non-ASCII domain
        // bytes even though net/url by itself permits escaped high bytes.
        let bytes = crate::http_runtime::http_redirect::url::template_decode_host_bytes(
            scheme.as_bytes(),
            authority.as_bytes(),
        )
        .map_err(|_| error("invalid X.509 URI host"))?;
        if !bytes.is_empty()
            && (bytes.ends_with(b".")
                || bytes.iter().any(|b| !(33..=126).contains(b))
                || bytes.split(|b| *b == b'.').any(|label| label.is_empty()))
        {
            return Err(error("invalid X.509 URI domain"));
        }
        host = String::from_utf8(bytes).map_err(|_| error("invalid X.509 URI domain"))?;
    } else if !scheme.is_empty() && rest.starts_with('/') {
        omit_host = true;
    } else if rest.split('/').next().is_some_and(|p| p.contains(':')) {
        return Err(error("first URL path segment contains colon"));
    }
    let path = decode(rest, false)?;
    let raw_path = if before == "*" || escape(&path, 0) == rest {
        String::new()
    } else {
        rest.into()
    };
    Ok(Url {
        scheme,
        opaque,
        user,
        host,
        path,
        raw_path,
        omit_host,
        force_query,
        query,
        fragment,
        raw_fragment,
    })
}
fn hostname(host: &str) -> &str {
    let host = if let Some(port) = port(host) {
        &host[..host.len() - port.len() - 1]
    } else {
        host
    };
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}
fn port(host: &str) -> Option<&str> {
    if let Some((_, port)) = host.rsplit_once(':') {
        if !port.contains(']') && port.bytes().all(|b| b.is_ascii_digit()) {
            return Some(port);
        }
    }
    None
}
fn path(u: &Url) -> String {
    if !u.raw_path.is_empty() && valid_encoded(&u.raw_path, 0) {
        u.raw_path.clone()
    } else if u.path == b"*" {
        "*".into()
    } else {
        escape(&u.path, 0)
    }
}
fn fragment(u: &Url) -> String {
    if !u.raw_fragment.is_empty() && valid_encoded(&u.raw_fragment, 1) {
        u.raw_fragment.clone()
    } else {
        escape(&u.fragment, 1)
    }
}
fn user_text(user: &(Vec<u8>, Option<Vec<u8>>), redacted: bool) -> String {
    let mut out = escape(&user.0, 2);
    if let Some(password) = &user.1 {
        out.push(':');
        if redacted {
            out.push_str("xxxxx");
        } else {
            out.push_str(&escape(password, 2));
        }
    }
    out
}
fn string(u: &Url, redacted: bool) -> String {
    let mut out = String::new();
    if !u.scheme.is_empty() {
        out.push_str(&u.scheme);
        out.push(':');
    }
    if !u.opaque.is_empty() {
        out.push_str(&u.opaque);
    } else {
        if !u.omit_host && (!u.scheme.is_empty() || !u.host.is_empty() || u.user.is_some()) {
            out.push_str("//");
            if let Some(user) = &u.user {
                out.push_str(&user_text(user, redacted));
                out.push('@');
            }
            let encoded = crate::http_runtime::http_redirect::url::template_encode_host_bytes(
                u.host.as_bytes(),
            );
            out.push_str(std::str::from_utf8(&encoded).expect("Go URL host encoder emits ASCII"));
        }
        let p = path(u);
        if !u.host.is_empty() && !p.is_empty() && !p.starts_with('/') {
            out.push('/');
        }
        if u.scheme.is_empty()
            && u.host.is_empty()
            && p.split('/').next().is_some_and(|s| s.contains(':'))
        {
            out.push_str("./");
        }
        out.push_str(&p);
    }
    if u.force_query || !u.query.is_empty() {
        out.push('?');
        out.push_str(&u.query);
    }
    if !u.fragment.is_empty() {
        out.push('#');
        out.push_str(&fragment(u));
    }
    out
}
struct View {
    url: Url,
    owner: Weak<Factory>,
}
fn user(factory: &Arc<Factory>, value: &Option<(Vec<u8>, Option<Vec<u8>>)>) -> RenderResult<Value> {
    factory.reserve(2048)?;
    let nil = value.is_none();
    let value = value.clone();
    let owner = Arc::downgrade(factory);
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    for name in ["String", "Username", "Password"] {
        let value = value.clone();
        let owner = owner.clone();
        methods.insert(
            name.into(),
            Arc::new(move |a| {
                arity(a, 0, 0)?;
                let f = owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                if name == "Password" {
                    return Err(error(
                        "invalid function signature: second return value is not error",
                    ));
                }
                if name == "Username" {
                    return match &value {
                        None => Err(error("nil pointer evaluating *url.Userinfo.Username")),
                        Some(u) => f.go_string(&u.0),
                    };
                }
                let text = value
                    .as_ref()
                    .map_or_else(String::new, |u| user_text(u, false));
                f.go_string(text.as_bytes())
            }),
        );
    }
    Ok(Value::Object(Arc::new(Object {
        methods,
        nil_pointer: nil.then(|| Arc::new(|| true) as Arc<dyn Fn() -> bool + Send + Sync>),
        go_type: Some("*url.Userinfo"),
        display: Some(
            value
                .as_ref()
                .map_or_else(String::new, |u| user_text(u, false))
                .into(),
        ),
        ..Object::default()
    })))
}
pub(super) fn value(factory: &Arc<Factory>, raw: &str) -> RenderResult<Value> {
    if !raw.is_ascii() {
        return Err(error("X.509 URI SAN is not IA5"));
    }
    factory.reserve(
        raw.len()
            .checked_mul(24)
            .and_then(|n| n.checked_add(16384))
            .ok_or_else(|| error("URI projection size overflow"))?,
    )?;
    from_url(factory, parse(raw)?)
}
fn from_url(factory: &Arc<Factory>, url: Url) -> RenderResult<Value> {
    let display = string(&url, false);
    let fields = BTreeMap::from([
        ("Scheme".into(), Value::String(url.scheme.as_str().into())),
        ("Opaque".into(), Value::String(url.opaque.as_str().into())),
        ("User".into(), user(factory, &url.user)?),
        ("Host".into(), Value::String(url.host.as_str().into())),
        ("Path".into(), factory.go_string(&url.path)?),
        (
            "RawPath".into(),
            Value::String(url.raw_path.as_str().into()),
        ),
        ("OmitHost".into(), Value::Bool(url.omit_host)),
        ("ForceQuery".into(), Value::Bool(url.force_query)),
        ("RawQuery".into(), Value::String(url.query.as_str().into())),
        ("Fragment".into(), factory.go_string(&url.fragment)?),
        (
            "RawFragment".into(),
            Value::String(url.raw_fragment.as_str().into()),
        ),
    ]);
    let data = Arc::new(View {
        url,
        owner: Arc::downgrade(factory),
    });
    let identity = Arc::as_ptr(&data) as usize;
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    for name in [
        "String",
        "Redacted",
        "RequestURI",
        "EscapedPath",
        "EscapedFragment",
        "Hostname",
        "Port",
        "IsAbs",
        "Query",
        "MarshalBinary",
    ] {
        let data = data.clone();
        methods.insert(
            name.into(),
            Arc::new(move |a| {
                arity(a, 0, 0)?;
                let f = data
                    .owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                let u = &data.url;
                f.reserve(
                    (u.path.len()
                        + u.fragment.len()
                        + u.query.len()
                        + u.host.len()
                        + u.opaque.len()
                        + u.user.as_ref().map_or(0, |(user, password)| {
                            user.len() + password.as_ref().map_or(0, Vec::len)
                        }))
                        * 8
                        + 8192,
                )?;
                Ok(match name {
                    "String" | "Redacted" => Value::String(string(u, name == "Redacted").into()),
                    "EscapedPath" => Value::String(path(u).into()),
                    "EscapedFragment" => Value::String(fragment(u).into()),
                    "Hostname" => Value::String(hostname(&u.host).into()),
                    "Port" => Value::String(port(&u.host).unwrap_or_default().into()),
                    "IsAbs" => Value::Bool(!u.scheme.is_empty()),
                    "Query" => {
                        return super::super::super::byte_values(u.query.as_bytes(), &f.owner()?);
                    }
                    "MarshalBinary" => {
                        return f.byte_slice(string(u, false).into_bytes().into(), false);
                    }
                    "RequestURI" => {
                        let mut out = if !u.opaque.is_empty() {
                            if u.opaque.starts_with("//") {
                                format!("{}:{}", u.scheme, u.opaque)
                            } else {
                                u.opaque.clone()
                            }
                        } else {
                            let p = path(u);
                            if p.is_empty() { "/".into() } else { p }
                        };
                        if u.force_query || !u.query.is_empty() {
                            out.push('?');
                            out.push_str(&u.query);
                        }
                        Value::String(out.into())
                    }
                    _ => return Err(error("unknown URL method")),
                })
            }),
        );
    }
    Ok(Value::Object(Arc::new(Object {
        fields,
        methods,
        display: Some(display.into()),
        go_type: Some("*url.URL"),
        pointer_identity: Some(identity),
        data: Some(data),
        field_order: Some(
            [
                "Scheme",
                "Opaque",
                "User",
                "Host",
                "Path",
                "Fragment",
                "RawQuery",
                "RawPath",
                "RawFragment",
                "ForceQuery",
                "OmitHost",
            ]
            .map(Arc::from)
            .into(),
        ),
        ..Object::default()
    })))
}
