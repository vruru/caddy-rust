// Go net/url behavior adapted from Go 1.27.3 src/net/url/url.go.
// Copyright 2009 The Go Authors. BSD-3-Clause; see THIRD-PARTY-NOTICES.
//! Owned, read-only net/url facts from the accepted request Uri. Unlike URI
//! certificate SANs, request URL hosts are not subject to X.509 IA5 rules.
use super::super::Control;
use super::{RenderResult, arity, error};
use crate::http_runtime::http_redirect::url::{
    template_decode_bytes as decode, template_decode_host_bytes as decode_host,
    template_encode_host_bytes as escape_host, template_encode_path_bytes as escape_path,
    template_encode_user_bytes as escape_user,
};
use gotmpl::{Object, TypedSlice, Value, ValueFunc};
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
struct User {
    username: Vec<u8>,
    password: Option<Vec<u8>>,
}
struct View {
    scheme: Vec<u8>,
    host: Vec<u8>,
    path: Vec<u8>,
    raw_path: Vec<u8>,
    query: Vec<u8>,
    force_query: bool,
    user: Option<Arc<User>>,
    owner: Weak<Control>,
    bytes: usize,
}
fn sum(parts: &[usize]) -> RenderResult<usize> {
    parts
        .iter()
        .try_fold(0usize, |n, v| n.checked_add(*v))
        .ok_or_else(|| error("request URL allocation size overflow"))
}
fn prepay(owner: &Arc<Control>, bytes: usize, factor: usize, fixed: usize) -> RenderResult<()> {
    let peak = bytes
        .checked_mul(factor)
        .and_then(|n| n.checked_add(fixed))
        .ok_or_else(|| error("request URL allocation size overflow"))?;
    owner.charge(bytes.div_ceil(64) + 1)?;
    owner.reserve_host_bytes(peak)
}
fn owner(weak: &Weak<Control>, bytes: usize) -> RenderResult<Arc<Control>> {
    let owner = weak
        .upgrade()
        .ok_or_else(|| error("request URL template owner retired"))?;
    prepay(&owner, bytes, 16, 4096)?;
    Ok(owner)
}
fn encoded_valid(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@!\'()*[]%".contains(b))
}
fn escaped_path(view: &View) -> Vec<u8> {
    if !view.raw_path.is_empty() && encoded_valid(&view.raw_path) {
        view.raw_path.clone()
    } else if view.path == b"*" {
        b"*".to_vec()
    } else {
        escape_path(&view.path)
    }
}
fn user_text(user: &User, redacted: bool) -> Vec<u8> {
    let mut bytes = escape_user(&user.username);
    if let Some(password) = &user.password {
        bytes.push(b':');
        if redacted {
            bytes.extend_from_slice(b"xxxxx");
        } else {
            bytes.extend_from_slice(&escape_user(password));
        }
    }
    bytes
}
fn string(view: &View, redacted: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if !view.scheme.is_empty() {
        bytes.extend_from_slice(&view.scheme);
        bytes.push(b':');
    }
    if !view.scheme.is_empty() || !view.host.is_empty() || view.user.is_some() {
        if !view.host.is_empty() || !view.path.is_empty() || view.user.is_some() {
            bytes.extend_from_slice(b"//");
        }
        if let Some(user) = &view.user {
            bytes.extend_from_slice(&user_text(user, redacted));
            bytes.push(b'@');
        }
        bytes.extend_from_slice(&escape_host(&view.host));
    }
    let path = escaped_path(view);
    if !path.is_empty() && !path.starts_with(b"/") && !view.host.is_empty() {
        bytes.push(b'/');
    }
    if bytes.is_empty()
        && path
            .split(|b| *b == b'/')
            .next()
            .is_some_and(|part| part.contains(&b':'))
    {
        bytes.extend_from_slice(b"./");
    }
    bytes.extend_from_slice(&path);
    if view.force_query || !view.query.is_empty() {
        bytes.push(b'?');
        bytes.extend_from_slice(&view.query);
    }
    bytes
}
fn request_uri(view: &View) -> Vec<u8> {
    let mut bytes = escaped_path(view);
    if bytes.is_empty() {
        bytes.push(b'/');
    }
    if view.force_query || !view.query.is_empty() {
        bytes.push(b'?');
        bytes.extend_from_slice(&view.query);
    }
    bytes
}
fn host_port(host: &[u8]) -> (&[u8], &[u8]) {
    let (host, port) = host
        .iter()
        .rposition(|b| *b == b':')
        .filter(|i| host[i + 1..].iter().all(u8::is_ascii_digit))
        .map_or((host, b"".as_slice()), |i| (&host[..i], &host[i + 1..]));
    (
        if host.starts_with(b"[") && host.ends_with(b"]") {
            &host[1..host.len() - 1]
        } else {
            host
        },
        port,
    )
}
fn user_value(user: Option<&Arc<User>>, weak: &Weak<Control>) -> RenderResult<Value> {
    let mut methods = BTreeMap::<Arc<str>, ValueFunc>::new();
    for name in ["String", "Username", "Password"] {
        let user = user.cloned();
        let weak = weak.clone();
        methods.insert(
            name.into(),
            Arc::new(move |args| {
                arity(args, 0, 0)?;
                let bytes = user.as_ref().map_or(0, |u| {
                    u.username.len() + u.password.as_ref().map_or(0, Vec::len)
                });
                let _owner = owner(&weak, bytes)?;
                if name == "Password" {
                    return Err(error(
                        "invalid function signature: second return value is not error",
                    ));
                }
                Ok(Value::from_go_bytes(user.as_ref().map_or_else(
                    Vec::new,
                    |user| {
                        if name == "String" {
                            user_text(user, false)
                        } else {
                            user.username.clone()
                        }
                    },
                )))
            }),
        );
    }
    let display = String::from_utf8(user.map_or_else(Vec::new, |user| user_text(user, false)))
        .map_err(|_| error("request user encoding is not UTF-8"))?;
    Ok(Value::Object(Arc::new(Object {
        methods,
        display: Some(display.into()),
        go_type: Some("*url.Userinfo"),
        nil_pointer: user
            .is_none()
            .then(|| Arc::new(|| true) as Arc<dyn Fn() -> bool + Send + Sync>),
        pointer_identity: user.map(|u| Arc::as_ptr(u) as usize),
        data: user.map(|u| u.clone() as Arc<dyn std::any::Any + Send + Sync>),
        ..Object::default()
    })))
}
pub(super) fn value(uri: &http::Uri, control: &Arc<Control>) -> RenderResult<Value> {
    let raw_scheme = uri.scheme_str().unwrap_or("");
    let raw_authority = uri.authority().map_or("", |v| v.as_str());
    let raw_path = uri.path_and_query().map_or("", |path| path.raw_path());
    let raw_query = uri.query().unwrap_or("");
    let bytes = sum(&[
        raw_scheme.len(),
        raw_authority.len(),
        raw_path.len(),
        raw_query.len(),
        32,
    ])?;
    prepay(control, bytes, 32, 16384)?;
    let weak = Arc::downgrade(control);
    let (raw_user, raw_host) = raw_authority
        .rsplit_once('@')
        .map_or((None, raw_authority), |(u, h)| (Some(u), h));
    let user = if let Some(raw) = raw_user {
        let (username, password) = raw
            .split_once(':')
            .map_or((raw, None), |(u, p)| (u, Some(p)));
        Some(Arc::new(User {
            username: decode(username.as_bytes())
                .map_err(|_| error("invalid request URL user escape"))?,
            password: password
                .map(|p| decode(p.as_bytes()))
                .transpose()
                .map_err(|_| error("invalid request URL password escape"))?,
        }))
    } else {
        None
    };
    let path = decode(raw_path.as_bytes()).map_err(|_| error("invalid request URL path escape"))?;
    // net/url's bare-asterisk parser bypasses setPath; RawPath stays empty.
    let bare_asterisk = raw_path == "*" && uri.scheme().is_none()
        && uri.authority().is_none() && uri.query().is_none();
    let raw_path = if bare_asterisk || escape_path(&path) == raw_path.as_bytes() {
        Vec::new()
    } else {
        raw_path.as_bytes().to_vec()
    };
    let view = Arc::new(View {
        scheme: raw_scheme.as_bytes().to_vec(),
        host: decode_host(raw_scheme.as_bytes(), raw_host.as_bytes())
            .map_err(|_| error("invalid request URL host"))?,
        path,
        raw_path,
        query: raw_query.as_bytes().to_vec(),
        force_query: uri.query() == Some(""),
        user,
        owner: weak.clone(),
        bytes,
    });
    let fields = BTreeMap::from([
        (
            "Scheme".into(),
            Value::from_go_bytes(view.scheme.as_slice()),
        ),
        ("Opaque".into(), Value::from("")),
        ("User".into(), user_value(view.user.as_ref(), &weak)?),
        ("Host".into(), Value::from_go_bytes(view.host.as_slice())),
        ("Path".into(), Value::from_go_bytes(view.path.as_slice())),
        ("Fragment".into(), Value::from("")),
        (
            "RawQuery".into(),
            Value::from_go_bytes(view.query.as_slice()),
        ),
        (
            "RawPath".into(),
            Value::from_go_bytes(view.raw_path.as_slice()),
        ),
        ("RawFragment".into(), Value::from("")),
        ("ForceQuery".into(), Value::Bool(view.force_query)),
        ("OmitHost".into(), Value::Bool(false)),
    ]);
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
        let view = view.clone();
        methods.insert(
            name.into(),
            Arc::new(move |args| {
                arity(args, 0, 0)?;
                let control = owner(&view.owner, view.bytes)?;
                Ok(match name {
                    "String" | "Redacted" => {
                        Value::from_go_bytes(string(&view, name == "Redacted"))
                    }
                    "RequestURI" => Value::from_go_bytes(request_uri(&view)),
                    "EscapedPath" => Value::from_go_bytes(escaped_path(&view)),
                    "EscapedFragment" => Value::from(""),
                    "Hostname" => Value::from_go_bytes(host_port(&view.host).0),
                    "Port" => Value::from_go_bytes(host_port(&view.host).1),
                    "IsAbs" => Value::Bool(!view.scheme.is_empty()),
                    "Query" => return super::byte_values(&view.query, &control),
                    "MarshalBinary" => {
                        let bytes = string(&view, false);
                        let weak = Arc::downgrade(&control);
                        Value::Slice(
                            TypedSlice::bytes(if bytes.is_empty() {
                                None
                            } else {
                                Some(bytes.into())
                            })
                            .with_host_budget(Arc::new(
                                move |bytes| {
                                    weak.upgrade()
                                        .ok_or_else(|| error("request URL template owner retired"))?
                                        .reserve_host_bytes(bytes)
                                },
                            )),
                        )
                    }
                    _ => return Err(error("unknown request URL method")),
                })
            }),
        );
    }
    let display = String::from_utf8(string(&view, false))
        .map_err(|_| error("request URL display encoding is not UTF-8"))?;
    Ok(Value::Object(Arc::new(Object {
        fields,
        methods,
        display: Some(display.into()),
        go_type: Some("*url.URL"),
        pointer_identity: Some(uri as *const http::Uri as usize),
        data: Some(view),
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
