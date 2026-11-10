use super::AdminError;
use http::{HeaderMap, header};
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct LocalPolicy {
    pub disabled: bool,
    pub listen: String,
    pub enforce_origin: bool,
    pub origins: Option<Vec<String>>,
    pub persist: bool,
    pub loader: Option<super::loader_schema::LoaderPlan>,
    pub identity: Option<super::remote::Identity>,
    pub remote: Option<super::remote::Remote>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Raw {
    disabled: bool,
    listen: String,
    enforce_origin: bool,
    origins: Option<Vec<String>>,
    config: Option<Settings>,
    identity: Option<super::remote::Identity>,
    remote: Option<super::remote::Remote>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    persist: Option<bool>,
    load: Option<Value>,
    load_delay: Option<Value>,
}

impl LocalPolicy {
    pub fn parse(config: &Value) -> Result<Self, AdminError> {
        if !config.is_object() && !config.is_null() {
            return Err(AdminError::new(400, "configuration_must_be_object_or_null"));
        }
        let raw: Raw = match config.get("admin") {
            None | Some(Value::Null) => Raw::default(),
            Some(v) => {
                let mut typed = v.clone();
                super::ids::strip_meta(&mut typed);
                serde_json::from_value(typed)
                    .map_err(|_| AdminError::new(400, "invalid_or_unknown_admin_field"))?
            }
        };
        if raw.remote.is_some()
            && raw
                .identity
                .as_ref()
                .is_none_or(|i| i.identifiers.is_empty())
        {
            return Err(AdminError::new(400, "remote_admin_requires_identity"));
        }
        if raw.identity.as_ref().is_some_and(|i| {
            i.identifiers.len() > 1024
                || i.identifiers
                    .iter()
                    .any(|s| s.is_empty() || s.len() > 253 || s.contains(['\0', '{', '}']))
        }) {
            return Err(AdminError::new(400, "invalid_admin_identity"));
        }
        let loader = super::loader_schema::LoaderPlan::parse(
            raw.config.as_ref().and_then(|s| s.load.as_ref()),
            raw.config.as_ref().and_then(|s| s.load_delay.as_ref()),
        )?;
        let listen = if raw.listen.is_empty() {
            std::env::var("CADDY_ADMIN").unwrap_or_else(|_| "localhost:2019".to_owned())
        } else {
            raw.listen
        };
        if listen.is_empty() || listen.len() > 4096 || listen.contains(['\0', '{', '}']) {
            return Err(AdminError::new(
                400,
                "invalid_or_unimplemented_admin_address",
            ));
        }
        let mut remote = raw.remote;
        if let Some(remote) = &mut remote
            && remote.listen.is_empty()
        {
            remote.listen = ":2021".to_owned();
        }
        if let Some(remote) = &remote
            && listen.starts_with("fd/")
            && remote.listen.starts_with("fd/")
        {
            let a = super::inherited::number(&listen)?;
            let b = super::inherited::number(&remote.listen)?;
            if a == b
                || super::inherited::key(&listen)
                    .is_some_and(|key| Some(key) == super::inherited::key(&remote.listen))
            {
                return Err(AdminError::new(400, "admin_inherited_socket_used_twice"));
            }
        }
        address_syntax(&listen)?;
        if let Some(remote) = &remote {
            address_syntax(&remote.listen)?;
        }
        let policy = Self {
            disabled: raw.disabled,
            listen,
            enforce_origin: raw.enforce_origin,
            origins: raw.origins,
            identity: raw.identity,
            remote,
            persist: raw.config.and_then(|s| s.persist).unwrap_or(true),
            loader,
        };
        if let Some(origins) = &policy.origins {
            if origins.len() > 1024 {
                return Err(AdminError::new(400, "admin_origin_limit_exceeded"));
            }
            for origin in origins {
                ParsedOrigin::parse(origin, false)?;
            }
        }
        Ok(policy)
    }
}

#[derive(Clone)]
struct ParsedOrigin {
    scheme: Option<String>,
    authority: String,
}
impl ParsedOrigin {
    fn parse(raw: &str, require_scheme: bool) -> Result<Self, AdminError> {
        if raw.is_empty()
            || raw.len() > 4096
            || raw.contains(['*', '@', '\r', '\n', '\t', ' ', '\\', '?', '#'])
            || raw.eq_ignore_ascii_case("null")
        {
            return Err(AdminError::new(403, "invalid_origin"));
        }
        let (scheme, authority) = match raw.split_once("://") {
            Some((scheme, rest)) => {
                if !matches!(scheme, "http" | "https") || rest.contains('/') {
                    return Err(AdminError::new(403, "invalid_origin"));
                }
                (Some(scheme.to_owned()), rest)
            }
            None if !require_scheme => (None, raw),
            _ => return Err(AdminError::new(403, "invalid_origin")),
        };
        let parsed: http::uri::Authority = authority
            .parse()
            .map_err(|_| AdminError::new(403, "invalid_origin_authority"))?;
        if authority.contains('/') || parsed.host().is_empty() || authority.ends_with(':') {
            return Err(AdminError::new(403, "invalid_origin_authority"));
        }
        Ok(Self {
            scheme,
            authority: authority.to_ascii_lowercase(),
        })
    }
}

#[derive(Clone)]
pub(super) struct OriginPolicy {
    allowed: Vec<ParsedOrigin>,
    enforce: bool,
    unix: bool,
}
impl OriginPolicy {
    pub fn new(local: &LocalPolicy, unix: bool, port: u16) -> Result<Self, AdminError> {
        let values = match &local.origins {
            Some(v) => v.clone(),
            None if unix => Vec::new(),
            None => vec![
                format!("localhost:{port}"),
                format!("127.0.0.1:{port}"),
                format!("[::1]:{port}"),
            ],
        };
        Ok(Self {
            allowed: values
                .iter()
                .map(|s| ParsedOrigin::parse(s, false))
                .collect::<Result<_, _>>()?,
            enforce: local.enforce_origin,
            unix,
        })
    }
    /// Returned exact origin may be echoed as ACAO. No wildcard or reflection
    /// occurs before this allowlist check. Missing Origin is valid for CLI.
    pub fn check(&self, h: &HeaderMap) -> Result<Option<String>, AdminError> {
        for name in [header::HOST, header::ORIGIN, header::REFERER] {
            if h.get_all(name).iter().count() > 1 {
                return Err(AdminError::new(400, "duplicate_security_header"));
            }
        }
        for name in ["upgrade", "sec-fetch-mode", "sec-fetch-site"] {
            if h.get_all(name).iter().count() > 1 {
                return Err(AdminError::new(400, "duplicate_security_header"));
            }
        }
        if h.get("upgrade")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| {
                s.to_ascii_lowercase()
                    .split(',')
                    .any(|s| s.trim() == "websocket")
            })
        {
            return Err(AdminError::new(400, "admin_websocket_forbidden"));
        }
        if h.get("sec-fetch-mode")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.eq_ignore_ascii_case("no-cors"))
            || h.get("sec-fetch-site")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.eq_ignore_ascii_case("cross-site"))
        {
            return Err(AdminError::new(403, "cross_site_admin_request_forbidden"));
        }
        if let Some(host) = h.get(header::HOST) {
            let raw = host
                .to_str()
                .map_err(|_| AdminError::new(400, "invalid_admin_host"))?;
            let authority: http::uri::Authority = raw
                .parse()
                .map_err(|_| AdminError::new(400, "invalid_admin_host"))?;
            if raw.contains(['@', '/', '\\']) || authority.host().is_empty() || raw.ends_with(':') {
                return Err(AdminError::new(400, "invalid_admin_host"));
            }
        }
        if !self.unix {
            let host = h
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AdminError::new(403, "admin_host_required"))?;
            if !self
                .allowed
                .iter()
                .any(|o| o.authority.eq_ignore_ascii_case(host))
            {
                return Err(AdminError::new(403, "admin_host_not_allowed"));
            }
        }
        let origin = if let Some(raw) = h.get(header::ORIGIN) {
            Some(
                raw.to_str()
                    .map_err(|_| AdminError::new(400, "invalid_origin"))?
                    .to_owned(),
            )
        } else if self.enforce || h.contains_key("sec-fetch-mode") {
            let raw = h
                .get(header::REFERER)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AdminError::new(403, "admin_origin_required"))?;
            let u = url::Url::parse(raw).map_err(|_| AdminError::new(403, "invalid_referer"))?;
            if !matches!(u.scheme(), "http" | "https")
                || !u.username().is_empty()
                || u.password().is_some()
            {
                return Err(AdminError::new(403, "invalid_referer"));
            }
            Some(format!(
                "{}://{}",
                u.scheme(),
                &u[url::Position::BeforeHost..url::Position::AfterPort]
            ))
        } else {
            None
        };
        if let Some(raw) = origin {
            let origin = ParsedOrigin::parse(&raw, true)?;
            if !self.allowed.iter().any(|o| {
                o.authority == origin.authority
                    && o.scheme
                        .as_ref()
                        .is_none_or(|s| Some(s) == origin.scheme.as_ref())
            }) {
                return Err(AdminError::new(403, "admin_origin_not_allowed"));
            }
            Ok(Some(raw))
        } else {
            Ok(None)
        }
    }
}

pub(super) fn remote_browser_check(headers: &HeaderMap) -> Result<(), AdminError> {
    for name in [
        "host",
        "origin",
        "referer",
        "upgrade",
        "sec-fetch-mode",
        "sec-fetch-site",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(AdminError::new(400, "duplicate_security_header"));
        }
    }
    if headers
        .get("upgrade")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| {
            h.to_ascii_lowercase()
                .split(',')
                .any(|s| s.trim() == "websocket")
        })
    {
        return Err(AdminError::new(400, "admin_websocket_forbidden"));
    }
    if headers.contains_key("origin")
        || headers.contains_key("sec-fetch-mode")
        || headers
            .get("sec-fetch-site")
            .is_some_and(|h| h == "cross-site")
    {
        return Err(AdminError::new(403, "remote_browser_origin_not_allowed"));
    }
    Ok(())
}

fn address_syntax(raw: &str) -> Result<(), AdminError> {
    let invalid = || AdminError::new(400, "invalid_admin_listener_address");
    if raw.starts_with("fd/") {
        super::inherited::number(raw)?;
        return Ok(());
    }
    if let Some(unix) = raw.strip_prefix("unix/") {
        if let Some(name) = unix.strip_prefix('@') {
            if name.is_empty() || name.len() > 107 || name.contains(['|', '\0']) {
                return Err(invalid());
            }
        } else {
            let path = match unix.rsplit_once('|') {
                None => unix,
                Some((path, "0600" | "0660")) => path,
                _ => return Err(invalid()),
            };
            let max = if cfg!(target_os = "macos") { 103 } else { 107 };
            if !std::path::Path::new(path).is_absolute() || path.len() > max {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
