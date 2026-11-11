//! Strictly compiled HTTP configuration. Known but incomplete capabilities fail
//! before activation. The raw configuration may contain secrets; do not Debug it.
#[path = "http_config/helpers.rs"]
pub(crate) mod helpers;
#[path = "http_config/types.rs"]
pub(crate) mod types;
use anyhow::{Result, ensure};
use helpers::*;
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use types::*;

#[derive(Clone)]
pub struct PreparedConfig {
    pub(crate) servers: Vec<Arc<ServerConfig>>,
    pub(crate) certificates: Vec<FileCertificate>,
    shutdown_policy: HttpShutdownPolicy,
}
/// Native shutdown settings. Zero/omitted Go grace means genuinely unlimited
/// drain, represented by None rather than an artificial maximum duration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpShutdownPolicy {
    pub grace_period: Option<Duration>,
    pub shutdown_delay: Duration,
}
impl PreparedConfig {
    pub fn shutdown_policy(&self) -> HttpShutdownPolicy {
        self.shutdown_policy
    }
}
#[derive(Clone)]
pub(crate) struct ServerConfig {
    pub(crate) access_logs: Option<AccessLogConfig>,
    pub(crate) listen: Vec<SocketAddr>,
    pub(crate) routes: Vec<Route>,
    pub(crate) errors: Vec<Route>,
    pub(crate) tls: bool,
    pub(crate) certificate_tags: Vec<String>,
    pub(crate) trusted_proxies: Vec<ipnet::IpNet>,
    pub(crate) trusted_strict: bool,
    pub(crate) client_ip_headers: Vec<String>,
    pub(crate) read_header_timeout: Duration,
    pub(crate) read_idle_timeout: Duration,
    pub(crate) protocols: Vec<String>,
    pub(crate) redirect_http: bool,
    pub(crate) manage_certificates: bool,
    pub(crate) skip_manage: Vec<String>,
    pub(crate) skip_redirect: Vec<String>,
    pub(crate) ignore_loaded_certificates: bool,
}
#[derive(Clone)]
pub(crate) struct AccessLogConfig {
    pub(crate) default_name: String,
    pub(crate) names: std::collections::BTreeMap<String, Vec<String>>,
    pub(crate) skip_hosts: Vec<String>,
    pub(crate) skip_unmapped: bool,
    pub(crate) credentials: bool,
}

fn access_logs(value: &Value, path: &str) -> Result<AccessLogConfig> {
    let map = object(value, path)?;
    deny_unknown(map,&["default_logger_name","logger_names","skip_hosts","skip_unmapped_hosts","should_log_credentials","trace"],path)?;
    ensure!(!boolean(map.get("trace"),false,path)?, "HTTP handler trace logging is not implemented");
    let mut names=std::collections::BTreeMap::new();
    if let Some(value)=map.get("logger_names").filter(|value|!value.is_null()) {
        let map=object(value,path)?;
        ensure!(map.len()<=8192, "too many access logger hosts");
        for (host,value) in map {
            let mapped=if let Some(value)=value.as_str() {vec![value.to_owned()]} else {strings(value,path)?};
            ensure!(mapped.len()<=16 && mapped.iter().all(|name|name.len()<=128),"too many or oversized access logger destinations");
            let normalized = host.trim_end_matches('.').to_ascii_lowercase();
            ensure!(!names.contains_key(&normalized), "ambiguous access logger host");
            names.insert(normalized,mapped);
        }
    }
    let default_name=map.get("default_logger_name").filter(|value|!value.is_null()).map(|value|string(value,path)).transpose()?.unwrap_or_default();
    ensure!(default_name.len()<=128,"oversized default access logger name");
    Ok(AccessLogConfig{
        default_name,
        names,
        skip_hosts:map.get("skip_hosts").filter(|value|!value.is_null()).map(|value|strings(value,path)).transpose()?.unwrap_or_default().into_iter().map(|host|host.trim_end_matches('.').to_ascii_lowercase()).collect(),
        skip_unmapped:boolean(map.get("skip_unmapped_hosts"),false,path)?,
        credentials:boolean(map.get("should_log_credentials"),false,path)?,
    })
}

#[derive(Clone)]
pub(crate) struct FileCertificate {
    pub(crate) certificate: String,
    pub(crate) key: String,
    pub(crate) tags: Vec<String>,
}

pub fn validate_json(value: &Value) -> Result<PreparedConfig> {
    pending_placeholders(value)?;
    let root = object(value, "/")?;
    deny_unknown(
        root,
        &[
            "apps",
            "logging",
            "admin",
            "storage",
            "persist_config",
            "grace_period",
            "shutdown_delay",
        ],
        "/",
    )?;
    for key in [
        "logging",
        "admin",
        "storage",
        "persist_config",
        "grace_period",
        "shutdown_delay",
    ] {
        if root.contains_key(key) {
            return Err(unsupported(&format!("/{key}")));
        }
    }
    let apps = object(
        root.get("apps")
            .ok_or_else(|| anyhow::anyhow!("apps required"))?,
        "/apps",
    )?;
    deny_unknown(apps, &["http", "tls"], "/apps")?;
    let mut certificates = Vec::new();
    if let Some(tls) = apps.get("tls") {
        let tls = object(tls, "/apps/tls")?;
        deny_unknown(tls, &["certificates"], "/apps/tls")?;
        if let Some(raw) = tls.get("certificates") {
            let raw = object(raw, "/apps/tls/certificates")?;
            deny_unknown(raw, &["load_files"], "/apps/tls/certificates")?;
            if let Some(files) = raw.get("load_files") {
                for file in files
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("load_files array required"))?
                {
                    let file = object(file, "/apps/tls/certificates/load_files/*")?;
                    deny_unknown(
                        file,
                        &["certificate", "key", "tags"],
                        "/apps/tls/certificates/load_files/*",
                    )?;
                    certificates.push(FileCertificate {
                        certificate: string(required(file, "certificate")?, "certificate")?,
                        key: string(required(file, "key")?, "key")?,
                        tags: file
                            .get("tags")
                            .map(|v| strings(v, "tags"))
                            .transpose()?
                            .unwrap_or_default(),
                    });
                }
            }
        }
    }
    let http = object(
        apps.get("http")
            .ok_or_else(|| anyhow::anyhow!("HTTP app required"))?,
        "/apps/http",
    )?;
    deny_unknown(
        http,
        &[
            "servers",
            "http_port",
            "https_port",
            "grace_period",
            "shutdown_delay",
        ],
        "/apps/http",
    )?;
    let grace = http
        .get("grace_period")
        .filter(|value| !value.is_null())
        .map(|value| signed_duration(value, "/apps/http/grace_period"))
        .transpose()?
        .unwrap_or(0);
    let delay = http
        .get("shutdown_delay")
        .filter(|value| !value.is_null())
        .map(|value| signed_duration(value, "/apps/http/shutdown_delay"))
        .transpose()?
        .unwrap_or(0);
    let shutdown_policy = HttpShutdownPolicy {
        grace_period: (grace > 0).then(|| Duration::from_nanos(grace as u64)),
        shutdown_delay: Duration::from_nanos(delay.max(0) as u64),
    };
    if http.contains_key("http_port") || http.contains_key("https_port") {
        return Err(unsupported("/apps/http/port_overrides"));
    }
    let raw = object(
        http.get("servers")
            .ok_or_else(|| anyhow::anyhow!("servers required"))?,
        "/apps/http/servers",
    )?;
    ensure!(raw.len() <= 1024, "server count exceeded");
    let mut servers = Vec::new();
    let mut listen = std::collections::HashSet::new();
    for value in raw.values() {
        let config = parse_server(value)?;
        for addr in &config.listen {
            ensure!(listen.insert(*addr), "duplicate listener address");
        }
        servers.push(Arc::new(config));
    }
    Ok(PreparedConfig {
        servers,
        certificates,
        shutdown_policy,
    })
}

/// Candidate names before static certificates are loaded. The runtime's
/// active_managed_names removes names covered by loaded static certificates.
pub fn managed_names(config: &PreparedConfig) -> Vec<Vec<String>> {
    let mut names = std::collections::BTreeSet::new();
    for server in &config.servers {
        if server.tls && server.manage_certificates && server.certificate_tags.is_empty() {
            for name in server_names(server) {
                if !server
                    .skip_manage
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&name))
                {
                    names.insert(name);
                }
            }
        }
    }
    names.into_iter().map(|n| vec![n]).collect()
}
pub(crate) fn server_names(server: &ServerConfig) -> Vec<String> {
    route_names(&server.routes)
}
fn route_names(routes: &[Route]) -> Vec<String> {
    fn visit(routes: &[Route], names: &mut std::collections::BTreeSet<String>) {
        for route in routes {
            for matcher in route.matchers.iter().flatten() {
                if let Matcher::Host(hosts) = matcher {
                    for host in hosts {
                        if !host.contains('{')
                            && host.parse::<std::net::IpAddr>().is_err()
                            && (!host.contains('*') || host.starts_with("*."))
                        {
                            names.insert(host.trim_end_matches('.').to_ascii_lowercase());
                        }
                    }
                }
            }
            for handler in &route.handlers {
                if let Handler::Subroute { routes, .. } = handler {
                    visit(routes, names);
                }
            }
        }
    }
    let mut names = std::collections::BTreeSet::new();
    visit(routes, &mut names);
    names.into_iter().collect()
}
fn required<'a>(m: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a Value> {
    m.get(key)
        .ok_or_else(|| anyhow::anyhow!("required configuration field missing"))
}
fn parse_server(value: &Value) -> Result<ServerConfig> {
    let path = "/apps/http/servers/*";
    let m = object(value, path)?;
    deny_unknown(
        m,
        &[
            "listen",
            "routes",
            "errors",
            "protocols",
            "automatic_https",
            "listener_wrappers",
            "tls_connection_policies",
            "trusted_proxies",
            "trusted_proxies_strict",
            "client_ip_headers",
            "read_header_timeout",
            "read_idle_timeout",
            "idle_timeout",
            "logs",
        ],
        path,
    )?;
    if m.contains_key("idle_timeout") {
        return Err(unsupported("/apps/http/servers/*/idle_timeout"));
    }
    let access_logs = m.get("logs").filter(|value|!value.is_null())
        .map(|value| access_logs(value,path)).transpose()?;
    let mut listen = Vec::new();
    for raw in strings(required(m, "listen")?, path)? {
        let raw = helpers::replace(&raw, true, helpers::global_lookup)?;
        let raw = raw.strip_prefix("tcp/").unwrap_or(&raw);
        let raw = if raw.starts_with(':') {
            format!("[::]{raw}")
        } else {
            raw.to_owned()
        };
        listen.push(
            raw.parse::<SocketAddr>()
                .map_err(|_| unsupported("/apps/http/servers/*/listen/network_or_hostname"))?,
        );
    }
    ensure!(
        !listen.is_empty() && listen.len() <= 1024,
        "listener count invalid"
    );
    let policies = m
        .get("tls_connection_policies")
        .map(|v| {
            v.as_array()
                .ok_or_else(|| anyhow::anyhow!("TLS policy array required"))
        })
        .transpose()?;
    let mut tags = Vec::new();
    if let Some(policies) = policies {
        ensure!(
            policies.len() <= 1,
            "multiple TLS policies not yet supported"
        );
        for policy in policies {
            let policy = object(policy, path)?;
            deny_unknown(
                policy,
                &["certificate_selection"],
                "/apps/http/servers/*/tls_connection_policies/*",
            )?;
            if let Some(selection) = policy.get("certificate_selection") {
                let selection = object(selection, path)?;
                deny_unknown(
                    selection,
                    &["any_tag"],
                    "/apps/http/servers/*/tls_connection_policies/*/certificate_selection",
                )?;
                tags = selection
                    .get("any_tag")
                    .map(|v| strings(v, path))
                    .transpose()?
                    .unwrap_or_default();
            }
        }
    }
    let mut wrapper_tls = false;
    if let Some(wrappers) = m.get("listener_wrappers") {
        let wrappers = wrappers
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("listener wrappers array required"))?;
        for wrapper in wrappers {
            let wrapper = object(wrapper, path)?;
            deny_unknown(wrapper, &["wrapper"], path)?;
            ensure!(
                wrapper.get("wrapper").and_then(Value::as_str) == Some("tls"),
                "unsupported listener wrapper"
            );
            ensure!(!wrapper_tls, "duplicate TLS listener wrapper");
            wrapper_tls = true;
        }
    }
    let mut disabled = false;
    let mut redirect_http = true;
    let mut manage_certificates = true;
    let mut skip_manage = Vec::new();
    let mut skip_redirect = Vec::new();
    let mut ignore_loaded_certificates = false;
    if let Some(auto) = m.get("automatic_https") {
        let auto = object(auto, path)?;
        deny_unknown(
            auto,
            &[
                "disable",
                "disable_redirects",
                "disable_certificates",
                "skip",
                "skip_certificates",
                "ignore_loaded_certificates",
                "prefer_wildcard",
            ],
            "/apps/http/servers/*/automatic_https",
        )?;
        disabled = boolean(auto.get("disable"), false, path)?;
        redirect_http = !disabled && !boolean(auto.get("disable_redirects"), false, path)?;
        manage_certificates = !disabled && !boolean(auto.get("disable_certificates"), false, path)?;
        skip_redirect = auto
            .get("skip")
            .map(|v| strings(v, path))
            .transpose()?
            .unwrap_or_default();
        skip_manage = skip_redirect.clone();
        skip_manage.extend(
            auto.get("skip_certificates")
                .map(|v| strings(v, path))
                .transpose()?
                .unwrap_or_default(),
        );
        ignore_loaded_certificates = boolean(auto.get("ignore_loaded_certificates"), false, path)?;
        if auto.contains_key("prefer_wildcard") {
            return Err(unsupported(
                "/apps/http/servers/*/automatic_https/prefer_wildcard",
            ));
        }
    }
    let routes = parse_routes(m.get("routes"), 0, false)?;
    let inferred = !disabled
        && listen.iter().any(|a| a.port() != 80)
        && route_names(&routes)
            .iter()
            .any(|n| !skip_redirect.iter().any(|s| s.eq_ignore_ascii_case(n)));
    let tls = wrapper_tls
        || policies.is_some()
        || (!disabled && listen.iter().any(|a| a.port() == 443))
        || inferred;
    let protocols = m
        .get("protocols")
        .map(|v| strings(v, path))
        .transpose()?
        .unwrap_or_else(|| {
            if tls {
                vec!["h1".into(), "h2".into(), "h3".into()]
            } else {
                vec!["h1".into(), "h2".into()]
            }
        });
    ensure!(!protocols.is_empty(), "empty protocol list");
    for protocol in &protocols {
        if protocol == "h3" {
            return Err(unsupported("/apps/http/servers/*/protocols/h3"));
        }
        ensure!(
            matches!(protocol.as_str(), "h1" | "h2" | "h2c"),
            "unsupported HTTP protocol"
        );
    }
    ensure!(
        !protocols.iter().any(|p| matches!(p.as_str(), "h2" | "h2c"))
            || protocols.contains(&"h1".to_owned()),
        "h2 and h2c require h1 for Caddy config compatibility"
    );
    let trusted_proxies = if let Some(proxies) = m.get("trusted_proxies") {
        let proxies = object(proxies, path)?;
        deny_unknown(proxies, &["source", "ranges"], path)?;
        ensure!(
            proxies.get("source").and_then(Value::as_str) == Some("static"),
            "unsupported trusted proxy source"
        );
        parse_ranges(required(proxies, "ranges")?, path)?
    } else {
        Vec::new()
    };
    let trusted_strict = m
        .get("trusted_proxies_strict")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_number()
                .and_then(|n| n.as_go_i64())
                .map(|n| n > 0)
                .ok_or_else(|| anyhow::anyhow!("integer trusted proxy strict flag required"))
        })
        .transpose()?
        .unwrap_or(false);
    Ok(ServerConfig {
        access_logs,
        listen,
        routes,
        errors: if let Some(v) = m.get("errors") {
            let e = object(v, path)?;
            deny_unknown(e, &["routes"], path)?;
            parse_routes(e.get("routes"), 0, false)?
        } else {
            vec![]
        },
        tls,
        certificate_tags: tags,
        trusted_proxies,
        trusted_strict,
        client_ip_headers: m
            .get("client_ip_headers")
            .map(|v| strings(v, path))
            .transpose()?
            .unwrap_or_else(|| vec!["X-Forwarded-For".into()]),
        read_header_timeout: m
            .get("read_header_timeout")
            .map(|v| duration(v, path))
            .transpose()?
            .filter(|d| !d.is_zero())
            .unwrap_or(Duration::from_secs(60)),
        read_idle_timeout: m
            .get("read_idle_timeout")
            .map(|v| duration(v, path))
            .transpose()?
            .filter(|d| !d.is_zero())
            .unwrap_or(Duration::from_secs(60)),
        protocols,
        redirect_http,
        manage_certificates,
        skip_manage,
        skip_redirect,
        ignore_loaded_certificates,
    })
}
fn parse_ranges(value: &Value, path: &str) -> Result<Vec<ipnet::IpNet>> {
    strings(value, path)?
        .iter()
        .map(|s| {
            s.parse::<ipnet::IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| anyhow::anyhow!("invalid IP range at {path}"))
        })
        .collect()
}
fn parse_routes(value: Option<&Value>, depth: usize, normalized: bool) -> Result<Vec<Route>> {
    ensure!(depth < 64, "route nesting limit exceeded");
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let raw = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("route array required"))?;
    ensure!(raw.len() <= 65536, "route count limit exceeded");
    let mut routes = Vec::new();
    for v in raw {
        let path = "/apps/http/servers/*/routes/*";
        let m = object(v, path)?;
        deny_unknown(m, &["group", "match", "handle", "terminal"], path)?;
        let mut handlers = vec![];
        if let Some(values) = m.get("handle") {
            for v in values
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("handler array required"))?
            {
                handlers.push(parse_handler(v, depth + 1, normalized)?);
            }
        }
        routes.push(Route {
            group: m.get("group").map(|v| string(v, path)).transpose()?,
            matchers: parse_matcher_sets(m.get("match"), depth + 1)?,
            handlers,
            terminal: boolean(m.get("terminal"), false, path)?,
        });
    }
    Ok(routes)
}
fn parse_matcher_sets(value: Option<&Value>, depth: usize) -> Result<Vec<MatcherSet>> {
    ensure!(depth < 64, "matcher nesting limit exceeded");
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let raw = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("matcher sets array required"))?;
    let mut sets = Vec::new();
    for v in raw {
        let m = object(v, "matcher")?;
        let mut set = Vec::new();
        for (k, v) in m {
            set.push(match k.as_str() {
                "host" => {
                    let mut seen = std::collections::HashSet::new();
                    let mut hosts = Vec::new();
                    for raw in strings(v, "host")? {
                        let empty = std::cell::Cell::new(false);
                        let expanded = helpers::replace(&raw, false, |key| {
                            let result = helpers::global_lookup(key);
                            if result.as_ref().is_some_and(String::is_empty) {
                                empty.set(true);
                            }
                            result
                        })?;
                        ensure!(!empty.get(), "empty global hostname placeholder");
                        let host = idna::domain_to_ascii(&expanded)
                            .map_err(|_| anyhow::anyhow!("invalid IDNA hostname"))?
                            .to_ascii_lowercase();
                        ensure!(seen.insert(host.clone()), "duplicate host matcher");
                        hosts.push(host);
                    }
                    Matcher::Host(hosts)
                }
                "path" => {
                    let patterns = strings(v, "path")?;
                    if patterns.iter().any(|p| p.contains('%')) {
                        return Err(unsupported("/match/path/escaped_patterns"));
                    }
                    Matcher::Path(patterns.iter().map(|s| s.to_lowercase()).collect())
                }
                "path_regexp" => {
                    let m = object(v, "path_regexp")?;
                    deny_unknown(m, &["name", "pattern"], "path_regexp")?;
                    Matcher::PathRegex {
                        name: m
                            .get("name")
                            .map(|v| string(v, "regex name"))
                            .transpose()?
                            .unwrap_or_default(),
                        regex: regex::Regex::new(
                            required(m, "pattern")?
                                .as_str()
                                .ok_or_else(|| anyhow::anyhow!("regex pattern string required"))?,
                        )
                        .map_err(|_| anyhow::anyhow!("invalid path regular expression"))?,
                    }
                }
                "method" => Matcher::Method(strings(v, "method")?),
                "header" => {
                    let mut h = Vec::new();
                    for (k, v) in object(v, "header")? {
                        http::HeaderName::try_from(k)
                            .map_err(|_| anyhow::anyhow!("invalid matcher header name"))?;
                        h.push((
                            k.clone(),
                            if v.is_null() {
                                None
                            } else {
                                Some(strings(v, "header matcher")?)
                            },
                        ));
                    }
                    Matcher::Header(h)
                }
                "not" => Matcher::Not(parse_matcher_sets(Some(v), depth + 1)?),
                "remote_ip" | "client_ip" => {
                    let m = object(v, "IP matcher")?;
                    deny_unknown(m, &["ranges"], "IP matcher")?;
                    let ranges = parse_ranges(required(m, "ranges")?, "IP matcher")?;
                    if k == "remote_ip" {
                        Matcher::RemoteIp(ranges)
                    } else {
                        Matcher::ClientIp(ranges)
                    }
                }
                "protocol" => {
                    let s = string(v, "protocol")?;
                    ensure!(
                        matches!(
                            s.as_str(),
                            "http" | "https" | "grpc" | "http/1.0" | "http/1.1" | "http/2"
                        ),
                        "unsupported protocol matcher"
                    );
                    Matcher::Protocol(s)
                }
                "file" => {
                    let m = object(v, "file matcher")?;
                    deny_unknown(
                        m,
                        &["root", "try_files", "try_policy", "split_path"],
                        "file matcher",
                    )?;
                    let policy = m
                        .get("try_policy")
                        .map(|v| string(v, "try_policy"))
                        .transpose()?
                        .unwrap_or_default();
                    ensure!(
                        matches!(policy.as_str(), "" | "first_exist" | "first_exist_fallback"),
                        "unsupported file try policy"
                    );
                    Matcher::File {
                        root: m.get("root").map(|v| string(v, "file root")).transpose()?,
                        try_files: m
                            .get("try_files")
                            .map(|v| strings(v, "try_files"))
                            .transpose()?
                            .unwrap_or_else(|| vec!["{http.request.uri.path}".into()]),
                        split_path: m
                            .get("split_path")
                            .map(|v| strings(v, "file split_path"))
                            .transpose()?
                            .unwrap_or_default(),
                        fallback: policy == "first_exist_fallback",
                    }
                }
                _ => return Err(unsupported("/apps/http/servers/*/routes/*/match/module")),
            });
        }
        sets.push(set);
    }
    Ok(sets)
}
fn parse_handler(value: &Value, depth: usize, normalized: bool) -> Result<Handler> {
    let normalized_value = crate::module_json::inline(value, "handler", normalized)?;
    let value = normalized_value.as_ref();
    let path = "/apps/http/servers/*/routes/*/handle/*";
    let m = object(value, path)?;
    let handler = required(m, "handler")?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("handler ID required"))?;
    Ok(match handler {
        "static_response" => {
            deny_unknown(
                m,
                &["handler", "status_code", "body", "headers", "close"],
                path,
            )?;
            let status = m
                .get("status_code")
                .map(crate::module_json::weak_string)
                .transpose()?
                .unwrap_or_default();
            Handler::StaticResponse {
                status,
                body: m
                    .get("body")
                    .map(|v| string(v, path))
                    .transpose()?
                    .unwrap_or_default(),
                headers: HeaderOps {
                    set: m
                        .get("headers")
                        .map(|v| parse_header_values(v, path))
                        .transpose()?
                        .unwrap_or_default(),
                    ..Default::default()
                },
                close: boolean(m.get("close"), false, path)?,
            }
        }
        "headers" => {
            deny_unknown(m, &["handler", "request", "response"], path)?;
            let request = m
                .get("request")
                .map(|v| parse_header_ops(v, path, false))
                .transpose()?
                .unwrap_or_default();
            let (response, deferred) = if let Some(v) = m.get("response") {
                (
                    parse_header_ops(v, path, true)?,
                    boolean(object(v, path)?.get("deferred"), false, path)?,
                )
            } else {
                (HeaderOps::default(), false)
            };
            Handler::Headers {
                request,
                response,
                deferred,
            }
        }
        "subroute" => {
            deny_unknown(m, &["handler", "routes", "errors"], path)?;
            Handler::Subroute {
                errors_configured: m.contains_key("errors"),
                routes: parse_routes(m.get("routes"), depth + 1, true)?,
                errors: if let Some(v) = m.get("errors") {
                    let e = object(v, path)?;
                    deny_unknown(e, &["routes"], path)?;
                    parse_routes(e.get("routes"), depth + 1, true)?
                } else {
                    vec![]
                },
            }
        }
        "rewrite" => {
            deny_unknown(
                m,
                &[
                    "handler",
                    "uri",
                    "method",
                    "strip_path_prefix",
                    "strip_path_suffix",
                ],
                path,
            )?;
            Handler::Rewrite {
                uri: m.get("uri").map(|v| string(v, path)).transpose()?,
                method: m.get("method").map(|v| string(v, path)).transpose()?,
                strip_path_prefix: m
                    .get("strip_path_prefix")
                    .map(|v| string(v, path))
                    .transpose()?,
                strip_path_suffix: m
                    .get("strip_path_suffix")
                    .map(|v| string(v, path))
                    .transpose()?,
            }
        }
        "vars" => Handler::Vars(
            m.iter()
                .filter(|(k, _)| k.as_str() != "handler" && k.as_str() != "@id")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
        "map" => {
            deny_unknown(
                m,
                &["handler", "source", "destinations", "mappings", "defaults"],
                path,
            )?;
            let destinations = strings(required(m, "destinations")?, path)?
                .iter()
                .map(|s| {
                    ensure!(
                        s.starts_with('{')
                            && s.ends_with('}')
                            && s.matches('{').count() == 1
                            && s.matches('}').count() == 1
                            && s.len() > 2,
                        "map destination must be a placeholder"
                    );
                    Ok(s[1..s.len() - 1].to_owned())
                })
                .collect::<Result<Vec<_>>>()?;
            let mut mappings = Vec::new();
            if let Some(raw) = m.get("mappings") {
                for value in raw
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("map mappings array required"))?
                {
                    let entry = object(value, path)?;
                    deny_unknown(entry, &["input", "input_regexp", "outputs"], path)?;
                    ensure!(
                        !(entry
                            .get("input")
                            .map(|v| string(v, path))
                            .transpose()?
                            .is_some_and(|s| !s.is_empty())
                            && entry
                                .get("input_regexp")
                                .map(|v| string(v, path))
                                .transpose()?
                                .is_some_and(|s| !s.is_empty())),
                        "map input conflicts with regexp"
                    );
                    let outputs = required(entry, "outputs")?
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("map outputs array required"))?
                        .clone();
                    ensure!(
                        outputs.len() == destinations.len(),
                        "map output length mismatch"
                    );
                    mappings.push(MapEntry {
                        input: entry.get("input").map(|v| string(v, path)).transpose()?,
                        regex: entry
                            .get("input_regexp")
                            .map(|v| {
                                regex::Regex::new(
                                    v.as_str().ok_or_else(|| {
                                        anyhow::anyhow!("map regexp string required")
                                    })?,
                                )
                                .map_err(|_| anyhow::anyhow!("invalid map regexp"))
                            })
                            .transpose()?,
                        outputs,
                    });
                }
            }
            let mut literals = std::collections::HashSet::new();
            let mut expressions = std::collections::HashSet::new();
            for mapping in &mut mappings {
                if mapping
                    .regex
                    .as_ref()
                    .is_some_and(|r| r.as_str().is_empty())
                {
                    mapping.regex = None;
                }
                if let Some(regex) = &mapping.regex {
                    ensure!(
                        expressions.insert(regex.as_str().to_owned()),
                        "duplicate map regular expression"
                    );
                } else {
                    let input = mapping.input.clone().unwrap_or_default();
                    ensure!(literals.insert(input.clone()), "duplicate map literal");
                    mapping.input = Some(input);
                }
            }
            let defaults = m
                .get("defaults")
                .map(|v| strings(v, path))
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .map(Value::String)
                .collect::<Vec<_>>();
            ensure!(
                defaults.is_empty() || defaults.len() == destinations.len(),
                "map default length mismatch"
            );
            Handler::Map {
                source: string(required(m, "source")?, path)?,
                destinations,
                mappings,
                defaults,
            }
        }
        "authentication" => {
            deny_unknown(m, &["handler", "providers"], path)?;
            let providers = object(required(m, "providers")?, path)?;
            deny_unknown(providers, &["http_basic"], path)?;
            let basic = object(required(providers, "http_basic")?, path)?;
            deny_unknown(basic, &["accounts", "hash", "hash_cache", "realm"], path)?;
            if let Some(hash) = basic.get("hash") {
                let h = object(hash, path)?;
                deny_unknown(h, &["algorithm"], path)?;
                ensure!(
                    h.get("algorithm").and_then(Value::as_str) == Some("bcrypt"),
                    "unsupported authentication hash"
                );
            }
            let cache = match basic.get("hash_cache") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let cache_config =
                        object(value, "/authentication/providers/http_basic/hash_cache")?;
                    deny_unknown(
                        cache_config,
                        &[],
                        "/authentication/providers/http_basic/hash_cache",
                    )?;
                    Some(crate::http_runtime::auth_cache::AuthCache::new()?)
                }
            };
            let mut accounts = Vec::new();
            for value in required(basic, "accounts")?
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("auth accounts array required"))?
            {
                let a = object(value, path)?;
                deny_unknown(a, &["username", "password"], path)?;
                let password = string(required(a, "password")?, path)?;
                bcrypt::HashParts::from_str(&password)
                    .map_err(|_| anyhow::anyhow!("invalid bcrypt configuration hash"))?;
                accounts.push(Account {
                    username: string(required(a, "username")?, path)?,
                    password,
                });
            }
            ensure!(
                accounts.len() <= 4096,
                "authentication account limit exceeded"
            );
            Handler::Authentication {
                accounts,
                cache,
                realm: basic
                    .get("realm")
                    .map(|v| string(v, path))
                    .transpose()?
                    .unwrap_or_else(|| "restricted".into()),
            }
        }
        "file_server" => {
            deny_unknown(
                m,
                &["handler", "root", "hide", "index_names", "pass_thru"],
                path,
            )?;
            Handler::FileServer {
                root: m.get("root").map(|v| string(v, path)).transpose()?,
                hide: m
                    .get("hide")
                    .map(|v| strings(v, path))
                    .transpose()?
                    .unwrap_or_default(),
                index_names: m
                    .get("index_names")
                    .map(|v| strings(v, path))
                    .transpose()?
                    .unwrap_or_else(|| vec!["index.html".into(), "index.txt".into()]),
                pass_thru: boolean(m.get("pass_thru"), false, path)?,
            }
        }
        "reverse_proxy" => Handler::ReverseProxy(Box::new(parse_proxy(m, path)?)),
        _ => return Err(unsupported(path)),
    })
}
fn parse_header_values(value: &Value, path: &str) -> Result<Vec<(String, Vec<String>)>> {
    let mut values = Vec::new();
    for (name, v) in object(value, path)? {
        http::HeaderName::try_from(name)
            .map_err(|_| anyhow::anyhow!("invalid configured header name"))?;
        let vals = strings(v, path)?;
        for v in &vals {
            ensure!(
                !v.contains(['\r', '\n', '\0']),
                "invalid configured header value"
            );
        }
        values.push((name.clone(), vals));
    }
    Ok(values)
}
fn parse_header_ops(value: &Value, path: &str, response: bool) -> Result<HeaderOps> {
    let m = object(value, path)?;
    deny_unknown(
        m,
        if response {
            &["set", "add", "delete", "deferred"]
        } else {
            &["set", "add", "delete"]
        },
        path,
    )?;
    let delete = m
        .get("delete")
        .map(|v| strings(v, path))
        .transpose()?
        .unwrap_or_default();
    for name in &delete {
        ensure!(
            !name.contains(['\r', '\n', '\0']),
            "invalid configured header deletion"
        );
    }
    Ok(HeaderOps {
        set: m
            .get("set")
            .map(|v| parse_header_values(v, path))
            .transpose()?
            .unwrap_or_default(),
        add: m
            .get("add")
            .map(|v| parse_header_values(v, path))
            .transpose()?
            .unwrap_or_default(),
        delete,
    })
}
fn parse_proxy(m: &serde_json::Map<String, Value>, path: &str) -> Result<ProxyConfig> {
    let transport = m.get("transport").map(|v| object(v, path)).transpose()?;
    let is_fastcgi = transport
        .and_then(|t| t.get("protocol"))
        .and_then(Value::as_str)
        == Some("fastcgi");
    deny_unknown(
        m,
        &[
            "handler",
            "upstreams",
            "transport",
            "headers",
            "flush_interval",
            "stream_close_delay",
            "request_buffers",
        ],
        path,
    )?;
    let mut upstreams = Vec::new();
    for v in required(m, "upstreams")?
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("upstream array required"))?
    {
        let u = object(v, path)?;
        deny_unknown(u, &["dial"], path)?;
        let dial = string(required(u, "dial")?, path)?;
        ensure!(
            !dial.contains(['\r', '\n', '\0'])
                && (is_fastcgi || !dial.contains('/') && !dial.starts_with("unix")),
            "unsupported upstream dial address"
        );
        if is_fastcgi && let Some((network, address)) = dial.split_once('/') {
            ensure!(
                matches!(network, "tcp" | "tcp4" | "tcp6" | "unix") && !address.is_empty(),
                "unsupported FastCGI network address"
            );
        }
        upstreams.push(dial);
    }
    ensure!(
        !upstreams.is_empty() && upstreams.len() <= 4096,
        "upstream count invalid"
    );
    let fastcgi = if is_fastcgi {
        let t = transport.expect("FastCGI protocol requires a transport object");
        deny_unknown(
            t,
            &[
                "protocol",
                "root",
                "split_path",
                "resolve_root_symlink",
                "env",
                "dial_timeout",
                "read_timeout",
                "write_timeout",
                "capture_stderr",
            ],
            path,
        )?;
        let split_path = t
            .get("split_path")
            .map(|v| strings(v, path))
            .transpose()?
            .unwrap_or_default();
        ensure!(
            split_path.iter().all(|pattern| pattern.is_ascii()),
            "FastCGI split path must be ASCII"
        );
        let mut env = std::collections::BTreeMap::new();
        let mut env_size = 0usize;
        if let Some(value) = t.get("env") {
            for (key, value) in object(value, path)? {
                ensure!(
                    !key.is_empty() && !key.contains('\0'),
                    "invalid FastCGI environment key"
                );
                let value = string(value, path)?;
                env_size = env_size
                    .saturating_add(key.len())
                    .saturating_add(value.len());
                ensure!(
                    env_size <= 1024 * 1024 && env.len() < 4096,
                    "FastCGI environment budget exceeded"
                );
                env.insert(key.clone(), value);
            }
        }
        let request_buffer = m
            .get("request_buffers")
            .filter(|v| !v.is_null())
            .map(|v| {
                v.as_i64()
                    .ok_or_else(|| anyhow::anyhow!("invalid FastCGI request_buffers"))
            })
            .transpose()?
            .unwrap_or(0);
        ensure!(
            cfg!(unix),
            "FastCGI transport has not been validated on this platform"
        );
        ensure!(request_buffer >= -1, "invalid FastCGI request_buffers");
        Some(FastCgiConfig {
            root: t
                .get("root")
                .map(|v| string(v, path))
                .transpose()?
                .filter(|s| !s.is_empty()),
            split_path,
            resolve_root_symlink: boolean(t.get("resolve_root_symlink"), false, path)?,
            env,
            request_buffer: match request_buffer {
                -1 => None,
                0 => Some(4096),
                size => Some(size as u64),
            },
            explicit_request_buffer: request_buffer != 0,
            capture_stderr: boolean(t.get("capture_stderr"), false, path)?,
        })
    } else {
        ensure!(
            !m.contains_key("request_buffers"),
            "unsupported HTTP request_buffers"
        );
        None
    };
    let mut tls = None;
    let mut http2_only = false;
    let mut enable_http2 = true;
    let mut compression = true;
    let mut dial_timeout = Duration::from_secs(3);
    let mut response_header_timeout = None;
    let mut read_timeout = None;
    let mut write_timeout = None;
    if let Some(t) = transport {
        if !is_fastcgi {
            deny_unknown(
                t,
                &[
                    "protocol",
                    "tls",
                    "versions",
                    "compression",
                    "dial_timeout",
                    "response_header_timeout",
                    "read_timeout",
                    "write_timeout",
                ],
                path,
            )?;
            if let Some(protocol) = t.get("protocol") {
                ensure!(
                    string(protocol, path)? == "http",
                    "unsupported reverse proxy transport"
                );
            }
            if let Some(v) = t.get("tls") {
                let t = object(v, path)?;
                deny_unknown(
                    t,
                    &[
                        "server_name",
                        "insecure_skip_verify",
                        "root_ca_pem_files",
                        "root_ca_pool",
                        "client_certificate_file",
                        "client_certificate_key_file",
                        "handshake_timeout",
                    ],
                    path,
                )?;
                tls = Some(ProxyTls {
                    server_name: t.get("server_name").map(|v| string(v, path)).transpose()?,
                    insecure_skip_verify: boolean(t.get("insecure_skip_verify"), false, path)?,
                    root_ca_pool: t
                        .get("root_ca_pool")
                        .map(|v| strings(v, path))
                        .transpose()?
                        .unwrap_or_default(),
                    client_certificate_file: t
                        .get("client_certificate_file")
                        .map(|v| string(v, path))
                        .transpose()?
                        .filter(|v| !v.is_empty()),
                    client_certificate_key_file: t
                        .get("client_certificate_key_file")
                        .map(|v| string(v, path))
                        .transpose()?
                        .filter(|v| !v.is_empty()),
                    handshake_timeout: t
                        .get("handshake_timeout")
                        .map(|v| duration(v, path))
                        .transpose()?
                        .filter(|d| !d.is_zero()),
                    root_ca_pem_files: t
                        .get("root_ca_pem_files")
                        .map(|v| strings(v, path))
                        .transpose()?
                        .unwrap_or_default(),
                });
            }
            if let Some(v) = t.get("versions") {
                let versions = strings(v, path)?;
                ensure!(
                    versions
                        .iter()
                        .all(|v| matches!(v.as_str(), "1.1" | "2" | "h2c")),
                    "unsupported upstream HTTP version"
                );
                // Caddy's TLS transport still permits HTTP/1 fallback. Its h2c
                // switch affects plaintext requests only, even for ["h2c"].
                enable_http2 =
                    versions.is_empty() || versions.iter().any(|v| v == "2" || v == "h2c");
                http2_only = tls.is_none() && versions.iter().any(|v| v == "h2c");
            }
        }
        compression = !is_fastcgi && boolean(t.get("compression"), true, path)?;
        if let Some(v) = t.get("dial_timeout") {
            dial_timeout = duration(v, path)?;
            if dial_timeout.is_zero() {
                dial_timeout = Duration::from_secs(3);
            }
        }
        if let Some(v) = t.get("response_header_timeout") {
            let timeout = duration(v, path)?;
            if !timeout.is_zero() {
                return Err(unsupported(
                    "/reverse_proxy/transport/response_header_timeout/write_completion_gate",
                ));
            }
            response_header_timeout = Some(timeout);
        }
        read_timeout = t
            .get("read_timeout")
            .map(|v| duration(v, path))
            .transpose()?
            .filter(|d| !d.is_zero());
        write_timeout = t
            .get("write_timeout")
            .map(|v| duration(v, path))
            .transpose()?
            .filter(|d| !d.is_zero());
    }
    if m.get("flush_interval")
        .map(|v| signed_duration(v, path))
        .transpose()?
        .is_some_and(|v| v > 0)
    {
        return Err(unsupported("/reverse_proxy/flush_interval/positive"));
    }
    let mut request_headers = HeaderOps::default();
    let mut response_headers = HeaderOps::default();
    if let Some(v) = m.get("headers") {
        let h = object(v, path)?;
        deny_unknown(h, &["request", "response"], path)?;
        if let Some(v) = h.get("request") {
            request_headers = parse_header_ops(v, path, false)?;
        }
        if let Some(v) = h.get("response") {
            response_headers = parse_header_ops(v, path, false)?;
        }
    }
    Ok(ProxyConfig {
        upstreams,
        fastcgi,
        tls,
        http2_only,
        enable_http2,
        compression,
        dial_timeout,
        response_header_timeout,
        read_timeout,
        write_timeout,
        request_headers,
        response_headers,
        flush_interval: m
            .get("flush_interval")
            .map(|v| signed_duration(v, path))
            .transpose()?
            .unwrap_or(0),
        stream_close_delay: m
            .get("stream_close_delay")
            .map(|v| duration(v, path))
            .transpose()?,
    })
}
use std::str::FromStr;

fn pending_placeholders(value: &Value) -> Result<()> {
    pending_placeholders_depth(value, 0)
}
fn pending_placeholders_depth(value: &Value, depth: usize) -> Result<()> {
    ensure!(depth <= 128, "configuration nesting exceeds limit");
    match value {
        Value::String(s) => {
            let bytes = s.as_bytes();
            let mut close = None;
            for i in (0..bytes.len()).rev() {
                if bytes[i] == b'}' && (i == bytes.len() - 1 || i == 0 || bytes[i - 1] != b'\\') {
                    close = Some(i);
                }
                if bytes[i] == b'{'
                    && (i == 0 || bytes[i - 1] != b'\\')
                    && let Some(end) = close
                {
                    let key = &s[i + 1..end];
                    if key.starts_with("file.")
                        || key.starts_with("http.request.tls.")
                        || (key.starts_with("http.reverse_proxy.")
                            && !matches!(
                                key,
                                "http.reverse_proxy.upstream.address"
                                    | "http.reverse_proxy.upstream.hostport"
                                    | "http.reverse_proxy.upstream.host"
                                    | "http.reverse_proxy.upstream.port"
                            ))
                    {
                        return Err(helpers::unsupported("/placeholder/provider"));
                    }
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                pending_placeholders_depth(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if matches!(
                    key.as_str(),
                    "@id"
                        | "pattern"
                        | "input"
                        | "input_regexp"
                        | "password"
                        | "username"
                        | "realm"
                        | "tags"
                        | "destinations"
                ) {
                    continue;
                }
                if key == "outputs"
                    && values
                        .get("input_regexp")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty())
                {
                    continue;
                }
                pending_placeholders_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
