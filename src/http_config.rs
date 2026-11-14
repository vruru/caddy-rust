//! Strictly compiled HTTP configuration. Known but incomplete capabilities fail
//! before activation. The raw configuration may contain secrets; do not Debug it.
#[path = "http_config/listeners.rs"]
mod listeners;
pub(crate) use listeners::{ListenSpec,ListenIdentity,Family as ListenerFamily};
mod header_ops;
pub(crate) mod header_compile;
#[path = "http_config/helpers.rs"]
pub(crate) mod helpers;
#[path = "http_config/proxy_ext.rs"]
pub(crate) mod proxy_ext;
#[path = "http_config/types.rs"]
pub(crate) mod types;
#[path = "http_config/route_timeouts.rs"]
pub(crate) mod route_timeouts;
#[path = "http_config/server_transfers.rs"]
pub(crate) mod server_transfers;
use anyhow::{Result, ensure};
use helpers::*;
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use types::*;
#[path = "http_config/rewrite.rs"]
mod rewrite;

#[derive(Clone)]
pub struct PreparedConfig {
    pub(crate) metrics: Option<crate::metrics::config::Config>,
    pub(crate) events: Option<Arc<crate::events::EventsApp>>,
    pub(crate) http_port: u16,
    pub(crate) https_port: u16,
    pub(crate) explicit_tls_subjects: std::sync::Arc<crate::tls_app_config::ExplicitSubjects>,
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
#[path = "http_config/header_alias.rs"]
mod header_alias;
pub(crate) use header_alias::HeaderAliases;

#[derive(Clone)]
pub(crate) struct ServerConfig {
    pub(crate) name: Arc<str>,
    pub(crate) access_logs: Option<AccessLogConfig>,
    pub(crate) header_aliases: HeaderAliases,
    pub(crate) listener_stack:Arc<crate::http_runtime::listener_stack::Stack>,
    /// Original declarations are authoritative for ports and hostname identity.
    pub(crate) listen_specs: Vec<ListenSpec>,
    /// Numeric subset for provision-only validation; stage uses its sealed plan.
    pub(crate) listen: Vec<SocketAddr>,
    pub(crate) listen_v6_only: std::collections::HashSet<SocketAddr>,
    pub(crate) routes: Vec<Route>,
    pub(crate) named_routes: std::collections::BTreeMap<String, Route>,
    pub(crate) errors: Vec<Route>,
    pub(crate) tls: bool,
    pub(crate) redirect_before_tls: Option<i64>,
    pub(crate) redirect_after_tls: Option<i64>,
    pub(crate) strict_sni_host: bool,
    pub(crate) tls_policies: Vec<crate::tls_policy::ConnectionPolicy>,
    pub(crate) trusted_proxies: Vec<ipnet::IpNet>,
    pub(crate) trusted_strict: bool,
    pub(crate) client_ip_headers: Vec<String>,
    pub(crate) read_header_timeout: Option<Duration>,
    pub(crate) read_idle_timeout: Duration,
    pub(crate) transfers: server_transfers::ServerTransfers,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) protocols: Vec<String>,
    pub(crate) redirect_http: bool,
    pub(crate) manage_certificates: bool,
    pub(crate) skip_manage: Vec<String>,
    pub(crate) skip_redirect: Vec<String>,
    pub(crate) ignore_loaded_certificates: bool,
}
impl ServerConfig {
    pub(crate) fn request_head_limit(&self)->Option<Duration>{
        match(self.read_header_timeout,self.transfers.read_hard){
            (Some(a),Some(b))=>Some(a.min(b)),(a,b)=>a.or(b),
        }
    }
}
#[derive(Clone)]
pub(crate) struct AccessLogConfig {
    pub(crate) default_name: String,
    pub(crate) names: std::collections::BTreeMap<String, Vec<String>>,
    pub(crate) skip_hosts: Vec<String>,
    pub(crate) skip_unmapped: bool,
    pub(crate) credentials: bool,
    pub(crate) trace: bool,
}

fn access_logs(value: &Value, path: &str) -> Result<AccessLogConfig> {
    let map = object(value, path)?;
    deny_unknown(
        map,
        &[
            "default_logger_name",
            "logger_names",
            "skip_hosts",
            "skip_unmapped_hosts",
            "should_log_credentials",
            "trace",
        ],
        path,
    )?;
    let trace = boolean(map.get("trace"), false, path)?;
    let mut names = std::collections::BTreeMap::new();
    if let Some(value) = map.get("logger_names").filter(|value| !value.is_null()) {
        let map = object(value, path)?;
        ensure!(map.len() <= 8192, "too many access logger hosts");
        for (host, value) in map {
            let mapped = if let Some(value) = value.as_str() {
                vec![value.to_owned()]
            } else {
                strings(value, path)?
            };
            ensure!(
                mapped.len() <= 16 && mapped.iter().all(|name| name.len() <= 128),
                "too many or oversized access logger destinations"
            );
            let normalized = host.trim_end_matches('.').to_ascii_lowercase();
            ensure!(
                !names.contains_key(&normalized),
                "ambiguous access logger host"
            );
            names.insert(normalized, mapped);
        }
    }
    let default_name = map
        .get("default_logger_name")
        .filter(|value| !value.is_null())
        .map(|value| string(value, path))
        .transpose()?
        .unwrap_or_default();
    ensure!(
        default_name.len() <= 128,
        "oversized default access logger name"
    );
    Ok(AccessLogConfig {
        trace,
        default_name,
        names,
        skip_hosts: map
            .get("skip_hosts")
            .filter(|value| !value.is_null())
            .map(|value| strings(value, path))
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
            .collect(),
        skip_unmapped: boolean(map.get("skip_unmapped_hosts"), false, path)?,
        credentials: boolean(map.get("should_log_credentials"), false, path)?,
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
            "metrics",
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
    fn port(http:&serde_json::Map<String,Value>,field:&str,default:u16)->Result<u16>{
        let value=http.get(field).filter(|value|!value.is_null()).map(|value|value.as_number().and_then(serde_json::Number::as_go_i64).ok_or_else(||anyhow::anyhow!("integer HTTP application port required"))).transpose()?.unwrap_or(0);
        ensure!((0..=65535).contains(&value),"HTTP application port out of range");
        Ok(if value==0{default}else{value as u16})
    }
    let http_port=port(http,"http_port",80)?;
    let https_port=port(http,"https_port",443)?;
    let raw = object(
        http.get("servers")
            .ok_or_else(|| anyhow::anyhow!("servers required"))?,
        "/apps/http/servers",
    )?;
    ensure!(raw.len() <= 1024, "server count exceeded");
    let mut metrics = http.get("metrics").filter(|v|!v.is_null()).map(crate::metrics::config::Config::parse).transpose()?;
    // Merge deprecated per-server switches before provisioning every server.
    for value in raw.values() {
        if let Some(value)=value.get("metrics").filter(|v|!v.is_null()) {
            let legacy=crate::metrics::config::Config::parse(value)?;
            let current=metrics.get_or_insert_with(Default::default);current.merge(legacy);
        }
    }
    let mut servers = Vec::new();
    let mut compiled_tls_memory = 0usize;
    let mut regex_remaining = 64 << 20;
    let mut declared = std::collections::HashSet::new();
    for (name,value) in raw {
        let mut config = parse_server(value, &mut regex_remaining,http_port,https_port)?;
        config.name=Arc::from(if name.is_empty(){"UNKNOWN"}else{name.as_str()});
        compiled_tls_memory = compiled_tls_memory.saturating_add(
            config
                .tls_policies
                .iter()
                .map(|policy| policy.compiled_memory())
                .sum::<usize>(),
        );
        ensure!(
            compiled_tls_memory <= 64 << 20,
            "TLS regexp configuration memory budget exceeded"
        );
        for spec in &config.listen_specs {ensure!(declared.insert(spec.clone()),"duplicate listener declaration");}
        // Distinct declarations may intentionally share a physical TCP port.
        servers.push(Arc::new(config));
    }
    Ok(PreparedConfig {
        metrics,
        events: None,
        http_port,https_port,
        explicit_tls_subjects: Default::default(),
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
        if server.tls
            && server.manage_certificates
        {
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
fn parse_server(value: &Value, regex_remaining: &mut usize,http_port:u16,https_port:u16) -> Result<ServerConfig> {
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
            "strict_sni_host",
            "trusted_proxies",
            "trusted_proxies_strict",
            "client_ip_headers",
            "expected_underscore_headers",
            "expected_dot_headers",
            "read_header_timeout",
            "read_timeout",
            "write_timeout",
            "write_idle_timeout",
            "read_min_rate",
            "write_min_rate",
            "max_write_chunk",
            "read_idle_timeout",
            "idle_timeout",
            "logs",
            "named_routes",
            "metrics",
        ],
        path,
    )?;
    let access_logs = m
        .get("logs")
        .filter(|value| !value.is_null())
        .map(|value| access_logs(value, path))
        .transpose()?;
    let mut listen_specs = Vec::new();
    for raw in strings(required(m, "listen")?, path)? {
        let raw = helpers::replace(&raw, true, helpers::global_lookup)?;
        listeners::append_specs(&raw,&mut listen_specs)?;
    }
    ensure!(!listen_specs.is_empty()&&listen_specs.len()<=1024,"listener count invalid");
    let mut listen=Vec::new();let mut listen_v6_only=std::collections::HashSet::new();
    for spec in &listen_specs {if let Some((address,only_v6))=spec.numeric(){listen.push(address);if only_v6{listen_v6_only.insert(address);}}}
    let policies = m
        .get("tls_connection_policies")
        .filter(|value| !value.is_null());
    let tls_policies = crate::tls_policy::parse_policies(policies)?;
    let mut tls_wrapper = None;
    let mut redirects = Vec::new();
    let mut listener_operations=Vec::new();
    if let Some(wrappers) = m.get("listener_wrappers").filter(|v| !v.is_null()) {
        let wrappers = wrappers
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("listener wrappers array required"))?;
        ensure!(wrappers.len()<=64,"listener wrapper limit exceeded");
        for (index, value) in wrappers.iter().enumerate() {
            let normalized = crate::module_json::inline(value, "wrapper", false)?;
            let wrapper = object(&normalized, path)?;
            match wrapper.get("wrapper").and_then(Value::as_str) {
                Some("tls") => {
                    deny_unknown(wrapper, &["wrapper"], path)?;
                    // An explicit leading TLS marker has the same unambiguous
                    // meaning as the implicit marker; accepting it is useful.
                    ensure!(tls_wrapper.is_none(), "duplicate TLS listener wrapper");
                    tls_wrapper = Some(index);
                }
                Some("http_redirect") => {
                    deny_unknown(wrapper, &["wrapper", "max_header_bytes"], path)?;
                    let maximum = wrapper
                        .get("max_header_bytes")
                        .filter(|v| !v.is_null())
                        .map(|v| {
                            v.as_number()
                                .and_then(serde_json::Number::as_go_i64)
                                .ok_or_else(|| {
                                    anyhow::anyhow!("integer redirect header limit required")
                                })
                        })
                        .transpose()?
                        .unwrap_or(0);
                    redirects.push((index, maximum));
                    listener_operations.push((index,crate::http_runtime::listener_stack::Operation::Redirect(maximum)));
                }
                Some("proxy_protocol")=>{listener_operations.push((index,crate::http_runtime::listener_stack::Operation::Proxy(crate::proxy_protocol::Config::parse(&normalized,path)?)));}
                _ => return Err(unsupported("listener wrapper")),
            }
        }
    }
    // The original app inserts a leading TLS placeholder when none is explicit.
    // Repeated redirect wrappers first see identical five bytes at the innermost
    // wrapper, which either redirects or replays them for the outer layers.
    let redirect_before_tls = redirects
        .iter()
        .find(|(index, _)| tls_wrapper.is_some_and(|tls| *index < tls))
        .map(|(_, limit)| *limit);
    let redirect_after_tls = redirects
        .iter()
        .find(|(index, _)| tls_wrapper.is_none_or(|tls| *index > tls))
        .map(|(_, limit)| *limit);
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
    let routes = parse_routes(m.get("routes"), 0, false, regex_remaining)?;
    let inferred = !disabled
        && listen_specs.iter().any(|a| a.port() != http_port)
        && route_names(&routes)
            .iter()
            .any(|n| !skip_redirect.iter().any(|s| s.eq_ignore_ascii_case(n)));
    let tls = policies
        .and_then(Value::as_array)
        .is_some_and(|policies| !policies.is_empty())
        || (!disabled && listen_specs.iter().any(|a| a.port() == https_port))
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
        ensure!(
            matches!(protocol.as_str(), "h1" | "h2" | "h2c" | "h3"),
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
    let expected = |name: &str| {
        m.get(name)
            .filter(|value| !value.is_null())
            .map(|value| strings(value, path))
            .transpose()
            .map(Option::unwrap_or_default)
    };
    let header_aliases = HeaderAliases::provision(
        expected("expected_underscore_headers")?,
        expected("expected_dot_headers")?,
    )?;
    Ok(ServerConfig {
        listener_stack:Arc::new(crate::http_runtime::listener_stack::Stack::ordered(listener_operations,tls_wrapper)),
        name: Arc::from("UNKNOWN"),
        access_logs,
        header_aliases,
        listen_specs,
        listen,
        listen_v6_only,
        routes,
        named_routes: m
            .get("named_routes")
            .filter(|value| !value.is_null())
            .map(|value| {
                let named = object(value, "/apps/http/servers/*/named_routes")?;
                ensure!(named.len() <= 65536, "named route count limit exceeded");
                named
                    .iter()
                    .map(|(name, value)| {
                        Ok((name.clone(), parse_route(value, 0, false, regex_remaining)?))
                    })
                    .collect::<Result<_>>()
            })
            .transpose()?
            .unwrap_or_default(),
        errors: if let Some(v) = m.get("errors") {
            let e = object(v, path)?;
            deny_unknown(e, &["routes"], path)?;
            parse_routes(e.get("routes"), 1, false, regex_remaining)?
        } else {
            vec![]
        },
        tls,
        redirect_before_tls,
        redirect_after_tls,
        strict_sni_host: boolean(
            m.get("strict_sni_host"),
            tls_policies.iter().any(|policy| {
                policy
                    .client_auth
                    .as_ref()
                    .is_some_and(|auth| auth.is_active())
            }),
            path,
        )?,
        tls_policies,
        trusted_proxies,
        trusted_strict,
        client_ip_headers: m
            .get("client_ip_headers")
            .map(|v| strings(v, path))
            .transpose()?
            .unwrap_or_else(|| vec!["X-Forwarded-For".into()]),
        transfers: server_transfers::parse(m,path)?,
        read_header_timeout: match m
            .get("read_header_timeout")
            .filter(|v| !v.is_null())
            .map(|v| signed_duration(v, path))
            .transpose()?
        {
            None | Some(0) => Some(Duration::from_secs(60)),
            Some(nanos) if nanos > 0 => Some(Duration::from_nanos(nanos as u64)),
            Some(_) => None,
        },
        idle_timeout: match m.get("idle_timeout").map(|v| signed_duration(v, path)).transpose()? {
            None | Some(0) => Some(Duration::from_secs(300)),
            Some(nanos) if nanos > 0 => Some(Duration::from_nanos(nanos as u64)),
            Some(_) => None,
        },
        read_idle_timeout: match m
            .get("read_idle_timeout")
            .map(|v| signed_duration(v, path))
            .transpose()?
        {
            None | Some(0) => Duration::from_secs(60),
            Some(nanos) if nanos > 0 => Duration::from_nanos(nanos as u64),
            Some(_) => Duration::ZERO,
        },
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
fn parse_routes(
    value: Option<&Value>,
    depth: usize,
    normalized: bool,
    regex_remaining: &mut usize,
) -> Result<Vec<Route>> {
    ensure!(depth < 64, "route nesting limit exceeded");
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let raw = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("route array required"))?;
    ensure!(raw.len() <= 65536, "route count limit exceeded");
    raw.iter()
        .map(|value| parse_route(value, depth, normalized, regex_remaining))
        .collect()
}

fn parse_route(
    value: &Value,
    depth: usize,
    normalized: bool,
    regex_remaining: &mut usize,
) -> Result<Route> {
    let path = "/apps/http/servers/*/routes/*";
    let m = object(value, path)?;
    deny_unknown(m, &["group", "match", "handle", "terminal"], path)?;
    let handlers: Vec<_> = m
        .get("handle")
        .map(|values| {
            values
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("handler array required"))?
                .iter()
                .map(|value| {
                    let raw=crate::module_json::inline(value,"handler",normalized)?;
                    let handler=parse_handler(raw.as_ref(),depth+1,true,regex_remaining)?;
                    let trace=crate::http_runtime::handler_trace::Module::prepare(raw.as_ref(),&handler,true)?;
                    Ok((handler,trace))
                })
                .collect::<Result<_>>()
        })
        .transpose()?
        .unwrap_or_default();
    let (handlers, trace_modules)=handlers.into_iter().unzip();
    Ok(Route {
        metrics: depth==0,
        trace_modules,
        group: m.get("group").map(|v| string(v, path)).transpose()?,
        matchers: parse_matcher_sets(m.get("match"), depth + 1, regex_remaining)?,
        handlers,
        terminal: boolean(m.get("terminal"), false, path)?,
    })
}
fn parse_request_regexp(value: &Value, remaining: &mut usize) -> Result<RequestRegex> {
    let fields = object(value, "request regexp")?;
    deny_unknown(fields, &["name", "pattern"], "request regexp")?;
    let name = optional_handler_string(fields, "name", "request regexp name")?;
    ensure!(
        name.len() <= 256
            && (name.is_empty() || name.bytes().any(|b| b == b'_' || b.is_ascii_alphanumeric())),
        "invalid request regexp name"
    );
    let pattern = optional_handler_string(fields, "pattern", "request regexp pattern")?;
    let regex = crate::go_regexp::GoRegexp::compile(&pattern, (*remaining).min(2 << 20))?;
    *remaining -= regex.memory_usage();
    Ok(RequestRegex {
        name: Arc::from(name),
        regex: Arc::new(regex),
    })
}

pub(crate) fn parse_matcher_sets(
    value: Option<&Value>,
    depth: usize,
    regex_remaining: &mut usize,
) -> Result<Vec<MatcherSet>> {
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
                "expression" => Matcher::Expression(Arc::new(crate::http_runtime::cel_matcher::Plan::prepare(v, regex_remaining)?)),
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
                    Matcher::Path(patterns.iter().map(|s|crate::http_runtime::path_match::lower(s.as_bytes())).collect())
                }
                "path_regexp" => Matcher::PathRegex(parse_request_regexp(v, regex_remaining)?),
                "header_regexp" => Matcher::HeaderRegex(
                    object(v, "header_regexp")?
                        .iter()
                        .map(|(name, value)| {
                            Ok((
                                http::HeaderName::try_from(name)?,
                                parse_request_regexp(value, regex_remaining)?,
                            ))
                        })
                        .collect::<Result<_>>()?,
                ),
                "vars_regexp" => Matcher::VarsRegex(
                    object(v, "vars_regexp")?
                        .iter()
                        .map(|(name, value)| {
                            Ok((name.clone(), parse_request_regexp(value, regex_remaining)?))
                        })
                        .collect::<Result<_>>()?,
                ),
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
                "query" | "vars" => {
                    let values = v.as_object().filter(|_| !v.is_null());
                    ensure!(
                        values.is_some() || v.is_null(),
                        "query/vars matcher object required"
                    );
                    let mut rules = Vec::new();
                    for (key, value) in values.into_iter().flatten() {
                        let values = if value.is_null() {
                            Vec::new()
                        } else {
                            strings(value, k)?
                        };
                        rules.push((key.clone(), values));
                    }
                    if k == "query" {
                        Matcher::Query(rules)
                    } else {
                        Matcher::Vars(rules)
                    }
                }
                "url_pattern" => {
                    let fields = object(v, "URLPattern matcher")?;
                    deny_unknown(
                        fields,
                        &["pattern", "base_url", "ignore_case"],
                        "URLPattern matcher",
                    )?;
                    let pattern = optional_handler_string(fields, "pattern", "URLPattern pattern")?;
                    let base = optional_handler_string(fields, "base_url", "URLPattern base URL")?;
                    let ignore_case = boolean(
                        fields.get("ignore_case").filter(|v| !v.is_null()),
                        false,
                        "URLPattern ignore_case",
                    )?;
                    Matcher::UrlPattern(crate::http_runtime::url_pattern::Plan::prepare(
                        &pattern,
                        &base,
                        ignore_case,
                        regex_remaining,
                    )?)
                }
                "tls" => {
                    let fields = object(v, "tls matcher")?;
                    deny_unknown(fields, &["handshake_complete"], "tls matcher")?;
                    let complete = fields
                        .get("handshake_complete")
                        .filter(|v| !v.is_null())
                        .map(|v| boolean(Some(v), false, "TLS handshake_complete"))
                        .transpose()?;
                    Matcher::Tls(complete)
                }
                "not" => Matcher::Not(parse_matcher_sets(Some(v), depth + 1, regex_remaining)?),
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
                            "http"
                                | "https"
                                | "grpc"
                                | "http/1.0"
                                | "http/1.0+"
                                | "http/1.1"
                                | "http/1.1+"
                                | "http/2"
                                | "http/2+"
                                | "http/3"
                                | "http/3+"
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
                    let policy = match policy.as_str() {
                        "" | "first_exist" => FileMatchPolicy::First,
                        "first_exist_fallback" => FileMatchPolicy::Fallback,
                        "largest_size" => FileMatchPolicy::Largest,
                        "smallest_size" => FileMatchPolicy::Smallest,
                        "most_recently_modified" => FileMatchPolicy::Newest,
                        _ => return Err(unsupported("/match/file/try_policy")),
                    };
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
                        policy,
                    }
                }
                _ => return Err(unsupported("/apps/http/servers/*/routes/*/match/module")),
            });
        }
        sets.push(set);
    }
    Ok(sets)
}
fn optional_handler_string(
    m: &serde_json::Map<String, Value>,
    name: &str,
    path: &str,
) -> Result<String> {
    m.get(name)
        .filter(|value| !value.is_null())
        .map(|value| string(value, path))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn parse_handler(
    value: &Value,
    depth: usize,
    normalized: bool,
    regex_remaining: &mut usize,
) -> Result<Handler> {
    let normalized_value = crate::module_json::inline(value, "handler", normalized)?;
    let value = normalized_value.as_ref();
    let path = "/apps/http/servers/*/routes/*/handle/*";
    let m = object(value, path)?;
    let handler = required(m, "handler")?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("handler ID required"))?;
    Ok(match handler {
        "acme_server" => Handler::AcmeServer(std::sync::Arc::new(crate::acme_server::parse(value)?)),
        "error" => {
            deny_unknown(m, &["handler", "status_code", "error"], path)?;
            Handler::StaticError {
                status: m
                    .get("status_code")
                    .map(crate::module_json::weak_string)
                    .transpose()?
                    .unwrap_or_default(),
                message: optional_handler_string(m, "error", path)?,
            }
        }
        "invoke" => {
            deny_unknown(m, &["handler", "name"], path)?;
            Handler::Invoke(optional_handler_string(m, "name", path)?)
        }
        "log_append" => {
            deny_unknown(m, &["handler", "key", "value", "early"], path)?;
            Handler::LogAppend(std::sync::Arc::new(LogAppendConfig {
                key: optional_handler_string(m, "key", path)?,
                value: optional_handler_string(m, "value", path)?,
                early: boolean(m.get("early").filter(|value| !value.is_null()), false, path)?,
            }))
        }
        "push"=>{
            deny_unknown(m,&["handler","resources","headers"],path)?;
            let mut resources=Vec::new();
            if let Some(value)=m.get("resources").filter(|v|!v.is_null()){
                for (index,value)in value.as_array().ok_or_else(||anyhow::anyhow!("push resources array required at {path}"))?.iter().enumerate(){
                    let rp=format!("{path}/resources/{index}");let resource=object(value,&rp)?;deny_unknown(resource,&["method","target"],&rp)?;
                    resources.push(PushResource{method:optional_handler_string(resource,"method",&rp)?,target:optional_handler_string(resource,"target",&rp)?});
                }
            }
            let headers=m.get("headers").filter(|v|!v.is_null()).map(|v|parse_header_ops(v,path,false,regex_remaining)).transpose()?.unwrap_or_default();
            Handler::Push(std::sync::Arc::new(PushConfig{resources,headers}))
        }
        "tracing" => Handler::Tracing(std::sync::Arc::new(crate::metrics::distributed_trace::config::Config::parse(value)?)),
        "metrics" => {
            deny_unknown(m, &["handler","disable_openmetrics"], path)?;
            Handler::Metrics { disable_openmetrics: boolean(m.get("disable_openmetrics").filter(|v| !v.is_null()),false,path)? }
        }
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
        "request_body" => {
            let mut config = RequestBodyConfig {
                max_size: 0,
                set: String::new(),
            };
            // Go encoding/json accepts folded aliases for typed struct fields.
            // Inline module normalization already put keys in Go encoding order.
            for (name, value) in m {
                let field = |expected: &str| {
                    name.chars()
                        .map(|ch| match ch {
                            '\u{017f}' => 's',
                            _ => ch.to_ascii_lowercase(),
                        })
                        .eq(expected.chars())
                };
                if matches!(name.as_str(), "handler" | "@id") {
                    continue;
                }
                if field("max_size") {
                    if !value.is_null() {
                        config.max_size = value
                            .as_number()
                            .and_then(serde_json::Number::as_go_i64)
                            .ok_or_else(|| {
                                anyhow::anyhow!("request_body max_size requires a signed integer")
                            })?;
                    }
                } else if field("set") {
                    if !value.is_null() {
                        config.set = string(value, path)?;
                    }
                } else {
                    return Err(anyhow::anyhow!("unknown request_body configuration field"));
                }
            }
            Handler::RequestBody(config)
        }
        "templates" => {
            deny_unknown(m,&["handler","file_root","mime_types","delimiters","match"],path)?;
            if let Some(extensions)=m.get("match"){ensure!(extensions.is_null() || object(extensions,path)?.is_empty(),"unsupported template extension module");}
            let root=m.get("file_root").filter(|v|!v.is_null()).map(|v|string(v,path)).transpose()?.filter(|root|!root.is_empty()).unwrap_or_else(||"{http.vars.root}".into());
            let mime_types=m.get("mime_types").filter(|v|!v.is_null()).map(|v|strings(v,path)).transpose()?.unwrap_or_else(||vec!["text/html".into(),"text/plain".into(),"text/markdown".into()]);
            let delimiters=m.get("delimiters").filter(|v|!v.is_null()).map(|v|strings(v,path)).transpose()?.filter(|v|!v.is_empty()).unwrap_or_else(||vec!["{{".into(),"}}".into()]);
            ensure!(delimiters.len()==2,"templates delimiters requires exactly two strings");
            crate::http_runtime::templates::prepare_metadata()?;
            Handler::Templates(std::sync::Arc::new(crate::http_runtime::templates::TemplatePlan{root,mime_types,delimiters:[if delimiters[0].is_empty(){"{{".into()}else{delimiters[0].clone()},if delimiters[1].is_empty(){"}}".into()}else{delimiters[1].clone()}]}))
        }
        "timeouts" => Handler::Timeouts(route_timeouts::parse(value,path)?),
        "encode" => Handler::Encode(std::sync::Arc::new(parse_encode(m, path)?)),
        "headers" => {
            deny_unknown(m, &["handler", "request", "response"], path)?;
            let request = m
                .get("request")
                .filter(|v|!v.is_null())
                .map(|v| parse_header_ops(v, path, false,regex_remaining))
                .transpose()?
                .unwrap_or_default();
            let (response, deferred) = if let Some(v) = m.get("response").filter(|v|!v.is_null()) {
                (
                    parse_header_ops(v, path, true,regex_remaining)?,
                    boolean(object(v, path)?.get("deferred").filter(|v|!v.is_null()), false, path)?,
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
                routes: parse_routes(m.get("routes"), depth + 1, true, regex_remaining)?,
                errors: if let Some(v) = m.get("errors") {
                    let e = object(v, path)?;
                    deny_unknown(e, &["routes"], path)?;
                    parse_routes(e.get("routes"), depth + 1, true, regex_remaining)?
                } else {
                    vec![]
                },
            }
        }
        "rewrite" => Handler::Rewrite(Arc::new(rewrite::parse(m,path,regex_remaining,true)?)),
        "vars" => Handler::Vars(
            m.iter()
                .filter(|(k, _)| k.as_str() != "handler" && k.as_str() != "@id")
                .map(|(k, v)| (k.clone(), std::sync::Arc::new(v.clone())))
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
                        pattern: entry.get("input_regexp").filter(|v|!v.is_null()).map(|v|string(v,path)).transpose()?,
                        regex: entry.get("input_regexp").filter(|v|!v.is_null()).map(|v|{
                            let pattern=v.as_str().ok_or_else(||anyhow::anyhow!("map regexp string required"))?;
                            if pattern.is_empty(){Ok(None)}else{header_compile::compile_map_static(pattern,regex_remaining).map(Some)}
                        }).transpose()?.flatten(),
                        outputs,
                    });
                }
            }
            let mut literals = std::collections::HashSet::new();
            let mut expressions = std::collections::HashSet::new();
            for mapping in &mut mappings {
                if let Some(pattern) = mapping.pattern.as_ref().filter(|p|!p.is_empty()) {
                    ensure!(expressions.insert(pattern.clone()), "duplicate map regular expression");
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
            Handler::Map(Arc::new(MapPlan {
                source: string(required(m, "source")?, path)?.into(),
                destinations: destinations.into(),
                mappings: mappings.into(),
                defaults: defaults.into(),
            }))
        }
        "authentication" => {
            deny_unknown(m, &["handler", "providers"], path)?;
            let providers = object(required(m, "providers")?, path)?;
            deny_unknown(providers, &["http_basic"], path)?;
            let basic = object(required(providers, "http_basic")?, path)?;
            deny_unknown(basic, &["accounts", "hash", "hash_cache", "realm"], path)?;
            let algorithm = if let Some(hash) = basic.get("hash").filter(|v| !v.is_null()) {
                let h=object(hash,path)?;deny_unknown(h,&["algorithm"],path)?;
                match h.get("algorithm").and_then(Value::as_str){
                    Some("bcrypt")=>crate::http_runtime::auth_hash::Algorithm::Bcrypt,
                    Some("argon2id")=>crate::http_runtime::auth_hash::Algorithm::Argon2id,
                    _=>return Err(anyhow::anyhow!("unsupported authentication hash")),
                }
            }else{crate::http_runtime::auth_hash::Algorithm::Bcrypt};
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
            let mut usernames=std::collections::BTreeSet::new();
            for value in required(basic,"accounts")?.as_array().ok_or_else(||anyhow::anyhow!("auth accounts array required"))? {
                let a=object(value,path)?;deny_unknown(a,&["username","password"],path)?;
                let username=helpers::replace(&string(required(a,"username")?,path)?,false,helpers::global_lookup)?;
                let mut password=helpers::replace(&string(required(a,"password")?,path)?,false,helpers::global_lookup)?;
                ensure!(!username.is_empty()&&!password.is_empty(),"authentication username/password required");
                ensure!(usernames.insert(username.clone()),"duplicate authentication username");
                if !password.starts_with('$'){
                    use base64::Engine;
                    let engine=base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD,base64::engine::general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true));
                    let clean=password.bytes().filter(|b| !matches!(b,b'\r'|b'\n')).collect::<Vec<_>>();
                    password=String::from_utf8(engine.decode(clean).map_err(|_|anyhow::anyhow!("invalid encoded authentication hash"))?).map_err(|_|anyhow::anyhow!("invalid authentication hash text"))?;
                }
                algorithm.validate(&password).map_err(|_|anyhow::anyhow!("invalid or resource-exceeding authentication hash"))?;
                accounts.push(Account{username,password});
            }
            ensure!(
                accounts.len() <= 4096,
                "authentication account limit exceeded"
            );
            Handler::Authentication {
                algorithm,
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
                &[
                    "handler",
                    "status_code",
                    "root",
                    "hide",
                    "index_names",
                    "pass_thru",
                    "canonical_uris",
                    "precompressed",
                    "precompressed_order",
                    "etag_file_extensions",
                    "browse",
                ],
                path,
            )?;
            Handler::FileServer {
                status: m.get("status_code").map(crate::module_json::weak_string).transpose()?.unwrap_or_default(),
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
                canonical_uris: boolean(
                    m.get("canonical_uris").filter(|v| !v.is_null()),
                    true,
                    path,
                )?,
                sidecars: parse_file_sidecars(m, path)?,
                browse: m
                    .get("browse")
                    .filter(|v| !v.is_null())
                    .map(|value| {
                        let fields = object(value, "file_server browse")?;
                        deny_unknown(
                            fields,
                            &["template_file", "reveal_symlinks", "sort", "file_limit"],
                            "browse",
                        )?;
                        let template = optional_handler_string(
                            fields,
                            "template_file",
                            "browse template file",
                        )?;

                        let limit = fields
                            .get("file_limit")
                            .filter(|v| !v.is_null())
                            .map(|v| {
                                v.as_number().and_then(|n| n.as_go_i64()).ok_or_else(|| {
                                    anyhow::anyhow!("browse file_limit must be an integer")
                                })
                            })
                            .transpose()?
                            .unwrap_or_default();
                        ensure!(
                            limit <= 100_000,
                            "browse file_limit exceeds the native maximum"
                        );
                        Ok::<_, anyhow::Error>(crate::http_runtime::browse::BrowsePlan {
                            template_file: template,
                            file_limit: limit,
                            reveal_symlinks: boolean(
                                fields.get("reveal_symlinks").filter(|v| !v.is_null()),
                                false,
                                "browse reveal_symlinks",
                            )?,
                            sort: fields
                                .get("sort")
                                .filter(|v| !v.is_null())
                                .map(|v| strings(v, "browse sort"))
                                .transpose()?
                                .unwrap_or_default(),
                        })
                    })
                    .transpose()?,
            }
        }
        "intercept" => {
            deny_unknown(m, &["handler", "handle_response"], path)?;
            Handler::Intercept(parse_response_routes(
                m.get("handle_response"),
                depth,
                regex_remaining,
            )?)
        }
        "copy_response" => {
            deny_unknown(m, &["handler", "status_code"], path)?;
            Handler::CopyResponse(
                m.get("status_code")
                    .map(crate::module_json::weak_string)
                    .transpose()?
                    .unwrap_or_default(),
            )
        }
        "copy_response_headers" => {
            deny_unknown(m, &["handler", "include", "exclude"], path)?;
            let include = parse_response_header_filter(m.get("include"), path)?;
            let exclude = parse_response_header_filter(m.get("exclude"), path)?;
            ensure!(
                include.is_empty() || exclude.is_empty(),
                "cannot define both include and exclude"
            );
            Handler::CopyResponseHeaders(ResponseHeaderFilter { include, exclude })
        }
        "reverse_proxy" => {
            Handler::ReverseProxy(Box::new(parse_proxy(m, path, depth, regex_remaining)?))
        }
        _ => return Err(unsupported(path)),
    })
}

fn parse_response_header_filter(
    value: Option<&Value>,
    path: &str,
) -> Result<std::collections::HashSet<String>> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(Default::default());
    };
    value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{path}: expected header filter list"))?
        .iter()
        .map(|entry| {
            if entry.is_null() {
                Ok(String::new())
            } else {
                Ok(string(entry, path)?.to_ascii_lowercase())
            }
        })
        .collect()
}

fn parse_response_routes(
    value: Option<&Value>,
    depth: usize,
    regex_remaining: &mut usize,
) -> Result<Vec<ResponseRoute>> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let path = "/apps/http/servers/*/routes/*/handle/*/handle_response";
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{path}: expected response route list"))?;
    ensure!(
        entries.len() <= 65536,
        "response route count limit exceeded"
    );
    entries
        .iter()
        .map(|entry| {
            if entry.is_null() {
                return Ok(ResponseRoute::default());
            }
            let obj = object(entry, path)?;
            deny_unknown(obj, &["match", "status_code", "routes"], path)?;
            Ok(ResponseRoute {
                matcher: obj
                    .get("match")
                    .filter(|v| !v.is_null())
                    .map(|v| parse_response_matcher(v, path))
                    .transpose()?,
                status: obj
                    .get("status_code")
                    .map(crate::module_json::weak_string)
                    .transpose()?
                    .unwrap_or_default(),
                routes: obj
                    .get("routes")
                    .filter(|v| !v.is_null())
                    .map(|v| parse_routes(Some(v), depth + 1, true, regex_remaining))
                    .transpose()?,
            })
        })
        .collect()
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
fn parse_response_matcher(value: &Value, path: &str) -> Result<ResponseMatcher> {
    let obj = object(value, path)?;
    deny_unknown(obj, &["status_code", "headers"], path)?;

    let status_codes = if let Some(v) = obj.get("status_code") {
        if v.is_null() {
            None
        } else {
            let arr = v
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("{}: expected array for status_code", path))?;
            let mut codes = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let code = if item.is_null() {
                    0
                } else {
                    item.as_number()
                        .and_then(serde_json::Number::as_go_i64)
                        .ok_or_else(|| {
                            anyhow::anyhow!("{}: status_code[{}]: expected integer", path, i)
                        })?
                };
                codes.push(code);
            }
            Some(codes)
        }
    } else {
        None
    };

    let mut headers = Vec::new();
    if let Some(v) = obj.get("headers")
        && !v.is_null()
    {
        let headers_obj = v
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{}: headers: expected object", path))?;
        for (key, val) in headers_obj.iter() {
            let header_value = if val.is_null() {
                None
            } else {
                let arr = val
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("{}: headers: expected array for key", path))?;
                let mut strs = Vec::with_capacity(arr.len());
                for (i, item) in arr.iter().enumerate() {
                    let s = if item.is_null() {
                        ""
                    } else {
                        item.as_str().ok_or_else(|| {
                            anyhow::anyhow!("{}: headers: expected string at index {}", path, i)
                        })?
                    };
                    strs.push(s.to_string());
                }
                Some(strs)
            };

            headers.push((key.clone(), header_value));
        }
    }

    Ok(ResponseMatcher {
        status_codes,
        headers,
    })
}

fn parse_header_ops(value:&Value,path:&str,response:bool,remaining:&mut usize)->Result<HeaderOps>{header_ops::parse(value,path,response,remaining)}

fn parse_proxy(
    m: &serde_json::Map<String, Value>,
    path: &str,
    depth: usize,
    regex_remaining: &mut usize,
) -> Result<ProxyConfig> {
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
            "load_balancing",
            "handle_response",
            "health_checks",
            "dynamic_upstreams",
            "rewrite",
        ],
        path,
    )?;
    let ext = Arc::new(proxy_ext::parse(m, path, regex_remaining)?);
    let mut upstreams = Vec::new();
    let empty = Vec::new();
    let configured_upstreams = match m.get("upstreams").filter(|v| !v.is_null()) {
        Some(value) => value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("upstream array required"))?,
        None => &empty,
    };
    for v in configured_upstreams {
        let u = object(v, path)?;
        deny_unknown(u, &["dial", "max_requests"], path)?;
        let dial = string(required(u, "dial")?, path)?;
        ensure!(
            !dial.contains(['\r', '\n', '\0'])
                && (is_fastcgi
                    || dial
                        .split_once('/')
                        .is_none_or(|(network, address)| matches!(
                            network,
                            "tcp" | "tcp4" | "tcp6" | "unix"
                        ) && !address.is_empty())),
            "unsupported upstream dial address"
        );
        if is_fastcgi && let Some((network, address)) = dial.split_once('/') {
            ensure!(
                matches!(network, "tcp" | "tcp4" | "tcp6" | "unix") && !address.is_empty(),
                "unsupported FastCGI network address"
            );
        }
        let max_requests = typed_proxy_int(u.get("max_requests"))?;
        upstreams.push(crate::http_runtime::proxy_policy::Upstream { dial, max_requests });
    }
    ensure!(
        (!upstreams.is_empty() || ext.dynamic.is_some()) && upstreams.len() <= 4096,
        "upstream count invalid"
    );
    let load_balancing = m.get("load_balancing").filter(|v| !v.is_null());
    let selection = if let Some(value) = load_balancing {
        let lb = object(value, path)?;
        deny_unknown(
            lb,
            &[
                "selection_policy",
                "retries",
                "try_duration",
                "try_interval",
                "retry_match",
            ],
            path,
        )?;
        parse_selector(
            lb.get("selection_policy"),
            path,
            if ext.dynamic.is_some() {
                0
            } else {
                upstreams.len()
            },
            0,
        )?
    } else {
        crate::http_runtime::proxy_policy::Selection::Random
    };
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
                        "renegotiation",
                        "curves",
                        "insecure_skip_verify",
                        "root_ca_pem_files",
                        "root_ca_pool",
                        "ca",
                        "except_ports",
                        "client_certificate_file",
                        "client_certificate_key_file",
                        "client_certificate_automate",
                        "handshake_timeout",
                    ],
                    path,
                )?;
                let ca = t.get("ca").filter(|v|!v.is_null()).cloned();
                if let Some(ca)=&ca {object(ca,path)?;}
                if ca.is_some() {
                    ensure!(t.get("root_ca_pool").map(|v|strings(v,path)).transpose()?.is_none_or(|v|v.is_empty())
                        && t.get("root_ca_pem_files").map(|v|strings(v,path)).transpose()?.is_none_or(|v|v.is_empty()),
                        "conflicting upstream Root CA pool configuration");
                }
                let renegotiation=t.get("renegotiation").filter(|v|!v.is_null()).map(|v|string(v,path)).transpose()?.unwrap_or_default();
                let renegotiation=native_ssl_tls::Renegotiation::parse(&renegotiation).map_err(anyhow::Error::msg)?;
                tls = Some(ProxyTls {
                    renegotiation,
                    ca,
                    curves: t.get("curves").filter(|v|!v.is_null()).map(|v|strings(v,path)).transpose()?.unwrap_or_default(),
                    except_ports: t
                        .get("except_ports")
                        .map(|v| strings(v, path))
                        .transpose()?
                        .unwrap_or_default(),
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
                    client_certificate_automate:t.get("client_certificate_automate").filter(|v|!v.is_null()).map(|v|string(v,path)).transpose()?.filter(|v|!v.is_empty()),
                    managed_client:None,
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
            let nanos = signed_duration(v, path)?;
            // A negative value is disabled by HTTP/1, and already expired
            // when HTTP/2 finishes sending. Keep its sign until the writer reports.
            response_header_timeout = (nanos != 0).then_some(nanos);
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
    let mut request_headers = HeaderOps::default();
    let mut response_headers = HeaderOps::default();
    if let Some(v) = m.get("headers") {
        let h = object(v, path)?;
        deny_unknown(h, &["request", "response"], path)?;
        if let Some(v) = h.get("request").filter(|v|!v.is_null()) {
            request_headers = parse_header_ops(v, path, false,regex_remaining)?;
        }
        if let Some(v) = h.get("response").filter(|v|!v.is_null()) {
            response_headers = parse_header_ops(v, path, true,regex_remaining)?;
            // Proxy headers are applied on the received upstream response;
            // its deferred flag does not wrap a downstream writer in Caddy.
            boolean(object(v, path)?.get("deferred").filter(|v|!v.is_null()), false, path)?;
        }
    }
    Ok(ProxyConfig {
        rewrite: m.get("rewrite").filter(|v|!v.is_null()).map(|v|rewrite::parse(object(v,path)?,path,regex_remaining,false).map(Arc::new)).transpose()?,
        ext,
        upstreams,
        selection,
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
        response_headers: std::sync::Arc::new(response_headers),
        response_routes: parse_response_routes(m.get("handle_response"), depth, regex_remaining)?,
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

fn pending_placeholders(value: &Value) -> Result<()> {
    pending_placeholders_depth(value, 0, false)
}
fn pending_placeholders_depth(value: &Value, depth: usize, typed_expression: bool) -> Result<()> {
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
                        || (!typed_expression && key.starts_with("http.request.tls.") && helpers::TlsScalar::from_name(key).is_none())
                        || (key.starts_with("http.reverse_proxy.")
                            && !matches!(
                                key,
                                "http.reverse_proxy.upstream.address"
                                    | "http.reverse_proxy.upstream.hostport"
                                    | "http.reverse_proxy.upstream.host"
                                    | "http.reverse_proxy.upstream.port"
                                    | "http.reverse_proxy.upstream.requests"
                                    | "http.reverse_proxy.upstream.max_requests"
                                    | "http.reverse_proxy.upstream.fails"
                                    | "http.reverse_proxy.status_code"
                                    | "http.reverse_proxy.status_text"
                                    | "http.reverse_proxy.retries"
                                    | "http.reverse_proxy.is_transport_error"
                                    | "http.reverse_proxy.active.target_upstream"
                            )
                            && !key.starts_with("http.reverse_proxy.header."))
                    {
                        return Err(helpers::unsupported("/placeholder/provider"));
                    }
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                pending_placeholders_depth(value, depth + 1, typed_expression)?;
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
                pending_placeholders_depth(value, depth + 1, typed_expression || key == "expression")?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_encode(
    m: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<crate::http_runtime::encode_response::EncodePlan> {
    use crate::http_runtime::{
        accepted_encodings::Coding, encode_body::CodecPlan, encode_response::EncodePlan,
    };
    deny_unknown(
        m,
        &["handler", "encodings", "prefer", "minimum_length", "match"],
        path,
    )?;
    let int = |value: Option<&Value>, default: i64| -> Result<i64> {
        match value {
            None | Some(Value::Null) => Ok(default),
            Some(value) => value
                .as_number()
                .and_then(serde_json::Number::as_go_i64)
                .ok_or_else(|| anyhow::anyhow!("encode integer expected")),
        }
    };
    let mut encodings = Vec::new();
    if let Some(raw) = m.get("encodings").filter(|v| !v.is_null()) {
        for (name, value) in object(raw, path)? {
            let settings = object(value, path)?;
            let coding = match name.as_str() {
                "gzip" => {
                    deny_unknown(settings, &["level"], path)?;
                    let level = int(settings.get("level"), 0)?;
                    ensure!((-3..=9).contains(&level), "invalid gzip level");
                    CodecPlan::Gzip(level as i32)
                }
                "zstd" => {
                    deny_unknown(settings, &["level", "checksum"], path)?;
                    let level = settings
                        .get("level")
                        .filter(|v| !v.is_null())
                        .map(|v| string(v, path))
                        .transpose()?
                        .unwrap_or_default();
                    let level = match level.to_ascii_lowercase().as_str() {
                        "" | "default" => "default",
                        "fastest" => "fastest",
                        "better" => "better",
                        "best" => "best",
                        _ => anyhow::bail!("invalid zstd level"),
                    };
                    let checksum = settings
                        .get("checksum")
                        .filter(|v| !v.is_null())
                        .map(|v| {
                            v.as_bool()
                                .ok_or_else(|| anyhow::anyhow!("invalid zstd checksum setting"))
                        })
                        .transpose()?;
                    CodecPlan::Zstd { level, checksum }
                }
                _ => {
                    return Err(unsupported(
                        "/apps/http/servers/*/routes/*/handle/*/encodings/module",
                    ));
                }
            };
            encodings.push(coding);
        }
    }
    let names = m
        .get("prefer")
        .filter(|v| !v.is_null())
        .map(|v| strings(v, path))
        .transpose()?
        .unwrap_or_default();
    let enabled = |coding| encodings.iter().any(|plan| plan.coding() == coding);
    let mut prefer = Vec::new();
    if names.is_empty() {
        prefer.extend(
            [Coding::Zstd, Coding::Brotli, Coding::Gzip]
                .into_iter()
                .filter(|c| enabled(*c)),
        );
    } else {
        for name in names {
            let coding = Coding::parse(&name)
                .filter(|c| enabled(*c))
                .ok_or_else(|| anyhow::anyhow!("preferred encoder not enabled"))?;
            ensure!(!prefer.contains(&coding), "duplicate encoder preference");
            prefer.push(coding);
        }
    }
    let minimum_length = int(m.get("minimum_length"), 512)?;
    let minimum_length = if minimum_length == 0 {
        512
    } else {
        minimum_length
    };
    let matcher = m
        .get("match")
        .filter(|v| !v.is_null())
        .map(|v| parse_response_matcher(v, path))
        .transpose()?;
    Ok(EncodePlan {
        encodings,
        prefer,
        minimum_length,
        matcher,
    })
}

fn parse_file_sidecars(
    m: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<crate::http_runtime::file_sidecars::SidecarPlan> {
    use crate::http_runtime::{accepted_encodings::Coding, file_sidecars::SidecarPlan};
    let mut encodings = Vec::new();
    if let Some(raw) = m.get("precompressed").filter(|v| !v.is_null()) {
        for (module, settings) in object(raw, path)? {
            let encoding = Coding::parse(module)
                .ok_or_else(|| unsupported("/file_server/precompressed/module"))?;
            deny_unknown(object(settings, path)?, &[], path)?;
            encodings.push(encoding);
        }
    }
    let strings_or_default = |name| -> Result<Vec<String>> {
        let Some(raw) = m.get(name).filter(|v| !v.is_null()) else {
            return Ok(Vec::new());
        };
        raw.as_array()
            .ok_or_else(|| anyhow::anyhow!("invalid file server array"))?
            .iter()
            .map(|v| {
                if v.is_null() {
                    Ok(String::new())
                } else {
                    string(v, path)
                }
            })
            .collect()
    };
    let order = strings_or_default("precompressed_order")?;
    let suffixes = strings_or_default("etag_file_extensions")?;
    ensure!(
        order.len() <= 64 && suffixes.len() <= 64,
        "file representation configuration limit exceeded"
    );
    Ok(SidecarPlan {
        encodings,
        order,
        etag_suffixes: suffixes.into(),
    })
}

fn typed_proxy_int(value: Option<&Value>) -> Result<i64> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value
            .as_number()
            .and_then(serde_json::Number::as_go_i64)
            .ok_or_else(|| anyhow::anyhow!("invalid proxy integer")),
    }
}

fn parse_selector(
    value: Option<&Value>,
    path: &str,
    upstreams: usize,
    depth: u8,
) -> Result<crate::http_runtime::proxy_policy::Selection> {
    use crate::http_runtime::proxy_policy::Selection;
    ensure!(depth <= 12, "proxy selection fallback depth exceeded");
    let Some(value) = value else {
        return Ok(Selection::Random);
    };
    let m = object(value, path)?;
    let policy = string(required(m, "policy")?, path)?;
    let child = || parse_selector(m.get("fallback"), path, upstreams, depth + 1).map(Box::new);
    let optional_string = |field| {
        m.get(field)
            .filter(|v| !v.is_null())
            .map(|v| string(v, path))
            .transpose()
    };
    let allowed: &[&str] = match policy.as_str() {
        "random" | "first" | "least_conn" | "round_robin" | "ip_hash" | "client_ip_hash"
        | "uri_hash" => &["policy"],
        "weighted_round_robin" => &["policy", "weights"],
        "random_choose" => &["policy", "choose"],
        "query" => &["policy", "key", "fallback"],
        "header" => &["policy", "field", "fallback"],
        "cookie" => &["policy", "name", "secret", "max_age", "fallback"],
        _ => {
            return Err(unsupported(
                "/reverse_proxy/load_balancing/selection_policy",
            ));
        }
    };
    deny_unknown(m, allowed, path)?;
    Ok(match policy.as_str() {
        "random" => Selection::Random,
        "first" => Selection::First,
        "least_conn" => Selection::Least,
        "round_robin" => Selection::RoundRobin,
        "weighted_round_robin" => {
            let array = required(m, "weights")?
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid proxy weights"))?;
            ensure!(
                array.len() <= 4096
                    && (upstreams == 0 || array.len() == 1 || array.len() == upstreams),
                "proxy weights must match upstream count"
            );
            let mut weights = Vec::with_capacity(upstreams.max(array.len()));
            let mut sum: i64 = 0;
            for item in array {
                let n = typed_proxy_int(Some(item))?;
                ensure!(n >= 0, "invalid proxy weight");
                sum = sum
                    .checked_add(n)
                    .ok_or_else(|| anyhow::anyhow!("proxy weight sum overflow"))?;
                weights.push(n as u64);
            }
            ensure!(sum > 0, "proxy weights cannot all be zero");
            // The pinned module supports a single weight with a larger
            // pool: it chooses the first upstream. Preserve that shape,
            // while still honoring its capacity and never panicking.
            if upstreams > 0 {
                weights.resize(upstreams, 0);
            }
            Selection::Weighted(weights)
        }
        "random_choose" => {
            let n = typed_proxy_int(m.get("choose"))?;
            let n = if n == 0 { 2 } else { n };
            ensure!(n >= 2, "proxy random_choose requires at least two choices");
            Selection::RandomChoose(usize::try_from(n).unwrap_or(usize::MAX))
        }
        "ip_hash" => Selection::Ip,
        "client_ip_hash" => Selection::ClientIp,
        "uri_hash" => Selection::Uri,
        "query" => {
            let key = optional_string("key")?
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("proxy query key is required"))?;
            Selection::Query {
                key,
                fallback: child()?,
            }
        }
        "header" => {
            let field = optional_string("field")?
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("proxy hash header field is required"))?;
            Selection::Header {
                field,
                fallback: child()?,
            }
        }
        "cookie" => {
            let name = optional_string("name")?
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "lb".to_owned());
            let secret = optional_string("secret")?.unwrap_or_default();
            let max_age = m
                .get("max_age")
                .filter(|v| !v.is_null())
                .map(|v| signed_duration(v, path))
                .transpose()?
                .unwrap_or(0);
            Selection::Cookie {
                name,
                secret,
                max_age_secs: (max_age.max(0) / 1_000_000_000) as u64,
                fallback: child()?,
            }
        }
        _ => unreachable!("policy keys checked before parsing"),
    })
}
