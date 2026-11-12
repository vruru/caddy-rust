// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Owned HTTP active probes; scheduling and transport admission live in sibling modules.
use super::proxy::ProxyClient;
use super::proxy_health::Probe;
use super::resource_budget::Resources;
use super::*; // Body, ProxyConfig (same glob proxy_client.rs uses)
use crate::go_regexp::ReplaceBudget; // path
use crate::http_config::helpers::{global_lookup, replace};
use crate::http_config::proxy_ext::ActiveCfg; // path
use crate::logging::{Event, Field, FieldValue, Level, Logging, Origin};
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Response, Uri};
use http_body_util::{BodyExt, Empty, Full};
use rustls::pki_types::ServerName;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Fail<T> = std::result::Result<T, String>;
type Headers = Vec<(HeaderName, HeaderValue)>;

const MODULE: &str = "http.handlers.reverse_proxy";
const LOGGER: &str = "http.handlers.reverse_proxy.health_checker.active";
const TARGET: &str = "http.reverse_proxy.active.target_upstream";
const DEFAULT_UA: &str = "Go-http-client/1.1";
const REQ_FAILED: &str = "HTTP request failed";
/// Upper bound on a body handed to the regex. Larger bodies fail the probe instead of being truncated.
const SAFE_BODY: u64 = 1 << 20;
const REGEX_SCRATCH_MAX: usize = 16 << 20;
const REGEX_DEADLINE: Duration = Duration::from_millis(150);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REDIRECTS: usize = 10;
const SLURP: u64 = 2 << 10; // Go maxBodySlurpSize before following a redirect
const SENSITIVE: [&str; 6] = [
    "authorization",
    "www-authenticate",
    "cookie",
    "cookie2",
    "proxy-authorization",
    "proxy-authenticate",
];
const HEX: &[u8; 16] = b"0123456789ABCDEF";

struct HttpProbe {
    client: ProxyClient,
    config: Arc<ProxyConfig>,
    resources: Arc<Resources>,
    logging: Option<Arc<Logging>>,
    events: Option<Arc<crate::events::EventsApp>>,
    event_cancel: tokio_util::sync::CancellationToken,
    /// Last expanded hostAddr per index; used as the `host` field in transition events.
    hosts: Mutex<Vec<String>>,
    _scheduler_credit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Clone)]
struct Url {
    scheme: String,
    host: String, // URL authority (Go u.Host)
    pq: String,   // escaped path + optional ?rawquery
}

struct Plan {
    url: Url,
    dial: String,      // fixed connect address for every hop (Caddy DialInfo)
    host_addr: String, // Go hostAddr, for logs/events
    host_override: String,
    headers: Fail<Headers>, // Err = Go transport rejects header => request failure
    user_agent: Option<HeaderValue>,
    body: Bytes,
    sni: Option<String>,
}

struct Verdict {
    ok: bool,
    observed: bool,
    msg: &'static str,
    reason: String,
    status: Option<u16>,
    rest: Option<(Body, bool, Option<u64>)>, // body, gzip, drain cap
    match_body: Option<Vec<u8>>,
}

impl Verdict {
    fn pass(rest: Option<(Body, bool, Option<u64>)>) -> Self {
        Self {
            ok: true,
            observed: true,
            msg: "",
            reason: String::new(),
            status: None,
            rest,
            match_body: None,
        }
    }
    fn fail(msg: &'static str, reason: impl Into<String>, status: Option<u16>) -> Self {
        Self {
            ok: false,
            observed: true,
            msg,
            reason: reason.into(),
            status,
            rest: None,
            match_body: None,
        }
    }
    fn unobserved(msg: &'static str, reason: impl Into<String>, status: Option<u16>) -> Self {
        let mut verdict = Self::fail(msg, reason, status);
        verdict.observed = false;
        verdict
    }
}

pub(super) fn build(
    client: ProxyClient,
    config: Arc<ProxyConfig>,
    resources: Arc<Resources>,
    logging: Option<Arc<Logging>>,
    scheduler_credit: tokio::sync::OwnedSemaphorePermit,
    events: Option<Arc<crate::events::EventsApp>>,
    event_cancel: tokio_util::sync::CancellationToken,
) -> Arc<dyn Probe> {
    let hosts = config.upstreams.iter().map(|u| u.dial.clone()).collect();
    Arc::new(HttpProbe {
        client,
        config,
        resources,
        logging,
        events,
        event_cancel,
        hosts: Mutex::new(hosts),
        _scheduler_credit: scheduler_credit,
    })
}

impl Probe for HttpProbe {
    fn run(&self, index: usize) -> Pin<Box<dyn Future<Output = Option<bool>> + Send + '_>> {
        Box::pin(self.probe(index))
    }

    fn transition_dropped(&self, _index: usize) {
        let count = self
            .resources
            .proxy_health_events_coalesced
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.log(
            Level::Warn,
            "health event transition queue coalesced",
            vec![("count", text(count.to_string()))],
        );
    }
    fn changed(
        &self,
        index: usize,
        healthy: bool,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        // Capture the host at the observed edge, before a later DNS/probe update.
        let host = self
            .hosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(index)
            .cloned()
            .unwrap_or_default();
        let logging = self.logging.clone();
        let events = self.events.clone();
        let cancel = self.event_cancel.clone();
        Box::pin(async move {
            if healthy {
                log_to(
                    logging.as_ref(),
                    Level::Info,
                    "host is up",
                    vec![("host", text(host.clone()))],
                );
            }
            if let Some(events) = events {
                let data = [("host".to_owned(), crate::events::Value::Str(host))]
                    .into_iter()
                    .collect();
                let emitted = events
                    .emit(
                        crate::events::EmitContext { cancel },
                        if healthy { "healthy" } else { "unhealthy" },
                        MODULE,
                        data,
                    )
                    .await;
                if !matches!(emitted.status, crate::events::Status::Completed)
                    || !emitted.errors.is_empty()
                {
                    log_to(
                        logging.as_ref(),
                        Level::Error,
                        "health event handler did not complete",
                        vec![("status", text(format!("{:?}", emitted.status)))],
                    );
                }
            }
        })
    }
}

impl HttpProbe {
    async fn probe(&self, index: usize) -> Option<bool> {
        let active = self.config.ext.health.active.as_ref()?;
        let upstream = self.config.upstreams.get(index)?;
        let plan = match self.plan(active, &upstream.dial) {
            Ok(plan) => plan,
            Err(reason) => {
                let fields = vec![
                    ("upstream_index", int(index as i64)),
                    ("error", text(reason)),
                ];
                self.log(
                    Level::Error,
                    "cannot build active health check request",
                    fields,
                );
                return None;
            }
        };
        self.remember(index, &plan.host_addr);
        let deadline = match active.timeout {
            t if t > 0 => Some(Instant::now() + Duration::from_nanos(t as u64)),
            0 => Some(Instant::now() + DEFAULT_TIMEOUT),
            _ => None, // no own deadline; the scheduler's stop token cancels
        };
        let mut verdict = within(deadline, self.exchange(active, &plan))
            .await
            .unwrap_or_else(|| Verdict::fail(REQ_FAILED, "timeout", None));
        if let Some(body) = verdict.match_body.take() {
            // Go's Client.Timeout ends with the body read, before Match.
            // Local regex admission/execution has its own bounded budget.
            verdict = match self.matches(body).await {
                Ok(true) => Verdict::pass(None),
                Ok(false) => {
                    Verdict::fail("response body failed expectations", "regex mismatch", None)
                }
                Err(error) => Verdict::unobserved("response body failed expectations", error, None),
            };
        }
        let Verdict {
            ok,
            observed,
            msg,
            reason,
            status,
            rest,
            match_body: _,
        } = verdict;
        if let Some((body, gzip, cap)) = rest {
            // Like Go's deferred io.Copy(io.Discard, body): bounded by max_size and deadline; errors ignored.
            let _ = within(deadline, read_body(body, gzip, cap, false)).await;
        }
        if !ok {
            let mut fields = Vec::new();
            if let Some(s) = status {
                fields.push(("status_code", int(s as i64)));
            }
            fields.push(("host", text(plan.host_addr.clone())));
            if reason != "status" && reason != "regex mismatch" {
                fields.push(("error", text(reason)));
            }
            self.log(Level::Info, msg, fields);
        }
        observed.then_some(ok)
    }

    fn plan(&self, a: &ActiveCfg, dial_tpl: &str) -> Fail<Plan> {
        let network_addr = strict(dial_tpl)?;
        let unix = network_addr.starts_with("unix/");
        if unix && a.port != 0 && a.upstream.is_empty() {
            return Err("health_port requires a TCP health upstream".into());
        }
        let base = if unix {
            "localhost".to_owned()
        } else {
            tcp_address(&network_addr)?
        };
        let (dhost, dport) = split_host_port(&base);
        let port = if a.port != 0 && a.upstream.is_empty() {
            a.port.to_string()
        } else {
            dport.to_owned()
        };
        let host_addr = if a.port != 0 && a.upstream.is_empty() {
            join_host_port(dhost, &port)
        } else {
            base.clone()
        };
        // active.upstream overrides both dial and URL host; port only applies without it.
        let mut dial = if a.upstream.is_empty() {
            host_addr.clone()
        } else {
            let expanded=strict(&a.upstream)?;
            if super::http_dial::unix_path(&expanded).map_err(|e|e.to_string())?.is_some(){expanded}else{tcp_address(&expanded)?}
        };
        let url_host = if dial.starts_with("unix/"){ "localhost".to_owned() }else{dial.clone()};
        if a.upstream.is_empty() && a.port == 0 {
            if unix {
                dial = network_addr.clone();
            } else if let Some((network, _)) = network_addr.split_once('/') {
                dial = format!("{network}/{dial}");
            }
        }
        // Go's OverrideHealthCheckScheme sees the original health hostAddr
        // port (health_port already applied), even when active.upstream
        // separately replaces the URL host and physical dial address.
        let tls = self.config.tls_for_port(&port);
        let https = tls.is_some();
        let pq = if let Some(pq) = &a.uri_path_query {
            pq.clone()
        } else {
            with_slash(escape_path(a.path.as_bytes()))
        };
        let url = Url {
            scheme: if https { "https" } else { "http" }.into(),
            host: url_host,
            pq,
        };

        let lookup = |k: &str| {
            if k == TARGET {
                Some(network_addr.clone())
            } else {
                global_lookup(k)
            }
        };
        let (mut host_override, mut user_agent, mut list, mut invalid) =
            (String::new(), None, Vec::new(), None);
        for (raw, vals) in &a.headers {
            let key = expand(raw, true, lookup)?; // ReplaceAll
            if key == "Host" {
                // Go canonicalizes the JSON header map before expansion.
                let v = a
                    .headers
                    .iter()
                    .find(|(k, _)| k == "Host")
                    .and_then(|(_, v)| v.first());
                host_override = expand(v.map_or("", String::as_str), true, lookup)?;
                continue;
            }
            let Ok(name) = HeaderName::from_bytes(key.as_bytes()) else {
                invalid = Some("invalid header field name");
                continue;
            };
            let excluded = self.config.fastcgi.is_none()
                && [
                    header::HOST,
                    header::CONTENT_LENGTH,
                    header::TRANSFER_ENCODING,
                    header::TRAILER,
                ]
                .contains(&name);
            for raw_val in vals {
                let val = expand(raw_val, false, lookup)?; // ReplaceKnown
                let Ok(value) = HeaderValue::from_bytes(val.trim_matches([' ', '\t']).as_bytes())
                else {
                    invalid = Some("invalid header field value");
                    continue;
                };
                if name == header::USER_AGENT && self.config.fastcgi.is_none() {
                    user_agent.get_or_insert(value); // Go writes only the first value
                } else if !excluded {
                    list.push((name.clone(), value));
                }
            }
        }
        // Body: globals only (target_upstream is set after the body in Go); ReplaceKnown keeps JSON braces.
        let body = if a.body.is_empty() {
            Bytes::new()
        } else {
            Bytes::from(expand(&a.body, false, global_lookup)?)
        };
        let sni = match tls.and_then(|t| t.server_name.as_deref()) {
            Some(s) if !s.is_empty() => {
                let expanded = expand(s, true, global_lookup)?;
                if expanded.is_empty() && s.contains('{') {
                    // Caddy's dynamic DialTLSContext never falls back to the
                    // URL host after a placeholder expands to an empty name.
                    Some(if tls.is_some_and(|t| t.insecure_skip_verify) {
                        "0.0.0.0".into() // IP names omit SNI, matching tls.Client.
                    } else {
                        String::new() // send() rejects it; this is a failed probe.
                    })
                } else {
                    Some(expanded).filter(|s| !s.is_empty())
                }
            }
            _ => None,
        };
        let headers = invalid.map_or(Ok(list), |e| Err(e.to_string()));
        Ok(Plan {
            url,
            dial,
            host_addr,
            host_override,
            headers,
            user_agent,
            body,
            sni,
        })
    }

    async fn exchange(&self, a: &ActiveCfg, p: &Plan) -> Verdict {
        let base = match &p.headers {
            Ok(h) => h,
            Err(e) => return Verdict::fail(REQ_FAILED, e.clone(), None),
        };
        let (mut url, mut method, mut with_body) = (p.url.clone(), a.method.clone(), true);
        let (mut headers, mut host, mut stripped, mut hops) =
            (base.clone(), p.host_override.clone(), false, 0);
        let (resp, gzip) = loop {
            let (resp, gzip) = match self
                .send(p, &url, &method, with_body, &headers, &host)
                .await
            {
                Ok(r) => r,
                Err(e) => return Verdict::fail(REQ_FAILED, e, None),
            };
            let status = resp.status().as_u16();
            if !a.follow_redirects || !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break (resp, gzip); // follow_redirects=false: keep the 3xx (ErrUseLastResponse)
            }
            let loc = resp
                .headers()
                .get(header::LOCATION)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_str().map(str::to_owned));
            let Some(loc) = loc else { break (resp, gzip) };
            if hops == MAX_REDIRECTS {
                return Verdict::fail(REQ_FAILED, "stopped after 10 redirects", None);
            }
            hops += 1;
            let next = loc
                .map_err(|_| "failed to parse Location header".to_string())
                .and_then(|l| url.resolve(&l));
            let (next, abs) = match next {
                Ok(n) => n,
                Err(e) => return Verdict::fail(REQ_FAILED, e, None),
            };
            let _ = read_body(resp.into_body(), false, Some(SLURP), false).await;
            if matches!(status, 301..=303) {
                if method != Method::GET && method != Method::HEAD {
                    method = Method::GET;
                }
                with_body = false;
            } else {
                with_body = true; // 307/308: Go re-attaches the initial body via GetBody
            }
            // Preserve custom Host only for relative Locations (Go issue #22233).
            let keep_host = !p.host_override.is_empty() && p.host_override != p.url.host && !abs;
            host = if keep_host {
                p.host_override.clone()
            } else {
                String::new()
            };
            if !stripped && next.host != p.url.host {
                let (d, i) = (
                    hostname(&next.host).to_ascii_lowercase(),
                    hostname(&p.url.host).to_ascii_lowercase(),
                );
                stripped = !same_site(&d, &i); // sticky once a cross-domain hop occurred
            }
            headers = base
                .iter()
                .filter(|(n, _)| !(stripped && SENSITIVE.contains(&n.as_str())))
                .cloned()
                .collect();
            let downgrade = url.scheme == "https" && next.scheme == "http";
            if !downgrade
                && !headers
                    .iter()
                    .any(|(n, v)| *n == header::REFERER && !v.is_empty())
                && let Ok(r) = HeaderValue::from_str(&url.text())
            {
                headers.push((header::REFERER, r));
            }
            url = next;
        };

        let status = resp.status().as_u16();
        let drain_cap = (a.max_size > 0).then_some(a.max_size as u64);
        let ok_status = if a.expect_status > 0 {
            status_matches(status as i64, a.expect_status)
        } else {
            (200..300).contains(&status)
        };
        if !ok_status {
            let msg = if a.expect_status > 0 {
                "unexpected status code"
            } else {
                "status code out of tolerances"
            };
            let mut v = Verdict::fail(msg, "status", Some(status));
            v.rest = Some((resp.into_body(), gzip, drain_cap));
            return v;
        }
        if a.expect_body.is_none() {
            return Verdict::pass(Some((resp.into_body(), gzip, drain_cap)));
        }
        // max_size in (0, 1MiB]: Go LimitReader prefix. Otherwise read 1MiB+1 to detect overflow.
        let cap = drain_cap.map_or(SAFE_BODY + 1, |m| m.min(SAFE_BODY + 1));
        let body = match read_body(resp.into_body(), gzip, Some(cap), true).await {
            Ok(b) => b,
            Err(e) if e == "health body allocation unavailable" => {
                return Verdict::unobserved("failed to read response body", e, None);
            }
            Err(e) => return Verdict::fail("failed to read response body", e, None),
        };
        if body.len() as u64 > SAFE_BODY {
            let reason = "body exceeds the 1 MiB probe regex budget (set max_size <= 1048576)";
            return Verdict::unobserved("failed to read response body", reason, None);
        }
        let mut verdict = Verdict::pass(None);
        verdict.match_body = Some(body);
        verdict
    }

    async fn send(
        &self,
        p: &Plan,
        url: &Url,
        method: &Method,
        with_body: bool,
        headers: &[(HeaderName, HeaderValue)],
        host: &str,
    ) -> Fail<(Response<Body>, bool)> {
        // Keep physical Unix paths out of HTTP authorities. Explicit active
        // Host overrides continue to take precedence over this logical default.
        let sni = if url.scheme == "https" {
            let name = p
                .sni
                .clone()
                .unwrap_or_else(|| hostname(&url.host).to_owned());
            Some(ServerName::try_from(super::http_dial::tls_host(&name).to_owned()).map_err(|_| "invalid TLS server name".to_string())?)
        } else {
            None
        };
        let unix_host = (host.is_empty() && url.scheme == "https" && p.dial.starts_with("unix/"))
            .then(|| super::http_dial::unix_tls_host(sni.as_ref()));
        let authority = if !host.is_empty() { host } else { unix_host.as_deref().unwrap_or(&url.host) };
        let uri: Uri = format!("{}://{}{}", url.scheme, super::http_dial::wire_host(authority), url.pq)
            .parse().map_err(|_| "invalid request URL".to_string())?;
        let send_body = with_body && !p.body.is_empty();
        let body: Body = if send_body {
            Full::new(p.body.clone())
                .map_err(|n| match n {})
                .boxed_unsync()
        } else {
            Empty::<Bytes>::new().map_err(|n| match n {}).boxed_unsync()
        };
        let mut req = Request::new(body);
        *req.method_mut() = method.clone();
        *req.uri_mut() = uri;
        let h = req.headers_mut();
        for (n, v) in headers {
            h.append(n.clone(), v.clone());
        }
        if self.config.fastcgi.is_none() {
            h.insert(
                header::HOST,
                HeaderValue::from_str(&super::http_dial::wire_host(authority)).map_err(|_| "invalid Host".to_string())?,
            );
        }
        match &p.user_agent {
            None if self.config.fastcgi.is_none() => {
                drop(h.insert(header::USER_AGENT, HeaderValue::from_static(DEFAULT_UA)))
            }
            None => {}
            Some(v) if v.is_empty() => {} // explicit empty UA suppresses it, as in Go
            Some(v) => drop(h.insert(header::USER_AGENT, v.clone())),
        }
        // Go Transport: transparent gzip unless DisableCompression, an Accept-Encoding/Range is set, or HEAD.
        let gzip_req = self.config.fastcgi.is_none()
            && self.config.compression
            && *method != Method::HEAD
            && h.get(header::ACCEPT_ENCODING).is_none_or(|v| v.is_empty())
            && h.get(header::RANGE).is_none_or(|v| v.is_empty());
        if gzip_req {
            h.append(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        }
        if self.config.fastcgi.is_none() && send_body {
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(p.body.len()));
        } else if self.config.fastcgi.is_none()
            && matches!(method.as_str(), "POST" | "PUT" | "PATCH")
        {
            h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        if let Some(transport) = &self.config.fastcgi {
            let response = super::fastcgi::probe(
                req,
                self.resources.clone(),
                &self.config,
                transport,
                p.dial.clone(),
                self.logging.as_ref(),
            )
            .await
            .map_err(|error| error.to_string())?;
            return Ok((response, false));
        }
        let unix_path=super::http_dial::unix_path(&p.dial).map_err(|e|e.to_string())?;
        let (family,address)=if unix_path.is_some(){(super::http_dial::Family::Any,"localhost:0")}else{super::http_dial::Family::parse(&p.dial).map_err(|e|e.to_string())?};
        let client = self
            .client
            .client_for(&format!("{}://{}", url.scheme, address), family, false, sni,unix_path)
            .map_err(|e| format!("upstream client: {e}"))?;
        let resp = client.request(req).await.map_err(|e| error_chain(&e))?;
        let gzip = gzip_req
            && resp
                .headers()
                .get(header::CONTENT_ENCODING)
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
        Ok((
            resp.map(|body| {
                body.map_err(|error| -> BoxError { error.into() })
                    .boxed_unsync()
            }),
            gzip,
        ))
    }

    async fn matches(&self, body: Vec<u8>) -> Fail<bool> {
        let config = self.config.clone();
        let until = Instant::now() + REGEX_DEADLINE;
        let job = move || {
            let regex = config
                .ext
                .health
                .active
                .as_ref()
                .and_then(|a| a.expect_body.as_ref())?;
            let scratch = regex
                .regex
                .search_memory()
                .saturating_add(7 * SAFE_BODY as usize)
                .min(REGEX_SCRATCH_MAX);
            Some(
                regex
                    .regex
                    .is_match_bytes(&body, &ReplaceBudget::new(scratch, Some(until)))
                    .map_err(|_| ()),
            )
        };
        match self.resources.request_regexp.run(job).await {
            Ok(Some(Ok(hit))) => Ok(hit),
            Ok(Some(Err(()))) => Err("regex budget exceeded".into()),
            Ok(None) => Ok(true),
            Err(_) => Err("regex lane unavailable".into()),
        }
    }

    fn remember(&self, index: usize, host: &str) {
        let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = hosts.get_mut(index).filter(|s| s.as_str() != host) {
            *slot = host.to_owned();
        }
    }

    fn log(&self, level: Level, msg: &str, fields: Vec<(&'static str, FieldValue)>) {
        log_to(self.logging.as_ref(), level, msg, fields);
    }
}

fn log_to(
    logging: Option<&Arc<Logging>>,
    level: Level,
    msg: &str,
    fields: Vec<(&'static str, FieldValue)>,
) {
    let Some(logging) = logging else {
        return;
    };
    if let Ok(mut event) = Event::new(
        Origin::Module {
            module_id: MODULE.into(),
        },
        LOGGER,
        level,
        msg,
    ) {
        event
            .fields
            .extend(fields.into_iter().map(|(k, v)| Field::new(k, v)));
        let _ = logging.try_emit(event);
    }
}

impl Url {
    fn text(&self) -> String {
        format!("{}://{}{}", self.scheme, self.host, self.pq)
    }

    /// RFC 3986 reference resolution like Go's `req.URL.Parse(loc)`. The fragment is dropped.
    /// Returns (url, location_is_absolute).
    fn resolve(&self, loc: &str) -> Fail<(Url, bool)> {
        let loc = loc.split('#').next().unwrap_or_default();
        let (scheme, rest) = match split_scheme(loc) {
            Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
            None => (None, loc),
        };
        let abs = scheme.is_some();
        let scheme = scheme.unwrap_or_else(|| self.scheme.clone());
        if scheme != "http" && scheme != "https" {
            return Err(format!("unsupported protocol scheme {scheme:?}"));
        }
        let (host, tail, has_authority) = match rest.strip_prefix("//") {
            Some(r) => {
                let end = r.find(['/', '?']).unwrap_or(r.len());
                let auth = &r[..end];
                (
                    auth.rsplit_once('@').map_or(auth, |(_, h)| h).to_owned(),
                    &r[end..],
                    true,
                )
            }
            None if abs => return Err("opaque Location unsupported".into()),
            None => (self.host.clone(), rest, false),
        };
        if host.is_empty() {
            return Err("no Host in redirect URL".into());
        }
        let (path, query) = tail
            .split_once('?')
            .map_or((tail, None), |(p, q)| (p, Some(q)));
        let (bpath, bquery) = self
            .pq
            .split_once('?')
            .map_or((self.pq.as_str(), None), |(p, q)| (p, Some(q)));
        let (path, query) = if has_authority || path.starts_with('/') {
            (remove_dots(path), query)
        } else if path.is_empty() {
            (bpath.to_owned(), query.or(bquery))
        } else {
            let dir = &bpath[..bpath.rfind('/').map_or(0, |i| i + 1)];
            (remove_dots(&format!("{dir}{path}")), query)
        };
        let mut pq = escape_loose(if path.is_empty() { "/" } else { &path });
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            pq.push('?');
            pq.push_str(&escape_loose(q));
        }
        Ok((Url { scheme, host, pq }, abs))
    }
}

async fn read_body(body: Body, gzip: bool, cap: Option<u64>, keep: bool) -> Fail<Vec<u8>> {
    let mut body = if gzip {
        super::proxy::gzip_decode(body)
    } else {
        body.map_err(|error| -> BoxError { error.into() })
            .boxed_unsync()
    };
    let mut remaining = cap.unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    let mut frames = 0usize;
    while remaining > 0 {
        let Some(frame) = body.frame().await else {
            break;
        };
        let frame = frame.map_err(|error| format!("reading body: {error}"))?;
        if let Some(data) = frame.data_ref() {
            let take = data
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            if keep {
                bytes
                    .try_reserve(take)
                    .map_err(|_| "health body allocation unavailable".to_string())?;
                bytes.extend_from_slice(&data[..take]);
            }
            remaining -= take as u64;
        }
        frames += 1;
        if frames == 64 {
            frames = 0;
            tokio::task::yield_now().await;
        }
    }
    Ok(bytes)
}

async fn within<F: Future>(deadline: Option<Instant>, fut: F) -> Option<F::Output> {
    match deadline {
        Some(d) => tokio::time::timeout_at(tokio::time::Instant::from_std(d), fut)
            .await
            .ok(),
        None => Some(fut.await),
    }
}

fn expand(s: &str, unknown_empty: bool, lookup: impl Fn(&str) -> Option<String>) -> Fail<String> {
    replace(s, unknown_empty, lookup).map_err(|_| "placeholder expansion failed".to_string())
}

/// Go `ReplaceOrErr(s, true, true)`: unknown or empty global placeholders are errors.
fn strict(s: &str) -> Fail<String> {
    let bad = Cell::new(false);
    let out = expand(s, true, |k| match global_lookup(k) {
        Some(v) if !v.is_empty() => Some(v),
        _ => {
            bad.set(true);
            None
        }
    })?;
    if bad.get() {
        return Err("invalid use of placeholders in dial address for active health checks".into());
    }
    Ok(out)
}

fn tcp_address(addr: &str) -> Fail<String> {
    let (network, rest) = addr
        .split_once('/')
        .map_or((String::new(), addr), |(n, r)| {
            (n.trim().to_ascii_lowercase(), r)
        });
    if !matches!(network.as_str(), "" | "tcp" | "tcp4" | "tcp6") {
        return Err(format!(
            "network {network:?} not supported by the HTTP probe"
        ));
    }
    if rest.is_empty() {
        return Err("empty dial address".into());
    }
    if split_host_port(rest).1.contains('-') {
        return Err("multiple addresses (upstream must map to only one address)".into());
    }
    Ok(rest.to_owned())
}

fn split_host_port(s: &str) -> (&str, &str) {
    if let Some((h, rest)) = s.strip_prefix('[').and_then(|r| r.split_once(']')) {
        return (h, rest.strip_prefix(':').unwrap_or(""));
    }
    match s.split_once(':') {
        Some((h, p)) if !p.contains(':') => (h, p),
        _ => (s, ""),
    }
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn hostname(authority: &str) -> &str {
    split_host_port(authority).0
}

/// Go `isDomainOrSubdomain`.
fn same_site(sub: &str, parent: &str) -> bool {
    sub == parent
        || (!sub.contains([':', '%'])
            && sub.len() > parent.len()
            && sub.ends_with(parent)
            && sub.as_bytes()[sub.len() - parent.len() - 1] == b'.')
}

/// Caddy `StatusCodeMatches`: exact code, or a class such as 2 for 2xx.
fn status_matches(actual: i64, configured: i64) -> bool {
    actual == configured
        || (configured < 100 && actual >= configured * 100 && actual < (configured + 1) * 100)
}

fn split_scheme(s: &str) -> Option<(&str, &str)> {
    for (i, c) in s.char_indices() {
        match c {
            'a'..='z' | 'A'..='Z' => {}
            '0'..='9' | '+' | '-' | '.' if i > 0 => {}
            ':' if i > 0 => return Some((&s[..i], &s[i + 1..])),
            _ => return None,
        }
    }
    None
}

fn push_pct(out: &mut String, b: u8) {
    out.push('%');
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 15) as usize] as char);
}

fn escape_path(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    for &c in b {
        if c.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(&c) {
            out.push(c as char);
        } else {
            push_pct(&mut out, c);
        }
    }
    out
}

/// Escapes only bytes that cannot appear in a request target, leaving existing %XX intact.
fn escape_loose(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c <= b' ' || c >= 0x7f || b"\"<>\\^`{|}".contains(&c) {
            push_pct(&mut out, c);
        } else {
            out.push(c as char);
        }
    }
    out
}

fn with_slash(path: String) -> String {
    if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

/// Go `resolvePath` dot-segment removal. A trailing "." or ".." keeps the trailing slash.
fn remove_dots(p: &str) -> String {
    let parts: Vec<&str> = p.strip_prefix('/').unwrap_or(p).split('/').collect();
    let mut out: Vec<&str> = Vec::with_capacity(parts.len());
    for (i, seg) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        match *seg {
            "." => {}
            ".." => drop(out.pop()),
            s => {
                out.push(s);
                continue;
            }
        }
        if last {
            out.push("");
        }
    }
    format!("/{}", out.join("/"))
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

fn text(v: impl Into<String>) -> FieldValue {
    FieldValue::ByteString(v.into().into_bytes())
}

fn int(v: i64) -> FieldValue {
    FieldValue::I64(v)
}
