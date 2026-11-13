//! Prepared static reverse proxy selection and per-host request admission.
//! Policy names and key semantics follow Caddy v2.11.7 selectionpolicies.go.
use super::proxy_health::ActiveState;
use super::proxy_hosts::{HostState as Host, RUN_BUDGET};
use super::{Body, BoxError, Bytes};
use crate::http_config::proxy_ext::PassiveCfg;
use hmac::{Hmac, Mac, digest::CtOutput};
use http::{HeaderMap, HeaderValue, Version, header, uri::Uri};
use http_body_util::BodyExt;
use sha2::Sha256;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use xxhash_rust::xxh64::Xxh64;

#[derive(Clone)]
pub(crate) struct Upstream {
    pub(crate) dial: String,
    pub(crate) max_requests: i64,
}

#[derive(Clone)]
pub(crate) enum Selection {
    Random,
    First,
    Least,
    RoundRobin,
    Weighted(Vec<u64>),
    RandomChoose(usize),
    Ip,
    ClientIp,
    Uri,
    Query {
        key: String,
        fallback: Box<Self>,
    },
    Header {
        field: String,
        fallback: Box<Self>,
    },
    Cookie {
        name: String,
        secret: String,
        max_age_secs: u64,
        fallback: Box<Self>,
    },
}

/// Per-HTTP-runtime, shared by all routes and overlapping generations. The
/// raw configured dial is the key, including any placeholders it contains.
pub(super) struct HostRegistry {
    hosts: Mutex<HashMap<String, Weak<Host>>>,
    inflight: Mutex<Inflight>,
    failures: Arc<tokio::sync::Semaphore>,
    dynamic: Mutex<HashMap<String, (Arc<Host>, tokio::time::Instant)>>,
    dropped_failures: AtomicU64,
    last_failure_warning: AtomicU64,
}
#[derive(Default)]
struct Inflight { entries: HashMap<String,u64>, bytes: usize }
impl Default for HostRegistry {
    fn default() -> Self {
        Self {
            hosts: Mutex::new(HashMap::new()),
            inflight: Mutex::new(Inflight::default()),
            failures: Arc::new(tokio::sync::Semaphore::new(RUN_BUDGET)),
            dynamic: Mutex::new(HashMap::new()),
            dropped_failures: AtomicU64::new(0),
            last_failure_warning: AtomicU64::new(0),
        }
    }
}

impl HostRegistry {
    /// Runs on the existing bounded blocking lane. Registry locks only copy
    /// owned identities; failure-ledger expiration happens after releasing them.
    pub(super) fn statuses(&self, configured: &std::collections::HashSet<&str>) -> anyhow::Result<Vec<crate::admin::UpstreamStatus>> {
        const LIMIT: usize = 8 << 20;
        const ROWS: usize = 65536;
        let mut records: Vec<(String, Option<Arc<Host>>, u64)> = Vec::new();
        let hint=self.hosts.lock().unwrap_or_else(|e|e.into_inner()).len()
            .saturating_add(self.inflight.lock().unwrap_or_else(|e|e.into_inner()).entries.len())
            .saturating_add(self.dynamic.lock().unwrap_or_else(|e|e.into_inner()).len()).min(ROWS);
        records.try_reserve_exact(hint)?;
        let mut charged = records.capacity().saturating_mul(std::mem::size_of::<(String, Option<Arc<Host>>, u64)>());
        let mut add = |address: &str, host: Option<Arc<Host>>, count: u64| -> anyhow::Result<()> {
            anyhow::ensure!(records.len()<ROWS,"upstream snapshot row limit exceeded");
            // Configuration churn may grow a registry after the hint. A bounded
            // geometric replacement is prepaid before either allocation moves.
            if records.len()==records.capacity() {
                let next=records.capacity().max(16).saturating_mul(2).min(ROWS);
                let allocation=next.saturating_mul(std::mem::size_of::<(String, Option<Arc<Host>>, u64)>());
                anyhow::ensure!(charged.saturating_add(allocation)<=LIMIT,"upstream snapshot capacity exceeded");
                records.try_reserve_exact(next-records.len())?;
                charged=charged.saturating_add(allocation);
            }
            charged = charged.checked_add(std::mem::size_of::<crate::admin::UpstreamStatus>()).and_then(|n| n.checked_add(address.len()))
                .filter(|n| *n <= LIMIT).ok_or_else(|| anyhow::anyhow!("upstream snapshot limit exceeded"))?;
            let mut key = String::new();key.try_reserve_exact(address.len())?;key.push_str(address);
            records.push((key,host,count));Ok(())
        };
        {
            let hosts=self.hosts.lock().unwrap_or_else(|e|e.into_inner());
            for (address,weak) in hosts.iter() {
                if configured.contains(address.as_str()) && let Some(host)=weak.upgrade(){add(address,Some(host),0)?;}
            }
            // No other path nests these two locks. This prevents a finished
            // expanded-address request from being resurrected in the snapshot.
            let inflight=self.inflight.lock().unwrap_or_else(|e|e.into_inner());
            for (address,count) in inflight.entries.iter() {
                if *count>0 && !(configured.contains(address.as_str()) && hosts.get(address).is_some_and(|weak|weak.strong_count()>0)){add(address,None,*count)?;}
            }
        }
        {
            let dynamic=self.dynamic.lock().unwrap_or_else(|e|e.into_inner());
            for (address,(host,_)) in dynamic.iter(){add(address,Some(host.clone()),0)?;}
        }
        let now=tokio::time::Instant::now();
        let mut out=Vec::new();out.try_reserve_exact(records.len())?;
        for(address,host,count)in records {
            let(num_requests,fails)=host.map_or((count,0),|host|(host.running.load(Ordering::Acquire),host.fails(now)));
            out.push(crate::admin::UpstreamStatus{address,num_requests,fails});
        }
        Ok(out)
    }
    fn enter_address(self: &Arc<Self>, address: &str) -> anyhow::Result<AddressLease> {
        let mut inflight=self.inflight.lock().unwrap_or_else(|e|e.into_inner());
        if !inflight.entries.contains_key(address) {
            anyhow::ensure!(inflight.entries.len()<65536,"expanded upstream status capacity exceeded");
            anyhow::ensure!(address.len()<=65536,"expanded upstream status address too long");
            // The request already owns the expanded address. Bound the shared
            // retained copy independently of request-body or failure budgets.
            anyhow::ensure!(inflight.bytes.saturating_add(address.len())<=8<<20,"expanded upstream status bytes exceeded");
            inflight.entries.try_reserve(1)?;
            inflight.bytes+=address.len();
        }
        let count=inflight.entries.entry(address.to_owned()).or_default();
        *count=count.checked_add(1).ok_or_else(||anyhow::anyhow!("expanded upstream count overflow"))?;
        Ok(AddressLease{registry:self.clone(),address:address.to_owned()})
    }
    pub(super) fn dropped_failures(&self) -> u64 {
        self.dropped_failures.load(Ordering::Relaxed)
    }
    pub(super) fn record_dropped_failure(&self) -> bool {
        self.dropped_failures.fetch_add(1, Ordering::Relaxed);
        static CLOCK: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        let second = CLOCK
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_secs()
            .saturating_add(1);
        self.last_failure_warning
            .try_update(Ordering::AcqRel, Ordering::Acquire, |previous| {
                (previous < second).then_some(second)
            })
            .is_ok()
    }
    pub(super) fn prune(&self) {
        self.hosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, host| host.strong_count() > 0);
    }

    pub(super) fn clear_dynamic(&self) {
        let removed = std::mem::take(&mut *self.dynamic.lock().unwrap_or_else(|e| e.into_inner()));
        drop(removed);
    }
    /// Go fillDynamicHost never consults the static UsagePool. Dynamic
    /// failures and request counts persist only in this separate idle map.
    fn resolve_dynamic(&self, configs: &[Upstream]) -> anyhow::Result<Vec<Endpoint>> {
        let now = tokio::time::Instant::now();
        let mut retained = self.dynamic.lock().unwrap_or_else(|e| e.into_inner());
        retained.retain(|_, (_, expires)| *expires > now);
        let added = configs
            .iter()
            .map(|config| config.dial.as_str())
            .filter(|key| !retained.contains_key(*key))
            .collect::<std::collections::HashSet<_>>()
            .len();
        anyhow::ensure!(
            retained.len().saturating_add(added) <= 65536,
            "dynamic host-state capacity exceeded"
        );
        let expires = now + std::time::Duration::from_secs(3600);
        Ok(configs
            .iter()
            .map(|config| {
                let (host, seen) = retained
                    .entry(config.dial.clone())
                    .or_insert_with(|| (Arc::new(Host::new(self.failures.clone())), expires));
                *seen = expires;
                Endpoint {
                    config: config.clone(),
                    host: host.clone(),
                    active: Arc::new(ActiveState::default()),
                    passive: None,
                }
            })
            .collect())
    }
    fn resolve(&self, configs: &[Upstream]) -> Vec<Endpoint> {
        let mut registry = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        configs
            .iter()
            .map(|config| {
                let record = registry.entry(config.dial.clone()).or_default();
                let host = record.upgrade().unwrap_or_else(|| {
                    let host = Arc::new(Host::new(self.failures.clone()));
                    *record = Arc::downgrade(&host);
                    host
                });
                Endpoint {
                    config: config.clone(),
                    host,
                    active: Arc::new(ActiveState::default()),
                    passive: None,
                }
            })
            .collect()
    }
}

struct Endpoint {
    config: Upstream,
    host: Arc<Host>,
    active: Arc<ActiveState>,
    passive: Option<PassiveCfg>,
}

impl Endpoint {
    fn capacity(&self) -> u64 {
        if self.config.max_requests == 0
            && let Some(cfg) = &self.passive
            && cfg.unhealthy_request_count > 0
        {
            return cfg.unhealthy_request_count as u64;
        }
        u64::try_from(self.config.max_requests).unwrap_or(0)
    }

    fn available(&self) -> bool {
        if !self.active.healthy() {
            return false;
        }
        if let Some(cfg) = &self.passive
            && (cfg.max_fails < 0
                || self.host.fails(tokio::time::Instant::now()) >= cfg.max_fails as u64)
        {
            return false;
        }
        let max = self.capacity();
        max == 0 || self.host.running.load(Ordering::Acquire) < max
    }

    fn reserve(&self) -> Option<(Arc<RequestLease>, u64)> {
        if !self.available() {
            return None;
        }
        let max = self.capacity();
        let previous = self
            .host
            .running
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                if max > 0 && count >= max {
                    return None;
                }
                count.checked_add(1)
            })
            .ok()?;
        Some((Arc::new(RequestLease {host:self.host.clone(),address:Mutex::new(None)}), previous))
    }
}

pub(super) struct RequestLease { host: Arc<Host>, address: Mutex<Option<AddressLease>> }
struct AddressLease { registry: Arc<HostRegistry>, address: String }
impl Drop for AddressLease {
    fn drop(&mut self) {
        let mut map=self.registry.inflight.lock().unwrap_or_else(|e|e.into_inner());
        if let Some(count)=map.entries.get_mut(&self.address){*count=count.saturating_sub(1);if *count==0 {map.entries.remove(&self.address);map.bytes=map.bytes.saturating_sub(self.address.len());}}
    }
}
impl RequestLease {
    pub(super) fn bind_address(&self,registry:&Arc<HostRegistry>,address:&str)->anyhow::Result<()> {
        let mut slot=self.address.lock().unwrap_or_else(|e|e.into_inner());
        anyhow::ensure!(slot.is_none(),"upstream address already bound");
        *slot=Some(registry.enter_address(address)?);Ok(())
    }
}
impl Drop for RequestLease {
    fn drop(&mut self) {
        let previous = self.host.running.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

pub(super) struct PreparedSelection {
    pool: Vec<Endpoint>,
    policy: Arc<Policy>,
    passive: Option<PassiveCfg>,
}

pub(super) struct SelectionInput<'a> {
    pub authority: &'a str,
    pub uri: &'a Uri,
    pub version: Version,
    pub headers: &'a HeaderMap,
    pub peer_ip: &'a [u8],
    pub client_ip: &'a str,
    pub secure: bool,
}

pub(super) struct OwnedSelectionInput {
    authority: String,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    peer_ip: Vec<u8>,
    client_ip: String,
    secure: bool,
}
impl SelectionInput<'_> {
    pub(super) fn owned(&self) -> OwnedSelectionInput {
        OwnedSelectionInput {
            authority: self.authority.to_owned(),
            uri: self.uri.clone(),
            version: self.version,
            headers: self.headers.clone(),
            peer_ip: self.peer_ip.to_owned(),
            client_ip: self.client_ip.to_owned(),
            secure: self.secure,
        }
    }
}
impl OwnedSelectionInput {
    pub(super) fn borrowed(&self) -> SelectionInput<'_> {
        SelectionInput {
            authority: &self.authority,
            uri: &self.uri,
            version: self.version,
            headers: &self.headers,
            peer_ip: &self.peer_ip,
            client_ip: &self.client_ip,
            secure: self.secure,
        }
    }
}

pub(super) struct Selected {
    pub dial: String,
    pub fails: u64,
    pub host: Arc<Host>,
    pub max_requests: i64,
    pub prior_requests: u64,
    pub lease: Arc<RequestLease>,
    pub cookies: Vec<HeaderValue>,
}

impl PreparedSelection {
    pub(super) fn metric_probes(&self)->Vec<(Arc<str>,crate::metrics::upstream::Probe)>{
        self.pool.iter().map(|endpoint|{
            let host=endpoint.host.clone();let active=endpoint.active.clone();let passive=endpoint.passive.clone();
            let probe:crate::metrics::upstream::Probe=Arc::new(move||active.healthy() && passive.as_ref().is_none_or(|cfg|cfg.max_fails>=0 && host.fails(tokio::time::Instant::now())<(cfg.max_fails as u64)));
            (Arc::from(endpoint.config.dial.as_str()),probe)
        }).collect()
    }

    pub(super) fn new(registry: &HostRegistry, policy: &Selection, upstreams: &[Upstream]) -> Self {
        Self {
            pool: registry.resolve(upstreams),
            policy: Arc::new(Policy::new(policy)),
            passive: None,
        }
    }
    pub(super) fn new_health(
        registry: &HostRegistry,
        policy: &Selection,
        upstreams: &[Upstream],
        passive: Option<PassiveCfg>,
    ) -> Self {
        let mut prepared = Self::new(registry, policy, upstreams);
        for endpoint in &mut prepared.pool {
            endpoint.passive = passive.clone();
        }
        prepared.passive = passive;
        prepared
    }
    pub(super) fn with_upstreams(
        &self,
        registry: &HostRegistry,
        upstreams: &[Upstream],
    ) -> anyhow::Result<Self> {
        let mut pool = registry.resolve_dynamic(upstreams)?;
        for endpoint in &mut pool {
            endpoint.passive = self.passive.clone();
        }
        Ok(Self {
            pool,
            policy: self.policy.clone(),
            passive: self.passive.clone(),
        })
    }
    pub(super) fn active_states(&self) -> Vec<Arc<ActiveState>> {
        self.pool.iter().map(|e| e.active.clone()).collect()
    }
    pub(super) fn needs_worker(&self, input: &SelectionInput<'_>) -> bool {
        let host_work = self.pool.iter().fold(0usize, |total, e| {
            total.saturating_add(e.host.work_units().saturating_mul(64))
        });
        self.policy
            .work(self.pool.len(), input)
            .saturating_add(host_work)
            > 32 * 1024
    }

    /// Re-select only before an upstream request exists. A racing contender
    /// can consume the sampled slot; it does not turn a dial into a replay.
    pub(super) fn select(&self, input: &SelectionInput<'_>) -> anyhow::Result<Option<Selected>> {
        for _ in 0..self.pool.len().clamp(1, 8) {
            let mut cookies = Vec::new();
            let Some(index) = self.policy.select(&self.pool, input, &mut cookies)? else {
                return Ok(None);
            };
            let endpoint = &self.pool[index];
            if let Some((lease, prior_requests)) = endpoint.reserve() {
                return Ok(Some(Selected {
                    dial: endpoint.config.dial.clone(),
                    fails: endpoint.host.fails(tokio::time::Instant::now()),
                    host: endpoint.host.clone(),
                    max_requests: endpoint.capacity() as i64,
                    prior_requests,
                    lease,
                    cookies,
                }));
            }
        }
        Ok(None)
    }
}

type Tag = CtOutput<Hmac<Sha256>>;
enum Policy {
    Random,
    First,
    Least,
    RoundRobin(AtomicU32),
    Weighted(Vec<u64>, AtomicU64),
    RandomChoose(usize),
    Ip,
    ClientIp,
    Uri,
    Query(String, Box<Self>),
    Header(String, Box<Self>),
    Cookie(CookiePolicy),
}

struct CookiePolicy {
    name: String,
    secret: String,
    max_age_secs: u64,
    fallback: Box<Policy>,
}

impl Policy {
    fn new(policy: &Selection) -> Self {
        match policy {
            Selection::Random => Self::Random,
            Selection::First => Self::First,
            Selection::Least => Self::Least,
            Selection::RoundRobin => Self::RoundRobin(AtomicU32::new(0)),
            Selection::Weighted(weights) => Self::Weighted(weights.clone(), AtomicU64::new(0)),
            Selection::RandomChoose(k) => Self::RandomChoose(*k),
            Selection::Ip => Self::Ip,
            Selection::ClientIp => Self::ClientIp,
            Selection::Uri => Self::Uri,
            Selection::Query { key, fallback } => {
                Self::Query(key.clone(), Box::new(Self::new(fallback)))
            }
            Selection::Header { field, fallback } => {
                Self::Header(field.clone(), Box::new(Self::new(fallback)))
            }
            Selection::Cookie {
                name,
                secret,
                max_age_secs,
                fallback,
            } => Self::Cookie(CookiePolicy {
                name: name.clone(),
                secret: secret.clone(),
                max_age_secs: *max_age_secs,
                fallback: Box::new(Self::new(fallback)),
            }),
        }
    }

    fn work(&self, pool: usize, input: &SelectionInput<'_>) -> usize {
        let hash = |bytes: usize| pool.saturating_mul(bytes.saturating_add(64));
        match self {
            Self::Ip | Self::ClientIp => hash(64),
            Self::Uri => hash(
                input
                    .uri
                    .path_and_query()
                    .map_or(1, |p| p.as_str().len())
                    .saturating_add(input.authority.len()),
            ),
            Self::Query(_, fallback) => hash(input.uri.query().map_or(0, str::len))
                .saturating_add(fallback.work(pool, input)),
            Self::Header(field, fallback) => input
                .headers
                .get(field.as_str())
                .filter(|v| !v.is_empty())
                .map_or_else(|| fallback.work(pool, input), |v| hash(v.len()))
                .max(if field == "Host" {
                    hash(input.authority.len())
                } else {
                    0
                }),
            Self::Cookie(cookie) => hash(32)
                .saturating_add(
                    input
                        .headers
                        .get_all(header::COOKIE)
                        .iter()
                        .map(HeaderValue::len)
                        .sum::<usize>(),
                )
                .saturating_add(cookie.fallback.work(pool, input)),
            Self::RandomChoose(_) => pool.saturating_mul(256),
            Self::Random | Self::Least | Self::RoundRobin(_) | Self::Weighted(..) | Self::First => {
                pool.saturating_mul(16)
            }
        }
    }

    fn select(
        &self,
        pool: &[Endpoint],
        input: &SelectionInput<'_>,
        cookies: &mut Vec<HeaderValue>,
    ) -> anyhow::Result<Option<usize>> {
        let available = || {
            pool.iter()
                .enumerate()
                .filter(|(_, endpoint)| endpoint.available())
        };
        match self {
            Self::First => Ok(available().next().map(|(i, _)| i)),
            Self::Random => {
                let count = available().count();
                if count == 0 {
                    return Ok(None);
                }
                Ok(available()
                    .nth(random_below(count)?)
                    .or_else(|| available().next())
                    .map(|(i, _)| i))
            }
            Self::Least => least(available(), false),
            Self::RoundRobin(robin) => {
                for _ in pool {
                    let seq = robin.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                    let i = seq as usize % pool.len();
                    if pool[i].available() {
                        return Ok(Some(i));
                    }
                }
                Ok(None)
            }
            Self::Weighted(weights, robin) => {
                // If an endpoint is temporarily full, the remaining configured
                // weights still apply. Keep the common snapshot to one pass
                // over live atomics and never index past the configured pool.
                let entries: Vec<_> = available()
                    .filter_map(|(i, _)| {
                        let w = weights.get(i).copied().unwrap_or(0);
                        (w > 0).then_some((i, w))
                    })
                    .collect();
                let total: u64 = entries.iter().map(|(_, w)| w).sum();
                if total == 0 {
                    return Ok(None);
                }
                let mut ticket = robin.fetch_add(1, Ordering::Relaxed).wrapping_add(1) % total;
                for (i, w) in entries {
                    if ticket < w {
                        return Ok(Some(i));
                    }
                    ticket -= w;
                }
                Ok(None)
            }
            Self::RandomChoose(choose) => {
                let k = (*choose).min(pool.len());
                let mut subset = Vec::with_capacity(k);
                for (seen, entry) in available().enumerate() {
                    if subset.len() < k {
                        subset.push(entry);
                    } else {
                        let replacement = random_below(seen + 1)?;
                        if replacement < k {
                            subset[replacement] = entry;
                        }
                    }
                }
                least(subset.into_iter(), true)
            }
            Self::Ip => Ok(by_hash(pool, input.peer_ip)),
            Self::ClientIp => Ok(by_hash(pool, input.client_ip.as_bytes())),
            Self::Uri => {
                if ((matches!(input.version, Version::HTTP_10 | Version::HTTP_11))
                    && input.uri.scheme().is_some())
                    || input.uri.path_and_query().is_none()
                {
                    Ok(by_hash(pool, input.uri.to_string().as_bytes()))
                } else {
                    Ok(by_hash(
                        pool,
                        input
                            .uri
                            .path_and_query()
                            .expect("checked")
                            .as_str()
                            .as_bytes(),
                    ))
                }
            }
            Self::Query(key, fallback) => {
                let values = query_value(
                    input.uri.query().unwrap_or_default().as_bytes(),
                    key.as_bytes(),
                );
                if values.is_empty() {
                    fallback.select(pool, input, cookies)
                } else {
                    Ok(by_hash(pool, &values))
                }
            }
            Self::Header(field, fallback) => {
                let value = if field == "Host" {
                    Some(input.authority.as_bytes())
                } else if field.eq_ignore_ascii_case("Host")
                    || field.eq_ignore_ascii_case("Transfer-Encoding")
                {
                    None
                } else {
                    input.headers.get(field.as_str()).map(HeaderValue::as_bytes)
                };
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    Ok(by_hash(pool, value))
                } else {
                    fallback.select(pool, input, cookies)
                }
            }
            Self::Cookie(policy) => policy.select(pool, input, cookies),
        }
    }
}

impl CookiePolicy {
    fn tag(&self, dial: &str) -> Tag {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(dial.as_bytes());
        mac.finalize()
    }
    fn select(
        &self,
        pool: &[Endpoint],
        input: &SelectionInput<'_>,
        cookies: &mut Vec<HeaderValue>,
    ) -> anyhow::Result<Option<usize>> {
        if let Some(incoming) =
            cookie_value(input.headers, self.name.as_bytes()).and_then(parse_tag)
        {
            for (i, endpoint) in pool.iter().enumerate() {
                if endpoint.available() && incoming == self.tag(&endpoint.config.dial) {
                    return Ok(Some(i));
                }
            }
        }
        let Some(i) = self.fallback.select(pool, input, cookies)? else {
            return Ok(None);
        };
        // net/http silently omits an invalid cookie name; still select the
        // fallback backend, without serializing untrusted control bytes.
        if http::HeaderName::from_bytes(self.name.as_bytes()).is_err() {
            return Ok(Some(i));
        }
        let mut value = String::with_capacity(self.name.len() + 130);
        value.push_str(&self.name);
        value.push('=');
        use std::fmt::Write as _;
        for b in self.tag(&pool[i].config.dial).into_bytes() {
            write!(value, "{b:02x}").expect("String write");
        }
        value.push_str("; Path=/");
        if self.max_age_secs != 0 {
            write!(value, "; Max-Age={}", self.max_age_secs).expect("String write");
        }
        value.push_str(if input.secure {
            "; HttpOnly; Secure; SameSite=None"
        } else {
            "; HttpOnly; SameSite=Lax"
        });
        let mut field = HeaderValue::from_str(&value)?;
        field.set_sensitive(true);
        cookies.push(field);
        Ok(Some(i))
    }
}

fn least<'a>(
    entries: impl Iterator<Item = (usize, &'a Endpoint)>,
    first_zero: bool,
) -> anyhow::Result<Option<usize>> {
    let mut best = None;
    let mut count = u64::MAX;
    let mut ties = 0;
    for (i, entry) in entries {
        let active = entry.host.running.load(Ordering::Acquire);
        if first_zero && active == 0 {
            return Ok(Some(i));
        }
        if active < count {
            count = active;
            best = Some(i);
            ties = 1;
        } else if active == count {
            ties += 1;
            if random_below(ties)? == 0 {
                best = Some(i);
            }
        }
    }
    Ok(best)
}

fn by_hash(pool: &[Endpoint], key: &[u8]) -> Option<usize> {
    let mut best = None;
    let mut high = 0;
    for (i, endpoint) in pool.iter().enumerate() {
        if !endpoint.available() {
            continue;
        }
        let mut hash = Xxh64::new(0);
        hash.update(endpoint.config.dial.as_bytes());
        hash.update(key);
        let score = hash.digest();
        if score > high {
            high = score;
            best = Some(i);
        }
    }
    best
}

pub(super) fn random_below(bound: usize) -> anyhow::Result<usize> {
    if bound <= 1 {
        return Ok(0);
    }
    // Rejection sampling avoids bias from a modulo unless the range divides
    // u64 exactly. No cross-request RNG lock or per-handler RNG state.
    let bound = bound as u64;
    let accepted = u64::MAX - u64::MAX % bound;
    loop {
        let mut bytes = [0u8; 8];
        static RANDOM: std::sync::LazyLock<&'static dyn rustls::crypto::SecureRandom> =
            std::sync::LazyLock::new(|| crate::crypto::provider().secure_random);
        RANDOM
            .fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("upstream selection entropy unavailable"))?;
        let v = u64::from_le_bytes(bytes);
        if v < accepted {
            return Ok((v % bound) as usize);
        }
    }
}

fn query_value(query: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut seen = false;
    for part in query.split(|&b| b == b'&') {
        if part.is_empty() || part.contains(&b';') {
            continue;
        }
        let (name, raw) = part
            .iter()
            .position(|&b| b == b'=')
            .map_or((part, &[][..]), |i| (&part[..i], &part[i + 1..]));
        if decode_query(name).is_none_or(|name| name != key) {
            continue;
        }
        let Some(value) = decode_query(raw) else {
            continue;
        };
        if seen {
            result.push(b',');
        }
        result.extend_from_slice(&value);
        seen = true;
    }
    result
}

fn decode_query(raw: &[u8]) -> Option<std::borrow::Cow<'_, [u8]>> {
    if !raw.iter().any(|&b| matches!(b, b'%' | b'+')) {
        return Some(raw.into());
    }
    let mut result = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => result.push(b' '),
            b'%' => {
                result.push(hex(*raw.get(i + 1)?)? << 4 | hex(*raw.get(i + 2)?)?);
                i += 2;
            }
            other => result.push(other),
        }
        i += 1;
    }
    Some(result.into())
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(super) fn cookie_value<'a>(headers: &'a HeaderMap, name: &[u8]) -> Option<&'a [u8]> {
    for field in headers.get_all(header::COOKIE).iter() {
        for pair in field.as_bytes().split(|&b| b == b';') {
            let pair = pair.trim_ascii();
            let Some(split) = pair.iter().position(|&b| b == b'=') else {
                continue;
            };
            if pair[..split].trim_ascii() != name {
                continue;
            }
            let mut value = &pair[split + 1..];
            if value.len() >= 2 && value.first() == Some(&b'"') && value.last() == Some(&b'"') {
                value = &value[1..value.len() - 1];
            }
            if value
                .iter()
                .all(|&b| (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b';' | b'\\'))
            {
                return Some(value);
            }
        }
    }
    None
}

fn parse_tag(value: &[u8]) -> Option<Tag> {
    if value.len() != 64 || value.iter().any(u8::is_ascii_uppercase) {
        return None;
    }
    let mut tag = hmac::digest::Output::<Hmac<Sha256>>::default();
    for (i, b) in value.as_chunks::<2>().0.iter().enumerate() {
        tag[i] = hex(b[0])? << 4 | hex(b[1])?;
    }
    Some(CtOutput::new(tag))
}

pub(super) fn with_lease(body: Body, lease: Arc<RequestLease>) -> Body {
    if hyper::body::Body::is_end_stream(&body) {
        return body;
    }
    LeaseBody {
        body,
        lease: Some(lease),
    }
    .boxed_unsync()
}

struct LeaseBody {
    body: Body,
    lease: Option<Arc<RequestLease>>,
}
impl hyper::body::Body for LeaseBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) || self.body.is_end_stream() {
            self.lease.take();
        }
        frame
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
