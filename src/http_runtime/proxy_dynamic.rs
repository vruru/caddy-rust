// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Bounded, owned A/SRV/Multi sources with request-independent lookup state.
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, anyhow, bail, ensure};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts,
    ServerOrderingStrategy,
};
use hickory_resolver::proto::rr::{RData, RecordType};
use tokio::sync::{Semaphore, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::proxy_dns_exchange::{Dial, Exchange, Source};
use super::proxy_dns_ip::Address as DnsIp;
use super::proxy_dns_runtime::{DialBudget, TrackedRuntime, dial_budget};
use super::proxy_policy::{Upstream, random_below};
use crate::http_config::proxy_ext::{DynamicCfg, IpVersions};

pub(crate) const MAX_ENDPOINTS: usize = 4096;
const CACHE_KEYS: usize = 100;
const CACHE_BYTES: usize = 1 << 20;
const MAX_INFLIGHT: usize = CACHE_KEYS;
const MAX_MULTI_DEPTH: usize = 8;
const LOOKUP_DEADLINE: Duration = Duration::from_secs(30);
const STOPPED: &str = "dynamic upstreams: DNS runtime stopped";
const SYS_RECHECK: Duration = Duration::from_secs(5);
const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_CONF_MAX: u64 = 64 << 10;
pub(crate) type GlobalExpand = Arc<dyn Fn(&str) -> Result<String> + Send + Sync>;

type Dns = Resolver<TrackedRuntime>;
type Expander<'a> = dyn Fn(&str) -> Result<String> + 'a;
pub(crate) type GetFuture = Pin<Box<dyn Future<Output = Result<Vec<Upstream>>> + Send + 'static>>;
pub(crate) type EventHook = Arc<dyn Fn(Level, &str) + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Warn,
    Error,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DnsLimits {
    pub(crate) lookup_concurrency: usize,
    pub(crate) max_queued: usize,
}

impl Default for DnsLimits {
    fn default() -> Self {
        Self {
            lookup_concurrency: 64,
            max_queued: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// shared DNS state
// ---------------------------------------------------------------------------

pub(crate) struct DnsShared {
    tasks: TaskTracker,
    stop: CancellationToken,
    bg_slots: Arc<Semaphore>,
    bg_rejected: Arc<AtomicU64>,
    lookup_slots: Semaphore,
    queue_slots: Arc<Semaphore>,
    sys: Mutex<SysState>,
    sys_serial: Arc<Semaphore>,
    config_io: super::resource_budget::BlockingBudget,
    global: GlobalExpand,
    hook: Option<EventHook>,
    retained_owner:Option<Arc<dyn crate::cert_cpu::MaterialOwner>>,
}

// ---------------------------------------------------------------------------
// Hosts File Snapshot (RFC6724 Ordering Preservation)
// ---------------------------------------------------------------------------

pub(crate) struct HostSnapshot {
    /// File-order list of IPs per hostname.
    /// Key: ASCII-lowercase name (with trailing dot applied for qualified names).
    /// Unix: Some(map). Non-Unix: None.
    ordered: Option<HashMap<String, Vec<DnsIp>>>,
    order: super::proxy_nss::Order,
    /// Fallback for non-Unix systems (uses Hickory's Hosts implementation).
    fallback: Option<Arc<hickory_resolver::Hosts>>,
    retained_owner:Option<Arc<dyn crate::cert_cpu::MaterialOwner>>,
}

/// Mimics Go's `net` hostname normalization for `/etc/hosts` lookup.
/// 1. Lowercase ASCII.
/// 2. Add trailing dot if string contains a dot and does not end with one.
///    Literal IPs are handled separately by the caller (returning None in static_ips).
fn go_host_key(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    if lower.contains('.') && !lower.ends_with('.') {
        format!("{}.", lower)
    } else {
        lower
    }
}

struct SysConf {
    search: Arc<[String]>,
    single_request: bool,
    no_reload: bool,
    ndots: usize,
    opts: ResolverOpts,
    hosts: Arc<HostSnapshot>,
    servers: Arc<[SocketAddr]>,
    use_tcp: bool,
    rotate: Option<Arc<AtomicU32>>,
    retained_owner:Option<Arc<dyn crate::cert_cpu::MaterialOwner>>,
}

#[derive(Clone)]
struct GoConf {
    search: Vec<String>,
    single_request: bool,
    no_reload: bool,
    retry_config: bool,
    servers: Vec<SocketAddr>,
    use_tcp: bool,
    rotate: bool,
}

impl GoConf {
    fn default_ns() -> Self {
        let servers = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
        .map(|ip| SocketAddr::new(ip, 53))
        .to_vec();
        Self {
            search: Vec::new(),
            single_request: false,
            no_reload: false,
            retry_config: false,
            servers,
            use_tcp: false,
            rotate: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stamp {
    Unknown,
    Missing,
    File(Option<SystemTime>, u64),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ConfigStamp {
    resolv: Stamp,
    hosts: Stamp,
    nss: Stamp,
}

#[derive(Default)]
struct SysState {
    checked: Option<Instant>,
    stamp: Option<ConfigStamp>,
    conf: Option<Arc<SysConf>>,
    err: Option<String>,
}

#[derive(Clone)]
struct DnsSpec {
    addrs: Option<Vec<String>>,
    dial_ns: i64,
    fallback_ns: i64,
}

struct NetAddr {
    unix: Option<super::proxy_dns_unix::Kind>,
    tcp: bool,
    family: Option<u8>,
    host: String,
    port: u16,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl DnsShared {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tasks: TaskTracker,
        stop: CancellationToken,
        bg_slots: Arc<Semaphore>,
        bg_rejected: Arc<AtomicU64>,
        limits: DnsLimits,
        global: GlobalExpand,
        config_io: super::resource_budget::BlockingBudget,
        hook: Option<EventHook>,
    ) -> Result<Arc<Self>> {
        ensure!(
            limits.lookup_concurrency > 0 && limits.max_queued >= limits.lookup_concurrency,
            "dns limits: need 0 < lookup_concurrency <= max_queued"
        );
        Ok(Arc::new(Self {
            retained_owner:None,
            tasks,
            stop,
            bg_slots,
            bg_rejected,
            lookup_slots: Semaphore::new(limits.lookup_concurrency),
            queue_slots: Arc::new(Semaphore::new(limits.max_queued)),
            sys: Mutex::new(SysState::default()),
            sys_serial: Arc::new(Semaphore::new(1)),
            config_io,
            global,
            hook,
        }))
    }
    pub(crate) fn with_retained_owner(mut self:Arc<Self>,owner:Arc<dyn crate::cert_cpu::MaterialOwner>)->Result<Arc<Self>> {
        Arc::get_mut(&mut self).ok_or_else(||anyhow!("DNS owner must bind before sharing"))?.retained_owner=Some(owner);Ok(self)
    }
    async fn configuration<T,F>(&self,operation:F)->Result<T,super::resource_budget::BudgetError>
    where T:Send+'static,F:FnOnce()->T+Send+'static {
        if let Some(owner)=&self.retained_owner {
            let held=self.config_io.run_retained(owner.clone(),operation).await?;
            // This private handoff is only used below: persistent SysConf and
            // HostSnapshot attach this same owner; scalar/address intermediates
            // stay inside a retained lookup/transport future.
            Ok(held.into_configuration())
        }else {self.config_io.run(operation).await}
    }
    /// Closed ACME TXT consumer; it has independent lookup/background gates and
    /// reuses the exact custom/system resolver, network and search semantics.
    pub(crate) async fn lookup_txt(self:&Arc<Self>,name:&str,resolvers:&[String])->Result<Vec<Vec<u8>>> {
        let _queued=self.queue_slots.clone().try_acquire_owned().map_err(|_|anyhow!("ACME DNS queue capacity exceeded"))?;
        let _lookup=self.lookup_slots.acquire().await.map_err(|_|anyhow!(STOPPED))?;
        let spec=DnsSpec{addrs:(!resolvers.is_empty()).then(||resolvers.to_vec()),dial_ns:30_000_000_000,fallback_ns:300_000_000};
        let (resolver,sys)=self.resolver_for(&spec,IpVer::Any).await?;
        let lookup=lookup_record(&resolver,&sys,name,RecordType::TXT).await?;
        let owner=self.retained_owner.as_ref().ok_or_else(||anyhow!("ACME TXT material owner unavailable"))?;
        owner.reserve(4096*std::mem::size_of::<Vec<u8>>())?;
        let mut values=Vec::new();values.try_reserve_exact(4096)?;let mut total=0usize;
        for record in lookup.answers() {if let RData::TXT(txt)=&record.data {
            owner.reserve(0)?;
            ensure!(values.len()<4096,"ACME DNS TXT count exceeded");let mut value=Vec::new();
            for segment in &txt.txt_data {
                total=total.checked_add(segment.len()).ok_or_else(||anyhow!("ACME DNS TXT capacity exceeded"))?;
                let length=value.len().checked_add(segment.len()).ok_or_else(||anyhow!("ACME DNS TXT capacity exceeded"))?;
                ensure!(length<=65535&&total<=1024*1024,"ACME DNS TXT size exceeded");
                if length>value.capacity() {
                    let capacity=length.max(value.capacity().saturating_mul(2)).max(256).min(65535);
                    owner.reserve(capacity)?;value.try_reserve_exact(capacity-value.len())?;
                }
                value.extend_from_slice(segment);
            }
            values.push(value);
        }}Ok(values)
    }

    pub(super) fn close(&self) {
        self.stop.cancel();
        self.tasks.close();
    }
    /// Cancels all lookups and hickory background tasks, then waits for them to finish.
    pub(crate) async fn shutdown(&self) {
        self.stop.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }

    pub(crate) fn rejected_background_spawns(&self) -> u64 {
        self.bg_rejected.load(Ordering::Relaxed)
    }

    fn emit(&self, level: Level, msg: &str) {
        if let Some(h) = &self.hook {
            h(level, msg);
        }
    }

    fn build(
        &self,
        cfg: ResolverConfig,
        opts: &ResolverOpts,
        ver: IpVer,
        dial_ns: i64,
        source: Exchange,
    ) -> Result<Arc<Dns>> {
        let rt = TrackedRuntime::new(
            self.tasks.clone(),
            self.stop.clone(),
            self.bg_slots.clone(),
            self.bg_rejected.clone(),
        )
        .with_retained_owner(self.retained_owner.clone())
        .with_dial_timeout(dial_ns)
        .with_custom(source)
        .with_exchange_leg(opts.timeout);
        let mut b = Dns::builder_with_config(cfg, rt);
        let o = b.options_mut();
        *o = opts.clone();
        o.cache_size = 0;
        // The Go attempts x servers loop lives in ExchangeStream; Hickory must not re-send.
        o.attempts = 0;
        o.num_concurrent_reqs = 1;
        o.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        // Pure-Go net.Resolver advertises EDNS even without resolv.conf edns0.
        // Go's only special-use DNS suppression is handled by our nameList.
        // Honor configured servers for ordinary .invalid/.localhost names.
        o.allow_special_use_queries = true;
        o.edns0 = true;
        o.edns_payload_len = 1232;
        o.ip_strategy = ver.strategy();
        // ResolverBuilder otherwise reads /etc/hosts synchronously here.
        // We manage hosts explicitly via HostSnapshot.
        o.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        // One request spans the whole Go loop.
        o.timeout = LOOKUP_DEADLINE;
        // A + AAAA of a single lookup
        o.max_active_requests = 2;
        o.case_randomization = false;
        let resolver = b
            .build()
            .map_err(|e| anyhow!("building DNS resolver: {e}"))?;
        Ok(Arc::new(resolver))
    }

    /// Global-only expansion + Caddy `ParseNetworkAddressWithDefaults(v, "udp", 53)`.
    fn custom_addrs(&self, raw: &[String]) -> Result<Vec<NetAddr>> {
        ensure!(
            !raw.is_empty(),
            "resolver: at least one address is required"
        );
        raw.iter()
            .map(|a| {
                let v = (self.global)(a).map_err(|e| anyhow!("resolver address {a:?}: {e:#}"))?;
                parse_net_addr(&v)
            })
            .collect()
    }

    /// Go `resolverConfig.tryUpdate`: stat at most every 5s, one refresher; no lock during IO.
    async fn sys_conf(&self) -> Result<Arc<SysConf>> {
        let now = Instant::now();
        {
            let st = lock(&self.sys);
            if st
                .checked
                .is_some_and(|t| now.duration_since(t) < SYS_RECHECK)
            {
                if let Some(conf) = &st.conf {
                    return Ok(conf.clone());
                }
                if let Some(error) = &st.err {
                    return Err(anyhow!("{error}"));
                }
            }
        }
        // A lookup already owns the bounded lookup slot; this is a single
        // refresher permit rather than a mutex held over configuration I/O.
        let _serial = match self.sys_serial.try_acquire() {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                if let Some(conf) = lock(&self.sys).conf.clone() { return Ok(conf); }
                self.sys_serial.acquire().await.map_err(|_| anyhow!(STOPPED))?
            }
            Err(tokio::sync::TryAcquireError::Closed) => return Err(anyhow!(STOPPED)),
        };
        let (prior_stamp, prior) = {
            let st = lock(&self.sys);
            if st
                .checked
                .is_some_and(|t| now.duration_since(t) < SYS_RECHECK)
            {
                if let Some(conf) = &st.conf {
                    return Ok(conf.clone());
                }
                if let Some(error) = &st.err {
                    return Err(anyhow!("{error}"));
                }
            }
            (st.stamp, st.conf.clone())
        };
        let retained_owner=self.retained_owner.clone();
        // Closed owner mode prepays bounded resolv/NSS parse state before I/O.
        if let Some(owner)=&retained_owner {owner.reserve(8*1024*1024)?;}
        let (stamp, read) =
            self.configuration(move || {
                    let mut stamp = ConfigStamp {
                        resolv: stat_resolv_conf(),
                        hosts: stat_hosts(),
                        nss: stat_nss(),
                    };
                    let read = if stamp.resolv != Stamp::Unknown
                        && stamp.hosts != Stamp::Unknown
                        && stamp.nss != Stamp::Unknown
                        && prior_stamp == Some(stamp)
                    {
                        None
                    } else {
                        let settings = match prior.as_ref().filter(|old| old.no_reload
                            || (stamp.resolv != Stamp::Unknown && prior_stamp.is_some_and(|p| p.resolv == stamp.resolv))) {
                            Some(old) => Ok((old.opts.clone(), GoConf {
                                search: old.search.to_vec(),
                                single_request: old.single_request,
                                no_reload: old.no_reload,
                                retry_config: false,
                                servers: old.servers.to_vec(),
                                use_tcp: old.use_tcp,
                                rotate: old.rotate.is_some(),
                            }, old.rotate.clone())),
                            None => read_sys(stamp.resolv).map(|(opts, go)| (opts, go, None)),
                        };
                        Some(settings.and_then(|(opts, go, rotate)| {
                            if go.retry_config { stamp.resolv = Stamp::Unknown; }
                            let (order, nss_retry) = read_nss();
                            if nss_retry { stamp.nss = Stamp::Unknown; }
                            let (mut hosts, hosts_retry) = if order == super::proxy_nss::Order::DnsOnly {
                                (HostSnapshot { ordered: Some(HashMap::new()), fallback: None, order,retained_owner:retained_owner.clone() }, false)
                            } else { read_hosts(retained_owner.as_ref())? };
                            if hosts_retry { stamp.hosts = Stamp::Unknown; }
                            hosts.order = order;
                            Ok((opts, go, Arc::new(hosts), rotate))
                        }))
                    };
                    (stamp, read)
                })
                .await
                .map_err(|_| anyhow!("system DNS configuration worker unavailable"))?;
        let mut st = lock(&self.sys);
        st.checked = Some(Instant::now());
        match read {
            None => st
                .conf
                .clone()
                .ok_or_else(|| anyhow!("system DNS configuration unavailable")),
            Some(Ok((opts, go, hosts, rotate))) => {
                let conf = Arc::new(SysConf {
                    retained_owner:self.retained_owner.clone(),
                    search: go.search.into(),
                    single_request: go.single_request,
                    no_reload: go.no_reload,
                    ndots: opts.ndots,
                    opts,
                    hosts,
                    servers: go.servers.into(),
                    use_tcp: go.use_tcp,
                    rotate: go.rotate.then(|| rotate.unwrap_or_else(|| Arc::new(AtomicU32::new(0)))) ,
                });
                st.stamp = Some(stamp);
                st.conf = Some(conf.clone());
                st.err = None;
                Ok(conf)
            }
            Some(Err(error)) => {
                let message = error.to_string();
                st.err = Some(message.clone());
                let previous = st.conf.clone();
                drop(st);
                self.emit(Level::Warn, "system DNS configuration read failed");
                previous.ok_or_else(|| anyhow!("{message}"))
            }
        }
    }

    #[cfg(not(target_vendor = "apple"))]
    fn system_resolver(&self, sys: &SysConf, ver: IpVer) -> Result<Arc<Dns>> {
        self.logical_resolver(sys, ver, None)
    }

    /// Never shared between lookups, so a shared stream can never report Busy.
    fn logical_resolver(&self, sys: &SysConf, ver: IpVer, dial: Option<Dial>) -> Result<Arc<Dns>> {
        let source = Arc::new(Source {
            servers: sys.servers.clone(),
            dial,
            attempts: sys.opts.attempts,
            use_tcp: sys.use_tcp,
            rotate: sys.rotate.clone(),
        });
        let logical =
            NameServerConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST), true, vec![conn(true, 53)]);
        let cfg = ResolverConfig::from_parts(
            None,
            vec![],
            vec![logical],
        );
        self.build(cfg, &sys.opts, ver, 0, source)
    }

    /// Called on every cache miss inside the bounded lookup lane.
    async fn resolver_for(
        self: &Arc<Self>,
        dns: &DnsSpec,
        ver: IpVer,
    ) -> Result<(Arc<Dns>, Arc<SysConf>)> {
        let sys = self.sys_conf().await?;
        let dial = dns.addrs.is_some().then(|| {
            let weak = Arc::downgrade(self);
            let spec = dns.clone();
            let dial: Dial = Arc::new(move |query_deadline| {
                let weak = weak.clone();
                let spec = spec.clone();
                Box::pin(async move {
                    let shared = weak
                        .upgrade()
                        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Interrupted, STOPPED))?;
                    let stop = shared.stop.clone();
                    tokio::select! {biased;
                        _=stop.cancelled()=>Err(std::io::Error::new(std::io::ErrorKind::Interrupted,STOPPED)),
                        result=shared.dial_nameserver(&spec, query_deadline)=>result.map_err(|error|std::io::Error::other(format!("{error:#}"))),
                    }
                })
            });
            dial
        });
        Ok((self.logical_resolver(&sys, ver, dial)?, sys))
    }

    async fn dial_nameserver(
        &self,
        spec: &DnsSpec,
        query_deadline: Option<Instant>,
    ) -> Result<super::proxy_dns_socket::DnsSocket> {
        let deadline = match dial_budget(spec.dial_ns) {
            DialBudget::Expired => bail!("dial DNS server: i/o timeout"),
            DialBudget::None => None,
            DialBudget::Cap(duration) => Some(
                Instant::now()
                    .checked_add(duration)
                    .ok_or_else(|| anyhow!("DNS dial timeout exceeds monotonic clock range"))?,
            ),
        };
        let deadline = match (deadline, query_deadline) {
            (Some(dial), Some(query)) => Some(dial.min(query)),
            (dial, query) => dial.or(query),
        };
        let operation = async {
            let addrs = self.custom_addrs(
                spec.addrs
                    .as_deref()
                    .ok_or_else(|| anyhow!("custom DNS addresses unavailable"))?,
            )?;
            let chosen = &addrs[rnd(addrs.len() as u64)? as usize];
            if let Some(kind) = chosen.unix {
                return Ok(super::proxy_dns_unix::connect(&chosen.host, kind, "127.0.0.1:53".parse().unwrap()).await?);
            }
            let sys = self.sys_conf().await?;
            let ips = match DnsIp::parse(&chosen.host) {
                Some(ip) => vec![ip],
                None => self.resolve_ns_host(&sys, chosen, spec.dial_ns).await?,
            };
            let addresses = self.ip_addresses(ips, chosen.port, chosen.family, true).await?;
            ensure!(
                !addresses.is_empty(),
                "DNS server has no suitable addresses"
            );
            #[cfg(not(target_vendor = "apple"))]
            let addresses = self.order_addresses(addresses).await?;
            let logical = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
            Ok::<_, anyhow::Error>(
                super::proxy_dns_dial::connect(
                    addresses,
                    chosen.tcp,
                    chosen.family,
                    spec.fallback_ns,
                    deadline,
                    logical,
                )
                .await?,
            )
        };
        match deadline {
            Some(deadline) => {
                tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation)
                    .await
                    .map_err(|_| anyhow!("dial DNS server: i/o timeout"))?
            }
            None => operation.await,
        }
    }

    async fn ip_addresses(&self, ips: Vec<DnsIp>, port: u16, version: Option<u8>, zones: bool) -> Result<Vec<SocketAddr>> {
        if zones && ips.iter().any(|ip| ip.zone.is_some()) {
            self.configuration(move || ips.into_iter().filter_map(|ip| {
                super::proxy_dns_dial::family(ip.socket(port), version)
            }).collect()).await.map_err(|_| anyhow!("DNS zone selection worker unavailable"))
        } else {
            Ok(ips.into_iter().filter_map(|ip| {
                super::proxy_dns_dial::family(SocketAddr::new(ip.ip, port), version)
            }).collect())
        }
    }

    async fn order_addresses(&self, addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>> {
        if addresses.len() < 2 {
            return Ok(addresses);
        }
        self.configuration(move || {
                let mut entries: Vec<_> = addresses
                    .into_iter()
                    .map(|address| {
                        let local = if address.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        };
                        let source = std::net::UdpSocket::bind(local)
                            .and_then(|socket| {
                                socket.connect(address)?;
                                socket.local_addr()
                            })
                            .ok()
                            .map(|address| address.ip());
                        (address, source)
                    })
                    .collect();
                entries.sort_by(|a, b| {
                    super::proxy_dns_addrselect::compare(&(a.0.ip(), a.1), &(b.0.ip(), b.1))
                });
                entries.into_iter().map(|(address, _)| address).collect()
            })
            .await
            .map_err(|_| anyhow!("DNS address selection worker unavailable"))
    }

    /// Go `Dialer.DialContext` name resolution: system resolver, family from network, within dial_timeout.
    async fn resolve_ns_host(
        &self,
        sys: &SysConf,
        a: &NetAddr,
        dial_ns: i64,
    ) -> Result<Vec<DnsIp>> {
        let ver = match a.family {
            Some(4) => IpVer::V4,
            Some(6) => IpVer::V6,
            _ => IpVer::Any,
        };
        #[cfg(not(target_vendor = "apple"))]
        let r = self.system_resolver(sys, ver)?;
        #[cfg(not(target_vendor = "apple"))]
        let fut = lookup_ips(&r, sys, &a.host);
        #[cfg(target_vendor = "apple")]
        let fut = async {
            let _ = (sys,ver);
            super::proxy_dns_native::lookup(&a.host,a.family).await.map_err(anyhow::Error::from)
        };
        let res = match dial_budget(dial_ns) {
            DialBudget::Expired => bail!("dial DNS server {:?}: i/o timeout", a.host),
            DialBudget::None => fut.await,
            DialBudget::Cap(d) => tokio::time::timeout(d, fut)
                .await
                .map_err(|_| anyhow!("dial DNS server {:?}: i/o timeout", a.host))?,
        }
        .map_err(|e| anyhow!("resolving DNS server {:?}: {e}", a.host))?;
        let ips = res;
        ensure!(
            ips.len() <= MAX_ENDPOINTS,
            "resolving DNS server {:?}: more than {MAX_ENDPOINTS} addresses",
            a.host
        );
        ensure!(
            !ips.is_empty(),
            "resolving DNS server {:?}: no addresses",
            a.host
        );
        Ok(ips)
    }
}

/// LookupIP's literal fast path precedes NSS. A hosts result is authoritative,
/// even when later family filtering leaves no suitable address.
async fn lookup_ips(resolver: &Dns, sys: &SysConf, name: &str) -> Result<Vec<DnsIp>> {
    if let Some(ip) = DnsIp::parse(name) { return Ok(vec![ip]); }
    let hosts = &sys.hosts;
    if hosts.order.files_first() {
        if let Some(ips) = static_ips(hosts, name)? { return Ok(ips); }
        if hosts.order == super::proxy_nss::Order::FilesOnly { bail!("no such host"); }
    }
    let mut error = None;
    let absolute = format!("{name}.");
    for candidate in super::proxy_dns_search::Names::new(name, &sys.search, sys.ndots) {
        if sys.single_request && matches!(resolver.options().ip_strategy, LookupIpStrategy::Ipv4AndIpv6) {
            let mut ips = Vec::new();
            // Both families are queried, in order, even when A already succeeds.
            for kind in [RecordType::A, RecordType::AAAA] {
                match resolver.lookup(candidate.clone(), kind).await {
                    Ok(answer) => {
                        for record in answer.answers() {
                            let ip = match &record.data {
                                RData::A(a) => Some(IpAddr::V4(a.0)),
                                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                ips.push(DnsIp::plain(ip));
                                if ips.len() > MAX_ENDPOINTS { return Ok(ips); }
                            }
                        }
                    }
                    Err(e) if error.is_none() || candidate == absolute => error = Some(anyhow!(e)),
                    Err(_) => {},
                }
            }
            if !ips.is_empty() { return Ok(ips); }
        } else {
            let original = candidate == absolute;
            match resolver.lookup_ip(candidate).await {
                Ok(answer) => {
                    let ips: Vec<_> = answer.iter().take(MAX_ENDPOINTS + 1).map(DnsIp::plain).collect();
                    if !ips.is_empty() { return Ok(ips); }
                }
                Err(e) if error.is_none() || original => error = Some(anyhow!(e)),
                Err(_) => {},
            }
        }
    }
    if hosts.order.files_last() && let Some(ips) = static_ips(hosts, name)? { return Ok(ips); }
    Err(error.unwrap_or_else(|| anyhow!("no such host")))
}

async fn lookup_record(resolver: &Dns, sys: &SysConf, name: &str, kind: RecordType) -> Result<hickory_resolver::lookup::Lookup> {
    let mut error = None;
    let absolute = format!("{name}.");
    for candidate in super::proxy_dns_search::Names::new(name, &sys.search, sys.ndots) {
        let original = candidate == absolute;
        match resolver.lookup(candidate, kind).await {
            Ok(answer) => return Ok(answer),
            Err(e) if error.is_none() || original => error = Some(anyhow!(e)),
            Err(_) => {},
        }
    }
    Err(error.unwrap_or_else(|| anyhow!("no such host")))
}

fn static_ips(hosts: &HostSnapshot, name: &str) -> Result<Option<Vec<DnsIp>>> {
    // If the name is a literal IP, return None so the caller (Leaf.lookup)
    // proceeds to the resolver's fast path (which handles literals efficiently).
    if name.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }

    // Unix path: File-ordered lookup
    if let Some(map) = &hosts.ordered {
        let key = go_host_key(name);
        return match map.get(&key) {
            Some(ips) => {
                // Independently cap the expanded address list. The input-file
                // byte limit does not bound the number of short repeated entries.
                ensure!(
                    ips.len() <= MAX_ENDPOINTS,
                    "system hosts: address limit exceeded for {name:?}"
                );
                Ok(Some(ips.clone()))
            }
            None => Ok(None),
        };
    }

    // Non-Unix fallback path: Use Hickory's Hosts implementation
    if let Some(h) = &hosts.fallback {
        return static_ips_legacy(h, name);
    }

    Ok(None)
}

/// Legacy implementation for non-Unix platforms using Hickory.
/// Kept as a helper to preserve original logic if fallback is active.
fn static_ips_legacy(hosts: &hickory_resolver::Hosts, name: &str) -> Result<Option<Vec<DnsIp>>> {
    use hickory_resolver::proto::{op::Query, rr::Name};
    // Non-Unix fallback uses Hickory name parsing.
    let name = Name::from_ascii(name)?;
    let mut ips = Vec::new();
    for kind in [RecordType::A, RecordType::AAAA] {
        if let Some(lookup) = hosts.lookup_static_host(&Query::query(name.clone(), kind)) {
            for record in lookup.answers() {
                let ip = match &record.data {
                    RData::A(ip) => IpAddr::V4(ip.0),
                    RData::AAAA(ip) => IpAddr::V6(ip.0),
                    _ => continue,
                };
                ensure!(
                    ips.len() < MAX_ENDPOINTS,
                    "system hosts address limit exceeded"
                );
                ips.push(DnsIp::plain(ip));
            }
        }
    }
    Ok((!ips.is_empty()).then_some(ips))
}

fn conn(tcp: bool, port: u16) -> ConnectionConfig {
    let mut c = if tcp {
        ConnectionConfig::tcp()
    } else {
        ConnectionConfig::udp()
    };
    c.port = port;
    c
}

fn stat_resolv_conf() -> Stamp {
    if !cfg!(all(
        unix,
        not(any(target_os = "android", target_vendor = "apple"))
    )) {
        return Stamp::Unknown;
    }
    match std::fs::metadata(RESOLV_CONF) {
        Ok(m) => Stamp::File(m.modified().ok(), m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Stamp::Missing,
        Err(_) => Stamp::Unknown,
    }
}

fn read_sys(stamp: Stamp) -> Result<(ResolverOpts, GoConf)> {
    let (mut cfg, mut opts, mut go) = read_sys_raw(stamp)?;
    if go.search.is_empty() {
        go.search = cfg.search().iter().map(|name| super::proxy_dns_search::rooted(&name.to_utf8())).collect();
        if go.search.is_empty() && let Some(domain) = cfg.domain() {
            go.search.push(super::proxy_dns_search::rooted(&domain.to_utf8()));
        }
    }
    cfg.name_servers.truncate(3);
    opts.attempts = opts.attempts.max(1);
    opts.timeout = opts.timeout.max(Duration::from_secs(1));
    opts.ndots = opts.ndots.min(15);
    ensure!(
        (1..=3).contains(&go.servers.len()),
        "internal: Go nameserver list out of range"
    );
    Ok((opts, go))
}

fn read_sys_raw(stamp: Stamp) -> Result<(ResolverConfig, ResolverOpts, GoConf)> {
    match stamp {
        Stamp::Missing => {
            let (cfg, opts) = go_default_conf();
            return Ok((cfg, opts, GoConf::default_ns()));
        }
        Stamp::File(_, len) if len > RESOLV_CONF_MAX => {
            bail!("{RESOLV_CONF} exceeds {RESOLV_CONF_MAX} bytes")
        }
        _ => {}
    }
    #[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
    {
        let data = match super::proxy_dns_file::read(RESOLV_CONF, RESOLV_CONF_MAX) {
            Ok(data) => data,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData) => return Err(error.into()),
            Err(error) => {
                let (cfg, opts) = go_default_conf();
                let mut go = GoConf::default_ns();
                go.retry_config = error.kind() != std::io::ErrorKind::NotFound;
                return Ok((cfg, opts, go));
            }
        };
        let go = go_scan(&data);
        let mut data = super::proxy_dns_search::without_search(&data);
        let (cfg, opts) = match hickory_resolver::system_conf::parse_resolv_conf(&data) {
            Ok(value) => value,
            Err(error) if matches!(&error, hickory_resolver::net::NetError::Io(io) if io.to_string() == "no nameservers found in config") =>
            {
                data.extend_from_slice(b"\nnameserver 127.0.0.1\nnameserver ::1\n");
                hickory_resolver::system_conf::parse_resolv_conf(&data)
                    .map_err(|error| anyhow!("reading system DNS configuration: {error}"))?
            }
            Err(error) => return Err(anyhow!("reading system DNS configuration: {error}")),
        };
        Ok((cfg, opts, go))
    }
    #[cfg(any(not(unix), target_os = "android", target_vendor = "apple"))]
    {
        let (cfg, opts) = hickory_resolver::system_conf::read_system_conf()
            .map_err(|e| anyhow!("reading system DNS configuration: {e}"))?;
        let servers: Vec<_> = cfg
            .name_servers
            .iter()
            .take(3)
            .map(|ns| SocketAddr::new(ns.ip, 53))
            .collect();
        let go = if servers.is_empty() {
            GoConf::default_ns()
        } else {
            GoConf {
                search: Vec::new(),
                single_request: false,
                no_reload: false,
                retry_config: false,
                servers,
                use_tcp: false,
                rotate: false,
            }
        };
        Ok((cfg, opts, go))
    }
}

/// Go `dnsReadConfig` subset: IP-only `nameserver` (first 3, port 53),
/// `options use-vc|usevc|tcp`, `options rotate`; no servers -> defaultNS.
#[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
fn go_scan(data: &[u8]) -> GoConf {
    let mut go = GoConf {
        search: Vec::new(),
        single_request: false,
        no_reload: false,
        retry_config: false,
        servers: Vec::new(),
        use_tcp: false,
        rotate: false,
    };
    for line in data.split(|&b| b == b'\n') {
        if matches!(line.first(), Some(b';' | b'#')) {
            continue;
        }
        let mut fields = line
            .split(|b| matches!(b, b' ' | b'\t' | b'\r'))
            .filter(|f| !f.is_empty());
        match fields.next() {
            Some(b"nameserver") => {
                if go.servers.len() < 3
                    && let Some(ip) = fields
                        .next()
                        .and_then(|f| std::str::from_utf8(f).ok())
                        .and_then(DnsIp::parse)
                {
                    go.servers.push(ip.socket(53));
                }
            }
            Some(b"domain") => {
                if let Some(name) = fields.next().and_then(|s| std::str::from_utf8(s).ok()) {
                    go.search = vec![super::proxy_dns_search::rooted(name)];
                }
            }
            Some(b"search") => {
                go.search = fields.filter_map(|s| std::str::from_utf8(s).ok())
                    .map(super::proxy_dns_search::rooted).filter(|s| s != ".").collect();
            }
            Some(b"options") => {
                for option in fields {
                    match option {
                        b"single-request" | b"single-request-reopen" => go.single_request = true,
                        b"no-reload" => go.no_reload = true,
                        b"rotate" => go.rotate = true,
                        b"use-vc" | b"usevc" | b"tcp" => go.use_tcp = true,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if go.servers.is_empty() {
        go.servers = GoConf::default_ns().servers;
    }
    go
}

fn stat_nss() -> Stamp {
    #[cfg(target_os = "linux")]
    match std::fs::metadata("/etc/nsswitch.conf") {
        Ok(metadata) => Stamp::File(metadata.modified().ok(), metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Stamp::Missing,
        Err(_) => Stamp::Unknown,
    }
    #[cfg(not(target_os = "linux"))]
    { Stamp::Missing }
}

/// The original pure-Go resolver falls back to files,dns on NSS I/O/parse error.
/// The byte cap bounds configuration work without disabling ordinary lookups.
fn read_nss() -> (super::proxy_nss::Order, bool) {
    #[cfg(target_os = "linux")]
    {
        match super::proxy_dns_file::read("/etc/nsswitch.conf", 64 << 10) {
            Ok(data) => (super::proxy_nss::parse(Some(&data)), false),
            Err(error) => (super::proxy_nss::Order::default(), error.kind() != std::io::ErrorKind::NotFound),
        }
    }
    #[cfg(not(target_os = "linux"))]
    { (super::proxy_nss::Order::default(), false) }
}

fn stat_hosts() -> Stamp {
    #[cfg(unix)]
    match std::fs::metadata("/etc/hosts") {
        Ok(metadata) => Stamp::File(metadata.modified().ok(), metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Stamp::Missing,
        Err(_) => Stamp::Unknown,
    }
    #[cfg(not(unix))]
    {
        Stamp::Unknown
    }
}

/// Called only by the bounded configuration I/O worker, never a reactor.
fn read_hosts(retained_owner:Option<&Arc<dyn crate::cert_cpu::MaterialOwner>>) -> Result<(HostSnapshot, bool)> {
    #[cfg(unix)]
    {
        const MAX: u64 = 1 << 20;
        if let Some(owner)=retained_owner {owner.reserve(2*1024*1024)?;}
        let data = match super::proxy_dns_file::read("/etc/hosts", MAX) {
            Ok(data) => data,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied) => {
                return Ok((HostSnapshot {
                    retained_owner:retained_owner.cloned(),
                    ordered: Some(HashMap::new()),
                    order: super::proxy_nss::Order::default(),
                    fallback: None,
                }, error.kind() != std::io::ErrorKind::NotFound));
            }
            Err(error) => return Err(error.into()),
        };
        // Includes simultaneous raw input, lowercased temporary key, HashMap
        // growth/reallocation and per-alias address vectors. Zone strings are
        // Arc-backed and cannot multiply their input length per alias.
        if let Some(owner)=retained_owner {owner.reserve(data.len().checked_mul(256).and_then(|n|n.checked_add(65536)).ok_or_else(||anyhow!("hosts accounting overflow"))?)?;}

        let mut map: HashMap<String, Vec<DnsIp>> = HashMap::new();

        for line in data.split(|&b| b == b'\n') {
            // Strip comments (everything after '#')
            let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
                &line[..pos]
            } else {
                line
            };

            if line.is_empty() {
                continue;
            }

            let mut fields = line
                .split(|b| matches!(b, b' ' | b'\t' | b'\r'))
                .filter(|f| !f.is_empty());

            // First field: IP Address
            let ip_field = match fields.next() {
                Some(f) => f,
                None => continue,
            };

            let ip = match std::str::from_utf8(ip_field).ok() {
                Some(s) => match DnsIp::parse(s) {
                    Some(ip) => ip,
                    None => continue,
                },
                None => continue,
            };

            // Subsequent fields: Aliases
            for alias_field in fields {
                if let Ok(alias) = std::str::from_utf8(alias_field) {
                    let key = go_host_key(alias);
                    // Push IP to preserve file ordering. No dedup.
                    map.entry(key).or_default().push(ip.clone());
                }
            }
        }

        Ok((HostSnapshot {
            retained_owner:retained_owner.cloned(),
            ordered: Some(map),
            order: super::proxy_nss::Order::default(),
            fallback: None,
        }, false))
    }

    #[cfg(not(unix))]
    {
        // Non-Unix: Use Hickory's standard system parsing
        Ok((HostSnapshot {
            retained_owner:retained_owner.cloned(),
            ordered: None,
            order: super::proxy_nss::Order::default(),
            fallback: Some(Arc::new(hickory_resolver::Hosts::from_system()?)),
        }, false))
    }
}

/// Go `defaultNS` (no resolv.conf): 127.0.0.1:53, [::1]:53; ndots 1, timeout 5s, attempts 2.
fn go_default_conf() -> (ResolverConfig, ResolverOpts) {
    let ns = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .map(|ip| NameServerConfig::new(ip, true, vec![conn(false, 53), conn(true, 53)]));
    let mut o = ResolverOpts::default();
    o.ndots = 1;
    o.timeout = Duration::from_secs(5);
    o.attempts = 2;
    #[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
    let search = hickory_resolver::system_conf::parse_resolv_conf(b"nameserver 127.0.0.1\n")
        .ok().map(|(cfg, _)| cfg.search().to_vec()).unwrap_or_default();
    // Hickory deliberately exposes resolv.conf parsing only on its Unix-file
    // platforms. Other platforms still need the hostname suffix default when
    // no configured resolver/search list exists; never call an unavailable API.
    #[cfg(any(not(unix), target_os = "android", target_vendor = "apple"))]
    let search = hostname::get().ok().and_then(|name| name.into_string().ok())
        .and_then(|name| name.split_once('.').map(|(_, suffix)| suffix.to_owned()))
        .filter(|suffix| !suffix.is_empty())
        .and_then(|suffix| hickory_resolver::proto::rr::Name::from_str_relaxed(&suffix).ok())
        .map(|name| vec![name]).unwrap_or_default();
    (ResolverConfig::from_parts(None, search, ns.to_vec()), o)
}

/// Internet `[network/]host[:port]` (default udp/53), or Unix network/path.
pub(super) fn validate_acme_resolvers(addresses:&[String])->Result<()> {
    for address in addresses {parse_net_addr(address)?;}Ok(())
}
fn parse_net_addr(addr: &str) -> Result<NetAddr> {
    let (net, rest) = match addr.split_once('/') {
        Some((n, r)) => (n.trim().to_ascii_lowercase(), r),
        None => (String::new(), addr),
    };
    let unix = match net.as_str() {
        "unix" => Some(super::proxy_dns_unix::Kind::Stream),
        "unixgram" => Some(super::proxy_dns_unix::Kind::Datagram),
        "unixpacket" => Some(super::proxy_dns_unix::Kind::Packet),
        _ => None,
    };
    if unix.is_some() {
        ensure!(!rest.is_empty() && !rest.as_bytes().contains(&0), "resolver Unix address must be nonempty without NUL");
        return Ok(NetAddr { unix, tcp: false, family: None, host: rest.to_owned(), port: 0 });
    }
    let (tcp, family) = match net.as_str() {
        "" | "udp" => (false, None),
        "udp4" => (false, Some(4u8)),
        "udp6" => (false, Some(6)),
        "tcp" => (true, None),
        "tcp4" => (true, Some(4)),
        "tcp6" => (true, Some(6)),
        other => bail!("resolver address {addr:?}: network {other:?} unsupported (udp*, tcp*, unix, unixgram, unixpacket)"),
    };
    let (host, port) = match split_host_port(rest) {
        Some((h, p)) => {
            let port = parse_port(p).ok_or_else(|| {
                anyhow!("resolver address {addr:?}: need exactly one port, got {p:?}")
            })?;
            (h.to_owned(), port)
        }
        None => (rest.trim_matches(['[', ']']).to_owned(), 53),
    };
    ensure!(
        !host.is_empty() && !host.contains(['[', ']', '/']),
        "resolver address {addr:?}: invalid host"
    );
    ensure!(
        port != 0,
        "resolver address {addr:?}: port 0 is not dialable"
    );
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure!(
            super::proxy_dns_dial::family(SocketAddr::new(ip, port), family).is_some(),
            "resolver address {addr:?}: IP family does not match network {net:?}"
        );
    }
    Ok(NetAddr {
        unix: None,
        tcp,
        family,
        host,
        port,
    })
}

/// Go `net.SplitHostPort`; `None` = Caddy's "missing port" fallback.
fn split_host_port(a: &str) -> Option<(&str, &str)> {
    if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let p = tail.strip_prefix(':')?;
        return (!p.contains([':', '[', ']']) && !h.contains('[')).then_some((h, p));
    }
    let (h, p) = a.rsplit_once(':')?;
    (!h.contains([':', '[', ']']) && !p.contains(['[', ']'])).then_some((h, p))
}

fn parse_port(p: &str) -> Option<u16> {
    if p.is_empty() {
        return Some(53);
    }
    let num = |s: &str| {
        (!s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
            .then(|| s.parse::<u16>().ok())
            .flatten()
    };
    let (a, b) = p.split_once('-').unwrap_or((p, p));
    let (a, b) = (num(a)?, num(b)?);
    (a == b).then_some(a)
}

fn pos_dur(ns: i64) -> Duration {
    Duration::from_nanos(ns.max(0) as u64)
}

/// Sole adapter over `proxy_policy::random_below`.
fn rnd(n: u64) -> Result<u64> {
    let v = random_below(n as usize).map_err(|e| anyhow!("random source: {e}"))?;
    ensure!(v < n as usize, "random source returned {v} for bound {n}");
    Ok(v as u64)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum IpVer {
    Any,
    V4,
    V6,
}

impl IpVer {
    fn from_cfg(v: &IpVersions) -> Self {
        match v {
            IpVersions::Any => Self::Any,
            IpVersions::V4 => Self::V4,
            IpVersions::V6 => Self::V6,
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Self::Any => "ip",
            Self::V4 => "ip4",
            Self::V6 => "ip6",
        }
    }
    fn strategy(self) -> LookupIpStrategy {
        match self {
            Self::Any => LookupIpStrategy::Ipv4AndIpv6,
            Self::V4 => LookupIpStrategy::Ipv4Only,
            Self::V6 => LookupIpStrategy::Ipv6Only,
        }
    }
}

// ---------------------------------------------------------------------------
// leaf sources, cache, singleflight
// ---------------------------------------------------------------------------

enum LeafKind {
    A {
        name: String,
        port: String,
        ver: IpVer,
    },
    Srv {
        name: String,
        service: String,
        proto: String,
        dial_network: String,
    },
}

struct Entry {
    fresh_until: Instant,
    ups: Arc<[String]>,
    bytes: usize,
    zero: bool,
}

#[derive(Clone)]
enum Out {
    Ok(Arc<[String]>),
    Err(Arc<str>),
    Retry,
}

type FlightTx = watch::Sender<Option<Out>>;

enum Outcome {
    Done(Result<Arc<[String]>, String>),
    Stopped,
    Abandoned,
}

enum Join {
    Hit(Arc<[String]>),
    Lead(watch::Receiver<Option<Out>>),
    Follow(watch::Receiver<Option<Out>>),
}

#[derive(Default)]
struct LeafState {
    cache: HashMap<String, Entry>,
    bytes: usize,
    inflight: HashMap<String, Arc<FlightTx>>,
    generation: u64,
}

impl LeafState {
    fn store(
        &mut self,
        key: &str,
        ups: Arc<[String]>,
        fresh_until: Instant,
        zero: bool,
    ) -> Option<String> {
        if let Some(old) = self.cache.remove(key) {
            self.bytes -= old.bytes;
        }
        let bytes = 128 + key.len() + ups.iter().map(|s| s.len() + 24).sum::<usize>();
        if bytes > CACHE_BYTES {
            return Some(format!(
                "upstreams for {key:?} (~{bytes} B) exceed the cache budget; not cached"
            ));
        }
        while !self.cache.is_empty()
            && (self.cache.len() >= CACHE_KEYS || self.bytes + bytes > CACHE_BYTES)
        {
            let victim = self
                .cache
                .iter()
                .min_by_key(|(_, e)| e.fresh_until)
                .map(|(k, _)| k.clone());
            if let Some(e) = victim.and_then(|k| self.cache.remove(&k)) {
                self.bytes -= e.bytes;
            }
        }
        self.bytes += bytes;
        self.cache.insert(
            key.to_owned(),
            Entry {
                fresh_until,
                ups,
                bytes,
                zero,
            },
        );
        None
    }
}

struct Leaf {
    kind: LeafKind,
    refresh_ns: i64,
    grace: Duration,
    dns: DnsSpec,
    ver: IpVer,
    shared: Arc<DnsShared>,
    state: Mutex<LeafState>,
}

#[derive(Clone)]
enum Query {
    Ip { name: String, port: String },
    Srv(String),
}

struct Plan {
    leaf: Arc<Leaf>,
    key: String,
    query: Query,
}

impl Leaf {
    fn new(cfg: &DynamicCfg, shared: &Arc<DnsShared>) -> Result<Arc<Self>> {
        let (kind, refresh_ns, grace_ns, dns, ver) = match cfg {
            DynamicCfg::A {
                name,
                port,
                refresh,
                dns,
                versions,
            } => {
                let ver = IpVer::from_cfg(versions);
                (
                    LeafKind::A {
                        name: name.clone(),
                        port: port.clone(),
                        ver,
                    },
                    *refresh,
                    0,
                    dns,
                    ver,
                )
            }
            DynamicCfg::Srv {
                name,
                service,
                proto,
                refresh,
                grace_period,
                dns,
                dial_network,
            } => {
                let kind = LeafKind::Srv {
                    name: name.clone(),
                    service: service.clone(),
                    proto: proto.clone(),
                    dial_network: dial_network.clone(),
                };
                (kind, *refresh, *grace_period, dns, IpVer::Any)
            }
            DynamicCfg::Multi(_) => bail!("internal: multi is not a leaf source"),
        };
        if let Some(raw) = &dns.resolver_addresses {
            shared.custom_addrs(raw)?; // provision-time validation (Go ParseAddresses)
        }
        Ok(Arc::new(Self {
            kind,
            refresh_ns,
            grace: pos_dur(grace_ns), // Go: grace only when GracePeriod > 0
            dns: DnsSpec {
                addrs: dns.resolver_addresses.clone(),
                dial_ns: dns.dial_timeout,
                fallback_ns: dns.fallback_delay,
            },
            ver,
            shared: shared.clone(),
            state: Mutex::new(LeafState::default()),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, LeafState> {
        lock(&self.state)
    }

    /// Synchronous placeholder expansion into an owned key and query.
    fn plan(self: &Arc<Self>, expand: &Expander<'_>) -> Result<Plan> {
        let (key, query) = match &self.kind {
            LeafKind::A { name, port, ver } => {
                let (n, p) = (expand(name)?, expand(port)?);
                (
                    format!("{n}\0{p}\0{}", ver.tag()),
                    Query::Ip { name: n, port: p },
                )
            }
            LeafKind::Srv {
                name,
                service,
                proto,
                ..
            } => {
                let n = expand(name)?;
                if service.is_empty() && proto.is_empty() {
                    (n.clone(), Query::Srv(n))
                } else {
                    let (s, p) = (expand(service)?, expand(proto)?);
                    let key = format!("_{s}._{p}.{n}");
                    // Go net.LookupSRV: empty service and proto mean "query name as-is".
                    let target = if s.is_empty() && p.is_empty() {
                        n
                    } else {
                        key.clone()
                    };
                    (key, Query::Srv(target))
                }
            }
        };
        Ok(Plan {
            leaf: self.clone(),
            key,
            query,
        })
    }

    fn join_or_lead(self: &Arc<Self>, key: &str, query: &Query) -> Result<Join> {
        ensure!(!self.shared.stop.is_cancelled(), STOPPED);
        let mut st = self.lock();
        if let Some(e) = st.cache.get(key)
            && Instant::now() < e.fresh_until
        {
            return Ok(Join::Hit(e.ups.clone()));
        }
        // Per-key serializer: followers wait, then re-check actual freshness.
        // Negative refresh and failures still cost one lookup per request.
        if let Some(f) = st.inflight.get(key) {
            return Ok(Join::Follow(f.subscribe()));
        }
        ensure!(
            st.inflight.len() < MAX_INFLIGHT,
            "dynamic upstreams: more than {MAX_INFLIGHT} distinct lookups in flight"
        );
        let permit = (self.shared.queue_slots.clone().try_acquire_owned())
            .map_err(|_| anyhow!("dynamic upstreams: DNS lookup queue is full"))?;
        let (tx, rx) = watch::channel(None);
        let tx = Arc::new(tx);
        st.inflight.insert(key.to_owned(), tx.clone());
        let source_epoch = st.generation;
        drop(st);
        let (leaf, key, query) = (self.clone(), key.to_owned(), query.clone());
        self.shared.tasks.spawn(async move {
            let _permit = permit;
            let stop = leaf.shared.stop.clone();
            let outcome = tokio::select! {
                biased;
                _ = stop.cancelled() => Outcome::Stopped,
                _ = tx.closed() => Outcome::Abandoned,
                r = leaf.lookup_bounded(&query) => Outcome::Done(r),
            };
            let out = leaf.finish(source_epoch, &key, &tx, outcome);
            tx.send_replace(Some(out));
        });
        Ok(Join::Lead(rx))
    }

    fn finish(&self, source_epoch: u64, key: &str, tx: &Arc<FlightTx>, outcome: Outcome) -> Out {
        let mut note = None;
        let out = {
            let mut g = self.lock();
            let st = &mut *g;
            if st.inflight.get(key).is_some_and(|f| Arc::ptr_eq(f, tx)) {
                st.inflight.remove(key);
            }
            let current = source_epoch == st.generation;
            let grace =
                current && !self.grace.is_zero() && matches!(self.kind, LeafKind::Srv { .. });
            let cache = current && (self.refresh_ns >= 0 || grace);
            match outcome {
                Outcome::Abandoned => Out::Retry,
                Outcome::Stopped => Out::Err(Arc::from(STOPPED)),
                Outcome::Done(Ok(ups)) => {
                    if cache {
                        let until = after(pos_dur(self.refresh_ns));
                        note = st
                            .store(key, ups.clone(), until, false)
                            .map(|m| (Level::Warn, m));
                    }
                    Out::Ok(ups)
                }
                Outcome::Done(Err(e)) if !grace => Out::Err(Arc::from(e)),
                Outcome::Done(Err(e)) => {
                    let ups = match st.cache.get_mut(key).filter(|en| !en.zero) {
                        Some(en) => {
                            en.fresh_until = after(self.grace);
                            en.ups.clone()
                        }
                        None => {
                            // Go zero-value srvLookup: empty, Refresh 0 -> fresh only for grace - refresh.
                            let w = if self.refresh_ns < 0 {
                                self.grace.saturating_add(Duration::from_nanos(
                                    self.refresh_ns.unsigned_abs(),
                                ))
                            } else {
                                self.grace.saturating_sub(pos_dur(self.refresh_ns))
                            };
                            let until = if w.is_zero() {
                                Instant::now()
                            } else {
                                after(w)
                            };
                            let empty: Arc<[String]> = Arc::from(Vec::new());
                            let _ = st.store(key, empty.clone(), until, true);
                            empty
                        }
                    };
                    note = Some((
                        Level::Error,
                        format!("SRV lookup failed; using previously cached: {e}"),
                    ));
                    Out::Ok(ups)
                }
            }
        };
        if let Some((level, msg)) = note {
            self.shared.emit(level, &msg);
        }
        out
    }

    async fn lookup_bounded(&self, q: &Query) -> Result<Arc<[String]>, String> {
        // LookupIP literals precede resolver configuration and admission. They
        // must also work when unrelated DNS configuration is unreadable.
        if let Query::Ip { name, port } = q && let Some(ip) = DnsIp::lookup_literal(name) {
            let address = if matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local()) {
                DnsIp::parse(name).unwrap_or_else(|| DnsIp::plain(ip))
            } else { DnsIp::plain(ip) };
            return self.finish_ips(vec![address], name, port).await;
        }
        let work = async {
            let _permit = (self.shared.lookup_slots.acquire().await)
                .map_err(|_| "dynamic upstreams: lookup semaphore closed".to_owned())?;
            #[cfg(target_vendor = "apple")]
            if self.dns.addrs.is_none() && let Query::Ip { name, port } = q {
                let version=match self.ver {IpVer::V4=>Some(4),IpVer::V6=>Some(6),IpVer::Any=>None};
                let ips=super::proxy_dns_native::lookup(name,version).await.map_err(|e|format!("A/AAAA lookup {name:?}: {e}"))?;
                // libc already applies Darwin address-selection policy. Keep
                // that order rather than replacing it with a second policy.
                let out=ips.into_iter().map(|address|{
                    let host=match address.ip {
                        IpAddr::V6(ip) if ip.is_unicast_link_local()=>address.zone.as_ref().map_or_else(||ip.to_string(),|z|format!("{ip}%{z}")),
                        ip=>ip.to_string(),
                    };join_host_port(&host,port)
                }).collect::<Vec<_>>();
                return Ok(out.into());
            }
            let (resolver, sys) = self
                .shared
                .resolver_for(&self.dns, self.ver)
                .await
                .map_err(|e| format!("{e:#}"))?;
            self.lookup(&resolver, q, &sys).await
        };
        tokio::time::timeout(LOOKUP_DEADLINE, work)
            .await
            .unwrap_or_else(|_| {
                Err(format!(
                    "dynamic upstreams: lookup exceeded {LOOKUP_DEADLINE:?}"
                ))
            })
    }

    async fn finish_ips(&self, ips: Vec<DnsIp>, name: &str, port: &str) -> Result<Arc<[String]>, String> {
        if ips.len() > MAX_ENDPOINTS {
            return Err(format!(
                "A/AAAA lookup {name:?}: more than {MAX_ENDPOINTS} addresses"
            ));
        }
        let version = match self.ver {
            IpVer::Any => None,
            IpVer::V4 => Some(4),
            IpVer::V6 => Some(6),
        };
        // Hosts-file IPAddr sorting observes zones before LookupIP removes them.
        // A link-local destination cannot be dialed after losing its interface.
        // Preserve that meaningful scope as an enhancement over Go LookupIP;
        // global/loopback output retains existing Go-compatible formatting.
        let keep_zones = ips.len() > 1 || ips.iter().any(|ip| matches!(ip.ip, IpAddr::V6(v) if v.is_unicast_link_local()) && ip.zone.is_some());
        let addresses = self.shared.ip_addresses(ips, 53, version, keep_zones)
            .await.map_err(|error| format!("{error:#}"))?;
        let addresses = self
            .shared
            .order_addresses(addresses)
            .await
            .map_err(|error| format!("{error:#}"))?;
        let out: Vec<_> = addresses
            .into_iter()
            .map(|address| {
                let host = match address {
                    SocketAddr::V6(v) if v.ip().is_unicast_link_local() && v.scope_id() != 0 => format!("{}%{}", v.ip(), v.scope_id()),
                    _ => address.ip().to_string(),
                };
                join_host_port(&host, port)
            })
            .collect();
        if out.is_empty() {
            return Err(format!("A/AAAA lookup {name:?}: no addresses"));
        }
        Ok(out.into())
    }

    async fn lookup(
        &self,
        resolver: &Dns,
        q: &Query,
        sys: &SysConf,
    ) -> Result<Arc<[String]>, String> {
        match (q, &self.kind) {
            (Query::Ip { name, port }, LeafKind::A { .. }) => {
                // Go returns a matching hosts-file entry as one authoritative
                // address list; it does not query a missing second IP family.
                let ips = lookup_ips(resolver, sys, name)
                    .await
                    .map_err(|e| format!("A/AAAA lookup {name:?}: {e:#}"))?;
                self.finish_ips(ips, name, port).await
            }
            (Query::Srv(target), LeafKind::Srv { dial_network, .. }) => {
                let lookup = (lookup_record(resolver, sys, target.as_str(), RecordType::SRV).await)
                    .map_err(|e| format!("SRV lookup {target:?}: {e}"))?;
                let (mut recs, mut filtered) = (Vec::new(), 0usize);
                for record in lookup.answers() {
                    let rdata = &record.data;
                    let RData::SRV(srv) = rdata else { continue };
                    let host = srv.target.to_string();
                    if !is_domain_name(&host) {
                        filtered += 1;
                        continue;
                    }
                    if recs.len() == MAX_ENDPOINTS {
                        return Err(format!(
                            "SRV lookup {target:?}: more than {MAX_ENDPOINTS} records"
                        ));
                    }
                    recs.push(SrvRec {
                        priority: srv.priority,
                        weight: srv.weight,
                        port: srv.port,
                        host,
                    });
                }
                if recs.is_empty() {
                    return Err(match filtered {
                        0 => format!("SRV lookup {target:?}: no records"),
                        n => format!(
                            "SRV lookup {target:?}: all {n} records had invalid target names"
                        ),
                    });
                }
                if filtered > 0 {
                    let msg = format!(
                        "SRV records filtered: {filtered} invalid target name(s) for {target:?}"
                    );
                    self.shared.emit(Level::Warn, &msg);
                }
                sort_srv(&mut recs).map_err(|e| format!("SRV lookup {target:?}: {e:#}"))?;
                Ok(recs
                    .into_iter()
                    .map(|r| {
                        let addr = join_host_port(&r.host, &r.port.to_string());
                        if dial_network.is_empty() {
                            addr
                        } else {
                            format!("{dial_network}/{addr}")
                        }
                    })
                    .collect())
            }
            _ => Err("internal: query/source kind mismatch".to_owned()),
        }
    }
}

impl Plan {
    async fn run(self) -> Result<Arc<[String]>> {
        let work = async {
            loop {
                match self.leaf.join_or_lead(&self.key, &self.query)? {
                    Join::Hit(ups) => return Ok(ups),
                    // Go re-checks freshness after taking the lookup lock.
                    // A follower never adopts somebody else's stale/error result.
                    Join::Follow(rx) => {
                        let _ = wait(rx).await;
                    }
                    Join::Lead(rx) => match wait(rx).await {
                        Out::Ok(ups) => return Ok(ups),
                        Out::Err(e) => return Err(anyhow!("{e}")),
                        Out::Retry => {}
                    },
                }
            }
        };
        tokio::time::timeout(LOOKUP_DEADLINE, work)
            .await
            .map_err(|_| {
                anyhow!(
                    "dynamic upstreams: lookup for {:?} exceeded {LOOKUP_DEADLINE:?}",
                    self.key
                )
            })?
    }
}

async fn wait(mut rx: watch::Receiver<Option<Out>>) -> Out {
    loop {
        let cur = rx.borrow_and_update().clone();
        if let Some(out) = cur {
            return out;
        }
        if rx.changed().await.is_err() {
            return Out::Retry;
        }
    }
}

// ---------------------------------------------------------------------------
// public entry point
// ---------------------------------------------------------------------------

enum Root {
    Single(Arc<Leaf>),
    Multi(Vec<Arc<Leaf>>),
}

pub(crate) struct DynamicUpstreams {
    root: Root,
    shared: Arc<DnsShared>,
}

impl DynamicUpstreams {
    pub(crate) fn new(cfg: &DynamicCfg, shared: &Arc<DnsShared>) -> Result<Self> {
        let root = match cfg {
            DynamicCfg::Multi(list) => {
                let mut leaves = Vec::new();
                flatten(list, shared, 1, &mut leaves)?;
                Root::Multi(leaves)
            }
            leaf => Root::Single(Leaf::new(leaf, shared)?),
        };
        Ok(Self {
            root,
            shared: shared.clone(),
        })
    }

    pub(crate) fn get(&self, expand: &Expander<'_>) -> GetFuture {
        let to_ups = |ups: &[String]| {
            ups.iter()
                .map(|d| Upstream {
                    dial: d.clone(),
                    max_requests: 0,
                })
                .collect::<Vec<_>>()
        };
        match &self.root {
            Root::Single(leaf) => {
                let plan = leaf.plan(expand);
                Box::pin(async move { Ok(to_ups(&plan?.run().await?)) })
            }
            Root::Multi(leaves) => {
                let plans: Vec<Result<Plan>> = leaves.iter().map(|l| l.plan(expand)).collect();
                let shared = self.shared.clone();
                Box::pin(async move {
                    let mut out: Vec<Upstream> = Vec::new();
                    for (idx, plan) in plans.into_iter().enumerate() {
                        let res = match plan {
                            Ok(p) => p.run().await,
                            Err(e) => Err(e),
                        };
                        match res {
                            Err(e) => shared.emit(
                                Level::Error,
                                &format!(
                                    "upstream source returned error (source_idx={idx}): {e:#}"
                                ),
                            ),
                            Ok(ups) if ups.is_empty() => shared.emit(
                                Level::Warn,
                                &format!("upstream source returned 0 upstreams (source_idx={idx})"),
                            ),
                            Ok(ups) => {
                                ensure!(
                                    out.len() + ups.len() <= MAX_ENDPOINTS,
                                    "multi upstreams: more than {MAX_ENDPOINTS} endpoints"
                                );
                                out.extend(to_ups(&ups));
                            }
                        }
                    }
                    ensure!(!shared.stop.is_cancelled(), STOPPED);
                    Ok(out)
                })
            }
        }
    }

    /// Go `CachingUpstreamSource`: only a top-level SRV source; never recurses into Multi.
    pub(crate) fn reset_cache(&self, expand: Option<&Expander<'_>>) -> Result<bool> {
        let Root::Single(leaf) = &self.root else {
            return Ok(false);
        };
        if !matches!(leaf.kind, LeafKind::Srv { .. }) {
            return Ok(false);
        }
        let key = expand.map(|f| leaf.plan(f).map(|p| p.key)).transpose()?;
        let mut st = leaf.lock();
        st.generation = st.generation.wrapping_add(1); // conservative: in-flight results are returned to waiters but not cached
        match key {
            None => {
                st.cache.clear();
                st.inflight.clear();
                st.bytes = 0;
            }
            Some(k) => {
                st.inflight.remove(&k);
                if let Some(e) = st.cache.remove(&k) {
                    st.bytes -= e.bytes;
                }
            }
        }
        Ok(true)
    }
}

fn flatten(
    list: &[DynamicCfg],
    shared: &Arc<DnsShared>,
    depth: usize,
    out: &mut Vec<Arc<Leaf>>,
) -> Result<()> {
    ensure!(
        depth <= MAX_MULTI_DEPTH,
        "multi upstream sources nested deeper than {MAX_MULTI_DEPTH}"
    );
    for cfg in list {
        match cfg {
            DynamicCfg::Multi(inner) => flatten(inner, shared, depth + 1, out)?,
            leaf => out.push(Leaf::new(leaf, shared)?),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Go net helpers
// ---------------------------------------------------------------------------

struct SrvRec {
    priority: u16,
    weight: u16,
    port: u16,
    host: String,
}

/// Go `byPriorityWeight.sort`.
fn sort_srv(recs: &mut [SrvRec]) -> Result<()> {
    recs.sort_by_key(|r| (r.priority, r.weight));
    let mut i = 0;
    while i < recs.len() {
        let p = recs[i].priority;
        let j = recs[i..]
            .iter()
            .position(|r| r.priority != p)
            .map_or(recs.len(), |n| i + n);
        shuffle_by_weight(&mut recs[i..j])?;
        i = j;
    }
    Ok(())
}

fn shuffle_by_weight(g: &mut [SrvRec]) -> Result<()> {
    let mut sum: u64 = g.iter().map(|r| u64::from(r.weight)).sum();
    let mut s = 0;
    while sum > 0 && g.len() - s > 1 {
        let n = rnd(sum)?;
        let mut acc = 0u64;
        for i in s..g.len() {
            acc += u64::from(g[i].weight);
            if acc > n {
                g.swap(s, i);
                break;
            }
        }
        sum -= u64::from(g[s].weight);
        s += 1;
    }
    Ok(())
}

/// Go `isDomainName` (used by `LookupSRV` to filter targets).
fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let b = s.as_bytes();
    let l = b.len();
    if l == 0 || l > 254 || (l == 254 && b[l - 1] != b'.') {
        return false;
    }
    let (mut last, mut non_numeric, mut part) = (b'.', false, 0usize);
    for &c in b {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part += 1;
            }
            b'0'..=b'9' => part += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || part == 0 || part > 63 {
                    return false;
                }
                part = 0;
            }
            _ => return false,
        }
        last = c;
    }
    last != b'-' && part <= 63 && non_numeric
}

/// Go `net.JoinHostPort`; the port is kept verbatim, so named ports stay as strings.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d)
        .unwrap_or_else(|| now + Duration::from_secs(30 * 365 * 86_400))
}
