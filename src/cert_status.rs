//! Background OCSP maintenance. Cache and network responses share one strict
//! validator; certificate status never causes network IO in a TLS handshake.
#[path = "cert_status/network.rs"]
mod network;
#[path = "cert_status/precommit.rs"]
mod precommit;
#[path = "cert_status/verify.rs"]
mod verify;
pub use precommit::OcspProbeBusy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OcspState {
    Good,
    Revoked,
    Unknown,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct VerifiedStatus {
    pub state: OcspState,
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub legacy_signature: bool,
    pub produced_at: i64,
    /// Hard deadline, capped by leaf and delegated responder expiry.
    pub valid_until: i64,
    /// CertMagic refreshes at the midpoint of the effective validity interval.
    pub refresh_at: i64,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<u8>,
}

pub(crate) use verify::verify_signature as verify_x509_signature;
pub use verify::{
    KeyCompromiseProof, LiveKeyCompromiseFact, verify_key_compromise_proof, verify_response_capture,
    verify_response_observation,
    request as create_request, validate_issuer, verify_response, verify_response_with_max_age,
};

use crate::{
    certstore::{self, FsStore},
    tls_resolver::{HotCertificateResolver, OcspCertificate},
};
use anyhow::{Result, anyhow, ensure};
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use network::OcspTransport;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

type CertificateKey = ([u8; 32], u64);
type CertificateGateKey = (usize, CertificateKey);
type PolicySelector = Arc<dyn Fn(&OcspCertificate) -> Result<OcspConfig> + Send + Sync>;
pub type OcspInventorySelector = Arc<dyn Fn(&OcspCertificate) -> bool + Send + Sync>;

/// Shared process budgets prevent policy/generation counts multiplying the
/// global request, queued-work and per-origin responder limits.
pub struct OcspResources {
    global: Arc<Semaphore>,
    restore_slots: Arc<Semaphore>,
    cpu_slots: Arc<Semaphore>,
    work_slots: Semaphore,
    responders: Mutex<HashMap<String, Weak<Semaphore>>>,
    gates: Mutex<HashMap<CertificateGateKey, Weak<AsyncMutex<()>>>>,
    max_concurrent: usize,
    max_per_responder: usize,
}
impl OcspResources {
    pub fn limits(&self) -> (usize, usize) {
        (self.max_concurrent, self.max_per_responder)
    }
    pub fn new(max_concurrent: usize, max_per_responder: usize) -> Result<Self> {
        let cpu = Arc::new(Semaphore::new(
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(4),
        ));
        Self::with_cpu(max_concurrent, max_per_responder, cpu)
    }
    /// Network/restore admission and CPU dispatch are distinct budgets. Share
    /// the caller's existing certificate CPU budget across policies/generations.
    pub(crate) fn with_cpu(
        max_concurrent: usize,
        max_per_responder: usize,
        cpu: Arc<Semaphore>,
    ) -> Result<Self> {
        ensure!(
            (1..=128).contains(&max_concurrent)
                && (1..=max_concurrent).contains(&max_per_responder),
            "invalid OCSP concurrency limits"
        );
        Ok(Self {
            global: Arc::new(Semaphore::new(max_concurrent)),
            restore_slots: Arc::new(Semaphore::new(max_concurrent * 2)),
            cpu_slots: cpu,
            work_slots: Semaphore::new(4096),
            responders: Mutex::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            max_concurrent,
            max_per_responder,
        })
    }
}

/// The URL override map uses exact responder URL keys, as CertMagic does.
/// An empty override disables querying that responder. Proxy and extra roots
/// affect background HTTP only and never alter certificate/TLS trust globally.
#[derive(Clone)]
pub struct OcspConfig {
    pub disable_stapling: bool,
    pub responder_overrides: HashMap<String, String>,
    pub http_proxy: Option<String>,
    pub extra_ca_pem: Vec<Vec<u8>>,
    /// Hard freshness bound only when the responder omits nextUpdate.
    /// Unlike Go's unbounded staple, the default expires after 24h from thisUpdate.
    pub no_next_update_max_age: Duration,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            disable_stapling: false,
            responder_overrides: HashMap::new(),
            http_proxy: None,
            extra_ca_pem: Vec::new(),
            no_next_update_max_age: Duration::from_secs(86400),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OcspOptions {
    pub check_interval: Duration,
    pub request_timeout: Duration,
    pub max_concurrent: usize,
    pub max_concurrent_per_responder: usize,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}
impl Default for OcspOptions {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(30),
            max_concurrent: 8,
            max_concurrent_per_responder: 2,
            retry_initial: Duration::from_secs(60),
            retry_max: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OcspEvent {
    pub identity: [u8; 32],
    pub leaf_sha256: [u8; 32],
    pub generation: u64,
    pub names: Vec<String>,
    pub kind: &'static str,
    pub status: Option<VerifiedStatus>,
    /// Avoid warning noise for short-lived certificates, matching CertMagic.
    pub quiet: bool,
    pub error: Option<String>,
    pub persisted: Option<bool>,
}

/// Classification of stored OCSP restoration. Only Restored carries an
/// accepted authenticated status; missing/rejected outcomes are never Good.
/// This path never queries AIA or an OCSP responder.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheRestore {
    Disabled,
    NotApplicable,
    Missing,
    NeedsIssuer,
    Expired,
    Invalid,
    StaleStatus,
    StaleGeneration,
    Restored { status: VerifiedStatus },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefreshMode {
    Online,
    CacheOnly,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct KnownOcspStatus {
    pub identity: [u8; 32],
    pub leaf_sha256: [u8; 32],
    pub status: VerifiedStatus,
    pub persisted: bool,
}

#[derive(PartialEq, Eq)]
struct NegativeNotice {
    this_update: i64,
    state: OcspState,
    reason: Option<u8>,
    revoked_at: Option<i64>,
    persisted: bool,
}

#[derive(Default)]
struct Entry {
    status: Option<VerifiedStatus>,
    next_check: i64,
    failures: u32,
    publish_blocked: bool,
    negative_notice: Option<NegativeNotice>,
}
#[derive(Clone)]
struct Observed {
    leaf_sha256: [u8; 32],
    status: VerifiedStatus,
    persisted: bool,
}
struct Inner {
    store: FsStore,
    resolver: Arc<HotCertificateResolver>,
    options: OcspOptions,
    policy: PolicySelector,
    global: Arc<Semaphore>,
    restore_slots: Arc<Semaphore>,
    cpu_slots: Arc<Semaphore>,
    resources: Arc<OcspResources>,
    inventory: OcspInventorySelector,
    identity_scope: Option<[u8; 32]>,
    entries: Mutex<HashMap<CertificateKey, Entry>>,
    observations: Mutex<HashMap<[u8; 32], Observed>>,
    events: broadcast::Sender<OcspEvent>,
    changed: Notify,
}
#[derive(Clone)]
pub struct OcspManager {
    inner: Arc<Inner>,
}
impl OcspManager {
    pub fn new(
        store: FsStore,
        resolver: Arc<HotCertificateResolver>,
        options: OcspOptions,
    ) -> Result<Self> {
        Self::with_policy(
            store,
            resolver,
            options,
            Arc::new(|_| Ok(OcspConfig::default())),
        )
    }
    /// The selector must represent one immutable policy version for this
    /// manager. Do not mutate captured policy state in place. A policy change
    /// requires cancelling and joining the old manager before replacement, or
    /// loading new certificate instance generations. `notify_changed` only
    /// schedules discovery; it is not policy revocation or replacement.
    pub fn with_policy(
        store: FsStore,
        resolver: Arc<HotCertificateResolver>,
        options: OcspOptions,
        policy: PolicySelector,
    ) -> Result<Self> {
        let resources = Arc::new(OcspResources::new(
            options.max_concurrent,
            options.max_concurrent_per_responder,
        )?);
        Self::with_resources_and_inventory(
            store,
            resolver,
            options,
            policy,
            Arc::new(|_| true),
            resources,
        )
    }
    /// Both selectors describe one immutable generation. Out-of-scope entries
    /// are untouched, including their existing staple and failure bookkeeping.
    pub fn with_resources_and_inventory(
        store: FsStore,
        resolver: Arc<HotCertificateResolver>,
        options: OcspOptions,
        policy: PolicySelector,
        inventory: OcspInventorySelector,
        resources: Arc<OcspResources>,
    ) -> Result<Self> {
        let cpu = resources.cpu_slots.clone();
        Self::with_resources_and_inventory_cpu(
            store, resolver, options, policy, inventory, resources, cpu,
        )
    }
    pub(crate) fn with_resources_and_inventory_cpu(
        store: FsStore,
        resolver: Arc<HotCertificateResolver>,
        options: OcspOptions,
        policy: PolicySelector,
        inventory: OcspInventorySelector,
        resources: Arc<OcspResources>,
        cpu: Arc<Semaphore>,
    ) -> Result<Self> {
        ensure!(
            (1..=128).contains(&options.max_concurrent)
                && (1..=options.max_concurrent).contains(&options.max_concurrent_per_responder),
            "invalid OCSP concurrency limits"
        );
        ensure!(
            options.max_concurrent == resources.max_concurrent
                && options.max_concurrent_per_responder == resources.max_per_responder,
            "OCSP resource budgets differ from manager options"
        );
        ensure!(
            options.check_interval >= Duration::from_secs(1)
                && options.check_interval <= Duration::from_secs(86400),
            "invalid OCSP check interval"
        );
        ensure!(
            options.retry_initial >= Duration::from_secs(1)
                && options.retry_max >= options.retry_initial
                && options.retry_max <= Duration::from_secs(86400),
            "invalid OCSP retry interval"
        );
        // Validate transport limits before starting any workers.
        let _ = OcspTransport::new(options.request_timeout, 1024 * 1024, None, &[])?;
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(Inner {
                store,
                resolver,
                global: resources.global.clone(),
                restore_slots: resources.restore_slots.clone(),
                cpu_slots: cpu,
                resources,
                inventory,
                identity_scope: None,
                options,
                policy,
                entries: Mutex::new(HashMap::new()),
                observations: Mutex::new(HashMap::new()),
                events,
                changed: Notify::new(),
            }),
        })
    }
    /// Reconcile a lagged event subscriber. This is volatile authenticated
    /// metadata, not a claim that a failed disk write survived process restart.
    pub fn negative_observations(&self) -> Result<Vec<KnownOcspStatus>> {
        Ok(self
            .inner
            .observations
            .lock()
            .map_err(|_| anyhow!("OCSP observation state unavailable"))?
            .iter()
            .filter(|(_, o)| o.status.state != OcspState::Good)
            .map(|(identity, o)| KnownOcspStatus {
                identity: *identity,
                leaf_sha256: o.leaf_sha256,
                status: o.status.clone(),
                persisted: o.persisted,
            })
            .collect())
    }
    /// Set once before sharing/running the manager. The inventory selector is
    /// still applied to each complete record; this only avoids cloning public
    /// DER belonging to unrelated scopes.
    pub(crate) fn with_identity_scope(mut self, identity: [u8; 32]) -> Result<Self> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| anyhow!("OCSP scope already shared"))?;
        inner.identity_scope = Some(identity);
        inner.events = broadcast::channel(8).0;
        Ok(self)
    }
    pub fn subscribe(&self) -> broadcast::Receiver<OcspEvent> {
        self.inner.events.subscribe()
    }
    /// Call after publishing certificates. This does not revoke or replace an
    /// immutable policy selector; see `with_policy`. New certs
    /// are also discovered at the regular scan; this avoids delaying their
    /// first staple until the next hourly maintenance scan.
    pub fn notify_changed(&self) {
        if let Ok(mut entries) = self.inner.entries.lock() {
            for entry in entries.values_mut() {
                if entry.publish_blocked {
                    entry.publish_blocked = false;
                    entry.next_check = 0;
                }
            }
        }
        self.inner.changed.notify_one();
    }

    pub async fn refresh_one(
        &self,
        certificate: OcspCertificate,
        cancel: CancellationToken,
    ) -> Result<()> {
        self.refresh_shared(Arc::new(certificate), cancel).await
    }
    async fn refresh_shared(
        &self,
        certificate: Arc<OcspCertificate>,
        cancel: CancellationToken,
    ) -> Result<()> {
        if !(self.inner.inventory)(&certificate) {
            return Ok(());
        }
        let _work = self
            .inner
            .resources
            .work_slots
            .try_acquire()
            .map_err(|_| anyhow!("OCSP queued work capacity exhausted"))?;
        let quiet = self
            .inspect(&certificate, cancel.clone())
            .await
            .map(|value| value.quiet)
            .unwrap_or(false);
        let leaf_sha256 = leaf_hash(&certificate);
        let summary = OcspCertificate {
            preparation: None,
            identity: certificate.identity,
            generation: certificate.generation,
            names: certificate.names.clone(),
            management_name: certificate.management_name.clone(),
            chain_der: Vec::new(),
            leaf_state: certificate.leaf_state.clone(),
            leaf_sha256: certificate.leaf_sha256,
            key_state: certificate.key_state.clone(),
        };
        let result = self
            .refresh_one_inner(certificate, cancel.clone(), RefreshMode::Online)
            .await
            .map(|_| ());
        if let Err(error) = &result {
            if cancel.is_cancelled() {
                return result;
            }
            if error.is::<crate::tls_resolver::OcspPublishCapacity>() {
                let mut entries = self
                    .inner
                    .entries
                    .lock()
                    .map_err(|_| anyhow!("OCSP maintenance state unavailable"))?;
                let entry = entries
                    .entry((summary.identity, summary.generation))
                    .or_default();
                entry.publish_blocked = true;
                entry.next_check =
                    now()?.saturating_add(self.inner.options.check_interval.as_secs() as i64);
            } else if error.is::<crate::tls_resolver::OcspPublishConflict>() {
                let mut entries = self
                    .inner
                    .entries
                    .lock()
                    .map_err(|_| anyhow!("OCSP maintenance state unavailable"))?;
                entries
                    .entry((summary.identity, summary.generation))
                    .or_default()
                    .next_check = now()?.saturating_add(5);
            }
            let _ = self.inner.events.send(OcspEvent {
                identity: summary.identity,
                leaf_sha256,
                generation: summary.generation,
                names: summary.names,
                kind: "ocsp_refresh_failed",
                status: None,
                quiet,
                error: Some(error.to_string().chars().take(512).collect()),
                persisted: None,
            });
        }
        result
    }

    /// Revalidate stored OCSP before accepting connections. No network or
    /// cache mutation is performed. A timeout cancels then joins the in-flight
    /// verification/lease work; cancellation does not detach blocking IO.
    pub async fn restore_cached_one(
        &self,
        certificate: OcspCertificate,
        cancel: CancellationToken,
    ) -> Result<CacheRestore> {
        if !(self.inner.inventory)(&certificate) {
            return Ok(CacheRestore::NotApplicable);
        }
        let _slot = self
            .inner
            .restore_slots
            .try_acquire()
            .map_err(|_| anyhow!("OCSP cache restore capacity exhausted"))?;
        ensure!(!cancel.is_cancelled(), "OCSP cache restore cancelled");
        let work = cancel.child_token();
        let operation =
            self.refresh_one_inner(Arc::new(certificate), work.clone(), RefreshMode::CacheOnly);
        tokio::pin!(operation);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                work.cancel();
                let _ = operation.await;
                Err(anyhow!("OCSP cache restore cancelled"))
            }
            result = &mut operation => result,
            _ = tokio::time::sleep(self.inner.options.request_timeout) => {
                work.cancel();
                let _ = operation.await;
                Err(anyhow!("OCSP cache restore deadline exceeded"))
            }
        }
    }

    fn certificate_gate(&self, certificate: &OcspCertificate) -> Result<Arc<AsyncMutex<()>>> {
        // A resolver owns its generation counter. Include its pinned Arc
        // identity so separate generations with the same counter never share
        // an in-process waiter; online cache writes still use the file lease.
        let gate_key = (
            Arc::as_ptr(&self.inner.resolver) as usize,
            (certificate.identity, certificate.generation),
        );
        Ok({
            let mut gates = self
                .inner
                .resources
                .gates
                .lock()
                .map_err(|_| anyhow!("OCSP gate state unavailable"))?;
            gates.retain(|_, v| v.strong_count() > 0);
            match gates.get(&gate_key).and_then(Weak::upgrade) {
                Some(v) => v,
                None => {
                    let v = Arc::new(AsyncMutex::new(()));
                    gates.insert(gate_key, Arc::downgrade(&v));
                    v
                }
            }
        })
    }
    async fn inspect(
        &self,
        certificate: &OcspCertificate,
        cancel: CancellationToken,
    ) -> Result<CertificateInspection> {
        let chain = certificate.chain_der.clone();
        crate::cert_cpu::run(self.inner.cpu_slots.clone(), cancel, move || {
            inspect_certificate(&chain)
        })
        .await
    }
    fn configuration(&self, certificate: &OcspCertificate) -> Result<OcspConfig> {
        let mut config = (self.inner.policy)(certificate)?;
        if config.no_next_update_max_age.is_zero() {
            config.no_next_update_max_age = Duration::from_secs(86400);
        }
        ensure!(
            (Duration::from_secs(7200)..=Duration::from_secs(31 * 86400))
                .contains(&config.no_next_update_max_age),
            "invalid no-nextUpdate OCSP maximum age"
        );
        Ok(config)
    }
    async fn reconcile_known_negative(
        &self,
        certificate: &OcspCertificate,
        quiet: bool,
    ) -> Result<()> {
        if let Some(known) = self
            .observed(&certificate.identity)?
            .filter(|observed| observed.status.state != OcspState::Good)
        {
            self.apply_negative(certificate, &known.status, quiet)
                .await?;
        }
        Ok(())
    }

    async fn refresh_one_inner(
        &self,
        certificate: Arc<OcspCertificate>,
        cancel: CancellationToken,
        mode: RefreshMode,
    ) -> Result<CacheRestore> {
        if !(self.inner.inventory)(&certificate) {
            return Ok(CacheRestore::NotApplicable);
        }
        let gate = self.certificate_gate(&certificate)?;
        let _guard = tokio::select! {_ =cancel.cancelled()=>return Err(anyhow!("OCSP refresh cancelled")),guard=gate.lock()=>guard};
        let config = self.configuration(&certificate)?;
        if config.disable_stapling {
            self.inner
                .resolver
                .set_ocsp(&certificate.identity, certificate.generation, None)?;
            self.record(&certificate, None, None)?;
            return Ok(CacheRestore::Disabled);
        }
        ensure!(
            !certificate.chain_der.is_empty(),
            "OCSP certificate chain empty"
        );
        let inspection = self.inspect(&certificate, cancel.clone()).await?;
        let quiet = inspection.quiet;
        let (responder, aia) = (inspection.responder, inspection.aia);
        let Some(original) = responder else {
            if inspection.must_staple {
                self.emit(&certificate, "ocsp_must_staple_unavailable", None, false);
            }
            self.inner
                .resolver
                .set_ocsp(&certificate.identity, certificate.generation, None)?;
            self.record(&certificate, None, None)?;
            return Ok(CacheRestore::NotApplicable);
        };
        if mode == RefreshMode::CacheOnly && certificate.chain_der.len() < 2 {
            return Ok(CacheRestore::NeedsIssuer);
        }
        let responder = config
            .responder_overrides
            .get(&original)
            .cloned()
            .unwrap_or_else(|| original.clone());
        let query_disabled = responder.is_empty();
        let transport = if mode == RefreshMode::Online {
            Some(OcspTransport::new(
                self.inner.options.request_timeout,
                1024 * 1024,
                config.http_proxy.as_deref(),
                &config.extra_ca_pem,
            )?)
        } else {
            None
        };
        let limiter = if mode == RefreshMode::Online {
            Some(self.responder_limit(if query_disabled {
                &original
            } else {
                &responder
            })?)
        } else {
            None
        };
        let responder_permit = if let Some(limiter) = &limiter {
            Some(
                tokio::select! {_ =cancel.cancelled()=>return Err(anyhow!("OCSP refresh cancelled")),permit=limiter.clone().acquire_owned()=>permit?},
            )
        } else {
            None
        };
        let global_permit = tokio::select! {_ =cancel.cancelled()=>return Err(anyhow!("OCSP refresh cancelled")),permit=self.inner.global.clone().acquire_owned()=>permit?};
        let budget = Arc::new(OcspNetworkBudget {
            _global: global_permit,
            _responder: responder_permit,
        });
        let cache_key = inspection.cache_key;
        let scope = format!("ocsp_{}", hex(&Sha256::digest(cache_key.as_bytes())));
        let lock_cancel = cancel.child_token();
        let lease_result = tokio::time::timeout(
            self.inner.options.request_timeout,
            self.inner.store.lock(&scope, lock_cancel.clone()),
        )
        .await;
        let lease = match lease_result {
            Ok(v) => v?,
            Err(_) => {
                lock_cancel.cancel();
                return Err(anyhow!("OCSP storage lock timed out"));
            }
        };
        let work = cancel.child_token();
        let stop_watch = CancellationToken::new();
        let watcher = {
            let work = work.clone();
            let lost = lease.lost();
            let stop = stop_watch.clone();
            tokio::spawn(async move {
                tokio::select! {_ =lost.cancelled()=>work.cancel(),_ =stop.cancelled()=>{}}
            })
        };
        let mut restored = CacheRestore::Missing;
        let result = async {
            let issuer = if certificate.chain_der.len() > 1 {
                certificate.chain_der[1].clone()
            } else {
                let url = aia.ok_or_else(|| anyhow!("OCSP issuer URL absent"))?;
                transport
                    .as_ref()
                    .ok_or_else(|| anyhow!("cached OCSP issuer absent"))?
                    .get(&url, &work)
                    .await?
            };
            let leaf_der = certificate.chain_der[0].clone();
            let issuer_for_check = issuer.clone();
            let checked_at = now()?;
            let issuer_budget = budget.clone();
            let cpu = acquire_cpu(self.inner.cpu_slots.clone(), &work).await?;
            tokio::task::spawn_blocking(move || {
                let _cpu = cpu;
                let _budget = issuer_budget;
                verify::validate_issuer(&leaf_der, &issuer_for_check, checked_at)
            })
            .await??;
            let known = match self.observed(&certificate.identity) {
                Ok(known) => known,
                Err(_) => {
                    // Diagnostic bookkeeping cannot prevent authentication of
                    // a newly received fact. The later observe still reports
                    // the error, after the shared leaf has learned the fact.
                    self.emit(
                        &certificate,
                        "ocsp_observation_state_unavailable",
                        None,
                        quiet,
                    );
                    None
                }
            };
            if let Some(observed) = known.as_ref().filter(|o| o.status.state != OcspState::Good) {
                self.apply_negative(&certificate, &observed.status, quiet)
                    .await?;
            }
            let mut previous = known
                .filter(|o| o.status.state == OcspState::Good && o.status.valid_until > checked_at)
                .map(|o| o.status);
            if let Some(raw) = self.inner.store.load(&cache_key).await? {
                if raw.len() > 1024 * 1024 {
                    if mode == RefreshMode::CacheOnly {
                        restored = CacheRestore::Invalid;
                        return Ok(());
                    }
                    self.inner.store.delete_fenced(&cache_key, &lease).await?;
                    return Err(anyhow!("OCSP cache exceeds response size limit"));
                }
                match verify_owned(
                    raw.to_vec(),
                    certificate.chain_der[0].clone(),
                    issuer.clone(),
                    config.no_next_update_max_age,
                    None,
                    Some(budget.clone()),
                    acquire_cpu(self.inner.cpu_slots.clone(), &work).await?,
                )
                .await
                {
                    Ok((status, proof)) => {
                        self.note_key_compromise(proof, &certificate, quiet);
                        if let Err(error) = record_leaf(&certificate, &status) {
                            self.preserve_negative(&certificate, &status, quiet, None)
                                .await?;
                            return Err(error);
                        }
                        // Preserve the shared leaf fact before consulting the
                        // producer-local history. A predecessor may already
                        // know a newer Revoked/Unknown state for this leaf.
                        if mode == RefreshMode::CacheOnly
                            && status.state == OcspState::Good
                            && !certificate.leaf_state.admission().allow_staple
                        {
                            restored = CacheRestore::StaleStatus;
                            return Ok(());
                        }
                        let accepted = match self.observe(&certificate, &status, true) {
                            Ok(value) => value,
                            Err(error) => {
                                self.preserve_negative(&certificate, &status, quiet, None)
                                    .await?;
                                return Err(error);
                            }
                        };
                        if accepted {
                            restored = CacheRestore::Restored {
                                status: status.clone(),
                            };
                            if status.state == OcspState::Good {
                                lease.check().await?;
                                ensure!(!work.is_cancelled(), "OCSP refresh cancelled");
                                if !self.inner.resolver.set_ocsp(
                                    &certificate.identity,
                                    certificate.generation,
                                    Some((raw.to_vec(), status.valid_until)),
                                )? {
                                    restored = CacheRestore::StaleGeneration;
                                    return Ok(());
                                }
                                let fresh =
                                    status.next_update.is_some() && checked_at < status.refresh_at;
                                previous = Some(status.clone());
                                if fresh || mode == RefreshMode::CacheOnly {
                                    self.record(&certificate, Some(status.clone()), None)?;
                                    self.emit(
                                        &certificate,
                                        "ocsp_staple_loaded",
                                        Some(status),
                                        quiet,
                                    );
                                    return Ok(());
                                }
                            } else {
                                self.apply_negative(&certificate, &status, quiet).await?;
                                if mode == RefreshMode::CacheOnly
                                    && !self.inner.resolver.set_ocsp(
                                        &certificate.identity,
                                        certificate.generation,
                                        None,
                                    )?
                                {
                                    restored = CacheRestore::StaleGeneration;
                                }
                            }
                        } else {
                            restored = CacheRestore::StaleStatus;
                        }
                    }
                    Err(error) => {
                        if mode == RefreshMode::CacheOnly {
                            restored = if error.is::<verify::ExpiredStatus>() {
                                CacheRestore::Expired
                            } else {
                                CacheRestore::Invalid
                            };
                        } else {
                            self.inner.store.delete_fenced(&cache_key, &lease).await?;
                        }
                    }
                }
            }
            if mode == RefreshMode::CacheOnly {
                self.reconcile_known_negative(&certificate, quiet).await?;
                return Ok(());
            }
            if query_disabled {
                if previous.is_none() {
                    self.inner.resolver.set_ocsp(
                        &certificate.identity,
                        certificate.generation,
                        None,
                    )?;
                }
                self.record(&certificate, previous, None)?;
                return Ok(());
            }
            let fetched = async {
                let request = create_request(&certificate.chain_der[0], &issuer)?;
                let raw = transport
                    .as_ref()
                    .ok_or_else(|| anyhow!("OCSP network is unavailable in cached-only mode"))?
                    .post(&responder, &request, &work)
                    .await?;
                let (status, proof) = verify_owned(
                    raw.clone(),
                    certificate.chain_der[0].clone(),
                    issuer,
                    config.no_next_update_max_age,
                    None,
                    Some(budget.clone()),
                    acquire_cpu(self.inner.cpu_slots.clone(), &work).await?,
                )
                .await?;
                self.note_key_compromise(proof, &certificate, quiet);
                // Authentication establishes a leaf fact independently of
                // whether this job still owns permission to write the cache.
                if let Err(error) = record_leaf(&certificate, &status) {
                    self.preserve_negative(
                        &certificate,
                        &status,
                        quiet,
                        Some((&cache_key, &raw, &lease)),
                    )
                    .await?;
                    return Err(error);
                }
                lease.check().await?;
                ensure!(!work.is_cancelled(), "OCSP refresh cancelled");
                let accepted = match self.observe(&certificate, &status, false) {
                    Ok(value) => value,
                    Err(error) => {
                        self.preserve_negative(
                            &certificate,
                            &status,
                            quiet,
                            Some((&cache_key, &raw, &lease)),
                        )
                        .await?;
                        return Err(error);
                    }
                };
                if !accepted {
                    if let Some(known) = self
                        .observed(&certificate.identity)?
                        .filter(|o| o.status.state != OcspState::Good)
                    {
                        self.apply_negative(&certificate, &known.status, quiet)
                            .await?;
                    }
                    return Err(anyhow!(
                        "OCSP response is older than an authenticated known status"
                    ));
                }
                if status.state == OcspState::Good {
                    let publication = self.inner.resolver.set_ocsp(
                        &certificate.identity,
                        certificate.generation,
                        Some((raw.clone(), status.valid_until)),
                    );
                    let persisted = self
                        .inner
                        .store
                        .store_fenced(&cache_key, &raw, &lease)
                        .await;
                    self.mark_persisted(&certificate.identity, &status, persisted.is_ok())?;
                    if let Err(error) = persisted {
                        self.cache_error(&certificate, &error, quiet);
                    }
                    let current = publication?;
                    self.emit(
                        &certificate,
                        if current {
                            "ocsp_staple_updated"
                        } else {
                            "ocsp_status_observed"
                        },
                        Some(status.clone()),
                        quiet,
                    );
                } else {
                    // Persist authenticated negative responses too. The format
                    // remains raw DER understood by original Caddy, which never
                    // staples NonGood. A disk failure still retains the volatile
                    // observation and must not hide the identity-level event.
                    let persisted = self
                        .inner
                        .store
                        .store_fenced(&cache_key, &raw, &lease)
                        .await;
                    self.mark_persisted(&certificate.identity, &status, persisted.is_ok())?;
                    if let Err(error) = persisted {
                        self.cache_error(&certificate, &error, quiet);
                    }
                    self.apply_negative(&certificate, &status, quiet).await?;
                }
                Ok(status)
            }
            .await;
            match fetched {
                Ok(status) => {
                    self.record(&certificate, Some(status), None)?;
                    Ok(())
                }
                Err(error) => {
                    let known = self.observed(&certificate.identity)?;
                    previous = known
                        .filter(|o| {
                            o.status.state == OcspState::Good
                                && o.status.valid_until > now().unwrap_or(i64::MAX)
                        })
                        .map(|o| o.status);
                    if previous.is_none() {
                        self.inner.resolver.set_ocsp(
                            &certificate.identity,
                            certificate.generation,
                            None,
                        )?;
                    }
                    self.record(&certificate, previous, Some(()))?;
                    Err(error)
                }
            }
        }
        .await;
        stop_watch.cancel();
        let watcher_result = watcher
            .await
            .map_err(|_| anyhow!("OCSP lease watcher failed"));
        let release = lease.release().await;
        result.and(watcher_result).and(release)?;
        Ok(restored)
    }

    fn responder_limit(&self, responder: &str) -> Result<Arc<Semaphore>> {
        let url =
            reqwest::Url::parse(responder).map_err(|_| anyhow!("invalid OCSP responder URL"))?;
        let origin = url.origin().ascii_serialization();
        let mut limits = self
            .inner
            .resources
            .responders
            .lock()
            .map_err(|_| anyhow!("OCSP limiter state unavailable"))?;
        limits.retain(|_, v| v.strong_count() > 0);
        Ok(match limits.get(&origin).and_then(Weak::upgrade) {
            Some(v) => v,
            None => {
                let v = Arc::new(Semaphore::new(
                    self.inner.options.max_concurrent_per_responder,
                ));
                limits.insert(origin, Arc::downgrade(&v));
                v
            }
        })
    }
    fn note_key_compromise(&self, proof: Option<LiveKeyCompromiseFact>,
        certificate: &OcspCertificate, quiet: bool) {
        let Some(proof) = proof else { return; };
        let result = (|| {
            let guard=self.inner.resolver.leaf_guard();let deny=guard.key_deny();
            ensure!(deny.owns_state(&certificate.key_state) && certificate.key_state.spki_der()==proof.spki_der(),
                "OCSP observation key reservation changed");
            deny.record_observed(proof)
        })();
        if let Err(error) = result {
            self.cache_error(certificate, &error, quiet);
            self.emit(certificate, if error.is::<crate::key_compromise::KeyCompromiseNotDurable>() {
                "key_compromise_not_durable"
            } else { "key_compromise_not_recorded" }, None, quiet);
        }
    }

    fn observed(&self, identity: &[u8; 32]) -> Result<Option<Observed>> {
        Ok(self
            .inner
            .observations
            .lock()
            .map_err(|_| anyhow!("OCSP observation state unavailable"))?
            .get(identity)
            .cloned())
    }
    fn observe(
        &self,
        certificate: &OcspCertificate,
        status: &VerifiedStatus,
        persisted: bool,
    ) -> Result<bool> {
        let identity = &certificate.identity;
        let mut observations = self
            .inner
            .observations
            .lock()
            .map_err(|_| anyhow!("OCSP observation state unavailable"))?;
        if let Some(previous) = observations.get(identity)
            && status_order(status, &previous.status).is_lt()
        {
            return Ok(false);
        }
        if !observations.contains_key(identity)
            && observations.len() >= crate::tls_resolver::MAX_CERTIFICATES
        {
            // Retired identities are also pruned here for explicit refresh_one
            // callers which do not run the inventory maintenance loop.
            let current = self.inner.resolver.ocsp_identities()?;
            observations.retain(|identity, _| current.contains(identity));
        }
        ensure!(
            observations.contains_key(identity)
                || observations.len() < crate::tls_resolver::MAX_CERTIFICATES,
            "OCSP observation capacity exhausted"
        );
        observations.insert(
            *identity,
            Observed {
                leaf_sha256: leaf_hash(certificate),
                status: status.clone(),
                persisted,
            },
        );
        Ok(true)
    }
    fn mark_persisted(
        &self,
        identity: &[u8; 32],
        status: &VerifiedStatus,
        persisted: bool,
    ) -> Result<()> {
        let mut observations = self
            .inner
            .observations
            .lock()
            .map_err(|_| anyhow!("OCSP observation state unavailable"))?;
        if let Some(observed) = observations.get_mut(identity)
            && status_order(&observed.status, status).is_eq()
        {
            observed.persisted = persisted;
        }
        Ok(())
    }
    async fn preserve_negative(
        &self,
        certificate: &OcspCertificate,
        status: &VerifiedStatus,
        quiet: bool,
        cache: Option<(&str, &[u8], &crate::certstore::StorageLease)>,
    ) -> Result<()> {
        if status.state == OcspState::Good {
            return Ok(());
        }
        if let Some((key, raw, lease)) = cache
            && let Err(error) = self.inner.store.store_fenced(key, raw, lease).await
        {
            self.cache_error(certificate, &error, quiet);
        }
        self.apply_negative(certificate, status, quiet).await
    }
    async fn apply_negative(
        &self,
        certificate: &OcspCertificate,
        status: &VerifiedStatus,
        quiet: bool,
    ) -> Result<()> {
        ensure!(
            status.state != OcspState::Good,
            "negative OCSP state expected"
        );
        let kind = if status.state == OcspState::Revoked {
            "cert_ocsp_revoked"
        } else {
            "ocsp_status_unknown"
        };
        let mut conflict = None;
        for _ in 0..8 {
            let resolver = self.inner.resolver.clone();
            let identity = certificate.identity;
            let all = crate::cert_cpu::run(
                self.inner.cpu_slots.clone(),
                CancellationToken::new(),
                move || resolver.ocsp_certificates_for_identity(&identity),
            )
            .await?;
            let mut retired = false;
            let mut found = false;
            for current in all
                .into_iter()
                .filter(|current| current.identity == certificate.identity)
            {
                found = true;
                match self
                    .inner
                    .resolver
                    .set_ocsp(&current.identity, current.generation, None)
                {
                    Ok(true) => {}
                    Ok(false) => retired = true,
                    Err(error) => {
                        retired = true;
                        conflict = Some(error);
                    }
                }
                self.emit_negative(&current, kind, status, quiet);
            }
            if !found {
                self.emit_negative(certificate, kind, status, quiet);
            }
            if !retired {
                return Ok(());
            }
        }
        Err(conflict
            .unwrap_or_else(|| anyhow::Error::new(crate::tls_resolver::OcspPublishConflict)))
    }
    fn emit_negative(
        &self,
        certificate: &OcspCertificate,
        kind: &'static str,
        status: &VerifiedStatus,
        quiet: bool,
    ) {
        let persisted = self
            .observed(&certificate.identity)
            .ok()
            .flatten()
            .is_some_and(|o| o.persisted);
        let notice = NegativeNotice {
            this_update: status.this_update,
            state: status.state,
            reason: status.revocation_reason,
            revoked_at: status.revoked_at,
            persisted,
        };
        let changed = match self.inner.entries.lock() {
            Ok(mut entries) => {
                let entry = entries
                    .entry((certificate.identity, certificate.generation))
                    .or_default();
                let changed = entry.negative_notice.as_ref() != Some(&notice);
                entry.negative_notice = Some(notice);
                changed
            }
            Err(_) => true, // A bookkeeping failure cannot suppress authenticated revocation.
        };
        if changed {
            self.emit(certificate, kind, Some(status.clone()), quiet);
        }
    }
    fn cache_error(&self, certificate: &OcspCertificate, error: &anyhow::Error, quiet: bool) {
        let _ = self.inner.events.send(OcspEvent {
            identity: certificate.identity,
            leaf_sha256: leaf_hash(certificate),
            generation: certificate.generation,
            names: certificate.names.clone(),
            kind: "ocsp_cache_write_failed",
            status: None,
            quiet,
            error: Some(error.to_string().chars().take(512).collect()),
            persisted: Some(false),
        });
    }
    fn emit(
        &self,
        certificate: &OcspCertificate,
        kind: &'static str,
        status: Option<VerifiedStatus>,
        quiet: bool,
    ) {
        let persisted = self
            .observed(&certificate.identity)
            .ok()
            .flatten()
            .map(|o| o.persisted)
            .or_else(|| status.as_ref().map(|_| false));
        let _ = self.inner.events.send(OcspEvent {
            identity: certificate.identity,
            leaf_sha256: leaf_hash(certificate),
            generation: certificate.generation,
            names: certificate.names.clone(),
            kind,
            status,
            quiet,
            error: None,
            persisted,
        });
    }
    fn record(
        &self,
        certificate: &OcspCertificate,
        status: Option<VerifiedStatus>,
        failed: Option<()>,
    ) -> Result<()> {
        let now = now()?;
        let mut entries = self
            .inner
            .entries
            .lock()
            .map_err(|_| anyhow!("OCSP maintenance state unavailable"))?;
        let entry = entries
            .entry((certificate.identity, certificate.generation))
            .or_default();
        if status.as_ref().is_some_and(|s| s.state == OcspState::Good) {
            entry.negative_notice = None;
        }
        entry.status = status;
        let interval = if failed.is_some() {
            entry.failures = entry.failures.saturating_add(1);
            let base = self
                .inner
                .options
                .retry_initial
                .as_secs()
                .saturating_mul(1u64 << entry.failures.saturating_sub(1).min(20))
                .min(self.inner.options.retry_max.as_secs());
            base + base.saturating_mul(certificate.identity[0] as u64 % 11) / 100
        } else {
            entry.failures = 0;
            self.inner.options.check_interval.as_secs()
        };
        entry.next_check = now.saturating_add(interval.min(i64::MAX as u64) as i64);
        if failed.is_none()
            && let Some(status) = &entry.status
        {
            entry.next_check = entry.next_check.min(if status.refresh_at > now {
                status.refresh_at
            } else {
                now.saturating_add(self.inner.options.retry_initial.as_secs() as i64)
            });
        }
        Ok(())
    }

    /// Independent certificate jobs are bounded by both the global and each
    /// responder's limits. Slow or failing responders do not run under TLS or
    /// inventory locks. On shutdown every launched job is cancelled and joined.
    pub async fn run(&self, cancel: CancellationToken) -> Result<()> {
        // Inventory data is retained as shared public-only records. Completing
        // a job or reaching a retry deadline never reclones the full TLS cache.
        let mut tasks = FuturesUnordered::new();
        let mut active: HashMap<CertificateKey, CancellationToken> = HashMap::new();
        let mut inventory: HashMap<CertificateKey, Arc<OcspCertificate>> = HashMap::new();
        let mut refresh_inventory = true;
        let mut schedule = true;
        let mut waiting = false;
        let mut next_scan = tokio::time::Instant::now();
        let result=async { loop {
            if cancel.is_cancelled(){break;}
            if refresh_inventory||tokio::time::Instant::now()>=next_scan {
                refresh_inventory=false;next_scan=tokio::time::Instant::now()+self.inner.options.check_interval;
                let resolver=self.inner.resolver.clone();
                let identity=self.inner.identity_scope;
                let certificates=crate::cert_cpu::run(self.inner.cpu_slots.clone(),cancel.clone(),move||match identity {
                    Some(identity)=>Ok(resolver.ocsp_current_certificate(&identity)?.into_iter().collect()),
                    None=>resolver.ocsp_certificates(),
                }).await?;
                let certificates=certificates.into_iter().filter(|certificate|(self.inner.inventory)(certificate)).collect::<Vec<_>>();
                ensure!(certificates.len()<=crate::tls_resolver::MAX_CERTIFICATES,"OCSP inventory exceeds resolver certificate limit");
                let current:HashSet<_>=certificates.iter().map(|c|(c.identity,c.generation)).collect();
                for (key,token) in &active{if !current.contains(key){token.cancel();}}
                self.inner.entries.lock().map_err(|_|anyhow!("OCSP maintenance state unavailable"))?.retain(|key,_|current.contains(key));
                let identities:HashSet<_>=current.iter().map(|key|key.0).collect();
                self.inner.observations.lock().map_err(|_|anyhow!("OCSP observation state unavailable"))?.retain(|identity,_|identities.contains(identity));
                inventory=certificates.into_iter().map(|certificate|((certificate.identity,certificate.generation),Arc::new(certificate))).collect();
                schedule=true;
            }
            if schedule {schedule=false;waiting=false;
            let checked_at=now()?;
            for (key,certificate) in &inventory {
                if active.contains_key(key){continue;}
                let due=self.inner.entries.lock().map_err(|_|anyhow!("OCSP maintenance state unavailable"))?.get(key).is_none_or(|e|e.next_check<=checked_at);
                if !due{continue;}
                if tasks.len()>=4096{waiting=true;continue;}
                let token=cancel.child_token();active.insert(*key,token.clone());let manager=self.clone();let certificate=certificate.clone();let key=*key;
                tasks.push(async move {
                    let result=std::panic::AssertUnwindSafe(manager.refresh_shared(certificate,token)).catch_unwind().await
                        .unwrap_or_else(|_|Err(anyhow!("OCSP worker panicked")));
                    (key,result)
                });
            }}
            let wake={let entries=self.inner.entries.lock().map_err(|_|anyhow!("OCSP maintenance state unavailable"))?;let checked_at=now()?;
                entries.iter().filter(|(key,_)|!active.contains_key(key)).map(|(_,e)|Duration::from_secs(e.next_check.saturating_sub(checked_at).max(1)as u64)).min().unwrap_or(self.inner.options.check_interval)};
            tokio::select! {
                _ =cancel.cancelled()=>break,
                _ =self.inner.changed.notified()=>{refresh_inventory=true;},
                _ =tokio::time::sleep(wake.min(next_scan.saturating_duration_since(tokio::time::Instant::now())))=>{schedule=true;},
                result=tasks.next(),if !tasks.is_empty()=>{
                    if let Some((key,_))=result {
                        active.remove(&key);schedule=waiting;
                        let mut entries=self.inner.entries.lock().map_err(|_|anyhow!("OCSP maintenance state unavailable"))?;
                        let entry=entries.entry(key).or_default();
                        if !entry.publish_blocked&&entry.next_check<=now()?{entry.next_check=now()?.saturating_add(self.inner.options.retry_initial.as_secs()as i64);}
                    }
                }
            }
        } Ok(()) }.await;
        for token in active.values() {
            token.cancel();
        }
        // Drain instead of dropping futures: their bounded blocking crypto and
        // lease-loss watcher tasks must finish and release the held scope.
        while tasks.next().await.is_some() {}
        if cancel.is_cancelled() {
            Ok(())
        } else {
            result
        }
    }
}
fn record_leaf(certificate: &OcspCertificate, status: &VerifiedStatus) -> Result<()> {
    use crate::leaf_guard::{Observation, Status};
    certificate.observe_leaf(Observation {
        status: match status.state {
            OcspState::Good => Status::Good,
            OcspState::Revoked => Status::Revoked,
            OcspState::Unknown => Status::Unknown,
        },
        this_update: status.this_update,
        produced_at: status.produced_at,
        valid_until: status.valid_until,
        reason: status.revocation_reason,
    })
}

struct CertificateInspection {
    quiet: bool,
    must_staple: bool,
    responder: Option<String>,
    aia: Option<String>,
    cache_key: String,
}
fn inspect_certificate(chain: &[Vec<u8>]) -> Result<CertificateInspection> {
    ensure!(!chain.is_empty(), "OCSP certificate chain empty");
    let leaf = verify::certificate(&chain[0])?;
    let parsed_staple = verify::must_staple(&leaf);
    let quiet = leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp()
        < 7 * 86400
        && !parsed_staple.as_ref().copied().unwrap_or(true);
    let (responder, aia) = verify::endpoints(&chain[0])?;
    // Preserve the existing error boundary: a malformed TLS feature matters
    // here only when there is no responder; online verification is unchanged.
    let must_staple = if responder.is_none() {
        parsed_staple?
    } else {
        parsed_staple.unwrap_or(true)
    };
    Ok(CertificateInspection {
        quiet,
        must_staple,
        responder,
        aia,
        cache_key: cache_key(&[], chain),
    })
}

struct OcspNetworkBudget {
    _global: tokio::sync::OwnedSemaphorePermit,
    _responder: Option<tokio::sync::OwnedSemaphorePermit>,
}
async fn acquire_cpu(
    cpu: Arc<Semaphore>,
    cancel: &CancellationToken,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    tokio::select! {biased;
        _ = cancel.cancelled() => Err(anyhow!("OCSP CPU dispatch cancelled")),
        permit = cpu.acquire_owned() => permit.map_err(|_|anyhow!("OCSP CPU dispatch stopped")),
    }
}
async fn verify_owned(
    raw: Vec<u8>,
    leaf: Vec<u8>,
    issuer: Vec<u8>,
    max_age: Duration,
    admission: Option<tokio::sync::OwnedSemaphorePermit>,
    budget: Option<Arc<OcspNetworkBudget>>,
    cpu: tokio::sync::OwnedSemaphorePermit,
) -> Result<(VerifiedStatus, Option<LiveKeyCompromiseFact>)> {
    verify_owned_prepared(raw,leaf,issuer,max_age,admission,budget,cpu,None).await
}
async fn verify_owned_prepared(
    raw: Vec<u8>,
    leaf: Vec<u8>,
    issuer: Vec<u8>,
    max_age: Duration,
    admission: Option<tokio::sync::OwnedSemaphorePermit>,
    budget: Option<Arc<OcspNetworkBudget>>,
    cpu: tokio::sync::OwnedSemaphorePermit,
    preparation: Option<Arc<crate::tls_app_config::CertificatePreparation>>,
) -> Result<(VerifiedStatus, Option<LiveKeyCompromiseFact>)> {
    tokio::task::spawn_blocking(move || {
        // Tuple field order destroys actual copied inputs before admission.
        let input = ((raw,leaf,issuer),preparation);
        let _cpu = cpu;
        let now = now()?;
        let _admission = admission;
        let _budget = budget;
        verify::verify_response_observation(&input.0.0, &input.0.1, &input.0.2, now, max_age)
    })
    .await?
}
fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// CertMagic's legacy cache key uses FNV-1a32 of concatenated 64-column LF PEM.
/// This key is only a locator; every loaded response is cryptographically bound
/// to the actual leaf serial and issuer before use, including hash collisions.
/// The prefix derives exclusively from leaf DER (CN, then DNS/IP/email/URI),
/// never the resolver's alias list: one chain identity always has one cache key.
pub fn cache_key(_names: &[String], chain: &[Vec<u8>]) -> String {
    let mut hash = 0x811c9dc5u32;
    for der in chain {
        let encoded = pem::encode_config(
            &pem::Pem::new("CERTIFICATE", der.as_slice()),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );
        for byte in encoded.bytes() {
            hash = (hash ^ (byte as u32)).wrapping_mul(0x01000193);
        }
    }
    let primary = chain
        .first()
        .and_then(|der| verify::certificate(der).ok())
        .and_then(|cert| {
            let common_name = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|a| a.as_str().ok())
                .filter(|v| !v.is_empty())
                .map(str::to_owned);
            common_name.or_else(|| {
                cert.subject_alternative_name()
                    .ok()
                    .flatten()
                    .and_then(|san| {
                        use x509_parser::extensions::GeneralName;
                        let names = &san.value.general_names;
                        names
                            .iter()
                            .find_map(|name| match name {
                                GeneralName::DNSName(name) => Some((*name).to_owned()),
                                _ => None,
                            })
                            .or_else(|| {
                                names.iter().find_map(|name| match name {
                                    GeneralName::IPAddress(bytes) => {
                                        if let Ok(bytes) = <[u8; 4]>::try_from(*bytes) {
                                            Some(std::net::Ipv4Addr::from(bytes).to_string())
                                        } else if let Ok(bytes) = <[u8; 16]>::try_from(*bytes) {
                                            let address = std::net::Ipv6Addr::from(bytes);
                                            Some(
                                                address
                                                    .to_ipv4_mapped()
                                                    .map(|ip| ip.to_string())
                                                    .unwrap_or_else(|| address.to_string()),
                                            )
                                        } else {
                                            None
                                        }
                                    }
                                    _ => None,
                                })
                            })
                            .or_else(|| {
                                names.iter().find_map(|name| match name {
                                    GeneralName::RFC822Name(name) => Some((*name).to_owned()),
                                    _ => None,
                                })
                            })
                            .or_else(|| {
                                names.iter().find_map(|name| match name {
                                    GeneralName::URI(name) => Some((*name).to_owned()),
                                    _ => None,
                                })
                            })
                    })
            })
        });
    let prefix = primary
        .map(|name| format!("{}-", certstore::safe(&name)))
        .unwrap_or_default();
    format!("ocsp/{prefix}{hash:x}")
}

fn status_order(a: &VerifiedStatus, b: &VerifiedStatus) -> std::cmp::Ordering {
    fn rank(state: OcspState) -> u8 {
        match state {
            OcspState::Good => 0,
            OcspState::Unknown => 1,
            OcspState::Revoked => 2,
        }
    }
    a.this_update
        .cmp(&b.this_update)
        .then_with(|| rank(a.state).cmp(&rank(b.state)))
        .then_with(|| a.produced_at.cmp(&b.produced_at))
        .then_with(|| a.valid_until.cmp(&b.valid_until))
}
fn leaf_hash(certificate: &OcspCertificate) -> [u8; 32] {
    certificate
        .chain_der
        .first()
        .map(|der| Sha256::digest(der).into())
        .unwrap_or([0u8; 32])
}
