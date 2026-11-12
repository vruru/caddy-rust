//! ACME orchestration with resumable private checkpoints and per-name leases.
//! This module does not bind ports. HTTP-01/TLS-ALPN-01 listeners must use the
//! same ChallengeRegistry supplied to this manager and be ready before ensure.
//! FileStorage's legacy stale-lock protocol is not a distributed fencing
//! service; deployments must keep only one active certificate-manager runtime.

use crate::{
    acme_wire::{
        AccountSession, AccountSigner, AcmeWire, AriWindow, Identifier, KeyType, Order,
        ProtocolError, WireOptions, ari_certificate_id,
    },
    certstore::{
        CertificateBundle, FsStore, RecoveryReport, StorageLease, StoredAccount, account_lock_name,
        account_primary, issuer_key, names_key,
    },
    challenge::{ChallengeLease, ChallengeRegistry},
    tls_resolver::{CertificateInput, HotCertificateResolver},
};
use anyhow::{Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, OnceCell, Semaphore, broadcast},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}
impl ChallengeType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::TlsAlpn01 => "tls-alpn-01",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExternalAccountBinding {
    pub kid: String,
    pub hmac_key: String,
}

impl Drop for ExternalAccountBinding {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}
/// Caddy 2.11.7 defaults: LE alone without an email; append ZeroSSL only with
/// an email. Explicit issuer configurations should replace this entire list.
pub fn default_issuers(email: &str) -> Vec<AcmeIssuerConfig> {
    let mut primary = AcmeIssuerConfig::lets_encrypt();
    primary.email = email.to_owned();
    let mut result = vec![primary];
    if !email.is_empty() {
        let mut zero = result[0].clone();
        zero.wire.directory = "https://acme.zerossl.com/v2/DV90".to_owned();
        result.push(zero);
    }
    result
}

#[derive(Clone)]
pub struct AcmeIssuerConfig {
    pub wire: WireOptions,
    pub email: String,
    pub account_key_type: KeyType,
    pub leaf_key_type: KeyType,
    pub certificate_lifetime_ns: i64,
    pub profile: String,
    pub challenge_types: Vec<ChallengeType>,
    pub terms_of_service_agreed: bool,
    pub eab: Option<ExternalAccountBinding>,
}
impl AcmeIssuerConfig {
    pub fn lets_encrypt() -> Self {
        Self {
            wire: WireOptions {
                directory: "https://acme-v02.api.letsencrypt.org/directory".to_owned(),
                extra_ca_pem: Vec::new(),
                trusted_ca_origins: Vec::new(),
                allow_insecure_loopback: false,
                request_timeout: Duration::from_secs(30),
                network_proxy:None,
            },
            email: String::new(),
            account_key_type: KeyType::P256,
            leaf_key_type: KeyType::P256,
            certificate_lifetime_ns: 0,
            profile: String::new(),
            challenge_types: vec![ChallengeType::Http01, ChallengeType::TlsAlpn01],
            terms_of_service_agreed: true,
            eab: None,
        }
    }
}

#[derive(Clone)]
pub struct AutomationOptions {
    pub issuers: Vec<AcmeIssuerConfig>,
    pub renewal_window_ratio: f64,
    pub max_concurrent: usize,
    pub max_concurrent_per_ca: usize,
    pub poll_interval: Duration,
    pub job_timeout: Duration,
}
impl Default for AutomationOptions {
    fn default() -> Self {
        Self {
            issuers: default_issuers(""),
            renewal_window_ratio: 1.0 / 3.0,
            max_concurrent: 10,
            max_concurrent_per_ca: 2,
            poll_interval: Duration::from_secs(300),
            job_timeout: Duration::from_secs(1200),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ManagedCertificate {
    pub names: Vec<String>,
    pub issuer_key: String,
    pub not_after_unix: i64,
    pub renew_at_unix: i64,
    pub leaf_sha256: String,
    pub obtained: bool,
}
/// Explicit lifecycle control results; ordinary handler failures still continue.
#[derive(Debug)]
pub struct ObtainEventAborted;
impl std::fmt::Display for ObtainEventAborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate obtaining aborted by event handler")
    }
}
impl std::error::Error for ObtainEventAborted {}
#[derive(Debug)]
pub struct ObtainEventCancelled;
impl std::fmt::Display for ObtainEventCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate obtaining event cancelled")
    }
}
impl std::error::Error for ObtainEventCancelled {}
#[derive(Debug)]
pub struct ObtainEventRejected(pub crate::events::Reject);
impl std::fmt::Display for ObtainEventRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "certificate obtaining event rejected: {:?}", self.0)
    }
}
impl std::error::Error for ObtainEventRejected {}
#[derive(Clone, Debug)]
pub struct AutomationEvent {
    pub names: Vec<String>,
    pub kind: &'static str,
    pub recovery_issue: Option<Value>,
}

/// Explicit administrator recovery, never selected by automatic retry loops.
/// ConfirmNoOrder is a statement that the operator checked the CA and accepts
/// creating a new order; elapsed time alone is not sufficient evidence.
pub enum OrderResolution {
    Attach { order_url: String },
    ConfirmNoOrder,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoadMode {
    Online,
    CacheOnly,
    Probe,
    Refresh,
}

pub(crate) enum RefreshOutcome {
    Usable {
        certificate: ManagedCertificate,
        ari_after: i64,
    },
    Unusable,
    Missing,
}

#[derive(Debug)]
pub(crate) struct PendingPromotion;
impl std::fmt::Display for PendingPromotion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ACME certificate cache has an unpromoted issuance attempt")
    }
}
impl std::error::Error for PendingPromotion {}

/// Strict read-only candidate inspection. Busy never waits for a same-manager
/// name gate; material is one stable grouped storage snapshot, not an issuance
/// candidate or permission to serve an expired, future or revoked certificate.
pub enum CachedProbe {
    Busy,
    Missing,
    Material {
        usable: Option<ManagedCertificate>,
        bundle: CertificateBundle,
    },
}

#[derive(Clone)]
pub struct CertificateManager {
    inner: Arc<ManagerInner>,
}
struct ManagerInner {
    must_staple: bool,
    reuse_private_keys: bool,
    lifecycle_events: Option<Arc<crate::events::EventsApp>>,
    store: FsStore,
    registry: ChallengeRegistry,
    resolver: Arc<HotCertificateResolver>,
    publish_to_resolver: bool,
    options: AutomationOptions,
    global: Arc<Semaphore>,
    local: Arc<Semaphore>,
    solver: Option<SolverPreparation>,
    issuers: Vec<IssuerState>,
    gates: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    events: broadcast::Sender<AutomationEvent>,
    recovered: OnceCell<RecoveryReport>,
    recovery_announced: AtomicBool,
}
/// Prepare a real listener only for the selected pending authorization. The
/// owner must retain its listener lease through ensure and release it on every
/// completion/cancellation path. No callback is made for cached/ARI-only work.
pub type SolverPreparation = Arc<
    dyn Fn(
            String,
            ChallengeType,
            CancellationToken,
        ) -> futures_util::future::BoxFuture<'static, Result<()>>
        + Send
        + Sync,
>;
struct CaState {
    limiter: Arc<Semaphore>,
    next_allowed_unix: Arc<AtomicI64>,
}
/// Process-shared issuance limits. Root configuration generations and distinct
/// automation policies must reuse this object instead of multiplying budgets.
pub struct AutomationResources {
    global: Arc<Semaphore>,
    permission_global: Arc<Semaphore>,
    local: Arc<Semaphore>,
    cas: std::sync::Mutex<HashMap<String, Weak<Semaphore>>>,
    cooldowns: std::sync::Mutex<HashMap<[u8; 32], Arc<AtomicI64>>>,
    max_concurrent: usize,
    max_per_ca: usize,
}
impl AutomationResources {
    pub(crate) fn cpu_slots(&self) -> Arc<Semaphore> {
        self.local.clone()
    }
    pub fn limits(&self) -> (usize, usize) {
        (self.max_concurrent, self.max_per_ca)
    }
    pub fn new(max_concurrent: usize, max_per_ca: usize) -> Result<Self> {
        ensure!(
            (1..=128).contains(&max_concurrent) && (1..=32).contains(&max_per_ca),
            "ACME concurrency outside bounds"
        );
        Ok(Self {
            global: Arc::new(Semaphore::new(max_concurrent)),
            permission_global: Arc::new(Semaphore::new(max_concurrent)),
            local: Arc::new(Semaphore::new(
                std::thread::available_parallelism()
                    .map_or(1, usize::from)
                    .min(4),
            )),
            cas: std::sync::Mutex::new(HashMap::new()),
            cooldowns: std::sync::Mutex::new(HashMap::new()),
            max_concurrent,
            max_per_ca,
        })
    }
    /// Permission is an independent network operation. Slow CA orders cannot
    /// consume its budget, and permission always releases before acquisition.
    pub(crate) async fn admit_permission(
        &self,
        origin: String,
        cancel: &CancellationToken,
    ) -> Result<OriginPermit> {
        ensure!(origin.len() <= 4096, "certificate origin limit exceeded");
        let issuer = tokio::select! { biased;
            _ = cancel.cancelled() => bail!("certificate operation cancelled"),
            permit = self.ca(format!("permission\0{origin}"))?.acquire_owned() => permit.map_err(|_| anyhow!("certificate origin closed"))?,
        };
        let global = tokio::select! { biased;
            _ = cancel.cancelled() => bail!("certificate operation cancelled"),
            permit = self.permission_global.clone().acquire_owned() => permit.map_err(|_| anyhow!("certificate networking closed"))?,
        };
        Ok(OriginPermit {
            _global: global,
            _issuer: issuer,
        })
    }
    fn ca(&self, origin: String) -> Result<Arc<Semaphore>> {
        let mut states = self
            .cas
            .lock()
            .map_err(|_| anyhow!("ACME resource state unavailable"))?;
        if let Some(state) = states.get(&origin).and_then(Weak::upgrade) {
            return Ok(state);
        }
        states.retain(|_, state| state.strong_count() > 0);
        ensure!(states.len() < 1024, "ACME origin resource limit exceeded");
        let state = Arc::new(Semaphore::new(self.max_per_ca));
        states.insert(origin, Arc::downgrade(&state));
        Ok(state)
    }
    fn cooldown(&self, store: &FsStore, config: &AcmeIssuerConfig) -> Result<Arc<AtomicI64>> {
        let mut hash = Sha256::new();
        hash.update(b"acme-equivalent-issuer-retry-v1");
        let frame = |hash: &mut Sha256, bytes: &[u8]| {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        };
        let (dev, ino) = store.root_identity();
        hash.update(dev.to_be_bytes());
        hash.update(ino.to_be_bytes());
        frame(&mut hash, config.wire.directory.as_bytes());
        frame(&mut hash, config.email.as_bytes());
        frame(&mut hash, config.profile.as_bytes());
        hash.update(config.certificate_lifetime_ns.to_be_bytes());
        frame(
            &mut hash,
            &serde_json::to_vec(&(
                config.account_key_type,
                config.leaf_key_type,
                &config.challenge_types,
            ))?,
        );
        hash.update([
            u8::from(config.terms_of_service_agreed),
            u8::from(config.wire.allow_insecure_loopback),
        ]);
        hash.update(config.wire.request_timeout.as_nanos().to_be_bytes());
        match &config.wire.network_proxy {
            None=>frame(&mut hash,b"environment"),
            Some(proxy)=>{let(kind,value)=proxy.fingerprint();frame(&mut hash,kind);frame(&mut hash,value);}
        }

        hash.update((config.wire.extra_ca_pem.len() as u64).to_be_bytes());
        for root in &config.wire.extra_ca_pem {
            frame(&mut hash, root);
        }
        hash.update((config.wire.trusted_ca_origins.len() as u64).to_be_bytes());
        for origin in &config.wire.trusted_ca_origins {
            frame(&mut hash, origin.as_bytes());
        }
        match &config.eab {
            Some(eab) => {
                hash.update([1]);
                frame(&mut hash, eab.kid.as_bytes());
                frame(&mut hash, eab.hmac_key.as_bytes());
            }
            None => hash.update([0]),
        }
        let key: [u8; 32] = hash.finalize().into();
        let mut cooldowns = self
            .cooldowns
            .lock()
            .map_err(|_| anyhow!("ACME retry state unavailable"))?;
        if let Some(state) = cooldowns.get(&key) {
            return Ok(state.clone());
        }
        let at = now();
        cooldowns
            .retain(|_, state| Arc::strong_count(state) > 1 || state.load(Ordering::Acquire) > at);
        ensure!(
            cooldowns.len() < 16_384,
            "ACME retry scope capacity exceeded"
        );
        let state = Arc::new(AtomicI64::new(0));
        cooldowns.insert(key, state.clone());
        Ok(state)
    }
}
pub(crate) struct OriginPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    _issuer: tokio::sync::OwnedSemaphorePermit,
}
struct IssuerState {
    config: AcmeIssuerConfig,
    ca: Arc<CaState>,
    wire: OnceCell<AcmeWire>,
}
// Field order releases the global budget before its issuer admission. A caller
// must not request another issuer while holding either permit.
struct NetworkPermit<'a> {
    _global: tokio::sync::SemaphorePermit<'a>,
    _issuer: tokio::sync::SemaphorePermit<'a>,
}

#[derive(Serialize, Deserialize)]
struct Job {
    version: u8,
    names: Vec<String>,
    #[serde(default)]
    renewal_names: Option<Vec<String>>,
    directory: String,
    account_location: String,
    #[serde(default)]
    config_email: String,
    #[serde(default)]
    leaf_key_type: KeyType,
    #[serde(default)]
    must_staple: bool,
    #[serde(default)]
    reuse_private_keys: bool,
    #[serde(default)]
    certificate_lifetime_ns: i64,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    attempt_id: String,
    #[serde(default)]
    abandoned: bool,
    phase: String,
    csr_der: Vec<u8>,
    private_key_pem: String,
    #[serde(default)]
    initial_key_hash: Option<String>,
    #[serde(default)]
    requested_not_after: Option<String>,
    #[serde(default)]
    order_url: Option<String>,
    #[serde(default)]
    certificate_url: Option<String>,
    #[serde(default)]
    downloaded_pem: Option<String>,
    #[serde(default)]
    stored_leaf_sha256: Option<String>,
    #[serde(default)]
    replaces_disabled: bool,
    #[serde(default)]
    poll_after_unix: i64,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

/// Reservations are issuer-local. An uncertain order is never blindly
/// repeated at that CA, but does not remove independent issuers' availability.
#[derive(Serialize, Deserialize)]
struct Reservation {
    version: u8,
    names: Vec<String>,
    directory: String,
    account_location: String,
    config_email: String,
    leaf_key_type: KeyType,
    #[serde(default)]
    must_staple: bool,
    #[serde(default)]
    reuse_private_keys: bool,
    #[serde(default)]
    certificate_lifetime_ns: i64,
    #[serde(default)]
    profile: String,
    job_id: String,
    active: bool,
}
// Reservation activity is derived from the persisted phase. Treat inconsistent
// markers as corruption; an inactive marker must never hide a live order.
fn validate_reservation_job(marker: &Reservation, job: &Job) -> Result<()> {
    ensure!(job.version == 1 && job.names == marker.names
        && job.directory == marker.directory && job.account_location == marker.account_location
        && job.config_email == marker.config_email && job.leaf_key_type == marker.leaf_key_type
        && job.must_staple == marker.must_staple && job.reuse_private_keys == marker.reuse_private_keys
        && job.certificate_lifetime_ns == marker.certificate_lifetime_ns && job.profile == marker.profile,
        "active ACME checkpoint identity changed");
    ensure!(marker.active == !["prepared", "stored"].contains(&job.phase.as_str()),
        "ACME reservation activity disagrees with its checkpoint phase");
    ensure!(job.phase != "prepared" || job.order_url.is_none(),
        "prepared ACME checkpoint retains an order URL");
    crate::acme_wire::OrderParameters {profile:job.profile.clone(),not_after:job.requested_not_after.clone()}.validate()?;
    ensure!(job.certificate_lifetime_ns == 0 || job.phase == "prepared" || job.requested_not_after.is_some(),
        "active ACME checkpoint lost requested expiry");
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Attempt {
    version: u8,
    names: Vec<String>,
    attempt_id: String,
    issuer_sequence: Vec<String>,
    current_job_id: Option<String>,
    base_leaf: Option<String>,
    winner: Option<Winner>,
}
#[derive(Serialize, Deserialize)]
struct Winner {
    issuer_key: String,
    job_id: String,
    leaf_sha256: String,
}

#[derive(Serialize, Deserialize)]
struct PendingAccount {
    version: u8,
    directory: String,
    phase: String,
    private_key_pem: String,
    #[serde(default)]
    eab: Option<ExternalAccountBinding>,
    #[serde(default)]
    storage_email: Option<String>,
    #[serde(default)]
    metadata: Option<Value>,
}
impl Drop for PendingAccount {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

struct MaterialInfo {
    not_before: i64,
    not_after: i64,
    leaf_id: crate::leaf_guard::LeafId,
    spki_der: Arc<[u8]>,
    _key_state: Arc<crate::key_compromise::KeyState>,
    leaf_sha256: String,
}
#[derive(Clone)]
pub(crate) struct ReusableKey {
    pub(crate) pem:Zeroizing<Vec<u8>>,
    pub(crate) state:Arc<crate::key_compromise::KeyState>,
    pub(crate) spki:Arc<[u8]>,
}
pub(crate) fn prepare_reusable_key(pem:Zeroizing<Vec<u8>>,deny:&crate::key_compromise::KeyDeny)->Result<ReusableKey> {
    use rcgen::PublicKeyData;
    let signer=crate::crypto::x509_signer::X509Signer::from_private_key(&pem)?;
    let spki:Arc<[u8]>=Arc::from(signer.subject_public_key_info());
    let state=deny.register_spki(spki.clone())?;
    Ok(ReusableKey{pem,state,spki})
}
#[derive(Clone)]
struct Replacement {
    reuse_key: Option<ReusableKey>,
    not_after: i64,
    forced: bool,
    renewal_names: Option<Vec<String>>,
    certificate_id: Option<String>,
    previous_leaf: String,
    directory: String,
    account: String,
}

impl CertificateManager {
    async fn net_permit<'a>(
        &'a self,
        issuer: &'a IssuerState,
        cancel: &CancellationToken,
    ) -> Result<NetworkPermit<'a>> {
        let issuer = tokio::select! { biased;
            _ = cancel.cancelled() => bail!("ACME operation cancelled"),
            permit = issuer.ca.limiter.acquire() => permit.map_err(|_| anyhow!("ACME issuer closed"))?,
        };
        let global = tokio::select! { biased;
            _ = cancel.cancelled() => bail!("ACME operation cancelled"),
            permit = self.inner.global.acquire() => permit.map_err(|_| anyhow!("ACME manager closed"))?,
        };
        Ok(NetworkPermit {
            _global: global,
            _issuer: issuer,
        })
    }
    async fn cpu<T: Send + 'static>(
        &self,
        cancel: &CancellationToken,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        crate::cert_cpu::run(self.inner.local.clone(), cancel.clone(), operation).await
    }
    async fn inspect_material(
        &self,
        bundle: &CertificateBundle,
        names: &[String],
        cancel: &CancellationToken,
    ) -> Result<MaterialInfo> {
        let bundle = CertificateBundle {
            chain_pem: bundle.chain_pem.clone(),
            private_key_pem: bundle.private_key_pem.clone(),
            metadata: Value::Null,
        };
        let names = names.to_vec();
        let deny=self.inner.resolver.leaf_guard().key_deny().clone();
        self.cpu(cancel, move || material_info(&bundle,&names,&deny)).await
    }
    async fn certificate_id(
        &self,
        pem: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Option<String>> {
        let pem = pem.to_vec();
        self.cpu(cancel, move || ari_certificate_id(&pem)).await
    }
    async fn account_signer(
        &self,
        pem: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Arc<AccountSigner>> {
        let pem = Zeroizing::new(pem.to_vec());
        self.cpu(cancel, move || Ok(Arc::new(AccountSigner::from_pem(&pem)?)))
            .await
    }
    pub fn new(
        store: FsStore,
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        options: AutomationOptions,
    ) -> Result<Self> {
        let resources = Arc::new(AutomationResources::new(
            options.max_concurrent,
            options.max_concurrent_per_ca,
        )?);
        Self::with_resources(store, registry, resolver, options, resources)
    }
    pub fn with_resources(
        store: FsStore,
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        options: AutomationOptions,
        resources: Arc<AutomationResources>,
    ) -> Result<Self> {
        Self::with_resources_and_solver(store, registry, resolver, options, resources, None)
    }
    pub fn with_resources_and_solver(
        store: FsStore,
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        options: AutomationOptions,
        resources: Arc<AutomationResources>,
        solver: Option<SolverPreparation>,
    ) -> Result<Self> {
        ensure!(
            !options.issuers.is_empty() && options.issuers.len() <= 16,
            "ACME issuer count outside bounds"
        );
        ensure!(
            options.renewal_window_ratio.is_finite()
                && options.renewal_window_ratio > 0.0
                && options.renewal_window_ratio < 1.0,
            "invalid certificate renewal ratio"
        );
        ensure!(
            (1..=128).contains(&options.max_concurrent)
                && (1..=32).contains(&options.max_concurrent_per_ca),
            "ACME concurrency outside bounds"
        );
        ensure!(
            !options.poll_interval.is_zero()
                && options.poll_interval <= Duration::from_secs(86400)
                && options.job_timeout >= Duration::from_secs(1)
                && options.job_timeout <= Duration::from_secs(3600),
            "ACME timing outside bounds"
        );
        for issuer in &options.issuers {
            ensure!(
                !issuer.challenge_types.is_empty() && issuer.challenge_types.len() <= 2,
                "ACME challenge configuration outside bounds"
            );
            issuer_key(&issuer.wire.directory)?;
            ensure!(issuer.profile.len() <= 1024, "ACME profile exceeds bounds");
        }
        ensure!(
            options.max_concurrent == resources.max_concurrent
                && options.max_concurrent_per_ca == resources.max_per_ca,
            "ACME resource budgets differ from manager options"
        );
        let mut issuers = Vec::new();
        for mut config in options.issuers.iter().cloned() {
            let directory = url::Url::parse(&config.wire.directory)
                .map_err(|_| anyhow!("invalid ACME directory URL"))?;
            config.wire.directory = directory.to_string();
            let ca = directory.origin().ascii_serialization();
            // Equivalent issuer policies on one actual store keep Retry-After
            // across per-name managers/reloads. Different accounts, TLS roots
            // or issuer configuration never inherit an unrelated cooldown.
            let state = Arc::new(CaState {
                limiter: resources.ca(ca)?,
                next_allowed_unix: resources.cooldown(&store, &config)?,
            });
            issuers.push(IssuerState {
                config,
                ca: state,
                wire: OnceCell::new(),
            });
        }
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(ManagerInner {
                must_staple:false,
                reuse_private_keys:false,
                lifecycle_events: None,
                store,
                registry,
                resolver,
                publish_to_resolver: true,
                global: resources.global.clone(),
                local: resources.local.clone(),
                solver,
                options,
                issuers,
                gates: Mutex::new(HashMap::new()),
                events,
                recovered: OnceCell::new(),
                recovery_announced: AtomicBool::new(false),
            }),
        })
    }
    /// The generation retains this event app; later reloads cannot replace it.
    pub fn with_events(mut self, events: Option<Arc<crate::events::EventsApp>>) -> Result<Self> {
        Arc::get_mut(&mut self.inner)
            .ok_or_else(|| anyhow!("certificate manager already shared"))?
            .lifecycle_events = events;
        Ok(self)
    }
    /// Generation-scoped leaf CSR behavior; account signing keys are unaffected.
    pub fn with_csr_options(mut self,must_staple:bool,reuse_private_keys:bool)->Result<Self> {
        let inner=Arc::get_mut(&mut self.inner).ok_or_else(||anyhow!("certificate manager already shared"))?;
        inner.must_staple=must_staple;inner.reuse_private_keys=reuse_private_keys;Ok(self)
    }
    async fn emit_obtaining(&self, names: &[String], previous: Option<&Replacement>,
        cancel: &CancellationToken) -> Result<crate::cert_events::Attempt> {
        let subject=names.first().ok_or_else(||anyhow!("certificate lifecycle subject missing"))?;
        let lifecycle=crate::cert_events::Attempt::new(subject,previous.map(|p|p.not_after));
        let Some(app) = &self.inner.lifecycle_events else { return Ok(lifecycle); };
        if !app.should_emit("cert_obtaining") {return Ok(lifecycle)}
        let mut data = crate::events::EventData::new();
        data.insert("identifier".to_owned(), crate::events::Value::Str(names.first()
            .ok_or_else(|| anyhow!("certificate lifecycle subject missing"))?.clone()));
        if let Some(previous) = previous {
            let remaining = lifecycle.remaining.expect("renewal remaining");
            data.insert("renewal".to_owned(), crate::events::Value::Bool(true));
            data.insert("forced".to_owned(), crate::events::Value::Bool(previous.forced));
            data.insert("remaining".to_owned(), crate::events::Value::Duration(remaining));
            data.insert("issuer".to_owned(), crate::events::Value::Str(issuer_key(&previous.directory)?));
        }
        let emitted = app.emit(crate::events::EmitContext { cancel: cancel.child_token() },
            "cert_obtaining", "tls", data).await;
        match emitted.status {
            crate::events::Status::Completed => Ok(lifecycle),
            crate::events::Status::Aborted => Err(ObtainEventAborted.into()),
            crate::events::Status::Cancelled => Err(ObtainEventCancelled.into()),
            crate::events::Status::Rejected(reason) => {
                let _ = self.inner.events.send(AutomationEvent {
                    names: names.to_vec(), kind: "cert_obtaining_rejected",
                    recovery_issue: Some(json!({"reason": format!("{reason:?}")})),
                });
                Err(ObtainEventRejected(reason).into())
            },
        }
    }
    pub fn recovery_report(&self) -> Option<RecoveryReport> {
        self.inner.recovered.get().cloned()
    }
    /// The calling generation owns certificate purpose checks and scoped
    /// publication. Keep using its LeafGuard, but never insert an unowned key.
    pub(crate) fn storage_only(mut self) -> Result<Self> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| anyhow!("certificate manager already shared"))?;
        inner.publish_to_resolver = false;
        // A service-owned single-group manager forwards results through its
        // owning Group; it doesn't need the standalone manager's large ring.
        inner.events = broadcast::channel(8).0;
        Ok(self)
    }
    async fn startup_recovery(&self, cancel: CancellationToken) -> Result<&RecoveryReport> {
        let report = self
            .inner
            .recovered
            .get_or_try_init(|| self.inner.store.recover_report(cancel))
            .await?;
        if self.inner.recovery_announced.load(Ordering::Acquire) {
            return Ok(report);
        }
        let issues = report
            .issues
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if self
            .inner
            .recovery_announced
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            for issue in issues {
                let _ = self.inner.events.send(AutomationEvent {
                    names: Vec::new(),
                    kind: "storage_scope_recovery_required",
                    recovery_issue: Some(issue),
                });
            }
        }
        Ok(report)
    }
    pub fn subscribe(&self) -> broadcast::Receiver<AutomationEvent> {
        self.inner.events.subscribe()
    }

    pub async fn resolve_ambiguous_order(
        &self,
        job_id: &str,
        resolution: OrderResolution,
        cancel: CancellationToken,
    ) -> Result<()> {
        let initial: Job = serde_json::from_value(
            self.inner
                .store
                .journal_load(job_id)
                .await?
                .ok_or_else(|| anyhow!("ACME recovery checkpoint not found"))?,
        )
        .map_err(|_| anyhow!("invalid ACME recovery checkpoint"))?;
        let names = normalize_names(&initial.names)?;
        let lease = self
            .inner
            .store
            .lock(&format!("issue_cert_{}", names[0]), cancel.clone())
            .await?;
        let result = async {
            let mut job: Job = serde_json::from_value(
                self.inner
                    .store
                    .journal_load(job_id)
                    .await?
                    .ok_or_else(|| anyhow!("ACME recovery checkpoint disappeared"))?,
            )
            .map_err(|_| anyhow!("invalid ACME recovery checkpoint"))?;
            ensure!(
                job.version == 1
                    && job.names == names
                    && job.order_url.is_none()
                    && job.phase == "new_order_intent",
                "checkpoint is not an ambiguous newOrder"
            );
            self.validate_job_renewal_scope(&job).await?;
            match resolution {
                OrderResolution::ConfirmNoOrder => {
                    job.phase = "prepared".to_owned();
                }
                OrderResolution::Attach { order_url } => {
                    let issuer = self
                        .inner
                        .issuers
                        .iter()
                        .find(|i| i.config.wire.directory == job.directory)
                        .ok_or_else(|| anyhow!("recovery issuer is no longer configured"))?;
                    let _network = self.net_permit(issuer, &cancel).await?;
                    let issuer_name = issuer_key(&job.directory)?;
                    let email = if issuer.config.email.is_empty() {
                        self.inner
                            .store
                            .most_recent_account_email(&issuer_name)
                            .await?
                            .unwrap_or_default()
                    } else {
                        issuer.config.email.clone()
                    };
                    let account = self
                        .inner
                        .store
                        .load_account(&issuer_name, &email)
                        .await?
                        .ok_or_else(|| anyhow!("recovery account material missing"))?;
                    ensure!(
                        account.metadata["location"].as_str() == Some(&job.account_location),
                        "recovery account identity changed"
                    );
                    let wire = issuer
                        .wire
                        .get_or_try_init(|| {
                            AcmeWire::connect_with_cpu(
                                issuer.config.wire.clone(),
                                self.inner.local.clone(),
                                &cancel,
                            )
                        })
                        .await?;
                    let session = wire.restore(
                        self.account_signer(&account.private_key_pem, &cancel)
                            .await?,
                        &job.account_location,
                    )?;
                    let resource = session.order(&order_url, &cancel).await?;
                    validate_order(&resource.value, job.renewal_names.as_deref().unwrap_or(&names))?;
                    job.order_url = Some(order_url);
                    job.phase = "order_recovered".to_owned();
                }
            }
            self.save_job(job_id, &job, &lease).await
        }
        .await;
        let released = lease.release().await;
        result?;
        released
    }

    pub async fn ensure(
        &self,
        names: &[String],
        cancel: CancellationToken,
    ) -> Result<ManagedCertificate> {
        let names = normalize_names(names)?;
        self.startup_recovery(cancel.clone()).await?;
        self.ensure_inner(names, cancel.child_token()).await
    }

    async fn name_gate(&self, names: &[String]) -> Result<Arc<Mutex<()>>> {
        let gate_key = digest(names.join("\0").as_bytes());
        let gate = {
            let mut gates = self.inner.gates.lock().await;
            gates.retain(|_, v| v.strong_count() > 0);
            if let Some(gate) = gates.get(&gate_key).and_then(Weak::upgrade) {
                gate
            } else {
                ensure!(gates.len() < 65536, "certificate task capacity reached");
                let gate = Arc::new(Mutex::new(()));
                gates.insert(gate_key, Arc::downgrade(&gate));
                gate
            }
        };
        Ok(gate)
    }

    /// Restore complete, currently valid stored material into this manager's
    /// resolver without contacting the CA, checking ARI, registering accounts or
    /// creating an order. A due renewal is still returned with its original
    /// deadline; normal ensure/run will renew it after candidate validation.
    /// Local storage transactions may be recovered. Unstored ACME candidates are
    /// deliberately left for normal ensure, never promoted by this read path.
    pub async fn load_cached(
        &self,
        names: &[String],
        cancel: CancellationToken,
    ) -> Result<Option<ManagedCertificate>> {
        let names = normalize_names(names)?;
        self.startup_recovery(cancel.clone()).await?;
        let gate = self.name_gate(&names).await?;
        let _gate = tokio::select! {biased;_=cancel.cancelled()=>return Err(anyhow!("ACME cache load cancelled")),guard=gate.lock()=>guard};
        let lease = self
            .inner
            .store
            .lock(&format!("issue_cert_{}", names[0]), cancel.clone())
            .await?;
        let result = self
            .load_existing(&names, Some(&lease), &cancel, LoadMode::CacheOnly)
            .await;
        let release = lease.release().await;
        let (cached, _, _) = result?;
        release?;
        Ok(cached)
    }

    /// Inspect the existing certificate's renewal deadline with an optional
    /// authenticated ARI refresh. This never promotes a candidate, reconciles an
    /// order, registers an account, creates an order or changes resolver state.
    /// Pending/incomplete storage is an error, not permission to issue. Callers
    /// must obtain on-demand permission before a subsequently due ensure().
    pub(crate) async fn refresh_cached(
        &self,
        names: &[String],
        cancel: CancellationToken,
    ) -> Result<RefreshOutcome> {
        let names = normalize_names(names)?;
        let gate = self.name_gate(&names).await?;
        let _gate = tokio::select! { biased;
            _ = cancel.cancelled() => bail!("ACME renewal inspection cancelled"),
            guard = gate.lock() => guard,
        };
        let lease = self
            .inner
            .store
            .lock(&format!("issue_cert_{}", names[0]), cancel.clone())
            .await?;
        let work = cancel.child_token();
        let lost = lease.lost();
        let result = {
            let operation = self.load_existing(&names, Some(&lease), &work, LoadMode::Refresh);
            tokio::pin!(operation);
            tokio::select! { biased;
                _ = cancel.cancelled() => { work.cancel(); let _ = operation.await; Err(anyhow!("ACME renewal inspection cancelled")) },
                _ = lost.cancelled() => { work.cancel(); let _ = operation.await; Err(anyhow!("certificate storage lease lost")) },
                _ = tokio::time::sleep(self.inner.options.job_timeout.min(Duration::from_secs(480))) => { work.cancel(); let _ = operation.await; Err(anyhow!("ACME renewal inspection deadline exceeded")) },
                result = &mut operation => result.map(|(ready,selected,bundle)|match (ready,selected) {
                    (Some(certificate),_) => RefreshOutcome::Usable {
                        certificate,
                        ari_after: bundle.as_ref().and_then(|bundle| ari_refresh_time(&bundle.metadata)).unwrap_or(i64::MAX),
                    },
                    (None,Some(_)) => RefreshOutcome::Unusable,
                    (None,None) => RefreshOutcome::Missing,
                }),
            }
        };
        work.cancel();
        let released = lease.release().await;
        result.and_then(|ready| released.map(|_| ready))
    }

    /// No recovery, storage lease, ACME, ARI or checkpoint write. FsStore's
    /// grouped reader rejects pending transactions and changing generations.
    /// Local integrity/I/O errors remain errors rather than guessed misses.
    pub async fn probe_cached(
        &self,
        names: &[String],
        cancel: CancellationToken,
    ) -> Result<CachedProbe> {
        let names = normalize_names(names)?;
        ensure!(!cancel.is_cancelled(), "ACME cache probe cancelled");
        let gate = self.name_gate(&names).await?;
        let Ok(_guard) = gate.try_lock() else {
            return Ok(CachedProbe::Busy);
        };
        let (usable, _, bundle) = self
            .load_existing(&names, None, &cancel, LoadMode::Probe)
            .await?;
        Ok(match bundle {
            Some(bundle) => CachedProbe::Material { usable, bundle },
            None => CachedProbe::Missing,
        })
    }

    async fn ensure_inner(
        &self,
        names: Vec<String>,
        cancel: CancellationToken,
    ) -> Result<ManagedCertificate> {
        let gate = self.name_gate(&names).await?;
        let _gate = tokio::select! {biased;_=cancel.cancelled()=>return Err(anyhow!("ACME operation cancelled")),guard=gate.lock()=>guard};
        // Only per-name queueing is outside the execution deadline. Network
        // queues are issuer-scoped first, so a busy issuer cannot occupy the
        // global budget while its requests merely wait for that issuer.
        let operation = self.ensure_active(names, cancel.clone());
        tokio::pin!(operation);
        tokio::select! {
            result=&mut operation=>result,
            _=tokio::time::sleep(self.inner.options.job_timeout)=>{
                cancel.cancel();let _=operation.await;Err(anyhow!("ACME job deadline exceeded"))
            }
        }
    }
    async fn ensure_active(
        &self,
        names: Vec<String>,
        cancel: CancellationToken,
    ) -> Result<ManagedCertificate> {
        let lease = self
            .inner
            .store
            .lock(&format!("issue_cert_{}", names[0]), cancel.clone())
            .await?;
        let initial = async {
            // Recover a previously completed local leg before deciding that any
            // network request is necessary. Keep registration/domain lock order.
            let (ready, previous) = self.load_state(&names, &lease, &cancel).await?;
            if ready.is_some() {
                return Ok((ready, previous, None, None, None));
            }
            // One abortable event precedes new attempt/key/account/order work,
            // including issuer fallback; already ready material emits nothing.
            let lifecycle=self.emit_obtaining(&names, previous.as_ref(), &cancel).await?;
            let initial_reuse=if previous.is_none(){self.initial_reuse_plan(&names,&cancel).await?}else{None};
            use p256::elliptic_curve::rand_core::RngCore;
            let mut random = [0u8; 32];
            p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut random);
            let attempt = Attempt {
                version: 1,
                names: names.clone(),
                attempt_id: digest(&random),
                issuer_sequence: {
                    let mut sequence=self.inner.issuers.iter().map(|issuer|issuer.config.wire.directory.clone()).collect::<Vec<_>>();
                    if let Some((_,preferred))=&initial_reuse {let first=sequence.remove(*preferred);sequence.insert(0,first);}
                    sequence
                },
                current_job_id: None,
                base_leaf: previous.as_ref().map(|p| p.previous_leaf.clone()),
                winner: None,
            };
            self.store_checkpoint(
                &attempt_key(&names)?,
                serde_json::to_value(&attempt)?,
                &lease,
            )
            .await?;
            Ok::<_, anyhow::Error>((None, previous, Some(attempt.attempt_id), Some(lifecycle),initial_reuse))
        }
        .await;
        let release = lease.release().await;
        let (ready, mut previous, attempt_id, lifecycle,initial_reuse) = initial?;
        release?;
        if let Some(ready) = ready {
            return Ok(ready);
        }
        let lifecycle=lifecycle.ok_or_else(||anyhow!("certificate lifecycle attempt missing"))?;
        let attempt_id =
            attempt_id.ok_or_else(|| anyhow!("certificate attempt was not initialized"))?;
        let _ = self.inner.events.send(AutomationEvent {
            names: names.clone(),
            kind: "issuance_started",
            recovery_issue: None,
        });
        let mut last_error = None;
        let mut tried_issuers = std::collections::HashSet::new();
        let mut issuer_order=(0..self.inner.issuers.len()).collect::<Vec<_>>();
        if let Some((_,preferred))=&initial_reuse {issuer_order.remove(*preferred);issuer_order.insert(0,*preferred);}
        for (rank,index) in issuer_order.into_iter().enumerate() {
            let issuer=&self.inner.issuers[index];
            if !tried_issuers.insert(issuer_key(&issuer.config.wire.directory)?) {
                continue;
            }
            if cancel.is_cancelled() {
                bail!("ACME operation cancelled")
            }
            if rank > 0 {
                sleep_cancel(Duration::from_millis(250u64 << rank.min(5)), &cancel).await?;
            }
            let allowed = issuer.ca.next_allowed_unix.load(Ordering::Acquire);
            if allowed > now() {
                last_error = Some(RetryAfterError(allowed).into());
                continue;
            }
            let network = self.net_permit(issuer, &cancel).await?;
            let allowed = issuer.ca.next_allowed_unix.load(Ordering::Acquire);
            if allowed > now() {
                last_error = Some(RetryAfterError(allowed).into());
                continue;
            }
            let wire = match issuer
                .wire
                .get_or_try_init(|| {
                    AcmeWire::connect_with_cpu(
                        issuer.config.wire.clone(),
                        self.inner.local.clone(),
                        &cancel,
                    )
                })
                .await
            {
                Ok(wire) => wire,
                Err(error) => {
                    record_issuer_error(issuer, &error);
                    last_error = Some(error);
                    continue;
                }
            };
            let reservation = match self.read_reservation(&names, issuer).await {
                Ok(value) => value,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let account = match self
                .account(
                    issuer,
                    wire,
                    reservation.as_ref().map(|r| r.account_location.as_str()),
                    &cancel,
                )
                .await
            {
                Ok(account) => account,
                Err(error) => {
                    record_issuer_error(issuer, &error);
                    last_error = Some(error);
                    continue;
                }
            };
            // Registration/network setup has finished; do not hold a CA
            // permit while load_state may refresh a different issuer's ARI.
            drop(network);
            let lease = self
                .inner
                .store
                .lock(&format!("issue_cert_{}", names[0]), cancel.clone())
                .await?;
            let leg_cancel = cancel.child_token();
            let result = {
                let lost = lease.lost();
                let operation = async {
                    let (ready, replaces) = self.load_state(&names, &lease, &leg_cancel).await?;
                    if let Some(ready) = ready {
                        return Ok(ready);
                    }
                    if replaces.is_some() {
                        previous = replaces;
                    }
                    // Damaged/partial material blocks this CA before newOrder.
                    let scope_issuer = issuer_key(&issuer.config.wire.directory)?;
                    let scope_names = names_key(&names)?;
                    self.inner
                        .store
                        .recover_certificate_with_lease(&scope_issuer, &scope_names, &lease)
                        .await?;
                    let _ = self.read_issuer_certificate(&scope_issuer,&scope_names,&leg_cancel).await?;
                    let current = self.read_reservation(&names, issuer).await?;
                    if let Some(active) = current.as_ref() {
                        ensure!(
                            active.account_location == account.location(),
                            "active ACME account identity changed"
                        );
                    }
                    let _network = self.net_permit(issuer, &leg_cancel).await?;
                    let allowed = issuer.ca.next_allowed_unix.load(Ordering::Acquire);
                    if allowed > now() {
                        return Err(RetryAfterError(allowed).into());
                    }
                    self.issue(
                        &names,
                        issuer,
                        &account,
                        &lease,
                        (previous.as_ref(), current.as_ref(), &attempt_id),
                        initial_reuse.as_ref().map(|(key,_)|key),
                        &lifecycle,
                        &leg_cancel,
                    )
                    .await
                };
                tokio::pin!(operation);
                // Each issuer receives a bounded leg budget. Deadline/cancel is
                // joined before another issuer runs; no detached late writer.
                let budget = (self.inner.options.job_timeout
                    / (self.inner.issuers.len() as u32 + 1))
                    .min(Duration::from_secs(120))
                    .max(Duration::from_secs(1));
                tokio::select! {
                    value=&mut operation=>value,
                    _=tokio::time::sleep(budget)=>{leg_cancel.cancel();let _=operation.await;Err(anyhow!("ACME issuer leg deadline exceeded"))},
                    _=lost.cancelled()=>{leg_cancel.cancel();let _=operation.await;Err(anyhow!("certificate storage lease lost"))},
                }
            };
            let abandoned = if result.is_err() {
                self.abandon_leg(&names, &attempt_id, &lease).await
            } else {
                Ok(())
            };
            let released = lease.release().await;
            abandoned?;
            match result {
                Ok(value) => {
                    released?;
                    let _ = self.inner.events.send(AutomationEvent {
                        names: names.clone(),
                        kind: "certificate_ready",
                        recovery_issue: None,
                    });
                    return Ok(value);
                }
                Err(error) => {
                    released?;
                    record_issuer_error(issuer, &error);
                    last_error = Some(error);
                }
            }
        }
        let error=last_error.unwrap_or_else(|| anyhow!("no ACME issuer available"));
        let issuer_keys=self.inner.issuers.iter().map(|i|issuer_key(&i.config.wire.directory)).collect::<Result<Vec<_>>>()?;
        lifecycle.failed(self.inner.lifecycle_events.as_ref(),&issuer_keys,&error,&cancel).await;
        Err(error)
    }

    async fn initial_key(&self,issuer:&str,key:&str,cancel:&CancellationToken)
        ->Result<Option<(crate::certstore::InitialPrivateKey,ReusableKey)>> {
        if !self.inner.reuse_private_keys {return Ok(None);}
        let (_,initial)=self.inner.store.load_certificate_for_key_reuse(issuer,key).await?;
        let Some(initial)=initial else{return Ok(None);};
        let pem=initial.pem();let deny=self.inner.resolver.leaf_guard().key_deny().clone();
        let reusable=self.cpu(cancel,move||prepare_reusable_key(pem,&deny)).await?;
        Ok(Some((initial,reusable)))
    }
    async fn read_issuer_certificate(&self,issuer:&str,key:&str,cancel:&CancellationToken)->Result<Option<CertificateBundle>> {
        if !self.inner.reuse_private_keys {return self.inner.store.load_certificate(issuer,key).await;}
        let (bundle,initial)=self.inner.store.load_certificate_for_key_reuse(issuer,key).await?;
        if let Some(initial)=initial {
            let pem=initial.pem();let deny=self.inner.resolver.leaf_guard().key_deny().clone();
            self.cpu(cancel,move||prepare_reusable_key(pem,&deny)).await?;
        }
        Ok(bundle)
    }
    async fn initial_reuse_plan(&self,names:&[String],cancel:&CancellationToken)->Result<Option<(ReusableKey,usize)>> {
        let key=names_key(names)?;
        for (index,issuer) in self.inner.issuers.iter().enumerate() {
            let issuer=issuer_key(&issuer.config.wire.directory)?;
            if let Some((_,reusable))=self.initial_key(&issuer,&key,cancel).await? {
                if !reusable.state.banned() {return Ok(Some((reusable,index)));}
            }
        }
        Ok(None)
    }
    async fn save_issued_certificate(&self,issuer:&str,key:&str,bundle:&CertificateBundle,
        lease:&StorageLease,initial_hash:Option<&str>)->Result<()> {
        if let Some(expected)=initial_hash {
            let (current,initial)=self.inner.store.load_certificate_for_key_reuse(issuer,key).await?;
            if let Some(initial)=initial {
                ensure!(initial.digest()==expected,"initial certificate private key changed during issuance");
                return self.inner.store.save_certificate_with_initial_key(issuer,key,bundle,lease,&initial).await;
            }
            // A committed leg may have survived its final checkpoint. Never
            // overwrite a different generation installed by an external writer.
            ensure!(current.as_ref().is_some_and(|current|current.chain_pem==bundle.chain_pem
                && current.private_key_pem.as_slice()==bundle.private_key_pem.as_slice()),
                "initial certificate bootstrap generation changed");
            Ok(())
        } else {self.inner.store.save_certificate(issuer,key,bundle,lease).await}
    }
    async fn load_state(
        &self,
        names: &[String],
        lease: &StorageLease,
        cancel: &CancellationToken,
    ) -> Result<(Option<ManagedCertificate>, Option<Replacement>)> {
        if let Some(attempt) = self.load_attempt(names).await?
            && let Some(job_id) = attempt.current_job_id.as_ref()
            && let Some(value) = self.inner.store.journal_load(job_id).await?
            && let Some(directory) = value["directory"].as_str()
            && let Some(issuer) = self
                .inner
                .issuers
                .iter()
                .find(|i| i.config.wire.directory == directory)
            && self
                .recover_candidate(names, issuer, lease, cancel)
                .await
                .is_err()
        {
            let _ = self.inner.events.send(AutomationEvent {
                names: names.to_vec(),
                kind: "issuer_candidate_recovery_failed",
                recovery_issue: None,
            });
        }
        self.load_existing(names, Some(lease), cancel, LoadMode::Online)
            .await
            .map(|(ready, previous, _)| (ready, previous))
    }
    async fn read_reservation(
        &self,
        names: &[String],
        issuer: &IssuerState,
    ) -> Result<Option<Reservation>> {
        let Some(value) = self
            .inner
            .store
            .journal_load(&reservation_id(names, &issuer.config.wire.directory)?)
            .await?
        else {
            return Ok(None);
        };
        let marker: Reservation = serde_json::from_value(value)
            .map_err(|_| anyhow!("invalid issuer ACME reservation"))?;
        ensure!(
            marker.version == 1
                && marker.names == names
                && marker.directory == issuer.config.wire.directory,
            "issuer ACME reservation scope changed"
        );
        let job: Job = serde_json::from_value(self.inner.store.journal_load(&marker.job_id).await?
            .ok_or_else(|| anyhow!("issuer ACME order checkpoint missing"))?)
            .map_err(|_| anyhow!("invalid issuer ACME checkpoint"))?;
        validate_reservation_job(&marker, &job)?;
        if !marker.active {
            return Ok(None);
        }
        ensure!(
            marker.config_email == issuer.config.email
                && marker.leaf_key_type == issuer.config.leaf_key_type
                && marker.must_staple == self.inner.must_staple
                && marker.reuse_private_keys == self.inner.reuse_private_keys
                && marker.certificate_lifetime_ns == issuer.config.certificate_lifetime_ns
                && marker.profile == issuer.config.profile,
            "active issuer configuration changed; restore it or explicitly resolve that issuer order"
        );
        Ok(Some(marker))
    }

    async fn validate_job_renewal_scope(&self, job: &Job) -> Result<()> {
        if let Some(sans) = &job.renewal_names {
            ensure!(job.names.len() == 1, "Name0 renewal checkpoint has multiple storage subjects");
            let issuer = issuer_key(&job.directory)?;
            let name = names_key(&job.names)?;
            let old = self.inner.store.load_certificate(&issuer, &name).await?
                .ok_or_else(|| anyhow!("Name0 renewal checkpoint lost its signed resource"))?;
            ensure!(crate::certstore::name0_renewal_names(&old, &name)?.as_ref() == Some(sans),
                "Name0 renewal checkpoint changed signed subject scope");
        }
        Ok(())
    }

    async fn recover_candidate(
        &self,
        names: &[String],
        issuer_state: &IssuerState,
        lease: &StorageLease,
        cancel: &CancellationToken,
    ) -> Result<Option<Reservation>> {
        let Some(value) = self
            .inner
            .store
            .journal_load(&reservation_id(names, &issuer_state.config.wire.directory)?)
            .await?
        else {
            return Ok(None);
        };
        let marker: Reservation = serde_json::from_value(value)
            .map_err(|_| anyhow!("invalid issuer ACME reservation"))?;
        ensure!(
            marker.version == 1 && marker.names == names
                && marker.directory == issuer_state.config.wire.directory,
            "active ACME reservation scope changed"
        );
        let mut job: Job = serde_json::from_value(
            self.inner
                .store
                .journal_load(&marker.job_id)
                .await?
                .ok_or_else(|| anyhow!("active ACME order checkpoint missing"))?,
        )
        .map_err(|_| anyhow!("invalid active ACME checkpoint"))?;
        validate_reservation_job(&marker, &job)?;
        self.validate_job_renewal_scope(&job).await?;
        if marker.active {
        ensure!(
            self.inner
                .issuers
                .iter()
                .any(|i| i.config.wire.directory == marker.directory
                    && i.config.email == marker.config_email
                    && i.config.leaf_key_type == marker.leaf_key_type
                    && i.config.certificate_lifetime_ns == marker.certificate_lifetime_ns
                    && i.config.profile == marker.profile
                    && marker.must_staple == self.inner.must_staple
                    && marker.reuse_private_keys == self.inner.reuse_private_keys),
            "active ACME issuer configuration changed; restore it or explicitly resolve the order"
        );
        }
        if job.phase == "prepared" {
            return Ok(None);
        }
        let issuer = issuer_key(&marker.directory)?;
        let key = names_key(names)?;
        self.inner
            .store
            .recover_certificate_with_lease(&issuer, &key, lease)
            .await?;
        // Finish an already validated candidate without depending on CA/account
        // connectivity. A prior commit may have succeeded before its checkpoint.
        if let Some(current) = self.read_issuer_certificate(&issuer,&key,cancel).await? {
            let info = self.inspect_material(&current, names, cancel).await?;
            if job.stored_leaf_sha256.as_deref() == Some(&info.leaf_sha256) {
                job.phase = "stored".to_owned();
                job.private_key_pem.zeroize();
                job.csr_der.clear();
                job.downloaded_pem = None;
                self.save_job(&marker.job_id, &job, lease).await?;
                if self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der).is_ok()
                    && self
                    .claim_winner(
                        names,
                        &job.attempt_id,
                        &marker.job_id,
                        &issuer,
                        &info.leaf_sha256,
                        lease,
                    )
                    .await?
                    && info.not_before <= now()
                    && info.not_after > now()
                {
                    self.publish(names, &current, cancel).await?;
                }
                return Ok(None);
            }
        }
        if let Some(chain) = job.downloaded_pem.as_ref() {
            let bundle = CertificateBundle {
                chain_pem: chain.as_bytes().to_vec(),
                private_key_pem: Zeroizing::new(job.private_key_pem.as_bytes().to_vec()),
                metadata: json!({"sans":job.renewal_names.as_deref().unwrap_or(names),"issuer_data":{"url":job.certificate_url,"ca":job.directory,"account":job.account_location}}),
            };
            let info = self.inspect_material(&bundle, names, cancel).await?;
            let denied = match self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der) {
                Ok(()) => false,
                Err(error) if error.is::<crate::key_compromise::KeyCompromised>() => true,
                Err(error) => return Err(error),
            };
            if denied || info.not_after <= now() {
                job.phase = "prepared".to_owned();
                job.order_url = None;
                job.certificate_url = None;
                job.downloaded_pem = None;
                job.stored_leaf_sha256 = None;
                job.poll_after_unix = 0;
                self.save_job(&marker.job_id, &job, lease).await?;
                return Ok(None);
            }
            if info.not_before > now() {
                return Err(RetryAfterError(info.not_before).into());
            }
            job.phase = "store_intent".to_owned();
            job.stored_leaf_sha256 = Some(info.leaf_sha256);
            self.save_job(&marker.job_id, &job, lease).await?;
            self.save_issued_certificate(&issuer,&key,&bundle,lease,job.initial_key_hash.as_deref()).await?;
            job.phase = "stored".to_owned();
            job.private_key_pem.zeroize();
            job.csr_der.clear();
            job.downloaded_pem = None;
            self.save_job(&marker.job_id, &job, lease).await?;
            if self
                .claim_winner(
                    names,
                    &job.attempt_id,
                    &marker.job_id,
                    &issuer,
                    job.stored_leaf_sha256
                        .as_deref()
                        .ok_or_else(|| anyhow!("candidate fingerprint missing"))?,
                    lease,
                )
                .await?
            {
                self.publish(names, &bundle, cancel).await?;
            }
            return Ok(None);
        }
        Ok(Some(marker))
    }

    async fn load_existing(
        &self,
        names: &[String],
        lease: Option<&StorageLease>,
        cancel: &CancellationToken,
        mode: LoadMode,
    ) -> Result<(
        Option<ManagedCertificate>,
        Option<Replacement>,
        Option<CertificateBundle>,
    )> {
        let key = names_key(names)?;
        let selection = {
            let active_attempt = self.load_attempt(names).await?;
            let selected = active_attempt.as_ref().and_then(|a| {
                a.winner
                    .as_ref()
                    .map(|w| w.leaf_sha256.as_str())
                    .or(a.base_leaf.as_deref())
            });
            let restricted = active_attempt.is_some();
            let winner = active_attempt.as_ref().and_then(|a| a.winner.as_ref());
            let mut best = None;
            let mut fallback = None;
            for (index, issuer) in self.inner.issuers.iter().enumerate() {
                ensure!(!cancel.is_cancelled(), "ACME cache inspection cancelled");
                if let Some(lease) = lease {
                    lease.check().await?;
                }
                let issuer_name = issuer_key(&issuer.config.wire.directory)?;
                let material = async {
                    if let Some(lease) = lease.filter(|_| mode != LoadMode::Refresh) {
                        self.inner
                            .store
                            .recover_certificate_with_lease(&issuer_name, &key, lease)
                            .await?;
                    }
                    let Some(bundle) = self.read_issuer_certificate(&issuer_name,&key,cancel).await?
                    else {
                        return Ok(None);
                    };
                    let info = self.inspect_material(&bundle, names, cancel).await?;
                    Ok::<_, anyhow::Error>(Some((bundle, info)))
                }
                .await;
                let Some((bundle, info)) = (match material {
                    Ok(value) => value,
                    Err(error) if mode != LoadMode::Online => return Err(error),
                    Err(_) => {
                        let _ = self.inner.events.send(AutomationEvent {
                            names: names.to_vec(),
                            kind: "issuer_certificate_material_error",
                            recovery_issue: None,
                        });
                        continue;
                    }
                }) else {
                    continue;
                };
                {
                    let preferred = !restricted
                        || (selected == Some(info.leaf_sha256.as_str())
                            && winner.is_none_or(|w| w.issuer_key == issuer_name));
                    if !preferred {
                        // A crash can replace the base generation before its
                        // winner CAS. Serve complete valid material while there is
                        // no winner, rather than hiding every on-disk certificate.
                        if winner.is_none()
                            && info.not_before <= now()
                            && info.not_after > now()
                            && fallback.as_ref().is_none_or(
                                |(_, _, old): &(usize, CertificateBundle, MaterialInfo)| {
                                    info.not_before > old.not_before
                                },
                            )
                        {
                            fallback = Some((index, bundle, info));
                        }
                        continue;
                    }
                    if best.as_ref().is_none_or(
                        |(_, _, old): &(usize, CertificateBundle, MaterialInfo)| {
                            info.not_before > old.not_before
                        },
                    ) {
                        best = Some((index, bundle, info));
                    }
                }
            }
            if mode == LoadMode::Refresh && best.is_none() && restricted {
                return Err(PendingPromotion.into());
            }
            best.or(fallback)
        };
        let mut previous_id = None;
        if let Some((index, mut bundle, info)) = selection {
            let issuer = &self.inner.issuers[index];
            let now = now();
            // Preserve the attempt/winner selection above. A revocation vetoes
            // cached readiness; it must not select an older issuer's leaf.
            let denied = match self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der) {
                Ok(()) => false,
                Err(error) if error.is::<crate::key_compromise::KeyCompromised>() => true,
                Err(error) => return Err(error),
            };
            let revocation = self.material_revocation(&info)?;
            let revoked = denied || (info.not_after > now && revocation.is_some());
            let renewal_names = if denied || revocation.as_ref().is_some_and(|v| v.version.reason == Some(1)) {
                None
            } else { crate::certstore::name0_renewal_names(&bundle, &key)? };
            if denied && let Some(lease) = lease {
                // Scope comes from this manager's current authorized issuer and
                // actual selected bundle. Do not reconstruct or export a key
                // retained from another policy/store.
                let archived = self.inner.store.archive_compromised_key(
                    &issuer_key(&issuer.config.wire.directory)?, &key,
                    Sha256::digest(&info.spki_der).into(), names, lease).await;
                let _ = self.inner.events.send(AutomationEvent {
                    names: names.to_vec(), kind: match archived {
                        Ok(true) => "compromised_key_archived",
                        Ok(false) => "compromised_key_not_archived",
                        Err(_) => "compromised_key_archive_failed",
                    }, recovery_issue: None,
                });
            }

            if matches!(mode, LoadMode::Online | LoadMode::Refresh) && info.not_before > now {
                // A stored future leaf can mean local clock skew. Preserve the
                // selected winner/base and wait rather than creating another
                // order (possibly another future leaf) at each scheduler pass.
                return Err(FutureCertificate(info.not_before).into());
            }
            if !denied && mode == LoadMode::Online && info.not_before <= now && info.not_after > now {
                self.publish(names, &bundle, cancel).await?;
            }
            let certificate_id = { self.certificate_id(&bundle.chain_pem, cancel).await? };
            let mut ari = parse_ari(&bundle.metadata);
            if matches!(mode, LoadMode::Online | LoadMode::Refresh)
                && certificate_id.is_some()
                && !revoked
                && issuer.ca.next_allowed_unix.load(Ordering::Acquire) <= now
                && info.not_after > now
                && ari.as_ref().is_none_or(|a| a.refresh_after_unix <= now)
            {
                let update = async {
                    let _network = self.net_permit(issuer, cancel).await?;
                    if issuer.ca.next_allowed_unix.load(Ordering::Acquire) > now {
                        return Ok(None);
                    }
                    let wire = issuer
                        .wire
                        .get_or_try_init(|| {
                            AcmeWire::connect_with_cpu(
                                issuer.config.wire.clone(),
                                self.inner.local.clone(),
                                cancel,
                            )
                        })
                        .await?;
                    if let Some(cert_id) = certificate_id.as_deref() {
                        return wire.renewal_info(cert_id, cancel).await;
                    }
                    Ok(None)
                }
                .await;
                ensure!(!cancel.is_cancelled(), "ACME operation cancelled");
                match update {
                    Ok(Some(updated)) => {
                        // Caddy may have persisted an equivalent SAN set in a
                        // different order. Native leases use normalized first SAN.
                        if renewal_names.is_none() { bundle.metadata["sans"] = json!(names); }
                        write_ari(
                            &mut bundle.metadata,
                            &updated,
                            &info,
                            self.inner.options.renewal_window_ratio,
                        )?;
                        let lease = lease
                            .ok_or_else(|| anyhow!("online cache update requires storage lease"))?;
                        lease.check().await?;
                        self.inner
                            .store
                            .save_certificate(
                                &issuer_key(&issuer.config.wire.directory)?,
                                &key,
                                &bundle,
                                lease,
                            )
                            .await?;
                        ari = Some(updated);
                    }
                    Err(error) => {
                        record_issuer_error(issuer, &error);
                        if mode == LoadMode::Refresh {
                            return Err(error);
                        }
                    }
                    Ok(None) => {}
                }
            }
            let reuse_key=(self.inner.reuse_private_keys && !denied
                && !revocation.as_ref().is_some_and(|v|v.version.reason==Some(1)))
                .then(||ReusableKey{pem:bundle.private_key_pem.clone(),state:info._key_state.clone(),spki:info.spki_der.clone()});
            previous_id = Some(Replacement {
                reuse_key,
                not_after: info.not_after,
                forced: revoked,
                renewal_names,
                certificate_id,
                previous_leaf: info.leaf_sha256.clone(),
                directory: issuer.config.wire.directory.clone(),
                account: bundle.metadata["issuer_data"]["account"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
            });
            let renew_at = renewal_time(
                info.not_before,
                info.not_after,
                self.inner.options.renewal_window_ratio,
                ari.as_ref(),
                &info.leaf_sha256,
            )?;
            if !revoked
                && (mode != LoadMode::Online || now < renew_at)
                && info.not_before <= now
                && info.not_after > now
                && self.material_revocation(&info)?.is_none()
            {
                if mode == LoadMode::CacheOnly {
                    self.publish(names, &bundle, cancel).await?;
                }
                return Ok((
                    Some(ManagedCertificate {
                        names: names.to_vec(),
                        issuer_key: issuer_key(&issuer.config.wire.directory)?,
                        not_after_unix: info.not_after,
                        renew_at_unix: renew_at,
                        leaf_sha256: info.leaf_sha256,
                        obtained: false,
                    }),
                    previous_id,
                    matches!(mode, LoadMode::Probe | LoadMode::Refresh).then_some(bundle),
                ));
            }
            return Ok((
                None,
                previous_id,
                (mode == LoadMode::Probe).then_some(bundle),
            ));
        }
        Ok((None, previous_id, None))
    }

    async fn account(
        &self,
        issuer: &IssuerState,
        wire: &AcmeWire,
        expected_location: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<AccountSession> {
        for _ in 0..8 {
            match self
                .account_once(issuer, wire, expected_location, cancel)
                .await
            {
                Ok(account) => return Ok(account),
                Err(error) if error.downcast_ref::<RetryAccountAlias>().is_some() => continue,
                Err(error) => return Err(error),
            }
        }
        bail!("ACME account alias changed repeatedly; retry required")
    }
    async fn account_once(
        &self,
        issuer: &IssuerState,
        wire: &AcmeWire,
        expected_location: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<AccountSession> {
        let issuer_name = issuer_key(wire.directory_url())?;
        let email = if issuer.config.email.is_empty() {
            self.inner
                .store
                .most_recent_account_email(&issuer_name)
                .await?
                .unwrap_or_default()
        } else {
            issuer.config.email.clone()
        };
        let pending_id = digest(format!("account\0{}\0{}", wire.directory_url(), email).as_bytes());
        if let Some(value) = self.inner.store.journal_load(&pending_id).await?
            && value["phase"] == "account_received"
        {
            let pending: PendingAccount = serde_json::from_value(value.clone())
                .map_err(|_| anyhow!("invalid ACME account checkpoint"))?;
            let registration = value["lease_name"]
                .as_str()
                .ok_or_else(|| anyhow!("account checkpoint lease missing"))?;
            return self
                .finish_account(
                    wire,
                    (&issuer_name, &pending_id, registration),
                    pending,
                    expected_location,
                    cancel,
                )
                .await;
        }
        if let Some(value) = self.inner.store.journal_load(&pending_id).await?
            && value["phase"] == "stored"
            && let Some(actual) = value["storage_email"].as_str()
        {
            let name = self
                .inner
                .store
                .account_registration_lock_name(&issuer_name, actual)
                .await?;
            let lease = self.inner.store.lock(&name, cancel.clone()).await?;
            let result = async {
                self.inner
                    .store
                    .recover_account_with_lease(&issuer_name, actual, &lease)
                    .await?;
                if let Some(account) = self.inner.store.load_account(&issuer_name, actual).await? {
                    let location = account.metadata["location"]
                        .as_str()
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| anyhow!("saved account alias has no location"))?;
                    ensure!(
                        account.metadata["status"] == "valid"
                            && value["metadata"]["location"]
                                .as_str()
                                .is_none_or(|saved| saved == location)
                            && expected_location.is_none_or(|v| v == location),
                        "saved ACME account alias identity changed"
                    );
                    return wire
                        .restore(
                            self.account_signer(&account.private_key_pem, cancel)
                                .await?,
                            location,
                        )
                        .map(Some);
                }
                Ok(None)
            }
            .await;
            let released = lease.release().await;
            let result = result?;
            released?;
            if let Some(session) = result {
                return Ok(session);
            }
            bail!("saved ACME account alias material missing; restore its identity")
        }
        let registration = self
            .inner
            .store
            .account_registration_lock_name(&issuer_name, &email)
            .await?;
        let lease = self.inner.store.lock(&registration, cancel.clone()).await?;
        // Never pass the lease's own cancellation token to network calls:
        // caller/deadline cancellation must also stop an uncertain request.
        // Join the operation before releasing its fenced registration lease.
        let result = {
            let registration_cancel = cancel.child_token();
            let lost = lease.lost();
            let operation = async {
                self.inner
                    .store
                    .recover_account_with_lease(&issuer_name, &email, &lease)
                    .await?;
                if let Some(value) = self.inner.store.journal_load(&pending_id).await?
                    && value["phase"] == "account_received"
                {
                    let pending: PendingAccount = serde_json::from_value(value)
                        .map_err(|_| anyhow!("invalid account publication checkpoint"))?;
                    return Ok((None, Some(pending)));
                }
                let existing = self.inner.store.load_account(&issuer_name, &email).await?;
                if let Some(account) = existing {
                    ensure!(
                        account_lock_name(&account.metadata)? == registration,
                        "account contact changed while acquiring registration lock"
                    );
                    let signer = self
                        .account_signer(&account.private_key_pem, cancel)
                        .await?;
                    if let Some(location) = account.metadata["location"]
                        .as_str()
                        .filter(|v| !v.is_empty())
                    {
                        ensure!(
                            account.metadata["status"] == "valid"
                                && expected_location.is_none_or(|v| v == location),
                            "stored ACME account identity changed"
                        );
                        return Ok::<_, anyhow::Error>((
                            Some(wire.restore(signer, location)?),
                            None,
                        ));
                    }
                    let (session, response) = wire
                        .account(
                            signer,
                            &email,
                            issuer.config.terms_of_service_agreed,
                            true,
                            None,
                            &registration_cancel,
                        )
                        .await?;
                    ensure!(
                        expected_location.is_none_or(|v| v == session.location()),
                        "recovered account identity changed"
                    );
                    let mut metadata = account.metadata.clone();
                    merge_account(&mut metadata, &response.metadata)?;
                    let pending = PendingAccount {
                        version: 1,
                        directory: wire.directory_url().to_owned(),
                        phase: "account_received".to_owned(),
                        private_key_pem: std::str::from_utf8(&account.private_key_pem)?.to_owned(),
                        eab: None,
                        storage_email: Some(account_primary(&metadata)?.to_owned()),
                        metadata: Some(metadata),
                    };
                    self.store_checkpoint(&pending_id, serde_json::to_value(&pending)?, &lease)
                        .await?;
                    return Ok((None, Some(pending)));
                }
                let old = self.inner.store.journal_load(&pending_id).await?;
                // A different publisher may have completed an alias after our
                // optimistic read but before we acquired this registration lease.
                if old
                    .as_ref()
                    .is_some_and(|v| v["phase"] == "stored" && v["storage_email"].is_string())
                {
                    return Err(anyhow::Error::new(RetryAccountAlias));
                }
                ensure!(
                    expected_location.is_none(),
                    "active order account material missing; restore it instead of registering another account"
                );
                let mut pending = if let Some(value) = old.filter(|v| v["phase"] != "stored") {
                    let pending: PendingAccount = serde_json::from_value(value)
                        .map_err(|_| anyhow!("invalid account checkpoint"))?;
                    ensure!(
                        pending.version == 1 && pending.directory == wire.directory_url(),
                        "account checkpoint identity changed"
                    );
                    pending
                } else {
                    let kind = issuer.config.account_key_type;
                    let (_, key) = self
                        .cpu(cancel, move || AccountSigner::generate(kind))
                        .await?;
                    let pending = PendingAccount {
                        version: 1,
                        directory: wire.directory_url().to_owned(),
                        phase: "key_prepared".to_owned(),
                        private_key_pem: std::str::from_utf8(&key)?.to_owned(),
                        eab: None,
                        storage_email: None,
                        metadata: Some(if email.is_empty() {
                            json!({"contact":[]})
                        } else {
                            json!({"contact":[format!("mailto:{email}")]})
                        }),
                    };
                    self.store_checkpoint(&pending_id, serde_json::to_value(&pending)?, &lease)
                        .await?;
                    pending
                };
                if pending.phase == "account_received" {
                    return Ok((None, Some(pending)));
                }
                let signer = self
                    .account_signer(pending.private_key_pem.as_bytes(), cancel)
                    .await?;
                let recovered = if pending.phase != "key_prepared" {
                    match wire
                        .account(
                            signer.clone(),
                            &email,
                            issuer.config.terms_of_service_agreed,
                            true,
                            None,
                            &registration_cancel,
                        )
                        .await
                    {
                        Ok(result) => Some(result),
                        Err(error) => {
                            if !error.downcast_ref::<ProtocolError>().is_some_and(|p| {
                                p.status() == 400 && p.kind() == "accountDoesNotExist"
                            }) {
                                return Err(error.context("account registration remains uncertain"));
                            }
                            None
                        }
                    }
                } else {
                    None
                };
                let (_, response) = if let Some(result) = recovered {
                    result
                } else {
                    if issuer.config.eab.is_none()
                        && pending.eab.is_none()
                        && wire
                            .directory_url()
                            .starts_with("https://acme.zerossl.com/")
                    {
                        let (kid, hmac_key) =
                            wire.zero_ssl_eab(&email, &registration_cancel).await?;
                        pending.eab = Some(ExternalAccountBinding { kid, hmac_key });
                        self.store_checkpoint(&pending_id, serde_json::to_value(&pending)?, &lease)
                            .await?;
                    }
                    pending.phase = "registration_intent".to_owned();
                    self.store_checkpoint(&pending_id, serde_json::to_value(&pending)?, &lease)
                        .await?;
                    wire.account(
                        signer,
                        &email,
                        issuer.config.terms_of_service_agreed,
                        false,
                        issuer
                            .config
                            .eab
                            .as_ref()
                            .or(pending.eab.as_ref())
                            .map(|e| (e.kid.as_str(), e.hmac_key.as_str())),
                        &registration_cancel,
                    )
                    .await?
                };
                let mut metadata = pending.metadata.take().unwrap_or_else(|| {
                    if email.is_empty() {
                        json!({"contact":[]})
                    } else {
                        json!({"contact":[format!("mailto:{email}")]})
                    }
                });
                merge_account(&mut metadata, &response.metadata)?;
                pending.phase = "account_received".to_owned();
                pending.storage_email = Some(account_primary(&metadata)?.to_owned());
                pending.metadata = Some(metadata);
                self.store_checkpoint(&pending_id, serde_json::to_value(&pending)?, &lease)
                    .await?;
                Ok((None, Some(pending)))
            };
            tokio::pin!(operation);
            tokio::select! {
                result = &mut operation => result,
                _ = lost.cancelled() => {
                    registration_cancel.cancel();
                    let _ = operation.await;
                    Err(anyhow!("account storage lease lost"))
                }
            }
        };
        let released = lease.release().await;
        let (ready, pending) = result?;
        released?;
        if let Some(ready) = ready {
            return Ok(ready);
        }
        self.finish_account(
            wire,
            (&issuer_name, &pending_id, &registration),
            pending.ok_or_else(|| anyhow!("account publication missing"))?,
            expected_location,
            cancel,
        )
        .await
    }

    async fn finish_account(
        &self,
        wire: &AcmeWire,
        scope: (&str, &str, &str),
        mut pending: PendingAccount,
        expected_location: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<AccountSession> {
        let (issuer_name, pending_id, registration) = scope;
        ensure!(
            registration == "register_acme_account"
                || registration.starts_with("register_acme_account_"),
            "invalid account registration lease"
        );
        ensure!(
            pending.version == 1
                && pending.directory == wire.directory_url()
                && pending.phase == "account_received",
            "invalid account publication checkpoint"
        );
        let metadata = pending
            .metadata
            .as_ref()
            .ok_or_else(|| anyhow!("account publication metadata missing"))?;
        let actual = account_primary(metadata)?.to_owned();
        ensure!(
            pending.storage_email.as_deref() == Some(&actual),
            "account publication alias changed"
        );
        let location = metadata["location"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("account publication location missing"))?
            .to_owned();
        ensure!(
            metadata["status"] == "valid" && expected_location.is_none_or(|v| v == location),
            "account publication identity changed"
        );
        let signer = self
            .account_signer(pending.private_key_pem.as_bytes(), cancel)
            .await?;
        let session = wire.restore(signer.clone(), &location)?;
        let destination_lock = account_lock_name(metadata)?;
        let lease = self
            .inner
            .store
            .lock(&destination_lock, cancel.clone())
            .await?;
        let result = async {
            self.inner
                .store
                .recover_account_with_lease(issuer_name, &actual, &lease)
                .await?;
            let mut stored = metadata.clone();
            if let Some(existing) = self.inner.store.load_account(issuer_name, &actual).await? {
                ensure!(
                    self.account_signer(&existing.private_key_pem, cancel)
                        .await?
                        .public_spki()?
                        == signer.public_spki()?
                        && existing.metadata["location"]
                            .as_str()
                            .filter(|v| !v.is_empty())
                            .is_none_or(|v| v == location),
                    "account destination contains a different identity"
                );
                stored = existing.metadata;
                merge_account(&mut stored, metadata)?;
            }
            self.inner
                .store
                .save_account(
                    issuer_name,
                    &actual,
                    &StoredAccount {
                        metadata: stored,
                        private_key_pem: Zeroizing::new(
                            pending.private_key_pem.as_bytes().to_vec(),
                        ),
                    },
                    &lease,
                )
                .await
        }
        .await;
        let released = lease.release().await;
        result?;
        released?;
        // Never hold two registration locks: publication may change the CA's
        // primary contact, including an explicit empty list -> default account.
        let lease = self.inner.store.lock(registration, cancel.clone()).await?;
        let result = async {
            let current = self
                .inner
                .store
                .journal_load(pending_id)
                .await?
                .ok_or_else(|| anyhow!("account publication checkpoint disappeared"))?;
            ensure!(
                (current["phase"] == "stored"
                    && current["storage_email"].as_str() == Some(&actual)
                    && current["metadata"]["location"].as_str() == Some(&location))
                    || (current["metadata"]["location"].as_str() == Some(&location)
                        && current["private_key_pem"].as_str() == Some(&pending.private_key_pem)),
                "account checkpoint changed during publication"
            );
            pending.phase = "stored".to_owned();
            pending.private_key_pem.zeroize();
            pending.eab = None;
            self.store_checkpoint(pending_id, serde_json::to_value(&pending)?, &lease)
                .await
        }
        .await;
        let released = lease.release().await;
        result?;
        released?;
        Ok(session)
    }

    async fn check_job_key(&self, key: &[u8], cancel: &CancellationToken) -> Result<Arc<crate::key_compromise::KeyState>> {
        let key = Zeroizing::new(key.to_vec());
        let deny = self.inner.resolver.leaf_guard().key_deny().clone();
        self.cpu(cancel, move || {
            let signer = crate::certmagic::signing_key(&key, "pending-managed-key")?;
            let public = signer.public_key().ok_or_else(|| anyhow!("pending key SPKI unavailable"))?;
            let key=deny.register_spki(Arc::from(public.as_ref()))?;
            deny.check_state(&key)?;Ok(key)
        }).await
    }

    async fn issue(
        &self,
        names: &[String],
        issuer: &IssuerState,
        account: &AccountSession,
        lease: &StorageLease,
        cycle: (Option<&Replacement>, Option<&Reservation>, &str),
        initial_reuse:Option<&ReusableKey>,
        lifecycle: &crate::cert_events::Attempt,
        cancel: &CancellationToken,
    ) -> Result<ManagedCertificate> {
        let (replacement, reservation, attempt_id) = cycle;
        let wire = issuer
            .wire
            .get_or_try_init(|| {
                AcmeWire::connect_with_cpu(
                    issuer.config.wire.clone(),
                    self.inner.local.clone(),
                    cancel,
                )
            })
            .await?;
        let issuer_name = issuer_key(wire.directory_url())?;
        let initial=self.initial_key(&issuer_name,&names_key(names)?,cancel).await?;
        let initial_hash=initial.as_ref().map(|(snapshot,_)|snapshot.digest().to_owned());
        if let Some((snapshot,key))=&initial && key.state.banned() {
            let archived=self.inner.store.archive_initial_private_key(&issuer_name,&names_key(names)?,snapshot,
                Sha256::digest(&key.spki).into(),names,lease).await;
            let _=self.inner.events.send(AutomationEvent{names:names.to_vec(),kind:match archived {
                Ok(true)=>"compromised_key_archived",Ok(false)=>"compromised_key_not_archived",Err(_)=>"compromised_key_archive_failed",
            },recovery_issue:None});
        }


        let renewal_names = replacement.filter(|r| r.directory == wire.directory_url())
            .and_then(|r| r.renewal_names.clone());
        let replaces = replacement
            .filter(|r| {
                r.directory == wire.directory_url()
                    && r.account == account.location()
                    && wire.directory().renewal_info.is_some()
            })
            .and_then(|r| r.certificate_id.as_deref());
        let mut order_identity = format!(
                "order\0{}\0{}\0{:?}\0{}\0{}",
                wire.directory_url(),
                account.location(),
                issuer.config.leaf_key_type,
                names.join("\0"),
                replacement
                    .map(|r| r.previous_leaf.as_str())
                    .unwrap_or("initial")
            );
        if self.inner.must_staple || self.inner.reuse_private_keys {
            order_identity.push_str(&format!("\0csr-v2:{}:{}",self.inner.must_staple,self.inner.reuse_private_keys));
        }
        if issuer.config.certificate_lifetime_ns != 0 || !issuer.config.profile.is_empty() {
            order_identity.push_str(&format!("\0order-parameters-v1:{}:{}:{}",issuer.config.certificate_lifetime_ns,
                issuer.config.profile.len(),issuer.config.profile));
        }
        let computed_id=digest(order_identity.as_bytes());
        let id = reservation.map(|r| r.job_id.clone()).unwrap_or(computed_id);
        let mut _job_key_reservation: Option<Arc<crate::key_compromise::KeyState>>=None;
        let mut job = if let Some(value) = self.inner.store.journal_load(&id).await? {
            let job: Job = serde_json::from_value(value)
                .map_err(|_| anyhow!("invalid ACME order checkpoint"))?;
            ensure!(
                job.version == 1
                    && job.directory == wire.directory_url()
                    && job.account_location == account.location()
                    && job.names == names
                    && job.config_email == issuer.config.email
                    && job.leaf_key_type == issuer.config.leaf_key_type
                    && job.must_staple == self.inner.must_staple
                    && job.reuse_private_keys == self.inner.reuse_private_keys
                    && job.certificate_lifetime_ns == issuer.config.certificate_lifetime_ns
                    && job.profile == issuer.config.profile,
                "ACME order checkpoint identity changed"
            );
            job
        } else {
            let csr_names = renewal_names.clone().unwrap_or_else(|| names.to_vec());
            let kind = issuer.config.leaf_key_type;
            let deny=self.inner.resolver.leaf_guard().key_deny().clone();
            let must_staple=self.inner.must_staple;
            let reusable=replacement.and_then(|r|r.reuse_key.as_ref()).or(initial_reuse)
                .or_else(||initial.as_ref().map(|(_,key)|key)).map(|key|key.pem.clone());
            let (csr,key,reserved_key)=self.cpu(cancel,move ||generate_csr_with_options(&csr_names,kind,&deny,must_staple,reusable)).await?;
            _job_key_reservation=Some(reserved_key);
            let job = Job {
                version: 1,
                names: names.to_vec(),
                renewal_names: renewal_names.clone(),
                directory: wire.directory_url().to_owned(),
                account_location: account.location().to_owned(),
                config_email: issuer.config.email.clone(),
                leaf_key_type: issuer.config.leaf_key_type,
                must_staple:self.inner.must_staple,
                reuse_private_keys:self.inner.reuse_private_keys,
                certificate_lifetime_ns:issuer.config.certificate_lifetime_ns,
                profile:issuer.config.profile.clone(),
                requested_not_after:None,
                attempt_id: attempt_id.to_owned(),
                abandoned: false,
                phase: "prepared".to_owned(),
                csr_der: csr,
                initial_key_hash:initial_hash.clone(),
                private_key_pem: std::str::from_utf8(&key)
                    .map_err(|_| anyhow!("invalid generated certificate key"))?
                    .to_owned(),
                order_url: None,
                certificate_url: None,
                downloaded_pem: None,
                stored_leaf_sha256: None,
                replaces_disabled: false,
                poll_after_unix: 0,
            };
            self.save_job(&id, &job, lease).await?;
            job
        };
        if job.phase!="stored" && job.initial_key_hash.is_some() {
            ensure!(job.initial_key_hash==initial_hash,"initial certificate private key checkpoint scope changed");
        }
        self.validate_job_renewal_scope(&job).await?;
        if job.phase != "stored" {
            match self.check_job_key(job.private_key_pem.as_bytes(), cancel).await {
                Ok(key) => _job_key_reservation=Some(key),
                Err(error) if error.is::<crate::key_compromise::KeyCompromised>() => {
                    let csr_names = renewal_names.clone().unwrap_or_else(|| names.to_vec()); let kind = issuer.config.leaf_key_type;
                    let deny=self.inner.resolver.leaf_guard().key_deny().clone();
                    let must_staple=self.inner.must_staple;
                    let (csr,key,reserved_key)=self.cpu(cancel,move ||generate_csr_with_options(&csr_names,kind,&deny,must_staple,None)).await?;
                    _job_key_reservation=Some(reserved_key);
                    job.private_key_pem.zeroize();
                    job.private_key_pem = std::str::from_utf8(&key)?.to_owned();
                    job.renewal_names = renewal_names.clone();
                    job.csr_der = csr; job.initial_key_hash=initial_hash.clone();job.phase = "prepared".to_owned();
                    job.order_url = None; job.certificate_url = None; job.downloaded_pem = None;
                    job.stored_leaf_sha256 = None; job.poll_after_unix = 0; job.replaces_disabled = false;
                    self.save_job(&id, &job, lease).await?;
                },
                Err(error) => return Err(error),
            }
        }
        self.activate_leg(names, attempt_id, &id, lease).await?;
        job.attempt_id = attempt_id.to_owned();
        job.abandoned = false;
        self.save_job(&id, &job, lease).await?;
        if job.phase == "stored" {
            let current = self.read_issuer_certificate(&issuer_name,&names_key(names)?,cancel).await?;
            if let Some(bundle) = current {
                let info = self.inspect_material(&bundle, names, cancel).await?;
                let renew_at = renewal_time(
                    info.not_before,
                    info.not_after,
                    self.inner.options.renewal_window_ratio,
                    parse_ari(&bundle.metadata).as_ref(),
                    &info.leaf_sha256,
                )?;
                if job.stored_leaf_sha256.as_deref() == Some(&info.leaf_sha256)
                    && info.not_before <= now()
                    && now() < renew_at
                    && self.material_revocation(&info)?.is_none()
                    && self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der).is_ok()
                {
                    ensure!(
                        self.claim_winner(
                            names,
                            attempt_id,
                            &id,
                            &issuer_name,
                            &info.leaf_sha256,
                            lease
                        )
                        .await?,
                        "certificate attempt lost publication CAS"
                    );
                    self.publish(names, &bundle, cancel).await?;
                    return self.managed(names, &issuer_name, &bundle, info, false);
                }
            }
            // This journal is terminal, never an uncertain CA request. A missing,
            // externally replaced or now-due certificate starts a fresh cycle.
            let csr_names = renewal_names.clone().unwrap_or_else(|| names.to_vec());
            let kind = issuer.config.leaf_key_type;
            let deny=self.inner.resolver.leaf_guard().key_deny().clone();
            let must_staple=self.inner.must_staple;
            let reusable=replacement.and_then(|r|r.reuse_key.as_ref()).or(initial_reuse)
                .or_else(||initial.as_ref().map(|(_,key)|key)).map(|key|key.pem.clone());
            let (csr,key,reserved_key)=self.cpu(cancel,move ||generate_csr_with_options(&csr_names,kind,&deny,must_staple,reusable)).await?;
            _job_key_reservation=Some(reserved_key);
            job.renewal_names = renewal_names.clone();
            job.csr_der = csr;
            job.initial_key_hash=initial_hash.clone();
            job.private_key_pem = std::str::from_utf8(&key)
                .map_err(|_| anyhow!("invalid generated certificate key"))?
                .to_owned();
            job.phase = "prepared".to_owned();
            job.order_url = None;
            job.certificate_url = None;
            job.downloaded_pem = None;
            job.stored_leaf_sha256 = None;
            job.poll_after_unix = 0;
            job.replaces_disabled = false;
            self.save_job(&id, &job, lease).await?;
        }
        let issuance_names = job.renewal_names.clone().unwrap_or_else(|| names.to_vec());
        if job.poll_after_unix > now() {
            let error = anyhow::Error::new(RetryAfterError(job.poll_after_unix));
            return Err(if job.order_url.is_some() {
                ActiveOrderError(error).into()
            } else {
                error
            });
        }
        if job.order_url.is_none() && job.phase == "new_order_intent" {
            let identifiers = issuance_names
                .iter()
                .map(|name| Identifier {
                    kind: "dns".to_owned(),
                    value: name.clone(),
                })
                .collect::<Vec<_>>();
            let parameters = crate::acme_wire::OrderParameters {profile:job.profile.clone(),not_after:job.requested_not_after.clone()};
            match account.reconcile_order_with_parameters(&identifiers, &parameters, cancel).await {
                Ok(Some(url)) => {
                    job.order_url = Some(url);
                    job.phase = "order_recovered".to_owned();
                    self.save_job(&id, &job, lease).await?;
                }
                _ => return Err(AmbiguousOrder.into()),
            }
        }
        if job.order_url.is_none() {
            // Capture this absolute date once, before the durable intent and
            // POST. Unknown outcomes retain it through restart/reconciliation.
            let not_after = if job.certificate_lifetime_ns == 0 { None } else {
                let date = time::OffsetDateTime::now_utc()
                    .checked_add(time::Duration::nanoseconds(job.certificate_lifetime_ns))
                    .ok_or_else(|| anyhow!("ACME requested certificate lifetime overflows"))?
                    .replace_nanosecond(0)?;
                Some(date.format(&time::format_description::well_known::Rfc3339)?)
            };
            let parameters = crate::acme_wire::OrderParameters {profile:job.profile.clone(),not_after};
            account.validate_order_parameters(&parameters)?;
            job.requested_not_after = parameters.not_after.clone();
            job.phase = "new_order_intent".to_owned();
            self.save_job(&id, &job, lease).await?;
            let identifiers = issuance_names
                .iter()
                .map(|name| Identifier {
                    kind: "dns".to_owned(),
                    value: name.clone(),
                })
                .collect::<Vec<_>>();
            let result = account
                .new_order_with_parameters(
                    &identifiers,
                    if job.replaces_disabled {
                        None
                    } else {
                        replaces
                    },
                    &parameters,
                    cancel,
                )
                .await;
            let order = match result {
                Ok(order) => order,
                Err(error) => {
                    if error.downcast_ref::<ProtocolError>().is_some_and(|p| {
                        !p.uncertain() && (400..500).contains(&p.status()) && p.kind() != "unknown"
                    }) {
                        job.phase = "prepared".to_owned();
                        if replaces.is_some()
                            && !job.replaces_disabled
                            && error.downcast_ref::<ProtocolError>().is_some_and(|p| {
                                ["alreadyReplaced", "conflict"].contains(&p.kind())
                            })
                        {
                            job.replaces_disabled = true;
                            self.save_job(&id, &job, lease).await?;
                            // The rejected replacement did not create an order.
                            // Retry without `replaces` once, retaining key/CSR.
                            job.phase = "new_order_intent".to_owned();
                            self.save_job(&id, &job, lease).await?;
                            match account.new_order_with_parameters(&identifiers, None, &parameters, cancel).await {
                                Ok(order) => order,
                                Err(error) => {
                                    if error.downcast_ref::<ProtocolError>().is_some_and(|p| {
                                        !p.uncertain()
                                            && (400..500).contains(&p.status())
                                            && p.kind() != "unknown"
                                    }) {
                                        job.phase = "prepared".to_owned();
                                        self.save_job(&id, &job, lease).await?;
                                        return Err(error);
                                    } else {
                                        return Err(anyhow::Error::new(AmbiguousOrder)
                                            .context(error.to_string()));
                                    }
                                }
                            }
                        } else {
                            self.save_job(&id, &job, lease).await?;
                            return Err(error);
                        }
                    } else {
                        return Err(anyhow::Error::new(AmbiguousOrder).context(error.to_string()));
                    }
                }
            };
            job.order_url = Some(order.location.ok_or_else(|| {
                anyhow::Error::new(AmbiguousOrder)
                    .context("ACME newOrder has no recoverable location")
            })?);
            job.phase = "order_created".to_owned();
            self.save_job(&id, &job, lease).await?;
        }
        let url = job
            .order_url
            .as_deref()
            .ok_or_else(|| anyhow!("ACME order location missing"))?
            .to_owned();
        let mut proofs = Vec::<ChallengeLease>::new();
        let operation=async {
            let mut resource=account.order(&url,cancel).await?;
            let expired=resource.value.expires.as_deref().and_then(|v|time::OffsetDateTime::parse(v,&time::format_description::well_known::Rfc3339).ok()).is_some_and(|v|v.unix_timestamp()<=now());
            if resource.value.status=="invalid" || (expired && resource.value.status!="valid") {
                // The CA has definitively terminated this order. Retain the
                // private key/CSR, but a later bounded scheduler attempt may
                // create a new order rather than polling this URL forever.
                job.phase="prepared".to_owned();job.order_url=None;job.certificate_url=None;job.downloaded_pem=None;
                self.save_job(&id,&job,lease).await?;
                bail!("ACME order is definitively invalid or expired; retry required")
            }
            validate_order(&resource.value,&issuance_names)?;
            if resource.value.status=="pending" {
                ensure!(resource.value.authorizations.len()<=100,"ACME authorization count exceeds bounds");
                for authorization_url in &resource.value.authorizations {
                    let authorization=account.authorization(authorization_url,cancel).await?.value;
                    ensure!(!authorization.wildcard && authorization.identifier.kind=="dns" && issuance_names.contains(&authorization.identifier.value.to_ascii_lowercase()),"ACME authorization identifier changed");
                    if authorization.status=="valid" {continue}
                    ensure!(authorization.status=="pending","ACME authorization is not pending or valid");
                    let challenge=issuer.config.challenge_types.iter().find_map(|kind|authorization.challenges.iter().find(|c|c.kind==kind.as_str() && ["pending","processing"].contains(&c.status.as_str())).map(|c|(*kind,c))).ok_or_else(||anyhow!("requested ACME challenge unavailable"))?;
                    if let Some(prepare)=&self.inner.solver {prepare(issuer.config.wire.directory.clone(),challenge.0,cancel.child_token()).await?;}
                    let token=challenge.1.token.as_deref().ok_or_else(||anyhow!("ACME challenge token missing"))?;
                    let authorization_value=format!("{token}.{}",account.thumbprint());
                    let ttl=self.inner.options.job_timeout.min(Duration::from_secs(3600));
                    let proof=match challenge.0 {
                        ChallengeType::Http01=>self.inner.registry.register_http(&id,&authorization.identifier.value,token,&authorization_value,ttl)?,
                        ChallengeType::TlsAlpn01=>self.inner.registry.register_tls_with_events(&id,&authorization.identifier.value,&authorization_value,ttl,self.inner.lifecycle_events.clone(),cancel.child_token())?,
                    };proofs.push(proof);
                    job.phase="authorizing".to_owned();self.save_job(&id,&job,lease).await?;
                    lease.check().await?;let response=account.respond(&challenge.1.url,cancel).await?;resource.retry_after=resource.retry_after.max(response.retry_after);
                }
                for _ in 0..240 {
                    if resource.value.status!="pending" {break}
                    self.wait_poll(&id,&mut job,lease,resource.retry_after,cancel).await?;
                    resource=account.order(&url,cancel).await?;validate_order(&resource.value,&issuance_names)?;lease.check().await?;
                }
            }
            if resource.value.status=="ready" {
                let _finalize_key_reservation=self.check_job_key(job.private_key_pem.as_bytes(),cancel).await?;
                job.phase="finalize_intent".to_owned();self.save_job(&id,&job,lease).await?;
                resource=account.finalize(&resource.value.finalize,&job.csr_der,cancel).await?;
                job.phase="finalized".to_owned();self.save_job(&id,&job,lease).await?;
            }
            for _ in 0..240 {
                if resource.value.status=="valid" {break}
                ensure!(resource.value.status=="processing" || resource.value.status=="ready","ACME order failed to finalize");
                self.wait_poll(&id,&mut job,lease,resource.retry_after,cancel).await?;
                resource=account.order(&url,cancel).await?;validate_order(&resource.value,&issuance_names)?;lease.check().await?;
            }
            ensure!(resource.value.status=="valid","ACME certificate polling deadline exceeded");
            job.certificate_url=resource.value.certificate;
            if job.downloaded_pem.is_none() {
                let certificate=account.download(job.certificate_url.as_deref().ok_or_else(||anyhow!("valid ACME order has no certificate URL"))?,cancel).await?;
                job.downloaded_pem=Some(String::from_utf8(certificate).map_err(|_|anyhow!("ACME certificate response is not PEM"))?);
                job.phase="downloaded".to_owned();self.save_job(&id,&job,lease).await?;
            }
            let mut bundle=CertificateBundle {chain_pem:job.downloaded_pem.as_ref().ok_or_else(||anyhow!("ACME certificate missing"))?.as_bytes().to_vec(),private_key_pem:Zeroizing::new(job.private_key_pem.as_bytes().to_vec()),metadata:json!({"sans":issuance_names,"issuer_data":{"url":job.certificate_url,"ca":wire.directory_url(),"account":account.location()}})};
            let info=self.inspect_material(&bundle,names,cancel).await?;
            self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der)?;
            ensure!(info.not_before<=now() && info.not_after>now(),"issued certificate is not currently valid");
            if let Some(cert_id)=self.certificate_id(&bundle.chain_pem,cancel).await? && let Ok(Some(ari))=wire.renewal_info(&cert_id,cancel).await {write_ari(&mut bundle.metadata,&ari,&info,self.inner.options.renewal_window_ratio)?;}
            job.stored_leaf_sha256=Some(info.leaf_sha256.clone());job.phase="store_intent".to_owned();self.save_job(&id,&job,lease).await?;
            lease.check().await?;self.save_issued_certificate(&issuer_name,&names_key(names)?,&bundle,lease,job.initial_key_hash.as_deref()).await?;
            lifecycle.obtained(self.inner.lifecycle_events.as_ref(),&issuer_name,names,&job.csr_der,cancel).await;
            job.phase="stored".to_owned();job.private_key_pem.zeroize();job.downloaded_pem=None;job.csr_der.clear();self.save_job(&id,&job,lease).await?;
            // Once persisted, publication errors retain this candidate. A later
            // ensure loads it instead of creating or paying for another order.
            ensure!(self.claim_winner(names,attempt_id,&id,&issuer_name,&info.leaf_sha256,lease).await?,"certificate attempt lost publication CAS");
            self.publish(names,&bundle,cancel).await?;
            self.managed(names,&issuer_name,&bundle,info,true)
        }.await;
        drop(proofs);
        operation.map_err(|error| {
            if job.order_url.is_some() {
                ActiveOrderError(error).into()
            } else {
                error
            }
        })
    }

    async fn wait_poll(
        &self,
        id: &str,
        job: &mut Job,
        lease: &StorageLease,
        retry: Option<Duration>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let delay = retry
            .unwrap_or(Duration::from_secs(1))
            .max(Duration::from_secs(1));
        job.poll_after_unix = now() + delay.as_secs() as i64;
        self.save_job(id, job, lease).await?;
        sleep_cancel(delay, cancel).await?;
        job.poll_after_unix = 0;
        Ok(())
    }
    async fn save_job(&self, id: &str, job: &Job, lease: &StorageLease) -> Result<()> {
        let operation = async {
            self.store_checkpoint(id, serde_json::to_value(job)?, lease)
                .await?;
            let marker_id = reservation_id(&job.names, &job.directory)?;
            let active = !["prepared", "stored"].contains(&job.phase.as_str());
            if let Some(value) = self.inner.store.journal_load(&marker_id).await? {
                let previous: Reservation = serde_json::from_value(value)
                    .map_err(|_| anyhow!("invalid active ACME reservation"))?;
                ensure!(
                    !previous.active || previous.job_id == id,
                    "another ACME order is already active for these names"
                );
                if !active && previous.job_id != id {
                    return Ok(());
                }
            }
            let marker = Reservation {
                version: 1,
                names: job.names.clone(),
                directory: job.directory.clone(),
                account_location: job.account_location.clone(),
                config_email: job.config_email.clone(),
                leaf_key_type: job.leaf_key_type,
                must_staple:job.must_staple,
                reuse_private_keys:job.reuse_private_keys,
                certificate_lifetime_ns:job.certificate_lifetime_ns,
                profile:job.profile.clone(),
                job_id: id.to_owned(),
                active,
            };
            self.store_checkpoint(&marker_id, serde_json::to_value(marker)?, lease)
                .await
        }
        .await;
        operation.map_err(|error| {
            if !["prepared", "stored"].contains(&job.phase.as_str()) {
                ActiveOrderError(error).into()
            } else {
                error
            }
        })
    }
    async fn load_attempt(&self, names: &[String]) -> Result<Option<Attempt>> {
        let Some(value) = self.inner.store.journal_load(&attempt_key(names)?).await? else {
            return Ok(None);
        };
        let attempt: Attempt =
            serde_json::from_value(value).map_err(|_| anyhow!("invalid certificate attempt"))?;
        ensure!(
            attempt.version == 1 && attempt.names == names,
            "certificate attempt scope changed"
        );
        Ok(Some(attempt))
    }
    async fn activate_leg(
        &self,
        names: &[String],
        attempt_id: &str,
        job_id: &str,
        lease: &StorageLease,
    ) -> Result<()> {
        let mut attempt = self
            .load_attempt(names)
            .await?
            .ok_or_else(|| anyhow!("certificate attempt missing"))?;
        ensure!(
            attempt.attempt_id == attempt_id && attempt.winner.is_none(),
            "certificate attempt was superseded"
        );
        attempt.current_job_id = Some(job_id.to_owned());
        self.store_checkpoint(&attempt_key(names)?, serde_json::to_value(attempt)?, lease)
            .await
    }
    async fn claim_winner(
        &self,
        names: &[String],
        attempt_id: &str,
        job_id: &str,
        issuer: &str,
        leaf: &str,
        lease: &StorageLease,
    ) -> Result<bool> {
        let Some(mut attempt) = self.load_attempt(names).await? else {
            return Ok(false);
        };
        if attempt.attempt_id != attempt_id || attempt.current_job_id.as_deref() != Some(job_id) {
            return Ok(false);
        }
        if let Some(winner) = attempt.winner {
            return Ok(winner.job_id == job_id
                && winner.issuer_key == issuer
                && winner.leaf_sha256 == leaf);
        }
        attempt.winner = Some(Winner {
            issuer_key: issuer.to_owned(),
            job_id: job_id.to_owned(),
            leaf_sha256: leaf.to_owned(),
        });
        self.store_checkpoint(&attempt_key(names)?, serde_json::to_value(attempt)?, lease)
            .await?;
        Ok(true)
    }
    async fn abandon_leg(
        &self,
        names: &[String],
        attempt_id: &str,
        lease: &StorageLease,
    ) -> Result<()> {
        let Some(attempt) = self.load_attempt(names).await? else {
            return Ok(());
        };
        if attempt.attempt_id != attempt_id || attempt.winner.is_some() {
            return Ok(());
        }
        if let Some(id) = attempt.current_job_id
            && let Some(value) = self.inner.store.journal_load(&id).await?
        {
            let mut job: Job = serde_json::from_value(value)
                .map_err(|_| anyhow!("invalid abandoned ACME checkpoint"))?;
            job.abandoned = true;
            self.save_job(&id, &job, lease).await?;
        }
        Ok(())
    }
    async fn store_checkpoint(
        &self,
        id: &str,
        mut value: Value,
        lease: &StorageLease,
    ) -> Result<()> {
        value["lease_name"] = json!(lease.name());
        self.inner
            .store
            .journal_store_fenced(id, &value, lease)
            .await
    }
    async fn publish(
        &self,
        names: &[String],
        bundle: &CertificateBundle,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if !self.inner.publish_to_resolver {
            ensure!(!cancel.is_cancelled(), "ACME operation cancelled");
            return Ok(());
        }
        for attempt in 0..8 {
            let names_owned = names.to_vec();
            let chain = bundle.chain_pem.clone();
            let key = bundle.private_key_pem.clone();
            let resolver = self.inner.resolver.clone();
            match self
                .cpu(cancel, move || {
                    Ok(resolver.upsert(&CertificateInput {
                        names: &names_owned,
                        certificate_pem: &chain,
                        private_key_pem: &key,
                    }))
                })
                .await?
            {
                Ok(()) => {
                    // Cached material is also a new resolver instance. Observers
                    // must discover it even when no ACME order was necessary.
                    let _ = self.inner.events.send(AutomationEvent {
                        names: names.to_vec(),
                        kind: "certificate_published",
                        recovery_issue: None,
                    });
                    return Ok(());
                }
                Err(error) => {
                    if error.to_string()
                        != "certificate update conflicted with concurrent publication; retry required"
                    {
                        return Err(error);
                    }
                }
            }
            sleep_cancel(Duration::from_millis(10 * (1 << attempt)), cancel).await?;
        }
        bail!("certificate publication retry budget exhausted")
    }
    fn material_revocation(
        &self,
        info: &MaterialInfo,
    ) -> Result<Option<crate::leaf_guard::Revocation>> {
        self.inner
            .resolver
            .leaf_guard()
            .intern(info.leaf_id, info.not_after)?
            .revocation()
    }
    // Both callers have checked current validity: either freshly issued
    // material or a stored certificate still before its renewal deadline.
    fn managed(
        &self,
        names: &[String],
        issuer: &str,
        bundle: &CertificateBundle,
        info: MaterialInfo,
        obtained: bool,
    ) -> Result<ManagedCertificate> {
        self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der)?;
        ensure!(
            self.material_revocation(&info)?.is_none(),
            "managed certificate is revoked"
        );
        Ok(ManagedCertificate {
            names: names.to_vec(),
            issuer_key: issuer.to_owned(),
            not_after_unix: info.not_after,
            renew_at_unix: renewal_time(
                info.not_before,
                info.not_after,
                self.inner.options.renewal_window_ratio,
                parse_ari(&bundle.metadata).as_ref(),
                &info.leaf_sha256,
            )?,
            leaf_sha256: info.leaf_sha256,
            obtained,
        })
    }

    /// Each managed SAN set owns an independent loop. One failed CA/domain never
    /// prevents another from serving or renewing. Cancellation joins every loop.
    pub async fn run(&self, names: Vec<Vec<String>>, cancel: CancellationToken) -> Result<()> {
        ensure!(
            names.len() <= 65536,
            "managed certificate count exceeds bounds"
        );
        let groups = names
            .iter()
            .map(|group| normalize_names(group))
            .collect::<Result<Vec<_>>>()?;
        self.startup_recovery(cancel.clone()).await?;
        let mut jobs = JoinSet::new();
        for names in groups {
            let manager = self.clone();
            let token = cancel.child_token();
            jobs.spawn(async move {
                let mut failures = 0u32;
                loop {
                    if token.is_cancelled() {
                        break;
                    }
                    let delay = match manager.ensure(&names, token.clone()).await {
                        Ok(cert) => {
                            failures = 0;
                            Duration::from_secs((cert.renew_at_unix - now()).max(1) as u64)
                                .min(manager.inner.options.poll_interval)
                        }
                        Err(error) => {
                            let _ = manager.inner.events.send(AutomationEvent {
                                names: names.clone(),
                                kind: "issuance_failed",
                                recovery_issue: None,
                            });
                            failures = failures.saturating_add(1);
                            let suggested = error_retry_delay(&error);
                            retry_backoff(failures, &names).max(suggested)
                        }
                    };
                    if sleep_cancel(delay, &token).await.is_err() {
                        break;
                    }
                }
            });
        }
        let mut task_failed = false;
        loop {
            tokio::select! {
                _=cancel.cancelled()=>break,
                result=jobs.join_next(),if !jobs.is_empty()=>{
                    if result.is_some_and(|r|r.is_err()) {task_failed=true;let _=self.inner.events.send(AutomationEvent {names:Vec::new(),kind:"background_task_failed", recovery_issue:None,});}
                    if jobs.is_empty(){break}
                }
            }
        }
        // A task failure does not abort peers. On shutdown signal everyone and
        // await the shielded operations and lease release of every live task.
        cancel.cancel();
        while let Some(result) = jobs.join_next().await {
            if result.is_err() {
                task_failed = true;
            }
        }
        ensure!(!task_failed, "certificate background task failed");
        Ok(())
    }
}

#[derive(Debug)]
pub struct ActiveOrderError(anyhow::Error);
impl std::fmt::Display for ActiveOrderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an existing ACME order must be resumed before issuer fallback")
    }
}
impl std::error::Error for ActiveOrderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
#[derive(Debug)]
pub(crate) struct FutureCertificate(pub(crate) i64);
impl std::fmt::Display for FutureCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "stored certificate is not valid yet; check the local clock and retry after notBefore",
        )
    }
}
impl std::error::Error for FutureCertificate {}

#[derive(Debug)]
struct RetryAfterError(i64);
impl std::fmt::Display for RetryAfterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ACME server requested retry backoff")
    }
}
impl std::error::Error for RetryAfterError {}
pub(crate) fn error_retry_delay(error: &anyhow::Error) -> Duration {
    if let Some(error) = error.downcast_ref::<ActiveOrderError>() {
        return error_retry_delay(&error.0);
    }
    let deadline = error
        .downcast_ref::<RetryAfterError>()
        .map(|e| e.0)
        .or_else(|| error.downcast_ref::<FutureCertificate>().map(|e| e.0));
    if let Some(deadline) = deadline {
        // Periodically recheck local state even for extreme clock skew. The
        // stored notBefore/CA deadline remains authoritative on the next pass;
        // this bound prevents constructing an overflowing runtime timer.
        return Duration::from_secs(deadline.saturating_sub(now()).max(1) as u64)
            .min(Duration::from_secs(86400));
    }
    error
        .downcast_ref::<ProtocolError>()
        .and_then(ProtocolError::retry_after)
        .unwrap_or_default()
}
fn record_issuer_error(issuer: &IssuerState, error: &anyhow::Error) {
    if let Some(error) = error.downcast_ref::<ActiveOrderError>() {
        record_issuer_error(issuer, &error.0);
        return;
    }
    if let Some(error) = error.downcast_ref::<ProtocolError>()
        && let Some(delay) = error
            .retry_after()
            .or_else(|| (error.status() == 429).then_some(Duration::from_secs(60)))
    {
        issuer
            .ca
            .next_allowed_unix
            .fetch_max(now() + delay.as_secs() as i64, Ordering::AcqRel);
    }
}
#[derive(Debug)]
struct RetryAccountAlias;
impl std::fmt::Display for RetryAccountAlias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("account alias publication completed concurrently; retry lookup")
    }
}
impl std::error::Error for RetryAccountAlias {}
#[derive(Debug)]
pub struct AmbiguousOrder;
impl std::fmt::Display for AmbiguousOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ACME order creation is uncertain; reconcile the existing order before requesting another")
    }
}
impl std::error::Error for AmbiguousOrder {}

fn merge_account(original: &mut Value, updated: &Value) -> Result<()> {
    let original = original
        .as_object_mut()
        .ok_or_else(|| anyhow!("invalid ACME account metadata"))?;
    let updated = updated
        .as_object()
        .ok_or_else(|| anyhow!("invalid ACME account response"))?;
    for (key, value) in updated {
        original.insert(key.clone(), value.clone());
    }
    Ok(())
}
pub fn normalize_names(input: &[String]) -> Result<Vec<String>> {
    ensure!(
        !input.is_empty() && input.len() <= 100,
        "certificate name count outside bounds"
    );
    let mut names = Vec::new();
    for name in input {
        let name = name.trim().trim_end_matches('.');
        ensure!(
            !name.starts_with("*."),
            "wildcard certificates require a DNS-01 provider"
        );
        let parsed =
            url::Host::parse(name).map_err(|_| anyhow!("invalid certificate DNS identifier"))?;
        let url::Host::Domain(name) = parsed else {
            bail!("IP certificate identifiers require a supported IP challenge policy")
        };
        names.push(crate::challenge::normalize_domain(&name)?);
    }
    names.sort();
    names.dedup();
    Ok(names)
}
fn validate_order(order: &Order, names: &[String]) -> Result<()> {
    ensure!(
        ["pending", "ready", "processing", "valid"].contains(&order.status.as_str()),
        "ACME order is invalid or expired"
    );
    let mut actual = order
        .identifiers
        .iter()
        .map(|id| {
            ensure!(id.kind == "dns", "ACME order identifier type changed");
            Ok(id.value.to_ascii_lowercase())
        })
        .collect::<Result<Vec<_>>>()?;
    actual.sort();
    actual.dedup();
    let mut expected = names.to_vec(); expected.sort(); expected.dedup();
    ensure!(actual == expected, "ACME order identifiers changed");
    Ok(())
}
/// Generate a CSR only after the exact SPKI owns its reserved KeyState.
pub(crate) fn generate_csr(names:&[String],kind:KeyType,deny:&crate::key_compromise::KeyDeny)
    ->Result<(Vec<u8>,Zeroizing<Vec<u8>>,Arc<crate::key_compromise::KeyState>)> {
    generate_csr_with_options(names,kind,deny,false,None)
}
pub(crate) fn generate_csr_with_options(names:&[String],kind:KeyType,deny:&crate::key_compromise::KeyDeny,
    must_staple:bool,reusable:Option<Zeroizing<Vec<u8>>>)
    ->Result<(Vec<u8>,Zeroizing<Vec<u8>>,Arc<crate::key_compromise::KeyState>)> {
    use rcgen::{PublicKeyData,SigningKey};
    use der::{Decode,Encode};
    use x509_parser::prelude::FromDer;
    let pem=if let Some(pem)=reusable {
        let signer=crate::crypto::x509_signer::X509Signer::from_private_key(&pem)?;
        let spki=signer.subject_public_key_info();
        let state=deny.register_spki(Arc::from(spki))?;
        if deny.check_state(&state).is_ok() {pem} else {
            AccountSigner::generate(kind)?.1
        }
    } else {AccountSigner::generate(kind)?.1};
    let signer=crate::crypto::x509_signer::X509Signer::from_private_key(&pem)?;
    let spki=signer.subject_public_key_info();
    let reservation=deny.register_spki(Arc::from(spki.clone()))?;
    deny.check_state(&reservation)?;
    let mut params=rcgen::CertificateParams::new(names.to_vec()).map_err(|_|anyhow!("invalid certificate CSR names"))?;
    params.distinguished_name=rcgen::DistinguishedName::new();
    if must_staple {params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
        &[1,3,6,1,5,5,7,1,24],vec![0x30,0x03,0x02,0x01,0x05]));}
    let encoded=params.serialize_request(&signer).map_err(|_|anyhow!("certificate CSR signing failed"))?.der().to_vec();
    // Rcgen has no P224 SignatureAlgorithm and encodes its P256 template OID.
    // Bind the actual validated SPKI and sign that exact CertificationRequestInfo.
    let mut request=x509_cert::request::CertReq::from_der(&encoded)?;
    let csr=if request.info.public_key.to_der()?!=spki {
        request.info.public_key=x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki)?;
        let signature=signer.sign(&request.info.to_der()?).map_err(|_|anyhow!("CSR SPKI binding signature failed"))?;
        request.signature=der::asn1::BitString::new(0,signature)?;
        request.to_der()?
    } else {encoded};
    let (_,parsed)=x509_parser::certification_request::X509CertificationRequest::from_der(&csr)
        .map_err(|_|anyhow!("generated CSR is invalid"))?;
    crate::cert_status::verify_x509_signature(&parsed.certification_request_info.subject_pki,
        &parsed.signature_algorithm,&parsed.signature_value.data,parsed.certification_request_info.raw,true)?;
    deny.check_state(&reservation)?;
    Ok((csr,pem,reservation))
}
fn material_info(bundle: &CertificateBundle, names: &[String], deny:&crate::key_compromise::KeyDeny) -> Result<MaterialInfo> {
    use x509_parser::extensions::GeneralName;
    let blocks = crate::certmagic::pem_blocks(&bundle.chain_pem, "managed-certificate")?;
    let mut chain = Vec::new();
    for (label, der) in &blocks {
        ensure!(
            label == "CERTIFICATE",
            "invalid managed certificate PEM label"
        );
        let (remaining, _) = x509_parser::parse_x509_certificate(der)
            .map_err(|_| anyhow!("invalid managed certificate DER"))?;
        ensure!(remaining.is_empty(), "trailing managed certificate DER");
        chain.push(rustls::pki_types::CertificateDer::from(der.to_vec()));
    }
    let signer = crate::certmagic::signing_key(&bundle.private_key_pem, "managed-certificate")?;
    rustls::sign::CertifiedKey::new(chain, signer)
        .keys_match()
        .map_err(|_| anyhow!("managed certificate key mismatch"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&blocks[0].1)
        .map_err(|_| anyhow!("invalid managed leaf certificate"))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|_| anyhow!("invalid managed certificate SAN"))?
        .ok_or_else(|| anyhow!("managed certificate SAN missing"))?;
    let actual = san
        .value
        .general_names
        .iter()
        .filter_map(|v| {
            if let GeneralName::DNSName(name) = v {
                Some(name.to_ascii_lowercase())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        names.iter().all(|name| actual.contains(name)),
        "managed certificate SAN mismatch"
    );
    ensure!(
        cert.validity().not_after.timestamp() > cert.validity().not_before.timestamp(),
        "managed certificate lifetime is empty"
    );
    let spki_der:Arc<[u8]>=Arc::from(cert.public_key().raw);
    let key_state=deny.register_spki(spki_der.clone())?;
    Ok(MaterialInfo {
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        leaf_id: crate::leaf_guard::leaf_id(&blocks[0].1),
        spki_der,
        _key_state:key_state,
        leaf_sha256: digest(&blocks[0].1),
    })
}
/// Renewal is relative to the certificate's actual lifetime, never a fixed
/// calendar-day threshold. ARI chooses a repeatable uniform point in its window.
pub fn renewal_time(
    not_before: i64,
    not_after: i64,
    ratio: f64,
    ari: Option<&AriWindow>,
    fingerprint: &str,
) -> Result<i64> {
    ensure!(
        not_after > not_before && ratio.is_finite() && ratio > 0.0 && ratio < 1.0,
        "invalid certificate renewal inputs"
    );
    let fallback = not_after - ((not_after - not_before) as f64 * ratio).ceil() as i64;
    if let Some(ari) = ari {
        let end = ari.end_unix.min(not_after);
        let start = ari.start_unix;
        if end > start {
            let hash = Sha256::digest(fingerprint.as_bytes());
            let random = u64::from_be_bytes(
                hash[..8]
                    .try_into()
                    .map_err(|_| anyhow!("renewal selection failed"))?,
            );
            return Ok(start + (random % ((end - start) as u64)) as i64);
        }
    }
    Ok(fallback)
}
pub(crate) fn ari_refresh_time(meta: &Value) -> Option<i64> {
    parse_ari(meta).map(|ari| ari.refresh_after_unix)
}
fn parse_ari(meta: &Value) -> Option<AriWindow> {
    let ari = &meta["issuer_data"]["renewal_info"];
    let parse = |v: &Value| {
        time::OffsetDateTime::parse(v.as_str()?, &time::format_description::well_known::Rfc3339)
            .ok()
            .map(|t| t.unix_timestamp())
    };
    Some(AriWindow {
        start_unix: parse(&ari["suggestedWindow"]["start"])?,
        end_unix: parse(&ari["suggestedWindow"]["end"])?,
        refresh_after_unix: parse(&ari["_retryAfter"]).unwrap_or(0),
        certificate_id: ari["_uniqueIdentifier"].as_str()?.to_owned(),
    })
}
fn write_ari(meta: &mut Value, ari: &AriWindow, info: &MaterialInfo, ratio: f64) -> Result<()> {
    let format = |n: i64| -> Result<String> {
        time::OffsetDateTime::from_unix_timestamp(n)
            .map_err(|_| anyhow!("ARI date outside bounds"))?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| anyhow!("ARI date formatting failed"))
    };
    if meta.get("issuer_data").is_none() {
        meta["issuer_data"] = json!({});
    }
    ensure!(
        meta["issuer_data"].is_object(),
        "managed certificate issuer metadata is not an object"
    );
    meta["issuer_data"]["renewal_info"] = json!({"suggestedWindow":{"start":format(ari.start_unix)?,"end":format(ari.end_unix)?},"_uniqueIdentifier":ari.certificate_id,"_retryAfter":format(ari.refresh_after_unix)?,"_selectedTime":format(renewal_time(info.not_before,info.not_after,ratio,Some(ari),&info.leaf_sha256)?)?});
    Ok(())
}
pub(crate) fn retry_backoff(failures: u32, names: &[String]) -> Duration {
    let base = (5u64.saturating_mul(1u64 << failures.min(10))).min(3600);
    let hash = Sha256::digest(format!("{}:{failures}", names.join("\0")).as_bytes());
    let jitter = u16::from_be_bytes([hash[0], hash[1]]) as u64 % (base / 4 + 1);
    Duration::from_secs(base + jitter)
}
async fn sleep_cancel(duration: Duration, cancel: &CancellationToken) -> Result<()> {
    tokio::select! {biased;_=cancel.cancelled()=>Err(anyhow!("ACME operation cancelled")),_=tokio::time::sleep(duration)=>Ok(())}
}
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn reservation_id(names: &[String], directory: &str) -> Result<String> {
    Ok(digest(
        format!(
            "active_issuer\0{}\0{}",
            issuer_key(directory)?,
            names_key(names)?
        )
        .as_bytes(),
    ))
}
fn attempt_key(names: &[String]) -> Result<String> {
    Ok(digest(
        format!("certificate_attempt\0{}", names_key(names)?).as_bytes(),
    ))
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
