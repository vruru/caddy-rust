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
            },
            email: String::new(),
            account_key_type: KeyType::P256,
            leaf_key_type: KeyType::P256,
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

#[derive(Clone)]
pub struct CertificateManager {
    inner: Arc<ManagerInner>,
}
struct ManagerInner {
    store: FsStore,
    registry: ChallengeRegistry,
    resolver: Arc<HotCertificateResolver>,
    options: AutomationOptions,
    global: Semaphore,
    issuers: Vec<IssuerState>,
    gates: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    events: broadcast::Sender<AutomationEvent>,
    recovered: OnceCell<RecoveryReport>,
    recovery_announced: AtomicBool,
}
struct CaState {
    limiter: Semaphore,
    next_allowed_unix: AtomicI64,
}
struct IssuerState {
    config: AcmeIssuerConfig,
    ca: Arc<CaState>,
    wire: OnceCell<AcmeWire>,
}

#[derive(Serialize, Deserialize)]
struct Job {
    version: u8,
    names: Vec<String>,
    directory: String,
    account_location: String,
    #[serde(default)]
    config_email: String,
    #[serde(default)]
    leaf_key_type: KeyType,
    #[serde(default)]
    attempt_id: String,
    #[serde(default)]
    abandoned: bool,
    phase: String,
    csr_der: Vec<u8>,
    private_key_pem: String,
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
    job_id: String,
    active: bool,
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
    leaf_sha256: String,
}
#[derive(Clone)]
struct Replacement {
    certificate_id: Option<String>,
    previous_leaf: String,
    directory: String,
    account: String,
}

impl CertificateManager {
    pub fn new(
        store: FsStore,
        registry: ChallengeRegistry,
        resolver: Arc<HotCertificateResolver>,
        options: AutomationOptions,
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
        }
        let mut limiters = HashMap::new();
        let mut issuers = Vec::new();
        for mut config in options.issuers.iter().cloned() {
            let directory = url::Url::parse(&config.wire.directory)
                .map_err(|_| anyhow!("invalid ACME directory URL"))?;
            config.wire.directory = directory.to_string();
            let ca = directory.origin().ascii_serialization();
            let limiter = limiters
                .entry(ca)
                .or_insert_with(|| {
                    Arc::new(CaState {
                        limiter: Semaphore::new(options.max_concurrent_per_ca),
                        next_allowed_unix: AtomicI64::new(0),
                    })
                })
                .clone();
            issuers.push(IssuerState {
                config,
                ca: limiter,
                wire: OnceCell::new(),
            });
        }
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(ManagerInner {
                store,
                registry,
                resolver,
                global: Semaphore::new(options.max_concurrent),
                options,
                issuers,
                gates: Mutex::new(HashMap::new()),
                events,
                recovered: OnceCell::new(),
                recovery_announced: AtomicBool::new(false),
            }),
        })
    }
    pub fn recovery_report(&self) -> Option<RecoveryReport> {
        self.inner.recovered.get().cloned()
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
                        .get_or_try_init(|| AcmeWire::connect(issuer.config.wire.clone(), &cancel))
                        .await?;
                    let session = wire.restore(
                        Arc::new(AccountSigner::from_pem(&account.private_key_pem)?),
                        &job.account_location,
                    )?;
                    let resource = session.order(&order_url, &cancel).await?;
                    validate_order(&resource.value, &names)?;
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

    async fn ensure_inner(
        &self,
        names: Vec<String>,
        cancel: CancellationToken,
    ) -> Result<ManagedCertificate> {
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
        let _gate = tokio::select! {biased;_=cancel.cancelled()=>return Err(anyhow!("ACME operation cancelled")),guard=gate.lock()=>guard};
        let _global = tokio::select! {biased;_=cancel.cancelled()=>return Err(anyhow!("ACME operation cancelled")),permit=self.inner.global.acquire()=>permit.map_err(|_|anyhow!("ACME manager closed"))?};
        // Queueing for a per-name/global permit is cancellable but is not
        // charged to a job's execution deadline, avoiding starvation in fleets.
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
                return Ok((ready, previous, None));
            }
            use p256::elliptic_curve::rand_core::RngCore;
            let mut random = [0u8; 32];
            p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut random);
            let attempt = Attempt {
                version: 1,
                names: names.clone(),
                attempt_id: digest(&random),
                issuer_sequence: self
                    .inner
                    .issuers
                    .iter()
                    .map(|i| i.config.wire.directory.clone())
                    .collect(),
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
            Ok::<_, anyhow::Error>((None, previous, Some(attempt.attempt_id)))
        }
        .await;
        let release = lease.release().await;
        let (ready, mut previous, attempt_id) = initial?;
        release?;
        if let Some(ready) = ready {
            return Ok(ready);
        }
        let attempt_id =
            attempt_id.ok_or_else(|| anyhow!("certificate attempt was not initialized"))?;
        let _ = self.inner.events.send(AutomationEvent {
            names: names.clone(),
            kind: "issuance_started",
            recovery_issue: None,
        });
        let mut last_error = None;
        let mut tried_issuers = std::collections::HashSet::new();
        for (index, issuer) in self.inner.issuers.iter().enumerate() {
            if !tried_issuers.insert(issuer_key(&issuer.config.wire.directory)?) {
                continue;
            }
            if cancel.is_cancelled() {
                bail!("ACME operation cancelled")
            }
            if index > 0 {
                sleep_cancel(Duration::from_millis(250u64 << index.min(5)), &cancel).await?;
            }
            let allowed = issuer.ca.next_allowed_unix.load(Ordering::Acquire);
            if allowed > now() {
                last_error = Some(RetryAfterError(allowed).into());
                continue;
            }
            let _ca = tokio::select! {biased;_=cancel.cancelled()=>return Err(anyhow!("ACME operation cancelled")),p=issuer.ca.limiter.acquire()=>p.map_err(|_|anyhow!("ACME issuer closed"))?};
            let wire = match issuer
                .wire
                .get_or_try_init(|| AcmeWire::connect(issuer.config.wire.clone(), &cancel))
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
            drop(_ca);
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
                    let _ = self
                        .inner
                        .store
                        .load_certificate(&scope_issuer, &scope_names)
                        .await?;
                    let current = self.read_reservation(&names, issuer).await?;
                    if let Some(active) = current.as_ref() {
                        ensure!(
                            active.account_location == account.location(),
                            "active ACME account identity changed"
                        );
                    }
                    let _issuance_ca = tokio::select! {biased;_=leg_cancel.cancelled()=>return Err(anyhow!("ACME operation cancelled")),permit=issuer.ca.limiter.acquire()=>permit.map_err(|_|anyhow!("ACME issuer closed"))?};
                    self.issue(
                        &names,
                        issuer,
                        &account,
                        &lease,
                        (previous.as_ref(), current.as_ref(), &attempt_id),
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
        Err(last_error.unwrap_or_else(|| anyhow!("no ACME issuer available")))
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
        self.load_existing(names, lease, cancel).await
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
        if !marker.active {
            return Ok(None);
        }
        ensure!(
            marker.config_email == issuer.config.email
                && marker.leaf_key_type == issuer.config.leaf_key_type,
            "active issuer configuration changed; restore it or explicitly resolve that issuer order"
        );
        Ok(Some(marker))
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
            marker.version == 1 && marker.names == names,
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
        ensure!(
            job.version == 1
                && job.names == names
                && job.directory == marker.directory
                && job.account_location == marker.account_location
                && job.config_email == marker.config_email
                && job.leaf_key_type == marker.leaf_key_type,
            "active ACME checkpoint identity changed"
        );
        if job.phase == "prepared" {
            self.save_job(&marker.job_id, &job, lease).await?;
            return Ok(None);
        }
        ensure!(
            self.inner
                .issuers
                .iter()
                .any(|i| i.config.wire.directory == marker.directory
                    && i.config.email == marker.config_email
                    && i.config.leaf_key_type == marker.leaf_key_type),
            "active ACME issuer configuration changed; restore it or explicitly resolve the order"
        );
        let issuer = issuer_key(&marker.directory)?;
        let key = names_key(names)?;
        self.inner
            .store
            .recover_certificate_with_lease(&issuer, &key, lease)
            .await?;
        // Finish an already validated candidate without depending on CA/account
        // connectivity. A prior commit may have succeeded before its checkpoint.
        if let Some(current) = self.inner.store.load_certificate(&issuer, &key).await? {
            let info = material_info(&current, names)?;
            if job.stored_leaf_sha256.as_deref() == Some(&info.leaf_sha256) {
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
                metadata: json!({"sans":names,"issuer_data":{"url":job.certificate_url,"ca":job.directory,"account":job.account_location}}),
            };
            let info = material_info(&bundle, names)?;
            if info.not_after <= now() {
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
            self.inner
                .store
                .save_certificate(&issuer, &key, &bundle, lease)
                .await?;
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
        lease: &StorageLease,
        cancel: &CancellationToken,
    ) -> Result<(Option<ManagedCertificate>, Option<Replacement>)> {
        let key = names_key(names)?;
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
            lease.check().await?;
            let issuer_name = issuer_key(&issuer.config.wire.directory)?;
            let material = async {
                self.inner
                    .store
                    .recover_certificate_with_lease(&issuer_name, &key, lease)
                    .await?;
                let Some(bundle) = self
                    .inner
                    .store
                    .load_certificate(&issuer_name, &key)
                    .await?
                else {
                    return Ok(None);
                };
                let info = material_info(&bundle, names)?;
                Ok::<_, anyhow::Error>(Some((bundle, info)))
            }
            .await;
            let Some((bundle, info)) = (match material {
                Ok(value) => value,
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
        let mut previous_id = None;
        if let Some((index, mut bundle, info)) = best.or(fallback) {
            let issuer = &self.inner.issuers[index];
            let now = now();
            // Preserve the attempt/winner selection above. A revocation vetoes
            // cached readiness; it must not select an older issuer's leaf.
            let revoked = info.not_after > now && self.material_revocation(&info)?.is_some();
            if info.not_before <= now && info.not_after > now {
                self.publish(names, &bundle, cancel).await?;
            }
            let mut ari = parse_ari(&bundle.metadata);
            if !revoked
                && issuer.ca.next_allowed_unix.load(Ordering::Acquire) <= now
                && info.not_after > now
                && ari.as_ref().is_none_or(|a| a.refresh_after_unix <= now)
            {
                let update = async {
                    let _ari_ca=tokio::select!{biased;_=cancel.cancelled()=>return Err(anyhow!("ACME operation cancelled")),permit=issuer.ca.limiter.acquire()=>permit.map_err(|_|anyhow!("ACME issuer closed"))?};
                    let wire = issuer
                        .wire
                        .get_or_try_init(|| AcmeWire::connect(issuer.config.wire.clone(), cancel))
                        .await?;
                    if let Some(cert_id) = ari_certificate_id(&bundle.chain_pem)? {
                        return wire.renewal_info(&cert_id, cancel).await;
                    }
                    Ok(None)
                }
                .await;
                match update {
                    Ok(Some(updated)) => {
                        // Caddy may have persisted an equivalent SAN set in a
                        // different order. Native leases use normalized first SAN.
                        bundle.metadata["sans"] = json!(names);
                        write_ari(
                            &mut bundle.metadata,
                            &updated,
                            &info,
                            self.inner.options.renewal_window_ratio,
                        )?;
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
                    Err(error) => record_issuer_error(issuer, &error),
                    Ok(None) => {}
                }
            }
            previous_id = Some(Replacement {
                certificate_id: ari_certificate_id(&bundle.chain_pem)?,
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
                && now < renew_at
                && info.not_after > now
                && self.material_revocation(&info)?.is_none()
            {
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
                ));
            }
        }
        Ok((None, previous_id))
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
                            Arc::new(AccountSigner::from_pem(&account.private_key_pem)?),
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
        let result=async {
            self.inner.store.recover_account_with_lease(&issuer_name,&email,&lease).await?;
            if let Some(value)=self.inner.store.journal_load(&pending_id).await?&&value["phase"]=="account_received"{
                let pending:PendingAccount=serde_json::from_value(value).map_err(|_|anyhow!("invalid account publication checkpoint"))?;
                return Ok((None,Some(pending)));
            }
            let existing=self.inner.store.load_account(&issuer_name,&email).await?;
            if let Some(account)=existing {
                ensure!(account_lock_name(&account.metadata)?==registration,"account contact changed while acquiring registration lock");
                let signer=Arc::new(AccountSigner::from_pem(&account.private_key_pem)?);
                if let Some(location)=account.metadata["location"].as_str().filter(|v|!v.is_empty()){
                    ensure!(account.metadata["status"]=="valid"&&expected_location.is_none_or(|v|v==location),"stored ACME account identity changed");
                    return Ok::<_,anyhow::Error>((Some(wire.restore(signer,location)?),None));
                }
                let(session,response)=wire.account(signer,&email,issuer.config.terms_of_service_agreed,true,None,&lease.lost()).await?;
                ensure!(expected_location.is_none_or(|v|v==session.location()),"recovered account identity changed");
                let mut metadata=account.metadata.clone();merge_account(&mut metadata,&response.metadata)?;
                let pending=PendingAccount{version:1,directory:wire.directory_url().to_owned(),phase:"account_received".to_owned(),private_key_pem:std::str::from_utf8(&account.private_key_pem)?.to_owned(),eab:None,storage_email:Some(account_primary(&metadata)?.to_owned()),metadata:Some(metadata)};
                self.store_checkpoint(&pending_id,serde_json::to_value(&pending)?,&lease).await?;
                return Ok((None,Some(pending)));
            }
            let old=self.inner.store.journal_load(&pending_id).await?;
            // A different publisher may have completed an alias after our
            // optimistic read but before we acquired this registration lease.
            if old.as_ref().is_some_and(|v|v["phase"]=="stored"&&v["storage_email"].is_string()){
                return Err(anyhow::Error::new(RetryAccountAlias));
            }
            ensure!(expected_location.is_none(),"active order account material missing; restore it instead of registering another account");
            let mut pending=if let Some(value)=old.filter(|v|v["phase"]!="stored") {
                let pending:PendingAccount=serde_json::from_value(value).map_err(|_|anyhow!("invalid account checkpoint"))?;
                ensure!(pending.version==1&&pending.directory==wire.directory_url(),"account checkpoint identity changed");pending
            }else{
                let kind=issuer.config.account_key_type;
                let(_,key)=tokio::task::spawn_blocking(move||AccountSigner::generate(kind)).await.map_err(|_|anyhow!("account key generation failed"))??;
                let pending=PendingAccount{version:1,directory:wire.directory_url().to_owned(),phase:"key_prepared".to_owned(),private_key_pem:std::str::from_utf8(&key)?.to_owned(),eab:None,storage_email:None,metadata:Some(if email.is_empty(){json!({"contact":[]})}else{json!({"contact":[format!("mailto:{email}")]})})};
                self.store_checkpoint(&pending_id,serde_json::to_value(&pending)?,&lease).await?;pending
            };
            if pending.phase=="account_received"{return Ok((None,Some(pending)))}
            let signer=Arc::new(AccountSigner::from_pem(pending.private_key_pem.as_bytes())?);
            let recovered=if pending.phase!="key_prepared" {
                match wire.account(signer.clone(),&email,issuer.config.terms_of_service_agreed,true,None,&lease.lost()).await {
                    Ok(result)=>Some(result),
                    Err(error)=>{if !error.downcast_ref::<ProtocolError>().is_some_and(|p|p.status()==400&&p.kind()=="accountDoesNotExist"){return Err(error.context("account registration remains uncertain"))}None}
                }
            }else{None};
            let(_,response)=if let Some(result)=recovered {result}else{
                if issuer.config.eab.is_none()&&pending.eab.is_none()&&wire.directory_url().starts_with("https://acme.zerossl.com/"){
                    let(kid,hmac_key)=wire.zero_ssl_eab(&email,&lease.lost()).await?;pending.eab=Some(ExternalAccountBinding{kid,hmac_key});
                    self.store_checkpoint(&pending_id,serde_json::to_value(&pending)?,&lease).await?;
                }
                pending.phase="registration_intent".to_owned();self.store_checkpoint(&pending_id,serde_json::to_value(&pending)?,&lease).await?;
                wire.account(signer,&email,issuer.config.terms_of_service_agreed,false,issuer.config.eab.as_ref().or(pending.eab.as_ref()).map(|e|(e.kid.as_str(),e.hmac_key.as_str())),&lease.lost()).await?
            };
            let mut metadata=pending.metadata.take().unwrap_or_else(||if email.is_empty(){json!({"contact":[]})}else{json!({"contact":[format!("mailto:{email}")]})});
            merge_account(&mut metadata,&response.metadata)?;
            pending.phase="account_received".to_owned();pending.storage_email=Some(account_primary(&metadata)?.to_owned());pending.metadata=Some(metadata);
            self.store_checkpoint(&pending_id,serde_json::to_value(&pending)?,&lease).await?;Ok((None,Some(pending)))
        }.await;
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
        let signer = Arc::new(AccountSigner::from_pem(pending.private_key_pem.as_bytes())?);
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
                    AccountSigner::from_pem(&existing.private_key_pem)?.public_spki()?
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

    async fn issue(
        &self,
        names: &[String],
        issuer: &IssuerState,
        account: &AccountSession,
        lease: &StorageLease,
        cycle: (Option<&Replacement>, Option<&Reservation>, &str),
        cancel: &CancellationToken,
    ) -> Result<ManagedCertificate> {
        let (replacement, reservation, attempt_id) = cycle;
        let wire = issuer
            .wire
            .get_or_try_init(|| AcmeWire::connect(issuer.config.wire.clone(), cancel))
            .await?;
        let issuer_name = issuer_key(wire.directory_url())?;
        let replaces = replacement
            .filter(|r| {
                r.directory == wire.directory_url()
                    && r.account == account.location()
                    && wire.directory().renewal_info.is_some()
            })
            .and_then(|r| r.certificate_id.as_deref());
        let computed_id = digest(
            format!(
                "order\0{}\0{}\0{:?}\0{}\0{}",
                wire.directory_url(),
                account.location(),
                issuer.config.leaf_key_type,
                names.join("\0"),
                replacement
                    .map(|r| r.previous_leaf.as_str())
                    .unwrap_or("initial")
            )
            .as_bytes(),
        );
        let id = reservation.map(|r| r.job_id.clone()).unwrap_or(computed_id);
        let mut job = if let Some(value) = self.inner.store.journal_load(&id).await? {
            let job: Job = serde_json::from_value(value)
                .map_err(|_| anyhow!("invalid ACME order checkpoint"))?;
            ensure!(
                job.version == 1
                    && job.directory == wire.directory_url()
                    && job.account_location == account.location()
                    && job.names == names
                    && job.config_email == issuer.config.email
                    && job.leaf_key_type == issuer.config.leaf_key_type,
                "ACME order checkpoint identity changed"
            );
            job
        } else {
            let csr_names = names.to_vec();
            let kind = issuer.config.leaf_key_type;
            let (csr, key) = tokio::task::spawn_blocking(move || generate_csr(&csr_names, kind))
                .await
                .map_err(|_| anyhow!("certificate key generation failed"))??;
            let job = Job {
                version: 1,
                names: names.to_vec(),
                directory: wire.directory_url().to_owned(),
                account_location: account.location().to_owned(),
                config_email: issuer.config.email.clone(),
                leaf_key_type: issuer.config.leaf_key_type,
                attempt_id: attempt_id.to_owned(),
                abandoned: false,
                phase: "prepared".to_owned(),
                csr_der: csr,
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
        self.activate_leg(names, attempt_id, &id, lease).await?;
        job.attempt_id = attempt_id.to_owned();
        job.abandoned = false;
        self.save_job(&id, &job, lease).await?;
        if job.phase == "stored" {
            let current = self
                .inner
                .store
                .load_certificate(&issuer_name, &names_key(names)?)
                .await?;
            if let Some(bundle) = current {
                let info = material_info(&bundle, names)?;
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
            let csr_names = names.to_vec();
            let kind = issuer.config.leaf_key_type;
            let (csr, key) = tokio::task::spawn_blocking(move || generate_csr(&csr_names, kind))
                .await
                .map_err(|_| anyhow!("certificate key generation failed"))??;
            job.csr_der = csr;
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
        if job.poll_after_unix > now() {
            let error = anyhow::Error::new(RetryAfterError(job.poll_after_unix));
            return Err(if job.order_url.is_some() {
                ActiveOrderError(error).into()
            } else {
                error
            });
        }
        if job.order_url.is_none() && job.phase == "new_order_intent" {
            let identifiers = names
                .iter()
                .map(|name| Identifier {
                    kind: "dns".to_owned(),
                    value: name.clone(),
                })
                .collect::<Vec<_>>();
            match account.reconcile_order(&identifiers, cancel).await {
                Ok(Some(url)) => {
                    job.order_url = Some(url);
                    job.phase = "order_recovered".to_owned();
                    self.save_job(&id, &job, lease).await?;
                }
                _ => return Err(AmbiguousOrder.into()),
            }
        }
        if job.order_url.is_none() {
            job.phase = "new_order_intent".to_owned();
            self.save_job(&id, &job, lease).await?;
            let identifiers = names
                .iter()
                .map(|name| Identifier {
                    kind: "dns".to_owned(),
                    value: name.clone(),
                })
                .collect::<Vec<_>>();
            let result = account
                .new_order(
                    &identifiers,
                    if job.replaces_disabled {
                        None
                    } else {
                        replaces
                    },
                    &lease.lost(),
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
                            match account.new_order(&identifiers, None, &lease.lost()).await {
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
            validate_order(&resource.value,names)?;
            if resource.value.status=="pending" {
                ensure!(resource.value.authorizations.len()<=100,"ACME authorization count exceeds bounds");
                for authorization_url in &resource.value.authorizations {
                    let authorization=account.authorization(authorization_url,cancel).await?.value;
                    ensure!(!authorization.wildcard && authorization.identifier.kind=="dns" && names.contains(&authorization.identifier.value.to_ascii_lowercase()),"ACME authorization identifier changed");
                    if authorization.status=="valid" {continue}
                    ensure!(authorization.status=="pending","ACME authorization is not pending or valid");
                    let challenge=issuer.config.challenge_types.iter().find_map(|kind|authorization.challenges.iter().find(|c|c.kind==kind.as_str() && ["pending","processing"].contains(&c.status.as_str())).map(|c|(*kind,c))).ok_or_else(||anyhow!("requested ACME challenge unavailable"))?;
                    let token=challenge.1.token.as_deref().ok_or_else(||anyhow!("ACME challenge token missing"))?;
                    let authorization_value=format!("{token}.{}",account.thumbprint());
                    let ttl=self.inner.options.job_timeout.min(Duration::from_secs(3600));
                    let proof=match challenge.0 {
                        ChallengeType::Http01=>self.inner.registry.register_http(&id,&authorization.identifier.value,token,&authorization_value,ttl)?,
                        ChallengeType::TlsAlpn01=>self.inner.registry.register_tls(&id,&authorization.identifier.value,&authorization_value,ttl)?,
                    };proofs.push(proof);
                    job.phase="authorizing".to_owned();self.save_job(&id,&job,lease).await?;
                    lease.check().await?;let response=account.respond(&challenge.1.url,&lease.lost()).await?;resource.retry_after=resource.retry_after.max(response.retry_after);
                }
                for _ in 0..240 {
                    if resource.value.status!="pending" {break}
                    self.wait_poll(&id,&mut job,lease,resource.retry_after,cancel).await?;
                    resource=account.order(&url,cancel).await?;validate_order(&resource.value,names)?;lease.check().await?;
                }
            }
            if resource.value.status=="ready" {
                job.phase="finalize_intent".to_owned();self.save_job(&id,&job,lease).await?;
                resource=account.finalize(&resource.value.finalize,&job.csr_der,&lease.lost()).await?;
                job.phase="finalized".to_owned();self.save_job(&id,&job,lease).await?;
            }
            for _ in 0..240 {
                if resource.value.status=="valid" {break}
                ensure!(resource.value.status=="processing" || resource.value.status=="ready","ACME order failed to finalize");
                self.wait_poll(&id,&mut job,lease,resource.retry_after,cancel).await?;
                resource=account.order(&url,cancel).await?;validate_order(&resource.value,names)?;lease.check().await?;
            }
            ensure!(resource.value.status=="valid","ACME certificate polling deadline exceeded");
            job.certificate_url=resource.value.certificate;
            if job.downloaded_pem.is_none() {
                let certificate=account.download(job.certificate_url.as_deref().ok_or_else(||anyhow!("valid ACME order has no certificate URL"))?,cancel).await?;
                job.downloaded_pem=Some(String::from_utf8(certificate).map_err(|_|anyhow!("ACME certificate response is not PEM"))?);
                job.phase="downloaded".to_owned();self.save_job(&id,&job,lease).await?;
            }
            let mut bundle=CertificateBundle {chain_pem:job.downloaded_pem.as_ref().ok_or_else(||anyhow!("ACME certificate missing"))?.as_bytes().to_vec(),private_key_pem:Zeroizing::new(job.private_key_pem.as_bytes().to_vec()),metadata:json!({"sans":names,"issuer_data":{"url":job.certificate_url,"ca":wire.directory_url(),"account":account.location()}})};
            let info=material_info(&bundle,names)?;
            ensure!(info.not_before<=now() && info.not_after>now(),"issued certificate is not currently valid");
            if let Some(cert_id)=ari_certificate_id(&bundle.chain_pem)? && let Ok(Some(ari))=wire.renewal_info(&cert_id,cancel).await {write_ari(&mut bundle.metadata,&ari,&info,self.inner.options.renewal_window_ratio)?;}
            job.stored_leaf_sha256=Some(info.leaf_sha256.clone());job.phase="store_intent".to_owned();self.save_job(&id,&job,lease).await?;
            lease.check().await?;self.inner.store.save_certificate(&issuer_name,&names_key(names)?,&bundle,lease).await?;
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
        for attempt in 0..8 {
            match self.inner.resolver.upsert(&CertificateInput {
                names,
                certificate_pem: &bundle.chain_pem,
                private_key_pem: &bundle.private_key_pem,
            }) {
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
struct RetryAfterError(i64);
impl std::fmt::Display for RetryAfterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ACME server requested retry backoff")
    }
}
impl std::error::Error for RetryAfterError {}
fn error_retry_delay(error: &anyhow::Error) -> Duration {
    if let Some(error) = error.downcast_ref::<ActiveOrderError>() {
        return error_retry_delay(&error.0);
    }
    if let Some(error) = error.downcast_ref::<RetryAfterError>() {
        return Duration::from_secs((error.0 - now()).max(1) as u64);
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
    ensure!(actual == names, "ACME order identifiers changed");
    Ok(())
}
/// rcgen's built-in ring key importer caps RSA key sizes. Keep the caller's
/// actual key and use RustCrypto directly, including rsa8192, for PKCS10 signing.
pub(crate) struct CsrSigner {
    signer: AccountSigner,
    public: Vec<u8>,
}
impl CsrSigner {
    pub(crate) fn new(signer: AccountSigner) -> Result<Self> {
        use p256::pkcs8::der::Decode;
        let spki = signer.public_spki()?;
        let info = p256::pkcs8::spki::SubjectPublicKeyInfoRef::from_der(&spki)
            .map_err(|_| anyhow!("invalid CSR public key"))?;
        let public = info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| anyhow!("invalid CSR key bits"))?
            .to_vec();
        Ok(Self { signer, public })
    }
}
impl rcgen::PublicKeyData for CsrSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.signer {
            AccountSigner::P256(_) => &rcgen::PKCS_ECDSA_P256_SHA256,
            AccountSigner::P384(_) => &rcgen::PKCS_ECDSA_P384_SHA384,
            AccountSigner::Rsa(_) => &rcgen::PKCS_RSA_SHA256,
            AccountSigner::Ed25519(_) => &rcgen::PKCS_ED25519,
        }
    }
}
impl rcgen::SigningKey for CsrSigner {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let raw = self
            .signer
            .sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        // JOSE uses fixed-width r||s; X.509/PKCS10 requires an ASN.1 sequence.
        match self.signer {
            AccountSigner::P256(_) => Ok(p256::ecdsa::Signature::from_slice(&raw)
                .map_err(|_| rcgen::Error::RemoteKeyError)?
                .to_der()
                .as_bytes()
                .to_vec()),
            AccountSigner::P384(_) => Ok(p384::ecdsa::Signature::from_slice(&raw)
                .map_err(|_| rcgen::Error::RemoteKeyError)?
                .to_der()
                .as_bytes()
                .to_vec()),
            _ => Ok(raw),
        }
    }
}
fn generate_csr(names: &[String], kind: KeyType) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let (signer, pem) = AccountSigner::generate(kind)?;
    let pair = CsrSigner::new(signer)?;
    let mut params = rcgen::CertificateParams::new(names.to_vec())
        .map_err(|_| anyhow!("invalid certificate CSR names"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    Ok((
        params
            .serialize_request(&pair)
            .map_err(|_| anyhow!("certificate CSR signing failed"))?
            .der()
            .to_vec(),
        pem,
    ))
}
fn material_info(bundle: &CertificateBundle, names: &[String]) -> Result<MaterialInfo> {
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
    Ok(MaterialInfo {
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        leaf_id: crate::leaf_guard::leaf_id(&blocks[0].1),
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
fn retry_backoff(failures: u32, names: &[String]) -> Duration {
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
