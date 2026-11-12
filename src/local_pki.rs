//! Standard local CA and internal issuer. The caller owns policy authorization,
//! TLS publication and application transactions; no trust store is changed by
//! provisioning or issuing. Only an explicitly supplied installer can do so.
#[path = "local_pki/journal.rs"]
mod journal;
#[path = "local_pki/material.rs"]
mod material;
#[path = "local_pki/raw_der.rs"]
mod raw_der;
#[path = "local_pki/signer.rs"]
mod signer;
#[path = "local_pki/trust_command.rs"]
mod trust_command;
#[path = "local_pki/trust_install.rs"]
mod trust_install;
pub use trust_install::SystemTrustInstaller;

use anyhow::{Result, anyhow, ensure};
use futures_util::{StreamExt, stream::FuturesUnordered};
use material::Pair;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore, broadcast};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct KeyPairFiles {
    pub certificate: PathBuf,
    pub private_key: Option<PathBuf>,
    /// Only the original empty/default or `pem_file` formats are accepted.
    pub format: String,
}
#[derive(Clone)]
pub struct CaConfig {
    pub id: String,
    pub name: String,
    pub root_common_name: String,
    pub intermediate_common_name: String,
    pub intermediate_lifetime: Duration,
    pub maintenance_interval: Duration,
    pub renewal_window_ratio: f64,
    pub install_trust: bool,
    pub root: Option<KeyPairFiles>,
    pub intermediate: Option<KeyPairFiles>,
}
impl Default for CaConfig {
    fn default() -> Self {
        Self {
            id: "local".into(),
            name: "Caddy Local Authority".into(),
            root_common_name: "{pki.ca.name} - {time.now.year} ECC Root".into(),
            intermediate_common_name: "{pki.ca.name} - ECC Intermediate".into(),
            intermediate_lifetime: Duration::from_secs(7 * 86400),
            maintenance_interval: Duration::from_secs(600),
            renewal_window_ratio: 0.2,
            install_trust: true,
            root: None,
            intermediate: None,
        }
    }
}
impl CaConfig {
    fn normalized(mut self) -> Result<Self> {
        ensure!(
            !self.id.is_empty() && self.id.len() <= 240,
            "invalid local CA ID"
        );
        if self.name.is_empty() {
            self.name = "Caddy Local Authority".into();
        }
        if self.root_common_name.is_empty() {
            self.root_common_name = Self::default().root_common_name;
        }
        if self.intermediate_common_name.is_empty() {
            self.intermediate_common_name = Self::default().intermediate_common_name;
        }
        if self.intermediate_lifetime.is_zero() {
            self.intermediate_lifetime = Duration::from_secs(7 * 86400);
        }
        if self.maintenance_interval.is_zero() {
            self.maintenance_interval = Duration::from_secs(600);
        }
        ensure!(
            self.maintenance_interval >= Duration::from_secs(1)
                && self.maintenance_interval <= Duration::from_secs(86400),
            "invalid local CA maintenance interval"
        );
        ensure!(
            self.renewal_window_ratio.is_finite(),
            "invalid CA renewal ratio"
        );
        if self.renewal_window_ratio <= 0.0 || self.renewal_window_ratio > 1.0 {
            self.renewal_window_ratio = 0.2;
        }
        for pair in [&self.root, &self.intermediate].into_iter().flatten() {
            ensure!(
                matches!(pair.format.as_str(), "" | "pem_file"),
                "unsupported local CA keypair format"
            );
        }
        Ok(self)
    }
}

#[derive(Clone)]
pub struct CaSnapshot {
    pub id: String,
    pub generation: u64,
    pub root_certificate_pem: Vec<u8>,
    pub intermediate_chain_pem: Vec<u8>,
    pub root_not_after: i64,
    pub intermediate_not_after: i64,
}
#[derive(Clone, Debug)]
pub struct PkiEvent {
    pub ca_id: String,
    pub kind: &'static str,
    pub error: Option<String>,
}
#[derive(Clone)]
pub struct InternalIssuerOptions {
    pub lifetime: Duration,
    pub sign_with_root: bool,
}
impl Default for InternalIssuerOptions {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(12 * 3600),
            sign_with_root: false,
        }
    }
}
/// The adapter must actually install/check system, Firefox and Java trust as
/// requested by the original PKI app. Missing adapters produce a nonfatal
/// `pki_trust_install_unavailable` event, never a fictitious installation success.
/// Cancellation is cooperative: implementations must cancel and join their
/// subprocesses before returning. Dropping this future is not a cleanup API.
pub trait TrustInstaller: Send + Sync {
    fn install<'a>(
        &'a self,
        root_pem: &'a [u8],
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

struct State {
    root: Pair,
    intermediate: Pair,
    generation: u64,
    root_validity: (i64, i64),
    inter_validity: (i64, i64),
}
struct Shared {
    cpu: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    clock: Arc<dyn Fn() -> Result<i64> + Send + Sync>,
    events: broadcast::Sender<PkiEvent>,
    changed: Notify,
    tasks: TaskTracker,
    closed: CancellationToken,
    running: AtomicBool,
    admission: Mutex<()>,
}
struct Authority {
    config: CaConfig,
    prefix: String,
    lock_name: String,
    store: crate::certstore::FsStore,
    shared: Arc<Shared>,
    gate: AsyncMutex<()>,
    state: RwLock<Option<Arc<State>>>,
}
#[derive(Clone)]
pub struct LocalPki {
    store: crate::certstore::FsStore,
    shared: Arc<Shared>,
    authorities: Arc<Mutex<HashMap<String, Arc<Authority>>>>,
}
/// CPU work and queued-operation admission shared across independent CAs and
/// configuration generations. Cancellation, trust and task ownership remain
/// local to each LocalPki instance.
pub struct LocalPkiResources {
    cpu: Arc<Semaphore>,
    pending: Arc<Semaphore>,
}
impl LocalPkiResources {
    pub fn new(max_parallel: usize) -> Result<Self> {
        ensure!((1..=128).contains(&max_parallel), "invalid PKI resource limits");
        Ok(Self { cpu: Arc::new(Semaphore::new(max_parallel)), pending: Arc::new(Semaphore::new(4096)) })
    }
}
impl LocalPki {
    pub fn with_resources(store: crate::certstore::FsStore, configs: Vec<CaConfig>, resources: Arc<LocalPkiResources>) -> Result<Self> {
        Self::build(store, configs, resources, Arc::new(|| Ok(i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?)))
    }
    pub fn new(
        store: crate::certstore::FsStore,
        configs: Vec<CaConfig>,
        max_parallel: usize,
    ) -> Result<Self> {
        Self::with_clock(
            store,
            configs,
            max_parallel,
            Arc::new(|| {
                Ok(i64::try_from(
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                )?)
            }),
        )
    }
    /// The runtime must supply a trusted wall clock. This is dependency
    /// injection, not a user-configurable way to weaken certificate validity.
    pub fn with_clock(
        store: crate::certstore::FsStore,
        configs: Vec<CaConfig>,
        max_parallel: usize,
        clock: Arc<dyn Fn() -> Result<i64> + Send + Sync>,
    ) -> Result<Self> {
        Self::build(store, configs, Arc::new(LocalPkiResources::new(max_parallel)?), clock)
    }
    fn build(
        store: crate::certstore::FsStore,
        mut configs: Vec<CaConfig>,
        resources: Arc<LocalPkiResources>,
        clock: Arc<dyn Fn() -> Result<i64> + Send + Sync>,
    ) -> Result<Self> {
        ensure!(
            configs.len() <= 256,
            "invalid PKI resource limits"
        );
        if configs.is_empty() {
            configs.push(CaConfig::default());
        }
        let (events, _) = broadcast::channel(256);
        let this = Self {
            store,
            shared: Arc::new(Shared {
                cpu: resources.cpu.clone(),
                pending: resources.pending.clone(),
                clock,
                events,
                changed: Notify::new(),
                tasks: TaskTracker::new(),
                closed: CancellationToken::new(),
                running: AtomicBool::new(false),
                admission: Mutex::new(()),
            }),
            authorities: Arc::new(Mutex::new(HashMap::new())),
        };
        for config in configs {
            this.add(config)?;
        }
        Ok(this)
    }
    fn add(&self, config: CaConfig) -> Result<()> {
        let config = config.normalized()?;
        let prefix = format!("pki/authorities/{}", crate::certstore::safe(&config.id));
        let mut authorities = self
            .authorities
            .lock()
            .map_err(|_| anyhow!("PKI authority state unavailable"))?;
        ensure!(
            authorities.len() < 256
                && !authorities.contains_key(&config.id)
                && !authorities.values().any(|a| a.prefix == prefix),
            "duplicate or colliding CA ID"
        );
        let authority = Arc::new(Authority {
            lock_name: format!("local_pki_{}", journal::hash(prefix.as_bytes())),
            prefix,
            config: config.clone(),
            store: self.store.clone(),
            shared: self.shared.clone(),
            gate: AsyncMutex::new(()),
            state: RwLock::new(None),
        });
        authorities.insert(config.id, authority);
        self.shared.changed.notify_one();
        Ok(())
    }
    fn authority(&self, id: &str) -> Result<Arc<Authority>> {
        let id = if id.is_empty() { "local" } else { id };
        if let Some(authority) = self
            .authorities
            .lock()
            .map_err(|_| anyhow!("PKI authority state unavailable"))?
            .get(id)
            .cloned()
        {
            return Ok(authority);
        }
        if id == "local" {
            // Another caller may lazily provision the default concurrently.
            if self.add(CaConfig::default()).is_err() {
                return self
                    .authorities
                    .lock()
                    .map_err(|_| anyhow!("PKI authority state unavailable"))?
                    .get(id)
                    .cloned()
                    .ok_or_else(|| anyhow!("default CA unavailable"));
            }
            return self
                .authorities
                .lock()
                .map_err(|_| anyhow!("PKI authority state unavailable"))?
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow!("default CA unavailable"));
        }
        Err(anyhow!("unknown local CA"))
    }
    pub fn subscribe(&self) -> broadcast::Receiver<PkiEvent> {
        self.shared.events.subscribe()
    }
    pub fn snapshot(&self, id: &str) -> Result<Option<CaSnapshot>> {
        let id = if id.is_empty() { "local" } else { id };
        self.authorities
            .lock()
            .map_err(|_| anyhow!("PKI authority state unavailable"))?
            .get(id)
            .map(|authority| authority.snapshot())
            .transpose()
            .map(Option::flatten)
    }
    /// Names from the same provisioned authority, evaluated with its own clock.
    /// This copies no private state and performs no filesystem or network I/O.
    pub(crate) fn public_names(&self,id:&str)->Result<(String,String,String)> {
        let authority=self.authority(id)?;
        let now=(self.shared.clock)()?;
        Ok((authority.config.name.clone(),
            authority.common_name(&authority.config.root_common_name,now)?,
            authority.common_name(&authority.config.intermediate_common_name,now)?))
    }
    async fn accepted<T: Send + 'static>(
        &self,
        waiting: CancellationToken,
        operation: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T> {
        let task = {
            let _admission = self
                .shared
                .admission
                .lock()
                .map_err(|_| anyhow!("PKI admission unavailable"))?;
            ensure!(
                !self.shared.closed.is_cancelled() && !waiting.is_cancelled(),
                "PKI stopped or caller already cancelled"
            );
            let pending = self
                .shared
                .pending
                .clone()
                .try_acquire_owned()
                .map_err(|_| anyhow!("PKI work queue full"))?;
            self.shared.tasks.spawn(async move {
                let _pending = pending;
                operation.await
            })
        };
        tokio::select! { _ = waiting.cancelled() => Err(anyhow!("PKI caller stopped waiting; accepted work remains supervised")),
        result = task => result.map_err(|_|anyhow!("PKI accepted worker failed"))? }
    }
    /// A caller disconnect only abandons its wait. Accepted pair writes retain
    /// ownership in the manager tracker until completion or manager shutdown.
    pub async fn provision(&self, id: &str, cancel: CancellationToken) -> Result<CaSnapshot> {
        ensure!(!self.shared.closed.is_cancelled(), "PKI is stopped");
        let authority = self.authority(id)?;
        let owner = self.shared.closed.child_token();
        self.accepted(cancel, async move {
            authority.ensure_usable(owner).await?;
            authority
                .snapshot()?
                .ok_or_else(|| anyhow!("CA not provisioned"))
        })
        .await
    }
    /// CSR names must already be authorized by the caller's automation policy.
    pub async fn issue(
        &self,
        id: &str,
        csr_der: Vec<u8>,
        mut options: InternalIssuerOptions,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>> {
        ensure!(!self.shared.closed.is_cancelled(), "PKI is stopped");
        ensure!(csr_der.len() <= 128 * 1024, "CSR size limit exceeded");
        if options.lifetime.is_zero() {
            options.lifetime = InternalIssuerOptions::default().lifetime;
        }
        let authority = self.authority(id)?;
        let owner = self.shared.closed.child_token();
        let shared = self.shared.clone();
        self.accepted(cancel, async move {
            let state = authority.ensure_usable(owner.clone()).await?;
            let signing = if options.sign_with_root {
                let root = authority.root_key(owner.clone()).await?;
                ensure!(
                    material::chain(&root.chain_pem)?[0]
                        == material::chain(&state.root.chain_pem)?[0],
                    "root changed since issuance snapshot"
                );
                root
            } else {
                state.intermediate.clone()
            };
            let now = (shared.clock)()?;
            let include_signer = !options.sign_with_root;
            let issued = work(shared.cpu.clone(), owner.clone(), move || {
                material::issue(&csr_der, &signing, now, options.lifetime, include_signer)
            })
            .await?;
            ensure!(!owner.is_cancelled(), "PKI issuer stopped");
            Ok(issued)
        })
        .await
    }
    pub async fn shutdown(&self) -> Result<()> {
        {
            let _guard = self
                .shared
                .admission
                .lock()
                .map_err(|_| anyhow!("PKI admission unavailable"))?;
            self.shared.closed.cancel();
            self.shared.tasks.close();
        }
        tokio::time::timeout(Duration::from_secs(45), self.shared.tasks.wait())
            .await
            .map_err(|_| {
                anyhow!("PKI shutdown deadline exceeded; owned tasks remain supervised")
            })?;
        Ok(())
    }
    /// Maintenance, trust installation and independent CAs have separate tasks.
    /// Installers must own their resources and honor cancellation; they must not
    /// detach subprocesses which outlive their returned future.
    pub async fn run(
        &self,
        cancel: CancellationToken,
        installer: Option<Arc<dyn TrustInstaller>>,
    ) -> Result<()> {
        ensure!(!self.shared.closed.is_cancelled(), "PKI is stopped");
        ensure!(
            self.shared
                .running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "PKI maintenance already running"
        );
        let _stop_on_drop = RunGuard(self.shared.clone());
        let mut jobs = FuturesUnordered::new();
        let mut started = HashSet::new();
        let mut failure = None;
        let run_result:Result<()> = async { loop {
            let inventory = self
                .authorities
                .lock()
                .map_err(|_| anyhow!("PKI authority state unavailable"))?
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for authority in inventory {
                if !started.insert(authority.config.id.clone()) {
                    continue;
                }
                let owner = self.shared.closed.child_token();
                let installer = installer.clone();
                let _admission=self.shared.admission.lock().map_err(|_|anyhow!("PKI admission unavailable"))?;
                if !self.shared.closed.is_cancelled() {jobs.push(self.shared.tasks.spawn(async move { authority.maintain(owner, installer).await }));}
            }
            tokio::select! {
                _ = cancel.cancelled()=>break,
                _ = self.shared.closed.cancelled()=>break,
                _ = self.shared.changed.notified()=>{},
                result=jobs.next(),if !jobs.is_empty()=>{
                    match result {
                        Some(Ok(Ok(())))=>{},Some(Ok(Err(error)))=>failure=Some(error),
                        Some(Err(error))=>failure=Some(anyhow!("PKI authority worker failed: {error}")),None=>{}
                    }
                }
            }
        } Ok(()) }.await;
        if let Err(error) = run_result {
            failure = Some(error);
        }
        self.shutdown().await?;
        while let Some(result) = jobs.next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failure = Some(error),
                Err(error) => failure = Some(anyhow!("PKI worker failed: {error}")),
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

struct RunGuard(Arc<Shared>);
impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.closed.cancel();
        let _admission = self
            .0
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.0.tasks.close();
    }
}

async fn work<T: Send + 'static>(
    pool: Arc<Semaphore>,
    cancel: CancellationToken,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = tokio::select! { _ = cancel.cancelled() => return Err(anyhow!("PKI operation cancelled")),
    permit = pool.acquire_owned() => permit.map_err(|_|anyhow!("PKI crypto pool closed"))? };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await?
}

impl Authority {
    fn emit(&self, kind: &'static str, error: Option<&anyhow::Error>) {
        let _ = self.shared.events.send(PkiEvent {
            ca_id: self.config.id.clone(),
            kind,
            error: error.map(|error| error.to_string().chars().take(512).collect()),
        });
    }
    fn snapshot(&self) -> Result<Option<CaSnapshot>> {
        let current = self
            .state
            .read()
            .map_err(|_| anyhow!("CA state unavailable"))?
            .clone();
        current
            .map(|state| {
                Ok(CaSnapshot {
                    id: self.config.id.clone(),
                    generation: state.generation,
                    root_certificate_pem: state.root.chain_pem.clone(),
                    intermediate_chain_pem: state.intermediate.chain_pem.clone(),
                    root_not_after: state.root_validity.1,
                    intermediate_not_after: state.inter_validity.1,
                })
            })
            .transpose()
    }
    fn common_name(&self, template: &str, now: i64) -> Result<String> {
        let year = time::OffsetDateTime::from_unix_timestamp(now)?.year();
        let name = template
            .replace("{pki.ca.name}", &self.config.name)
            .replace("{time.now.year}", &year.to_string());
        ensure!(
            !name.contains('{') && !name.contains('}'),
            "unsupported CA name placeholder"
        );
        Ok(name)
    }
    async fn files(&self, files: KeyPairFiles, cancel: CancellationToken) -> Result<Pair> {
        work(self.shared.cpu.clone(), cancel, move || {
            fn read(path: PathBuf, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
                use std::io::Read;
                use std::os::unix::fs::OpenOptionsExt;
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
                    .open(path)?;
                ensure!(
                    file.metadata()?.is_file() && file.metadata()?.len() <= limit,
                    "invalid CA material file"
                );
                let mut value = Zeroizing::new(Vec::new());
                file.take(limit + 1).read_to_end(&mut value)?;
                ensure!(value.len() as u64 <= limit, "CA material size exceeded");
                Ok(value)
            }
            Ok(Pair {
                explicit_anchor: false,
                chain_pem: read(files.certificate, 1024 * 1024)?.to_vec(),
                private_key_pem: files
                    .private_key
                    .map(|path| read(path, 128 * 1024))
                    .transpose()?,
            })
        })
        .await
    }
    async fn root_key(&self, cancel: CancellationToken) -> Result<Pair> {
        let lease = self.store.lock(&self.lock_name, cancel.clone()).await?;
        let result = async {
            let now = (self.shared.clock)()?;
            let root = if let Some(files) = &self.config.root {
                let pair = self.files(files.clone(), cancel.clone()).await?;
                work(self.shared.cpu.clone(), cancel.clone(), move || {
                    material::configured_anchor(pair)
                })
                .await?
            } else {
                let pair = journal::PairStore {
                    store: &self.store,
                    prefix: &self.prefix,
                    kind: "root",
                    root: None,
                    now,
                    lease: &lease,
                    cpu: self.shared.cpu.clone(),
                    cancel: cancel.clone(),
                };
                pair.recover().await?;
                pair.load()
                    .await?
                    .ok_or_else(|| anyhow!("CA root missing"))?
            };
            let check = root.clone();
            work(self.shared.cpu.clone(), cancel, move || {
                material::validate(&check, None, now, false)
            })
            .await?;
            ensure!(
                root.private_key_pem.is_some(),
                "root signing key unavailable"
            );
            if let Some(state) = self
                .state
                .read()
                .map_err(|_| anyhow!("CA state unavailable"))?
                .as_ref()
            {
                ensure!(
                    material::chain(&state.root.chain_pem)?[0]
                        == material::chain(&root.chain_pem)?[0],
                    "root identity changed since provisioning; reload required"
                );
            }
            Ok(root)
        }
        .await;
        let released = lease.release().await;
        match result {
            Ok(root) => {
                released?;
                Ok(root)
            }
            Err(error) => {
                let _ = released;
                Err(error)
            }
        }
    }
    fn current(&self) -> Result<Option<Arc<State>>> {
        Ok(self
            .state
            .read()
            .map_err(|_| anyhow!("CA state unavailable"))?
            .clone())
    }
    fn fresh(&self, state: &State, now: i64) -> bool {
        now >= state.root_validity.0
            && now < state.root_validity.1
            && now >= state.inter_validity.0
            && now < state.inter_validity.1
            && (self.config.intermediate.is_some()
                || !due(
                    state.inter_validity.0,
                    state.inter_validity.1,
                    now,
                    self.config.renewal_window_ratio,
                ))
    }
    async fn ensure_usable(&self, cancel: CancellationToken) -> Result<Arc<State>> {
        let now = (self.shared.clock)()?;
        if let Some(state) = self.current()?
            && self.fresh(&state, now)
        {
            return Ok(state);
        }
        let result = self.refresh(false, cancel).await;
        let now = (self.shared.clock)()?;
        if let Some(state) = self.current()?
            && now >= state.root_validity.0
            && now < state.root_validity.1
            && now >= state.inter_validity.0
            && now < state.inter_validity.1
        {
            if let Err(error) = &result {
                self.emit("pki_renewal_failed_using_valid_issuer", Some(error));
            }
            return Ok(state);
        }
        result?;
        Err(anyhow!("CA issuer is not currently valid"))
    }
    async fn maintain(
        &self,
        cancel: CancellationToken,
        installer: Option<Arc<dyn TrustInstaller>>,
    ) -> Result<()> {
        let mut ticker = tokio::time::interval(self.config.maintenance_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut trust_attempted = false;
        let mut trust_task = None;
        loop {
            tokio::select! {_ = cancel.cancelled()=>break,_ = ticker.tick()=>{}}
            let result = self.refresh(true, cancel.clone()).await;
            if let Err(error) = &result
                && !cancel.is_cancelled()
            {
                self.emit("pki_maintenance_failed", Some(error));
            }
            if result.is_ok() && self.config.install_trust && !trust_attempted {
                trust_attempted = true;
                if let Some(installer) = installer.clone() {
                    if let Some(snapshot) = self.snapshot()? {
                        let owner = cancel.child_token();
                        let shared = self.shared.clone();
                        let id = self.config.id.clone();
                        let _admission = self
                            .shared
                            .admission
                            .lock()
                            .map_err(|_| anyhow!("PKI admission unavailable"))?;
                        if self.shared.closed.is_cancelled() {
                            break;
                        }
                        trust_task = Some(self.shared.tasks.spawn(async move {
                            let result = installer
                                .install(&snapshot.root_certificate_pem, owner.clone())
                                .await;
                            let _ = shared.events.send(PkiEvent {
                                ca_id: id,
                                kind: if result.is_ok() {
                                    "pki_trust_installed"
                                } else {
                                    "pki_trust_install_failed"
                                },
                                error: result
                                    .err()
                                    .map(|e| e.to_string().chars().take(512).collect()),
                            });
                        }));
                    }
                } else {
                    self.emit("pki_trust_install_unavailable", None);
                }
            }
        }
        if let Some(task) = trust_task {
            task.await.map_err(|_| anyhow!("PKI trust task failed"))?;
        }
        Ok(())
    }
    async fn refresh(&self, force: bool, cancel: CancellationToken) -> Result<()> {
        let _guard = tokio::select! { _ = cancel.cancelled() => return Err(anyhow!("PKI maintenance cancelled")),
        guard = self.gate.lock() => guard };
        let now = (self.shared.clock)()?;
        if !force
            && let Some(state) = self.current()?
            && self.fresh(&state, now)
        {
            return Ok(());
        }
        let lease = self.store.lock(&self.lock_name, cancel.clone()).await?;
        let mut notes = Vec::new();
        let result = async {
            let now = (self.shared.clock)()?;
            let root_store = journal::PairStore {
                store: &self.store,
                prefix: &self.prefix,
                kind: "root",
                root: None,
                now,
                lease: &lease,
                cpu: self.shared.cpu.clone(),
                cancel: cancel.clone(),
            };
            root_store.recover().await?;
            let root = if let Some(files) = &self.config.root {
                let pair = self.files(files.clone(), cancel.clone()).await?;
                work(self.shared.cpu.clone(), cancel.clone(), move || {
                    material::configured_anchor(pair)
                })
                .await?
            } else {
                match root_store.load().await? {
                    Some(root) => root,
                    None => {
                        // A legacy authority with a missing root is partial
                        // material, not permission to invent a replacement CA.
                        ensure!(self.config.intermediate.is_none(), "manual intermediate requires an existing or explicitly configured root; refusing to create another CA identity");
                        let inter_job = journal::job_name(&self.prefix, "intermediate");
                        let inter_crt_path=format!("{}/intermediate.crt",self.prefix);
                        let inter_key_path=format!("{}/intermediate.key",self.prefix);
                        let(inter_crt,inter_key,inter_checkpoint)=tokio::try_join!(self.store.load(&inter_crt_path),self.store.load(&inter_key_path),self.store.journal_load(&inter_job))?;
                        ensure!(inter_crt.is_none()&&inter_key.is_none()&&inter_checkpoint.is_none(),"local CA root missing while intermediate material exists; restore the authority instead of replacing its identity");
                        let name = self.common_name(&self.config.root_common_name, now)?;
                        let root = work(self.shared.cpu.clone(), cancel.clone(), move || {
                            material::new_root(&name, now)
                        })
                        .await?;
                        root_store.save(&root, None).await?;
                        notes.push("pki_root_created");
                        root
                    }
                }
            };
            let check = root.clone();
            work(self.shared.cpu.clone(), cancel.clone(), move || {
                material::validate(&check, None, now, false)
            })
            .await?;
            let (root_start, root_end) = material::validity(&root)?;
            if self.config.root.is_none()
                && due(root_start, root_end, now, self.config.renewal_window_ratio)
            {
                self.emit("pki_root_renewal_not_implemented", None);
            }
            let inter_store = journal::PairStore {
                store: &self.store,
                prefix: &self.prefix,
                kind: "intermediate",
                root: Some(&root),
                now,
                lease: &lease,
                cpu: self.shared.cpu.clone(),
                cancel: cancel.clone(),
            };
            inter_store.recover().await?;
            let intermediate = if let Some(files) = &self.config.intermediate {
                self.files(files.clone(), cancel.clone()).await?
            } else {
                let old = inter_store.load().await?;
                let renew = old
                    .as_ref()
                    .map(|pair| {
                        material::validity(pair).map(|(start, end)| {
                            due(start, end, now, self.config.renewal_window_ratio)
                        })
                    })
                    .transpose()?
                    .unwrap_or(true);
                if let Some(old) = &old {
                    let check = old.clone();
                    let parent = root.clone();
                    work(self.shared.cpu.clone(), cancel.clone(), move || {
                        material::validate(&check, Some(&parent), now, true)
                    })
                    .await?;
                }
                if renew {
                    let parent = root.clone();
                    let lifetime = self.config.intermediate_lifetime;
                    let name = self.common_name(&self.config.intermediate_common_name, now)?;
                    let new = work(self.shared.cpu.clone(), cancel.clone(), move || {
                        material::new_intermediate(&name, &parent, now, lifetime)
                    })
                    .await?;
                    inter_store
                        .save(
                            &new,
                            old.as_ref().map(|p| journal::hash(&p.chain_pem)).as_deref(),
                        )
                        .await?;
                    notes.push("pki_intermediate_renewed");
                    new
                } else {
                    old.expect("present nonrenewing intermediate")
                }
            };
            let check = intermediate.clone();
            let parent = root.clone();
            work(self.shared.cpu.clone(), cancel.clone(), move || {
                material::validate(&check, Some(&parent), now, false)
            })
            .await?;
            ensure!(
                intermediate.private_key_pem.is_some(),
                "intermediate signing key missing"
            );
            lease.check().await?;
            ensure!(!cancel.is_cancelled(), "PKI maintenance cancelled");
            // Root private keys are not retained in the in-memory signing cache.
            // Original Smallstep issuance does not enforce an anchor's name
            // constraints on the CSR. Caller authorization remains mandatory;
            // clients still enforce the full certificate chain constraints.
            let constrained = material::has_name_constraints(&root)?
                || material::has_name_constraints(&intermediate)?;
            let public_root = Pair {
                explicit_anchor: root.explicit_anchor,
                chain_pem: root.chain_pem,
                private_key_pem: None,
            };
            let mut state = self
                .state
                .write()
                .map_err(|_| anyhow!("CA state unavailable"))?;
            if state.as_ref().is_some_and(|old| {
                old.root.chain_pem == public_root.chain_pem
                    && old.intermediate.chain_pem == intermediate.chain_pem
            }) {
                return Ok(());
            }
            let root_validity = (root_start, root_end);
            let inter_validity = material::validity(&intermediate)?;
            let generation = state.as_ref().map_or(Ok(1), |old| {
                old.generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("CA generation exhausted"))
            })?;
            *state = Some(Arc::new(State {
                root: public_root,
                intermediate,
                generation,
                root_validity,
                inter_validity,
            }));
            notes.push("pki_ca_updated");
            if constrained {
                notes.push("pki_name_constraints_require_authorized_csr");
            }
            Ok(())
        }
        .await;
        let release = lease.release().await;
        match result {
            Ok(()) => {
                if let Err(error) = release {
                    self.emit("pki_lease_release_failed", Some(&error));
                }
                for kind in notes {
                    self.emit(kind, None);
                }
                Ok(())
            }
            Err(error) => {
                let _ = release;
                Err(error)
            }
        }
    }
}
pub fn due(not_before: i64, not_after: i64, now: i64, ratio: f64) -> bool {
    now as f64 > not_after as f64 - (not_after - not_before) as f64 * ratio
}
