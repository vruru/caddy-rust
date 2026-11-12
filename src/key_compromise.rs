//! Monotonic instance-local key vetoes backed by authenticated historical OCSP.
//! The records authorize no issuance or certificate-store write.
use crate::{cert_status::{KeyCompromiseProof, LiveKeyCompromiseFact, verify_key_compromise_proof}, certstore::FsStore};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, HashSet}, sync::{Arc, RwLock}, time::{SystemTime, UNIX_EPOCH}};
use tokio::sync::{Mutex, OnceCell, Semaphore, watch};
use tokio_util::sync::CancellationToken;

mod registry;
pub use registry::{KeyState, KeyRegistryError};
const MAX_KEY_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD: usize = 3 * 1024 * 1024;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug)]
pub struct KeyCompromised;
impl std::fmt::Display for KeyCompromised {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("certificate public key is compromised") }
}
impl std::error::Error for KeyCompromised {}
#[derive(Debug)]
pub struct KeyCompromiseNotDurable;
impl std::fmt::Display for KeyCompromiseNotDurable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("key veto recorded in memory; no durable proof queued")
    }
}
impl std::error::Error for KeyCompromiseNotDurable {}
struct State {
    registry: registry::Registry,
    durable: HashSet<[u8; 32]>,
    pending: HashMap<[u8; 32], Arc<KeyCompromiseProof>>,
    pending_bytes: usize,
    durable_bytes: usize,
}
pub struct KeyDeny {
    owner: Arc<()>,
    state: RwLock<State>,
    store: OnceCell<FsStore>,
    io: Mutex<()>,
    changed: watch::Sender<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record { version: u8, raw: String, leaf: String, issuer: String }
impl Default for KeyDeny { fn default() -> Self { Self::new() } }
impl KeyDeny {
    pub fn new() -> Self {
        let owner=Arc::new(());
        Self { state: RwLock::new(State { registry:registry::Registry::new(MAX_KEY_BYTES,owner.clone()),
            durable:HashSet::new(),pending:HashMap::new(),pending_bytes:0,durable_bytes:0 }),
            owner,store: OnceCell::new(),io: Mutex::new(()),changed: watch::channel(0).0 }
    }
    pub fn subscribe(&self) -> watch::Receiver<u64> { self.changed.subscribe() }
    pub fn require_loaded(&self) -> Result<()> {
        ensure!(self.store.initialized(), "key compromise history is not loaded"); Ok(())
    }
    /// Reserve before CSR signing, certificate publication or OCSP discovery.
    /// Healthy entries are weak; material/resolver/controller owns the live pin.
    pub fn register_spki(&self, spki: Arc<[u8]>) -> Result<Arc<KeyState>> {
        let id:[u8;32]=Sha256::digest(&spki).into();
        let reap={let state=self.state.read().map_err(|_|anyhow!("key compromise state unavailable"))?;
            if let Some(key)=state.registry.get(&id,&spki)? { return Ok(key); }
            state.registry.needs_reap(&id,spki.len())?};
        if reap {
            let mut cursor=0;
            loop {
                let retired=self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?
                    .registry.take_dead(&mut cursor);
                let Some(retired)=retired else {break};
                let(keys,buckets)=retired.release();
                self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?
                    .registry.release_credit(keys,buckets);
            }
        }
        let(key,retired)=self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?
            .registry.register(id,&spki)?;
        if let Some(retired)=retired {
            let(keys,buckets)=retired.release();
            self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?
                .registry.release_credit(keys,buckets);
        }
        Ok(key)
    }
    pub fn check_state(&self, key: &KeyState) -> Result<()> {
        ensure!(key.belongs(&self.owner), "certificate SPKI belongs to a different runtime");
        if key.banned() { return Err(KeyCompromised.into()); } Ok(())
    }
    pub fn owns_state(&self, key: &KeyState) -> bool { key.belongs(&self.owner) }
    pub fn check_spki_der(&self, spki: &[u8]) -> Result<()> {
        let id: [u8;32]=Sha256::digest(spki).into();
        let state=self.state.read().map_err(|_|anyhow!("key compromise state unavailable"))?;
        let key=state.registry.get(&id,spki)?.ok_or(KeyRegistryError::Unregistered)?;
        self.check_state(&key)
    }
    pub fn check_leaf_der(&self, leaf: &[u8]) -> Result<()> {
        let (tail, certificate) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|_| anyhow!("invalid key compromise leaf"))?;
        ensure!(tail.is_empty(), "trailing key compromise leaf");
        self.check_spki_der(certificate.public_key().raw)
    }
    /// Only a proof carrying a successful current verification can create a new record.
    pub fn record_live(&self, proof: KeyCompromiseProof) -> Result<()> {
        ensure!(proof.live_verified(), "historical proof cannot create a new key veto");
        let at = proof.verified_at().ok_or_else(|| anyhow!("missing current observation time"))?;
        self.record_current(proof.spki_arc(), at, Ok(proof))
    }
    /// A live fact bans the reserved key independently of historical eligibility.
    pub fn record_observed(&self, fact: LiveKeyCompromiseFact) -> Result<()> {
        let (spki, at, history) = fact.into_parts();
        self.record_current(spki, at, history)
    }
    fn record_current(&self, spki: Arc<[u8]>, at: i64,
        history: Result<KeyCompromiseProof>) -> Result<()> {
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        ensure!(at >= now.saturating_sub(300) && at <= now.saturating_add(300),
            "key compromise fact is not a current observation");
        let id: [u8; 32] = Sha256::digest(&spki).into();
        let mut state = self.state.write().map_err(|_| anyhow!("key compromise state unavailable"))?;
        // Every observer already owns the same reserved token. Pinning and
        // flipping it cannot allocate a key slot or fail because new keys filled
        // the pool after this certificate became active.
        state.registry.ban_existing(&id,&spki)?;
        let pending = match history {
            Err(error) => Err(anyhow::Error::new(KeyCompromiseNotDurable)
                .context(format!("historical proof unavailable: {error}"))),
            Ok(proof) => if !state.durable.contains(&id) && !state.pending.contains_key(&id) {
            let bytes = proof.retained_bytes();
            if state.pending_bytes.saturating_add(bytes) > MAX_PENDING_BYTES {
                Err(KeyCompromiseNotDurable.into())
            } else {
                state.pending_bytes += bytes;
                state.pending.insert(id, Arc::new(proof));
                Ok(())
            }
        } else { Ok(()) },
        };
        drop(state);
        // The veto is already effective even if bounded persistence admission
        // failed. Replacement must still be woken immediately.
        self.changed.send_modify(|generation| *generation = generation.wrapping_add(1));
        pending
    }
    pub async fn load(&self, store: FsStore, cpu: Arc<Semaphore>, cancel: CancellationToken) -> Result<()> {
        if let Some(current) = self.store.get() {
            ensure!(current.root_identity() == store.root_identity()
                && current.state_identity() == store.state_identity(), "key compromise state root changed");
            return Ok(());
        }
        let _io = self.io.lock().await;
        if let Some(current) = self.store.get() {
            ensure!(current.root_identity() == store.root_identity()
                && current.state_identity() == store.state_identity(), "key compromise state root changed");
            return Ok(());
        }
        let records = store.list("deny", true).await?.into_iter()
            .filter(|path| is_record_path(path)).collect::<Vec<_>>();
        let mut total = 0usize;
        for path in records {
            ensure!(!cancel.is_cancelled(), "key compromise restoration cancelled");
            let Some(bytes) = store.load(&path).await? else { return Err(anyhow!("key compromise record disappeared: {path}")); };
            total = total.saturating_add(bytes.len());
            ensure!(bytes.len() <= MAX_RECORD && total <= MAX_HISTORY_BYTES,
                "key compromise history size exceeded: {path}");
            let bytes = bytes.to_vec(); let expected = path.clone();
            let proof = crate::cert_cpu::run(cpu.clone(), cancel.clone(), move || {
                decode_record(&bytes, &expected)
            }).await.map_err(|error| anyhow!("invalid key compromise history {path}: {error}"))?;
            let id = proof.spki_id();
            let key=self.register_spki(Arc::from(proof.spki_der()))?;
            let mut state=self.state.write().map_err(|_|anyhow!("key compromise state unavailable"))?;
            state.registry.ban_existing(&id,key.spki_der())?;
            state.durable.insert(id);
        }
        self.state.write().map_err(|_| anyhow!("key compromise state unavailable"))?.durable_bytes = total;
        self.store.set(store).map_err(|_| anyhow!("key compromise history initialized concurrently"))?;
        Ok(())
    }
    /// An error leaves the signed pending proof retained for the next maintenance pass.
    pub async fn flush(&self, cpu: Arc<Semaphore>, cancel: CancellationToken) -> Result<()> {
        let _io = self.io.lock().await;
        let store = self.store.get().ok_or_else(|| anyhow!("key compromise history is not loaded"))?;
        let pending = self.state.read().map_err(|_| anyhow!("key compromise state unavailable"))?
            .pending.iter().map(|(id, proof)| (*id, proof.clone())).collect::<Vec<_>>();
        if pending.is_empty() { return Ok(()); }
        let lease = store.lock("key_compromise", cancel.child_token()).await?;
        let result = async {
            // A previous fenced write may have committed before a read-back or
            // lease-release error. Reconcile real encoded occupancy before any
            // new write so these files never consume capacity twice or vanish
            // from accounting. The one lease covers reconciliation and writes.
            let records = store.list("deny", true).await?.into_iter()
                .filter(|path| is_record_path(path)).collect::<Vec<_>>();
                let mut on_disk = HashSet::new();
            let mut total = 0usize;
            for path in records {
                ensure!(!cancel.is_cancelled(), "key compromise persistence cancelled");
                let bytes = store.load(&path).await?
                    .ok_or_else(|| anyhow!("key compromise record disappeared: {path}"))?;
                total = total.saturating_add(bytes.len());
                ensure!(bytes.len() <= MAX_RECORD && total <= MAX_HISTORY_BYTES,
                    "key compromise history size exceeded: {path}");
                on_disk.insert(path);
            }
            self.state.write().map_err(|_| anyhow!("key compromise state unavailable"))?.durable_bytes = total;
            for (id, proof) in pending {
                ensure!(!cancel.is_cancelled(), "key compromise persistence cancelled");
                let path = record_path(id);
                let bytes = serde_json::to_vec(&Record { version: 1, raw: STANDARD.encode(proof.raw()),
                    leaf: STANDARD.encode(proof.leaf_der()), issuer: STANDARD.encode(proof.issuer_der()) })?;
                ensure!(bytes.len() <= MAX_RECORD, "key compromise record size exceeded");
                if let Some(old) = store.load(&path).await? {
                    let bytes = old.to_vec(); let expected = path.clone();
                    let restored = crate::cert_cpu::run(cpu.clone(), cancel.clone(), move ||
                        decode_record(&bytes, &expected)).await?;
                    ensure!(restored.spki_der() == proof.spki_der(), "key compromise stored SPKI differs");
                } else {
                    {
                        let state = self.state.read().map_err(|_| anyhow!("key compromise state unavailable"))?;
                        ensure!(state.durable_bytes.saturating_add(bytes.len()) <= MAX_HISTORY_BYTES,
                            "key compromise history size exceeded");
                    }
                    store.store_fenced(&path, &bytes, &lease).await?;
                }
                let bytes = store.load(&path).await?
                    .ok_or_else(|| anyhow!("key compromise write disappeared"))?.to_vec();
                let retained = bytes.len(); let expected = path.clone();
                let restored = crate::cert_cpu::run(cpu.clone(), cancel.clone(), move ||
                    decode_record(&bytes, &expected)).await?;
                ensure!(restored.spki_der() == proof.spki_der(), "key compromise stored SPKI differs");
                let mut state = self.state.write().map_err(|_| anyhow!("key compromise state unavailable"))?;
                if on_disk.insert(path) { state.durable_bytes += retained; }
                state.durable.insert(id);
                if let Some(old) = state.pending.remove(&id) {
                    state.pending_bytes = state.pending_bytes.saturating_sub(old.retained_bytes());
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let released = lease.release().await;
        result?;
        released?;
        Ok(())
    }

}
fn record_path(id: [u8; 32]) -> String {
    format!("deny/{}.json", id.iter().map(|b| format!("{b:02x}")).collect::<String>())
}
fn decode_record(bytes: &[u8], path: &str) -> Result<KeyCompromiseProof> {
    ensure!(bytes.len() <= MAX_RECORD, "key compromise record size exceeded");
    let record: Record = serde_json::from_slice(bytes)?;
    ensure!(record.version == 1, "unsupported key compromise record version");
    let raw = STANDARD.decode(record.raw)?; let leaf = STANDARD.decode(record.leaf)?;
    let issuer = STANDARD.decode(record.issuer)?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let proof = verify_key_compromise_proof(&raw, &leaf, &issuer, now)?;
    ensure!(record_path(proof.spki_id()) == path, "key compromise record path mismatch");
    Ok(proof)
}

fn is_record_path(path: &str) -> bool {
    path.strip_prefix("deny/").and_then(|name| name.strip_suffix(".json"))
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit()
            || (b'a'..=b'f').contains(&byte)))
}
