//! Validated certificate snapshots and ACME-only challenge certificate routing.
//! No issuance, certificate storage writes, OCSP fetching, trust-chain validation,
//! on-demand issuance or listener configuration is performed here. Callers own
//! those policies. Successful replacement affects future handshakes only.

use crate::challenge::{ACME_ALPN, ChallengeRegistry, normalize_domain};
use crate::leaf_guard::{LeafGuard, LeafState, Observation, leaf_id};
use anyhow::{Result, anyhow, ensure};
use rustls::{
    ProtocolVersion, SignatureScheme,
    pki_types::CertificateDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use x509_parser::extensions::GeneralName;

pub(crate) const MAX_CERTIFICATES: usize = 16_384;
const MAX_NAMES: usize = 65536;
const MAX_CERT_BYTES: usize = 4 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 128 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPSERT_ATTEMPTS: usize = 8;
const MAX_OCSP_BYTES: usize = 1024 * 1024;
const MAX_STAPLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct CertificatePublicationConflict;
impl std::fmt::Display for CertificatePublicationConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate update conflicted with concurrent publication; retry required")
    }
}
impl std::error::Error for CertificatePublicationConflict {}

#[derive(Debug)]
pub(crate) struct CertificateResidencyRetired;
impl std::fmt::Display for CertificateResidencyRetired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate cache slot retired")
    }
}
impl std::error::Error for CertificateResidencyRetired {}

#[derive(Debug)]
pub struct OcspPublishConflict;
impl std::fmt::Display for OcspPublishConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OCSP update conflicted with concurrent publication; retry required")
    }
}
impl std::error::Error for OcspPublishConflict {}

#[derive(Debug)]
pub struct OcspPublishCapacity;
impl std::fmt::Display for OcspPublishCapacity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OCSP staple data limit exceeded")
    }
}
impl std::error::Error for OcspPublishCapacity {}

#[derive(Debug)]
pub struct OcspPublishExpired;
impl std::fmt::Display for OcspPublishExpired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OCSP response already expired")
    }
}
impl std::error::Error for OcspPublishExpired {}

/// Input is borrowed and never included in Debug or error strings. DNS aliases
/// are explicit, must be covered by the leaf SAN, and may include one leading
/// wildcard label. IP/default-certificate selection is outside this resolver.
pub struct CertificateInput<'a> {
    pub names: &'a [String],
    pub certificate_pem: &'a [u8],
    pub private_key_pem: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCompatibility {
    Tls12Or13,
    Tls12Only,
}
impl SignatureCompatibility {
    pub fn allows(self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_2
            || (self == Self::Tls12Or13 && version == ProtocolVersion::TLSv1_3)
    }
}
/// Preselection is not protocol authorization. Only `select_for_version` uses
/// the authoritative, already negotiated protocol to return its bound key.
#[derive(Clone)]
pub struct CertificateSelection {
    pub key: Arc<CertifiedKey>,
    pub(crate) leaf_state: Option<Arc<LeafState>>,
    pub signature_compatibility: SignatureCompatibility,
}

/// One generation's immutable manual-certificate metadata. Serving and OCSP
/// both use the same resolver; metadata contains no key or certificate copies.
#[derive(Clone)]
pub struct ManualCertificates {
    pub resolver: Arc<HotCertificateResolver>,
    pub certificates: Arc<Vec<ManualCertificateInfo>>,
}
#[derive(Clone)]
pub struct ManualCertificateInfo {
    pub identity: [u8; 32],
    pub names: Vec<String>,
    pub tags: Vec<String>,
}

/// Unforgeable local ownership for one certificate-management scope. Clone
/// this capability for that scope only; it is not a global revocation signal.
#[derive(Clone, Default)]
pub struct CertificateScope(Arc<()>);
impl CertificateScope {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The lifetime of one admitted managed cache slot, independent of the
/// configuration generations and certificate revisions that use it.
#[derive(Clone, Default)]
pub(crate) struct CertificateResidency(tokio_util::sync::CancellationToken);
impl CertificateResidency {
    /// Retiring one generation's projection does not affect its source or
    /// other generations. Retiring the source also retires every projection.
    pub(crate) fn projection(&self) -> Self {
        Self(self.0.child_token())
    }

    pub(crate) fn live(&self) -> bool {
        !self.0.is_cancelled()
    }

    pub(crate) fn retire(&self) {
        self.0.cancel();
    }

    pub(crate) async fn retired(&self) {
        self.0.cancelled().await;
    }
}

/// Compare-and-remove receipt for one actual publication. No private material
/// is retained. A reload, renewal, owner change or alias change invalidates it.
#[derive(Clone)]
pub struct ScopedCertificate {
    resolver: Arc<()>,
    owner: CertificateScope,
    identity: [u8; 32],
    instance_generation: u64,
    names: Vec<String>,
}
impl ScopedCertificate {
    pub(crate) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.resolver, &other.resolver)
            && Arc::ptr_eq(&self.owner.0, &other.owner.0)
            && self.instance_generation == other.instance_generation
            && self.identity == other.identity
            && self.names == other.names
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SignatureProfile {
    tls12: Vec<SignatureScheme>,
    tls13: Vec<SignatureScheme>,
}

/// Public certificate data only. The generation identifies a single loaded
/// instance, including reloads of byte-identical certificate material.
pub struct OcspCertificate {
    pub(crate) identity: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) names: Vec<String>,
    pub(crate) chain_der: Vec<Vec<u8>>,
    pub(crate) leaf_state: Arc<LeafState>,
    pub(crate) leaf_sha256: [u8; 32],
}
impl OcspCertificate {
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn names(&self) -> &[String] {
        &self.names
    }
    pub fn chain_der(&self) -> &[Vec<u8>] {
        &self.chain_der
    }
    /// Merge an authenticated fact before cache ownership/bookkeeping checks.
    /// Inventory construction binds the pinned state to this immutable leaf.
    pub(crate) fn observe_leaf(&self, observation: Observation) -> Result<()> {
        let leaf = self
            .chain_der
            .first()
            .ok_or_else(|| anyhow!("OCSP leaf missing"))?;
        ensure!(
            leaf_id(leaf) == self.leaf_sha256,
            "OCSP leaf binding mismatch"
        );
        self.leaf_state.observe(observation)
    }
}

#[derive(Clone)]
struct Staple {
    key: Arc<CertifiedKey>,
    tls13_key: Option<Arc<CertifiedKey>>,
    valid_until: i64,
}

#[derive(Clone)]
struct LoadedCertificate {
    key: Arc<CertifiedKey>,
    tls13_key: Option<Arc<CertifiedKey>>,
    leaf_state: Arc<LeafState>,
    leaf_sha256: [u8; 32],
    identity: [u8; 32],
    instance_generation: u64,
    owner: Option<CertificateScope>,
    residency: Option<Arc<CertificateResidency>>,
    staple: Option<Staple>,
    not_before: i64,
    not_after: i64,
    size: usize,
    signature_profile: SignatureProfile,
}

/// Public inventory retains only the immutable base key, never an optional
/// stapled-key clone. Clearing a staple therefore cannot hide retained bytes
/// from its independent cache budget.
struct InventoryEntry {
    key: Arc<CertifiedKey>,
    leaf_state: Arc<LeafState>,
    leaf_sha256: [u8; 32],
    identity: [u8; 32],
    generation: u64,
    names: Vec<String>,
    residency: Option<Arc<CertificateResidency>>,
}
impl InventoryEntry {
    fn live(&self) -> bool {
        self.residency.as_ref().is_none_or(|slot| slot.live())
    }
    fn certificate(&self) -> OcspCertificate {
        OcspCertificate {
            identity: self.identity,
            generation: self.generation,
            names: self.names.clone(),
            chain_der: self
                .key
                .cert
                .iter()
                .map(|der| der.as_ref().to_vec())
                .collect(),
            leaf_state: self.leaf_state.clone(),
            leaf_sha256: self.leaf_sha256,
        }
    }
}
fn certificate_inventory(
    names: &HashMap<String, Vec<Arc<LoadedCertificate>>>,
) -> Arc<HashMap<u64, InventoryEntry>> {
    let mut result: HashMap<u64, InventoryEntry> = HashMap::new();
    for (name, certificates) in names {
        for certificate in certificates {
            let entry = result
                .entry(certificate.instance_generation)
                .or_insert_with(|| InventoryEntry {
                    key: certificate.key.clone(),
                    leaf_state: certificate.leaf_state.clone(),
                    leaf_sha256: certificate.leaf_sha256,
                    identity: certificate.identity,
                    generation: certificate.instance_generation,
                    names: Vec::new(),
                    residency: certificate.residency.clone(),
                });
            entry.names.push(name.clone());
        }
    }
    for entry in result.values_mut() {
        entry.names.sort();
        entry.names.dedup();
    }
    Arc::new(result)
}

#[derive(Default)]
struct Snapshot {
    generation: u64,
    names: HashMap<String, Vec<Arc<LoadedCertificate>>>,
    inventory: Arc<HashMap<u64, InventoryEntry>>,
}

/// Each map is an immutable snapshot behind one short-held lock. Returning an
/// Arc keeps old signing material alive for handshakes/connections using it.
pub struct HotCertificateResolver {
    challenges: ChallengeRegistry,
    leaf_guard: Arc<LeafGuard>,
    certificates: RwLock<Arc<Snapshot>>,
    next_instance: AtomicU64,
    scope_identity: Arc<()>,
}

impl fmt::Debug for HotCertificateResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HotCertificateResolver")
            .finish_non_exhaustive()
    }
}

impl HotCertificateResolver {
    /// Every candidate and retiring resolver in one process must share this
    /// guard. Repackaging a leaf in another chain must not forget its status.
    pub fn with_leaf_guard(challenges: ChallengeRegistry, leaf_guard: Arc<LeafGuard>) -> Self {
        Self {
            challenges,
            leaf_guard,
            certificates: RwLock::new(Arc::new(Snapshot::default())),
            next_instance: AtomicU64::new(1),
            scope_identity: Arc::new(()),
        }
    }

    pub fn leaf_guard(&self) -> Arc<LeafGuard> {
        self.leaf_guard.clone()
    }

    fn instance_generation(&self) -> Result<u64> {
        self.next_instance
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| anyhow!("certificate instance generation exhausted"))
    }

    /// Validate the entire candidate outside the lock, then publish one snapshot.
    /// Any invalid key, SAN, PEM, validity or capacity leaves the
    /// currently published snapshot unchanged. Empty input intentionally clears.
    pub fn replace(&self, inputs: &[CertificateInput<'_>]) -> Result<()> {
        ensure!(
            inputs.len() <= MAX_CERTIFICATES,
            "certificate count limit exceeded"
        );
        let base = self
            .certificates
            .read()
            .map_err(|_| anyhow!("certificate state unavailable"))?
            .clone();
        let now = clock_now()?;
        let mut bytes = 0usize;
        let mut next: HashMap<String, Vec<Arc<LoadedCertificate>>> = HashMap::new();
        for input in inputs {
            bytes = bytes
                .checked_add(input.certificate_pem.len())
                .and_then(|n| n.checked_add(input.private_key_pem.len()))
                .ok_or_else(|| anyhow!("certificate data limit exceeded"))?;
            ensure!(bytes <= MAX_TOTAL_BYTES, "certificate data limit exceeded");
            let (names, mut cert) = load_certificate(input, &self.leaf_guard)?;
            cert.instance_generation = self.instance_generation()?;
            inherit_staple(&mut cert, &base.names, now);
            let cert = Arc::new(cert);
            for name in names {
                ensure!(
                    next.contains_key(&name) || next.len() < MAX_NAMES,
                    "certificate alias limit exceeded"
                );
                let candidates = next.entry(name).or_default();
                ensure!(
                    candidates.len() < 8,
                    "certificate candidates per alias limit exceeded"
                );
                candidates.push(cert.clone());
            }
        }
        prune_staples(&mut next, now, true)?;
        validate_snapshot_size(&next)?;
        let inventory = certificate_inventory(&next);
        let mut guard = self
            .certificates
            .write()
            .map_err(|_| anyhow!("certificate state unavailable"))?;
        let generation = guard
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("certificate generation exhausted"))?;
        let previous = std::mem::replace(
            &mut *guard,
            Arc::new(Snapshot {
                generation,
                names: next,
                inventory,
            }),
        );
        drop(guard);
        drop(previous);
        Ok(())
    }

    /// Atomically update aliases for one validated certificate. Concurrent
    /// updates for unrelated aliases merge optimistically outside the lock; a failed
    /// candidate cannot replace the current key. This does not remove aliases
    /// omitted by the caller: full configuration reload must use replace().
    pub fn upsert(&self, input: &CertificateInput<'_>) -> Result<()> {
        self.upsert_owned(input, None, None, None, || Ok(()))
            .map(|_| ())
    }

    /// Same validation and publication as upsert, with a scope-bound receipt.
    /// OCSP updates keep this receipt valid; loading even identical DER again
    /// creates a new instance and invalidates the old receipt.
    pub fn upsert_scoped(
        &self,
        input: &CertificateInput<'_>,
        owner: &CertificateScope,
    ) -> Result<ScopedCertificate> {
        let receipt = self.upsert_owned(input, Some(owner.clone()), None, None, || Ok(()))?;
        receipt.ok_or_else(|| anyhow!("certificate scope unavailable"))
    }

    pub(crate) fn upsert_resident(
        &self,
        input: &CertificateInput<'_>,
        owner: &CertificateScope,
        slot: &Arc<CertificateResidency>,
        cancel: &tokio_util::sync::CancellationToken,
        commit: impl FnOnce() -> Result<()>,
    ) -> Result<ScopedCertificate> {
        self.upsert_owned(
            input,
            Some(owner.clone()),
            Some(slot.clone()),
            Some(cancel),
            commit,
        )?
        .ok_or_else(|| anyhow!("certificate scope unavailable"))
    }

    pub(crate) fn upsert_checked(
        &self,
        input: &CertificateInput<'_>,
        cancel: &tokio_util::sync::CancellationToken,
        commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.upsert_owned(input, None, None, Some(cancel), commit)
            .map(|_| ())
    }

    fn upsert_owned(
        &self,
        input: &CertificateInput<'_>,
        owner: Option<CertificateScope>,
        residency: Option<Arc<CertificateResidency>>,
        cancel: Option<&tokio_util::sync::CancellationToken>,
        commit: impl FnOnce() -> Result<()>,
    ) -> Result<Option<ScopedCertificate>> {
        let check_active = || {
            ensure!(
                cancel.is_none_or(|token| !token.is_cancelled()),
                "certificate publication cancelled"
            );
            ensure!(
                residency.as_ref().is_none_or(|slot| slot.live()),
                CertificateResidencyRetired
            );
            Ok(())
        };
        check_active()?;
        let (names, mut cert) = load_certificate(input, &self.leaf_guard)?;
        cert.instance_generation = self.instance_generation()?;
        cert.owner = owner.clone();
        cert.residency = residency.clone();
        let receipt = owner.map(|owner| {
            let mut names = names.clone();
            names.sort();
            names.dedup();
            ScopedCertificate {
                resolver: self.scope_identity.clone(),
                owner,
                identity: cert.identity,
                instance_generation: cert.instance_generation,
                names,
            }
        });
        for _ in 0..MAX_UPSERT_ATTEMPTS {
            let base = self
                .certificates
                .read()
                .map_err(|_| anyhow!("certificate state unavailable"))?
                .clone();
            let now = clock_now()?;
            let mut candidate_cert = cert.clone();
            inherit_staple(&mut candidate_cert, &base.names, now);
            let cert = Arc::new(candidate_cert);
            // Cloning, merging, capacity checks and destruction of discarded
            // candidates do not block certificate lookups or other publishers.
            let mut next = base.names.clone();
            next.retain(|_, candidates| {
                candidates.retain(|old| old.residency.as_ref().is_none_or(|slot| slot.live()));
                !candidates.is_empty()
            });
            for name in &names {
                ensure!(
                    next.contains_key(name) || next.len() < MAX_NAMES,
                    "certificate alias limit exceeded"
                );
                let candidates = next.entry(name.clone()).or_default();
                // Renew one signing profile without discarding e.g. the RSA
                // certificate when an ECDSA certificate for the same name renews.
                candidates.retain(|old| match (&old.residency, &cert.residency) {
                    // One SAN slot has one revision. Do not evict a different
                    // live slot whose SAN list happens to overlap this alias.
                    (Some(old), Some(new)) => !Arc::ptr_eq(old, new),
                    (None, None) => {
                        let same_scope = match (&old.owner, &cert.owner) {
                            (Some(old), Some(new)) => Arc::ptr_eq(&old.0, &new.0),
                            (None, None) => true,
                            _ => false,
                        };
                        !same_scope || old.signature_profile != cert.signature_profile
                    }
                    _ => true,
                });
                ensure!(
                    candidates.len() < 8,
                    "certificate candidates per alias limit exceeded"
                );
                candidates.push(cert.clone());
            }
            prune_staples(&mut next, now, true)?;
            // A scoped insertion can retire its victim in the final commit
            // hook. Allow that one transient instance in the candidate only.
            validate_snapshot_size_with_limit(
                &next,
                MAX_CERTIFICATES + usize::from(residency.is_some()),
            )?;
            let generation = base
                .generation
                .checked_add(1)
                .ok_or_else(|| anyhow!("certificate generation exhausted"))?;
            let candidate = Arc::new(Snapshot {
                generation,
                inventory: certificate_inventory(&next),
                names: next,
            });
            let mut guard = self
                .certificates
                .write()
                .map_err(|_| anyhow!("certificate state unavailable"))?;
            if !Arc::ptr_eq(&base, &guard) {
                drop(guard);
                continue;
            }
            check_active()?;
            // The cache admission hook only commits short in-memory state;
            // all key validation and snapshot construction already succeeded.
            // Nothing fallible follows the hook in this publication.
            commit()?;
            let previous = std::mem::replace(&mut *guard, candidate);
            drop(guard);
            drop(previous);
            return Ok(receipt);
        }
        Err(CertificatePublicationConflict.into())
    }

    /// Evict only this resolver's exact loaded instance under the same owner.
    /// A stale task returns false without touching a replacement or other scope.
    /// Already accepted connections keep their Arc keys; LeafGuard is unchanged.
    pub fn remove_scoped(
        &self,
        owner: &CertificateScope,
        receipt: &ScopedCertificate,
    ) -> Result<bool> {
        if !Arc::ptr_eq(&owner.0, &receipt.owner.0)
            || !Arc::ptr_eq(&self.scope_identity, &receipt.resolver)
        {
            return Ok(false);
        }
        let matches = |cert: &LoadedCertificate| {
            cert.instance_generation == receipt.instance_generation
                && cert.identity == receipt.identity
                && cert
                    .owner
                    .as_ref()
                    .is_some_and(|scope| Arc::ptr_eq(&scope.0, &owner.0))
        };
        for _ in 0..MAX_UPSERT_ATTEMPTS {
            let base = self
                .certificates
                .read()
                .map_err(|_| anyhow!("certificate state unavailable"))?
                .clone();
            let mut aliases = base
                .names
                .iter()
                .filter_map(|(name, candidates)| {
                    candidates
                        .iter()
                        .any(|cert| matches(cert))
                        .then_some(name.clone())
                })
                .collect::<Vec<_>>();
            aliases.sort();
            if aliases != receipt.names {
                return Ok(false);
            }
            let mut names = base.names.clone();
            for name in &receipt.names {
                if let Some(candidates) = names.get_mut(name) {
                    candidates.retain(|cert| !matches(cert));
                }
            }
            names.retain(|_, candidates| !candidates.is_empty());
            let candidate = Arc::new(Snapshot {
                generation: base
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("certificate generation exhausted"))?,
                inventory: certificate_inventory(&names),
                names,
            });
            let mut guard = self
                .certificates
                .write()
                .map_err(|_| anyhow!("certificate state unavailable"))?;
            if !Arc::ptr_eq(&base, &guard) {
                drop(guard);
                continue;
            }
            let previous = std::mem::replace(&mut *guard, candidate);
            drop(guard);
            drop(previous);
            return Ok(true);
        }
        Err(anyhow!(
            "scoped certificate removal conflicted with concurrent publication; retry required"
        ))
    }

    /// Dispose of unreachable aliases after the owning work has joined. A
    /// replacement may already exist at the same alias; only a dead slot is
    /// eligible, irrespective of which certificate revision was published.
    pub(crate) fn sweep_retired(
        &self,
        owner: &CertificateScope,
        slot: &Arc<CertificateResidency>,
        aliases: &[String],
    ) -> Result<()> {
        ensure!(!slot.live(), "cannot sweep a live certificate cache slot");
        for _ in 0..MAX_UPSERT_ATTEMPTS {
            let base = self
                .certificates
                .read()
                .map_err(|_| anyhow!("certificate state unavailable"))?
                .clone();
            let mut names = base.names.clone();
            let mut changed = false;
            for alias in aliases {
                if let Some(entries) = names.get_mut(alias) {
                    let before = entries.len();
                    entries.retain(|cert| {
                        !(cert
                            .owner
                            .as_ref()
                            .is_some_and(|scope| Arc::ptr_eq(&scope.0, &owner.0))
                            && cert
                                .residency
                                .as_ref()
                                .is_some_and(|actual| Arc::ptr_eq(actual, slot)))
                    });
                    changed |= before != entries.len();
                    if entries.is_empty() {
                        names.remove(alias);
                    }
                }
            }
            if !changed {
                return Ok(());
            }
            let next = Arc::new(Snapshot {
                generation: base
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("certificate generation exhausted"))?,
                inventory: certificate_inventory(&names),
                names,
            });
            let mut guard = self
                .certificates
                .write()
                .map_err(|_| anyhow!("certificate state unavailable"))?;
            if Arc::ptr_eq(&base, &guard) {
                let previous = std::mem::replace(&mut *guard, next);
                drop(guard);
                drop(previous);
                return Ok(());
            }
        }
        Err(anyhow!(
            "retired certificate sweep conflicted with concurrent publication"
        ))
    }

    pub fn generation(&self) -> Option<u64> {
        Some(self.certificates.read().ok()?.generation)
    }

    /// Clone only public certificate data, outside the short snapshot lock.
    /// Call this from a bounded worker when inventories are large.
    pub fn ocsp_certificates(&self) -> Result<Vec<OcspCertificate>> {
        let snapshot = self
            .certificates
            .read()
            .map_err(|_| anyhow!("certificate state unavailable"))?
            .clone();
        let mut result = snapshot
            .inventory
            .values()
            .filter(|entry| entry.live())
            .map(InventoryEntry::certificate)
            .collect::<Vec<_>>();
        result.sort_by_key(|certificate| certificate.generation);
        Ok(result)
    }
    /// Scope filtering precedes DER cloning, but each returned record retains
    /// its complete actual alias set for exact-instance publication checks.
    pub(crate) fn ocsp_certificates_for_names(
        &self,
        names: &HashSet<String>,
    ) -> Result<Vec<OcspCertificate>> {
        let snapshot = self
            .certificates
            .read()
            .map_err(|_| anyhow!("certificate state unavailable"))?
            .clone();
        let ids = names
            .iter()
            .filter_map(|name| snapshot.names.get(name))
            .flatten()
            .map(|certificate| certificate.instance_generation)
            .collect::<HashSet<_>>();
        let mut result = ids
            .into_iter()
            .filter_map(|id| snapshot.inventory.get(&id))
            .filter(|entry| entry.live())
            .map(InventoryEntry::certificate)
            .collect::<Vec<_>>();
        result.sort_by_key(|certificate| certificate.generation);
        Ok(result)
    }
    pub(crate) fn ocsp_certificates_for_identity(
        &self,
        identity: &[u8; 32],
    ) -> Result<Vec<OcspCertificate>> {
        let snapshot = self
            .certificates
            .read()
            .map_err(|_| anyhow!("certificate state unavailable"))?
            .clone();
        let mut result = snapshot
            .inventory
            .values()
            .filter(|entry| entry.identity == *identity && entry.live())
            .map(InventoryEntry::certificate)
            .collect::<Vec<_>>();
        result.sort_by_key(|certificate| certificate.generation);
        Ok(result)
    }
    pub(crate) fn ocsp_identities(&self) -> Result<HashSet<[u8; 32]>> {
        let snapshot = self
            .certificates
            .read()
            .map_err(|_| anyhow!("certificate state unavailable"))?
            .clone();
        Ok(snapshot
            .inventory
            .values()
            .filter(|entry| entry.live())
            .map(|entry| entry.identity)
            .collect())
    }

    /// Attach only an already verified OCSP response to this exact loaded
    /// certificate instance. The status manager owns response authentication.
    /// A stale worker cannot attach to a byte-identical reloaded certificate.
    pub fn set_ocsp(
        &self,
        identity: &[u8; 32],
        generation: u64,
        staple: Option<(Vec<u8>, i64)>,
    ) -> Result<bool> {
        if let Some((bytes, valid_until)) = &staple {
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_OCSP_BYTES,
                "OCSP response size outside bounds"
            );
            if *valid_until <= now {
                return Err(anyhow::Error::new(OcspPublishExpired));
            }
        }
        for _ in 0..MAX_UPSERT_ATTEMPTS {
            let base = self
                .certificates
                .read()
                .map_err(|_| anyhow!("certificate state unavailable"))?
                .clone();
            let Some(old) =
                base.names.values().flatten().find(|cert| {
                    cert.identity == *identity && cert.instance_generation == generation
                })
            else {
                return Ok(false);
            };
            if staple.is_none() && old.staple.is_none() {
                return Ok(true);
            }
            let mut next_cert = old.as_ref().clone();
            next_cert.staple = if let Some((bytes, valid_until)) = &staple {
                ensure!(
                    *valid_until <= old.not_after,
                    "OCSP validity exceeds certificate expiry"
                );
                Some(make_staple(old, bytes, *valid_until))
            } else {
                None
            };
            let next_cert = Arc::new(next_cert);
            let mut names = base.names.clone();
            for candidates in names.values_mut() {
                for cert in candidates {
                    if cert.identity == *identity && cert.instance_generation == generation {
                        *cert = next_cert.clone();
                    }
                }
            }
            prune_staples(&mut names, clock_now()?, false)?;
            validate_snapshot_size(&names)?;
            let candidate = Arc::new(Snapshot {
                generation: base
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("certificate generation exhausted"))?,
                inventory: base.inventory.clone(),
                names,
            });
            let mut guard = self
                .certificates
                .write()
                .map_err(|_| anyhow!("certificate state unavailable"))?;
            if !Arc::ptr_eq(&base, &guard) {
                drop(guard);
                continue;
            }
            let previous = std::mem::replace(&mut *guard, candidate);
            drop(guard);
            drop(previous);
            return Ok(true);
        }
        Err(anyhow::Error::new(OcspPublishConflict))
    }

    /// Pure selection entry used by the rustls trait and isolated TLS QA. An
    /// offered ACME protocol is never allowed to fall through to ordinary TLS.
    pub fn select(
        &self,
        sni: Option<&str>,
        offered_alpn: &[&[u8]],
        signature_schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.select_candidate(sni, offered_alpn, signature_schemes)
            .map(|selected| selected.key)
    }

    pub fn select_candidate(
        &self,
        sni: Option<&str>,
        offered_alpn: &[&[u8]],
        signature_schemes: &[SignatureScheme],
    ) -> Option<CertificateSelection> {
        self.select_internal(sni, offered_alpn, signature_schemes, None, None)
    }

    pub fn select_for_version(
        &self,
        sni: Option<&str>,
        offered_alpn: &[&[u8]],
        signature_schemes: &[SignatureScheme],
        version: ProtocolVersion,
    ) -> Option<CertificateSelection> {
        self.select_internal(sni, offered_alpn, signature_schemes, Some(version), None)
    }

    pub fn select_candidate_filtered(
        &self,
        sni: Option<&str>,
        offered_alpn: &[&[u8]],
        signature_schemes: &[SignatureScheme],
        allowed_identities: &HashSet<[u8; 32]>,
    ) -> Option<CertificateSelection> {
        self.select_internal(
            sni,
            offered_alpn,
            signature_schemes,
            None,
            Some(allowed_identities),
        )
    }

    pub fn select_for_version_filtered(
        &self,
        sni: Option<&str>,
        offered_alpn: &[&[u8]],
        signature_schemes: &[SignatureScheme],
        version: ProtocolVersion,
        allowed_identities: &HashSet<[u8; 32]>,
    ) -> Option<CertificateSelection> {
        self.select_internal(
            sni,
            offered_alpn,
            signature_schemes,
            Some(version),
            Some(allowed_identities),
        )
    }

    fn select_internal(
        &self,
        sni: Option<&str>,
        offered_alpn: &[&[u8]],
        signature_schemes: &[SignatureScheme],
        version: Option<ProtocolVersion>,
        allowed_identities: Option<&HashSet<[u8; 32]>>,
    ) -> Option<CertificateSelection> {
        if version
            .is_some_and(|v| !matches!(v, ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3))
        {
            return None;
        }
        let raw_name = sni?;
        if offered_alpn.contains(&ACME_ALPN) {
            let sni = normalize_domain(raw_name).ok()?;
            if allowed_identities.is_some() {
                return None;
            }
            let mut key = self.challenges.lookup_tls(&sni, offered_alpn)?;
            if version == Some(ProtocolVersion::TLSv1_3) {
                let signer = crate::crypto::tls13_signer(&key.key)?;
                if !Arc::ptr_eq(&signer, &key.key) {
                    let mut bounded = key.as_ref().clone();
                    bounded.key = signer;
                    key = Arc::new(bounded);
                }
            }
            key.key.choose_scheme(signature_schemes)?;
            return Some(CertificateSelection {
                key,
                signature_compatibility: SignatureCompatibility::Tls12Or13,
                leaf_state: None,
            });
        }
        let sni = normalize_certificate_name(raw_name).ok()?;
        let snapshot = self.certificates.read().ok()?.clone();
        let now =
            i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
        let select = |candidates: &Vec<Arc<LoadedCertificate>>| {
            candidates.iter().find_map(|entry| {
                if allowed_identities.is_some_and(|allowed| !allowed.contains(&entry.identity)) {
                    return None;
                }
                if entry.residency.as_ref().is_some_and(|slot| !slot.live()) {
                    return None;
                }
                let admission = entry.leaf_state.admission();
                if !admission.allow_certificate || now < entry.not_before || now >= entry.not_after
                {
                    return None;
                }
                let staple = entry
                    .staple
                    .as_ref()
                    .filter(|staple| admission.allow_staple && now < staple.valid_until);
                let key = if version == Some(ProtocolVersion::TLSv1_3) {
                    staple
                        .and_then(|s| s.tls13_key.clone())
                        .or_else(|| entry.tls13_key.clone())?
                } else {
                    staple.map_or_else(|| entry.key.clone(), |s| s.key.clone())
                };
                key.key.choose_scheme(signature_schemes)?;
                Some(CertificateSelection {
                    key,
                    leaf_state: Some(entry.leaf_state.clone()),
                    signature_compatibility: if entry.tls13_key.is_some() {
                        SignatureCompatibility::Tls12Or13
                    } else {
                        SignatureCompatibility::Tls12Only
                    },
                })
            })
        };
        if let Some(key) = snapshot.names.get(&sni).and_then(select) {
            return Some(key);
        }
        if sni.parse::<IpAddr>().is_ok() || sni.starts_with("*.") {
            return None;
        }
        let (_, suffix) = sni.split_once('.')?;
        snapshot.names.get(&format!("*.{suffix}")).and_then(select)
    }
}

impl ResolvesServerCert for HotCertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // ALPN is bounded by the TLS ClientHello framing. Collecting borrowed
        // slices does not clone peer data or retain it after this handshake.
        let alpn = hello
            .alpn()
            .map(|v| v.collect::<Vec<_>>())
            .unwrap_or_default();
        self.select_for_version(
            hello.server_name(),
            &alpn,
            hello.signature_schemes(),
            hello.negotiated_version()?,
        )
        .map(|selected| selected.key)
    }
}

fn staple_size(key: &CertifiedKey) -> Result<usize> {
    key.cert
        .iter()
        .try_fold(key.ocsp.as_ref().map_or(0, Vec::len), |size, der| {
            size.checked_add(der.len())
                .ok_or_else(|| anyhow!("certificate size accounting overflow"))
        })
}

fn status_size(staple: &Staple) -> Result<usize> {
    let base = staple_size(&staple.key)?;
    if let Some(key) = &staple.tls13_key
        && !Arc::ptr_eq(key, &staple.key)
    {
        return base
            .checked_add(staple_size(key)?)
            .ok_or_else(|| anyhow!("OCSP data size overflow"));
    }
    Ok(base)
}
fn make_staple(cert: &LoadedCertificate, bytes: &[u8], valid_until: i64) -> Staple {
    let mut base = cert.key.as_ref().clone();
    base.ocsp = Some(bytes.to_vec());
    let key = Arc::new(base);
    let tls13_key = cert.tls13_key.as_ref().map(|other| {
        if Arc::ptr_eq(other, &cert.key) {
            key.clone()
        } else {
            let mut bound = other.as_ref().clone();
            bound.ocsp = Some(bytes.to_vec());
            Arc::new(bound)
        }
    });
    Staple {
        key,
        tls13_key,
        valid_until,
    }
}

/// Stable identity used by the OCSP cache and manual tag selection. Framing
/// includes chain length and each DER length, so different chains stay distinct.
pub fn certificate_chain_identity(chain: &[CertificateDer<'_>]) -> [u8; 32] {
    let mut identity = Sha256::new();
    identity.update(b"caddy-native-ocsp-chain-v1\0");
    identity.update((chain.len() as u64).to_be_bytes());
    for der in chain {
        identity.update((der.len() as u64).to_be_bytes());
        identity.update(der.as_ref());
    }
    identity.finalize().into()
}

fn load_certificate(
    input: &CertificateInput<'_>,
    leaf_guard: &LeafGuard,
) -> Result<(Vec<String>, LoadedCertificate)> {
    ensure!(
        !input.names.is_empty() && input.names.len() <= MAX_NAMES,
        "certificate aliases outside bounds"
    );
    ensure!(
        !input.certificate_pem.is_empty()
            && input.certificate_pem.len() <= MAX_CERT_BYTES
            && !input.private_key_pem.is_empty()
            && input.private_key_pem.len() <= MAX_KEY_BYTES,
        "certificate material outside bounds"
    );
    let blocks = crate::certmagic::pem_blocks(input.certificate_pem, "tls-candidate")?;
    let mut chain = Vec::with_capacity(blocks.len());
    for (label, der) in &blocks {
        ensure!(label == "CERTIFICATE", "unexpected certificate PEM label");
        let (remaining, _) = x509_parser::parse_x509_certificate(der)
            .map_err(|_| anyhow!("invalid certificate DER"))?;
        ensure!(remaining.is_empty(), "trailing certificate DER");
        chain.push(CertificateDer::from(der.to_vec()));
    }
    let preferred = crate::certmagic::signing_key(input.private_key_pem, "tls-candidate")?;
    let key = crate::crypto::tls12_signer(&preferred, input.private_key_pem)?;
    let identity = certificate_chain_identity(&chain);
    let certified = CertifiedKey::new(chain, key);
    certified
        .keys_match()
        .map_err(|_| anyhow!("certificate and private key do not match"))?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&blocks[0].1)
        .map_err(|_| anyhow!("invalid leaf certificate"))?;
    ensure!(
        leaf.validity().is_valid(),
        "certificate is not currently valid"
    );
    // A validation-only challenge certificate must never enter normal serving.
    ensure!(
        !leaf
            .extensions()
            .iter()
            .any(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31"),
        "ACME challenge certificate cannot be a normal certificate"
    );
    let san_names = certificate_san_names(&leaf)?;
    let names = input
        .names
        .iter()
        .map(|s| normalize_certificate_name(s))
        .collect::<Result<Vec<_>>>()?;
    for name in &names {
        ensure!(
            san_names.iter().any(|san| covers(san, name)),
            "certificate SAN does not cover alias"
        );
    }
    let key = Arc::new(certified);
    let tls13_key = crate::crypto::tls13_signer(&preferred).map(|signer| {
        if Arc::ptr_eq(&signer, &key.key) {
            key.clone()
        } else {
            let mut bound = key.as_ref().clone();
            bound.key = signer;
            Arc::new(bound)
        }
    });
    let schemes = [
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ED25519,
    ];
    let signature_profile = SignatureProfile {
        tls12: schemes
            .into_iter()
            .filter(|scheme| key.key.choose_scheme(&[*scheme]).is_some())
            .collect(),
        tls13: schemes
            .into_iter()
            .filter(|scheme| {
                tls13_key
                    .as_ref()
                    .is_some_and(|key| key.key.choose_scheme(&[*scheme]).is_some())
            })
            .collect(),
    };
    ensure!(
        !signature_profile.tls12.is_empty(),
        "certificate has unsupported signing profile"
    );
    let extra_key_bytes = if tls13_key
        .as_ref()
        .is_some_and(|other| !Arc::ptr_eq(other, &key))
    {
        staple_size(&key)?
    } else {
        0
    };
    let size = input
        .certificate_pem
        .len()
        .checked_add(input.private_key_pem.len())
        .and_then(|v| v.checked_add(extra_key_bytes))
        .ok_or_else(|| anyhow!("certificate size overflow"))?;
    let leaf_sha256 = leaf_id(&blocks[0].1);
    Ok((
        names,
        LoadedCertificate {
            key,
            tls13_key,
            leaf_state: leaf_guard.intern(leaf_sha256, leaf.validity().not_after.timestamp())?,
            leaf_sha256,
            identity,
            instance_generation: 0,
            owner: None,
            residency: None,
            staple: None,
            signature_profile,
            size,
            not_before: leaf.validity().not_before.timestamp(),
            not_after: leaf.validity().not_after.timestamp(),
        },
    ))
}

fn clock_now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}
fn inherit_staple(
    cert: &mut LoadedCertificate,
    names: &HashMap<String, Vec<Arc<LoadedCertificate>>>,
    now: i64,
) {
    let Some(staple) = names
        .values()
        .flatten()
        .filter(|old| old.identity == cert.identity)
        .filter_map(|old| old.staple.as_ref())
        .filter(|staple| staple.valid_until > now)
        .max_by_key(|staple| staple.valid_until)
    else {
        return;
    };
    if let Some(bytes) = &staple.key.ocsp {
        cert.staple = Some(make_staple(cert, bytes, staple.valid_until));
    }
}
// Optional status data must never prevent publication of required certificate
// material. Certificate publication may evict cached staples; OCSP attachment
// instead rejects over-budget candidates. All aliases keep one instance Arc.
fn prune_staples(
    names: &mut HashMap<String, Vec<Arc<LoadedCertificate>>>,
    now: i64,
    evict: bool,
) -> Result<()> {
    if !names.values().flatten().any(|cert| cert.staple.is_some()) {
        return Ok(());
    }
    let mut instances: HashMap<u64, Arc<LoadedCertificate>> = names
        .values()
        .flatten()
        .map(|cert| (cert.instance_generation, cert.clone()))
        .collect();
    let mut order = instances.keys().copied().collect::<Vec<_>>();
    order.sort_unstable();
    let mut bytes = 0usize;
    for generation in order {
        let cert = instances
            .get_mut(&generation)
            .ok_or_else(|| anyhow!("certificate instance missing"))?;
        if let Some(staple) = &cert.staple {
            let size = status_size(staple)?;
            let keep = staple.valid_until > now
                && (!evict
                    || bytes
                        .checked_add(size)
                        .is_some_and(|total| total <= MAX_STAPLE_BYTES));
            if keep {
                bytes = bytes
                    .checked_add(size)
                    .ok_or_else(|| anyhow!("OCSP staple data limit exceeded"))?;
            } else {
                let mut unstapled = cert.as_ref().clone();
                unstapled.staple = None;
                *cert = Arc::new(unstapled);
            }
        }
    }
    for cert in names.values_mut().flatten() {
        *cert = instances
            .get(&cert.instance_generation)
            .ok_or_else(|| anyhow!("certificate instance missing"))?
            .clone();
    }
    Ok(())
}

fn validate_snapshot_size(names: &HashMap<String, Vec<Arc<LoadedCertificate>>>) -> Result<()> {
    validate_snapshot_size_with_limit(names, MAX_CERTIFICATES)
}

fn validate_snapshot_size_with_limit(
    names: &HashMap<String, Vec<Arc<LoadedCertificate>>>,
    limit: usize,
) -> Result<()> {
    let mut unique = HashSet::new();
    let mut size = 0usize;
    let mut staple_bytes = 0usize;
    for cert in names.values().flatten() {
        if unique.insert(Arc::as_ptr(cert)) {
            ensure!(unique.len() <= limit, "certificate count limit exceeded");
            size = size
                .checked_add(cert.size)
                .ok_or_else(|| anyhow!("certificate data limit exceeded"))?;
            ensure!(size <= MAX_TOTAL_BYTES, "certificate data limit exceeded");
            if let Some(staple) = &cert.staple {
                staple_bytes = staple_bytes
                    .checked_add(status_size(staple)?)
                    .ok_or_else(|| anyhow!("OCSP staple data limit exceeded"))?;
                if staple_bytes > MAX_STAPLE_BYTES {
                    return Err(anyhow::Error::new(OcspPublishCapacity));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn canonical_certificate_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map_or_else(|| value.to_string(), |mapped| mapped.to_string()),
        IpAddr::V4(value) => value.to_string(),
    }
}

pub(crate) fn certificate_san_names(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<Vec<String>> {
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| anyhow!("invalid certificate SAN"))?
        .ok_or_else(|| anyhow!("certificate has no SAN"))?;
    let names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) if name.parse::<IpAddr>().is_err() => {
                normalize_certificate_name(name).ok()
            }
            GeneralName::IPAddress(octets) => {
                let ip = match *octets {
                    bytes if bytes.len() == 4 => {
                        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))
                    }
                    bytes if bytes.len() == 16 => {
                        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?))
                    }
                    _ => return None,
                };
                Some(canonical_certificate_ip(ip))
            }
            _ => None,
        });
    Ok(names.collect())
}

pub(crate) fn normalize_certificate_name(raw: &str) -> Result<String> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(canonical_certificate_ip(ip));
    }
    if let Some(suffix) = raw.strip_prefix("*.") {
        let suffix = normalize_domain(suffix)?;
        ensure!(
            suffix.contains('.'),
            "wildcard suffix must have at least two labels"
        );
        Ok(format!("*.{suffix}"))
    } else {
        normalize_domain(raw)
    }
}

fn covers(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }
    if name.starts_with("*.") || name.parse::<IpAddr>().is_ok() {
        return false;
    }
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        name.split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
    })
}
