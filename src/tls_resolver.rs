//! Validated certificate snapshots and ACME-only challenge certificate routing.
//! No issuance, certificate storage writes, OCSP fetching, trust-chain validation,
//! on-demand issuance or listener configuration is performed here. Callers own
//! those policies. Successful replacement affects future handshakes only.

#[path="tls_resolver/native_key.rs"]
mod native_key;
pub(crate) use native_key::{NativeCertificate,NativePrivateKey};
use crate::challenge::{ACME_ALPN, ChallengeRegistry, normalize_domain};
use crate::leaf_guard::{LeafGuard, LeafState, Observation, leaf_id};
use crate::tls_policy::certificate_selection::{CertificateFacts, CertificateFilter};
use anyhow::{Context, Result, anyhow, ensure};
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
    pub(crate) native:Option<NativeCertificate>,
    pub key: Arc<CertifiedKey>,
    pub(crate) instance: Option<CertificateInstance>,
    pub(crate) leaf_state: Option<Arc<LeafState>>,
    pub signature_compatibility: SignatureCompatibility,
}

/// Identifies the loaded instance which actually signed an accepted connection.
/// Reading this receipt never allocates a new publication generation.
#[derive(Clone, Copy)]
pub(crate) struct CertificateInstance {
    identity: [u8; 32],
    generation: u64,
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
    pub(crate) fn names(&self) -> &[String] { &self.names }
    pub(crate) fn owned_by(&self, owner: &CertificateScope) -> bool {
        Arc::ptr_eq(&self.owner.0, &owner.0)
    }
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }

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
    pub(crate) management_name: Arc<str>,
    pub(crate) chain_der: Vec<Vec<u8>>,
    pub(crate) leaf_state: Arc<LeafState>,
    pub(crate) leaf_sha256: [u8; 32],
    pub(crate) key_state: Arc<crate::key_compromise::KeyState>,
    // Last so all owned buffers die before their independent probe allowance.
    pub(crate) preparation: Option<Arc<crate::tls_app_config::CertificatePreparation>>,
}
pub(crate) struct OcspDescriptor {
    pub(crate) identity: [u8; 32],
    pub(crate) management_name: Arc<str>,
}
impl OcspCertificate {
    pub(crate) fn management_name(&self) -> &str { &self.management_name }
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
    native_key:Arc<NativePrivateKey>,
    managed_key_veto: bool,
    key_state: Arc<crate::key_compromise::KeyState>,
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
    signature_profile: Arc<SignatureProfile>,
    facts: Arc<CertificateFacts>,
    management_name: Arc<str>,
    san_names: Arc<Vec<String>>,
    // Content stage follows every immutable clone; rejected candidates keep
    // admission until the last real content owner is destroyed.
    preparation: Arc<crate::tls_app_config::CertificatePreparation>,
}

struct ResolverPreparations {
    tokens:Vec<Arc<crate::tls_app_config::CertificatePreparation>>,
    accepted:bool,
    _credit:crate::acme_wire::chain_memory::Scratch,
}
impl ResolverPreparations {
    fn new(count:usize)->Result<Self>{
        let bytes=count.checked_mul(std::mem::size_of::<Arc<crate::tls_app_config::CertificatePreparation>>())
            .and_then(|n|n.checked_add(64)).ok_or(crate::cert_transient::ResourceDenied)?;
        let credit=crate::cert_transient::reserve(bytes)?;
        let mut tokens=Vec::new();tokens.try_reserve_exact(count).map_err(|_|crate::cert_transient::ResourceDenied)?;
        Ok(Self{tokens,accepted:false,_credit:credit})
    }
    fn push(&mut self,preparation:&Arc<crate::tls_app_config::CertificatePreparation>){
        assert!(self.tokens.len()<self.tokens.capacity());self.tokens.push(preparation.clone());
    }
}
impl Drop for ResolverPreparations{
    fn drop(&mut self){if self.accepted {for token in &self.tokens {token.release();}}}
}

/// Prepay the temporary native snapshot maps/vectors before cloning them.
/// Accepted indexes transfer to the existing resolver alias/inventory bounds;
/// this does not turn those logical limits into a total resident-RSS semaphore.
fn index_credit<'a>(base:Option<&Snapshot>,incoming:impl Iterator<Item=&'a [String]>,extra_certificates:usize)
    ->Result<crate::acme_wire::chain_memory::Scratch>{
    use crate::cert_transient::{ResourceDenied,reserve};
    fn add(a:usize,b:usize)->Result<usize>{a.checked_add(b).ok_or_else(||ResourceDenied.into())}
    fn mul(a:usize,b:usize)->Result<usize>{a.checked_mul(b).ok_or_else(||ResourceDenied.into())}
    fn table(n:usize,record:usize)->Result<usize>{
        if n==0{return Ok(0)}
        // hashbrown's 7/8 load factor and power-of-two buckets; old+new
        // allocation coexist at growth. Include control bytes and alignment.
        let buckets=add(mul(n,8)?/7,4)?.checked_next_power_of_two().ok_or(ResourceDenied)?;
        add(mul(add(buckets,buckets/2)?,add(record,1)?)?,64)
    }
    let mut aliases=base.map_or(0,|s|s.names.len());
    let mut capacity=base.map_or(0,|s|s.names.capacity());
    let mut refs=0usize;let mut text=0usize;
    if let Some(base)=base {for(name,certificates)in &base.names{
        refs=add(refs,certificates.len())?;
        text=add(text,mul(name.len(),add(1,certificates.len())?)?)?;
    }}
    for names in incoming{aliases=add(aliases,names.len())?;refs=add(refs,names.len())?;
        for name in names{text=add(text,mul(name.len(),2)?)?}}
    capacity=capacity.max(aliases);
    let certificates=add(base.map_or(0,|s|s.inventory.len()),extra_certificates)?;
    let mut bytes=add(16384,text)?;
    bytes=add(bytes,table(capacity,std::mem::size_of::<(String,Vec<Arc<LoadedCertificate>>)>() )?)?;
    // Inventory, identity index, validation set and prune-staple maps are
    // all smaller than this record; six table peaks cover their overlap.
    bytes=add(bytes,mul(6,table(certificates,std::mem::size_of::<(u64,InventoryEntry)>())?)?)?;
    bytes=add(bytes,mul(add(mul(refs,3)?,mul(aliases,12)?)?,std::mem::size_of::<Arc<LoadedCertificate>>())?)?;
    bytes=add(bytes,mul(add(mul(refs,3)?,mul(certificates,12)?)?,std::mem::size_of::<String>())?)?;
    bytes=add(bytes,mul(certificates,std::mem::size_of::<LoadedCertificate>()+64)?)?;
    reserve(bytes)
}

/// Public inventory retains only the immutable base key, never an optional
/// stapled-key clone. Clearing a staple therefore cannot hide retained bytes
/// from its independent cache budget.
struct InventoryEntry {
    key_state: Arc<crate::key_compromise::KeyState>,
    key: Arc<CertifiedKey>,
    leaf_state: Arc<LeafState>,
    leaf_sha256: [u8; 32],
    identity: [u8; 32],
    generation: u64,
    names: Vec<String>,
    management_name: Arc<str>,
    residency: Option<Arc<CertificateResidency>>,
}
impl InventoryEntry {
    fn live(&self) -> bool {
        self.residency.as_ref().is_none_or(|slot| slot.live())
    }
    fn certificate(&self) -> OcspCertificate {
        OcspCertificate {
            preparation: None,
            identity: self.identity,
            generation: self.generation,
            names: self.names.clone(),
            management_name: self.management_name.clone(),
            chain_der: self
                .key
                .cert
                .iter()
                .map(|der| der.as_ref().to_vec())
                .collect(),
            leaf_state: self.leaf_state.clone(),
            leaf_sha256: self.leaf_sha256,
            key_state: self.key_state.clone(),
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
                    key_state: certificate.key_state.clone(),
                    key: certificate.key.clone(),
                    leaf_state: certificate.leaf_state.clone(),
                    leaf_sha256: certificate.leaf_sha256,
                    identity: certificate.identity,
                    generation: certificate.instance_generation,
                    names: Vec::new(),
                    management_name: certificate.management_name.clone(),
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

fn certificate_identity_inventory(inventory: &HashMap<u64, InventoryEntry>)
    -> Arc<HashMap<[u8; 32], u64>>
{
    let mut identities = HashMap::new();
    for entry in inventory.values() {
        identities.entry(entry.identity).and_modify(|generation: &mut u64| {
            *generation = (*generation).max(entry.generation);
        }).or_insert(entry.generation);
    }
    Arc::new(identities)
}

#[derive(Default)]
struct Snapshot {
    generation: u64,
    names: HashMap<String, Vec<Arc<LoadedCertificate>>>,
    inventory: Arc<HashMap<u64, InventoryEntry>>,
    identity_index: Arc<HashMap<[u8; 32], u64>>,
}

/// Each map is an immutable snapshot behind one short-held lock. Returning an
/// Arc keeps old signing material alive for handshakes/connections using it.
pub struct HotCertificateResolver {
    managed_keys: bool,
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
            managed_keys: false,
            challenges,
            leaf_guard,
            certificates: RwLock::new(Arc::new(Snapshot::default())),
            next_instance: AtomicU64::new(1),
            scope_identity: Arc::new(()),
        }
    }

    /// Administrative managed inventories use unscoped publication but still
    /// share the instance's key veto. Manual inventories keep their own mode.
    pub fn with_managed_leaf_guard(challenges: ChallengeRegistry, leaf_guard: Arc<LeafGuard>) -> Self {
        let mut resolver = Self::with_leaf_guard(challenges, leaf_guard);
        resolver.managed_keys = true;
        resolver
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
        let mut preparations=ResolverPreparations::new(inputs.len())?;
        let base = self
            .certificates
            .read()
            .map_err(|_| anyhow!("certificate state unavailable"))?
            .clone();
        let now = clock_now()?;
        let _indexes=index_credit(None,inputs.iter().map(|input|input.names),inputs.len())?;
        let mut bytes = 0usize;
        let mut next: HashMap<String, Vec<Arc<LoadedCertificate>>> = HashMap::new();
        for input in inputs {
            bytes = bytes
                .checked_add(input.certificate_pem.len())
                .and_then(|n| n.checked_add(input.private_key_pem.len()))
                .ok_or_else(|| anyhow!("certificate data limit exceeded"))?;
            ensure!(bytes <= MAX_TOTAL_BYTES, "certificate data limit exceeded");
            let (names, mut cert) = load_certificate(input, &self.leaf_guard)?;
            preparations.push(&cert.preparation);
            cert.managed_key_veto = self.managed_keys;
            if cert.managed_key_veto && cert.key_state.banned() { return Err(crate::key_compromise::KeyCompromised.into()); }
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
        if self.managed_keys && inventory.values().any(|entry|entry.key_state.banned()) {
            return Err(crate::key_compromise::KeyCompromised.into());
        }
        let previous = std::mem::replace(
            &mut *guard,
            Arc::new(Snapshot {
                generation,
                names: next,
                identity_index: certificate_identity_inventory(&inventory),
                inventory,
            }),
        );
        drop(guard);
        drop(previous);
        preparations.accepted=true;
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

    /// Warm replacement keeps the current connection's cached-selection
    /// constraints. Cold acquisition deliberately does not call this helper.
    /// The caller runs on the bounded certificate CPU worker before publication.
    pub(crate) fn candidate_allowed(
        &self,
        input: &CertificateInput<'_>,
        tags: &[String],
        filter: Option<&CertificateFilter>,
        schemes: &[SignatureScheme],
        version: Option<ProtocolVersion>,
    ) -> Result<bool> {
        let (_, certificate) = load_certificate(input, &self.leaf_guard)?;
        Ok(filter.is_none_or(|filter| filter.allows_tags(tags)
                && filter.allows_facts(&certificate.facts))
            && select_loaded(&certificate, schemes, version, clock_now()?).is_some())
    }

    /// Capture the actual selected managed instance. No name lookup may
    /// substitute another authority's certificate for this observation.
    pub(crate) fn scoped_instance(
        &self,
        instance: CertificateInstance,
    ) -> Option<(ScopedCertificate, Arc<CertificateResidency>)> {
        let snapshot = self.certificates.read().ok()?.clone();
        let inventory = snapshot.inventory.get(&instance.generation)?;
        if inventory.identity != instance.identity || !inventory.live() { return None; }
        let entry = snapshot.names.get(inventory.names.first()?)?.iter()
            .find(|entry| entry.instance_generation == instance.generation
                && entry.identity == instance.identity)?;
        let slot = entry.residency.clone()?;
        let owner = entry.owner.clone()?;
        Some((ScopedCertificate { resolver: self.scope_identity.clone(), owner,
            identity: instance.identity, instance_generation: instance.generation,
            names: inventory.names.clone() }, slot))
    }

    /// Exact current-publication metadata check; this does not select a
    /// certificate, allocate an instance or apply a new handshake policy.
    pub(crate) fn receipt_current(
        &self,
        receipt: &ScopedCertificate,
        slot: &Arc<CertificateResidency>,
    ) -> Result<bool> {
        if !Arc::ptr_eq(&receipt.resolver, &self.scope_identity) || !slot.live() {
            return Ok(false);
        }
        let snapshot = self.certificates.read()
            .map_err(|_| anyhow!("certificate state unavailable"))?.clone();
        Ok(snapshot.inventory.get(&receipt.instance_generation).is_some_and(|entry|
            entry.identity == receipt.identity && entry.names == receipt.names
                && entry.residency.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, slot))
                && entry.live()))
    }

    /// Validate a borrowed exact instance without replacing or reordering it.
    pub(crate) fn select_receipt(
        &self,
        receipt: &ScopedCertificate,
        slot: &Arc<CertificateResidency>,
        schemes: &[SignatureScheme],
        version: Option<ProtocolVersion>,
    ) -> Option<CertificateSelection> {
        if !Arc::ptr_eq(&receipt.resolver, &self.scope_identity)
            || receipt.names.is_empty() || !slot.live()
        { return None; }
        let snapshot = self.certificates.read().ok()?.clone();
        let exact = |entry: &&Arc<LoadedCertificate>| {
            entry.identity == receipt.identity
                && entry.instance_generation == receipt.instance_generation
                && entry.owner.as_ref().is_some_and(|owner| Arc::ptr_eq(&owner.0, &receipt.owner.0))
                && entry.residency.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, slot))
        };
        if !receipt.names.iter().all(|name| snapshot.names.get(name)
            .is_some_and(|entries| entries.iter().any(|entry| exact(&entry))))
        { return None; }
        let entry = snapshot.names.get(receipt.names.first()?)?.iter().find(exact)?;
        select_loaded(entry, schemes, version, clock_now().ok()?)
    }

    /// Validate a borrowed exact instance without replacing or reordering it.
    /// The hook keeps the same resolver -> ledger -> physical-cache lock order
    /// as publication. It must not perform I/O or acquire a resolver lock.
    pub(crate) fn with_current_receipt(
        &self,
        receipt: &ScopedCertificate,
        slot: &Arc<CertificateResidency>,
        cancel: &tokio_util::sync::CancellationToken,
        commit: impl FnOnce() -> Result<bool>,
    ) -> Result<Option<ScopedCertificate>> {
        ensure!(!cancel.is_cancelled(), "certificate publication cancelled");
        if !Arc::ptr_eq(&receipt.resolver, &self.scope_identity) || receipt.names.is_empty() {
            return Ok(None);
        }
        // instance_generation() allocates a publication ID. An existing
        // receipt is checked against snapshot instances, never the allocator.
        let guard = self.certificates.write()
            .map_err(|_| anyhow!("certificate state unavailable"))?;
        ensure!(!cancel.is_cancelled(), "certificate publication cancelled");
        if !slot.live() {
            return Ok(None);
        }
        let present = receipt.names.iter().all(|name| {
            guard.names.get(name).is_some_and(|candidates| {
                candidates.iter().any(|old| {
                    old.identity == receipt.identity
                        && old.instance_generation == receipt.instance_generation
                        && old.owner.as_ref().is_some_and(|owner| {
                            Arc::ptr_eq(&owner.0, &receipt.owner.0)
                        })
                        && old.residency.as_ref().is_some_and(|source| Arc::ptr_eq(source, slot))
                })
            })
        });
        if !present {
            return Ok(None);
        }
        if guard.inventory.get(&receipt.instance_generation).is_some_and(|entry|entry.key_state.banned()) {
            return Err(crate::key_compromise::KeyCompromised.into());
        }
        let admitted = commit()?;
        drop(guard);
        Ok(admitted.then(|| receipt.clone()))
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
        let mut preparations=ResolverPreparations::new(1)?;
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
        preparations.push(&cert.preparation);
        cert.managed_key_veto = self.managed_keys;
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
            let _indexes=index_credit(Some(&base),std::iter::once(names.as_slice()),1)?;
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
            let inventory = certificate_inventory(&next);
            let candidate = Arc::new(Snapshot {
                generation,
                identity_index: certificate_identity_inventory(&inventory),
                inventory,
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
            if (cert.managed_key_veto || cert.owner.is_some()) && cert.key_state.banned() {
                return Err(crate::key_compromise::KeyCompromised.into());
            }
            // The cache admission hook only commits short in-memory state;
            // all key validation and snapshot construction already succeeded.
            // Nothing fallible follows the hook in this publication.
            commit()?;
            let previous = std::mem::replace(&mut *guard, candidate);
            drop(guard);
            drop(previous);
            preparations.accepted=true;
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
            let inventory = certificate_inventory(&names);
            let candidate = Arc::new(Snapshot {
                generation: base
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("certificate generation exhausted"))?,
                identity_index: certificate_identity_inventory(&inventory),
                inventory,
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
            let inventory = certificate_inventory(&names);
            let next = Arc::new(Snapshot {
                generation: base
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("certificate generation exhausted"))?,
                identity_index: certificate_identity_inventory(&inventory),
                inventory,
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
    pub(crate) fn ocsp_descriptors(&self) -> Result<Vec<OcspDescriptor>> {
        let snapshot = self.certificates.read()
            .map_err(|_| anyhow!("certificate state unavailable"))?.clone();
        Ok(snapshot.identity_index.values().filter_map(|id| snapshot.inventory.get(id))
            .filter(|entry| entry.live()).map(|entry| OcspDescriptor {
                identity: entry.identity, management_name: entry.management_name.clone(),
            }).collect())
    }
    pub(crate) fn ocsp_descriptor(&self, identity: &[u8; 32]) -> Result<Option<OcspDescriptor>> {
        let snapshot = self.certificates.read()
            .map_err(|_| anyhow!("certificate state unavailable"))?.clone();
        Ok(snapshot.identity_index.get(identity).and_then(|id| snapshot.inventory.get(id))
            .filter(|entry| entry.live()).map(|entry| OcspDescriptor {
                identity: entry.identity, management_name: entry.management_name.clone(),
            }))
    }
    pub(crate) fn ocsp_current_certificate(&self, identity: &[u8; 32]) -> Result<Option<OcspCertificate>> {
        let snapshot = self.certificates.read()
            .map_err(|_| anyhow!("certificate state unavailable"))?.clone();
        Ok(snapshot.identity_index.get(identity).and_then(|id| snapshot.inventory.get(id))
            .filter(|entry| entry.live()).map(InventoryEntry::certificate))
    }
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
                identity_index: base.identity_index.clone(),
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
                native:None,
                key,
                instance: None,
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
                select_loaded(entry, signature_schemes, version, now)
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

fn select_loaded(
    entry: &LoadedCertificate,
    signature_schemes: &[SignatureScheme],
    version: Option<ProtocolVersion>,
    now: i64,
) -> Option<CertificateSelection> {
    if entry.residency.as_ref().is_some_and(|slot| !slot.live()) {
        return None;
    }
    // Scoped entries are managed publications; manual inventories have no
    // owner. A signed key veto immediately covers different leaves/stores.
    if (entry.managed_key_veto || entry.owner.is_some()) && entry.key_state.banned() {
        return None;
    }
    let admission = entry.leaf_state.admission();
    if !admission.allow_certificate || now < entry.not_before || now >= entry.not_after {
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
        native:Some(NativeCertificate{private:entry.native_key.clone(),leaf:entry.leaf_state.clone(),key_state:entry.key_state.clone(),enforce_key_veto:entry.managed_key_veto||entry.owner.is_some(),not_after:entry.not_after}),
        key,
        instance: Some(CertificateInstance {
            identity: entry.identity,
            generation: entry.instance_generation,
        }),
        leaf_state: Some(entry.leaf_state.clone()),
        signature_compatibility: if entry.tls13_key.is_some() {
            SignatureCompatibility::Tls12Or13
        } else {
            SignatureCompatibility::Tls12Only
        },
    })
}

pub(crate) enum PolicyMatch {
    NoViable,
    Unusable,
    Selected(CertificateSelection, bool),
}

pub(crate) struct PolicyQuery<'a> {
    filter: Option<&'a CertificateFilter>,
    offered_name: Option<&'a str>,
    signature_schemes: &'a [SignatureScheme],
    version: Option<ProtocolVersion>,
    now: i64,
}

impl<'a> PolicyQuery<'a> {
    pub(crate) fn new(
        filter: Option<&'a CertificateFilter>,
        offered_name: Option<&'a str>,
        signature_schemes: &'a [SignatureScheme],
        version: Option<ProtocolVersion>,
    ) -> Option<Self> {
        if version.is_some_and(|version| {
            !matches!(version, ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3)
        }) {
            return None;
        }
        Some(Self {
            filter,
            offered_name,
            signature_schemes,
            version,
            now: clock_now().ok()?,
        })
    }
}

pub(crate) struct PolicyInventory(Arc<Snapshot>);

impl PolicyInventory {
    /// One inventory lookup and one bounded alias bucket. Existing connections
    /// validate their signed instance instead of rerunning global preference.
    pub(crate) fn select_pinned(
        &self,
        instance: CertificateInstance,
        allow_reloaded_identity: bool,
        query: &PolicyQuery<'_>,
        allowed: impl Fn(&[u8; 32], &[String]) -> bool,
    ) -> PolicyMatch {
        let current = self.0.inventory.get(&instance.generation)
            .filter(|entry| entry.identity == instance.identity)
            .or_else(|| {
                if !allow_reloaded_identity { return None; }
                self.0.inventory.get(self.0.identity_index.get(&instance.identity)?)
                    .filter(|entry| entry.identity == instance.identity)
            });
        let entry = current.and_then(|current| self.0.names.get(current.names.first()?)
            .and_then(|entries| entries.iter().find(|entry| {
                entry.instance_generation == current.generation
                    && entry.identity == instance.identity
            })));

        self.scan(entry.into_iter().map(|entry| entry.as_ref()), query, allowed)
    }

    /// Raw presence is checked before tags, algorithms, age, or scope
    /// permissions. A filtered list is not an absent name.
    pub(crate) fn has_name(&self, name: &str) -> bool {
        self.0
            .names
            .get(name)
            .is_some_and(|entries| !entries.is_empty())
    }

    pub(crate) fn select_named(
        &self,
        name: &str,
        query: &PolicyQuery<'_>,
        allowed: impl Fn(&[u8; 32], &[String]) -> bool,
    ) -> PolicyMatch {
        let entries = self
            .0
            .names
            .get(name)
            .into_iter()
            .flatten()
            .map(Arc::as_ref);
        self.scan(entries, query, allowed)
    }

    pub(crate) fn select_global(
        &self,
        query: &PolicyQuery<'_>,
        allowed: impl Fn(&[u8; 32], &[String]) -> bool,
    ) -> PolicyMatch {
        // The existing immutable inventory deduplicates SAN aliases. Resolve
        // each entry from its first alias; that bucket has at most eight
        // revisions. This scans at most once per selector query and never
        // copies certificates, stacks, or optional staples.
        let entries = self.0.inventory.values().filter_map(|item| {
            self.0
                .names
                .get(item.names.first()?)?
                .iter()
                .find(|entry| entry.instance_generation == item.generation)
                .map(Arc::as_ref)
        });
        self.scan(entries, query, allowed)
    }

    fn scan<'a>(
        &self,
        entries: impl Iterator<Item = &'a LoadedCertificate>,
        query: &PolicyQuery<'_>,
        allowed: impl Fn(&[u8; 32], &[String]) -> bool,
    ) -> PolicyMatch {
        let mut viable = false;
        let mut best_effort = None;
        for entry in entries {
            if query
                .filter
                .is_some_and(|filter| !filter.allows_facts(&entry.facts))
            {
                continue;
            }
            let Some(inventory) = self.0.inventory.get(&entry.instance_generation) else {
                continue;
            };
            if !allowed(&entry.identity, &inventory.names) {
                continue;
            }
            viable = true;
            let preferred = query
                .offered_name
                .is_none_or(|name| entry.san_names.iter().any(|san| covers(san, name)));
            if !preferred && best_effort.is_some() {
                continue;
            }
            if let Some(selection) =
                select_loaded(entry, query.signature_schemes, query.version, query.now)
            {
                if preferred {
                    return PolicyMatch::Selected(selection, true);
                }
                best_effort = Some(selection);
            }
        }
        if let Some(selection) = best_effort {
            PolicyMatch::Selected(selection, false)
        } else if viable {
            PolicyMatch::Unusable
        } else {
            PolicyMatch::NoViable
        }
    }
}

impl HotCertificateResolver {
    pub(crate) fn policy_inventory(&self) -> Option<PolicyInventory> {
        Some(PolicyInventory(self.certificates.read().ok()?.clone()))
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

pub(crate) fn certificate_management_name(leaf: &x509_parser::certificate::X509Certificate<'_>) -> anyhow::Result<std::sync::Arc<str>> {
    if let Some(attribute) = leaf.subject().iter_common_name().last() {
        let value = crate::tls_policy::certificate_selection::attribute_string(attribute)
            .ok_or_else(|| anyhow::anyhow!("failed to decode CommonName attribute"))?;
        if !value.is_empty() {
            let lowered = value.chars().map(|ch| ch.to_lowercase().next().unwrap_or(ch)).collect::<String>();
            return Ok(std::sync::Arc::from(lowered));
        }
    }

    let san_ext = leaf.subject_alternative_name()?;
    if let Some(ext) = san_ext {
        let general_names = &ext.value.general_names;

        for gn in general_names {
            if let x509_parser::extensions::GeneralName::DNSName(s) = gn {
                let lowered: String = s.chars().map(|c| c.to_lowercase().next().unwrap_or(c)).collect();
                if !lowered.is_empty() {
                    return Ok(std::sync::Arc::from(lowered.as_str()));
                }
            }
        }

        for gn in general_names {
            if let x509_parser::extensions::GeneralName::IPAddress(ip_bytes) = gn {
                let ip_addr = match ip_bytes.len() {
                    4 => {
                        let arr: [u8; 4] = (*ip_bytes).try_into().map_err(|_| anyhow::anyhow!("invalid IPv4 address length in SAN"))?;
                        std::net::IpAddr::from(arr)
                    }
                    16 => {
                        let arr: [u8; 16] = (*ip_bytes).try_into().map_err(|_| anyhow::anyhow!("invalid IPv6 address length in SAN"))?;
                        std::net::IpAddr::from(arr)
                    }
                    _ => continue,
                };
                let canonical = canonical_certificate_ip(ip_addr);
                return Ok(std::sync::Arc::from(canonical.as_str()));
            }
        }
    }

    Err(anyhow::anyhow!("no suitable name found in certificate"))
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
    let blocks = crate::cert_transient::certificate_blocks(input.certificate_pem)?;
    let mut output=65536usize;
    for (_,der) in &blocks {
        // Two certified-chain DER copies, serial/SPKI/organization/SAN owned
        // facts and their conversion buffers. The same pinned typed shape
        // bounds collection records; primitive UTF-8 conversions are <=4x DER.
        let shape=crate::acme_wire::chain_deep_shape::full_cost(der)?;
        output=output.checked_add(der.len().checked_mul(4).ok_or(crate::cert_transient::ResourceDenied)?)
            .and_then(|n|shape.checked_mul(2).and_then(|shape|n.checked_add(shape)))
            .ok_or(crate::cert_transient::ResourceDenied)?;
    }
    for name in input.names {output=output.checked_add(name.len().checked_mul(8).ok_or(crate::cert_transient::ResourceDenied)?+8*std::mem::size_of::<String>()).ok_or(crate::cert_transient::ResourceDenied)?;}
    output=output.checked_add(crate::cert_transient::key_decode_bound(input.private_key_pem)?).ok_or(crate::cert_transient::ResourceDenied)?;
    let native_key_cost=NativePrivateKey::retained_bound(input.private_key_pem)?;
    output=output.checked_add(native_key_cost).ok_or(crate::cert_transient::ResourceDenied)?;
    let preparation=crate::tls_app_config::CertificatePreparation::reserve(output)?;
    let mut chain = Vec::with_capacity(blocks.len());
    for (label, der) in &blocks {
        ensure!(label == "CERTIFICATE", "unexpected certificate PEM label");
        let (remaining, _) = crate::cert_transient::parse_certificate(der)
            .context("invalid certificate DER")?;
        ensure!(remaining.is_empty(), "trailing certificate DER");
        chain.push(CertificateDer::from(der.to_vec()));
    }
    let preferred = crate::cert_transient::signing_key(input.private_key_pem, "tls-candidate")?;
    let key = crate::crypto::tls12_signer(&preferred, input.private_key_pem)?;
    let identity = certificate_chain_identity(&chain);
    let certified = CertifiedKey::new(chain, key);
    crate::certmagic::check_keys_match(&certified,"tls-candidate")?;
    let (_, leaf) = crate::cert_transient::parse_certificate(&blocks[0].1)
        .context("invalid leaf certificate")?;
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
    let facts = Arc::new(CertificateFacts::from_leaf(&leaf));
    let management_name = certificate_management_name(&leaf)?;
    let native_key=NativePrivateKey::new(input.private_key_pem,preparation.clone())?;
    let size = input
        .certificate_pem
        .len()
        .checked_add(input.private_key_pem.len())
        .and_then(|v| v.checked_add(extra_key_bytes))
        .and_then(|v|v.checked_add(native_key_cost))
        .and_then(|v| v.checked_add(facts.retained_bytes()))
        .and_then(|v| v.checked_add(leaf.public_key().raw.len()))
        .and_then(|v| v.checked_add(management_name.len() + 2 * std::mem::size_of::<usize>()))
        .and_then(|v| v.checked_add(san_names.capacity() * std::mem::size_of::<String>()))
        .and_then(|v| v.checked_add(san_names.iter().map(String::capacity).sum::<usize>()))
        .ok_or_else(|| anyhow!("certificate size overflow"))?;
    let leaf_sha256 = leaf_id(&blocks[0].1);
    Ok((
        names,
        LoadedCertificate {
            native_key,
            managed_key_veto: false,
            key_state: leaf_guard.key_deny().register_spki(Arc::from(leaf.public_key().raw))?,
            key,
            tls13_key,
            leaf_state: leaf_guard.intern(leaf_sha256, leaf.validity().not_after.timestamp())?,
            leaf_sha256,
            identity,
            instance_generation: 0,
            owner: None,
            residency: None,
            staple: None,
            signature_profile:Arc::new(signature_profile),
            facts,
            management_name,
            san_names: Arc::new(san_names),
            size,
            not_before: leaf.validity().not_before.timestamp(),
            not_after: leaf.validity().not_after.timestamp(),
            preparation,
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
        .filter(|old| old.identity == cert.identity && old.signature_profile==cert.signature_profile)
        .filter_map(|old| old.staple.as_ref())
        .filter(|staple| staple.valid_until > now)
        .max_by_key(|staple| staple.valid_until)
    else {
        return;
    };
    if staple.key.ocsp.is_some() {cert.staple=Some(staple.clone());}
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
                .checked_add(cert.size).and_then(|size| size.checked_add(96))
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
