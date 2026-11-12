//! Bounded validated dynamic business material shared across configuration generations.
//! A candidate plans its view without changing the active epoch. Only commit
//! changes the epoch; stale issuance and cleanup cannot mutate its successor.
use super::material::Material;
use crate::tls_resolver::CertificateResidency;
use anyhow::{Result, ensure};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// This is a separate, transient preparation-output allowance. The cache's
// BYTE_CAPACITY below counts admitted snapshots; it cannot prepay allocations
// which happen before a candidate has been validated and admitted.
const PREPARATION_CAPACITY: usize = 64 * 1024 * 1024;
static PREPARATION_BYTES: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Preparation {
    bytes: usize,
    released: AtomicBool,
}

impl Preparation {
    pub(crate) fn reserve(bytes: usize) -> Result<Arc<Self>> {
        ensure!(bytes <= PREPARATION_CAPACITY, crate::cert_transient::ResourceDenied);
        PREPARATION_BYTES.try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            used.checked_add(bytes).filter(|next| *next <= PREPARATION_CAPACITY)
        }).map_err(|_| crate::cert_transient::ResourceDenied)?;
        Ok(Arc::new(Self { bytes, released: AtomicBool::new(false) }))
    }

    pub(crate) fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            let before = PREPARATION_BYTES.fetch_sub(self.bytes, Ordering::AcqRel);
            debug_assert!(before >= self.bytes, "certificate preparation accounting underflow");
        }
    }
}

impl Drop for Preparation {
    fn drop(&mut self) { self.release(); }
}

/// Declare before entering the resolver/capacity/cache publication locks.
/// Recording acceptance never returns credits or wakes another worker. Drop
/// transfers only the exact accepted material's allowance after those locks
/// have unwound, including on cancellation or a later publication error.
#[derive(Default)]
pub(super) struct PreparationPublication {
    accepted: Option<Arc<Preparation>>,
}

impl PreparationPublication {
    pub(super) fn accepted(&mut self, preparation: Option<&Arc<Preparation>>) {
        let Some(preparation) = preparation else { return; };
        match &self.accepted {
            Some(previous) => assert!(Arc::ptr_eq(previous, preparation),
                "one certificate publication accepted different preparations"),
            None => self.accepted = Some(preparation.clone()),
        }
    }
}

impl Drop for PreparationPublication {
    fn drop(&mut self) {
        if let Some(preparation) = &self.accepted { preparation.release(); }
    }
}

#[derive(Clone)]
pub(super) struct Receipt {
    pub chain: [u8; 32],
    pub id: u64,
    pub slot: Arc<CertificateResidency>,
    pub revision: Arc<CertificateResidency>,
}
impl Receipt {
    pub(super) fn is(&self, entry: &CacheEntry) -> bool {
        self.chain == entry.material.identity
            && self.id == entry.id
            && Arc::ptr_eq(&self.slot, &entry.slot)
            && Arc::ptr_eq(&self.revision, &entry.revision)
    }
}

#[derive(Copy, Clone)]
pub(super) enum Effect {
    Fresh,
    Same,
    Renewed,
    Merged { retired: u64 },
}

pub(super) struct CacheEntry {
    pub(super) id: u64,
    pub(super) material: Arc<Material>,
    pub(super) issuer: String,
    pub(super) origin: String,
    pub(super) renew_at: i64,
    pub(super) ari_after: i64,
    pub(super) slot: Arc<CertificateResidency>,
    pub(super) revision: Arc<CertificateResidency>,
    pub(super) import_gate: tokio::sync::Mutex<()>,
    birth_epoch: u64,
}

impl CacheEntry {
    pub(super) fn receipt(&self) -> Receipt {
        Receipt {
            chain: self.material.identity,
            id: self.id,
            slot: self.slot.clone(),
            revision: self.revision.clone(),
        }
    }
}

pub(super) struct Revision {
    pub(super) material: Arc<Material>,
    pub(super) issuer: String,
    pub(super) origin: String,
    pub(super) renew_at: i64,
    pub(super) ari_after: i64,
}

pub(super) struct Publication {
    pub(super) entry: Arc<CacheEntry>,
    epoch: Arc<Epoch>,
    expected_old: Option<Arc<CacheEntry>>,
    expected_target: Option<Arc<CacheEntry>>,
    capacity: usize,
    effect: Effect,
}

impl Publication {
    pub(super) fn receipt(&self) -> Receipt {
        self.entry.receipt()
    }

    pub(super) fn effect(&self) -> Effect {
        self.effect
    }
}

#[derive(Debug)]
pub(super) struct CacheChanged;
impl std::fmt::Display for CacheChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate cache slot or generation changed; retry required")
    }
}
impl std::error::Error for CacheChanged {}

const BYTE_CAPACITY: usize = 64 * 1024 * 1024;

fn bytes(entry: &CacheEntry) -> usize {
    // Each admitted leaf/key pair is bounded before resolver publication.
    entry.material.certificate.len() + entry.material.key.len()
        + entry.material.retained_san_bytes()
}

pub(super) struct Epoch {
    pub(super) id: u64,
    pub(super) registered: HashMap<String, String>,
    pub(super) blocked: HashSet<u64>,
    pub(super) removed: HashMap<String, String>,
    pub(super) enabled: bool,
}

struct State {
    active: Arc<Epoch>,
    entries: HashMap<[u8; 32], Arc<CacheEntry>>,
    order: Vec<[u8; 32]>,
    bytes: usize,
    next_id: u64,
    next_epoch: u64,
}

pub(super) struct ResidentCache {
    state: Mutex<State>,
    events: tokio::sync::broadcast::Sender<u64>,
}

fn is_eligible(epoch: &Epoch, entry: &CacheEntry) -> bool {
    if !epoch.enabled || !entry.slot.live() || !entry.revision.live() {
        return false;
    }
    if epoch.blocked.contains(&entry.id) {
        return false;
    }
    if entry.birth_epoch < epoch.id {
        for name in &entry.material.names {
            if epoch.removed.get(name) == Some(&entry.issuer) {
                return false;
            }
        }
    }
    true
}

impl ResidentCache {
    pub(super) fn new() -> Self {
        let active = Arc::new(Epoch {
            id: 0,
            registered: HashMap::new(),
            blocked: HashSet::new(),
            removed: HashMap::new(),
            enabled: true,
        });
        Self {
            events: tokio::sync::broadcast::channel(4096).0,
            state: Mutex::new(State {
                active,
                entries: HashMap::new(),
                order: Vec::new(),
                bytes: 0,
                next_id: 0,
                next_epoch: 1,
            }),
        }
    }

    pub(super) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<u64> {
        self.events.subscribe()
    }

    pub(super) fn prepare(
        &self,
        registered: HashMap<String, String>,
        enabled: bool,
    ) -> Result<(Arc<Epoch>, Vec<Arc<CacheEntry>>)> {
        let (old_epoch, entry_arcs, new_epoch_id) = {
            let mut st = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
            let old = st.active.clone();
            // Preserve global insertion order to keep candidate ordering stable
            // across generation boundaries (mirroring Go's slice index order).
            let entries: Vec<Arc<CacheEntry>> = st
                .order
                .iter()
                .filter_map(|key| st.entries.get(key).cloned())
                .collect();
            let eid = st.next_epoch;
            st.next_epoch = st
                .next_epoch
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("epoch overflow"))?;
            (old, entries, eid)
        };

        // Only the current cache IDs are carried forward. Superseded issuers
        // cannot insert into this epoch, so no unbounded tombstone history is
        // needed to keep already removed material from reappearing.
        let removed = old_epoch
            .registered
            .iter()
            .filter(|(name, issuer)| registered.get(*name) != Some(*issuer))
            .map(|(name, issuer)| (name.clone(), issuer.clone()))
            .collect();
        let blocked = entry_arcs
            .iter()
            .filter(|entry| !is_eligible(&old_epoch, entry))
            .map(|entry| entry.id)
            .collect();
        let new_epoch = Arc::new(Epoch {
            id: new_epoch_id,
            registered,
            blocked,
            removed,
            enabled,
        });
        let candidates = entry_arcs
            .into_iter()
            .filter(|entry| is_eligible(&new_epoch, entry))
            .collect();

        Ok((new_epoch, candidates))
    }

    pub(super) fn activate(&self, epoch: Arc<Epoch>) -> Arc<Epoch> {
        let mut st = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::replace(&mut st.active, epoch)
    }

    pub(super) fn is_active(&self, epoch: &Arc<Epoch>) -> Result<bool> {
        let state = self.state.lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        Ok(Arc::ptr_eq(&state.active, epoch))
    }

    pub(super) fn plan(
        &self,
        epoch: &Arc<Epoch>,
        revision: Revision,
        capacity: usize,
        previous: Option<&Receipt>,
    ) -> Result<Option<Publication>> {
        let mut st = self.state.lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if !Arc::ptr_eq(&st.active, epoch) || !epoch.enabled {
            return Ok(None);
        }
        ensure!(capacity > 0, "invalid managed cache capacity");
        let chain = revision.material.identity;
        let target = st.entries.get(&chain).cloned();
        let old = if let Some(previous) = previous {
            let old = st.entries.get(&previous.chain).filter(|entry| {
                previous.is(entry)
                    && is_eligible(epoch, entry)
            }).ok_or(CacheChanged)?;
            Some(old.clone())
        } else {
            None
        };
        let usable_target = target.as_ref().filter(|entry| is_eligible(epoch, entry));
        let reused = match (&old, usable_target) {
            (None, Some(target)) => Some((Effect::Same, target.clone())),
            (Some(old), Some(target)) if old.material.identity != chain => {
                Some((Effect::Merged { retired: old.id }, target.clone()))
            }
            _ => None,
        };
        let (effect, entry) = if let Some(reused) = reused {
            reused
        } else {
            let (effect, id, birth_epoch, slot, revision_slot) = if let Some(old) = &old {
                (Effect::Renewed, old.id, old.birth_epoch, old.slot.clone(), Arc::new(old.slot.projection()))
            } else {
                let id = st.next_id;
                st.next_id = id.checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("certificate cache slot IDs exhausted"))?;
                let slot = Arc::new(CertificateResidency::default());
                (Effect::Fresh, id, epoch.id, slot.clone(), Arc::new(slot.projection()))
            };
            let entry = Arc::new(CacheEntry {
                id, birth_epoch, slot, revision: revision_slot,
                import_gate: tokio::sync::Mutex::new(()),
                material: revision.material,
                issuer: revision.issuer,
                origin: revision.origin,
                renew_at: revision.renew_at,
                ari_after: revision.ari_after,
            });
            (effect, entry)
        };
        ensure!(bytes(&entry) <= BYTE_CAPACITY, "resident certificate byte capacity exceeded");
        Ok(Some(Publication {
            entry, epoch: epoch.clone(), expected_old: old,
            expected_target: target, capacity, effect,
        }))
    }

    /// Runs only after resolver validation; the hook performs no I/O or await.
    pub(super) fn commit(&self, plan: Publication) -> Result<()> {
        self.commit_replacing(plan, None)
    }

    pub(super) fn commit_prepared(
        &self,
        plan: Publication,
        victim: Option<(&[String], &Arc<CertificateResidency>)>,
        publication: &mut PreparationPublication,
    ) -> Result<()> {
        let preparation = plan.entry.material.preparation.clone();
        self.commit_replacing(plan, victim)?;
        publication.accepted(preparation.as_ref());
        Ok(())
    }

    pub(super) fn commit_replacing(
        &self,
        plan: Publication,
        victim: Option<(&[String], &Arc<CertificateResidency>)>,
    ) -> Result<()> {
        let mut st = self.state.lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if !Arc::ptr_eq(&st.active, &plan.epoch)
            || !plan.entry.slot.live()
            || !plan.entry.revision.live()
        {
            return Err(CacheChanged.into());
        }
        if let Some(old) = &plan.expected_old {
            ensure!(st.entries.get(&old.material.identity)
                .is_some_and(|actual| Arc::ptr_eq(actual, old)), CacheChanged);
        }
        let target_matches = match (
            &plan.expected_target, st.entries.get(&plan.entry.material.identity)
        ) {
            (Some(expected), Some(actual)) => Arc::ptr_eq(expected, actual),
            (None, None) => true,
            _ => false,
        };
        ensure!(target_matches, CacheChanged);
        let mut removed: Vec<Arc<CacheEntry>> = Vec::new();
        if !matches!(plan.effect, Effect::Same)
            && let Some(old) = &plan.expected_old
        {
            removed.push(old.clone());
        }
        if let Some(target) = &plan.expected_target
            && !Arc::ptr_eq(target, &plan.entry)
            && !removed.iter().any(|entry| Arc::ptr_eq(entry, target))
        {
            removed.push(target.clone());
        }
        let protected = |entry: &Arc<CacheEntry>| {
            entry.material.identity == plan.entry.material.identity
                || plan.expected_old.as_ref().is_some_and(|old| Arc::ptr_eq(old, entry))
                || plan.expected_target.as_ref().is_some_and(|old| Arc::ptr_eq(old, entry))
        };
        if let Some((_, source)) = victim
            && let Some(victim) = st.entries.values().find(|entry| {
                Arc::ptr_eq(&entry.slot, source) && !protected(entry)
                    && !removed.iter().any(|old| Arc::ptr_eq(old, entry))
            })
        {
            removed.push(victim.clone());
        }
        let add_new = usize::from(matches!(plan.effect, Effect::Fresh | Effect::Renewed));
        let mut count = st.entries.len().checked_sub(removed.len())
            .and_then(|count| count.checked_add(add_new))
            .ok_or_else(|| anyhow::anyhow!("resident certificate count accounting failed"))?;
        let mut size = st.bytes;
        for entry in &removed {
            size = size.checked_sub(bytes(entry))
                .ok_or_else(|| anyhow::anyhow!("resident certificate byte accounting failed"))?;
        }
        if add_new > 0 {
            size = size.checked_add(bytes(&plan.entry))
                .ok_or_else(|| anyhow::anyhow!("resident certificate byte accounting failed"))?;
        }
        let (mut ineligible, mut eligible): (Vec<_>, Vec<_>) = st.entries.values()
            .filter(|entry| !protected(entry)
                && !removed.iter().any(|old| Arc::ptr_eq(old, entry)))
            .cloned().partition(|entry| !is_eligible(&plan.epoch, entry));
        while count > plan.capacity || size > BYTE_CAPACITY {
            let victim = if let Some(victim) = ineligible.pop() {
                victim
            } else {
                let index = random_index(eligible.len())?;
                eligible.swap_remove(index)
            };
            count = count.checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("resident certificate count accounting failed"))?;
            size = size.checked_sub(bytes(&victim))
                .ok_or_else(|| anyhow::anyhow!("resident certificate byte accounting failed"))?;
            removed.push(victim);
        }
        // No fallible work follows. A normal renewal keeps the source slot alive.
        let mut retired = Vec::new();
        for entry in removed {
            st.entries.remove(&entry.material.identity);
            st.order.retain(|chain| *chain != entry.material.identity);

            // Check if slots are the same physical residency (S)
            let same_slot = Arc::ptr_eq(&entry.slot, &plan.entry.slot);

            if !Arc::ptr_eq(&entry.revision, &plan.entry.revision) {
                entry.revision.retire();
                retired.push(entry.id);
            }

            // Retire the slot (S) ONLY if it is NOT the new entry's slot (S)
            // If they are the same slot, we preserved S for the new entry (plan.entry.slot).
            // If they are different, we must retire the old S.
            if !same_slot {
                entry.slot.retire();
            }
        }
        if add_new > 0 {
            let chain = plan.entry.material.identity;
            st.entries.insert(chain, plan.entry);
            st.order.push(chain);
        }
        st.bytes = size;
        drop(st);
        for id in retired {
            let _ = self.events.send(id);
        }
        Ok(())
    }

    pub(super) fn valid_import(&self, epoch: &Arc<Epoch>, entry: &Arc<CacheEntry>) -> Result<()> {
        self.commit_import(epoch, entry, None)
    }

    /// Verify the exact imported source. Only the actual active epoch may
    /// retire an exact shared victim; a candidate changes its own projection.
    pub(super) fn commit_import(
        &self,
        epoch: &Arc<Epoch>,
        entry: &Arc<CacheEntry>,
        victim: Option<(&[String], &Arc<CertificateResidency>)>,
    ) -> Result<()> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if epoch.id < st.active.id
            || !is_eligible(epoch, entry)
            || !st
                .entries
                .get(&entry.material.identity)
                .is_some_and(|actual| Arc::ptr_eq(actual, entry))
        {
            return Err(CacheChanged.into());
        }
        let removed = if Arc::ptr_eq(&st.active, epoch) {
            remove_projection_source(&mut st, victim)?
        } else {
            None
        };
        drop(st);
        if let Some(id) = removed {
            let _ = self.events.send(id);
        }
        Ok(())
    }

    pub(super) fn retire_projection(
        &self,
        epoch: &Arc<Epoch>,
        victim: Option<(&[String], &Arc<CertificateResidency>)>,
    ) -> Result<()> {
        if victim.is_none() {
            return Ok(());
        }
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if !Arc::ptr_eq(&st.active, epoch) {
            return Ok(());
        }
        let removed = remove_projection_source(&mut st, victim)?;
        drop(st);
        if let Some(id) = removed {
            let _ = self.events.send(id);
        }
        Ok(())
    }

    pub(super) fn snapshot(&self, epoch: &Arc<Epoch>) -> Result<Vec<Arc<CacheEntry>>> {
        let st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if epoch.id < st.active.id {
            return Ok(vec![]);
        }
        // Return in global insertion order
        let mut result = Vec::with_capacity(st.entries.len());
        for key in &st.order {
            if let Some(entry) = st.entries.get(key) {
                if is_eligible(epoch, entry) {
                    result.push(entry.clone());
                }
            }
        }
        Ok(result)
    }

    pub(super) fn current(&self, epoch: &Arc<Epoch>, entry: &Arc<CacheEntry>) -> Result<bool> {
        let st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        Ok(Arc::ptr_eq(&st.active, epoch)
            && is_eligible(epoch, entry)
            && st
                .entries
                .get(&entry.material.identity)
                .is_some_and(|actual| Arc::ptr_eq(actual, entry)))
    }

    pub(super) fn find(&self, epoch: &Arc<Epoch>, query: &str) -> Result<Option<Arc<CacheEntry>>> {
        let entries = self.snapshot(epoch)?;
        // Exact match on names
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.material.names.iter().any(|name| name == query))
        {
            return Ok(Some(entry.clone()));
        }
        // Single-label wildcard (not IP)
        if query.parse::<std::net::IpAddr>().is_err()
            && let Some((_, suffix)) = query.split_once('.')
        {
            let wildcard = format!("*.{suffix}");
            return Ok(entries
                .into_iter()
                .find(|entry| entry.material.names.contains(&wildcard)));
        }

        Ok(None)
    }

    pub(super) fn remove(&self, epoch: &Arc<Epoch>, entry: &Arc<CacheEntry>) -> Result<bool> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if !Arc::ptr_eq(&st.active, epoch) {
            return Ok(false);
        }
        let identity = &entry.material.identity;
        if st
            .entries
            .get(identity)
            .is_some_and(|actual| Arc::ptr_eq(actual, entry))
        {
            let remaining = st
                .bytes
                .checked_sub(bytes(entry))
                .ok_or_else(|| anyhow::anyhow!("resident cache accounting failed"))?;

            entry.revision.retire();
            entry.slot.retire();

            st.bytes = remaining;
            st.entries.remove(identity);
            if let Some(pos) = st.order.iter().position(|k| *k == *identity) {
                st.order.remove(pos);
            }
            drop(st);
            let _ = self.events.send(entry.id);
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn prune(&self, epoch: &Arc<Epoch>) -> Result<()> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if !Arc::ptr_eq(&st.active, epoch) {
            return Ok(());
        }
        let mut victims = Vec::new();
        let mut new_entries = HashMap::new();
        let mut new_order = Vec::new();
        let mut new_bytes = 0usize;

        for key in st.order.iter() {
            if let Some(entry) = st.entries.get(key) {
                if is_eligible(epoch, entry) {
                    new_entries.insert(*key, entry.clone());
                    new_order.push(*key);
                    new_bytes += bytes(entry);
                } else {
                    entry.revision.retire();
                    entry.slot.retire();
                    victims.push(entry.clone());
                }
            }
        }

        st.entries = new_entries;
        st.order = new_order;
        st.bytes = new_bytes;

        drop(st);
        for victim in victims {
            let _ = self.events.send(victim.id);
        }
        Ok(())
    }
}

fn remove_projection_source(
    state: &mut State,
    victim: Option<(&[String], &Arc<CertificateResidency>)>,
) -> Result<Option<u64>> {
    let Some((names, source)) = victim else {
        return Ok(None);
    };

    // Find entry by identity where slot matches
    let mut found_id: Option<u64> = None;
    let mut found_key: Option<[u8; 32]> = None;

    for (key, entry) in state.entries.iter() {
        // Check names match the victim names (exact set comparison)
        // Source is compared against the Physical Slot (S)
        if entry.material.names == *names && Arc::ptr_eq(&entry.slot, source) {
            found_id = Some(entry.id);
            found_key = Some(*key);
            break;
        }
    }

    let Some(id) = found_id else {
        return Ok(None);
    };
    let Some(key) = found_key else {
        return Ok(None);
    };

    let entry = state.entries.get(&key).unwrap(); // Safe: just found it
    let remaining = state
        .bytes
        .checked_sub(bytes(entry))
        .ok_or_else(|| anyhow::anyhow!("resident cache accounting failed"))?;

    entry.revision.retire();
    entry.slot.retire();
    state.bytes = remaining;
    state.entries.remove(&key);
    if let Some(pos) = state.order.iter().position(|k| *k == key) {
        state.order.remove(pos);
    }

    Ok(Some(id))
}

/// Uniform selection with bounded rejection, using the already configured OS
/// random source. This never changes TLS cipher or signature policy.
pub(super) fn random_index(len: usize) -> Result<usize> {
    ensure!(len > 0, "empty managed cache eviction set");
    let width = u64::try_from(len)?;
    let limit = u64::MAX - u64::MAX % width;
    for _ in 0..8 {
        let mut raw = [0u8; 8];
        crate::crypto::provider()
            .secure_random
            .fill(&mut raw)
            .map_err(|_| anyhow::anyhow!("managed cache random source unavailable"))?;
        let value = u64::from_le_bytes(raw);
        if value < limit {
            return Ok((value % width) as usize);
        }
    }
    Err(anyhow::anyhow!("managed cache random selection exhausted"))
}
