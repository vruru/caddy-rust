//! Bounded validated dynamic business material shared across configuration generations.
//! A candidate plans its view without changing the active epoch. Only commit
//! changes the epoch; stale issuance and cleanup cannot mutate its successor.
use super::material::Material;
use crate::tls_resolver::CertificateResidency;
use anyhow::{Result, ensure};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub(super) struct CacheEntry {
    pub(super) id: u64,
    pub(super) material: Arc<Material>,
    pub(super) issuer: String,
    pub(super) renew_at: i64,
    pub(super) ari_after: i64,
    pub(super) slot: Arc<CertificateResidency>,
    pub(super) import_gate: tokio::sync::Mutex<()>,
    birth_epoch: u64,
}

pub(super) struct Revision {
    pub(super) material: Arc<Material>,
    pub(super) issuer: String,
    pub(super) renew_at: i64,
    pub(super) ari_after: i64,
}

pub(super) struct Publication {
    pub(super) entry: Arc<CacheEntry>,
    epoch: Arc<Epoch>,
    expected: Option<Arc<CacheEntry>>,
    capacity: usize,
    fresh: bool,
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
    entries: HashMap<Vec<String>, Arc<CacheEntry>>,
    bytes: usize,
    next_id: u64,
    next_epoch: u64,
}

pub(super) struct ResidentCache {
    state: Mutex<State>,
    events: tokio::sync::broadcast::Sender<u64>,
}

fn is_eligible(epoch: &Epoch, entry: &CacheEntry) -> bool {
    if !epoch.enabled || !entry.slot.live() {
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
            let entries: Vec<Arc<CacheEntry>> = st.entries.values().cloned().collect();
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

    pub(super) fn plan(
        &self,
        epoch: &Arc<Epoch>,
        revision: Revision,
        capacity: usize,
        previous: Option<&Arc<CertificateResidency>>,
    ) -> Result<Option<Publication>> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if !Arc::ptr_eq(&st.active, epoch) || !epoch.enabled {
            return Ok(None);
        }
        ensure!(capacity > 0, "invalid managed cache capacity");
        let expected = st.entries.get(&revision.material.names).cloned();
        let eligible = expected.as_ref().filter(|entry| is_eligible(epoch, entry));
        if let Some(previous) = previous
            && !eligible.is_some_and(|entry| Arc::ptr_eq(previous, &entry.slot))
        {
            return Err(CacheChanged.into());
        }
        let (id, birth_epoch, slot, fresh) = match eligible {
            Some(entry) => (entry.id, entry.birth_epoch, entry.slot.clone(), false),
            None => {
                let id = st.next_id;
                st.next_id = id
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("certificate cache slot IDs exhausted"))?;
                (
                    id,
                    epoch.id,
                    Arc::new(CertificateResidency::default()),
                    true,
                )
            }
        };
        let entry = Arc::new(CacheEntry {
            id,
            birth_epoch,
            slot,
            import_gate: tokio::sync::Mutex::new(()),
            material: revision.material,
            issuer: revision.issuer,
            renew_at: revision.renew_at,
            ari_after: revision.ari_after,
        });
        ensure!(
            bytes(&entry) <= BYTE_CAPACITY,
            "resident certificate byte capacity exceeded"
        );
        Ok(Some(Publication {
            entry,
            epoch: epoch.clone(),
            expected,
            capacity,
            fresh,
        }))
    }

    /// Runs only after the resolver has validated its candidate snapshot.
    /// No I/O or acquisition of a resolver lock is permitted here.
    pub(super) fn commit(&self, plan: Publication) -> Result<()> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        let key = &plan.entry.material.names;
        let matches = match (&plan.expected, st.entries.get(key)) {
            (Some(expected), Some(actual)) => Arc::ptr_eq(expected, actual),
            (None, None) => true,
            _ => false,
        };
        if !matches || !Arc::ptr_eq(&st.active, &plan.epoch) || !plan.entry.slot.live() {
            return Err(CacheChanged.into());
        }
        let mut count = st.entries.len() + usize::from(plan.expected.is_none());
        let mut size = st
            .bytes
            .checked_sub(plan.expected.as_deref().map_or(0, bytes))
            .and_then(|size| size.checked_add(bytes(&plan.entry)))
            .ok_or_else(|| anyhow::anyhow!("resident cache accounting failed"))?;
        let mut victims = Vec::new();
        if count > plan.capacity || size > BYTE_CAPACITY {
            let (mut ineligible, mut eligible): (Vec<_>, Vec<_>) = st
                .entries
                .iter()
                .filter(|(names, _)| *names != key)
                .map(|(_, entry)| entry)
                .partition(|entry| !is_eligible(&plan.epoch, entry));
            while count > plan.capacity || size > BYTE_CAPACITY {
                let victim = if let Some(ineligible) = ineligible.pop() {
                    ineligible
                } else {
                    ensure!(
                        plan.fresh,
                        "resident certificate byte or count capacity exceeded on renewal"
                    );
                    let index = random_index(eligible.len())?;
                    eligible.swap_remove(index)
                };
                count -= 1;
                size = size
                    .checked_sub(bytes(victim))
                    .ok_or_else(|| anyhow::anyhow!("resident cache accounting failed"))?;
                victims.push(victim.clone());
            }
        }
        // All fallible planning is complete. Retire victims before they can
        // be selected by any generation that still has their resolver keys.
        if let Some(expected) = plan.expected
            && !Arc::ptr_eq(&expected.slot, &plan.entry.slot)
        {
            victims.push(expected);
        }
        for victim in &victims {
            victim.slot.retire();
            st.entries.remove(&victim.material.names);
        }
        st.entries.insert(key.clone(), plan.entry);
        st.bytes = size;
        drop(st);
        for victim in victims {
            let _ = self.events.send(victim.id);
        }
        Ok(())
    }

    pub(super) fn valid_import(&self, epoch: &Arc<Epoch>, entry: &Arc<CacheEntry>) -> Result<()> {
        let st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        if epoch.id < st.active.id
            || !is_eligible(epoch, entry)
            || !st
                .entries
                .get(&entry.material.names)
                .is_some_and(|actual| Arc::ptr_eq(actual, entry))
        {
            return Err(CacheChanged.into());
        }
        Ok(())
    }

    pub(super) fn snapshot(&self, epoch: &Arc<Epoch>) -> Result<Vec<Arc<CacheEntry>>> {
        let st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("resident cache state unavailable"))?;
        let mut result = Vec::new();
        if epoch.id < st.active.id {
            return Ok(result);
        }
        for entry in st.entries.values() {
            if is_eligible(epoch, entry) {
                result.push(entry.clone());
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
                .get(&entry.material.names)
                .is_some_and(|actual| Arc::ptr_eq(actual, entry)))
    }

    pub(super) fn find(&self, epoch: &Arc<Epoch>, query: &str) -> Result<Option<Arc<CacheEntry>>> {
        let entries = self.snapshot(epoch)?;
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.material.names.iter().any(|name| name == query))
        {
            return Ok(Some(entry.clone()));
        }
        if let Some((_, suffix)) = query.split_once('.') {
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
        let names = &entry.material.names;
        if st
            .entries
            .get(names)
            .is_some_and(|actual| Arc::ptr_eq(actual, entry))
        {
            let remaining = st
                .bytes
                .checked_sub(bytes(entry))
                .ok_or_else(|| anyhow::anyhow!("resident cache accounting failed"))?;
            entry.slot.retire();
            st.bytes = remaining;
            st.entries.remove(names);
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
        st.entries.retain(|_, entry| {
            let keep = is_eligible(epoch, entry);
            if !keep {
                entry.slot.retire();
                victims.push(entry.clone());
            }
            keep
        });
        st.bytes = st
            .entries
            .values()
            .map(|entry| entry.material.certificate.len() + entry.material.key.len())
            .sum();
        drop(st);
        for victim in victims {
            let _ = self.events.send(victim.id);
        }
        Ok(())
    }
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
