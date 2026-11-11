//! A generation's one resident count. Certificate parsing, publication
//! planning, storage and network work never run under this lock.
use super::{ResidencyBinding, Result, anyhow, ensure};
use crate::tls_resolver::{CertificateResidency, CertificateResidencyRetired, MAX_CERTIFICATES};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

// Identity scopes are independent of the business cache, but use the same
// Group admission pool. A new flight needs a slot before it can evict a key.
pub(super) const GROUP_LIMIT: usize = MAX_CERTIFICATES + 4096 + 256;

#[derive(Default)]
pub(super) struct Ledger(Mutex<State>);

#[derive(Default)]
struct State {
    manual: usize,
    positions: HashMap<Vec<String>, usize>,
    members: Vec<(Vec<String>, ResidencyBinding)>,
    configured: HashSet<Vec<String>>,
    displaced: HashSet<Vec<String>>,
}

impl State {
    fn remove(&mut self, index: usize) -> (Vec<String>, ResidencyBinding) {
        let member = self.members.swap_remove(index);
        self.positions.remove(&member.0);
        if let Some((moved, _)) = self.members.get(index) {
            *self.positions.get_mut(moved).expect("managed cache index") = index;
        }
        member
    }

    fn insert(&mut self, names: &[String], binding: &ResidencyBinding) {
        self.displaced.remove(names);
        self.positions.insert(names.to_vec(), self.members.len());
        self.members.push((names.to_vec(), binding.clone()));
    }

    fn displace(&mut self, index: usize) {
        let (names, binding) = self.remove(index);
        if self.configured.contains(&names) {
            self.displaced.insert(names);
        }
        binding.slot.retire();
    }
}

impl Ledger {
    pub(super) fn set_configured(
        &self,
        groups: &[Vec<String>],
        retained: &HashSet<Vec<String>>,
    ) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("certificate capacity unavailable"))?;
        let configured: HashSet<_> = groups.iter().cloned().collect();
        // Preparing the same candidate can be retried after a partial import.
        // Keep exact, still-unloaded names; never mark a restored live member
        // displaced merely because the retained snapshot recorded its old slot.
        let State {
            positions,
            members,
            displaced,
            ..
        } = &mut *state;
        let pending = |names: &[String]| {
            configured.contains(names)
                && positions
                    .get(names)
                    .is_none_or(|&index| !members[index].1.slot.live())
        };
        displaced.retain(|names| pending(names));
        displaced.extend(retained.iter().filter(|names| pending(names)).cloned());
        state.configured = configured;
        Ok(())
    }

    pub(super) fn displaced(&self) -> Result<HashSet<Vec<String>>> {
        let state = self
            .0
            .lock()
            .map_err(|_| anyhow!("certificate capacity unavailable"))?;
        // A shared source may have retired before the owned cleanup job has
        // removed the projection. Capture that exact formerly admitted name
        // for rollback without preserving its unusable material.
        Ok(state
            .displaced
            .iter()
            .cloned()
            .chain(
                state
                    .members
                    .iter()
                    .filter(|(names, binding)| {
                        !binding.slot.live() && state.configured.contains(names)
                    })
                    .map(|(names, _)| names.clone()),
            )
            .collect())
    }

    pub(super) fn set_manual(&self, count: usize) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("certificate capacity unavailable"))?;
        ensure!(
            state.members.is_empty() || state.manual == count,
            "manual certificate count changed in one generation"
        );
        state.manual = count;
        Ok(())
    }

    /// Called from the validated resolver CAS hook. The supplied callback
    /// checks/updates the shared physical cache before we change this ledger;
    /// the only permitted nested lock is the shared cache (no I/O or await).
    pub(super) fn admit(
        &self,
        names: &[String],
        binding: &ResidencyBinding,
        capacity: usize,
        commit: impl FnOnce(Option<(&[String], &ResidencyBinding)>) -> Result<()>,
    ) -> Result<bool> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("certificate capacity unavailable"))?;
        ensure!(capacity > 0, "invalid managed certificate admission");
        ensure!(binding.slot.live(), CertificateResidencyRetired);
        let limit = capacity.saturating_sub(state.manual).max(1);
        if let Some(&old) = state.positions.get(names) {
            let slot = &state.members[old].1.slot;
            if Arc::ptr_eq(slot, &binding.slot) {
                commit(None)?;
                return Ok(false);
            }
            // A new validated projection for the same SANs replaces the
            // prior local owner. It must not retire a shared source here.
            commit(None)?;
            state.remove(old).1.slot.retire();
            state.insert(names, binding);
            return Ok(true);
        }
        if state.members.len() >= limit {
            let mut i = 0;
            while i < state.members.len() {
                if state.members[i].1.slot.live() {
                    i += 1;
                } else {
                    state.displace(i);
                }
            }
        }
        let victim = if state.members.len() >= limit {
            Some(super::super::resident_cache::random_index(
                state.members.len(),
            )?)
        } else {
            None
        };
        commit(victim.map(|index| {
            let (names, binding) = &state.members[index];
            (names.as_slice(), binding)
        }))?;
        if let Some(victim) = victim {
            state.displace(victim);
        }
        state.insert(names, binding);
        Ok(victim.is_some())
    }

    pub(super) fn remove(&self, names: &[String], slot: &Arc<CertificateResidency>) {
        if let Ok(mut state) = self.0.lock()
            && let Some(&index) = state.positions.get(names)
            && Arc::ptr_eq(&state.members[index].1.slot, slot)
            && !slot.live()
        {
            state.displace(index);
        }
    }

    // CertMagic permits storage-only fallback once 90% of its cache is full.
    // This never authorizes a CA request for a policy without on-demand.
    pub(super) fn almost_full(&self, capacity: usize) -> bool {
        self.0.lock().is_ok_and(|state| {
            let count = state.manual
                + state
                    .members
                    .iter()
                    .filter(|(_, binding)| binding.slot.live())
                    .count();
            count.saturating_mul(10) >= capacity.saturating_mul(9)
        })
    }
}
