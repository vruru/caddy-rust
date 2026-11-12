//! One generation's bounded count of physical managed certificate slots.
use super::{ResidencyBinding, Result, anyhow, ensure};
use crate::tls_resolver::{CertificateResidencyRetired, MAX_CERTIFICATES};
use std::{collections::{HashMap, HashSet}, sync::{Arc, Mutex}};

pub(super) const GROUP_LIMIT: usize = MAX_CERTIFICATES + 4096 + 256;

#[derive(Default)]
pub(super) struct Ledger(Mutex<State>);

#[derive(Default)]
struct State {
    manual: usize,
    positions: HashMap<usize, usize>,
    members: Vec<(Vec<String>, ResidencyBinding)>,
    configured: HashSet<Vec<String>>,
    displaced: HashSet<Vec<String>>,
}

// Private, generation-local lookup key. Every member retains the Arc allocation.
fn physical_key(binding: &ResidencyBinding) -> usize {
    Arc::as_ptr(binding.source.as_ref().unwrap_or(&binding.slot)).addr()
}

impl State {
    fn exact(&self, binding: &ResidencyBinding) -> Option<usize> {
        let &index = self.positions.get(&physical_key(binding))?;
        Arc::ptr_eq(&self.members[index].1.slot, &binding.slot).then_some(index)
    }

    fn remove(&mut self, index: usize) -> (Vec<String>, ResidencyBinding) {
        let member = self.members.swap_remove(index);
        self.positions.remove(&physical_key(&member.1));
        if let Some((_, moved)) = self.members.get(index) {
            *self.positions.get_mut(&physical_key(moved)).expect("managed cache index") = index;
        }
        member
    }

    fn insert(&mut self, names: &[String], binding: &ResidencyBinding) {
        self.displaced.remove(names);
        let previous = self.positions.insert(physical_key(binding), self.members.len());
        debug_assert!(previous.is_none(), "one member per physical slot");
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
        let mut state = self.0.lock().map_err(|_| anyhow!("certificate capacity unavailable"))?;
        let configured: HashSet<_> = groups.iter().cloned().collect();
        let live: HashSet<_> = state.members.iter()
            .filter(|(_, binding)| binding.slot.live()).map(|(names, _)| names.clone()).collect();
        let pending = |names: &[String]| configured.contains(names) && !live.contains(names);
        state.displaced.retain(|names| pending(names));
        state.displaced.extend(retained.iter().filter(|names| pending(names)).cloned());
        state.configured = configured;
        Ok(())
    }

    pub(super) fn displaced(&self) -> Result<HashSet<Vec<String>>> {
        let state = self.0.lock().map_err(|_| anyhow!("certificate capacity unavailable"))?;
        Ok(state.displaced.iter().cloned().chain(state.members.iter()
            .filter(|(names, binding)| !binding.slot.live() && state.configured.contains(names))
            .map(|(names, _)| names.clone())).collect())
    }

    pub(super) fn set_manual(&self, count: usize) -> Result<()> {
        let mut state = self.0.lock().map_err(|_| anyhow!("certificate capacity unavailable"))?;
        ensure!(state.members.is_empty() || state.manual == count,
            "manual certificate count changed in one generation");
        state.manual = count;
        Ok(())
    }

    pub(super) fn reuse(
        &self,
        binding: &ResidencyBinding,
        commit: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        let state = self.0.lock().map_err(|_| anyhow!("certificate capacity unavailable"))?;
        if state.exact(binding).is_none() || !binding.slot.live() {
            return Ok(false);
        }
        commit()?;
        Ok(true)
    }

    /// Resolver CAS hook -> ledger -> physical cache. No mutation precedes commit.
    pub(super) fn admit(
        &self,
        names: &[String],
        binding: &ResidencyBinding,
        previous: Option<&ResidencyBinding>,
        capacity: usize,
        commit: impl FnOnce(Option<(&[String], &ResidencyBinding)>) -> Result<()>,
    ) -> Result<bool> {
        let mut state = self.0.lock().map_err(|_| anyhow!("certificate capacity unavailable"))?;
        ensure!(capacity > 0, "invalid managed certificate admission");
        ensure!(binding.slot.live(), CertificateResidencyRetired);
        let limit = capacity.saturating_sub(state.manual).max(1);
        let key = physical_key(binding);
        let replaced = previous.filter(|prior| physical_key(prior) != key)
            .and_then(|prior| state.exact(prior));
        if let Some(&index) = state.positions.get(&key) {
            let existing = &state.members[index].1;
            let same = Arc::ptr_eq(&existing.slot, &binding.slot);
            let explicit = previous.is_some_and(|prior| Arc::ptr_eq(&prior.slot, &existing.slot));
            ensure!(same || !existing.slot.live() || explicit,
                super::super::resident_cache::CacheChanged);
            commit(None)?;
            if let Some(index) = replaced {
                state.remove(index).1.slot.retire();
            }
            let index = state.positions[&key];
            let old = std::mem::replace(&mut state.members[index].1, binding.clone());
            state.members[index].0 = names.to_vec();
            state.displaced.remove(names);
            if !same { old.slot.retire(); }
            return Ok(replaced.is_some() || !same);
        }
        let live: Vec<_> = state.members.iter().enumerate()
            .filter(|(index, (_, old))| Some(*index) != replaced && old.occupies())
            .map(|(index, _)| index).collect();
        let victim = if live.len() >= limit {
            Some(live[super::super::resident_cache::random_index(live.len())?])
        } else {
            None
        };
        let mut removed: Vec<_> = state.members.iter().enumerate()
            .filter(|(index, (_, old))| !old.occupies() || Some(*index) == victim || Some(*index) == replaced)
            .map(|(index, _)| (index, Some(index) != replaced)).collect();
        commit(victim.map(|index| {
            let (names, old) = &state.members[index];
            (names.as_slice(), old)
        }))?;
        removed.sort_unstable_by(|left, right| right.0.cmp(&left.0));
        let changed = !removed.is_empty();
        for (index, displaced) in removed {
            let (names, old) = state.remove(index);
            if displaced && state.configured.contains(&names) {
                state.displaced.insert(names);
            }
            old.slot.retire();
        }
        state.insert(names, binding);
        Ok(changed)
    }

    pub(super) fn remove(&self, binding: &ResidencyBinding) {
        if let Ok(mut state) = self.0.lock()
            && let Some(index) = state.exact(binding)
            && !binding.occupies()
        {
            state.displace(index);
        }
    }

    pub(super) fn almost_full(&self, capacity: usize) -> bool {
        self.0.lock().is_ok_and(|state| {
            let count = state.manual + state.members.iter()
                .filter(|(_, binding)| binding.occupies()).count();
            count.saturating_mul(10) >= capacity.saturating_mul(9)
        })
    }
}
