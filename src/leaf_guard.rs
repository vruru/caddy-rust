//! Process-local status shared by every loaded instance of the same leaf.
//!
//! Callers must authenticate observations before supplying them. This is not
//! an OCSP parser or verifier. Revocation starts renewal; only a matching failed
//! renewal withdraws the leaf. Selection is an atomic point-in-time decision:
//! later withdrawal does not terminate an accepted handshake or connection.
//! Retired entries can be evicted after certificate NotAfter. As with TLS
//! validity checks, this assumes the wall clock is trustworthy; a later clock
//! rollback does not restore an already evicted status history. No withdrawal
//! history is promised across process restarts.

use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

pub type LeafId = [u8; 32];
pub fn leaf_id(der: &[u8]) -> LeafId {
    Sha256::digest(der).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Good,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub status: Status,
    pub this_update: i64,
    pub produced_at: i64,
    pub valid_until: i64,
    pub reason: Option<u8>,
}
impl Observation {
    fn order(self) -> (i64, u8, i64, i64) {
        let rank = match self.status {
            Status::Good => 0,
            Status::Unknown => 1,
            Status::Revoked => 2,
        };
        (self.this_update, rank, self.produced_at, self.valid_until)
    }
    fn revocation(self) -> RevocationVersion {
        RevocationVersion {
            this_update: self.this_update,
            produced_at: self.produced_at,
            valid_until: self.valid_until,
            reason: self.reason,
        }
    }
    fn reason_order(self) -> (bool, bool, u8) {
        (
            self.reason == Some(1),
            self.reason.is_some(),
            self.reason.unwrap_or(0),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationVersion {
    pub this_update: i64,
    pub produced_at: i64,
    pub valid_until: i64,
    pub reason: Option<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revocation {
    pub version: RevocationVersion,
    pub withdrawn: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    pub allow_certificate: bool,
    /// Policy permission only; the resolver also checks the attached response's
    /// authenticated validity deadline at selection time.
    pub allow_staple: bool,
}

const ALLOW: u8 = 1;
const STAPLE: u8 = 2;
const NEEDS_RENEW: u8 = 4;

#[derive(Default)]
struct Metadata {
    latest: Option<Observation>,
    revoked: Option<Observation>,
    good_since: Option<i64>,
    withdrawn_for: Option<RevocationVersion>,
}
impl Metadata {
    fn effective_revoked(&self) -> Option<Observation> {
        self.revoked
            .filter(|r| self.good_since.is_none_or(|good| r.this_update >= good))
    }
    fn withdrawn(&self) -> bool {
        self.withdrawn_for
            .is_some_and(|w| self.good_since.is_none_or(|good| w.this_update >= good))
    }
}

pub struct LeafState {
    metadata: Mutex<Metadata>,
    fast: AtomicU8,
    not_after: i64,
}
impl LeafState {
    fn new(not_after: i64) -> Self {
        Self {
            metadata: Mutex::new(Metadata::default()),
            fast: AtomicU8::new(ALLOW | STAPLE),
            not_after,
        }
    }
    fn metadata(&self) -> Result<MutexGuard<'_, Metadata>> {
        self.metadata
            .lock()
            .map_err(|_| anyhow!("leaf status unavailable"))
    }
    fn publish(&self, metadata: &Metadata) {
        let allow = !metadata.withdrawn();
        let revoked = metadata.effective_revoked().is_some();
        let staple = allow && !revoked && metadata.latest.is_none_or(|o| o.status == Status::Good);
        let renewal = allow && revoked;
        self.fast.store(
            (u8::from(allow) * ALLOW)
                | (u8::from(staple) * STAPLE)
                | (u8::from(renewal) * NEEDS_RENEW),
            Ordering::Release,
        );
    }
    /// Unknown is not proof that a withdrawn leaf became usable. An exact
    /// timestamp tie prefers key-compromise, then a deterministic reason order.
    /// Durability diagnostics belong to the producer, not this volatile guard.
    pub fn observe(&self, observation: Observation) -> Result<()> {
        let mut metadata = self.metadata()?;
        let order = |o: Observation| (o.order(), o.reason_order());
        if observation.status == Status::Good {
            metadata.good_since =
                Some(metadata.good_since.map_or(observation.this_update, |old| {
                    old.max(observation.this_update)
                }));
        }
        if observation.status == Status::Revoked
            && metadata
                .revoked
                .is_none_or(|old| order(observation) >= order(old))
        {
            metadata.revoked = Some(observation);
        }
        if metadata
            .latest
            .is_none_or(|old| order(observation) >= order(old))
        {
            metadata.latest = Some(observation);
        }
        self.publish(&metadata);
        Ok(())
    }
    /// Both flags come from the same publication; do not combine two separate
    /// reads when deciding which certificate/staple pair to return.
    pub fn admission(&self) -> Admission {
        let value = self.fast.load(Ordering::Acquire);
        Admission {
            allow_certificate: value & ALLOW != 0,
            allow_staple: value & STAPLE != 0,
        }
    }
    pub(crate) fn not_after(&self) -> i64 {
        self.not_after
    }
    pub fn needs_renewal(&self) -> bool {
        self.fast.load(Ordering::Acquire) & NEEDS_RENEW != 0
    }
    pub fn pending_revocation(&self) -> Result<Option<RevocationVersion>> {
        Ok(self
            .revocation()?
            .filter(|r| !r.withdrawn)
            .map(|r| r.version))
    }
    /// Includes already withdrawn versions so explicit startup/reload policy
    /// can retry them with backoff, without treating them as fresh pending work.
    /// The withdrawal can precede the returned newer revocation version.
    pub fn revocation(&self) -> Result<Option<Revocation>> {
        let metadata = self.metadata()?;
        Ok(metadata.effective_revoked().map(|o| Revocation {
            version: o.revocation(),
            withdrawn: metadata.withdrawn(),
        }))
    }
    pub fn withdraw_if_current(&self, version: &RevocationVersion) -> Result<bool> {
        let mut metadata = self.metadata()?;
        if !metadata
            .effective_revoked()
            .is_some_and(|o| o.status == Status::Revoked && o.revocation() == *version)
        {
            return Ok(false);
        }
        metadata.withdrawn_for = Some(*version);
        self.publish(&metadata);
        Ok(true)
    }
    fn prunable(&self, now: Option<i64>) -> bool {
        if now.is_some_and(|now| now >= self.not_after) {
            return true;
        }
        self.metadata().is_ok_and(|m| {
            !m.withdrawn()
                && m.effective_revoked().is_none()
                && m.latest.is_none_or(|o| o.status == Status::Good)
        })
    }
}

/// The map retains negative observations even when all resolver snapshots
/// retire. A full map fails new material preparation, never existing lookups.
/// Lock order is map then per-leaf metadata, with no reverse acquisition.
pub struct LeafGuard {
    states: Mutex<HashMap<LeafId, Arc<LeafState>>>,
    capacity: usize,
}
impl LeafGuard {
    pub fn new(capacity: usize) -> Result<Self> {
        ensure!(
            (1..=65536).contains(&capacity),
            "leaf status capacity outside bounds"
        );
        Ok(Self {
            states: Mutex::new(HashMap::new()),
            capacity,
        })
    }
    fn states(&self) -> Result<MutexGuard<'_, HashMap<LeafId, Arc<LeafState>>>> {
        self.states
            .lock()
            .map_err(|_| anyhow!("leaf registry unavailable"))
    }
    /// `not_after` must come from the same authenticated certificate DER.
    pub fn intern(&self, leaf: LeafId, not_after: i64) -> Result<Arc<LeafState>> {
        ensure!(not_after > 0, "leaf validity outside bounds");
        let mut states = self.states()?;
        if let Some(state) = states.get(&leaf) {
            ensure!(
                state.not_after == not_after,
                "leaf validity differs from registered certificate"
            );
            return Ok(state.clone());
        }
        if states.len() >= self.capacity {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|time| i64::try_from(time.as_secs()).ok());
            states.retain(|_, state| Arc::strong_count(state) != 1 || !state.prunable(now));
        }
        ensure!(
            states.len() < self.capacity,
            "leaf status capacity exhausted"
        );
        let state = Arc::new(LeafState::new(not_after));
        states.insert(leaf, state.clone());
        Ok(state)
    }
    /// Only a loader-registered leaf can receive observations. A callback cannot
    /// introduce an identifier with a made-up, prematurely expiring validity.
    pub fn observe(&self, leaf: LeafId, not_after: i64, observation: Observation) -> Result<()> {
        let state = self
            .states()?
            .get(&leaf)
            .cloned()
            .ok_or_else(|| anyhow!("leaf status is not registered"))?;
        ensure!(
            state.not_after == not_after,
            "leaf validity differs from registered certificate"
        );
        state.observe(observation)
    }
    /// Diagnostic latest responses only. This intentionally omits older revoked
    /// facts and is NEVER a persistence or startup-restoration representation.
    /// Restore by authenticating the original signed OCSP cache instead.
    pub fn observations(&self) -> Result<Vec<(LeafId, Observation)>> {
        let states = self.states()?;
        let mut result = Vec::with_capacity(states.len());
        for (leaf, state) in states.iter() {
            if let Some(observation) = state.metadata()?.latest {
                result.push((*leaf, observation));
            }
        }
        Ok(result)
    }
    pub fn pending_revocations(&self) -> Result<Vec<(LeafId, RevocationVersion)>> {
        let states = self.states()?;
        let mut result = Vec::with_capacity(states.len());
        for (leaf, state) in states.iter() {
            if let Some(version) = state.pending_revocation()? {
                result.push((*leaf, version));
            }
        }
        Ok(result)
    }
    pub fn revocations(&self) -> Result<Vec<(LeafId, Revocation)>> {
        let states = self.states()?;
        let mut result = Vec::with_capacity(states.len());
        for (leaf, state) in states.iter() {
            if let Some(revocation) = state.revocation()? {
                result.push((*leaf, revocation));
            }
        }
        Ok(result)
    }
}
