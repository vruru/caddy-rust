//! auth_cache.rs — per-generation password verification cache.
//! No TTL or implicit authentication deadline. Accepted owned leaders continue
//! after their HTTP waiters cancel; their work and follower counts are bounded.
//! Result keys retain HMAC digests, never plaintext credentials.

// Behavioral reference: Caddy v2.11.7 modules/caddyhttp/caddyauth/{basicauth,bcrypt}.go.
// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
// The anti-enumeration fake hash below is the original non-secret fixture.
pub(crate) const FAKE_BCRYPT_HASH: &str =
    "$2a$14$X3ulqf/iGxnf1k6oMZ.RZeJUoqI9PX2PM4rS5lkIKJXduLGXGPrt6";

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::{OwnedSemaphorePermit, watch};
use zeroize::Zeroizing;

use super::resource_budget::{BudgetError, Resources};
use super::auth_hash::Algorithm;

type HmacSha256 = Hmac<Sha256>;
type Digest = [u8; 32];
type Outcome = Option<Result<bool, AuthError>>;

/// Opaque result; never carries hash/password material and never printed with it.
#[derive(Clone, Copy, Debug)]
pub enum AuthError {
    Overloaded,
    HashInvalid,
    WorkerFailed,
}

const DONE_CAP: usize = 1000;
const EVICT: usize = 101;

struct Flight {
    id: Arc<()>, // identity for ABA-safe removal (ptr compare, not a counter)
    rx: watch::Receiver<Outcome>,
}

struct State {
    done_vec: Vec<(Digest, bool)>,
    done_idx: HashMap<Digest, usize>,
    inflight: HashMap<Digest, Flight>,
    rng: u64, // weak eviction RNG; seeded independently of the HMAC secret
}

pub struct AuthCache {
    secret: Zeroizing<[u8; 32]>,
    state: Mutex<State>,
}

impl std::fmt::Debug for AuthCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (done, inflight) = self.counts();
        f.debug_struct("AuthCache")
            .field("cached_results", &done)
            .field("inflight", &inflight)
            .finish_non_exhaustive()
    }
}

impl AuthCache {
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let mut secret = Zeroizing::new([0u8; 32]);
        let mut seed = [0u8; 8];
        let provider = crate::crypto::provider();
        provider
            .secure_random
            .fill(&mut *secret)
            .map_err(|_| anyhow::anyhow!("authentication cache entropy unavailable"))?;
        provider
            .secure_random
            .fill(&mut seed)
            .map_err(|_| anyhow::anyhow!("authentication cache entropy unavailable"))?;
        let mut rng = u64::from_le_bytes(seed);
        if rng == 0 {
            rng = 0x9E37_79B9_7F4A_7C15;
        }
        Ok(Arc::new(Self {
            secret,
            state: Mutex::new(State {
                done_vec: Vec::new(),
                done_idx: HashMap::new(),
                inflight: HashMap::new(),
                rng,
            }),
        }))
    }

    /// (cached_results, in_flight) — safe snapshot for QA.
    pub(crate) fn counts(&self) -> (usize, usize) {
        let g = self.lock();
        (g.done_vec.len(), g.inflight.len())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Recover from poisoning: our invariants are reconstructable.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn digest(&self, algorithm:Algorithm, hash: &str, pw: &[u8]) -> Digest {
        let mut mac = HmacSha256::new_from_slice(&*self.secret).expect("32-byte key");
        let scheme = algorithm.name().as_bytes();
        mac.update(b"caddy-auth-cache/v1\0");
        mac.update(&(scheme.len() as u64).to_be_bytes());
        mac.update(scheme);
        let hb = hash.as_bytes();
        mac.update(&(hb.len() as u64).to_be_bytes());
        mac.update(hb);
        mac.update(&(pw.len() as u64).to_be_bytes());
        mac.update(pw);
        mac.finalize().into_bytes().into()
    }

    pub(crate) async fn verify(
        self: &Arc<Self>,
        resources: Arc<Resources>,
        hash: String,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<bool, AuthError> {
        self.verify_with_algorithm(resources,Algorithm::Bcrypt,hash,password).await
    }

    pub(crate) async fn verify_with_algorithm(
        self:&Arc<Self>,resources:Arc<Resources>,algorithm:Algorithm,
        hash:String,password:Zeroizing<Vec<u8>>,
    )->Result<bool,AuthError>{
        let d = self.digest(algorithm,&hash, password.as_slice());
        let mut credentials = Some((hash, password));
        // No await between recording a flight and giving its job an owner.
        // Spawn only after unlocking: dropping an unpolled task must be able
        // to run FlightGuard without attempting to lock this mutex recursively.
        let (rx, held_follower, pending) = {
            let mut g = self.lock();
            if let Some(&idx) = g.done_idx.get(&d) {
                return Ok(g.done_vec[idx].1);
            }
            if let Some(f) = g.inflight.get(&d) {
                (f.rx.clone(), None, None)
            } else {
                let follower = resources
                    .auth_followers
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| {
                        resources
                            .auth_cache_rejected
                            .fetch_add(1, Ordering::Relaxed);
                        AuthError::Overloaded
                    })?;
                let leader = resources
                    .auth_leaders
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| {
                        resources
                            .auth_cache_rejected
                            .fetch_add(1, Ordering::Relaxed);
                        AuthError::Overloaded
                    })?;
                let (tx, rx) = watch::channel(None);
                let id = Arc::new(());
                g.inflight.insert(
                    d,
                    Flight {
                        id: id.clone(),
                        rx: rx.clone(),
                    },
                );
                let (hash, password) = credentials.take().expect("one cache leader");
                (rx, Some(follower), Some((leader, hash, password, id, tx)))
            }
        };
        drop(credentials); // Joined callers do not retain a second password copy.
        if let Some((leader, hash, password, id, tx)) = pending {
            let guard = FlightGuard {
                cache: self.clone(),
                d,
                id: id.clone(),
                armed: true,
                _leader: leader,
            };
            spawn_job(Job {
                cache: self.clone(),
                resources: resources.clone(),
                hash,
                algorithm,
                password,
                d,
                id,
                tx,
                guard,
            });
        }
        let _follower = match held_follower {
            Some(p) => p,
            None => resources
                .auth_followers
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    resources
                        .auth_cache_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    AuthError::Overloaded
                })?,
        };
        wait_on(rx).await
    }
}

async fn wait_on(mut rx: watch::Receiver<Outcome>) -> Result<bool, AuthError> {
    loop {
        {
            let v = rx.borrow_and_update();
            if let Some(res) = v.as_ref() {
                return *res;
            }
        }
        // Sender dropped without a terminal value (panic/abort) => worker failed.
        if rx.changed().await.is_err() {
            return Err(AuthError::WorkerFailed);
        }
    }
}

struct FlightGuard {
    cache: Arc<AuthCache>,
    d: Digest,
    id: Arc<()>,
    armed: bool,
    _leader: OwnedSemaphorePermit,
}

impl FlightGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut g = self.cache.lock();
            remove_flight(&mut g, self.d, &self.id);
        }
    }
}

struct Job {
    // Drop the flight before closing its watch channel, even if never polled.
    guard: FlightGuard,
    cache: Arc<AuthCache>,
    resources: Arc<Resources>,
    hash: String,
    algorithm: Algorithm,
    password: Zeroizing<Vec<u8>>,
    d: Digest,
    id: Arc<()>,
    tx: watch::Sender<Outcome>,
}
fn spawn_job(job: Job) {
    let tracker = job.resources.auth_tasks.clone();
    tracker.spawn(async move {
        let Job {
            cache,
            resources,
            hash,
            algorithm,
            password,
            d,
            id,
            tx,
            mut guard,
        } = job;
        let comparisons = resources.auth_comparisons.clone();

        let closure = move || -> Result<bool, AuthError> {
            // Runs under a real worker permit; password zeroized on drop.
            let pw = password;
            comparisons.fetch_add(1, Ordering::Relaxed);
            algorithm.compare(&hash,pw.as_slice())
        };

        let result = match resources.auth.run(closure).await {
            Ok(inner) => inner,
            Err(BudgetError::Overloaded) => Err(AuthError::Overloaded),
            Err(BudgetError::WorkerFailed) => Err(AuthError::WorkerFailed),
        };

        match result {
            Ok(val) => {
                // Cache the result and drop the flight atomically under one lock.
                {
                    let mut g = cache.lock();
                    insert_done(&mut g, d, val); // true and false both cached
                    remove_flight(&mut g, d, &id);
                }
                guard.disarm();
                let _ = tx.send(Some(Ok(val)));
            }
            Err(e) => {
                // Errors are not cached; clear the flight before waking retries.
                {
                    let mut state = cache.lock();
                    remove_flight(&mut state, d, &id);
                }
                guard.disarm();
                let _ = tx.send(Some(Err(e)));
            }
        }
        // guard drop (if still armed) clears the flight; tx drop closes the channel.
    });
}

fn remove_flight(state: &mut State, d: Digest, id: &Arc<()>) {
    if let Some(f) = state.inflight.get(&d)
        && Arc::ptr_eq(&f.id, id)
    {
        state.inflight.remove(&d);
    }
}

fn insert_done(state: &mut State, d: Digest, val: bool) {
    if state.done_idx.contains_key(&d) {
        return;
    }
    if state.done_vec.len() >= DONE_CAP {
        for _ in 0..EVICT {
            if state.done_vec.is_empty() {
                break;
            }
            let len = state.done_vec.len() as u64;
            let r = (next_rng(&mut state.rng) % len) as usize;
            let (gone, _) = state.done_vec.swap_remove(r);
            state.done_idx.remove(&gone);
            if r < state.done_vec.len() {
                let moved = state.done_vec[r].0; // element swapped into slot r
                state.done_idx.insert(moved, r);
            }
        }
    }
    let idx = state.done_vec.len();
    state.done_vec.push((d, val));
    state.done_idx.insert(d, idx);
}

fn next_rng(rng: &mut u64) -> u64 {
    // xorshift64; eviction only, not security-sensitive.
    let mut x = *rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *rng = x;
    x
}
