use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{ensure, Result, anyhow};

#[derive(Clone)]
pub(super) struct Registry {
    inner: Arc<Inner>,
}

struct Inner {
    map: RwLock<HashMap<String, Proof>>,
    next_id: AtomicU64,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner::default()),
        }
    }
}

impl Registry {
    pub(super) fn register(
        &self,
        owner: &str,
        domain: &str,
        path: &str,
        body: &[u8],
        ttl: Duration,
    ) -> Result<Lease> {
        // Normalize domain
        let normalized_domain = super::normalize_zerossl_host(domain)?;

        // Validate owner
        ensure!(!owner.is_empty() && owner.len() <= 128, "owner length invalid");
        for c in owner.chars() {
            ensure!(
                c.is_ascii_graphic() && !c.is_ascii_whitespace(),
                "owner contains invalid characters"
            );
        }

        // Validate path
        const PATH_PREFIX: &str = "/.well-known/pki-validation/";
        ensure!(
            path.starts_with(PATH_PREFIX) && path.len() > PATH_PREFIX.len(),
            "path prefix invalid"
        );
        ensure!(path.len() <= 1024, "path too long");
        for b in path.as_bytes() {
            ensure!(*b >= 0x20 && *b <= 0x7E, "path contains control chars");
            ensure!(*b != b'?' && *b != b'#', "path contains query/fragment");
        }

        // Validate body
        ensure!(!body.is_empty(), "body empty");
        ensure!(body.len() <= 16 * 1024, "body too large");

        // Validate ttl
        ensure!(
            ttl >= Duration::from_secs(1) && ttl <= Duration::from_secs(3600),
            "ttl out of range"
        );

        let mut write_guard = self
            .inner
            .map
            .write()
            .map_err(|_| anyhow!("lock poisoned"))?;

        // Clean expired entries
        let now = Instant::now();
        write_guard.retain(|_, proof| proof.expires > now);

        // Enforce limits: max 8192 hosts total, max 128 per owner
        ensure!(
            write_guard.contains_key(&normalized_domain) || write_guard.len() < 8192,
            "registry full: max 8192 hosts"
        );
        let owner_count = write_guard
            .values()
            .filter(|p| p.owner == owner)
            .count();
        ensure!(
            write_guard.contains_key(&normalized_domain) || owner_count < 128,
            "owner has too many entries: max 128"
        );

        let memory=crate::acme_wire::chain_memory::shared().payload.reserve(
            owner.len()+path.len()+body.len()+2*normalized_domain.len()+std::mem::size_of::<Proof>()+256)?;
        // Check for existing host (domain)
        if let Some(existing) = write_guard.get(&normalized_domain) {
            ensure!(
                existing.owner == owner,
                "conflict: host registered by different owner"
            );
            ensure!(
                existing.path == path,
                "conflict: host registered with different path"
            );
            ensure!(
                existing.body == body,
                "conflict: host registered with different body"
            );
            // Same owner, same path, same body: allow re-registration (update expiry)
            let id = self
                .inner
                .next_id
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| anyhow!("ZeroSSL proof generation exhausted"))?;

            let proof = Proof {
                owner: owner.to_string(),
                generation: id,
                expires: now + ttl,
                path: path.to_string(),
                body: body.to_vec(),
                _memory:memory,
            };
            write_guard.insert(normalized_domain.clone(), proof);

            return Ok(Lease {
                inner: Arc::clone(&self.inner),
                host: normalized_domain,
                generation: id,
            });
        }

        // New registration
        let id = self
            .inner
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| anyhow!("ZeroSSL proof generation exhausted"))?;

        let proof = Proof {
            owner: owner.to_string(),
            generation: id,
            expires: now + ttl,
            path: path.to_string(),
            body: body.to_vec(),
            _memory:memory,
        };

        write_guard.insert(normalized_domain.clone(), proof);

        Ok(Lease {
            inner: Arc::clone(&self.inner),
            host: normalized_domain,
            generation: id,
        })
    }

    pub(super) fn lookup(&self, authority: &str, path: &str) -> Option<Option<crate::cert_transient::Bytes>> {
        let normalized_host = super::normalize_zerossl_authority(authority).ok()?;

        let read_guard = self.inner.map.read().ok()?;

        // Check if host exists
        match read_guard.get(&normalized_host) {
            Some(proof) => {
                // Check if expired
                if proof.expires <= Instant::now() {
                    return None;
                }
                // Check path
                if proof.path == path {
                    Some(crate::cert_transient::Bytes::copy(&proof.body,crate::cert_transient::Lifetime::Temporary).ok())
                } else {
                    Some(None) // Host exists, path mismatch -> 404
                }
            }
            None => None, // Host not found -> 404
        }
    }
}

struct Proof {
    owner: String,
    generation: u64,
    expires: Instant,
    path: String,
    body: Vec<u8>,
    _memory:crate::acme_wire::chain_memory::Lease,
}

pub(crate) struct Lease {
    inner: Arc<Inner>,
    host: String,
    generation: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut write_guard) = self.inner.map.write() {
            if let Some(proof) = write_guard.get(&self.host) {
                if proof.generation == self.generation {
                    write_guard.remove(&self.host);
                }
            }
        }
    }
}
