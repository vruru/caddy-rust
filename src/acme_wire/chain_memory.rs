use anyhow::{Result, bail};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub(crate) struct MemoryDenied;
impl std::fmt::Display for MemoryDenied {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("certificate chain memory budget exhausted")}}
impl std::error::Error for MemoryDenied{}

pub(crate) const PAYLOAD_LIMIT: usize = 32 * 1024 * 1024;
pub(crate) const STAGING_LIMIT: usize = 8 * 1024 * 1024;
pub(crate) const SCRATCH_LIMIT: usize = 64 * 1024 * 1024;

fn scratch_sem() -> Arc<Semaphore> {
    shared().scratch.clone()
}

/// One aggregate for the process. AutomationResources passes this same Arc to
/// every generation/CA; standalone wire construction uses the same defaults.
pub(crate) struct Pools {
    pub(crate) payload: Arc<Pool>,
    pub(crate) staging: Arc<Pool>,
    scratch: Arc<Semaphore>,
}
pub(crate) fn shared() -> Arc<Pools> {
    static POOLS: OnceLock<Arc<Pools>> = OnceLock::new();
    POOLS
        .get_or_init(|| {
            Arc::new(Pools {
                payload: Pool::new(PAYLOAD_LIMIT),
                staging: Pool::new(STAGING_LIMIT),
                scratch: Arc::new(Semaphore::new(SCRATCH_LIMIT)),
            })
        })
        .clone()
}

pub(crate) struct Pool {
    limit: usize,
    used: AtomicUsize,
}

impl Pool {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Pool {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    fn claim(self: &Arc<Self>, n: usize) -> Result<()> {
        if n > self.limit {
            bail!(MemoryDenied);
        }
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = match current.checked_add(n) {
                Some(v) if v <= self.limit => v,
                _ => bail!(MemoryDenied),
            };
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(c) => current = c,
            }
        }
    }

    fn refund(self: &Arc<Self>, n: usize) {
        self.used.fetch_sub(n, Ordering::AcqRel);
    }

    pub(crate) fn reserve(self: &Arc<Self>, n: usize) -> Result<Lease> {
        self.claim(n)?;
        Ok(Lease {
            pool: self.clone(),
            bytes: n,
        })
    }

    pub(crate) fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

pub(crate) struct Lease {
    pool: Arc<Pool>,
    bytes: usize,
}

impl Lease {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn resize(&mut self, new_bytes: usize) -> Result<()> {
        if new_bytes > self.pool.limit {
            bail!(MemoryDenied);
        }
        if new_bytes > self.bytes {
            // Grow: claim the delta atomically before updating self.bytes.
            let delta = new_bytes - self.bytes;
            self.pool.claim(delta)?;
            self.bytes = new_bytes;
        } else if new_bytes < self.bytes {
            // Shrink: refund the unused pre-paid portion.
            // Caller must have proven the existing buffer is already covered by new_bytes.
            let delta = self.bytes - new_bytes;
            self.pool.refund(delta);
            self.bytes = new_bytes;
        }
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.pool.refund(self.bytes);
    }
}

pub(crate) struct Buffer {
    bytes: Vec<u8>,
    lease: Lease,
}

impl Buffer {
    pub(crate) fn adopt(bytes: Vec<u8>, mut lease: Lease) -> Result<Self> {
        let cap = bytes.capacity();
        lease.resize(cap)?;
        Ok(Buffer { bytes, lease })
    }

    pub(crate) fn assemble(pool: &Arc<Pool>, parts: &[&[u8]]) -> Result<Self> {
        let mut sum: usize = 0;
        for p in parts {
            sum = sum
                .checked_add(p.len())
                .ok_or_else(|| anyhow::anyhow!("overflow"))?;
        }
        const ASSEMBLE_LIMIT: usize = 4 * 1024 * 1024;
        if sum > ASSEMBLE_LIMIT {
            bail!("assemble limit exceeded");
        }
        let lease = pool.reserve(sum)?;
        let mut vec = Vec::new();
        vec.try_reserve_exact(sum)
            .map_err(|_| anyhow::anyhow!("alloc failed"))?;
        anyhow::ensure!(vec.capacity() == sum, "unexpected chain buffer capacity");
        for p in parts {
            vec.extend_from_slice(p);
        }
        Ok(Buffer { bytes: vec, lease })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
    pub(crate) fn into_parts(self) -> (Vec<u8>, Lease) {
        (self.bytes, self.lease)
    }
}

pub(crate) struct Scratch(OwnedSemaphorePermit);

pub(crate) async fn scratch(bytes: usize, cancel: CancellationToken) -> Result<Scratch> {
    if bytes > SCRATCH_LIMIT {
        bail!(MemoryDenied);
    }
    if u32::try_from(bytes).is_err() {
        bail!(MemoryDenied);
    }
    let sem = scratch_sem();
    let permit = tokio::select! {
        biased;
        _ = cancel.cancelled() => bail!("cancelled"),
        r = sem.clone().acquire_many_owned(bytes as u32) => match r {
            Ok(p) => p,
            Err(_) => bail!("semaphore closed"),
        },
    };
    Ok(Scratch(permit))
}

pub(crate) fn try_scratch(bytes: usize) -> Result<Scratch> {
    if bytes > SCRATCH_LIMIT {
        bail!(MemoryDenied);
    }
    if u32::try_from(bytes).is_err() {
        bail!(MemoryDenied);
    }
    let sem = scratch_sem();
    let permit = sem
        .clone()
        .try_acquire_many_owned(bytes as u32)
        .map_err(|_| MemoryDenied)?;
    Ok(Scratch(permit))
}

pub(crate) fn scratch_available() -> usize {
    scratch_sem().available_permits()
}

/// Body allocation is prepaid from the aggregate payload pool. Reallocation
/// additionally borrows the old capacity from staging until the old Vec dies.
/// Staging is never held across a network wait, so a slow peer cannot consume
/// all staging credit merely by withholding its response.
pub(crate) struct Collector {
    bytes: Vec<u8>,
    lease: Option<Lease>,
    pools: Option<Arc<Pools>>,
}
impl Collector {
    pub(crate) fn new(
        pools: Option<Arc<Pools>>,
        lease: Option<Lease>,
        length: Option<usize>,
    ) -> Result<Self> {
        let mut result = Self {
            bytes: Vec::new(),
            lease,
            pools,
        };
        if let Some(n) = length {
            result.grow(n)?;
        }
        Ok(result)
    }
    fn grow(&mut self, capacity: usize) -> Result<()> {
        anyhow::ensure!(
            capacity <= 4 * 1024 * 1024,
            "ACME response body exceeds bounds"
        );
        if capacity <= self.bytes.capacity() {
            return Ok(());
        }
        let Some(pools) = &self.pools else {
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| anyhow::anyhow!("ACME body allocation failed"))?;
            return Ok(());
        };
        self.lease
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("ACME body credit missing"))?
            .resize(capacity)?;
        let staging = pools.staging.reserve(self.bytes.capacity())?;
        let mut next = Vec::new();
        next.try_reserve_exact(capacity)
            .map_err(|_| anyhow::anyhow!("ACME body allocation failed"))?;
        anyhow::ensure!(next.capacity() == capacity, "unexpected ACME body capacity");
        next.extend_from_slice(&self.bytes);
        let old = std::mem::replace(&mut self.bytes, next);
        drop(old);
        drop(staging);
        Ok(())
    }
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<()> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("ACME body size overflow"))?;
        anyhow::ensure!(
            required <= 4 * 1024 * 1024,
            "ACME response body exceeds bounds"
        );
        if self.pools.is_some() && required > self.bytes.capacity() {
            self.grow(
                required
                    .checked_next_power_of_two()
                    .unwrap_or(4 * 1024 * 1024)
                    .min(4 * 1024 * 1024),
            )?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }
    pub(crate) fn into_parts(mut self) -> (Vec<u8>, Option<Lease>) {
        if let Some(lease) = &mut self.lease {
            lease
                .resize(self.bytes.capacity())
                .expect("shrinking body credit");
        }
        (self.bytes, self.lease)
    }
}
