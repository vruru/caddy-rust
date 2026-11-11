use hyper::body::Bytes;
use std::sync::Arc;
use tokio::sync::Semaphore;

use super::AdminError;

pub(super) const DEFAULT_INGRESS: usize = 64 << 20;
pub(super) const ADAPT_EGRESS: usize = 64 << 20;
pub(super) const CONFIG_EGRESS: usize = 64 << 20;
pub(super) const ADAPTED_CONFIG: usize = 64 << 20;

#[derive(Clone)]
pub(super) struct Pool {
    semaphore: Arc<Semaphore>,
    category: &'static str,
}

impl Pool {
    pub(super) fn new(total: usize, category: &'static str) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(total)),
            category,
        }
    }

    pub(super) fn reserve(&self, n: usize) -> Result<Credit, AdminError> {
        let unavailable = || AdminError::new(503, self.category);
        let permits = u32::try_from(n).map_err(|_| unavailable())?;
        let held = self
            .semaphore
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| unavailable())?;
        Ok(Credit { _held: held })
    }
}

pub(super) struct Credit {
    _held: tokio::sync::OwnedSemaphorePermit,
}

pub(super) struct Buffer {
    data: Vec<u8>,
    credit: Credit,
}

impl Buffer {
    pub(super) fn new(pool: &Pool, capacity: usize) -> Result<Self, AdminError> {
        let credit = pool.reserve(capacity)?;
        let mut data = Vec::new();
        data.try_reserve_exact(capacity)
            .map_err(|_| AdminError::new(503, "admin_buffer_allocation_failed"))?;
        if data.capacity() != capacity {
            return Err(AdminError::new(503, "admin_buffer_allocation_failed"));
        }
        Ok(Self { data, credit })
    }

    pub(super) fn push(
        &mut self,
        pool: &Pool,
        data: &[u8],
        limit: usize,
    ) -> Result<(), AdminError> {
        let required = self
            .data
            .len()
            .checked_add(data.len())
            .filter(|len| *len <= limit)
            .ok_or_else(|| AdminError::new(413, "admin_body_too_large"))?;
        let capacity = self.data.capacity();
        if required > capacity {
            let target = required
                .checked_next_power_of_two()
                .unwrap_or(limit)
                .max(4096)
                .min(limit);
            // Admission covers both live buffers during growth. Dropping the
            // old allocation before its credit also prevents early reuse.
            let mut next = Self::new(pool, target)?;
            next.data.extend_from_slice(&self.data);
            *self = next;
        }
        self.data.extend_from_slice(data);
        Ok(())
    }

    pub(super) fn from_parts(data: Vec<u8>, credit: Credit) -> Self {
        Self { data, credit }
    }

    pub(super) fn into_parts(self) -> (Vec<u8>, Credit) {
        (self.data, self.credit)
    }
    pub(super) fn release_data(self) -> Credit {
        let Self { data, credit } = self;
        drop(data);
        credit
    }

    pub(super) fn into_bytes(data: Vec<u8>, credit: Credit) -> Bytes {
        Bytes::from_owner(Self::from_parts(data, credit))
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl std::io::Write for Buffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.data.capacity() - self.data.len() {
            return Err(std::io::Error::other("reserved buffer capacity exceeded"));
        }
        self.data.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
