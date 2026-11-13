//! Immutable certificate labels with admission owned by the actual shared data.
use crate::{
    acme_wire::chain_memory::{Lease, Pool},
    cert_transient::ResourceDenied,
};
use anyhow::{Result, ensure};
use std::sync::{Arc, OnceLock};
use zeroize::{Zeroize, Zeroizing};
/// Shared certificate labels. Cloning the Arc shares labels and their lease.
/// `ManualCertificateInfo::tags` uses this instead of a deep-cloning Vec.
pub struct CertificateTags {
    values: Vec<String>,
    _memory: Option<Lease>,
}
impl std::ops::Deref for CertificateTags {
    type Target = [String];
    fn deref(&self) -> &[String] {
        &self.values
    }
}
impl Drop for CertificateTags {
    fn drop(&mut self) {
        self.values.zeroize();
    }
}
impl CertificateTags {
    /// Copy labels into the existing process payload budget. Admission precedes
    /// allocation; exhaustion returns an error. This does not expose the pool or
    /// permit extracting an unleased Vec from an inventory.
    /// ```no_run
    /// let tags=caddy_compat_native::certificate_tags::CertificateTags::try_from_slice(&["production".to_owned()])?;
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn try_from_slice(values: &[String]) -> Result<Arc<Self>> {
        Self::copy(
            values.len(),
            values.iter().map(String::as_str),
            &crate::acme_wire::chain_memory::shared().payload,
        )
    }
    pub(crate) fn empty() -> Arc<Self> {
        static EMPTY: OnceLock<Arc<CertificateTags>> = OnceLock::new();
        EMPTY
            .get_or_init(|| {
                Arc::new(Self {
                    values: Vec::new(),
                    _memory: None,
                })
            })
            .clone()
    }
    fn cost(capacity: usize, values: &[String]) -> Result<usize> {
        let base = capacity
            .checked_mul(std::mem::size_of::<String>())
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>() + 128))
            .ok_or(ResourceDenied)?;
        values.iter().try_fold(base, |n, s| {
            n.checked_add(s.capacity())
                .ok_or_else(|| ResourceDenied.into())
        })
    }
    pub(crate) fn adopt(mut values: Zeroizing<Vec<String>>, pool: &Arc<Pool>) -> Result<Arc<Self>> {
        if values.is_empty() {
            return Ok(Self::empty());
        }
        let memory = pool.reserve(Self::cost(values.capacity(), &values)?)?;
        Ok(Arc::new(Self {
            values: std::mem::take(&mut *values),
            _memory: Some(memory),
        }))
    }
    pub(crate) fn copy<'a>(
        count: usize,
        values: impl Clone + Iterator<Item = &'a str>,
        pool: &Arc<Pool>,
    ) -> Result<Arc<Self>> {
        if count == 0 {
            ensure!(
                values.clone().next().is_none(),
                "certificate tag count changed"
            );
            return Ok(Self::empty());
        }
        let base = count
            .checked_mul(std::mem::size_of::<String>())
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>() + 128))
            .ok_or(ResourceDenied)?;
        let bytes = values
            .clone()
            .try_fold(base, |n, s| n.checked_add(s.len()).ok_or(ResourceDenied))?;
        let upper = bytes.checked_mul(2).ok_or(ResourceDenied)?;
        let mut memory = pool.reserve(upper)?;
        let mut result = Zeroizing::new(Vec::new());
        result.try_reserve_exact(count)?;
        ensure!(
            result
                .capacity()
                .checked_mul(std::mem::size_of::<String>())
                .is_some_and(|n| n <= upper),
            "certificate tag capacity exceeds admission"
        );
        for value in values {
            ensure!(result.len() < count, "certificate tag count changed");
            let mut text = Zeroizing::new(String::new());
            text.try_reserve_exact(value.len())?;
            text.push_str(value);
            result.push(std::mem::take(&mut *text));
        }
        ensure!(result.len() == count, "certificate tag count changed");
        let actual = Self::cost(result.capacity(), &result)?;
        ensure!(
            actual <= memory.bytes(),
            "certificate tag allocation exceeds admission"
        );
        memory.resize(actual)?;
        Ok(Arc::new(Self {
            values: std::mem::take(&mut *result),
            _memory: Some(memory),
        }))
    }
}
