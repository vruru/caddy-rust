use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use std::sync::Arc;
use super::{chain_memory::Buffer,chain_validation::Names};

/// A single certificate chain obtained from an ACME endpoint.
pub struct CertificateChain {
    pub url: String,
    pub(crate) chain_pem: Arc<Buffer>,
    pub(super) first:Arc<Buffer>,
    pub(super) last:Arc<Buffer>,
    pub(super) count:usize,
    pub(super) names:Vec<Option<Arc<Names>>>,
}

/// User-configurable preferences for selecting among multiple certificate chains.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ChainPreference {
    /// If `Some(true)`, prefer the smallest chain (by PEM byte length).
    /// If `Some(false)`, prefer the largest chain.
    /// If `None`, no size-based preference is applied.
    pub smallest: Option<bool>,

    /// Preferred issuer Common Names for any certificate in the chain.
    /// Checked in list order; first match wins.
    pub any_common_name: Vec<String>,

    /// Preferred issuer Common Names for the last (root) certificate in the chain.
    /// Checked in list order; first match wins. Used as fallback if `any_common_name` yields no match.
    pub root_common_name: Vec<String>,
}

impl ChainPreference {
    /// Validate constraint limits on the preference lists.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.any_common_name.len() > 128 {
            return Err(anyhow!("any_common_name exceeds 128 entries"));
        }
        if self.root_common_name.len() > 128 {
            return Err(anyhow!("root_common_name exceeds 128 entries"));
        }

        let mut total_bytes: usize = 0;
        for s in self
            .any_common_name
            .iter()
            .chain(self.root_common_name.iter())
        {
            if s.len() > 4096 {
                return Err(anyhow!("a common name string exceeds 4096 UTF-8 bytes"));
            }
            total_bytes += s.len();
        }
        if total_bytes > 65536 {
            return Err(anyhow!("total common name bytes exceed 65536"));
        }

        Ok(())
    }

    /// Select the best chain from `chains` according to this preference.
    ///
    /// The caller guarantees that each chain is well-formed and that all chains
    /// share the same leaf certificate. This method performs no cryptographic
    /// validation.
    pub(crate) fn select(&self, mut chains: Vec<CertificateChain>) -> Result<CertificateChain> {
        if chains.is_empty() {
            return Err(anyhow!("no certificate chains provided"));
        }
        if chains.len() > 16 {
            return Err(anyhow!("too many certificate chains (max 16)"));
        }

        // Single chain: return it directly.
        if chains.len() == 1 {
            return Ok(chains.remove(0));
        }

        // Apply size-based stable sort if requested.
        match self.smallest {
            Some(true) => {
                chains.sort_by_key(|c| c.chain_pem.len());
            }
            Some(false) => {
                chains.sort_by(|a, b| b.chain_pem.len().cmp(&a.chain_pem.len()));
            }
            None => {}
        }

        for pref in &self.any_common_name {
            if let Some(index)=chains.iter().position(|chain|chain.names.iter().any(|segment|segment.as_ref().is_some_and(|names|names.values.iter().any(|cn|cn==pref)))) {
                return Ok(chains.remove(index));
            }
        }
        for pref in &self.root_common_name {
            if let Some(index)=chains.iter().position(|chain|chain.names.last().and_then(Option::as_ref).and_then(|names|names.values.last()).is_some_and(|cn|cn==pref)) {
                return Ok(chains.remove(index));
            }
        }
        Ok(chains.remove(0))
    }
    pub(crate) fn wants_alternates(&self)->bool {
        self.smallest.is_some() || self.wants_names()
    }
    pub(crate) fn wants_names(&self)->bool {
        !self.any_common_name.is_empty() || !self.root_common_name.is_empty()
    }
}
