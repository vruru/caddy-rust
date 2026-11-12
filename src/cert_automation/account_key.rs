//! An explicitly selected, already parsed ACME account signing identity.
use super::AccountSigner;
use anyhow::{Result, anyhow};
use std::sync::Arc;

/// A prepared key retains its signer and public RFC 7638 identity, not a second
/// PEM buffer. Parse on a bounded blocking lane when called from an async host.
/// Deliberately has no Debug implementation.
pub struct ConfiguredAccountKey {
    signer: Option<Arc<AccountSigner>>,
    fingerprint: String,
}
impl ConfiguredAccountKey {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let signer = AccountSigner::from_pem(pem)
            .map_err(|_| anyhow!("invalid configured ACME account key"))?;
        let fingerprint = signer.thumbprint();
        Ok(Self {
            signer: Some(Arc::new(signer)),
            fingerprint,
        })
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub(crate) fn signer(&self) -> Result<Arc<AccountSigner>> {
        self.signer
            .clone()
            .ok_or_else(|| anyhow!("invalid configured ACME account key"))
    }
    // Keep a known bad credential as an issuer-local failure, so an independent
    // configured fallback issuer remains available. It cannot sign anything.
    pub(crate) fn invalid(pem: &[u8]) -> Self {
        use sha2::Digest;
        Self {
            signer: None,
            fingerprint: format!("invalid:{:x}", sha2::Sha256::digest(pem)),
        }
    }
}
