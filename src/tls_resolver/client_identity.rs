//! Live signing permission for a certificate explicitly selected as managed
//! client identity. The certificate/key bytes remain the original cache data.
use super::*;
use rustls::{
    SignatureAlgorithm,
    pki_types::SubjectPublicKeyInfoDer,
    sign::{Signer, SigningKey},
};
use std::sync::atomic::AtomicBool;
use zeroize::Zeroize;
pub(super) struct ClientSigningGate {
    leaf: Arc<LeafState>,
    key: Arc<crate::key_compromise::KeyState>,
    required: AtomicBool,
}
impl ClientSigningGate {
    pub(super) fn new(
        leaf: Arc<LeafState>,
        key: Arc<crate::key_compromise::KeyState>,
    ) -> Arc<Self> {
        Arc::new(Self {
            leaf,
            key,
            required: AtomicBool::new(false),
        })
    }
    pub(super) fn require(&self) {
        self.required.store(true, Ordering::Release);
    }
    pub(super) fn allowed(&self) -> bool {
        !self.required.load(Ordering::Acquire)
            || (self.leaf.admission().allow_certificate && !self.key.banned())
    }
    pub(super) fn retained_bound() -> usize {
        std::mem::size_of::<Self>()
            + 2 * std::mem::size_of::<GuardedKey>()
            + 4 * std::mem::size_of::<usize>()
            + 128
    }
}
struct GuardedKey {
    inner: Arc<dyn SigningKey>,
    gate: Arc<ClientSigningGate>,
}
impl fmt::Debug for GuardedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedClientSigningKey")
    }
}
impl SigningKey for GuardedKey {
    fn choose_scheme(&self, schemes: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if !self.gate.allowed() {
            return None;
        }
        let signer = self.inner.choose_scheme(schemes)?;
        Some(Box::new(GuardedSigner {
            inner: signer,
            gate: self.gate.clone(),
        }))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }
}
struct GuardedSigner {
    inner: Box<dyn Signer>,
    gate: Arc<ClientSigningGate>,
}
impl fmt::Debug for GuardedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedClientSigner")
    }
}
impl Signer for GuardedSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        if !self.gate.allowed() {
            return Err(rustls::Error::General(
                "managed client signing permission withdrawn".into(),
            ));
        }
        let mut signature = self.inner.sign(message)?;
        if !self.gate.allowed() {
            signature.zeroize();
            return Err(rustls::Error::General(
                "managed client signing permission withdrawn".into(),
            ));
        }
        Ok(signature)
    }
    fn scheme(&self) -> SignatureScheme {
        self.inner.scheme()
    }
}
pub(super) fn guard_keys(
    key: Arc<CertifiedKey>,
    tls13: Option<Arc<CertifiedKey>>,
    gate: Arc<ClientSigningGate>,
) -> Result<(Arc<CertifiedKey>, Option<Arc<CertifiedKey>>)> {
    fn wrap(key: Arc<CertifiedKey>, gate: Arc<ClientSigningGate>) -> Result<Arc<CertifiedKey>> {
        let mut key = Arc::try_unwrap(key)
            .map_err(|_| anyhow!("client signing key unexpectedly shared during preparation"))?;
        key.key = Arc::new(GuardedKey {
            inner: key.key,
            gate,
        });
        Ok(Arc::new(key))
    }
    let same = tls13.as_ref().is_some_and(|other| Arc::ptr_eq(&key, other));
    if same {
        drop(tls13);
        let key = wrap(key, gate)?;
        Ok((key.clone(), Some(key)))
    } else {
        let key = wrap(key, gate.clone())?;
        let tls13 = tls13.map(|key| wrap(key, gate)).transpose()?;
        Ok((key, tls13))
    }
}
