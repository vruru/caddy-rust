//! Sealed capability for the optional SSL engine. No credential I/O or public
//! private-key extraction is exposed. Default Rustls signing stays unchanged.
use super::*;
use openssl::pkey::{PKey, PKeyRef, Private};
use std::sync::Mutex;
use zeroize::Zeroizing;
enum State {
    Pending(Zeroizing<Vec<u8>>),
    Ready(PKey<Private>),
}
pub(crate) struct NativePrivateKey {
    state: Mutex<State>,
    // The same stage owner follows this separate view. Once the resolver really
    // accepts it, its existing persistent/escaped-Arc accounting boundary applies.
    _preparation: Arc<crate::tls_app_config::CertificatePreparation>,
}
pub(crate) struct PreparedNativeKey {
    key: PKey<Private>,
    _owner: Arc<NativePrivateKey>,
}
impl PreparedNativeKey {
    pub(crate) fn key(&self) -> &PKeyRef<Private> {
        &self.key
    }
}
impl NativePrivateKey {
    pub(super) fn retained_bound(pem: &[u8]) -> Result<usize> {
        // Named persistent Rust input/metadata. Decoder scratch is separately
        // reserved only while prepare() runs; opaque provider key heap keeps
        // the same explicit provider/RSS boundary as the original signer.
        pem.len()
            .checked_add(std::mem::size_of::<Self>() + 256)
            .ok_or_else(|| crate::cert_transient::ResourceDenied.into())
    }
    pub(super) fn new(
        pem: &[u8],
        preparation: Arc<crate::tls_app_config::CertificatePreparation>,
    ) -> Result<Arc<Self>> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(pem.len())
            .map_err(|_| crate::cert_transient::ResourceDenied)?;
        raw.extend_from_slice(pem);
        Ok(Arc::new(Self {
            state: Mutex::new(State::Pending(Zeroizing::new(raw))),
            _preparation: preparation,
        }))
    }
    /// Only call on a bounded crypto worker. Parsing is lazy, cached once, and
    /// retains the whole owner when SSL takes a native reference to the PKey.
    pub(crate) fn prepare(self: &Arc<Self>) -> Result<PreparedNativeKey> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("native TLS private-key state unavailable"))?;
        let key = match &*state {
            State::Ready(key) => key.clone(),
            State::Pending(pem) => {
                let scratch = crate::cert_transient::reserve(
                    crate::cert_transient::key_decode_bound(pem.as_slice())?,
                )?;
                // Reuse the already validated single-block decoder. Parsing
                // DER avoids interactive PEM password callbacks and preserves
                // native alternate labels for the same unencrypted key DER.
                let mut blocks = crate::certmagic::pem_blocks(pem, "native-ssl-private-key")?;
                ensure!(
                    blocks.len() == 1,
                    "selected private key block count changed"
                );
                let der = Zeroizing::new(blocks.pop().expect("one block checked").1);
                let key = PKey::private_key_from_der(&der).map_err(|_| {
                    anyhow!("selected private key unavailable to SSL compatibility engine")
                })?;
                *state = State::Ready(key.clone());
                drop(scratch);
                key
            }
        };
        drop(state);
        Ok(PreparedNativeKey {
            key,
            _owner: self.clone(),
        })
    }
}
/// The authoritative resolver selection pins these exact same state tokens.
#[derive(Clone)]
pub(crate) struct NativeCertificate {
    pub(crate) private: Arc<NativePrivateKey>,
    pub(crate) leaf: Arc<LeafState>,
    pub(crate) key_state: Arc<crate::key_compromise::KeyState>,
    pub(crate) enforce_key_veto: bool,
    pub(super) client_gate:Arc<super::client_identity::ClientSigningGate>,
    pub(crate) not_after: i64,
}
impl NativeCertificate {
    pub(crate) fn admitted(&self) -> bool {
        self.client_gate.allowed()
            && self.leaf.admission().allow_certificate
            && (!self.enforce_key_veto || !self.key_state.banned())
    }
}
