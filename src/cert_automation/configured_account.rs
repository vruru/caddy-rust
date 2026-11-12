//! A configured account key is a lookup capability, never registration consent.
//! Its public metadata has its own key-bound, fenced sidecar; it must not
//! overwrite the historical email-selected account's key or contact aliases.
use super::*;

// Six-way JSON escaping of two bounded 8KiB URLs plus fixed identity fields.
const MAX_CACHE: usize = 128 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedAccount {
    version: u8,
    kind: String,
    directory: String,
    key_id: String,
    location: String,
    lease_name: String,
    #[serde(skip)]
    _credit: Option<crate::acme_wire::chain_memory::Scratch>,
}
struct EncodedCache {
    bytes: Vec<u8>,
    _credit: crate::acme_wire::chain_memory::Scratch,
}
impl AsRef<[u8]> for EncodedCache {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl CachedAccount {
    fn validate(&self, directory: &str, key_id: &str, scope: &str) -> Result<()> {
        ensure!(
            self.version == 1
                && self.kind == "configured_acme_account"
                && self.directory == directory
                && self.key_id == key_id
                && self.lease_name == scope
                && !self.location.is_empty()
                && self.location.len() <= 8192,
            "configured ACME account cache identity changed"
        );
        Ok(())
    }
    fn encoded(&self) -> Result<EncodedCache> {
        let sum = self
            .kind
            .len()
            .checked_add(self.directory.len())
            .and_then(|v| v.checked_add(self.key_id.len()))
            .and_then(|v| v.checked_add(self.location.len()))
            .and_then(|v| v.checked_add(self.lease_name.len()))
            .ok_or(crate::cert_transient::ResourceDenied)?;
        let bound = sum
            .checked_mul(6)
            .and_then(|v| v.checked_add(512))
            .ok_or(crate::cert_transient::ResourceDenied)?;
        ensure!(
            bound <= MAX_CACHE,
            "configured ACME account cache exceeds bounds"
        );
        let credit = crate::cert_transient::reserve(bound + 8192)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(bound)
            .map_err(|_| crate::cert_transient::ResourceDenied)?;
        serde_json::to_writer(&mut bytes, self)
            .map_err(|_| anyhow!("configured ACME account cache encoding failed"))?;
        ensure!(
            bytes.len() <= bound,
            "configured ACME account cache encoding exceeds bound"
        );
        Ok(EncodedCache {
            bytes,
            _credit: credit,
        })
    }
}

impl CertificateManager {
    pub(super) async fn configured_account(
        &self,
        issuer: &IssuerState,
        wire: &AcmeWire,
        key: &ConfiguredAccountKey,
        expected_location: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<AccountSession> {
        let signer = key.signer()?;
        ensure!(
            wire.directory_url().len() <= 8192,
            "configured ACME directory exceeds bounds"
        );
        let mut identity = Sha256::new();
        identity.update(b"native-configured-acme-account-v1\0");
        identity.update((wire.directory_url().len() as u64).to_be_bytes());
        identity.update(wire.directory_url().as_bytes());
        identity.update(key.fingerprint().as_bytes());
        let id = format!("{:x}", identity.finalize());
        let scope = format!("register_acme_account_configured_{id}");
        let lease = self.inner.store.lock(&scope, cancel.clone()).await?;
        let child = cancel.child_token();
        let lost = lease.lost();
        let result = {
            let operation = async {
                let cached = self
                    .inner
                    .store
                    .journal_decode_admitted(&id, |raw| {
                        ensure!(
                            raw.len() <= MAX_CACHE,
                            "configured ACME account cache exceeds bounds"
                        );
                        let credit = crate::cert_transient::reserve(raw.len() * 16 + 16384)?;
                        let mut value: CachedAccount = serde_json::from_slice(raw)
                            .map_err(|_| anyhow!("invalid configured ACME account cache"))?;
                        value._credit = Some(credit);
                        Ok(value)
                    })
                    .await?;
                if let Some(cached) = cached {
                    cached.validate(wire.directory_url(), key.fingerprint(), &scope)?;
                    ensure!(
                        expected_location.is_none_or(|v| v == cached.location),
                        "configured ACME account does not own the active order"
                    );
                    ensure!(
                        !child.is_cancelled(),
                        "configured ACME account lookup cancelled"
                    );
                    return wire.restore(signer.clone(), &cached.location);
                }
                // onlyReturnExisting is mandatory. In particular, an unknown key,
                // inactive account, timeout or API error never falls back to the
                // email cache or the normal automatic-registration path.
                let (session, _) = wire
                    .account(
                        signer.clone(),
                        "",
                        issuer.config.terms_of_service_agreed,
                        true,
                        None,
                        &child,
                    )
                    .await?;
                ensure!(
                    expected_location.is_none_or(|v| v == session.location()),
                    "configured ACME account does not own the active order"
                );
                ensure!(
                    !child.is_cancelled(),
                    "configured ACME account lookup cancelled"
                );
                ensure!(
                    session.location().len() <= 8192,
                    "configured ACME account URL exceeds bounds"
                );
                let bound = (wire.directory_url().len()
                    + key.fingerprint().len()
                    + session.location().len()
                    + scope.len())
                    * 4
                    + 8192;
                let credit = crate::cert_transient::reserve(bound)?;
                let cached = CachedAccount {
                    version: 1,
                    kind: "configured_acme_account".into(),
                    directory: wire.directory_url().into(),
                    key_id: key.fingerprint().into(),
                    location: session.location().into(),
                    lease_name: scope.clone(),
                    _credit: Some(credit),
                };
                let encoded = cached.encoded()?;
                self.inner
                    .store
                    .journal_store_encoded_fenced(&id, encoded, &lease)
                    .await?;
                ensure!(
                    !child.is_cancelled(),
                    "configured ACME account lookup cancelled"
                );
                Ok(session)
            };
            tokio::pin!(operation);
            tokio::select! {
                result = &mut operation => result,
                _ = lost.cancelled() => {
                    child.cancel();
                    let _ = operation.await;
                    Err(anyhow!("configured ACME account lease lost"))
                }
            }
        };
        let released = lease.release().await;
        let session = result?;
        released?;
        Ok(session)
    }
}
