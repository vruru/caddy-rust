use super::*;
use arc_swap::ArcSwap;
use rustls::{
    SignatureScheme, client::ResolvesClientCert, server::ResolvesServerCert, sign::CertifiedKey,
};

struct ClientKey {
    key: Arc<CertifiedKey>,
    begin: i64,
    end: i64,
    state: Arc<crate::leaf_guard::LeafState>,
    issuer_names: Vec<Vec<u8>>,
}
pub(super) struct IdentityClient {
    keys: ArcSwap<Vec<ClientKey>>,
}
impl std::fmt::Debug for IdentityClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagedIdentityClient")
    }
}
impl IdentityClient {
    pub(super) fn new() -> Self {
        Self {
            keys: ArcSwap::from_pointee(Vec::new()),
        }
    }
}
impl ResolvesClientCert for IdentityClient {
    fn resolve(&self, hints: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let now = now().ok()?;
        self.keys
            .load()
            .iter()
            .find(|entry| {
                now >= entry.begin
                    && now < entry.end
                    && entry.state.admission().allow_certificate
                    && entry.key.key.choose_scheme(schemes).is_some()
                    && (hints.is_empty()
                        || hints.iter().any(|hint| {
                            entry
                                .issuer_names
                                .iter()
                                .any(|issuer| issuer.as_slice() == *hint)
                        }))
            })
            .map(|entry| entry.key.clone())
    }
    fn has_certs(&self) -> bool {
        !self.keys.load().is_empty()
    }
}

impl CertificateServices {
    pub async fn identity(
        self: &Arc<Self>,
        cancel: CancellationToken,
    ) -> Result<Arc<dyn ResolvesServerCert>> {
        self.owned(cancel, |this, token| {
            Box::pin(async move {
                this.ensure_identity(token).await?;
                Ok(this.identity_resolver.clone() as Arc<dyn ResolvesServerCert>)
            })
        })
        .await
    }
    pub async fn identity_client(
        self: &Arc<Self>,
        cancel: CancellationToken,
    ) -> Result<Arc<dyn ResolvesClientCert>> {
        self.owned(cancel, |this, token| {
            Box::pin(async move {
                this.ensure_identity(token).await?;
                this.refresh_client_keys().await?;
                Ok(this.identity_client.clone() as Arc<dyn ResolvesClientCert>)
            })
        })
        .await
    }
    async fn ensure_identity(&self, cancel: CancellationToken) -> Result<()> {
        ensure!(
            self.prepared.initialized(),
            "certificate services are not prepared"
        );
        self.identity_ready
            .get_or_try_init(|| async {
                let identity = self
                    .plan
                    .identity
                    .as_ref()
                    .ok_or_else(|| anyhow!("administrative identity is not configured"))?;
                ensure!(
                    !identity.identifiers.is_empty(),
                    "administrative identity has no identifiers"
                );
                let groups = identity
                    .identifiers
                    .iter()
                    .map(|identifier| {
                        cert_automation::normalize_names(std::slice::from_ref(identifier))
                    })
                    .collect::<Result<Vec<_>>>()?;
                if self.restore.is_some() {
                    self.validate_retained_groups(&groups, true).await?;
                } else {
                    let bound = self
                        .state
                        .lock()
                        .await
                        .bound
                        .clone()
                        .ok_or_else(|| anyhow!("candidate listeners are not staged"))?;
                    let groups = stream::iter(groups)
                        .map(|names| async {
                            self.group(names, true, &bound, cancel.clone()).await
                        })
                        .buffer_unordered(8)
                        .collect::<Vec<_>>()
                        .await;
                    let groups = groups.into_iter().collect::<Result<Vec<_>>>()?;
                    let results = stream::iter(groups)
                        .map(|group| self.ensure_group(group, true, cancel.clone()))
                        .buffer_unordered(10)
                        .collect::<Vec<_>>()
                        .await;
                    for result in results {
                        result?;
                    }
                    self.restore_ocsp(true, cancel.clone()).await?;
                    self.reconcile_revoked(true, cancel.clone()).await?;
                }
                self.refresh_client_keys().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .map(|_| ())
    }
    pub(super) async fn refresh_client_keys(&self) -> Result<()> {
        let material = self
            .state
            .lock()
            .await
            .material
            .iter()
            .filter(|item| item.identity)
            .cloned()
            .collect::<Vec<_>>();
        let mut keys = Vec::new();
        for item in material {
            let key = item.material.client_key(now()?)?;
            let (begin, end) = item.material.times()?;
            let mut issuer_names = Vec::new();
            for certificate in &key.cert {
                let (_, certificate) = x509_parser::parse_x509_certificate(certificate.as_ref())
                    .map_err(|_| anyhow!("invalid administrative identity certificate"))?;
                issuer_names.push(certificate.issuer().as_raw().to_vec());
            }
            let leaf = key
                .cert
                .first()
                .ok_or_else(|| anyhow!("administrative identity certificate missing"))?;
            let state = self
                .context
                .leaf_guard
                .intern(crate::leaf_guard::leaf_id(leaf.as_ref()), end)?;
            keys.push(ClientKey {
                key,
                begin,
                end,
                state,
                issuer_names,
            });
        }
        self.identity_client.keys.store(Arc::new(keys));
        Ok(())
    }
}
