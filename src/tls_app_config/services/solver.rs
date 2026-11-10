use super::super::model::AcmeSettings;
use super::*;
use crate::{
    cert_automation::{ChallengeType, SolverPreparation},
    http_runtime::{ChallengeBindingRequest, ChallengeListenerLease},
};

pub(super) struct SolverBroker {
    settings: Vec<BindingSettings>,
    staged: Vec<StagedAddress>,
    provider: Option<Arc<dyn ChallengeListenerProvider>>,
    leases: AsyncMutex<Vec<Box<dyn ChallengeListenerLease>>>,
}
struct BindingSettings {
    directory: String,
    bind_host: String,
    bind_ip: Option<std::net::IpAddr>,
    http_port: u16,
    alpn_port: u16,
}
impl SolverBroker {
    pub(super) fn new(
        settings: Vec<AcmeSettings>,
        staged: Vec<StagedAddress>,
        provider: Option<Arc<dyn ChallengeListenerProvider>>,
    ) -> Result<Arc<Self>> {
        let mut directories = std::collections::HashSet::new();
        let settings = settings
            .into_iter()
            .map(|settings| {
                let directory = url::Url::parse(&settings.config.wire.directory)
                    .map_err(|_| anyhow!("invalid challenge issuer directory"))?
                    .to_string();
                ensure!(
                    directories.insert(directory.clone()),
                    "duplicate challenge issuer directory requires separate policy"
                );
                let bind_ip = if settings.bind_host.is_empty() {
                    None
                } else {
                    Some(settings.bind_host.parse().map_err(|_| {
                        anyhow!("hostname challenge bindings require resolver support")
                    })?)
                };
                Ok(BindingSettings {
                    directory,
                    bind_host: settings.bind_host,
                    bind_ip,
                    http_port: settings.http_port.unwrap_or(80),
                    alpn_port: settings.alpn_port.unwrap_or(443),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(Self {
            settings,
            staged,
            provider,
            leases: AsyncMutex::new(Vec::new()),
        }))
    }
    pub(super) fn callback(self: &Arc<Self>) -> SolverPreparation {
        let this = self.clone();
        Arc::new(move |directory, kind, cancel| {
            let this = this.clone();
            Box::pin(async move { this.prepare(directory, kind, cancel).await })
        })
    }
    async fn prepare(
        &self,
        directory: String,
        kind: ChallengeType,
        cancel: CancellationToken,
    ) -> Result<()> {
        ensure!(
            !cancel.is_cancelled(),
            "challenge listener preparation cancelled"
        );
        let settings = self
            .settings
            .iter()
            .find(|settings| settings.directory == directory)
            .ok_or_else(|| anyhow!("challenge issuer binding is missing"))?;
        let port = match kind {
            ChallengeType::Http01 => settings.http_port,
            ChallengeType::TlsAlpn01 => settings.alpn_port,
        };
        let capable = |binding: &StagedAddress| serves(binding, kind, port, settings.bind_ip);
        if self.staged.iter().any(&capable) {
            return Ok(());
        }
        let mut leases = tokio::select! { biased; _ = cancel.cancelled() => return Err(anyhow!("challenge listener preparation cancelled")), leases = self.leases.lock() => leases };
        if leases
            .iter()
            .any(|lease| lease.addresses().iter().any(&capable))
        {
            return Ok(());
        }
        ensure!(
            leases.len() < 32,
            "challenge listener lease capacity exceeded"
        );
        let provider = self
            .provider
            .as_ref()
            .ok_or_else(|| anyhow!("ACME requires a challenge listener provider"))?;
        let request = ChallengeBindingRequest {
            bind_host: settings.bind_host.clone(),
            http_port: (kind == ChallengeType::Http01).then_some(port),
            tls_alpn_port: (kind == ChallengeType::TlsAlpn01).then_some(port),
        };
        let lease = provider.acquire(vec![request], cancel.clone()).await?;
        if !lease.addresses().iter().any(|binding| {
            capable(binding)
                && binding.declared.port() == port
                && settings
                    .bind_ip
                    .is_none_or(|ip| binding.declared.ip() == ip)
        }) {
            let _ = lease.release().await;
            return Err(anyhow!(
                "challenge listener provider returned an invalid proof"
            ));
        }
        if cancel.is_cancelled() {
            let _ = lease.release().await;
            return Err(anyhow!("challenge listener preparation cancelled"));
        }
        leases.push(lease);
        Ok(())
    }
    pub(super) async fn release(&self) -> Result<()> {
        let leases = std::mem::take(&mut *self.leases.lock().await);
        let mut releases = Vec::new();
        for lease in leases {
            releases.push(lease.release());
        }
        let outcomes = stream::iter(releases)
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        ensure!(
            outcomes.into_iter().all(|outcome| outcome.is_ok()),
            "challenge listener release failed"
        );
        Ok(())
    }
}

fn serves(
    binding: &StagedAddress,
    kind: ChallengeType,
    port: u16,
    bind: Option<std::net::IpAddr>,
) -> bool {
    let protocol = match kind {
        ChallengeType::Http01 => binding.http01,
        ChallengeType::TlsAlpn01 => binding.tls_alpn01,
    };
    protocol
        && binding.actual.port() == port
        && bind.is_none_or(|requested| {
            let actual = binding.actual.ip();
            actual == requested
                || match actual {
                    std::net::IpAddr::V4(ip) => ip.is_unspecified() && requested.is_ipv4(),
                    // The native listener provider explicitly creates IPv6 wildcard
                    // sockets with only_v6(false). Its proof contract is dual-stack.
                    std::net::IpAddr::V6(ip) => ip.is_unspecified(),
                }
        })
}
