use super::*;
use crate::tls_policy::{ConnectionPolicy, HelloInfo};
use sha2::{Digest, Sha256};

pub(super) struct PreparedPolicy {
    pub definition: ConnectionPolicy,
    pub tls: Arc<rustls::ServerConfig>,
    pub resolver: Arc<CandidateResolver>,
    pub sessions: Arc<connection_sessions::SharedSessions>,
    pub identity: [u8; 32],
}
pub(super) struct Sources<'a> {
    pub manual: &'a ManualCertificates,
    pub managed: &'a Arc<HotCertificateResolver>,
    pub challenges: &'a Arc<HotCertificateResolver>,
    pub provider: Option<&'a Arc<dyn ScopedCertificateProvider>>,
    pub managed_names: &'a [String],
}
pub(super) async fn prepare(
    server: &Arc<ServerConfig>,
    sources: Sources<'_>,
    resources: &Arc<resource_budget::Resources>,
    retained_bytes: &mut usize,
) -> Result<Vec<Arc<PreparedPolicy>>> {
    let Sources {
        manual,
        managed,
        challenges,
        provider,
        managed_names,
    } = sources;
    if !server.tls {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for definition in &server.tls_policies {
        let tags = definition.any_tag.clone().unwrap_or_default();
        let selected = manual
            .certificates
            .iter()
            .filter(|certificate| {
                tags.is_empty() || certificate.tags.iter().any(|tag| tags.contains(tag))
            })
            .collect::<Vec<_>>();
        ensure!(
            tags.is_empty() || !selected.is_empty(),
            "TLS certificate tags matched no certificate"
        );
        let allowed_static = selected
            .iter()
            .map(|certificate| certificate.identity)
            .collect();
        let resolver = Arc::new(CandidateResolver {
            challenges: challenges.clone(),
            static_certificates: manual.resolver.clone(),
            managed: managed.clone(),
            allowed_static,
            allowed_managed: if tags.is_empty() {
                managed_names.to_vec()
            } else {
                Vec::new()
            },
            provider: if tags.is_empty() {
                provider.cloned()
            } else {
                None
            },
        });
        let resolver_for_build = resolver.clone();
        let definition = definition.clone();
        let prepared_definition = definition.clone();
        let mut alpn = Vec::new();
        if server.protocols.iter().any(|protocol| protocol == "h2") {
            alpn.push(b"h2".to_vec());
        }
        if server.protocols.iter().any(|protocol| protocol == "h1") {
            alpn.push(b"http/1.1".to_vec());
        }
        let (mut tls, identity, charge) = resources
            .metadata
            .run(move || prepared_definition.build_prepared(resolver_for_build, &alpn))
            .await
            .map_err(|_| anyhow::anyhow!("TLS policy provisioning worker unavailable"))??;
        tls.alpn_protocols
            .retain(|protocol| match protocol.as_slice() {
                b"h2" => server.protocols.iter().any(|value| value == "h2"),
                b"http/1.1" => server.protocols.iter().any(|value| value == "h1"),
                _ => true,
            });
        *retained_bytes = retained_bytes
            .checked_add(charge)
            .ok_or_else(|| anyhow::anyhow!("TLS client authentication memory overflow"))?;
        ensure!(
            *retained_bytes <= 64 << 20,
            "TLS client authentication memory budget exceeded"
        );
        result.push(Arc::new(PreparedPolicy {
            definition,
            tls: Arc::new(tls),
            resolver,
            sessions: Arc::new(connection_sessions::SharedSessions::new()),
            identity,
        }));
    }
    Ok(result)
}
pub(super) fn set_identity(policies: &[Arc<PreparedPolicy>]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"caddy-connection-policy-set-v1");
    hash.update((policies.len() as u64).to_be_bytes());
    for policy in policies {
        hash.update(policy.identity);
    }
    hash.finalize().into()
}
impl ActiveServer {
    pub(super) fn policy(
        &self,
        sni: &str,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Option<(usize, Arc<PreparedPolicy>)> {
        let hello = HelloInfo {
            sni,
            remote: peer.ip(),
            local: local.ip(),
        };
        for (index, policy) in self.tls_policies.iter().enumerate() {
            if policy.definition.match_captures(&hello).ok()?.is_some() {
                return Some((index, policy.clone()));
            }
        }
        None
    }
}
