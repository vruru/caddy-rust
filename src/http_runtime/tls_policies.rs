use super::*;
use crate::tls_policy::{ConnectionPolicy, HelloInfo};
use sha2::{Digest, Sha256};

pub(super) struct PreparedPolicy {
    pub native_suites:Option<Arc<[u16]>>,
    pub native_verifier:Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
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
    let tag_refs=manual.certificates.iter().try_fold(0usize,|n,c|n.checked_add(c.tags.len()).ok_or_else(||anyhow::anyhow!("manual tag index overflow")))?;
    let _tag_memory=crate::cert_transient::reserve(tag_refs.checked_mul(64).and_then(|n|n.checked_add(manual.certificates.len()*256+1024)).ok_or_else(||anyhow::anyhow!("manual tag index overflow"))?)?;
    let mut manual_tags = HashMap::<[u8; 32], Vec<&str>>::new();
    for certificate in manual.certificates.iter() {
        manual_tags
            .entry(certificate.identity)
            .or_default()
            .extend(certificate.tags.iter().map(String::as_str));
    }
    for tags in manual_tags.values_mut() {
        tags.sort_unstable();
        tags.dedup();
    }
    let mut result = Vec::new();
    for definition in &server.tls_policies {
        let selection = definition.certificate_selection.clone();
        let tagged = definition.requires_certificate_tags();
        let allowed_static = manual_tags
            .iter()
            .filter(|(_, tags)| {
                selection
                    .as_ref()
                    .is_none_or(|filter| filter.allows_tag_names(tags.iter().copied()))
            })
            .map(|(identity, _)| *identity)
            .collect();
        let resolver = Arc::new(CandidateResolver {
            challenges: challenges.clone(),
            static_certificates: manual.resolver.clone(),
            managed: managed.clone(),
            allowed_static,
            certificate_selection: selection,
            allowed_managed: if !tagged {
                managed_names.iter().cloned().collect()
            } else {
                Default::default()
            },
            provider: provider.cloned(),
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
        let (mut tls, identity, charge,native_verifier,native_suites) = resources
            .metadata
            .run(move || prepared_definition.build_prepared_with_verifier(resolver_for_build, &alpn))
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
            native_verifier,
            native_suites,
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
        peer: impl Into<crate::net_address::NetAddress>,
        local: impl Into<crate::net_address::NetAddress>,
    ) -> Option<(usize, Arc<PreparedPolicy>)> {
        let peer=peer.into().tls_ip();let local=local.into().tls_ip();
        let hello = HelloInfo {
            sni,
            remote:peer.map(|v|v.0),local:local.map(|v|v.0),
            remote_has_zone:peer.is_some_and(|v|v.1),local_has_zone:local.is_some_and(|v|v.1),
        };
        for (index, policy) in self.tls_policies.iter().enumerate() {
            if policy.definition.match_captures(&hello).ok()?.is_some() {
                return Some((index, policy.clone()));
            }
        }
        None
    }
}
