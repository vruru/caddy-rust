//! Standalone HTTP facade provisioning. The integrated backend supplies its
//! already prepared, generation-owned inventory instead of rereading files.
use super::*;
use crate::tls_resolver::{ManualCertificateInfo, ManualCertificates};
use futures_util::{StreamExt, TryStreamExt, stream};
use std::io::Cursor;
use zeroize::Zeroizing;

struct Material {
    index: usize,
    certificate: Zeroizing<Vec<u8>>,
    key: Zeroizing<Vec<u8>>,
    names: Vec<String>,
    tags: Vec<String>,
}

pub(super) async fn load(
    config: &PreparedConfig,
    registry: &ChallengeRegistry,
    managed: &Arc<HotCertificateResolver>,
    resources: &Arc<resource_budget::Resources>,
) -> Result<ManualCertificates> {
    let concurrency = std::thread::available_parallelism()
        .map(|cpu| cpu.get())
        .unwrap_or(1)
        .clamp(1, 16);
    let mut reads = stream::iter(config.certificates.iter().cloned().enumerate())
        .map(|(index, file)| async move {
            let certificate_path = crate::http_config::helpers::replace(
                &file.certificate,
                true,
                crate::http_config::helpers::global_lookup,
            )?;
            let key_path = crate::http_config::helpers::replace(
                &file.key,
                true,
                crate::http_config::helpers::global_lookup,
            )?;
            let certificate = read_bounded(certificate_path, 4 * 1024 * 1024, resources).await?;
            let key = read_bounded(key_path, 128 * 1024, resources).await?;
            Ok::<_, anyhow::Error>(Material {
                index,
                certificate,
                key,
                names: Vec::new(),
                tags: file.tags,
            })
        })
        .buffer_unordered(concurrency);
    let mut total = 0usize;
    let mut materials = Vec::new();
    while let Some(material) = reads.try_next().await? {
        total = total
            .saturating_add(material.certificate.len())
            .saturating_add(material.key.len());
        ensure!(
            total <= 64 * 1024 * 1024,
            "manual certificate material budget exceeded"
        );
        materials.push(material);
    }
    // Concurrent reads must never change same-SNI certificate preference.
    materials.sort_by_key(|material| material.index);
    let registry = registry.clone();
    let guard = managed.leaf_guard();
    resources
        .metadata
        .run(move || {
            let resolver = Arc::new(HotCertificateResolver::with_leaf_guard(registry, guard));
            let mut certificates = Vec::with_capacity(materials.len());
            for material in &mut materials {
                material.names = certificate_names(&material.certificate)?;
                let chain = rustls_pemfile::certs(&mut Cursor::new(&material.certificate))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| anyhow::anyhow!("invalid manual certificate chain"))?;
                ensure!(!chain.is_empty(), "empty manual certificate chain");
                certificates.push(ManualCertificateInfo {
                    identity: crate::tls_resolver::certificate_chain_identity(&chain),
                    names: material.names.clone(),
                    tags: crate::certificate_tags::CertificateTags::copy(material.tags.len(),material.tags.iter().map(String::as_str),&crate::acme_wire::chain_memory::shared().payload)?,
                });
            }
            let inputs = materials
                .iter()
                .map(|material| CertificateInput {
                    names: &material.names,
                    certificate_pem: &material.certificate,
                    private_key_pem: &material.key,
                })
                .collect::<Vec<_>>();
            resolver.replace(&inputs)?;
            Ok(ManualCertificates {
                resolver,
                certificates: Arc::new(certificates),
            })
        })
        .await
        .map_err(|_| anyhow::anyhow!("manual certificate provisioning task failed"))?
}

/// Catch accidental cross-generation resolver/metadata pairings before a
/// listener can publish. Revocation and OCSP changes keep these identities.
pub(super) fn validate(manual: &ManualCertificates) -> Result<()> {
    use std::collections::{BTreeSet, HashMap};
    let mut actual = HashMap::<[u8; 32], (usize, BTreeSet<String>)>::new();
    for certificate in manual.resolver.ocsp_certificates()? {
        let (count, names) = actual.entry(certificate.identity()).or_default();
        *count += 1;
        names.extend(
            certificate
                .names()
                .iter()
                .map(|name| name.trim_end_matches('.').to_ascii_lowercase()),
        );
    }
    let mut claimed = HashMap::<[u8; 32], (usize, BTreeSet<String>)>::new();
    for certificate in manual.certificates.iter() {
        let (count, names) = claimed.entry(certificate.identity).or_default();
        *count += 1;
        names.extend(
            certificate
                .names
                .iter()
                .map(|name| name.trim_end_matches('.').to_ascii_lowercase()),
        );
    }
    ensure!(
        actual == claimed,
        "manual certificate inventory does not match its resolver"
    );
    Ok(())
}

/// Raw key buffers never grow using Vec::reserve/realloc: every replaced buffer
/// is zeroed before deallocation. The real blocking job owns its budget permit
/// until the read returns, even when its asynchronous caller is cancelled.
async fn read_bounded(
    path: String,
    limit: usize,
    resources: &Arc<resource_budget::Resources>,
) -> Result<Zeroizing<Vec<u8>>> {
    resources
        .metadata
        .run(move || -> Result<_> {
            use std::io::Read;
            let mut file = crate::http_config::helpers::open_regular_file(path)
                .map_err(|_| anyhow::anyhow!("configured TLS material unavailable"))?;
            let metadata = file
                .metadata()
                .map_err(|_| anyhow::anyhow!("configured TLS material unavailable"))?;
            ensure!(
                metadata.len() > 0 && metadata.len() <= limit as u64,
                "configured TLS material outside bounds"
            );
            let maximum = limit + 1;
            let initial = (metadata.len() as usize).saturating_add(1).min(maximum);
            let mut bytes = Zeroizing::new(vec![0u8; initial]);
            let mut used = 0;
            loop {
                if used == bytes.len() {
                    ensure!(used <= limit, "TLS material grew beyond limit");
                    let mut larger =
                        Zeroizing::new(vec![0u8; bytes.len().saturating_mul(2).min(maximum)]);
                    larger[..used].copy_from_slice(&bytes[..used]);
                    bytes = larger;
                }
                let read = match file.read(&mut bytes[used..]) {
                    Ok(read) => read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => anyhow::bail!("configured TLS material read failed"),
                };
                if read == 0 {
                    break;
                }
                used += read;
                ensure!(used <= limit, "TLS material grew beyond limit");
            }
            ensure!(used != 0, "configured TLS material is empty");
            // Bound retained capacity by actual material length; the previous
            // potentially larger buffer is zeroed by its guard on this return.
            Ok(Zeroizing::new(bytes[..used].to_vec()))
        })
        .await
        .map_err(|_| anyhow::anyhow!("TLS material worker unavailable"))?
}
