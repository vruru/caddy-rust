use crate::{
    certmagic,
    tls_resolver::{CertificateInput, HotCertificateResolver},
};
use anyhow::{Result, anyhow, ensure};
use rustls::{pki_types::CertificateDer, sign::CertifiedKey};
use std::sync::Arc;
use x509_parser::{extensions::GeneralName, prelude::X509Certificate};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(super) struct Material {
    pub names: Vec<String>,
    pub certificate: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
    pub tags: Vec<String>,
    pub identity: [u8; 32],
    pub leaf_id: [u8; 32],
    not_before: i64,
    not_after: i64,
}
impl Material {
    pub(super) fn from_pem(certificate: Vec<u8>, key: Zeroizing<Vec<u8>>) -> Result<Self> {
        let blocks = certmagic::pem_blocks(&certificate, "configured certificate")?;
        for (label, der) in &blocks {
            ensure!(
                label == "CERTIFICATE",
                "invalid configured certificate PEM label"
            );
            let (remaining, _) = x509_parser::parse_x509_certificate(der)
                .map_err(|_| anyhow!("invalid configured certificate DER"))?;
            ensure!(remaining.is_empty(), "trailing configured certificate DER");
        }
        let (_, leaf) = x509_parser::parse_x509_certificate(&blocks[0].1)
            .map_err(|_| anyhow!("invalid configured leaf certificate"))?;
        let san = leaf
            .subject_alternative_name()
            .map_err(|_| anyhow!("invalid configured certificate SAN"))?
            .ok_or_else(|| anyhow!("configured certificate SAN missing"))?;
        let mut names = san
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(name) => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        ensure!(
            !names.is_empty(),
            "IP-only certificate requires IP selection support"
        );
        let not_before = leaf.validity().not_before.timestamp();
        let not_after = leaf.validity().not_after.timestamp();
        let leaf_id = crate::leaf_guard::leaf_id(&blocks[0].1);
        let mut material = Self {
            names,
            certificate,
            key,
            tags: Vec::new(),
            identity: [0; 32],
            leaf_id,
            not_before,
            not_after,
        };
        let certified = material.certified_key()?;
        material.identity = crate::tls_resolver::certificate_chain_identity(&certified.cert);
        Ok(material)
    }
    fn with_leaf<T>(&self, operation: impl FnOnce(&X509Certificate<'_>) -> Result<T>) -> Result<T> {
        let blocks = certmagic::pem_blocks(&self.certificate, "configured certificate")?;
        let (remaining, leaf) = x509_parser::parse_x509_certificate(&blocks[0].1)
            .map_err(|_| anyhow!("invalid configured leaf certificate"))?;
        ensure!(remaining.is_empty(), "trailing configured leaf DER");
        operation(&leaf)
    }
    pub(super) fn times(&self) -> Result<(i64, i64)> {
        Ok((self.not_before, self.not_after))
    }
    pub(super) fn validate_at(&self, now: i64, client: bool) -> Result<()> {
        self.with_leaf(|leaf| {
            ensure!(
                leaf.validity().not_before.timestamp() <= now
                    && now < leaf.validity().not_after.timestamp(),
                "configured certificate is not currently valid"
            );
            if let Some(eku) = leaf
                .extended_key_usage()
                .map_err(|_| anyhow!("invalid configured certificate EKU"))?
            {
                ensure!(
                    eku.value.any
                        || if client {
                            eku.value.client_auth
                        } else {
                            eku.value.server_auth
                        },
                    "configured certificate purpose mismatch"
                );
            }
            Ok(())
        })
    }
    pub(super) fn certified_key(&self) -> Result<Arc<CertifiedKey>> {
        let blocks = certmagic::pem_blocks(&self.certificate, "configured certificate")?;
        let chain = blocks
            .iter()
            .map(|(_, der)| CertificateDer::from(der.to_vec()))
            .collect();
        let key = certmagic::signing_key(&self.key, "configured certificate")?;
        let certified = CertifiedKey::new(chain, key);
        certified
            .keys_match()
            .map_err(|_| anyhow!("configured certificate key mismatch"))?;
        Ok(Arc::new(certified))
    }
    pub(super) fn client_key(&self, now: i64) -> Result<Arc<CertifiedKey>> {
        self.validate_at(now, true)?;
        self.certified_key()
    }
    pub(super) fn publish(&self, resolver: &HotCertificateResolver) -> Result<()> {
        resolver.upsert(&CertificateInput {
            names: &self.names,
            certificate_pem: &self.certificate,
            private_key_pem: &self.key,
        })
    }
}
