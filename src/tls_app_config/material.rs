use crate::{
    certmagic,
    tls_resolver::{CertificateInput, HotCertificateResolver},
};
use anyhow::{Result, anyhow, ensure};
use rustls::{pki_types::CertificateDer, sign::CertifiedKey};
use std::sync::Arc;
use x509_parser::extensions::GeneralName;
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
    certified: Arc<CertifiedKey>,
    server_auth: bool,
    client_auth: bool,
    pub(super) issuer_names: Vec<Vec<u8>>,
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

        // Determine EKU flags
        let mut server_auth = true;
        let mut client_auth = true;
        if let Some(eku) = leaf
            .extended_key_usage()
            .map_err(|_| anyhow!("invalid configured certificate EKU"))?
        {
            server_auth = eku.value.any || eku.value.server_auth;
            client_auth = eku.value.any || eku.value.client_auth;
        }

        // Cache issuer DN bytes for every cert in chain
        let mut issuer_names = Vec::with_capacity(blocks.len());
        for (_, der) in &blocks {
            let (_, cert) = x509_parser::parse_x509_certificate(der)
                .map_err(|_| anyhow!("invalid configured certificate DER"))?;
            issuer_names.push(cert.issuer().as_raw().to_vec());
        }

        let leaf_id = crate::leaf_guard::leaf_id(&blocks[0].1);

        // Compute certified key once to validate match and derive chain
        let chain: Vec<CertificateDer<'static>> = blocks
            .iter()
            .map(|(_, der)| CertificateDer::from(der.to_vec()))
            .collect();
        let signing_key = certmagic::signing_key(&key, "configured certificate")?;
        let certified = CertifiedKey::new(chain, signing_key);
        certified
            .keys_match()
            .map_err(|_| anyhow!("configured certificate key mismatch"))?;
        let certified = Arc::new(certified);

        let identity = crate::tls_resolver::certificate_chain_identity(&certified.cert);

        Ok(Self {
            names,
            certificate,
            key,
            tags: Vec::new(),
            identity,
            leaf_id,
            not_before,
            not_after,
            certified,
            server_auth,
            client_auth,
            issuer_names,
        })
    }

    pub(super) fn times(&self) -> Result<(i64, i64)> {
        Ok((self.not_before, self.not_after))
    }

    pub(super) fn validate_at(&self, now: i64, client: bool) -> Result<()> {
        ensure!(
            self.not_before <= now && now < self.not_after,
            "configured certificate is not currently valid"
        );
        let allowed = if client {
            self.client_auth
        } else {
            self.server_auth
        };
        ensure!(allowed, "configured certificate purpose mismatch");
        Ok(())
    }

    pub(super) fn certified_key(&self) -> Result<Arc<CertifiedKey>> {
        Ok(self.certified.clone())
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
