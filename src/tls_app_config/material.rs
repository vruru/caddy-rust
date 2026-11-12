use crate::{
    certmagic,
    tls_resolver::{CertificateInput, HotCertificateResolver},
};
use anyhow::{Result, anyhow, ensure};
use rustls::{pki_types::CertificateDer, sign::CertifiedKey};
use std::sync::{Arc,OnceLock};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(super) enum Validity {
    Current,
    Future(i64),
    Expired,
}

#[derive(Clone)]
pub(super) struct Material {
    pub names: Vec<String>,
    san_names: Vec<String>,
    pub certificate: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
    pub tags: Vec<String>,
    pub identity: [u8; 32],
    pub leaf_id: [u8; 32],
    pub management_name: Arc<str>,
    pub spki_id: [u8; 32],
    pub spki_der: Arc<[u8]>,
    key_state: OnceLock<Arc<crate::key_compromise::KeyState>>,
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
        let mut names = crate::tls_resolver::certificate_san_names(&leaf)?;
        names.sort();
        names.dedup();
        ensure!(
            !names.is_empty(),
            "configured certificate has no usable DNS or IP SAN"
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
        let management_name = crate::tls_resolver::certificate_management_name(&leaf)?;
        let spki_id = crate::leaf_guard::leaf_id(leaf.public_key().raw);

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
            san_names: names.clone(),
            names,
            certificate,
            key,
            tags: Vec::new(),
            identity,
            leaf_id,
            key_state: OnceLock::new(),
            management_name,
            spki_id,
            spki_der: Arc::from(leaf.public_key().raw),
            not_before,
            not_after,
            certified,
            server_auth,
            client_auth,
            issuer_names,
        })
    }

    pub(super) fn key_allowed(&self, deny:&crate::key_compromise::KeyDeny)->bool {
        self.key_state.get().is_some_and(|key|deny.owns_state(key)&&!key.banned())
    }
    pub(super) fn register_key(&self, deny: &crate::key_compromise::KeyDeny)
        -> Result<Arc<crate::key_compromise::KeyState>> {
        if let Some(key)=self.key_state.get() {
            ensure!(deny.owns_state(key), "certificate material belongs to another key registry");
            return Ok(key.clone());
        }
        let key=deny.register_spki(self.spki_der.clone())?;
        match self.key_state.set(key.clone()) {
            Ok(())=>Ok(key),
            Err(_) => {
                let prior=self.key_state.get().ok_or_else(||anyhow!("certificate key reservation disappeared"))?;
                ensure!(deny.owns_state(prior), "certificate material belongs to another key registry");
                Ok(prior.clone())
            },
        }
    }
    pub(super) fn san_names(&self) -> &[String] { &self.san_names }
    pub(super) fn retained_san_bytes(&self) -> usize {
        self.san_names.capacity() * std::mem::size_of::<String>()
            + self.san_names.iter().map(String::capacity).sum::<usize>()
            + self.management_name.len()
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

    /// Classify already-verified managed material without treating an expired
    /// leaf as ready. This is used only for post-commit maintenance planning.
    pub(super) fn classify_at(&self, now: i64) -> Result<Validity> {
        ensure!(self.server_auth, "configured certificate purpose mismatch");
        ensure!(
            self.not_before < self.not_after,
            "invalid certificate lifetime"
        );
        Ok(if now < self.not_before {
            Validity::Future(self.not_before)
        } else if now >= self.not_after {
            Validity::Expired
        } else {
            Validity::Current
        })
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
