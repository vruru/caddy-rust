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

enum PemSource {
    Prepared {certificate:Vec<u8>,key:Zeroizing<Vec<u8>>,
        _preparation:Arc<super::resident_cache::Preparation>},
    Legacy{certificate:Vec<u8>,key:Zeroizing<Vec<u8>>},
}
#[derive(Clone)]
pub(super) struct PemView {source:Arc<PemSource>,key:bool}
impl std::ops::Deref for PemView {
    type Target=[u8];
    fn deref(&self)->&[u8]{
        match self.source.as_ref(){
            PemSource::Prepared{certificate,key,..}=>if self.key{key}else{certificate},
            PemSource::Legacy{certificate,key}=>if self.key{key}else{certificate},
        }
    }
}
impl PemView {
    fn pair(source:PemSource)->(Self,Self){
        let source=Arc::new(source);(Self{source:source.clone(),key:false},Self{source,key:true})
    }
    pub(super) fn as_slice(&self)->&[u8]{self}
}
pub(super) struct Material {
    pub names: Vec<String>,
    san_names: Vec<String>,
    pub certificate: PemView,
    pub key: PemView,
    pub tags: Arc<crate::certificate_tags::CertificateTags>,
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
    // Declared last: failed candidates drop every owned material field before
    // returning their untransferred preparation allowance.
    pub(super) preparation:Option<Arc<super::resident_cache::Preparation>>,
}

impl Material {
    pub(super) fn from_pem(certificate: Vec<u8>, key: Zeroizing<Vec<u8>>) -> Result<Self> {
        let(certificate,key)=PemView::pair(PemSource::Legacy{certificate,key});
        Self::from_views(certificate,key)
    }
    pub(super) fn from_owned(bundle:crate::certstore::OwnedCertificateBundle,names:&[String])->Result<Self>{
        let blocks=crate::cert_transient::certificate_blocks(&bundle.chain_pem)?;
        let (_,leaf)=crate::cert_transient::parse_certificate(&blocks[0].1)?;
        let general_names=leaf.subject_alternative_name()?.map_or(0,|san|san.value.general_names.len());
        let chain_bytes=blocks.iter().try_fold(0usize,|sum,(_,der)|sum.checked_add(der.len())
            .ok_or_else(||anyhow!("certificate preparation size overflow")))?;
        // Separate prepaid output/working copies from the decoder's own AST
        // scratch. Native SAN strings have bounded normalized domain/IP sizes;
        // aliases use their actual authorized input sizes. The chain allowance
        // covers owned DER, SPKI/issuer names and temporary publication/OCSP
        // copies. Crypto-provider internal heap is not a whole-process bound.
        let alias_bytes=names.iter().try_fold(0usize,|sum,name|sum.checked_add(name.len()+std::mem::size_of::<String>())
            .ok_or_else(||anyhow!("certificate alias preparation size overflow")))?;
        let cost=bundle.chain_pem.len().checked_add(bundle.private_key_pem.len())
            .and_then(|n|n.checked_add(chain_bytes.checked_mul(24)?))
            .and_then(|n|n.checked_add(bundle.private_key_pem.len().checked_mul(32)?))
            .and_then(|n|n.checked_add(general_names.checked_mul(4*std::mem::size_of::<String>()+1024)?))
            .and_then(|n|n.checked_add(alias_bytes.checked_mul(8)?))
            .and_then(|n|n.checked_add(8192)).ok_or_else(||anyhow!("certificate preparation size overflow"))?;
        let preparation=super::resident_cache::Preparation::reserve(cost)?;
        drop(leaf);
        let certificate=bundle.chain_pem.to_vec();
        let key=Zeroizing::new(bundle.private_key_pem.to_vec());
        // Do not pin the storage-read input pool for resident certificate life.
        drop(bundle);
        let(certificate,key)=PemView::pair(PemSource::Prepared{certificate,key,_preparation:preparation.clone()});
        let mut material=Self::from_blocks(certificate,key,&blocks,Some(preparation))?;
        material.names=names.to_vec();
        Ok(material)
    }
    fn from_views(certificate:PemView,key:PemView)->Result<Self>{
        let blocks = crate::cert_transient::certificate_blocks(&certificate)?;
        Self::from_blocks(certificate,key,&blocks,None)
    }
    fn from_blocks<B:AsRef<[u8]>>(certificate:PemView,key:PemView,blocks:&[(String,B)],
        preparation:Option<Arc<super::resident_cache::Preparation>>)->Result<Self>{
        for (label, der) in blocks {
            ensure!(
                label == "CERTIFICATE",
                "invalid configured certificate PEM label"
            );
            let (remaining, _) = crate::cert_transient::parse_certificate(der.as_ref())?;
            ensure!(remaining.is_empty(), "trailing configured certificate DER");
        }
        let (_, leaf) = crate::cert_transient::parse_certificate(blocks[0].1.as_ref())?;
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
        for (_, der) in blocks {
            let (_, cert) = crate::cert_transient::parse_certificate(der.as_ref())?;
            issuer_names.push(cert.issuer().as_raw().to_vec());
        }

        let leaf_id = crate::leaf_guard::leaf_id(blocks[0].1.as_ref());
        let management_name = crate::tls_resolver::certificate_management_name(&leaf)?;
        let spki_id = crate::leaf_guard::leaf_id(leaf.public_key().raw);

        // Compute certified key once to validate match and derive chain
        let chain: Vec<CertificateDer<'static>> = blocks
            .iter()
            .map(|(_, der)| CertificateDer::from(der.as_ref().to_vec()))
            .collect();
        let signing_key = certmagic::signing_key(&key, "configured certificate")?;
        let certified = CertifiedKey::new(chain, signing_key);
        certmagic::check_keys_match(&certified,"configured certificate")?;
        let certified = Arc::new(certified);

        let identity = crate::tls_resolver::certificate_chain_identity(&certified.cert);

        Ok(Self {
            preparation,
            san_names: names.clone(),
            names,
            certificate,
            key,
            tags: crate::certificate_tags::CertificateTags::empty(),
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
