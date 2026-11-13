// src/cert_automation/attempt.rs
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroize;

use crate::acme_wire::chain_memory::Buffer;

/// A deserialized SPKI is revalidated and registered; no trusted bit is stored.
pub(super) struct RuntimeInput {
    pub record: InputRecord,
    pub key_state: Arc<crate::key_compromise::KeyState>,
    pub binding: InputBinding,
    pub _memory: Arc<crate::acme_wire::chain_memory::Scratch>,
}
impl RuntimeInput {
    pub(super) fn validate(record:InputRecord,input_id:&str,
        memory:Arc<crate::acme_wire::chain_memory::Scratch>,deny:&crate::key_compromise::KeyDeny)->Result<Self> {
        use x509_parser::prelude::FromDer;
        record.validate()?;
        ensure!(!record.retired,"attempt input secret has retired after winner commit");
        ensure!(super::digest(&record.csr_der)==record.csr_hash
            && super::digest(&record.spki_der)==record.spki_hash,"attempt input fingerprint changed");
        // This temporary AST lease is separate from the retained raw/key
        // input. It is acquired before the parser (including its extension
        // decoders) and outlives both the AST and signature verification.
        let _csr_ast = crate::cert_transient::reserve(
            crate::acme_wire::chain_deep_shape::csr_cost(&record.csr_der)?)?;
        let key=super::prepare_reusable_key(zeroize::Zeroizing::new(record.private_key_pem.as_bytes().to_vec()),deny)?;
        ensure!(key.spki.as_ref()==record.spki_der,"attempt private key differs from SPKI");
        deny.check_state(&key.state)?;
        let (tail,csr)=x509_parser::certification_request::X509CertificationRequest::from_der(&record.csr_der)
            .map_err(|_|anyhow::anyhow!("invalid persisted CSR"))?;
        ensure!(tail.is_empty()&&csr.certification_request_info.subject_pki.raw==record.spki_der
            &&csr.signature_value.unused_bits==0,"persisted CSR identity changed");
        crate::cert_status::verify_x509_signature(&csr.certification_request_info.subject_pki,
            &csr.signature_algorithm,&csr.signature_value.data,csr.certification_request_info.raw,true)?;
        let mut actual=Vec::new();
        for attribute in csr.certification_request_info.iter_attributes() {
            if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(request)=attribute.parsed_attribute(){
                for extension in &request.extensions {
                    if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san)=extension.parsed_extension(){
                        for name in &san.general_names {
                            ensure!(actual.len()<100,"persisted CSR SAN limit");
                            actual.push(match name {
                                x509_parser::extensions::GeneralName::DNSName(v)=>v.to_ascii_lowercase(),
                                x509_parser::extensions::GeneralName::IPAddress(v) if v.len()==4=>
                                    std::net::Ipv4Addr::new(v[0],v[1],v[2],v[3]).to_string(),
                                x509_parser::extensions::GeneralName::IPAddress(v) if v.len()==16=>
                                    crate::tls_resolver::canonical_certificate_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8;16]>::try_from(*v)?))),
                                _=>anyhow::bail!("persisted CSR subject type outside authorized scope"),
                            });
                        }
                    }
                }
            }
        }
        drop(csr);
        actual.sort();actual.dedup();
        ensure!(actual==record.names,"persisted CSR SAN scope changed");
        let binding=InputBinding::Shared{input_id:input_id.to_owned(),csr_hash:record.csr_hash.clone(),spki_hash:record.spki_hash.clone()};
        Ok(Self{record,key_state:key.state,binding,_memory:memory})
    }
}

// ---------- helpers ----------

fn is_hex64_ascii(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------- BackendId ----------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(super) enum BackendId {
    Acme {
        #[serde(deserialize_with = "super::job_codec::text")]
        directory: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        config_identity: String,
    },
    Internal {
        #[serde(deserialize_with = "super::job_codec::text")]
        ca: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        options_identity: String,
    },
}

// ---------- InputBinding ----------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(super) enum InputBinding {
    Shared {
        #[serde(deserialize_with = "super::job_codec::text")]
        input_id: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        csr_hash: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        spki_hash: String,
    },
    LegacyJob {
        #[serde(deserialize_with = "super::job_codec::text")]
        job_id: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        original_attempt_id: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        csr_hash: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        spki_hash: String,
        #[serde(deserialize_with = "super::job_codec::text")]
        reservation_hash: String,
    },
}

// ---------- InputRecord ----------

#[derive(Serialize, Deserialize)]
pub(super) struct InputRecord {
    pub version: u8,
    #[serde(default)]
    pub retired: bool,
    #[serde(deserialize_with = "super::job_codec::text")]
    pub attempt_id: String,
    #[serde(deserialize_with = "super::job_codec::names")]
    pub names: Vec<String>,
    #[serde(deserialize_with = "super::job_codec::csr")]
    pub csr_der: Vec<u8>,
    #[serde(deserialize_with = "super::job_codec::key")]
    pub private_key_pem: String,
    #[serde(deserialize_with = "super::job_codec::csr")]
    pub spki_der: Vec<u8>,
    #[serde(deserialize_with = "super::job_codec::text")]
    pub csr_hash: String,
    #[serde(deserialize_with = "super::job_codec::text")]
    pub spki_hash: String,
}

impl Drop for InputRecord {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

impl InputRecord {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.version == 2, "version must be 2");
        ensure!(is_hex64_ascii(&self.attempt_id), "attempt_id not hex64");
        ensure!(is_hex64_ascii(&self.csr_hash), "csr_hash not hex64");
        ensure!(is_hex64_ascii(&self.spki_hash), "spki_hash not hex64");
        ensure!(!self.names.is_empty() && self.names.len() <= 100,
            "names count out of 1..=100");
        for n in &self.names {
            ensure!(!n.is_empty() && n.len() <= 253, "name length out of 1..=253");
        }
        if self.retired {
            ensure!(self.csr_der.is_empty()&&self.private_key_pem.is_empty()&&self.spki_der.is_empty(),
                "retired input contains secret material");
            return Ok(())
        }
        ensure!(!self.csr_der.is_empty() && self.csr_der.len() <= 65536,
            "csr_der length out of 1..=65536");
        ensure!(!self.private_key_pem.is_empty() && self.private_key_pem.len() <= 131072,
            "private_key_pem length out of 1..=131072");
        ensure!(!self.spki_der.is_empty() && self.spki_der.len() <= 16384,
            "spki_der length out of 1..=16384");
        Ok(())
    }
}

// ---------- InternalLeg ----------

#[derive(Serialize, Deserialize)]
pub(super) struct InternalLeg {
    pub version: u8,
    #[serde(deserialize_with = "super::job_codec::text")]
    pub attempt_id: String,
    #[serde(deserialize_with = "super::job_codec::names")]
    pub names: Vec<String>,
    pub backend: BackendId,
    pub input: InputBinding,
    #[serde(deserialize_with = "super::job_codec::text")]
    pub phase: String,
    #[serde(with = "super::job_codec::pem")]
    pub downloaded_pem: Option<Arc<Buffer>>,
    #[serde(default, deserialize_with = "super::job_codec::optional_text")]
    pub stored_leaf_sha256: Option<String>,
    #[serde(default, deserialize_with = "super::job_codec::optional_text")]
    pub initial_key_hash: Option<String>,
    #[serde(skip)]
    pub _memory: Option<Arc<crate::acme_wire::chain_memory::Scratch>>,
}

impl InternalLeg {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.version == 2, "version must be 2");
        ensure!(matches!(self.backend, BackendId::Internal { .. }),
            "backend must be Internal");
        match self.phase.as_str() {
            "prepared" => {}
            "issued" => {
                ensure!(self.downloaded_pem.is_some(), "issued requires pem");
            }
            "store_intent" => {
                ensure!(self.downloaded_pem.is_some(), "store_intent requires pem");
                ensure!(self.stored_leaf_sha256.is_some(),
                    "store_intent requires leaf hash");
            }
            "stored" => {
                ensure!(self.stored_leaf_sha256.is_some(),
                    "stored requires leaf hash");
            }
            other => anyhow::bail!("unrecognised Internal leg phase: {other}"),
        }
        Ok(())
    }
}


/// A checkpoint cannot allocate an unbounded issuer sequence during decode.
pub(super) fn sequence<'de,D,T>(d:D)->std::result::Result<Vec<T>,D::Error>
where D:serde::Deserializer<'de>,T:serde::Deserialize<'de> {
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de,T:serde::Deserialize<'de>>serde::de::Visitor<'de> for Visitor<T> {
        type Value=Vec<T>;
        fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("at most16 issuer records")}
        fn visit_seq<A:serde::de::SeqAccess<'de>>(self,mut a:A)->std::result::Result<Vec<T>,A::Error>{
            let mut v=Vec::with_capacity(16);
            while v.len()<16 {
                match a.next_element()? {Some(item)=>v.push(item),None=>return Ok(v)}
            }
            if a.next_element::<serde::de::IgnoredAny>()?.is_some(){
                return Err(serde::de::Error::custom("issuer sequence limit"))
            }
            Ok(v)
        }
    }
    d.deserialize_seq(Visitor(std::marker::PhantomData))
}
