use serde::{Deserialize, Serialize};
use std::sync::Arc;
use anyhow::{anyhow, ensure};
use crate::zerossl_wire::models::CertificateObject;

pub(super) use super::attempt::{BackendId, InputBinding};
use crate::acme_wire::chain_memory::{Buffer,Scratch};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Prepared,
    CreateIntent,
    Created,
    VerifyIntent,
    Pending,
    Issued,
    StoreIntent,
    Stored,
    CancelIntent,
    Cancelled,
    CreateRejected,
}

#[derive(Serialize,Deserialize)]
pub(super) struct ValidationProof {
    #[serde(deserialize_with="super::job_codec::text")] pub(super) domain:String,
    #[serde(deserialize_with="super::job_codec::text")] pub(super) url:String,
    #[serde(deserialize_with="super::job_codec::text")] pub(super) body:String,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Leg {
    pub(super) version: u8,
    #[serde(deserialize_with = "super::job_codec::text")]
    pub(super) attempt_id: String,
    #[serde(deserialize_with = "super::job_codec::names")]
    pub(super) names: Vec<String>,
    pub(super) backend: BackendId,
    pub(super) input: InputBinding,
    pub(super) phase: Phase,
    #[serde(deserialize_with = "super::job_codec::csr")]
    pub(super) csr_der: Vec<u8>,
    #[serde(deserialize_with = "super::job_codec::text")]
    pub(super) csr_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) certificate: Option<CertificateObject>,
    #[serde(default)]
    pub(super) validation_proof:Option<ValidationProof>,
    #[serde(
        default,
        with = "super::job_codec::pem"
    )]
    pub(super) downloaded_pem: Option<Arc<Buffer>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::job_codec::optional_text"
    )]
    pub(super) stored_leaf_sha256: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::job_codec::optional_text"
    )]
    pub(super) initial_key_hash: Option<String>,
    #[serde(skip)]
    pub(super) _memory: Option<Arc<Scratch>>,
    #[serde(skip)]
    pub(super) _api_memory: Option<crate::acme_wire::chain_memory::Lease>,
}


fn is_hex_lower_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Leg {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.version == 1, "invalid version");

        ensure!(
            is_hex_lower_64(&self.attempt_id),
            "invalid attempt_id"
        );

        ensure!(
            !self.names.is_empty() && self.names.len() <= 100,
            "invalid names count"
        );
        for name in &self.names {
            ensure!(
                !name.is_empty() && name.len() <= 253,
                "invalid name length"
            );
        }

        match &self.backend {
            BackendId::ZeroSsl { config_identity } => {
                ensure!(
                    is_hex_lower_64(config_identity),
                    "invalid config_identity"
                );
            }
            _ => return Err(anyhow!("invalid backend type")),
        }

        match &self.input {
            InputBinding::Shared {
                input_id,
                csr_hash,
                spki_hash,
            } => {
                ensure!(!input_id.is_empty(), "empty input_id");
                ensure!(input_id.len() <= 4096, "input_id too long");
                ensure!(is_hex_lower_64(csr_hash), "invalid input csr_hash");
                ensure!(is_hex_lower_64(spki_hash), "invalid spki_hash");

            }
            InputBinding::LegacyJob { .. } => {
                return Err(anyhow!("invalid input binding"));
            }
        }

        ensure!(is_hex_lower_64(&self.csr_hash),"invalid derived CSR hash");
        ensure!(super::digest(&self.csr_der)==self.csr_hash,"derived CSR fingerprint changed");
        ensure!(!self.csr_der.is_empty(), "empty csr_der");
        ensure!(
            self.csr_der.len() <= 65536,
            "csr_der too large"
        );

        if let Some(ref cert) = self.certificate {
            cert.validate()?;
            ensure!(
                !cert.id.is_empty() && cert.id.len() <= 4096,
                "invalid certificate id"
            );
        }

        match self.phase {
            Phase::Prepared
            | Phase::CreateIntent
            | Phase::CreateRejected => {
                ensure!(
                    self.certificate.is_none(),
                    "certificate must be none"
                );
                ensure!(
                    self.downloaded_pem.is_none(),
                    "downloaded_pem must be none"
                );
            }
            _ => {
                ensure!(
                    self.certificate.is_some(),
                    "certificate must be present"
                );
            }
        }

        match self.phase {
            Phase::Issued | Phase::StoreIntent => {
                ensure!(
                    self.downloaded_pem.is_some(),
                    "downloaded_pem must be present"
                );
            }
            _ => {}
        }

        match self.phase {
            Phase::Prepared
            | Phase::CreateIntent
            | Phase::Created
            | Phase::VerifyIntent
            | Phase::Pending
            | Phase::CancelIntent
            | Phase::Cancelled
            | Phase::CreateRejected => {
                ensure!(
                    self.downloaded_pem.is_none(),
                    "downloaded_pem must be none"
                );
            }
            _ => {}
        }

        if let Some(proof)=&self.validation_proof {
            ensure!(!proof.domain.is_empty()&&proof.domain.len()<=253&&proof.url.len()<=4096
                &&!proof.body.is_empty()&&proof.body.len()<=16*1024,"invalid ZeroSSL validation proof");
        }
        if matches!(self.phase,Phase::VerifyIntent|Phase::Pending|Phase::Issued|Phase::StoreIntent|Phase::Stored){
            ensure!(self.validation_proof.is_some(),"ZeroSSL accepted validation proof missing");
        }
        match self.phase {
            Phase::StoreIntent | Phase::Stored => {
                ensure!(
                    self.stored_leaf_sha256.is_some(),
                    "stored_leaf_sha256 must be present"
                );
                if let Some(ref h) = self.stored_leaf_sha256 {
                    ensure!(
                        is_hex_lower_64(h),
                        "invalid stored_leaf_sha256"
                    );
                }
            }
            _ => {
                ensure!(
                    self.stored_leaf_sha256.is_none(),
                    "stored_leaf_sha256 must be none"
                );
            }
        }

        if self.phase == Phase::Stored {
            ensure!(
                self.downloaded_pem.is_none(),
                "downloaded_pem must be none"
            );
        }

        if let Some(ref h) = self.initial_key_hash {
            ensure!(
                is_hex_lower_64(h),
                "invalid initial_key_hash"
            );
        }

        if let Some(ref h) = self.stored_leaf_sha256 {
            ensure!(
                is_hex_lower_64(h),
                "invalid stored_leaf_sha256"
            );
        }

        Ok(())
    }
}
