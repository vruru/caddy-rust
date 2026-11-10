use crate::{
    acme_wire::KeyType,
    cert_automation::AcmeIssuerConfig,
    local_pki::{CaConfig, InternalIssuerOptions},
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use zeroize::Zeroizing;

/// Material and issuer configuration deliberately have no Debug implementation.
#[derive(Clone)]
pub(super) enum Issuer {
    Acme(Box<AcmeSettings>),
    Internal {
        ca: String,
        options: InternalIssuerOptions,
    },
}

#[derive(Clone)]
pub(super) struct AcmeSettings {
    pub config: AcmeIssuerConfig,
    pub roots: Vec<PathBuf>,
    pub http_port: Option<u16>,
    pub alpn_port: Option<u16>,
    pub bind_host: String,
    pub distributed: bool,
    pub timeout: Option<Duration>,
}

#[derive(Clone)]
pub(super) struct PermissionSetting {
    pub endpoint: String,
    pub legacy: bool,
}

#[derive(Clone)]
pub(super) struct Policy {
    pub subjects: Vec<String>,
    pub issuers: Vec<Issuer>,
    pub storage: Option<PathBuf>,
    pub renewal_ratio: f64,
    pub key_type: KeyType,
    pub on_demand: bool,
    pub disable_ocsp: bool,
    pub ocsp_overrides: BTreeMap<String, String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            subjects: Vec::new(),
            issuers: Vec::new(),
            storage: None,
            renewal_ratio: 1.0 / 3.0,
            key_type: KeyType::P256,
            on_demand: false,
            disable_ocsp: false,
            ocsp_overrides: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub(super) enum ManualSource {
    Files {
        certificate: PathBuf,
        key: PathBuf,
        tags: Vec<String>,
    },
    Pem {
        certificate: Vec<u8>,
        key: Zeroizing<Vec<u8>>,
        tags: Vec<String>,
    },
    Folder(PathBuf),
    Storage {
        certificate: String,
        key: String,
        tags: Vec<String>,
    },
}

#[derive(Clone)]
pub(super) struct Authority {
    pub config: CaConfig,
    pub storage: Option<PathBuf>,
}

#[derive(Clone)]
pub(super) struct Identity {
    pub identifiers: Vec<String>,
    pub issuers: Vec<Issuer>,
}

#[derive(Clone)]
pub struct CertificatePlan {
    pub(super) storage: Option<PathBuf>,
    pub(super) policies: Vec<Policy>,
    pub(super) authorities: BTreeMap<String, Authority>,
    pub(super) identity: Option<Identity>,
    pub(super) manual: Vec<ManualSource>,
    pub(super) automate: Vec<String>,
    pub(super) disable_ocsp: bool,
    pub(super) disable_storage_check: bool,
    pub(super) disable_storage_clean: bool,
    pub(super) renew_interval: Duration,
    pub(super) ocsp_interval: Duration,
    pub(super) clean_interval: Duration,
    pub(super) cache_capacity: usize,
    pub(super) permission: Option<PermissionSetting>,
}

impl Default for CertificatePlan {
    fn default() -> Self {
        Self {
            storage: None,
            policies: Vec::new(),
            authorities: BTreeMap::new(),
            identity: None,
            manual: Vec::new(),
            automate: Vec::new(),
            disable_ocsp: false,
            disable_storage_check: false,
            disable_storage_clean: false,
            renew_interval: Duration::from_secs(600),
            ocsp_interval: Duration::from_secs(3600),
            clean_interval: Duration::from_secs(86400),
            cache_capacity: 10000,
            permission: None,
        }
    }
}

impl CertificatePlan {
    pub fn automated_names(&self) -> &[String] {
        &self.automate
    }
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
    pub fn authority_ids(&self) -> impl Iterator<Item = &str> {
        self.authorities.keys().map(String::as_str)
    }
}
