use crate::{
    acme_wire::KeyType,
    cert_automation::AcmeIssuerConfig,
    local_pki::{CaConfig, InternalIssuerOptions},
    stek::TicketMode,
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

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
    // None preserves old standalone construction; Some(empty) uses the Caddy default.
    pub test_ca: Option<String>,
    pub values: Option<std::sync::Arc<super::issuer_values::Input>>,
    pub config: AcmeIssuerConfig,
    pub account_key: Option<std::sync::Arc<super::issuer_account_key::Input>>,
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
    pub subjects: std::sync::Arc<super::subject_values::Input>,
    pub issuers: Vec<Issuer>,
    pub storage: Option<PathBuf>,
    pub renewal_ratio: f64,
    pub key_type: KeyType,
    pub must_staple: bool,
    pub reuse_private_keys: bool,
    pub on_demand: bool,
    pub managers: Vec<super::external::Manager>,
    pub disable_ocsp: bool,
    pub ocsp_overrides: BTreeMap<String, String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            subjects: super::subject_values::Input::empty(super::subject_values::Kind::Policy),
            issuers: Vec::new(),
            storage: None,
            renewal_ratio: 1.0 / 3.0,
            key_type: KeyType::P256,
            must_staple: false,
            reuse_private_keys: false,
            on_demand: false,
            managers: Vec::new(),
            disable_ocsp: false,
            ocsp_overrides: BTreeMap::new(),
        }
    }
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
    pub(super) tls_resolvers: std::sync::Arc<[String]>,
    pub(super) storage: Option<PathBuf>,
    pub(super) http_challenge_port: Option<u16>,
    pub(super) alpn_challenge_port: Option<u16>,
    pub(super) ticket_mode: TicketMode,
    pub(super) policies: Vec<Policy>,
    pub(super) authorities: BTreeMap<String, Authority>,
    pub(super) identity: Option<Identity>,
    pub(super) manual: super::manual_values::Sources,
    pub(super) automate: std::sync::Arc<super::subject_values::Input>,
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
            tls_resolvers: std::sync::Arc::from([]),
            http_challenge_port: None,
            alpn_challenge_port: None,
            ticket_mode: TicketMode::RuntimeDefault,
            policies: Vec::new(),
            authorities: BTreeMap::new(),
            identity: None,
            manual: super::manual_values::Sources::default(),
            automate: super::subject_values::Input::empty(super::subject_values::Kind::Automate),
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
    pub(crate) fn http_application_ports(&mut self,http:u16,https:u16){
        self.http_challenge_port=Some(http);self.alpn_challenge_port=Some(https);
    }
    /// Typed configuration, available to provisioning/inspection callers.
    /// The actual native process activates it only after Root publication.
    pub fn session_tickets(&self) -> &TicketMode {
        &self.ticket_mode
    }

    /// Global defaults for TLS DNS consumers. Individual handlers may override.
    /// Address validation belongs to the consuming module, as in Caddy.
    pub fn dns_resolvers(&self) -> &[String] {
        &self.tls_resolvers
    }

    pub fn automated_names(&self) -> &[String] {
        self.automate.raw()
    }
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
    pub fn authority_ids(&self) -> impl Iterator<Item = &str> {
        self.authorities.keys().map(String::as_str)
    }
}
