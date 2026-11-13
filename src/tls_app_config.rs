//! Generation-scoped Caddy certificate configuration and services. Parsing is
//! strict; certificate acquisition, trust installation and maintenance have
//! separate lifecycle boundaries owned by the root configuration transaction.
#[path = "tls_app_config/decode.rs"]
mod decode;
#[path = "tls_app_config/error.rs"]
mod error;
#[path = "tls_app_config/external.rs"]
mod external;
#[path = "tls_app_config/issuer_account_key.rs"]
mod issuer_account_key;
#[path = "tls_app_config/issuer_values.rs"]
mod issuer_values;
#[path = "tls_app_config/subject_values.rs"]
mod subject_values;
pub(crate) use subject_values::ExplicitSubjects;
#[path = "tls_app_config/issuer_parse.rs"]
mod issuer_parse;
#[path = "tls_app_config/loaders.rs"]
mod loaders;
#[path = "tls_app_config/material.rs"]
mod material;
#[path = "tls_app_config/model.rs"]
mod model;
#[path = "tls_app_config/parse.rs"]
mod parse;
#[path = "tls_app_config/permission.rs"]
mod permission;
#[path = "tls_app_config/pki_parse.rs"]
mod pki_parse;
#[path = "tls_app_config/resident_cache.rs"]
mod resident_cache;
pub(crate) use resident_cache::Preparation as CertificatePreparation;
#[path = "tls_app_config/schema.rs"]
mod schema;
#[path = "tls_app_config/services.rs"]
mod services;
#[path = "tls_app_config/storage.rs"]
mod storage;

pub use error::{ConfigError, ConfigErrorKind};
pub use model::CertificatePlan;
pub use services::{
    CertificateEvent, CertificateServices, PrepareContext, PrepareMode, RetainedCertificates,
};
pub use storage::{CertificatePaths, CertificateResources};

/// Only these views belong to the certificate app. The root adapter validates
/// the remaining root/admin/app keys before constructing this borrowed view.
pub struct CertificateViews<'a> {
    pub storage: Option<&'a serde_json::Value>,
    pub tls: Option<&'a serde_json::Value>,
    pub pki: Option<&'a serde_json::Value>,
    pub identity: Option<&'a serde_json::Value>,
}

impl CertificatePlan {
    pub(crate) fn challenge_bind_hosts(&self)->impl Iterator<Item=&str>+Clone {
        self.policies.iter().flat_map(|policy|policy.issuers.iter()).chain(self.identity.iter().flat_map(|identity|identity.issuers.iter())).filter_map(|issuer|match issuer {
            model::Issuer::Acme(settings) if !settings.bind_host.is_empty() && !settings.config.challenge_types.is_empty()=>Some(settings.bind_host.as_str()),_=>None,
        })
    }
    pub fn parse(views: CertificateViews<'_>) -> Result<Self, ConfigError> {
        parse::parse(views)
    }
}

#[path="tls_app_config/managed_client.rs"]
mod managed_client;
pub(crate) use managed_client::{ManagedClientSource,ClientBinding,BoundClientIo};
