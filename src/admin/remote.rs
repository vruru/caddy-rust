use super::{AdminError, ids};
use base64::Engine;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, TrustAnchor, UnixTime},
    server::ResolvesServerCert,
};
use serde::Deserialize;
use std::sync::Arc;
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub(super) struct Identity {
    pub identifiers: Vec<String>,
    pub issuers: Vec<serde_json::Value>,
}
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Remote {
    pub listen: String,
    pub access_control: Vec<Access>,
}
impl Default for Remote {
    fn default() -> Self {
        Self {
            listen: ":2021".to_owned(),
            access_control: Vec::new(),
        }
    }
}
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Access {
    pub public_keys: Vec<String>,
    pub permissions: Vec<Permission>,
}
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Permission {
    pub paths: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
}
fn invalid() -> AdminError {
    AdminError::new(400, "invalid_remote_admin_configuration")
}
pub(super) struct RemoteAccess {
    pub tls: Arc<ServerConfig>,
    anchors: Vec<TrustAnchor<'static>>,
    pins: Vec<CertificateDer<'static>>,
    access: Vec<(Vec<Vec<u8>>, Vec<Permission>)>,
}
fn spki(cert: &CertificateDer<'_>) -> Result<Vec<u8>, AdminError> {
    Ok(webpki::anchor_from_trusted_cert(cert)
        .map_err(|_| invalid())?
        .subject_public_key_info
        .as_ref()
        .to_vec())
}
impl RemoteAccess {
    pub fn new(
        config: &Remote,
        resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Arc<Self>, AdminError> {
        if config.access_control.len() > 1024 {
            return Err(invalid());
        }
        let mut roots = RootCertStore::empty();
        let mut ca_roots = RootCertStore::empty();
        let mut access = Vec::new();
        let mut anchors = Vec::new();
        let mut count = 0;
        let mut pins = Vec::new();
        for group in &config.access_control {
            let mut keys = Vec::new();
            for raw in &group.public_keys {
                count += 1;
                if count > 4096 || raw.len() > 128 * 1024 {
                    return Err(invalid());
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(raw)
                    .map_err(|_| invalid())?;
                let der = CertificateDer::from(bytes);
                let anchor = webpki::anchor_from_trusted_cert(&der)
                    .map_err(|_| invalid())?
                    .to_owned();
                keys.push(anchor.subject_public_key_info.as_ref().to_vec());
                if super::remote_pin::is_end_entity(&der).map_err(|_| invalid())? {
                    pins.push(der.clone());
                } else {
                    anchors.push(anchor);
                    ca_roots.add(der.clone()).map_err(|_| invalid())?;
                }
                roots.add(der).map_err(|_| invalid())?;
            }
            for p in &group.permissions {
                if let Some(paths) = &p.paths {
                    for path in paths {
                        if !path.is_empty()
                            && path != "/"
                            && (!path.starts_with('/') || ids::clean(path) != *path)
                        {
                            return Err(invalid());
                        }
                    }
                }
                if p.methods.as_ref().is_some_and(|m| {
                    m.iter()
                        .any(|m| http::Method::from_bytes(m.as_bytes()).is_err())
                }) {
                    return Err(invalid());
                }
            }
            access.push((keys, group.permissions.clone()));
        }
        let provider = crate::crypto::provider();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .map_err(|_| invalid())?;
        // EE pins are never delegated certificate-authority trust. The full
        // roots object supplies only compatibility hints/signature verification.
        let ca_verifier = if ca_roots.is_empty() {
            None
        } else {
            Some(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(ca_roots),
                    provider.clone(),
                )
                .build()
                .map_err(|_| invalid())?
                    as Arc<dyn rustls::server::danger::ClientCertVerifier>,
            )
        };
        let verifier = super::remote_pin::Verifier::new(verifier, ca_verifier, pins.clone());
        let mut tls = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid())?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Session resumption would bypass validating against a changed trust set.
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        tls.send_tls13_tickets = 0;
        Ok(Arc::new(Self {
            tls: Arc::new(tls),
            anchors,
            pins,
            access,
        }))
    }
    /// Independently obtain the actual verified path. Raw peer-supplied trailing
    /// certificates are never used for application authorization.
    pub fn verified_grants(&self, chain: &[CertificateDer<'_>]) -> Result<Vec<usize>, AdminError> {
        let first = chain
            .first()
            .ok_or_else(|| AdminError::new(401, "client_certificate_required"))?;
        if chain.len() > 64 {
            return Err(invalid());
        }
        let keys = if self.pins.iter().any(|pin| pin.as_ref() == first.as_ref()) {
            super::remote_pin::validate(first, UnixTime::now())
                .map_err(|_| AdminError::new(401, "client_certificate_not_trusted"))?;
            vec![spki(first)?]
        } else {
            let ee = webpki::EndEntityCert::try_from(first).map_err(|_| invalid())?;
            let provider = rustls::crypto::ring::default_provider();
            let verified = ee
                .verify_for_usage(
                    provider.signature_verification_algorithms.all,
                    &self.anchors,
                    &chain[1..],
                    UnixTime::now(),
                    webpki::KeyUsage::client_auth(),
                    None,
                    None,
                )
                .map_err(|_| AdminError::new(401, "client_certificate_not_trusted"))?;
            let mut keys = vec![spki(first)?];
            for cert in verified.intermediate_certificates() {
                keys.push(spki(&cert.der())?);
            }
            keys.push(verified.anchor().subject_public_key_info.as_ref().to_vec());
            keys
        };
        let mut grants = Vec::new();
        for key in &keys {
            for (i, (allowed, _)) in self.access.iter().enumerate() {
                if allowed.contains(key) && !grants.contains(&i) {
                    grants.push(i);
                }
            }
        }
        if grants.is_empty() {
            return Err(AdminError::new(401, "client_identity_not_authorized"));
        }
        Ok(grants)
    }
    pub fn check(&self, grants: &[usize], method: &str, path: &str) -> Result<(), AdminError> {
        // Caddy chooses the first matching configured identity and requires every
        // permission entry in that access block to match (entries are not OR'd).
        let index = *grants
            .first()
            .ok_or_else(|| AdminError::new(401, "client_identity_not_authorized"))?;
        let (_, permissions) = self.access.get(index).ok_or_else(invalid)?;
        for permission in permissions {
            if permission
                .methods
                .as_ref()
                .is_some_and(|m| !m.iter().any(|m| m == method))
            {
                return Err(AdminError::new(403, "client_method_not_authorized"));
            }
            if permission
                .paths
                .as_ref()
                .is_some_and(|paths| !paths.iter().any(|p| path_allowed(path, p)))
            {
                return Err(AdminError::new(403, "client_path_not_authorized"));
            }
        }
        Ok(())
    }
}
fn path_allowed(request: &str, allowed: &str) -> bool {
    let trailing = request.ends_with('/');
    let request = ids::clean(request);
    let request = request.trim_end_matches('/');
    if allowed.is_empty() || allowed == "/" {
        return true;
    }
    let require_slash = allowed.ends_with('/');
    let allowed = allowed.trim_end_matches('/');
    if request == allowed {
        !require_slash || trailing
    } else {
        request.starts_with(&format!("{allowed}/"))
    }
}

#[derive(Clone)]
pub(super) struct Grant {
    pub chain: Vec<CertificateDer<'static>>,
    pub method: String,
    pub path: String,
}
