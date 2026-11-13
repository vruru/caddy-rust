use super::{ConnectionPolicy, ProtocolVersion};
use anyhow::{Result, ensure};
use aws_lc_rs::{agreement, rand::SystemRandom};
use rustls::{
    Error, NamedGroup, PeerMisbehaved, ServerConfig, SupportedCipherSuite,
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    server::ResolvesServerCert,
};
use std::sync::Arc;

impl ConnectionPolicy {
    /// Provision in the caller's bounded blocking metadata worker. No I/O or
    /// verifier construction is deferred into the handshake callback.
    pub fn build_config(
        &self,
        resolver: Arc<dyn ResolvesServerCert>,
        default_alpn: &[Vec<u8>],
    ) -> Result<ServerConfig> {
        ensure!(!self.cipher_suites.as_ref().is_some_and(|names|names.iter().any(|n|native_cipher(n))), "CBC policy requires the native HTTP TLS runtime");
        Ok(self.build_prepared(resolver, default_alpn)?.0)
    }
    pub(crate) fn build_prepared(&self,resolver:Arc<dyn ResolvesServerCert>,default_alpn:&[Vec<u8>])->Result<(ServerConfig,[u8;32],usize)>{
        let(config,identity,bytes,_,_)=self.build_prepared_with_verifier(resolver,default_alpn)?;
        Ok((config,identity,bytes))
    }
    pub(crate) fn build_prepared_with_verifier(
        &self,
        resolver: Arc<dyn ResolvesServerCert>,
        default_alpn: &[Vec<u8>],
    ) -> Result<(ServerConfig, [u8; 32], usize,Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,Option<Arc<[u16]>>)> {
        let mut provider = (*crate::crypto::provider()).clone();
        let mut native_ids=Vec::new();let mut has_cbc=false;
        if let Some(names) = &self.cipher_suites
            && !names.is_empty()
        {
            let mut selected = Vec::new();
            for name in names {
                if let Some(id)=native_cipher_id(name){has_cbc=true;if !native_ids.contains(&id){native_ids.push(id)}continue}

                let suite = cipher(name)?;
                // Go's CipherSuites only controls TLS1.2. Names of supported
                // TLS1.3 suites are accepted but never restrict TLS1.3.
                if suite.version().version == rustls::ProtocolVersion::TLSv1_2
                    && !selected
                        .iter()
                        .any(|existing: &SupportedCipherSuite| existing.suite() == suite.suite())
                {
                    selected.push(suite);
                    native_ids.push(u16::from(suite.suite()));
                }
            }
            // CBC-only policies still need a TLS12 parser configuration. Its
            // TLS12 wire is exclusively routed to SSL; these suites are never
            // negotiated by the Rustls fallback for such a policy.
            if selected.is_empty() && has_cbc {
                selected.extend(provider.cipher_suites.iter().copied().filter(|s|s.version().version==rustls::ProtocolVersion::TLSv1_2));
            }
            selected.extend(
                provider
                    .cipher_suites
                    .iter()
                    .copied()
                    .filter(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3),
            );
            provider.cipher_suites = selected;
        }
        if let Some(names) = &self.curves
            && !names.is_empty()
        {
            let mut selected = Vec::new();
            for name in names {
                let group = key_exchange_group(name)?;
                if !selected.iter().any(
                    |existing: &&'static dyn rustls::crypto::SupportedKxGroup| {
                        existing.name() == group.name()
                    },
                ) {
                    selected.push(group);
                }
            }
            provider.kx_groups = selected;
        }
        let minimum = self.protocol_min.unwrap_or(ProtocolVersion::Tls12);
        let maximum = self.protocol_max.unwrap_or(ProtocolVersion::Tls13);
        ensure!(minimum <= maximum, "TLS protocol minimum exceeds maximum");
        let mut versions = Vec::new();
        if maximum >= ProtocolVersion::Tls13 {
            versions.push(&rustls::version::TLS13);
        }
        if minimum <= ProtocolVersion::Tls12 {
            versions.push(&rustls::version::TLS12);
        }
        let auth = super::client_auth::prepare(self.client_auth.as_ref())?;
        let native_verifier=auth.verifier.clone();
        let builder = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)?;
        let builder = if let Some(verifier) = auth.verifier {
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let mut config = builder.with_cert_resolver(resolver);
        config.alpn_protocols = self
            .alpn
            .as_ref()
            .map(|names| names.iter().map(|name| name.as_bytes().to_vec()).collect())
            .unwrap_or_else(|| default_alpn.to_vec());
        ensure!(
            config
                .alpn_protocols
                .iter()
                .all(|protocol| !protocol.is_empty() && protocol.len() <= 255),
            "invalid ALPN protocol length"
        );
        if !config.alpn_protocols.is_empty()
            && !config
                .alpn_protocols
                .iter()
                .any(|protocol| protocol == b"acme-tls/1")
        {
            config.alpn_protocols.push(b"acme-tls/1".to_vec());
        }
        if self.client_auth.is_some() {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            config.max_tls13_tickets = 0;
            config.max_early_data_size = 0;
        }
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"caddy-connection-policy-v1");
        digest.update(self.identity);
        digest.update(auth.digest);
        Ok((config,digest.finalize().into(),auth.retained_bytes+if has_cbc{native_ids.len()*2+64}else{0},native_verifier,has_cbc.then(||Arc::from(native_ids))))
    }
    pub fn has_custom_settings(&self) -> bool {
        !self.matcher.is_empty()
            || self.certificate_selection.is_some()
            || self.protocol_min.is_some()
            || self.protocol_max.is_some()
            || self.cipher_suites.is_some()
            || self.curves.is_some()
            || self.alpn.is_some()
            || self.drop
            || self.client_auth.is_some()
            || self.default_sni.as_ref().is_some_and(|s| !s.is_empty())
            || self.fallback_sni.as_ref().is_some_and(|s| !s.is_empty())
    }
}
fn cipher(name: &str) -> Result<SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite::*;
    Ok(match name {
        "TLS_AES_128_GCM_SHA256" => TLS13_AES_128_GCM_SHA256,
        "TLS_AES_256_GCM_SHA384" => TLS13_AES_256_GCM_SHA384,
        "TLS_CHACHA20_POLY1305_SHA256" => TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
        _ => anyhow::bail!("unsupported TLS cipher suite"),
    })
}

// rustls's built-in AWS-LC profile does not expose P-521 key exchange, but
// the same pinned provider implements and validates ECDH on this curve.
// Keep it opt-in; this does not change the project's default provider.
#[derive(Debug)]
struct Secp521r1;
struct Secp521r1Exchange {
    private: agreement::EphemeralPrivateKey,
    public: agreement::PublicKey,
}
impl SupportedKxGroup for Secp521r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P521, &SystemRandom::new())
                .map_err(|_| Error::FailedToGetRandomBytes)?;
        let public = private
            .compute_public_key()
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        Ok(Box::new(Secp521r1Exchange { private, public }))
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
}
impl ActiveKeyExchange for Secp521r1Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let invalid = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
        // TLS negotiates only uncompressed NIST points here. AWS-LC also
        // accepts other encodings, so enforce the TLS shape before use.
        if peer.len() != 133 || peer.first() != Some(&0x04) {
            return Err(invalid);
        }
        let peer_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P521, peer);
        agreement::agree_ephemeral(self.private, peer_key, invalid, |secret| {
            Ok(SharedSecret::from(secret))
        })
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
    fn pub_key(&self) -> &[u8] {
        self.public.as_ref()
    }
}

/// Shared group mapping; callers preserve configured order and deduplicate.
pub(crate) fn key_exchange_group(name: &str) -> Result<&'static dyn SupportedKxGroup> {
    Ok(match name {
        "x25519" => rustls::crypto::ring::kx_group::X25519,
        "secp256r1" => rustls::crypto::ring::kx_group::SECP256R1,
        "secp384r1" => rustls::crypto::ring::kx_group::SECP384R1,
        "x25519mlkem768" => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        "secp521r1" => &Secp521r1,
        _ => anyhow::bail!("unsupported TLS key exchange group"),
    })
}

pub(crate) fn native_cipher(name:&str)->bool{native_cipher_id(name).is_some()}
fn native_cipher_id(name:&str)->Option<u16>{Some(match name{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"=>0xc009,"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"=>0xc00a,"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"=>0xc013,"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"=>0xc014,_=>return None})}
