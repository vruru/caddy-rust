//! Bounded in-memory HTTP-01 and RFC 8737 TLS-ALPN-01 challenge ownership.
//! This is an issuance building block, not an ACME client or listener. A lease
//! must remain alive until validation finishes; dropping it removes only that
//! registration generation. No proof or private key is included in Debug.

use anyhow::{Result, anyhow, ensure};
use rustls::{pki_types::PrivatePkcs8KeyDer, sign::CertifiedKey};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

pub const ACME_ALPN: &[u8] = b"acme-tls/1";
const MAX_HTTP: usize = 8192;
const MAX_TLS: usize = 4096;
const MAX_PER_OWNER: usize = 128;
const MAX_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Default)]
pub struct ChallengeRegistry {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    http: RwLock<HashMap<(String, String), HttpProof>>,
    tls: RwLock<HashMap<String, TlsProof>>,
    generation: AtomicU64,
}

struct HttpProof {
    owner: String,
    generation: u64,
    expires: Instant,
    authorization: Vec<u8>,
}

struct TlsProof {
    owner: String,
    generation: u64,
    expires: Instant,
    digest: [u8; 32],
    certificate: Arc<CertifiedKey>,
}

/// Non-cloneable proof ownership. Refresh returns a new generation, so an old
/// lease cannot remove its successor even when the same owner is reused.
pub struct ChallengeLease {
    inner: Arc<Inner>,
    generation: u64,
    kind: LeaseKind,
}

enum LeaseKind {
    Http((String, String)),
    Tls(String),
}

impl fmt::Debug for ChallengeRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeRegistry").finish_non_exhaustive()
    }
}

impl fmt::Debug for ChallengeLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeLease").finish_non_exhaustive()
    }
}

impl ChallengeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn generation(&self) -> Result<u64> {
        self.inner
            .generation
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| anyhow!("challenge generation exhausted"))
    }

    pub fn register_http(
        &self,
        owner: &str,
        domain: &str,
        token: &str,
        authorization: &str,
        ttl: Duration,
    ) -> Result<ChallengeLease> {
        let domain = normalize_domain(domain)?;
        validate_registration(owner, authorization, ttl)?;
        validate_token(token)?;
        ensure!(
            authorization.split_once('.').map(|p| p.0) == Some(token),
            "HTTP proof does not belong to its token"
        );
        let mut map = self
            .inner
            .http
            .write()
            .map_err(|_| anyhow!("challenge state unavailable"))?;
        let now = Instant::now();
        map.retain(|_, proof| proof.expires > now);
        let slot = (domain, token.to_owned());
        if let Some(existing) = map.get(&slot) {
            ensure!(
                existing.owner == owner && existing.authorization == authorization.as_bytes(),
                "challenge ownership or proof conflict"
            );
        }
        ensure!(
            map.contains_key(&slot) || map.len() < MAX_HTTP,
            "HTTP challenge capacity reached"
        );
        ensure!(
            map.contains_key(&slot)
                || map.values().filter(|p| p.owner == owner).count() < MAX_PER_OWNER,
            "HTTP challenge owner capacity reached"
        );
        let generation = self.generation()?;
        map.insert(
            slot.clone(),
            HttpProof {
                owner: owner.to_owned(),
                generation,
                expires: now + ttl,
                authorization: authorization.as_bytes().to_vec(),
            },
        );
        Ok(ChallengeLease {
            inner: self.inner.clone(),
            generation,
            kind: LeaseKind::Http(slot),
        })
    }

    /// `authority` is an already single-valued HTTP Host/:authority. The HTTP
    /// adapter must reject duplicate/ambiguous Host headers before this call.
    pub fn lookup_http(&self, authority: &str, token: &str) -> Option<Vec<u8>> {
        let domain = normalize_authority(authority).ok()?;
        validate_token(token).ok()?;
        let map = self.inner.http.read().ok()?;
        let proof = map.get(&(domain, token.to_owned()))?;
        (proof.expires > Instant::now()).then(|| proof.authorization.clone())
    }

    pub fn register_tls(
        &self,
        owner: &str,
        domain: &str,
        authorization: &str,
        ttl: Duration,
    ) -> Result<ChallengeLease> {
        let domain = normalize_domain(domain)?;
        validate_registration(owner, authorization, ttl)?;
        let digest: [u8; 32] = Sha256::digest(authorization.as_bytes()).into();
        // Key generation and certificate parsing never hold the shared lock.
        let certificate = Arc::new(challenge_certificate(&domain, &digest, ttl)?);
        let mut map = self
            .inner
            .tls
            .write()
            .map_err(|_| anyhow!("challenge state unavailable"))?;
        let now = Instant::now();
        map.retain(|_, proof| proof.expires > now);
        if let Some(existing) = map.get(&domain) {
            ensure!(
                existing.owner == owner && existing.digest == digest,
                "challenge ownership or proof conflict"
            );
        }
        ensure!(
            map.contains_key(&domain) || map.len() < MAX_TLS,
            "TLS challenge capacity reached"
        );
        ensure!(
            map.contains_key(&domain)
                || map.values().filter(|p| p.owner == owner).count() < MAX_PER_OWNER,
            "TLS challenge owner capacity reached"
        );
        let generation = self.generation()?;
        map.insert(
            domain.clone(),
            TlsProof {
                owner: owner.to_owned(),
                generation,
                expires: now + ttl,
                digest,
                certificate,
            },
        );
        Ok(ChallengeLease {
            inner: self.inner.clone(),
            generation,
            kind: LeaseKind::Tls(domain),
        })
    }

    /// Strict RFC 8737 negotiation: a mixed ALPN offer is not a challenge.
    /// The enclosing resolver must reject mixed offers containing acme-tls/1,
    /// rather than letting its normal certificate negotiate the ACME protocol.
    pub fn lookup_tls(&self, sni: &str, offered_alpn: &[&[u8]]) -> Option<Arc<CertifiedKey>> {
        if offered_alpn != [ACME_ALPN] {
            return None;
        }
        let domain = normalize_domain(sni).ok()?;
        let map = self.inner.tls.read().ok()?;
        let proof = map.get(&domain)?;
        (proof.expires > Instant::now()).then(|| proof.certificate.clone())
    }
}

impl Drop for ChallengeLease {
    fn drop(&mut self) {
        // A poisoned registry is fail-closed for reads and new registrations.
        // Recovering here only removes this lease, never repairs/serves state.
        match &self.kind {
            LeaseKind::Http(slot) => {
                let mut map = self.inner.http.write().unwrap_or_else(|e| e.into_inner());
                if map
                    .get(slot)
                    .is_some_and(|p| p.generation == self.generation)
                {
                    map.remove(slot);
                }
            }
            LeaseKind::Tls(slot) => {
                let mut map = self.inner.tls.write().unwrap_or_else(|e| e.into_inner());
                if map
                    .get(slot)
                    .is_some_and(|p| p.generation == self.generation)
                {
                    map.remove(slot);
                }
            }
        }
    }
}

fn challenge_certificate(domain: &str, digest: &[u8; 32], ttl: Duration) -> Result<CertifiedKey> {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|_| anyhow!("challenge key generation failed"))?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])
        .map_err(|_| anyhow!("challenge certificate names invalid"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    // A nonempty subject keeps SAN non-critical under RFC5280; the only
    // critical extension in this dedicated validation certificate is ACME.
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(digest));
    let now = SystemTime::now();
    params.not_before = (now - Duration::from_secs(60)).into();
    params.not_after = (now + ttl + Duration::from_secs(60)).into();
    let certificate = params
        .self_signed(&pair)
        .map_err(|_| anyhow!("challenge certificate signing failed"))?;
    let (remaining, parsed) = x509_parser::parse_x509_certificate(certificate.der())
        .map_err(|_| anyhow!("generated challenge certificate invalid"))?;
    ensure!(remaining.is_empty(), "generated challenge has trailing DER");
    let mut oids = HashSet::new();
    ensure!(
        parsed
            .extensions()
            .iter()
            .all(|e| oids.insert(e.oid.to_id_string())),
        "generated challenge contains duplicate extensions"
    );
    let san = parsed
        .subject_alternative_name()
        .map_err(|_| anyhow!("generated challenge SAN invalid"))?
        .ok_or_else(|| anyhow!("generated challenge SAN missing"))?;
    ensure!(
        san.value.general_names.len() == 1
            && matches!(san.value.general_names[0], x509_parser::extensions::GeneralName::DNSName(name) if name == domain),
        "generated challenge SAN mismatch"
    );
    let extensions = parsed
        .extensions()
        .iter()
        .filter(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .collect::<Vec<_>>();
    let mut expected = vec![0x04, 0x20];
    expected.extend_from_slice(digest);
    ensure!(
        extensions.len() == 1 && extensions[0].critical && extensions[0].value == expected,
        "generated challenge identifier mismatch"
    );
    ensure!(
        parsed.extensions().iter().filter(|e| e.critical).count() == 1,
        "generated challenge has additional critical extensions"
    );
    let public = parsed.public_key();
    ensure!(
        public.algorithm.algorithm.to_id_string() == "1.2.840.10045.2.1"
            && public
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_some_and(|oid| oid.to_id_string() == "1.2.840.10045.3.1.7"),
        "generated challenge must use P256"
    );
    let key = Zeroizing::new(pair.serialize_der());
    let signer = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(PrivatePkcs8KeyDer::from(key.to_vec()).into())
        .map_err(|_| anyhow!("challenge signing key invalid"))?;
    // rustls keys_match parses through webpki, which rejects the mandatory
    // RFC8737 critical extension. Only this private factory bypasses that
    // parser, after the strict extension checks above, with the same full-SPKI
    // equality check. User-supplied ordinary certificates still use keys_match.
    let signer_public = signer
        .public_key()
        .ok_or_else(|| anyhow!("challenge public key unavailable"))?;
    ensure!(
        signer_public.as_ref() == public.raw,
        "challenge key does not match certificate"
    );
    Ok(CertifiedKey::new(vec![certificate.der().clone()], signer))
}

fn validate_registration(owner: &str, authorization: &str, ttl: Duration) -> Result<()> {
    ensure!(
        !owner.is_empty()
            && owner.len() <= 128
            && owner.bytes().all(|b| (0x21..=0x7e).contains(&b)),
        "invalid challenge owner"
    );
    ensure!(
        ttl >= Duration::from_secs(1) && ttl <= MAX_TTL,
        "challenge TTL outside bounds"
    );
    ensure!(authorization.len() <= 1024, "challenge proof too large");
    let (token, thumbprint) = authorization
        .split_once('.')
        .ok_or_else(|| anyhow!("invalid challenge proof"))?;
    validate_token(token)?;
    ensure!(
        thumbprint.len() == 43 && thumbprint.bytes().all(base64url),
        "invalid challenge thumbprint"
    );
    Ok(())
}

fn base64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn validate_token(token: &str) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 512 && token.bytes().all(base64url),
        "invalid challenge token"
    );
    Ok(())
}

pub(crate) fn normalize_domain(raw: &str) -> Result<String> {
    ensure!(
        !raw.is_empty() && raw.len() <= 254 && raw.is_ascii(),
        "invalid DNS name"
    );
    let domain = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    ensure!(
        !domain.is_empty() && domain.len() <= 253 && domain.parse::<std::net::IpAddr>().is_err(),
        "invalid DNS name"
    );
    ensure!(
        domain.split('.').all(|label| !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid DNS name"
    );
    // Reject numeric dotted forms even if the std IP parser rejects leading zeros.
    ensure!(
        !domain.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "IP literals are not DNS challenge names"
    );
    Ok(domain)
}

fn normalize_authority(raw: &str) -> Result<String> {
    ensure!(
        raw.len() <= 260 && !raw.is_empty(),
        "invalid HTTP authority"
    );
    let domain = if let Some((domain, port)) = raw.rsplit_once(':') {
        ensure!(
            !domain.contains(':')
                && !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|n| n > 0),
            "invalid HTTP authority port"
        );
        domain
    } else {
        raw
    };
    normalize_domain(domain)
}
