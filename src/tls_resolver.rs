//! Validated certificate snapshots and ACME-only challenge certificate routing.
//! No issuance, certificate storage writes, OCSP fetching, trust-chain validation,
//! on-demand issuance or listener configuration is performed here. Callers own
//! those policies. Successful replacement affects future handshakes only.

use crate::challenge::{ACME_ALPN, ChallengeRegistry, normalize_domain};
use anyhow::{Result, anyhow, ensure};
use rustls::{
    SignatureScheme,
    pki_types::CertificateDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use x509_parser::extensions::GeneralName;

const MAX_CERTIFICATES: usize = 4096;
const MAX_NAMES: usize = 65536;
const MAX_CERT_BYTES: usize = 4 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 128 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPSERT_ATTEMPTS: usize = 8;

/// Input is borrowed and never included in Debug or error strings. DNS aliases
/// are explicit, must be covered by the leaf SAN, and may include one leading
/// wildcard label. IP/default-certificate selection is outside this resolver.
pub struct CertificateInput<'a> {
    pub names: &'a [String],
    pub certificate_pem: &'a [u8],
    pub private_key_pem: &'a [u8],
}

struct LoadedCertificate {
    key: Arc<CertifiedKey>,
    not_before: i64,
    not_after: i64,
    size: usize,
    signature_profile: Vec<SignatureScheme>,
}

#[derive(Default)]
struct Snapshot {
    generation: u64,
    names: HashMap<String, Vec<Arc<LoadedCertificate>>>,
}

/// Each map is an immutable snapshot behind one short-held lock. Returning an
/// Arc keeps old signing material alive for handshakes/connections using it.
pub struct HotCertificateResolver {
    challenges: ChallengeRegistry,
    certificates: RwLock<Arc<Snapshot>>,
}

impl fmt::Debug for HotCertificateResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HotCertificateResolver")
            .finish_non_exhaustive()
    }
}

impl HotCertificateResolver {
    pub fn new(challenges: ChallengeRegistry) -> Self {
        Self {
            challenges,
            certificates: RwLock::new(Arc::new(Snapshot::default())),
        }
    }

    /// Validate the entire candidate outside the lock, then publish one snapshot.
    /// Any invalid key, SAN, PEM, validity or capacity leaves the
    /// currently published snapshot unchanged. Empty input intentionally clears.
    pub fn replace(&self, inputs: &[CertificateInput<'_>]) -> Result<()> {
        ensure!(
            inputs.len() <= MAX_CERTIFICATES,
            "certificate count limit exceeded"
        );
        let mut bytes = 0usize;
        let mut next: HashMap<String, Vec<Arc<LoadedCertificate>>> = HashMap::new();
        for input in inputs {
            bytes = bytes
                .checked_add(input.certificate_pem.len())
                .and_then(|n| n.checked_add(input.private_key_pem.len()))
                .ok_or_else(|| anyhow!("certificate data limit exceeded"))?;
            ensure!(bytes <= MAX_TOTAL_BYTES, "certificate data limit exceeded");
            let (names, cert) = load_certificate(input)?;
            let cert = Arc::new(cert);
            for name in names {
                ensure!(
                    next.contains_key(&name) || next.len() < MAX_NAMES,
                    "certificate alias limit exceeded"
                );
                let candidates = next.entry(name).or_default();
                ensure!(
                    candidates.len() < 8,
                    "certificate candidates per alias limit exceeded"
                );
                candidates.push(cert.clone());
            }
        }
        let mut guard = self
            .certificates
            .write()
            .map_err(|_| anyhow!("certificate state unavailable"))?;
        let generation = guard
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("certificate generation exhausted"))?;
        let previous = std::mem::replace(
            &mut *guard,
            Arc::new(Snapshot {
                generation,
                names: next,
            }),
        );
        drop(guard);
        drop(previous);
        Ok(())
    }

    /// Atomically update aliases for one validated certificate. Concurrent
    /// updates for unrelated aliases merge optimistically outside the lock; a failed
    /// candidate cannot replace the current key. This does not remove aliases
    /// omitted by the caller: full configuration reload must use replace().
    pub fn upsert(&self, input: &CertificateInput<'_>) -> Result<()> {
        let (names, cert) = load_certificate(input)?;
        let cert = Arc::new(cert);
        for _ in 0..MAX_UPSERT_ATTEMPTS {
            let base = self
                .certificates
                .read()
                .map_err(|_| anyhow!("certificate state unavailable"))?
                .clone();
            // Cloning, merging, capacity checks and destruction of discarded
            // candidates do not block certificate lookups or other publishers.
            let mut next = base.names.clone();
            for name in &names {
                ensure!(
                    next.contains_key(name) || next.len() < MAX_NAMES,
                    "certificate alias limit exceeded"
                );
                let candidates = next.entry(name.clone()).or_default();
                // Renew one signing profile without discarding e.g. the RSA
                // certificate when an ECDSA certificate for the same name renews.
                candidates.retain(|old| old.signature_profile != cert.signature_profile);
                ensure!(
                    candidates.len() < 8,
                    "certificate candidates per alias limit exceeded"
                );
                candidates.push(cert.clone());
            }
            validate_snapshot_size(&next)?;
            let generation = base
                .generation
                .checked_add(1)
                .ok_or_else(|| anyhow!("certificate generation exhausted"))?;
            let candidate = Arc::new(Snapshot {
                generation,
                names: next,
            });
            let mut guard = self
                .certificates
                .write()
                .map_err(|_| anyhow!("certificate state unavailable"))?;
            if !Arc::ptr_eq(&base, &guard) {
                drop(guard);
                continue;
            }
            let previous = std::mem::replace(&mut *guard, candidate);
            drop(guard);
            drop(previous);
            return Ok(());
        }
        Err(anyhow!(
            "certificate update conflicted with concurrent publication; retry required"
        ))
    }

    pub fn generation(&self) -> Option<u64> {
        Some(self.certificates.read().ok()?.generation)
    }

    /// Pure selection entry used by the rustls trait and isolated TLS QA. An
    /// offered ACME protocol is never allowed to fall through to ordinary TLS.
    pub fn select(
        &self,
        sni: Option<&str>,
        offered_alpn: &[&[u8]],
        signature_schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let sni = normalize_domain(sni?).ok()?;
        if offered_alpn.contains(&ACME_ALPN) {
            let key = self.challenges.lookup_tls(&sni, offered_alpn)?;
            key.key.choose_scheme(signature_schemes)?;
            return Some(key);
        }
        let snapshot = self.certificates.read().ok()?.clone();
        let now =
            i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
        let select = |candidates: &Vec<Arc<LoadedCertificate>>| {
            candidates
                .iter()
                .find(|entry| {
                    now >= entry.not_before
                        && now < entry.not_after
                        && entry.key.key.choose_scheme(signature_schemes).is_some()
                })
                .map(|entry| entry.key.clone())
        };
        if let Some(key) = snapshot.names.get(&sni).and_then(select) {
            return Some(key);
        }
        let (_, suffix) = sni.split_once('.')?;
        snapshot.names.get(&format!("*.{suffix}")).and_then(select)
    }
}

impl ResolvesServerCert for HotCertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // ALPN is bounded by the TLS ClientHello framing. Collecting borrowed
        // slices does not clone peer data or retain it after this handshake.
        let alpn = hello
            .alpn()
            .map(|v| v.collect::<Vec<_>>())
            .unwrap_or_default();
        self.select(hello.server_name(), &alpn, hello.signature_schemes())
    }
}

fn load_certificate(input: &CertificateInput<'_>) -> Result<(Vec<String>, LoadedCertificate)> {
    ensure!(
        !input.names.is_empty() && input.names.len() <= MAX_NAMES,
        "certificate aliases outside bounds"
    );
    ensure!(
        !input.certificate_pem.is_empty()
            && input.certificate_pem.len() <= MAX_CERT_BYTES
            && !input.private_key_pem.is_empty()
            && input.private_key_pem.len() <= MAX_KEY_BYTES,
        "certificate material outside bounds"
    );
    let blocks = crate::certmagic::pem_blocks(input.certificate_pem, "tls-candidate")?;
    let mut chain = Vec::with_capacity(blocks.len());
    for (label, der) in &blocks {
        ensure!(label == "CERTIFICATE", "unexpected certificate PEM label");
        let (remaining, _) = x509_parser::parse_x509_certificate(der)
            .map_err(|_| anyhow!("invalid certificate DER"))?;
        ensure!(remaining.is_empty(), "trailing certificate DER");
        chain.push(CertificateDer::from(der.to_vec()));
    }
    let key = crate::certmagic::signing_key(input.private_key_pem, "tls-candidate")?;
    let certified = CertifiedKey::new(chain, key);
    certified
        .keys_match()
        .map_err(|_| anyhow!("certificate and private key do not match"))?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&blocks[0].1)
        .map_err(|_| anyhow!("invalid leaf certificate"))?;
    ensure!(
        leaf.validity().is_valid(),
        "certificate is not currently valid"
    );
    // A validation-only challenge certificate must never enter normal serving.
    ensure!(
        !leaf
            .extensions()
            .iter()
            .any(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31"),
        "ACME challenge certificate cannot be a normal certificate"
    );
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| anyhow!("invalid certificate SAN"))?
        .ok_or_else(|| anyhow!("certificate has no SAN"))?;
    let dns_names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| {
            if let GeneralName::DNSName(name) = name {
                Some(*name)
            } else {
                None
            }
        })
        // Extra SANs unsupported by this DNS-only selector (e.g. underscore
        // labels) do not invalidate another valid, explicitly requested alias.
        .filter_map(|name| normalize_pattern(name).ok())
        .collect::<Vec<_>>();
    let names = input
        .names
        .iter()
        .map(|s| normalize_pattern(s))
        .collect::<Result<Vec<_>>>()?;
    for name in &names {
        ensure!(
            dns_names.iter().any(|san| covers(san, name)),
            "certificate SAN does not cover alias"
        );
    }
    let signature_profile = [
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ED25519,
    ]
    .into_iter()
    .filter(|scheme| certified.key.choose_scheme(&[*scheme]).is_some())
    .collect::<Vec<_>>();
    ensure!(
        !signature_profile.is_empty(),
        "certificate has unsupported signing profile"
    );
    Ok((
        names,
        LoadedCertificate {
            key: Arc::new(certified),
            signature_profile,
            size: input.certificate_pem.len() + input.private_key_pem.len(),
            not_before: leaf.validity().not_before.timestamp(),
            not_after: leaf.validity().not_after.timestamp(),
        },
    ))
}

fn validate_snapshot_size(names: &HashMap<String, Vec<Arc<LoadedCertificate>>>) -> Result<()> {
    let mut unique = HashSet::new();
    let mut size = 0usize;
    for cert in names.values().flatten() {
        if unique.insert(Arc::as_ptr(cert)) {
            ensure!(
                unique.len() <= MAX_CERTIFICATES,
                "certificate count limit exceeded"
            );
            size = size
                .checked_add(cert.size)
                .ok_or_else(|| anyhow!("certificate data limit exceeded"))?;
            ensure!(size <= MAX_TOTAL_BYTES, "certificate data limit exceeded");
        }
    }
    Ok(())
}

fn normalize_pattern(raw: &str) -> Result<String> {
    if let Some(suffix) = raw.strip_prefix("*.") {
        let suffix = normalize_domain(suffix)?;
        ensure!(
            suffix.contains('.'),
            "wildcard suffix must have at least two labels"
        );
        Ok(format!("*.{suffix}"))
    } else {
        normalize_domain(raw)
    }
}

fn covers(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }
    if name.starts_with("*.") {
        return false;
    }
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        name.split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
    })
}
