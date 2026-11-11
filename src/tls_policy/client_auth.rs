//! Caddy's client-certificate modes. CertificateVerify is always authenticated;
//! only the explicit request/require modes omit certificate-chain trust checks.
use super::{ClientAuth, ClientAuthMode};
use anyhow::{Result, bail, ensure};
use base64::Engine;
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::{io::Read, sync::Arc};
use zeroize::Zeroizing;

const MAX_CERTIFICATES: usize = 4096;
const MAX_MATERIAL: usize = 16 << 20;
const MAX_ONE_CERTIFICATE: usize = 128 << 10;

pub(super) struct PreparedAuth {
    pub verifier: Option<Arc<dyn ClientCertVerifier>>,
    pub digest: [u8; 32],
    pub retained_bytes: usize,
}

/// Run during bounded blocking provisioning, never in the async socket reactor.
pub(super) fn prepare(config: Option<&ClientAuth>) -> Result<PreparedAuth> {
    let Some(config) = config.filter(|config| config.is_active()) else {
        return Ok(PreparedAuth {
            verifier: None,
            digest: [0; 32],
            retained_bytes: 0,
        });
    };
    ensure!(
        config.ca.is_none()
            || (config.trusted_ca_certs.is_empty() && config.trusted_ca_certs_pem_files.is_empty()),
        "conflicting client authentication trust CA"
    );
    let has_trust = config.ca.is_some()
        || !config.trusted_ca_certs.is_empty()
        || !config.trusted_ca_certs_pem_files.is_empty()
        || !config.trusted_leaf_certs.is_empty();
    let mode = config.mode.unwrap_or(if has_trust {
        ClientAuthMode::RequireAndVerify
    } else {
        ClientAuthMode::Require
    });
    let verify_chain = matches!(
        mode,
        ClientAuthMode::VerifyIfGiven | ClientAuthMode::RequireAndVerify
    );
    let mut budget = Budget { count: 0, bytes: 0 };
    let mut roots = Vec::new();
    if let Some(module) = &config.ca {
        load_pool(module, 0, &mut budget, &mut roots)?;
    } else {
        for raw in &config.trusted_ca_certs {
            roots.push(decode(raw, &mut budget)?);
        }
        for path in &config.trusted_ca_certs_pem_files {
            roots.extend(read_pem(path, PemSource::DeprecatedCa, &mut budget)?);
        }
    }
    let mut pin_groups = Vec::new();
    let mut deprecated_pins = Vec::new();
    for raw in &config.trusted_leaf_certs {
        deprecated_pins.push(decode(raw, &mut budget)?);
    }
    if !deprecated_pins.is_empty() {
        pin_groups.push(deprecated_pins);
    }
    for raw in &config.verifiers {
        let obj = super::require_object(raw)?;
        super::check_unknown(
            obj,
            &["verifier", "leaf_certs_loaders"],
            "client certificate verifier",
        )?;
        ensure!(
            obj.get("verifier").and_then(serde_json::Value::as_str) == Some("leaf"),
            "unsupported client certificate verifier"
        );
        let mut group = Vec::new();
        if let Some(loaders) = obj.get("leaf_certs_loaders").filter(|v| !v.is_null()) {
            for loader in super::require_array(loaders, "leaf certificate loaders")? {
                let obj = super::require_object(loader)?;
                match obj.get("loader").and_then(serde_json::Value::as_str) {
                    Some("file") => {
                        super::check_unknown(obj, &["loader", "files"], "leaf file loader")?;
                        for path in super::parse_string_array(obj.get("files"), "leaf files")?
                            .unwrap_or_default()
                        {
                            group.extend(read_pem(&path, PemSource::LeafFile, &mut budget)?);
                        }
                    }
                    Some("pem") => {
                        super::check_unknown(obj, &["loader", "certificates"], "leaf PEM loader")?;
                        for raw in
                            super::parse_string_array(obj.get("certificates"), "leaf certificates")?
                                .unwrap_or_default()
                        {
                            group.extend(parse_pem(
                                raw.as_bytes(),
                                PemSource::InlineLeaf,
                                &mut budget,
                            )?);
                        }
                    }
                    _ => bail!("unsupported client leaf certificate loader"),
                }
            }
        }
        // Each verifier must succeed; preserve each leaf verifier's own set.
        pin_groups.push(group);
    }
    let mut pool = RootCertStore::empty();
    let implicit_system = verify_chain
        && config.ca.is_none()
        && config.trusted_ca_certs.is_empty()
        && config.trusted_ca_certs_pem_files.is_empty();
    let explicit_system = config
        .ca
        .as_ref()
        .and_then(|value| value.get("provider"))
        .and_then(serde_json::Value::as_str)
        == Some("system");
    if implicit_system {
        load_system(&mut budget, &mut roots)?;
    }
    use sha2::{Digest, Sha256};
    let mut raw_seen = std::collections::HashSet::new();
    let mut retained_root_bytes = 0usize;
    for root in roots {
        if !raw_seen.insert(<Sha256 as Digest>::digest(root.as_ref())) {
            continue;
        }
        pool.add(root)
            .map_err(|_| anyhow::anyhow!("invalid client trust anchor"))?;
    }
    let platform_system = explicit_system
        && cfg!(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        ))
        && ["SSL_CERT_FILE", "SSL_CERT_DIR"]
            .iter()
            .all(|name| std::env::var_os(name).is_none_or(|value| value.is_empty()));
    // An implicit system pool verifies the chain but Go keeps ClientCAs nil,
    // so it does not advertise those roots as client-certificate hints.
    let hints = if implicit_system || platform_system {
        Vec::new()
    } else {
        pool.subjects()
    };
    let hint_bytes = hints
        .iter()
        .try_fold(0usize, |size, hint| {
            size.checked_add(hint.as_ref().len() + 2)
        })
        .ok_or_else(|| anyhow::anyhow!("client CA hint length overflow"))?;
    // Leave room for the signature schemes and extension framing in TLS1.3.
    ensure!(
        hint_bytes <= 63 << 10,
        "client CA hints exceed TLS CertificateRequest capacity"
    );
    let mut digest = Sha256::new();
    digest.update(b"caddy-client-auth-material-v2");
    let mandatory = !pin_groups.is_empty()
        || matches!(
            mode,
            ClientAuthMode::Require | ClientAuthMode::RequireAndVerify
        );
    digest.update([
        mode as u8,
        verify_chain as u8,
        mandatory as u8,
        implicit_system as u8,
        explicit_system as u8,
        platform_system as u8,
    ]);
    digest.update((pool.roots.len() as u64).to_be_bytes());
    let mut anchor_digests = Vec::with_capacity(pool.roots.len());
    for root in &pool.roots {
        let constraints = root
            .name_constraints
            .as_ref()
            .map_or(&[][..], |value| value.as_ref());
        let mut anchor = Sha256::new();
        for bytes in [
            root.subject_public_key_info.as_ref(),
            root.subject.as_ref(),
            constraints,
        ] {
            retained_root_bytes = retained_root_bytes.saturating_add(bytes.len());
            anchor.update((bytes.len() as u64).to_be_bytes());
            anchor.update(bytes);
        }
        anchor_digests.push(<[u8; 32]>::from(anchor.finalize()));
    }
    anchor_digests.sort_unstable();
    for anchor in anchor_digests {
        digest.update(anchor);
    }
    digest.update((pin_groups.len() as u64).to_be_bytes());
    let mut pin_bytes = pin_groups.capacity() * std::mem::size_of::<Vec<CertificateDer<'static>>>();
    for group in &pin_groups {
        pin_bytes = pin_bytes
            .saturating_add(group.capacity() * std::mem::size_of::<CertificateDer<'static>>());
        digest.update((group.len() as u64).to_be_bytes());
        for cert in group {
            pin_bytes = pin_bytes.saturating_add(cert.len().saturating_mul(2));
            digest.update((cert.len() as u64).to_be_bytes());
            digest.update(cert.as_ref());
        }
    }
    let digest = digest.finalize().into();
    let provider = crate::crypto::provider();
    let mut retained_bytes = pin_bytes
        .saturating_add(hints.capacity() * std::mem::size_of::<DistinguishedName>())
        .saturating_add(hint_bytes);
    let normal = if verify_chain && !pool.is_empty() {
        retained_bytes = retained_bytes
            .saturating_add(
                pool.roots.capacity()
                    * std::mem::size_of::<rustls::pki_types::TrustAnchor<'static>>(),
            )
            .saturating_add(retained_root_bytes);
        // The stock verifier defaults to a second copy of CA hints; we use
        // its path verifier only and explicitly clear the unused copy.
        Some(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(pool),
                provider.clone(),
            )
            .clear_root_hint_subjects()
            .build()
            .map_err(|_| anyhow::anyhow!("client trust verifier unavailable"))?,
        )
    } else {
        None
    };
    Ok(PreparedAuth {
        retained_bytes,
        digest,
        verifier: Some(Arc::new(Verifier {
            mode,
            verify_chain,
            normal,
            hints,
            pin_groups,
            algorithms: provider.signature_verification_algorithms,
        })),
    })
}

struct Budget {
    count: usize,
    bytes: usize,
}
impl Budget {
    fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        self.charge(bytes.len())?;
        parse_certificate(bytes)
    }
    fn charge(&mut self, size: usize) -> Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("client trust budget exceeded"))?;
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("client trust budget exceeded"))?;
        ensure!(
            self.count <= MAX_CERTIFICATES
                && self.bytes <= MAX_MATERIAL
                && size <= MAX_ONE_CERTIFICATE,
            "client trust budget exceeded"
        );
        Ok(())
    }
}
fn parse_certificate(bytes: &[u8]) -> Result<()> {
    let (rest, _) = x509_parser::parse_x509_certificate(bytes)
        .map_err(|_| anyhow::anyhow!("invalid client certificate DER"))?;
    ensure!(rest.is_empty(), "trailing client certificate DER");
    Ok(())
}
fn decode(raw: &str, budget: &mut Budget) -> Result<CertificateDer<'static>> {
    ensure!(
        raw.len() <= MAX_ONE_CERTIFICATE * 2,
        "client certificate too large"
    );
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| anyhow::anyhow!("invalid client certificate base64"))?;
    budget.accept(&bytes)?;
    Ok(CertificateDer::from(bytes))
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PemSource {
    Ca,
    DeprecatedCa,
    LeafFile,
    InlineLeaf,
}

fn read_pem(
    path: &str,
    source: PemSource,
    budget: &mut Budget,
) -> Result<Vec<CertificateDer<'static>>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "client trust input must be a regular file"
    );
    ensure!(
        metadata.len() <= MAX_MATERIAL as u64,
        "client trust PEM too large"
    );
    let mut data = Zeroizing::new(Vec::with_capacity(metadata.len() as usize + 1));
    file.take((MAX_MATERIAL + 1) as u64)
        .read_to_end(&mut data)?;
    parse_pem(&data, source, budget)
}

fn pem_line(mut line: &[u8]) -> &[u8] {
    if let Some(rest) = line.strip_suffix(b"\n") {
        line = rest.strip_suffix(b"\r").unwrap_or(rest);
    }
    while matches!(line.last(), Some(b' ' | b'\t')) {
        line = &line[..line.len() - 1];
    }
    line
}

fn parse_pem(
    data: &[u8],
    source: PemSource,
    budget: &mut Budget,
) -> Result<Vec<CertificateDer<'static>>> {
    ensure!(data.len() <= MAX_MATERIAL, "client trust PEM too large");
    // These are Caddy trust inputs, not CertMagic private-key bundles. Go's
    // PEM decoder finds blocks at line boundaries and ignores surrounding text.
    // Keep the input/temporary decoder bounded even for ignored private keys.
    let engine = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true),
    );
    let mut result = Vec::new();
    let mut leaf_bytes = Zeroizing::new(Vec::new());
    let mut begin: Option<(&[u8], usize)> = None;
    let mut offset = 0usize;
    for raw_line in data.split_inclusive(|byte| *byte == b'\n') {
        let line_start = offset;
        offset += raw_line.len();
        let line = pem_line(raw_line);
        if let Some(label) = line.strip_prefix(b"-----BEGIN ") {
            begin = label.strip_suffix(b"-----").map(|label| (label, offset));
            continue;
        }
        let Some(end_label) = line.strip_prefix(b"-----END ") else {
            continue;
        };
        let Some((label, body_start)) = begin.take() else {
            continue;
        };
        if end_label.strip_suffix(b"-----") != Some(label) {
            continue;
        }
        let mut body = &data[body_start..line_start];
        // PEM headers precede the encoded contents. Their metadata does not
        // grant trust; only the exact decoded X.509 certificate is used.
        while let Some(end) = body.iter().position(|byte| *byte == b'\n') {
            if !body[..end].contains(&b':') {
                break;
            }
            body = &body[end + 1..];
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(body.len()));
        encoded.extend(
            body.iter()
                .copied()
                .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n')),
        );
        let mut der = Zeroizing::new(Vec::with_capacity(encoded.len().div_ceil(4) * 3));
        if engine.decode_vec(&*encoded, &mut der).is_err() {
            continue;
        }
        if label != b"CERTIFICATE" {
            if source == PemSource::Ca {
                continue;
            }
            bail!("unexpected PEM block in client trust input");
        }
        match source {
            PemSource::Ca | PemSource::DeprecatedCa => {
                budget.accept(&der)?;
                result.push(CertificateDer::from(std::mem::take(&mut *der)));
            }
            PemSource::LeafFile | PemSource::InlineLeaf => {
                leaf_bytes.extend_from_slice(&der);
            }
        }
    }
    match source {
        PemSource::Ca => return Ok(result),
        PemSource::DeprecatedCa => {}
        PemSource::LeafFile => {
            // Go's leaf file loader calls ParseCertificates on concatenated DER.
            let mut pending = leaf_bytes.as_slice();
            while !pending.is_empty() {
                let (rest, _) = x509_parser::parse_x509_certificate(pending)
                    .map_err(|_| anyhow::anyhow!("invalid client certificate DER"))?;
                let size = pending.len() - rest.len();
                ensure!(size != 0, "empty client certificate DER");
                budget.charge(size)?;
                result.push(CertificateDer::from(pending[..size].to_vec()));
                pending = rest;
            }
        }
        PemSource::InlineLeaf => {
            // An inline item represents exactly one certificate, even if it
            // contains several PEM blocks. Do not silently enlarge a pin set.
            budget.accept(&leaf_bytes)?;
            result.push(CertificateDer::from(std::mem::take(&mut *leaf_bytes)));
        }
    }
    ensure!(!result.is_empty(), "no client trust certificates");
    Ok(result)
}
fn load_system(budget: &mut Budget, out: &mut Vec<CertificateDer<'static>>) -> Result<()> {
    for cert in rustls_native_certs::load_native_certs().certs {
        // System stores may contain unusable entries. Skip malformed anchors
        // without weakening explicitly configured file/inline trust material.
        if parse_certificate(&cert).is_err() || webpki::anchor_from_trusted_cert(&cert).is_err() {
            continue;
        }
        budget.accept(&cert)?;
        out.push(cert);
    }
    Ok(())
}
fn load_pool(
    raw: &serde_json::Value,
    depth: usize,
    budget: &mut Budget,
    out: &mut Vec<CertificateDer<'static>>,
) -> Result<()> {
    ensure!(depth < 8, "client trust provider nesting too deep");
    let obj = super::require_object(raw)?;
    match obj.get("provider").and_then(serde_json::Value::as_str) {
        Some("inline") => {
            super::check_unknown(
                obj,
                &["provider", "trusted_ca_certs"],
                "inline client trust pool",
            )?;
            for raw in
                super::parse_string_array(obj.get("trusted_ca_certs"), "client trust certificates")?
                    .unwrap_or_default()
            {
                out.push(decode(&raw, budget)?);
            }
        }
        Some("file") => {
            super::check_unknown(obj, &["provider", "pem_files"], "file client trust pool")?;
            for path in super::parse_string_array(obj.get("pem_files"), "client trust files")?
                .unwrap_or_default()
            {
                out.extend(read_pem(&path, PemSource::Ca, budget)?);
            }
        }
        Some("system") => {
            super::check_unknown(obj, &["provider"], "system client trust pool")?;
            ensure!(
                depth == 0,
                "system pool cannot export certificates to combined pool"
            );
            load_system(budget, out)?;
        }
        Some("combined") => {
            super::check_unknown(obj, &["provider", "sources"], "combined client trust pool")?;
            let sources = super::require_array(
                obj.get("sources")
                    .ok_or_else(|| anyhow::anyhow!("combined client trust sources required"))?,
                "client trust sources",
            )?;
            ensure!(
                !sources.is_empty() && sources.len() <= 256,
                "combined client trust source count invalid"
            );
            for source in sources {
                load_pool(source, depth + 1, budget, out)?;
            }
        }
        _ => bail!("unsupported client trust pool provider"),
    }
    Ok(())
}

struct Verifier {
    mode: ClientAuthMode,
    verify_chain: bool,
    normal: Option<Arc<dyn ClientCertVerifier>>,
    hints: Vec<DistinguishedName>,
    pin_groups: Vec<Vec<CertificateDer<'static>>>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPolicyClientVerifier")
            .finish_non_exhaustive()
    }
}
impl ClientCertVerifier for Verifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        !self.pin_groups.is_empty()
            || matches!(
                self.mode,
                ClientAuthMode::Require | ClientAuthMode::RequireAndVerify
            )
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let invalid = || Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
        if intermediates.len() > 64 || end_entity.len() > MAX_ONE_CERTIFICATE {
            return Err(invalid());
        }
        for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
            parse_certificate(cert).map_err(|_| invalid())?;
        }
        if self.verify_chain {
            self.normal
                .as_ref()
                .ok_or(Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))?
                .verify_client_cert(end_entity, intermediates, now)?;
        }
        if self
            .pin_groups
            .iter()
            .any(|group| !group.iter().any(|pin| pin.as_ref() == end_entity.as_ref()))
        {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
