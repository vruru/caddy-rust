//! Read-only inspection of CertMagic v0.25.6 FileStorage material.
//! This module does not register accounts, renew certificates, or acquire locks.

use anyhow::{Result, bail, ensure};
use rustix::fs::{self, Dir, Mode, OFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::File,
    io::Read,
    os::fd::OwnedFd,
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_ENTRIES: usize = 50_000;
const MAX_REPORTS: usize = 10_000;
const MAX_CERT: u64 = 4 * 1024 * 1024;
const MAX_KEY: u64 = 128 * 1024;
const MAX_JSON: u64 = 1024 * 1024;

fn safe_id(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn issue(id: &str, reason: &str) -> anyhow::Error {
    anyhow::anyhow!("storage item {id}: {reason}")
}

struct Reader {
    owner: u32,
    entries: usize,
}

impl Reader {
    fn list(&mut self, fd: &OwnedFd, id: &str) -> Result<Vec<CString>> {
        let mut names = Vec::new();
        let dir = Dir::read_from(fd).map_err(|_| issue(id, "directory enumeration failed"))?;
        for entry in dir {
            let entry = entry.map_err(|_| issue(id, "directory enumeration failed"))?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            self.entries += 1;
            ensure!(
                self.entries <= MAX_ENTRIES,
                "storage enumeration limit exceeded"
            );
            names.push(name.to_owned());
        }
        names.sort_by(|a, b| a.to_bytes().cmp(b.to_bytes()));
        Ok(names)
    }

    fn directory(&self, parent: &OwnedFd, name: &CStr, id: &str) -> Result<OwnedFd> {
        let fd = fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| issue(id, "directory missing, unsupported, or symlink"))?;
        let st = fs::fstat(&fd).map_err(|_| issue(id, "directory metadata unavailable"))?;
        ensure!(
            (st.st_uid == self.owner || st.st_uid == 0) && st.st_mode & 0o022 == 0,
            "storage item {id}: unsafe directory ownership or permissions"
        );
        Ok(fd)
    }

    fn optional_directory(
        &self,
        parent: &OwnedFd,
        name: &str,
        id: &str,
    ) -> Result<Option<OwnedFd>> {
        let name = CString::new(name).map_err(|_| issue(id, "invalid fixed directory"))?;
        match fs::statat(parent, name.as_c_str(), fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(_) => Err(issue(id, "directory metadata unavailable")),
            Ok(_) => self.directory(parent, &name, id).map(Some),
        }
    }

    fn read(
        &self,
        parent: &OwnedFd,
        name: &CStr,
        id: &str,
        limit: u64,
        private: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let fd = fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| issue(id, "required file unavailable or symlink"))?;
        let st = fs::fstat(&fd).map_err(|_| issue(id, "file metadata unavailable"))?;
        ensure!(
            fs::FileType::from_raw_mode(st.st_mode) == fs::FileType::RegularFile,
            "storage item {id}: material must be a regular file"
        );
        ensure!(
            st.st_uid == self.owner
                && st.st_nlink == 1
                && st.st_mode & 0o022 == 0
                && (!private || st.st_mode & 0o077 == 0),
            "storage item {id}: unsafe material ownership or permissions"
        );
        ensure!(
            st.st_size > 0 && st.st_size as u64 <= limit,
            "storage item {id}: material size outside bounds"
        );
        let file = File::from(fd);
        let mut bytes = Zeroizing::new(Vec::with_capacity(st.st_size as usize));
        (&file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| issue(id, "material read failed"))?;
        let after = fs::fstat(&file).map_err(|_| issue(id, "file metadata unavailable"))?;
        ensure!(
            bytes.len() as u64 == st.st_size as u64
                && bytes.len() as u64 <= limit
                && after.st_size == st.st_size
                && after.st_mtime == st.st_mtime
                && after.st_mtime_nsec == st.st_mtime_nsec,
            "storage item {id}: material changed during read"
        );
        Ok(bytes)
    }
}

/// No path, account identifier, domain, key, or email is included in this report.
pub fn inspect(root: &Path) -> Result<Value> {
    ensure!(root.is_absolute(), "storage root must be absolute");
    let root_id = safe_id(root.as_os_str().as_encoded_bytes());
    let mut fd = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| issue(&root_id, "storage root unavailable"))?;
    // Each component is opened relative to an already open descriptor. Neither
    // directory symlinks nor a check/open race can redirect the traversal.
    for component in root.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = CString::new(name.as_encoded_bytes())
                    .map_err(|_| issue(&root_id, "invalid storage root"))?;
                fd = fs::openat(
                    &fd,
                    name.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| issue(&root_id, "storage root unavailable or symlink"))?;
            }
            _ => bail!("invalid storage root components"),
        }
    }
    let st = fs::fstat(&fd).map_err(|_| issue(&root_id, "storage metadata unavailable"))?;
    ensure!(
        st.st_mode & 0o022 == 0,
        "storage item {root_id}: unsafe storage permissions"
    );
    let mut reader = Reader {
        owner: st.st_uid,
        entries: 0,
    };
    let mut certificates = Vec::new();
    let mut accounts = Vec::new();
    if let Some(base) = reader.optional_directory(&fd, "certificates", &root_id)? {
        for issuer in reader.list(&base, &root_id)? {
            let issuer_rel = joined(b"certificates", issuer.to_bytes());
            let issuer_id = safe_id(&issuer_rel);
            let issuer_fd = reader.directory(&base, &issuer, &issuer_id)?;
            for name in reader.list(&issuer_fd, &issuer_id)? {
                let rel = joined(&issuer_rel, name.to_bytes());
                let id = safe_id(&rel);
                let group = reader.directory(&issuer_fd, &name, &id)?;
                let expected: BTreeSet<Vec<u8>> = [b".crt".as_slice(), b".key", b".json"]
                    .into_iter()
                    .map(|ext| [name.to_bytes(), ext].concat())
                    .collect();
                let actual: BTreeSet<Vec<u8>> = reader
                    .list(&group, &id)?
                    .iter()
                    .map(|n| n.to_bytes().to_vec())
                    .collect();
                ensure!(
                    actual == expected,
                    "storage item {id}: incomplete or unsupported certificate layout"
                );
                let cert = reader.read(&group, &filename(&name, b".crt")?, &id, MAX_CERT, false)?;
                let key = reader.read(&group, &filename(&name, b".key")?, &id, MAX_KEY, true)?;
                let meta =
                    reader.read(&group, &filename(&name, b".json")?, &id, MAX_JSON, false)?;
                certificates.push(inspect_certificate(&id, &cert, &key, &meta)?);
                ensure!(
                    certificates.len() + accounts.len() <= MAX_REPORTS,
                    "storage material count limit exceeded"
                );
            }
        }
    }
    if let Some(base) = reader.optional_directory(&fd, "acme", &root_id)? {
        for issuer in reader.list(&base, &root_id)? {
            let issuer_rel = joined(b"acme", issuer.to_bytes());
            let issuer_id = safe_id(&issuer_rel);
            let issuer_fd = reader.directory(&base, &issuer, &issuer_id)?;
            let Some(users) = reader.optional_directory(&issuer_fd, "users", &issuer_id)? else {
                continue;
            };
            for name in reader.list(&users, &issuer_id)? {
                let rel = joined(&joined(&issuer_rel, b"users"), name.to_bytes());
                let id = safe_id(&rel);
                let group = reader.directory(&users, &name, &id)?;
                let names = reader.list(&group, &id)?;
                ensure!(
                    names.len() == 2,
                    "storage item {id}: incomplete or unsupported account layout"
                );
                let json_name = names
                    .iter()
                    .find(|n| n.to_bytes().ends_with(b".json"))
                    .ok_or_else(|| issue(&id, "account metadata missing"))?;
                let key_name = names
                    .iter()
                    .find(|n| n.to_bytes().ends_with(b".key"))
                    .ok_or_else(|| issue(&id, "account private key missing"))?;
                let stem = &json_name.to_bytes()[..json_name.to_bytes().len() - 5];
                ensure!(
                    key_name.to_bytes() == [stem, b".key"].concat()
                        || (json_name.to_bytes() == b"registration.json"
                            && key_name.to_bytes() == b"private.key"),
                    "storage item {id}: unsupported account pair layout"
                );
                let meta = reader.read(&group, json_name, &id, MAX_JSON, false)?;
                let key = reader.read(&group, key_name, &id, MAX_KEY, true)?;
                accounts.push(inspect_account(&id, &key, &meta)?);
                ensure!(
                    certificates.len() + accounts.len() <= MAX_REPORTS,
                    "storage material count limit exceeded"
                );
            }
        }
    }
    Ok(
        json!({"format":"certmagic-v0.25.6-inspection", "readOnly":true,
        "certificateCount":certificates.len(), "accountCount":accounts.len(),
        "certificates":certificates, "accounts":accounts,
        "scope":"material-integrity-only; no issuance, renewal, trust-chain, revocation or account-network validation"}),
    )
}

fn joined(parent: &[u8], name: &[u8]) -> Vec<u8> {
    [parent, b"/", name].concat()
}
fn filename(name: &CStr, ext: &[u8]) -> Result<CString> {
    CString::new([name.to_bytes(), ext].concat())
        .map_err(|_| anyhow::anyhow!("invalid storage filename"))
}

// pem::parse_many deliberately ignores surrounding text; explicitly frame every
// block so that garbage, unknown labels and additional private keys never vanish.
pub(crate) fn pem_blocks(bytes: &[u8], id: &str) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    let mut text = std::str::from_utf8(bytes)
        .map_err(|_| issue(id, "PEM is not UTF-8"))?
        .trim();
    let mut blocks = Vec::new();
    while !text.is_empty() {
        ensure!(
            text.starts_with("-----BEGIN "),
            "storage item {id}: invalid PEM framing"
        );
        let end_tag = text[11..]
            .find("-----")
            .map(|n| n + 11)
            .ok_or_else(|| issue(id, "invalid PEM framing"))?;
        let tag = &text[11..end_tag];
        ensure!(
            !tag.is_empty()
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' '),
            "storage item {id}: unsupported PEM label"
        );
        let footer = format!("-----END {tag}-----");
        let end = text
            .find(&footer)
            .ok_or_else(|| issue(id, "PEM footer missing"))?
            + footer.len();
        let block = pem::parse(&text[..end]).map_err(|_| issue(id, "PEM decoding failed"))?;
        let supported_headers = block.tag() == tag && block.headers().iter().next().is_none();
        let contents = Zeroizing::new(block.into_contents());
        ensure!(
            supported_headers,
            "storage item {id}: unsupported PEM headers"
        );
        blocks.push((tag.to_owned(), contents));
        ensure!(
            blocks.len() <= 32,
            "storage item {id}: PEM block count limit exceeded"
        );
        text = text[end..].trim();
    }
    ensure!(!blocks.is_empty(), "storage item {id}: empty PEM material");
    Ok(blocks)
}

pub(crate) fn signing_key(
    bytes: &[u8],
    id: &str,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>> {
    use rustls::pki_types::{
        PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };
    let blocks = pem_blocks(bytes, id)?;
    ensure!(
        blocks.len() == 1,
        "storage item {id}: expected one private key"
    );
    let (tag, contents) = &blocks[0];
    let key = match tag.as_str() {
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(contents.as_slice())),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(contents.as_slice())),
        "PRIVATE KEY" | "ED25519 PRIVATE KEY" => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(contents.as_slice()))
        }
        _ => return Err(issue(id, "unsupported private key label")),
    };
    let signer = crate::crypto::provider().key_provider.load_private_key(key.clone_key())
        .map_err(|_| issue(id, "unsupported or invalid private key"))?;
    let alg = algorithm(signer.algorithm(), id)?;
    ensure!(
        tag != "ED25519 PRIVATE KEY" || alg == "Ed25519",
        "storage item {id}: private key label mismatch"
    );
    Ok(signer)
}

fn algorithm(alg: rustls::SignatureAlgorithm, id: &str) -> Result<&'static str> {
    match alg {
        rustls::SignatureAlgorithm::RSA => Ok("RSA"),
        rustls::SignatureAlgorithm::ECDSA => Ok("ECDSA"),
        rustls::SignatureAlgorithm::ED25519 => Ok("Ed25519"),
        _ => Err(issue(id, "unsupported key algorithm")),
    }
}

/// Check only the public/private key binding, using the complete original
/// SubjectPublicKeyInfo bytes after bounded, strict X.509 decoding. WebPKI's
/// unrelated 64-KiB signed-certificate parser limit is not a key mismatch.
pub(crate) fn check_keys_match(certified:&rustls::sign::CertifiedKey,id:&str)->Result<()> {
    let public=certified.key.public_key()
        .ok_or_else(||issue(id,"signing public key unavailable"))?;
    let der=certified.cert.first().ok_or_else(||issue(id,"empty certificate chain"))?;
    let (remaining,leaf)=crate::cert_transient::parse_certificate(der.as_ref())?;
    ensure!(remaining.is_empty(),"storage item {id}: trailing X.509 material");
    crate::cert_transient::check_unique_extensions(&leaf)
        .map_err(|error|error.context(format!("storage item {id}: certificate extensions")))?;
    ensure!(public.as_ref()==leaf.public_key().raw,
        "storage item {id}: certificate/private key mismatch");
    Ok(())
}

fn inspect_certificate(id: &str, cert: &[u8], key: &[u8], meta: &[u8]) -> Result<Value> {
    let blocks = pem_blocks(cert, id)?;
    let mut chain = Vec::new();
    for (tag, der) in &blocks {
        ensure!(
            tag == "CERTIFICATE",
            "storage item {id}: unsupported certificate PEM label"
        );
        crate::cert_uri_san::check_der(der)?;
        let (rest, _) = x509_parser::parse_x509_certificate(der)
            .map_err(|_| issue(id, "invalid X.509 certificate"))?;
        ensure!(
            rest.is_empty(),
            "storage item {id}: trailing X.509 material"
        );
        chain.push(rustls::pki_types::CertificateDer::from(der.to_vec()));
    }
    let signer = signing_key(key, id)?;
    let algorithm = algorithm(signer.algorithm(), id)?;
    let certified = rustls::sign::CertifiedKey::new(chain, signer);
    check_keys_match(&certified,id)?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&blocks[0].1)
        .map_err(|_| issue(id, "invalid leaf certificate"))?;
    let before = leaf.validity().not_before.timestamp();
    let after = leaf.validity().not_after.timestamp();
    ensure!(
        before <= after,
        "storage item {id}: invalid certificate validity interval"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| issue(id, "system time unavailable"))?
        .as_secs() as i64;
    let state = if now < before {
        "notYetValid"
    } else if now > after {
        "expired"
    } else {
        "validNow"
    };
    let meta: Value =
        serde_json::from_slice(meta).map_err(|_| issue(id, "invalid certificate metadata JSON"))?;
    let object = meta
        .as_object()
        .ok_or_else(|| issue(id, "certificate metadata must be an object"))?;
    let san_count = string_array_count(object.get("sans"), id)?;
    // IssuerData is json.RawMessage, including for third-party issuers. Preserve
    // that compatibility: report only JSON shape; do not assume an ACME URL.
    let issuer_shape = match object.get("issuer_data") {
        None => "absent",
        Some(Value::Null) => "null",
        Some(Value::Object(_)) => "object",
        Some(Value::Array(_)) => "array",
        Some(Value::String(_)) => "string",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
    };
    let x509_san_count = leaf
        .subject_alternative_name()
        .map_err(|_| issue(id, "invalid subject alternative names"))?
        .map(|ext| ext.value.general_names.len())
        .unwrap_or(0);
    Ok(
        json!({"safeId":id,"algorithm":algorithm,"chainLength":blocks.len(),"keyMatches":true,
        "notBeforeUnix":before,"notAfterUnix":after,"validityState":state,
        "sanCount":san_count,"certificateSanCount":x509_san_count,
        "issuerMetadataPresent":object.contains_key("issuer_data"),"issuerMetadataShape":issuer_shape}),
    )
}

fn string_array_count(value: Option<&Value>, id: &str) -> Result<usize> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Array(values)) => {
            ensure!(
                values.len() <= 1024
                    && values
                        .iter()
                        .all(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 4096)),
                "storage item {id}: invalid string-list metadata"
            );
            Ok(values.len())
        }
        _ => Err(issue(id, "invalid string-list metadata")),
    }
}

fn inspect_account(id: &str, key: &[u8], meta: &[u8]) -> Result<Value> {
    let signer = signing_key(key, id)?;
    let algorithm = algorithm(signer.algorithm(), id)?;
    let meta: Value =
        serde_json::from_slice(meta).map_err(|_| issue(id, "invalid account metadata JSON"))?;
    let object = meta
        .as_object()
        .ok_or_else(|| issue(id, "account metadata must be an object"))?;
    let status = match object.get("status") {
        None | Some(Value::Null) => "absent",
        Some(Value::String(s)) if s.is_empty() => "absent",
        Some(Value::String(s)) if matches!(s.as_str(), "valid" | "deactivated" | "revoked") => {
            s.as_str()
        }
        _ => return Err(issue(id, "unsupported account status")),
    };
    let contact_count = string_array_count(object.get("contact"), id)?;
    let has_location = match object.get("location") {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        _ => return Err(issue(id, "invalid account location shape")),
    };
    if let Some(value) = object.get("orders") {
        ensure!(
            value.is_string() || value.is_null(),
            "storage item {id}: invalid account orders shape"
        );
    }
    if let Some(value) = object.get("termsOfServiceAgreed") {
        ensure!(
            value.is_boolean() || value.is_null(),
            "storage item {id}: invalid account agreement shape"
        );
    }
    Ok(
        json!({"safeId":id,"algorithm":algorithm,"privateKeyValid":true,"status":status,
        "hasLocation":has_location,"contactCount":contact_count}),
    )
}
