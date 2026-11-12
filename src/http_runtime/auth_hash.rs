//! Password comparison runs only in the bounded authentication CPU lane.
//! Argon2 scratch admission is independent of ordinary HTTP/disk/crypto jobs.
use super::auth_cache::AuthError;
use base64::Engine;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use zeroize::Zeroizing;
const MEMORY_POOL: usize = 512 << 20;
static MEMORY: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(MEMORY_POOL)));
#[derive(Clone, Copy)]
pub enum Algorithm {
    Bcrypt,
    Argon2id,
}
impl Algorithm {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Bcrypt => "bcrypt",
            Self::Argon2id => "argon2id",
        }
    }
    pub(crate) fn fake(self) -> &'static str {
        match self {
            Self::Bcrypt => super::auth_cache::FAKE_BCRYPT_HASH,
            Self::Argon2id => {
                "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg"
            }
        }
    }
    pub(crate) fn validate(self, hash: &str) -> Result<(), AuthError> {
        match self {
            Self::Bcrypt => bcrypt::HashParts::from_str(hash)
                .map(|_| ())
                .map_err(|_| AuthError::HashInvalid),
            Self::Argon2id => decode(hash).map(|_| ()),
        }
    }
    pub(crate) fn compare(self, hash: &str, password: &[u8]) -> Result<bool, AuthError> {
        match self {
            Self::Bcrypt => bcrypt::verify(password, hash).map_err(|_| AuthError::HashInvalid),
            Self::Argon2id => {
                let hash = decode(hash)?;
                let actual = derive(hash.params, &hash.salt, password, hash.key.len())?;
                Ok(openssl::memcmp::eq(actual.as_slice(), &hash.key))
            }
        }
    }
}
fn derive(
    params: argon2::Params,
    salt: &[u8],
    password: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let bytes = params
        .block_count()
        .checked_mul(std::mem::size_of::<argon2::Block>())
        .and_then(|n| n.checked_add(key_len + salt.len() + 16 * 1024))
        .ok_or(AuthError::Overloaded)?;
    let _charge = MEMORY
        .clone()
        .try_acquire_many_owned(u32::try_from(bytes).map_err(|_| AuthError::Overloaded)?)
        .map_err(|_| AuthError::Overloaded)?;
    let mut blocks = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(params.block_count())
        .map_err(|_| AuthError::Overloaded)?;
    blocks.resize(params.block_count(), argon2::Block::default());
    let mut key = Zeroizing::new(vec![0; key_len]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, &mut key, &mut *blocks)
        .map_err(|_| AuthError::HashInvalid)?;
    Ok(key)
}
pub(crate) fn generate(
    options: &crate::password::HashOptions,
    password: &[u8],
) -> anyhow::Result<Zeroizing<String>> {
    match options.algorithm {
        Algorithm::Bcrypt => {
            let cost = if (4..=31).contains(&options.bcrypt_cost) {
                options.bcrypt_cost as u32
            } else {
                14
            };
            // Go's limit counts password bytes, not the backend's appended NUL.
            // Validate before hashing so 72 bytes work without truncating 73.
            anyhow::ensure!(
                password.len() <= 72,
                "bcrypt plaintext must be at most 72 bytes"
            );
            let hash = bcrypt::hash(password, cost)
                .map_err(|_| anyhow::anyhow!("bcrypt hashing failed"))?;
            Ok(Zeroizing::new(hash))
        }
        Algorithm::Argon2id => {
            let params = parameters(
                options.argon2id_memory,
                options.argon2id_time,
                u32::from(options.argon2id_threads),
                options.argon2id_keylen as usize,
            )
            .map_err(|_| anyhow::anyhow!("invalid or resource-exceeding Argon2id parameters"))?;
            let mut salt = [0u8; 16];
            crate::crypto::provider()
                .secure_random
                .fill(&mut salt)
                .map_err(|_| anyhow::anyhow!("password salt entropy unavailable"))?;
            let key = derive(params, &salt, password, options.argon2id_keylen as usize)
                .map_err(|_| anyhow::anyhow!("password hashing resource unavailable"))?;
            let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
            Ok(Zeroizing::new(format!(
                "$argon2id$v=19$m={},t={},p={}${}${}",
                options.argon2id_memory,
                options.argon2id_time,
                options.argon2id_threads,
                engine.encode(salt),
                engine.encode(&*key)
            )))
        }
    }
}
fn parameters(m: u32, t: u32, p: u32, key_len: usize) -> Result<argon2::Params, AuthError> {
    if t == 0
        || p == 0
        || p > 255
        || m > 256 * 1024
        || u64::from(m.max(8 * p)) * u64::from(t) > 4 * 1024 * 1024
        || key_len == 0
        || key_len > 1024
    {
        return Err(AuthError::HashInvalid);
    }
    argon2::Params::new(m, t, p, Some(key_len)).map_err(|_| AuthError::HashInvalid)
}
struct Hash {
    params: argon2::Params,
    salt: Vec<u8>,
    key: Vec<u8>,
}
fn decode(hash: &str) -> Result<Hash, AuthError> {
    let bad = || AuthError::HashInvalid;
    if hash.len() > 16 << 10 {
        return Err(bad());
    }
    let parts = hash.split('$').collect::<Vec<_>>();
    if parts.len() != 6
        || parts[1] != "argon2id"
        || parts[2]
            .strip_prefix("v=")
            .unwrap_or(parts[2])
            .parse::<u32>()
            .map_err(|_| bad())?
            != 19
    {
        return Err(bad());
    }
    let values = parts[3].split(',').collect::<Vec<_>>();
    if values.len() != 3 {
        return Err(bad());
    }
    let parse = |s: &str, prefix: &str| -> Result<u32, AuthError> {
        let s = s.strip_prefix(prefix).unwrap_or(s);
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        s.parse().map_err(|_| bad())
    };
    let (m, t, p) = (
        parse(values[0], "m=")?,
        parse(values[1], "t=")?,
        parse(values[2], "p=")?,
    );
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let decode = |text: &str| {
        engine
            .decode(
                text.bytes()
                    .filter(|b| !matches!(b, b'\r' | b'\n'))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| bad())
    };
    let salt = decode(parts[4])?;
    let key = decode(parts[5])?;
    let params = parameters(m, t, p, key.len())?;
    Ok(Hash { params, salt, key })
}
