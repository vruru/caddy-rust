//! Native password-hash utility shared with HTTP Basic Auth.
pub use crate::http_runtime::auth_hash::Algorithm;
#[derive(Clone, Copy)]
pub struct HashOptions {
    pub algorithm: Algorithm,
    pub bcrypt_cost: i32,
    pub argon2id_time: u32,
    pub argon2id_memory: u32,
    pub argon2id_threads: u8,
    pub argon2id_keylen: u32,
}
impl Default for HashOptions {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Bcrypt,
            bcrypt_cost: 14,
            argon2id_time: 1,
            argon2id_memory: 47104,
            argon2id_threads: 1,
            argon2id_keylen: 32,
        }
    }
}
/// Generates a randomized stored hash without logging or retaining plaintext.
/// This performs synchronous CPU work. Async hosts must call it from their
/// bounded blocking lane; the CLI calls it before starting an async runtime.
/// Argon2 uses the same explicit work/memory bounds as HTTP verification.
pub fn hash(options: &HashOptions, plaintext: &[u8]) -> anyhow::Result<zeroize::Zeroizing<String>> {
    crate::crypto::install_default()?;
    crate::http_runtime::auth_hash::generate(options, plaintext)
}
