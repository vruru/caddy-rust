//! Optional RFC 7517 certificate metadata is validated before an account can
//! persist it. No x5u dereference or trust decision is performed here.
use super::{Budget, Error, Jwk, PKey, Public, Result, crypto, decode};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::x509::X509;

// Reuse the existing byte URL primitives, without introducing a dependency on
// a template Control or accepting a UTF8-only approximation of a Go URL.
#[path = "../http_runtime/http_redirect/url.rs"]
mod url;

fn reference(raw: &[u8]) -> std::result::Result<(), ()> {
    let (raw, fragment) = raw
        .iter()
        .position(|b| *b == b'#')
        .map_or((raw, None), |i| (&raw[..i], Some(&raw[i + 1..])));
    if let Some(fragment) = fragment {
        url::template_decode_bytes(fragment)?;
    }
    if raw.iter().any(|b| *b < 32 || *b == 127) {
        return Err(());
    }
    let mut scheme = &b""[..];
    let mut rest = raw;
    for (i, byte) in raw.iter().copied().enumerate() {
        if byte == b':' {
            if i == 0 {
                return Err(());
            }
            scheme = &raw[..i];
            rest = &raw[i + 1..];
            break;
        }
        if !(byte.is_ascii_alphabetic()
            || i > 0 && (byte.is_ascii_digit() || b"+-.".contains(&byte)))
        {
            break;
        }
    }
    rest = rest.split(|b| *b == b'?').next().ok_or(())?;
    if !rest.starts_with(b"/") {
        if !scheme.is_empty() {
            return Ok(());
        }
        if rest
            .split(|b| *b == b'/')
            .next()
            .is_some_and(|p| p.contains(&b':'))
        {
            return Err(());
        }
    }
    if rest.starts_with(b"//") && (!scheme.is_empty() || !rest.starts_with(b"///")) {
        let after = &rest[2..];
        let end = after.iter().position(|b| *b == b'/').unwrap_or(after.len());
        let authority = &after[..end];
        let (user, host) = authority
            .iter()
            .rposition(|b| *b == b'@')
            .map_or((None, authority), |i| {
                (Some(&authority[..i]), &authority[i + 1..])
            });
        let host_scheme = if scheme.eq_ignore_ascii_case(b"http") {
            b"http".as_slice()
        } else if scheme.eq_ignore_ascii_case(b"https") {
            b"https".as_slice()
        } else {
            scheme
        };
        url::template_decode_host_bytes(host_scheme, host)?;
        if let Some(user) = user {
            if !user
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(b))
            {
                return Err(());
            }
            url::template_decode_bytes(user)?;
        }
        rest = &after[end..];
    }
    url::template_decode_bytes(rest)?;
    Ok(())
}

fn fingerprint(raw: Option<&str>, length: usize, budget: &mut impl Budget) -> Result<Vec<u8>> {
    let mut decoded = decode(raw.unwrap_or_default(), 128, budget)?;
    // The pinned go-jose additionally accepts base64url of an ASCII hex digest.
    if decoded.len() == length * 2 {
        let digit = |b: u8| -> Result<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => Err(Error::Malformed("invalid certificate thumbprint hex")),
            }
        };
        for i in 0..length {
            decoded[i] = digit(decoded[i * 2])? * 16 + digit(decoded[i * 2 + 1])?;
        }
        decoded.truncate(length);
    }
    if !decoded.is_empty() && decoded.len() != length {
        return Err(Error::Malformed("certificate thumbprint size"));
    }
    Ok(decoded)
}

pub(super) fn validate(jwk: &Jwk, key: &PKey<Public>, budget: &mut impl Budget) -> Result<()> {
    if let Some(location) = &jwk.x5u {
        budget.work(location.len().div_ceil(16).max(1))?;
        reference(location.as_bytes()).map_err(|_| Error::Malformed("invalid x5u URL"))?;
    }
    let sha1 = fingerprint(jwk.x5t.as_deref(), 20, budget)?;
    let sha256 = fingerprint(jwk.x5t_s256.as_deref(), 32, budget)?;
    if let Some(chain) = &jwk.x5c {
        for (index, encoded) in chain.iter().enumerate() {
            budget.work(encoded.len().div_ceil(16).max(1))?;
            budget.charge(
                encoded
                    .len()
                    .checked_mul(16)
                    .ok_or(Error::Malformed("certificate size"))?,
            )?;
            let der = STANDARD
                .decode(encoded)
                .map_err(|_| Error::Malformed("invalid x5c encoding"))?;
            let cert = crypto(X509::from_der(&der))?;
            // OpenSSL permits trailing bytes; a JWK carries exactly one DER
            // certificate per entry, not a certificate followed by opaque data.
            if crypto(cert.to_der())? != der {
                return Err(Error::Malformed("invalid x5c DER"));
            }
            if index == 0 {
                if !crypto(cert.public_key())?.public_eq(key) {
                    return Err(Error::Malformed("x5c public key mismatch"));
                }
                if !sha1.is_empty() && sha1 != openssl::sha::sha1(&der) {
                    return Err(Error::Malformed("x5c SHA1 mismatch"));
                }
                if !sha256.is_empty() && sha256 != openssl::sha::sha256(&der) {
                    return Err(Error::Malformed("x5c SHA256 mismatch"));
                }
            }
        }
    }
    Ok(())
}
