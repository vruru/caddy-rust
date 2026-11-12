use anyhow::Result;
use der::Decode;
use openssl::dsa::Dsa;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, PKeyRef, Private};
use openssl::rsa::Rsa;

pub(super) fn parse_key(text: &str) -> anyhow::Result<PKey<Private>> {
    let pem = super::utility::first_pem(text.as_bytes())?;
    let der = pem.contents();
    let tag = pem.tag();

    let key = match tag {
        "PRIVATE KEY" => PKey::private_key_from_pkcs8(der)
            .map_err(|e| anyhow::anyhow!("failed to parse PKCS8 private key: {}", e)),
        "RSA PRIVATE KEY" => {
            let rsa = Rsa::private_key_from_der(der)
                .map_err(|e| anyhow::anyhow!("failed to parse RSA private key: {}", e))?;
            PKey::from_rsa(rsa).map_err(|e| anyhow::anyhow!("failed to convert RSA to PKey: {}", e))
        }
        "EC PRIVATE KEY" => {
            let ec = EcKey::private_key_from_der(der)
                .map_err(|e| anyhow::anyhow!("failed to parse EC private key: {}", e))?;
            PKey::from_ec_key(ec)
                .map_err(|e| anyhow::anyhow!("failed to convert EC to PKey: {}", e))
        }
        "DSA PRIVATE KEY" => {
            // Do not let OpenSSL's automatic decoder accept a PKCS8 object
            // merely because its PEM label was changed to the traditional one.
            der::AnyRef::from_der(der)?.sequence(|reader| {
                for _ in 0..6 {
                    let _ = der::asn1::IntRef::decode(reader)?;
                }
                Ok(())
            })?;
            let key = PKey::private_key_from_der(der)
                .map_err(|e| anyhow::anyhow!("failed to parse DSA private key: {}", e))?;
            if key.id() != Id::DSA {
                return Err(anyhow::anyhow!("parsed key is not DSA"));
            }
            Ok(key)
        }
        _ => Err(anyhow::anyhow!("unsupported PEM tag: {}", tag)),
    }?;
    if tag == "PRIVATE KEY" {
        anyhow::ensure!(
            matches!(key.id(), Id::RSA | Id::EC | Id::ED25519 | Id::X25519),
            "unsupported PKCS8 private key type"
        );
    }
    let key = match key.id() {
        Id::EC => {
            let ec = key.ec_key()?;
            let group = ec.group();
            anyhow::ensure!(
                matches!(
                    group.curve_name(),
                    Some(Nid::SECP224R1 | Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1)
                ) && group.asn1_flag() == openssl::ec::Asn1Flag::NAMED_CURVE,
                "unsupported private key EC curve"
            );
            // Go ignores an encoded public point and derives it from d. A new
            // EC key also discards compressed/omit-public serialization flags.
            let mut ctx = openssl::bn::BigNumContext::new()?;
            let mut public = openssl::ec::EcPoint::new(group)?;
            public.mul_generator2(group, ec.private_key(), &mut ctx)?;
            let rebuilt = EcKey::from_private_components(group, ec.private_key(), &public)?;
            rebuilt.check_key()?;
            PKey::from_ec_key(rebuilt)?
        }
        Id::RSA => {
            anyhow::ensure!(key.rsa()?.check_key()?, "invalid RSA private key");
            key
        }
        _ => key,
    };
    Ok(key)
}

pub(super) fn encode_key(key: &PKeyRef<Private>) -> Result<String> {
    let pem_bytes: Vec<u8> = match key.id() {
        Id::RSA => {
            let rsa = key
                .rsa()
                .map_err(|e| anyhow::anyhow!("failed to get RSA: {}", e))?;
            rsa.private_key_to_pem()
                .map_err(|e| anyhow::anyhow!("failed to encode RSA PEM: {}", e))?
        }
        Id::EC => {
            let ec = key
                .ec_key()
                .map_err(|e| anyhow::anyhow!("failed to get EC key: {}", e))?;
            ec.private_key_to_pem()
                .map_err(|e| anyhow::anyhow!("failed to encode EC PEM: {}", e))?
        }
        Id::DSA => {
            let dsa = key
                .dsa()
                .map_err(|e| anyhow::anyhow!("failed to get DSA: {}", e))?;
            dsa.private_key_to_pem()
                .map_err(|e| anyhow::anyhow!("failed to encode DSA PEM: {}", e))?
        }
        _ => key
            .private_key_to_pem_pkcs8()
            .map_err(|e| anyhow::anyhow!("failed to encode PKCS8 PEM: {}", e))?,
    };

    String::from_utf8(pem_bytes).map_err(|e| anyhow::anyhow!("PEM is not valid UTF-8: {}", e))
}

pub(super) fn generated(kind: &str) -> Result<String> {
    Ok(match generated_inner(kind) {
        Ok(key) => key,
        Err(error) => format!("failed to generate private key: {error}"),
    })
}

fn generated_inner(kind: &str) -> Result<String> {
    let key = match kind {
        "" | "rsa" => {
            let rsa = Rsa::generate(4096)
                .map_err(|e| anyhow::anyhow!("failed to generate RSA: {}", e))?;
            PKey::from_rsa(rsa)
                .map_err(|e| anyhow::anyhow!("failed to convert RSA to PKey: {}", e))?
        }
        "dsa" => {
            let params = match Dsa::generate_params(2048) {
                Ok(params) => params,
                Err(error) => return Ok(format!("failed to generate dsa params: {error}")),
            };
            let p_bits = params.p().num_bits();
            let q_bits = params.q().num_bits();
            if p_bits != 2048 || q_bits != 256 {
                return Err(anyhow::anyhow!(
                    "DSA params bits mismatch: p={}, q={}",
                    p_bits,
                    q_bits
                ));
            }
            let dsa = params
                .generate_key()
                .map_err(|e| anyhow::anyhow!("failed to generate DSA key: {}", e))?;
            PKey::from_dsa(dsa)
                .map_err(|e| anyhow::anyhow!("failed to convert DSA to PKey: {}", e))?
        }
        "ecdsa" => {
            let group = openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|e| anyhow::anyhow!("failed to create EC group: {}", e))?;
            let ec = EcKey::generate(&group)
                .map_err(|e| anyhow::anyhow!("failed to generate EC key: {}", e))?;
            PKey::from_ec_key(ec)
                .map_err(|e| anyhow::anyhow!("failed to convert EC to PKey: {}", e))?
        }
        "ed25519" => PKey::generate_ed25519()
            .map_err(|e| anyhow::anyhow!("failed to generate Ed25519: {}", e))?,
        _ => return Ok(format!("Unknown type {}", kind)),
    };

    encode_key(&key).map_err(|e| anyhow::anyhow!("failed to generate private key: {}", e))
}

pub(super) fn default_key() -> Result<PKey<Private>> {
    let rsa = Rsa::generate(2048).map_err(|e| anyhow::anyhow!("failed to generate RSA: {}", e))?;
    PKey::from_rsa(rsa).map_err(|e| anyhow::anyhow!("failed to convert RSA to PKey: {}", e))
}
