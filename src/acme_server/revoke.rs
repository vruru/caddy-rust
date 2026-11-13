use super::{
    bolt::Budget,
    controller::{ResponseData, problem},
    jws::{Signed, VerificationKey},
    records::{CertificateData, DbAccount, DbCert, RevokedInfo, SerialIndex},
    resources::Meter,
    store::Database,
};
use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    reason: Option<i64>,
}
fn reason(value: i64) -> &'static str {
    match value {
        0 => "unspecified reason",
        1 => "key compromised",
        2 => "ca compromised",
        3 => "affiliation changed",
        4 => "superseded",
        5 => "cessation of operation",
        6 => "certificate hold",
        8 => "remove from crl",
        9 => "privilege withdrawn",
        10 => "aa compromised",
        _ => "unspecified reason",
    }
}
pub(super) fn process(
    db: &mut Database,
    meter: &mut Meter,
    signed: &Signed,
    key: &VerificationKey,
    account: Option<&DbAccount>,
    response: &mut ResponseData,
) -> Result<()> {
    let request: Request = match serde_json::from_slice(&signed.payload) {
        Ok(request) => request,
        Err(_) => {
            problem(
                response,
                meter,
                "malformed",
                400,
                "invalid revocation payload",
            )?;
            return Ok(());
        }
    };
    let encoded = request.certificate.as_deref().unwrap_or_default();
    let size = encoded
        .len()
        .checked_mul(3)
        .ok_or_else(|| anyhow!("certificate capacity"))?
        / 4
        + 3;
    if size > 128 * 1024 + 3 {
        problem(
            response,
            meter,
            "malformed",
            400,
            "certificate capacity exceeded",
        )?;
        return Ok(());
    }
    meter.charge(
        size.checked_mul(64)
            .and_then(|n| n.checked_add(65536))
            .ok_or_else(|| anyhow!("certificate capacity"))?,
    )?;
    let der = match URL_SAFE_NO_PAD.decode(encoded) {
        Ok(der) => der,
        Err(_) => {
            problem(
                response,
                meter,
                "malformed",
                400,
                "invalid certificate encoding",
            )?;
            return Ok(());
        }
    };
    let (tail, certificate) = match x509_parser::parse_x509_certificate(&der) {
        Ok(cert) => cert,
        Err(_) => {
            problem(response, meter, "malformed", 400, "invalid certificate DER")?;
            return Ok(());
        }
    };
    if !tail.is_empty() {
        problem(response, meter, "malformed", 400, "invalid certificate DER")?;
        return Ok(());
    }
    let serial = openssl::bn::BigNum::from_slice(certificate.raw_serial())?
        .to_dec_str()?
        .to_string();
    let stored = db.transaction(meter, |tx| {
        let Some(index) = tx.get::<SerialIndex>(b"acme_serial_certs_index", serial.as_bytes())?
        else {
            return Ok(None);
        };
        tx.get::<DbCert>(b"acme_certs", index.certificate_id.as_bytes())
    })?;
    let Some(stored) = stored else {
        problem(
            response,
            meter,
            "serverInternal",
            500,
            "certificate is not registered",
        )?;
        return Ok(());
    };
    let leaf = stored
        .leaf
        .0
        .as_deref()
        .ok_or_else(|| anyhow!("certificate has no leaf"))?;
    let blocks = crate::certmagic::pem_blocks(leaf, "revoke")?;
    if blocks.len() != 1 || blocks[0].0 != "CERTIFICATE" || blocks[0].1.as_slice() != der {
        problem(
            response,
            meter,
            "serverInternal",
            500,
            "registered certificate does not match",
        )?;
        return Ok(());
    }
    if signed.header.jwk.is_some() {
        if !key.matches_spki(certificate.public_key().raw, meter)? {
            problem(
                response,
                meter,
                "unauthorized",
                403,
                "no authorization provided",
            )?;
            return Ok(());
        }
    } else {
        let Some(account) = account else {
            problem(
                response,
                meter,
                "unauthorized",
                403,
                "account required for revocation",
            )?;
            return Ok(());
        };
        if account.id != stored.account_id {
            let mut names = Vec::new();
            let mut unsupported = false;
            if let Some(san) = certificate
                .subject_alternative_name()
                .map_err(|_| anyhow!("invalid certificate SAN"))?
            {
                for name in &san.value.general_names {
                    use x509_parser::extensions::GeneralName;
                    match name {
                        GeneralName::DNSName(name) => {
                            names.push(("dns".into(), (*name).to_owned()))
                        }
                        GeneralName::IPAddress(raw) => {
                            let ip = match raw.len() {
                                4 => IpAddr::from(<[u8; 4]>::try_from(*raw)?),
                                16 => IpAddr::from(<[u8; 16]>::try_from(*raw)?),
                                _ => {
                                    unsupported = true;
                                    continue;
                                }
                            };
                            names.push(("ip".into(), ip.to_canonical().to_string()));
                        }
                        _ => unsupported = true,
                    }
                }
            }
            if unsupported
                || names.is_empty()
                || !db.transaction(meter, |tx| tx.authorizes_names(&account.id, &mut names))?
            {
                problem(
                    response,
                    meter,
                    "unauthorized",
                    403,
                    "account has no authorization for certificate",
                )?;
                return Ok(());
            }
        }
    }
    let revoked = db.transaction(meter, |tx| {
        tx.contains(b"revoked_x509_certs", serial.as_bytes())
    })?;
    if revoked {
        problem(
            response,
            meter,
            "alreadyRevoked",
            400,
            "certificate already revoked",
        )?;
        return Ok(());
    }
    if request
        .reason
        .is_some_and(|reason| !(0..=10).contains(&reason) || reason == 7)
    {
        problem(
            response,
            meter,
            "badRevocationReason",
            400,
            "invalid revocation reason",
        )?;
        return Ok(());
    }
    let not_after =
        OffsetDateTime::from_unix_timestamp(certificate.validity().not_after.timestamp())?
            .format(&Rfc3339)?;
    db.transaction(meter, |tx| {
        // The database actor serializes this whole check-and-publish.
        if tx.contains(b"revoked_x509_certs", serial.as_bytes())? {
            return Ok(());
        }
        let data = tx.get::<CertificateData>(b"x509_certs_data", serial.as_bytes())?;
        let provisioner = data
            .and_then(|data| data.provisioner)
            .map_or_else(String::new, |p| p.id);
        let record = RevokedInfo {
            serial: serial.clone(),
            provisioner_id: provisioner,
            reason_code: request.reason.unwrap_or(0),
            reason: request
                .reason
                .map_or_else(String::new, |code| reason(code).into()),
            revoked_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|_| super::store::Error::Record("clock unavailable"))?,
            expires_at: not_after,
            token_id: String::new(),
            mtls: false,
            acme: true,
            unknown: BTreeMap::new(),
        };
        tx.put(b"revoked_x509_certs", serial.as_bytes(), &record)
    })?;
    response.body.clear();
    response.status = 200;
    Ok(())
}
