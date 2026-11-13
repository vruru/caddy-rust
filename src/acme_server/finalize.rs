use super::{
    bolt::Budget,
    controller::{ResponseData, json, problem},
    orders::{Action, fresh, order_state},
    records::{DbAccount, DbCert, DbOrder, GoBytes, SerialIndex},
    resources::Meter,
    store::{Database, Error},
    views,
};
use anyhow::{Result, anyhow, ensure};
use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use serde::Deserialize;
use std::collections::BTreeMap;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    csr: Option<String>,
}
pub(super) fn prepare(
    db: &mut Database,
    meter: &mut Meter,
    config: &super::config::Config,
    id: &str,
    payload: &[u8],
    account: &DbAccount,
    base: &str,
    response: &mut ResponseData,
) -> Result<()> {
    let request: Request = match serde_json::from_slice(payload) {
        Ok(request) => request,
        Err(_) => {
            problem(
                response,
                meter,
                "malformed",
                400,
                "invalid finalize request",
            )?;
            return Ok(());
        }
    };
    let encoded = request
        .csr
        .as_deref()
        .unwrap_or_default()
        .trim_end_matches('=');
    let size = encoded
        .len()
        .checked_mul(3)
        .ok_or_else(|| anyhow!("CSR capacity exceeded"))?
        / 4
        + 3;
    if size > 128 * 1024 + 3 {
        problem(response, meter, "malformed", 400, "CSR exceeds capacity")?;
        return Ok(());
    }
    meter.charge(
        size.checked_mul(64)
            .and_then(|n| n.checked_add(65536))
            .ok_or_else(|| anyhow!("CSR capacity exceeded"))?,
    )?;
    let decoder = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    let csr = match decoder.decode(encoded) {
        Ok(csr) => csr,
        Err(_) => {
            problem(response, meter, "malformed", 400, "invalid CSR encoding")?;
            return Ok(());
        }
    };
    if crate::local_pki::AcmeProfile::check_request(&csr).is_err() {
        problem(
            response,
            meter,
            "malformed",
            400,
            "invalid CSR signature or DER",
        )?;
        return Ok(());
    }
    let order = db.transaction(meter, |tx| {
        let Some(mut order) = tx.get::<DbOrder>(b"acme_orders", id.as_bytes())? else {
            return Ok(None);
        };
        if order.account_id == account.id && order.provisioner_id == format!("acme/{}", config.ca) {
            order_state(tx, &mut order, OffsetDateTime::now_utc())?;
        }
        Ok(Some(order))
    })?;
    let Some(order) = order else {
        problem(response, meter, "malformed", 400, "order not found")?;
        return Ok(());
    };
    if order.account_id != account.id || order.provisioner_id != format!("acme/{}", config.ca) {
        problem(
            response,
            meter,
            "unauthorized",
            401,
            "account does not own order",
        )?;
        return Ok(());
    }
    meter
        .charge(order.authorization_ids.as_ref().map_or(0, Vec::len) * (base.len() + 256) + 8192)?;
    response.location = Some(format!("{base}/order/{}", order.id));
    if order.status == "valid" {
        response.body = json(&views::order(&order, base), meter)?;
        return Ok(());
    }
    if order.status != "ready" {
        problem(response, meter, "orderNotReady", 400, "order is not ready")?;
        return Ok(());
    }
    let before = OffsetDateTime::parse(&order.not_before, &Rfc3339)?;
    let after = OffsetDateTime::parse(&order.not_after, &Rfc3339)?;
    let duration = after
        .unix_timestamp()
        .checked_sub(before.unix_timestamp())
        .ok_or_else(|| anyhow!("certificate duration overflow"))?;
    if !(300..=365 * 86400 + 60).contains(&duration) || after <= OffsetDateTime::now_utc() {
        problem(
            response,
            meter,
            "badCSR",
            400,
            "certificate validity not authorized",
        )?;
        return Ok(());
    }
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    for identifier in order.identifiers.iter().flatten() {
        match identifier.kind.as_str() {
            "dns" => dns.push(identifier.value.clone()),
            "ip" => ips.push(identifier.value.parse()?),
            _ => {
                problem(
                    response,
                    meter,
                    "badCSR",
                    400,
                    "unsupported order identifiers",
                )?;
                return Ok(());
            }
        }
    }
    let profile = match crate::local_pki::AcmeProfile::verified(
        &csr,
        before.unix_timestamp(),
        after.unix_timestamp(),
        dns,
        ips,
    ) {
        Ok(profile) => profile,
        Err(_) => {
            problem(
                response,
                meter,
                "badCSR",
                400,
                "CSR identifiers do not match order",
            )?;
            return Ok(());
        }
    };
    let csr = crate::cert_cpu::RetainedBytes::copy(&csr, meter.0.clone())?;
    response.action = Some(Action::Finalize {
        order,
        csr,
        profile,
    });
    Ok(())
}
pub(super) fn publish(
    db: &mut Database,
    meter: &mut Meter,
    order: DbOrder,
    issued: Result<crate::cert_cpu::RetainedBytes>,
    mut response: ResponseData,
    authority: &str,
) -> Result<ResponseData> {
    let issued = match issued {
        Ok(issued) => issued,
        Err(_) => {
            meter.0.check()?;
            problem(
                &mut response,
                meter,
                "serverInternal",
                500,
                "certificate signing failed",
            )?;
            return Ok(response);
        }
    };
    meter.0.check()?;
    meter.charge(
        issued
            .as_bytes()
            .len()
            .checked_mul(64)
            .and_then(|n| n.checked_add(65536))
            .ok_or_else(|| anyhow!("certificate capacity exceeded"))?,
    )?;
    let blocks = crate::certmagic::pem_blocks(issued.as_bytes(), "acme-issued")?;
    ensure!(
        !blocks.is_empty() && blocks.len() <= 16,
        "invalid issued certificate chain"
    );
    ensure!(
        blocks
            .iter()
            .all(|(kind, der)| kind == "CERTIFICATE" && der.len() <= 128 * 1024),
        "invalid issued certificate chain"
    );
    let leaf = openssl::x509::X509::from_der(&blocks[0].1)?;
    let serial = leaf.serial_number().to_bn()?.to_dec_str()?.to_string();
    let encoding = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    let leaf_pem = pem::encode_config(
        &pem::Pem::new("CERTIFICATE", blocks[0].1.to_vec()),
        encoding,
    )
    .into_bytes();
    let mut intermediates = Vec::new();
    for (_, der) in blocks.iter().skip(1) {
        intermediates.extend_from_slice(
            pem::encode_config(&pem::Pem::new("CERTIFICATE", der.to_vec()), encoding).as_bytes(),
        );
    }
    let completed = db.transaction(meter, |tx| {
        let Some(mut current) = tx.get::<DbOrder>(b"acme_orders", order.id.as_bytes())? else {
            return Err(Error::Record("finalized order disappeared"));
        };
        if current.account_id != order.account_id {
            return Err(Error::Record("order owner changed during signing"));
        }
        if current.status == "valid" {
            return Ok(Some(current));
        }
        order_state(tx, &mut current, OffsetDateTime::now_utc())?;
        if current.status != "ready" {
            return Ok(None);
        }
        let id = fresh(tx, b"acme_certs")?;
        if tx.contains(b"acme_serial_certs_index", serial.as_bytes())? {
            return Err(Error::Record("certificate serial collision"));
        }
        let certificate = DbCert {
            id: id.clone(),
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|_| Error::Record("clock unavailable"))?,
            account_id: current.account_id.clone(),
            order_id: current.id.clone(),
            leaf: GoBytes(Some(leaf_pem)),
            intermediates: GoBytes((!intermediates.is_empty()).then_some(intermediates)),
            unknown: BTreeMap::new(),
        };
        tx.put(b"acme_certs", id.as_bytes(), &certificate)?;
        tx.put(
            b"acme_serial_certs_index",
            serial.as_bytes(),
            &SerialIndex {
                serial: serial.clone(),
                certificate_id: id.clone(),
                unknown: BTreeMap::new(),
            },
        )?;
        tx.put_raw(b"x509_certs", serial.as_bytes(), &blocks[0].1)?;
        tx.put(
            b"x509_certs_data",
            serial.as_bytes(),
            &super::records::CertificateData {
                provisioner: Some(super::records::ProvisionerData {
                    id: order.provisioner_id.clone(),
                    name: authority.into(),
                    kind: "ACME".into(),
                    unknown: BTreeMap::new(),
                }),
                unknown: BTreeMap::new(),
            },
        )?;
        current.status = "valid".into();
        current.certificate = id;
        tx.put(b"acme_orders", current.id.as_bytes(), &current)?;
        Ok(Some(current))
    })?;
    let Some(completed) = completed else {
        problem(
            &mut response,
            meter,
            "orderNotReady",
            400,
            "order authorization is no longer valid",
        )?;
        return Ok(response);
    };
    let base = response
        .location
        .as_deref()
        .and_then(|s| s.rsplit_once("/order/"))
        .map(|(base, _)| base)
        .ok_or_else(|| anyhow!("order binding unavailable"))?;
    response.body = json(&views::order(&completed, base), meter)?;
    Ok(response)
}
pub(super) fn certificate(
    db: &mut Database,
    meter: &mut Meter,
    id: &str,
    payload: &[u8],
    account: &DbAccount,
    response: &mut ResponseData,
) -> Result<()> {
    if !payload.is_empty() {
        problem(
            response,
            meter,
            "malformed",
            400,
            "POST-as-GET payload must be empty",
        )?;
        return Ok(());
    }
    let certificate = db.transaction(meter, |tx| tx.get::<DbCert>(b"acme_certs", id.as_bytes()))?;
    let Some(certificate) = certificate else {
        problem(response, meter, "malformed", 400, "certificate not found")?;
        return Ok(());
    };
    if certificate.account_id != account.id {
        problem(
            response,
            meter,
            "unauthorized",
            401,
            "account does not own certificate",
        )?;
        return Ok(());
    }
    let leaf = certificate
        .leaf
        .0
        .as_deref()
        .ok_or_else(|| anyhow!("stored certificate has no leaf"))?;
    let chain = certificate.intermediates.0.as_deref().unwrap_or_default();
    let body = match canonical_certificate(leaf, chain, meter) {
        Ok(body) => body,
        Err(_) => {
            meter.0.check()?;
            problem(
                response,
                meter,
                "serverInternal",
                500,
                "invalid stored certificate chain",
            )?;
            return Ok(());
        }
    };
    response.content_type = "application/pem-certificate-chain";
    response.body = body;
    Ok(())
}

/// A download is a parsed certificate bundle, not arbitrary stored bytes. This
/// also gives legacy CRLF records the same canonical LF PEM as the Go handler.
pub(super) fn canonical_certificate(
    leaf: &[u8],
    chain: &[u8],
    meter: &mut Meter,
) -> Result<Vec<u8>> {
    let input = leaf
        .len()
        .checked_add(chain.len())
        .ok_or_else(|| anyhow!("certificate size overflow"))?;
    meter.charge(
        input
            .checked_mul(64)
            .and_then(|n| n.checked_add(65536))
            .ok_or_else(|| anyhow!("certificate size overflow"))?,
    )?;
    meter.work(input.div_ceil(16).max(1))?;
    let mut joined = Vec::new();
    joined.try_reserve_exact(input)?;
    joined.extend_from_slice(leaf);
    joined.extend_from_slice(chain);
    let blocks = crate::certmagic::pem_blocks(&joined, "ACME certificate")?;
    let capacity = input
        .checked_mul(2)
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(|| anyhow!("certificate output overflow"))?;
    let mut body = Vec::new();
    body.try_reserve_exact(capacity)?;
    let encoding = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    for (kind, der) in blocks {
        meter.work(der.len().div_ceil(16).max(1))?;
        ensure!(
            kind == "CERTIFICATE",
            "stored bundle contains a non-certificate block"
        );
        let (tail, _) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| anyhow!("invalid stored certificate DER"))?;
        ensure!(tail.is_empty(), "trailing stored certificate DER");
        let encoded = pem::encode_config(&pem::Pem::new(kind, der.to_vec()), encoding);
        ensure!(
            body.len()
                .checked_add(encoded.len())
                .is_some_and(|n| n <= capacity),
            "certificate output exceeds prepaid capacity"
        );
        body.extend_from_slice(encoded.as_bytes());
    }
    Ok(body)
}
