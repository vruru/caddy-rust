//! Closed ACME signing profile: verified DNS/IP authorization replaces the
//! caller's untrusted requested SAN/subject fields. Ordinary internal issuance
//! keeps its separate original profile and API.
use anyhow::{Result, anyhow, ensure};
use std::net::IpAddr;
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
};

pub(crate) struct AcmeProfile {
    pub not_before: i64,
    pub not_after: i64,
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
}
impl AcmeProfile {
    pub(crate) fn check_request(csr: &[u8]) -> Result<()> {
        ensure!(
            !csr.is_empty() && csr.len() <= 128 * 1024,
            "CSR capacity exceeded"
        );
        super::material::csr_syntax(csr)?;
        let (tail, request) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr)
                .map_err(|_| anyhow!("invalid CSR DER"))?;
        ensure!(
            tail.is_empty() && request.signature_value.unused_bits == 0,
            "invalid CSR encoding"
        );
        crate::cert_status::verify_x509_signature(
            &request.certification_request_info.subject_pki,
            &request.signature_algorithm,
            &request.signature_value.data,
            request.certification_request_info.raw,
            true,
        )?;
        Ok(())
    }
    /// Runs on the already admitted signing/transaction worker. The caller has
    /// prepaid DER parsing, names, vectors and signature work before entry.
    pub(crate) fn verified(
        csr: &[u8],
        not_before: i64,
        not_after: i64,
        expected_dns: Vec<String>,
        expected_ips: Vec<IpAddr>,
    ) -> Result<Self> {
        ensure!(
            !csr.is_empty() && csr.len() <= 128 * 1024,
            "CSR capacity exceeded"
        );
        super::material::csr_syntax(csr)?;
        let (tail, request) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr)
                .map_err(|_| anyhow!("invalid CSR DER"))?;
        ensure!(
            tail.is_empty() && request.signature_value.unused_bits == 0,
            "invalid CSR encoding"
        );
        crate::cert_status::verify_x509_signature(
            &request.certification_request_info.subject_pki,
            &request.signature_algorithm,
            &request.signature_value.data,
            request.certification_request_info.raw,
            true,
        )?;
        let key = openssl::pkey::PKey::public_key_from_der(
            request.certification_request_info.subject_pki.raw,
        )?;
        if key.id() == openssl::pkey::Id::RSA {
            ensure!(
                key.bits() >= 2048 && key.bits() <= 8192,
                "unsupported ACME CSR RSA strength"
            );
        }
        let name = crate::http_runtime::client_cert_facts::parse_name(
            request.certification_request_info.subject.as_raw(),
        )
        .map_err(|_| anyhow!("invalid CSR subject"))?;
        let mut dns = Vec::new();
        let mut ips = Vec::new();
        let mut saw_san = false;
        if let Some(extensions) = request.requested_extensions() {
            for extension in extensions {
                if let ParsedExtension::SubjectAlternativeName(san) = extension {
                    ensure!(
                        !saw_san && san.general_names.len() <= 4096,
                        "invalid CSR SANs"
                    );
                    saw_san = true;
                    for value in &san.general_names {
                        match value {
                            GeneralName::DNSName(value) => dns.push(canonical_dns(value)?),
                            GeneralName::IPAddress(value) => ips.push(match value.len() {
                                4 => IpAddr::from(<[u8; 4]>::try_from(*value)?),
                                16 => IpAddr::from(<[u8; 16]>::try_from(*value)?).to_canonical(),
                                _ => return Err(anyhow!("invalid CSR IP")),
                            }),
                            GeneralName::URI(_) => {
                                return Err(anyhow!(
                                    "CSR URI is not an authorized DNS/IP identifier"
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        if !name.common_name.is_empty() {
            match name.common_name.parse::<IpAddr>() {
                Ok(ip) => ips.push(ip.to_canonical()),
                Err(_) => dns.push(canonical_dns(&name.common_name)?),
            };
        }
        dns.sort();
        dns.dedup();
        ips.sort();
        ips.dedup();
        let mut authorized = expected_dns
            .into_iter()
            .map(|name| canonical_dns(&name))
            .collect::<Result<Vec<_>>>()?;
        authorized.sort();
        authorized.dedup();
        let mut authorized_ips = expected_ips
            .into_iter()
            .map(|ip| ip.to_canonical())
            .collect::<Vec<_>>();
        authorized_ips.sort();
        authorized_ips.dedup();
        ensure!(
            dns == authorized && ips == authorized_ips,
            "CSR identifiers do not match the order exactly"
        );
        ensure!(not_after > not_before, "invalid ACME certificate validity");
        Ok(Self {
            not_before,
            not_after,
            common_name: name.common_name,
            dns_names: dns,
            ip_addresses: ips,
        })
    }
}
pub(crate) fn canonical_dns(value: &str) -> Result<String> {
    let wildcard = value.starts_with("*.");
    let raw = if wildcard { &value[2..] } else { value };
    ensure!(
        !raw.is_empty() && !raw.contains('*'),
        "invalid CSR DNS name"
    );
    // Match the strict ASCII/label mapping used by Go's idna.Lookup. The
    // permissive convenience function accepts URI delimiters (and could let
    // an order's DNS identifier change the HTTP proof URL's authority/path).
    let name = idna::uts46::Uts46::new()
        .to_ascii(
            raw.as_bytes(),
            idna::AsciiDenyList::STD3,
            idna::uts46::Hyphens::Check,
            idna::uts46::DnsLength::Ignore,
        )?
        .into_owned();
    // A final root label is a valid absolute DNS name. Keep it in the
    // authorized SAN rather than silently changing the requested identifier.
    let labels = name.strip_suffix('.').unwrap_or(&name);
    ensure!(
        !labels.is_empty()
            && labels.len() <= 253
            && !labels.starts_with('.')
            && !labels.ends_with('.')
            && !labels.contains(".."),
        "invalid CSR DNS name"
    );
    Ok(if wildcard { format!("*.{name}") } else { name })
}
