//! Real RFC8555/RFC8737 proof requests. Certificate trust is intentionally not
//! required for self-signed ALPN proofs; private-key possession still is.
use super::{
    records::DbChallenge,
    resources::{Leased, Resources, Scope},
};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Copy)]
pub(super) enum Validation {
    Valid,
    Failed {
        fatal: bool,
        kind: &'static str,
        detail: &'static str,
    },
}
fn connection() -> Validation {
    Validation::Failed {
        fatal: false,
        kind: "connection",
        detail: "challenge endpoint connection failed",
    }
}
fn rejected(detail: &'static str) -> Validation {
    Validation::Failed {
        fatal: true,
        kind: "rejectedIdentifier",
        detail,
    }
}
struct ProofVerifier {
    scope: Arc<Scope>,
}
impl std::fmt::Debug for ProofVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AcmeProofVerifier")
    }
}
impl ProofVerifier {
    fn spki<'a>(
        &self,
        cert: &'a CertificateDer<'_>,
    ) -> std::result::Result<SubjectPublicKeyInfoDer<'a>, rustls::Error> {
        self.scope
            .work(cert.len().div_ceil(16).max(1))
            .and_then(|_| self.scope.reserve(cert.len() * 64 + 4096))
            .map_err(|_| rustls::Error::General("ACME proof capacity exceeded".into()))?;
        let (tail, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if !tail.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(SubjectPublicKeyInfoDer::from(
            parsed.tbs_certificate.subject_pki.raw,
        ))
    }
}
impl ServerCertVerifier for ProofVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if chain.len() > 16 || chain.iter().map(|c| c.len()).sum::<usize>() + end.len() > 65535 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        self.spki(end)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature_with_raw_key(
            message,
            &self.spki(cert)?,
            signature,
            &crate::crypto::provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &self.spki(cert)?,
            signature,
            &crate::crypto::provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        crate::crypto::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
fn tls_config(scope: Arc<Scope>) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(crate::crypto::provider())
        .with_safe_default_protocol_versions()
        .expect("TLS12/13 available")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProofVerifier { scope }))
        .with_no_client_auth()
}
struct AddressJob {
    host: String,
    scope: Arc<Scope>,
}
impl AddressJob {
    fn execute(self) -> Result<Leased<Vec<SocketAddr>>> {
        self.scope.reserve(4 * 1024 * 1024)?;
        let addresses = (self.host.as_str(), 443)
            .to_socket_addrs()?
            .take(4097)
            .collect::<Vec<_>>();
        ensure!(
            !addresses.is_empty() && addresses.len() <= 4096,
            "challenge address count exceeded"
        );
        Ok(Leased {
            value: addresses,
            scope: self.scope,
        })
    }
}
pub(super) async fn validate(
    resources: Arc<Resources>,
    scope: Arc<Scope>,
    resolvers: Arc<[String]>,
    challenge: &DbChallenge,
    proof: &str,
) -> Result<Validation> {
    scope.check()?;
    scope.reserve(8 * 1024 * 1024)?;
    // Legacy records are parsed with the same strict host mapping as freshly
    // created orders. Never splice an unchecked stored name/token into a URL.
    let value = match challenge.value.parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical().to_string(),
        Err(_) => match crate::local_pki::canonical_acme_dns(&challenge.value) {
            Ok(name) if !name.starts_with("*.") => name,
            _ => return Ok(rejected("invalid challenge identifier")),
        },
    };
    if challenge.token.is_empty()
        || challenge.token.len() > 256
        || !challenge
            .token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Ok(rejected("invalid challenge token"));
    }
    let result = match challenge.kind.as_str() {
        "dns-01" => {
            let digest = URL_SAFE_NO_PAD
                .encode(Sha256::digest(proof.as_bytes()))
                .into_bytes();
            scope.work(resolvers.len())?;
            let work = crate::http_runtime::acme_dns::matches(
                format!("_acme-challenge.{value}"),
                resolvers,
                digest,
                scope.clone(),
                resources.cancel.child_token(),
                scope.remaining()?,
            )?;
            match work.await {
                Ok(true) => Validation::Valid,
                Ok(false) => Validation::Failed {
                    fatal: false,
                    kind: "rejectedIdentifier",
                    detail: "DNS TXT proof did not match",
                },
                Err(_) => connection(),
            }
        }
        "http-01" => {
            let tls = tls_config(scope.clone());
            let cancel = resources.cancel.clone();
            let token = scope.cancel.clone();
            let remaining = scope.remaining()?;
            let build_scope = scope.clone();
            let client = crate::cert_cpu::run(resources.cpu.clone(), token.clone(), move || {
                build_scope.check()?;
                Ok(reqwest::Client::builder()
                    .use_preconfigured_tls(tls)
                    .http1_only()
                    .pool_max_idle_per_host(0)
                    .redirect(reqwest::redirect::Policy::limited(10))
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(remaining)
                    .build()?)
            })
            .await?;
            let host = match value.parse::<IpAddr>() {
                Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
                _ => value.clone(),
            };
            let url = format!(
                "http://{host}/.well-known/acme-challenge/{}",
                challenge.token
            );
            let check = async {
                let mut response = client
                    .get(url)
                    .header(http::header::CONNECTION, "close")
                    .send()
                    .await?;
                if response.status().as_u16() >= 400 {
                    return Ok(connection());
                }
                let mut body = Vec::new();
                scope.reserve(8192)?;
                body.try_reserve_exact(8192)?;
                while let Some(chunk) = response.chunk().await? {
                    if body.len() + chunk.len() > 8192 {
                        return Ok(rejected("HTTP proof exceeds capacity"));
                    }
                    body.extend_from_slice(&chunk);
                    scope.check()?;
                }
                Ok::<_, anyhow::Error>(
                    if std::str::from_utf8(&body).is_ok_and(|s| s.trim() == proof) {
                        Validation::Valid
                    } else {
                        rejected("HTTP key authorization did not match")
                    },
                )
            };
            tokio::select! {biased;_=cancel.cancelled()=>return Err(anyhow!("ACME services stopped")),_=token.cancelled()=>return Err(anyhow!("ACME validation cancelled")),result=check=>result.unwrap_or_else(|_|connection())}
        }
        "tls-alpn-01" => {
            let job = AddressJob {
                host: value.clone(),
                scope: scope.clone(),
            };
            let addresses =
                match crate::cert_cpu::run(resources.cpu.clone(), scope.cancel.clone(), move || {
                    job.execute()
                })
                .await
                {
                    Ok(addresses) => addresses,
                    Err(_) => {
                        scope.check()?;
                        return Ok(connection());
                    }
                };
            let connect = async {
                let mut connection = None;
                for address in &addresses.value {
                    if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                        connection = Some(stream);
                        break;
                    }
                }
                let stream =
                    connection.ok_or_else(|| anyhow!("challenge connection unavailable"))?;
                let mut config = tls_config(scope.clone());
                config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
                let server_name = server_name(&value)?;
                let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(ServerName::try_from(server_name)?, stream)
                    .await?;
                let (_, state) = stream.get_ref();
                if state.alpn_protocol() != Some(b"acme-tls/1") {
                    return Ok(rejected("cannot negotiate acme-tls/1"));
                }
                let cert = state
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .ok_or_else(|| anyhow!("challenge certificate missing"))?;
                scope.reserve(cert.len() * 64 + 4096)?;
                scope.work(cert.len())?;
                Ok::<_, anyhow::Error>(check_alpn(cert, &value, &Sha256::digest(proof.as_bytes())))
            };
            tokio::select! {biased;
                _=resources.cancel.cancelled()=>return Err(anyhow!("ACME services stopped")),
                _=scope.cancel.cancelled()=>return Err(anyhow!("ACME validation cancelled")),
                _=tokio::time::sleep(scope.remaining()?)=>{scope.check()?;connection()},
                result=connect=>match result {Ok(validation)=>validation,Err(error)=>{
                    let no_alpn=error.chain().any(|error|error.downcast_ref::<rustls::Error>().is_some_and(|e|matches!(e,rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol))));
                    if no_alpn {rejected("cannot negotiate acme-tls/1")}else{connection()}
                }}
            }
        }
        _ => rejected("unsupported challenge type"),
    };
    scope.check()?;
    Ok(result)
}
fn server_name(value: &str) -> Result<String> {
    Ok(match value.parse::<IpAddr>() {
        Ok(ip) => match ip.to_canonical() {
            IpAddr::V4(ip) => {
                let b = ip.octets();
                format!("{}.{}.{}.{}.in-addr.arpa.", b[3], b[2], b[1], b[0])
            }
            IpAddr::V6(ip) => {
                let mut out = String::with_capacity(73);
                use std::fmt::Write;
                for byte in ip.octets().iter().rev() {
                    write!(&mut out, "{:x}.{:x}.", byte & 15, byte >> 4)?;
                }
                out.push_str("ip6.arpa.");
                out
            }
        },
        Err(_) => crate::local_pki::canonical_acme_dns(value)?,
    })
}
fn check_alpn(cert: &CertificateDer<'_>, value: &str, digest: &[u8]) -> Validation {
    let Ok((tail, cert)) = x509_parser::parse_x509_certificate(cert) else {
        return rejected("invalid proof certificate");
    };
    if !tail.is_empty() {
        return rejected("invalid proof certificate");
    }
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return rejected("proof certificate has no names");
    };
    // A single authorized SAN is required by RFC8737, including non-DNS/IP
    // names. Do not reproduce upstream's ignored-extra-SAN weakness.
    if san.value.general_names.len() != 1 {
        return rejected("proof certificate must have exactly one authorized name");
    }
    use x509_parser::extensions::GeneralName;
    let matched = match &san.value.general_names[0] {
        GeneralName::DNSName(name) => name.eq_ignore_ascii_case(value),
        GeneralName::IPAddress(raw) => {
            let ip = match raw.len() {
                4 => Some(IpAddr::from(
                    <[u8; 4]>::try_from(*raw).expect("length checked"),
                )),
                16 => Some(IpAddr::from(
                    <[u8; 16]>::try_from(*raw).expect("length checked"),
                )),
                _ => None,
            };
            ip.zip(value.parse::<IpAddr>().ok())
                .is_some_and(|(a, b)| a.to_canonical() == b.to_canonical())
        }
        _ => false,
    };
    if !matched {
        return rejected("proof certificate name mismatch");
    }
    let mut proof = None;
    let mut obsolete = false;
    for extension in cert.extensions() {
        let oid = extension.oid.to_id_string();
        if oid == "1.3.6.1.5.5.7.1.31" {
            if proof.is_some() || !extension.critical {
                return rejected("proof extension must be critical and unique");
            }
            proof = Some(extension.value);
        }
        if oid == "1.3.6.1.5.5.7.1.30.1" {
            obsolete = true;
        }
    }
    if obsolete {
        return rejected("obsolete proof extension");
    }
    match proof {
        Some(value)
            if value.len() == 34
                && value[..2] == [4, 32]
                && openssl::memcmp::eq(&value[2..], digest) =>
        {
            Validation::Valid
        }
        _ => rejected("proof digest extension mismatch"),
    }
}
