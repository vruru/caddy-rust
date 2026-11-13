//! Explicit TLS1.2 policy bridge to the complete SSL engine. Default/TLS1.3/
//! QUIC configurations continue through their existing Rustls provider.
use super::*;
use native_ssl_tls::{ServerClientAuth, server_engine::ServerEngine};
use openssl::{
    ssl::{
        AlpnError, Ssl, SslContextBuilder, SslMethod, SslOptions, SslSessionCacheMode, SslVersion,
    },
    x509::X509,
};
use rustls::{SignatureAlgorithm, SignatureScheme};
use std::io;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    Ec,
    Rsa,
}
pub(super) struct Suite {
    pub ssl: &'static str,
    pub id: u16,
    pub family: Family,
    pub cbc: bool,
}
const SUITES: &[Suite] = &[
    Suite {
        ssl: "ECDHE-ECDSA-AES128-SHA",
        id: 0xc009,
        family: Family::Ec,
        cbc: true,
    },
    Suite {
        ssl: "ECDHE-ECDSA-AES256-SHA",
        id: 0xc00a,
        family: Family::Ec,
        cbc: true,
    },
    Suite {
        ssl: "ECDHE-RSA-AES128-SHA",
        id: 0xc013,
        family: Family::Rsa,
        cbc: true,
    },
    Suite {
        ssl: "ECDHE-RSA-AES256-SHA",
        id: 0xc014,
        family: Family::Rsa,
        cbc: true,
    },
    Suite {
        ssl: "ECDHE-ECDSA-AES128-GCM-SHA256",
        id: 0xc02b,
        family: Family::Ec,
        cbc: false,
    },
    Suite {
        ssl: "ECDHE-ECDSA-AES256-GCM-SHA384",
        id: 0xc02c,
        family: Family::Ec,
        cbc: false,
    },
    Suite {
        ssl: "ECDHE-RSA-AES128-GCM-SHA256",
        id: 0xc02f,
        family: Family::Rsa,
        cbc: false,
    },
    Suite {
        ssl: "ECDHE-RSA-AES256-GCM-SHA384",
        id: 0xc030,
        family: Family::Rsa,
        cbc: false,
    },
    Suite {
        ssl: "ECDHE-ECDSA-CHACHA20-POLY1305",
        id: 0xcca9,
        family: Family::Ec,
        cbc: false,
    },
    Suite {
        ssl: "ECDHE-RSA-CHACHA20-POLY1305",
        id: 0xcca8,
        family: Family::Rsa,
        cbc: false,
    },
];
pub(super) fn cbc_id(id: u16) -> bool {
    SUITES.iter().any(|s| s.id == id && s.cbc)
}
pub(super) fn schemes(family: Family, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
    offered
        .iter()
        .copied()
        .filter(|s| match family {
            Family::Rsa => matches!(
                s,
                SignatureScheme::RSA_PKCS1_SHA256
                    | SignatureScheme::RSA_PKCS1_SHA384
                    | SignatureScheme::RSA_PKCS1_SHA512
                    | SignatureScheme::RSA_PSS_SHA256
                    | SignatureScheme::RSA_PSS_SHA384
                    | SignatureScheme::RSA_PSS_SHA512
                    | SignatureScheme::RSA_PKCS1_SHA1
            ),
            Family::Ec => matches!(
                s,
                SignatureScheme::ECDSA_NISTP256_SHA256
                    | SignatureScheme::ECDSA_NISTP384_SHA384
                    | SignatureScheme::ECDSA_NISTP521_SHA512
                    | SignatureScheme::ECDSA_SHA1_Legacy
                    | SignatureScheme::ED25519
            ),
        })
        .collect()
}
pub(super) fn allowed(ids: &[u16]) -> Vec<&'static Suite> {
    ids.iter()
        .filter_map(|id| SUITES.iter().find(|s| s.id == *id))
        .collect()
}
/// Match Go's fixed TLS12 safety order and its AES-GCM hardware/peer hint.
/// Configured order is an allow-set; an optional CBC entry cannot move ahead
/// of an available AEAD, nor AES256 ahead of AES128.
pub(super) fn ordered(ids: &[u16], offered: &[u16]) -> Vec<u16> {
    let hardware = {
        #[cfg(target_arch = "aarch64")]
        {
            std::arch::is_aarch64_feature_detected!("aes")
                && std::arch::is_aarch64_feature_detected!("pmull")
        }
        #[cfg(target_arch = "x86_64")]
        {
            std::is_x86_feature_detected!("aes")
                && std::is_x86_feature_detected!("pclmulqdq")
                && std::is_x86_feature_detected!("sse4.1")
                && std::is_x86_feature_detected!("ssse3")
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            false
        }
    };
    let known = offered.iter().copied().find(|id| {
        matches!(
            id,
            0x0005
                | 0x000a
                | 0x002f
                | 0x0035
                | 0x003c
                | 0x009c
                | 0x009d
                | 0xc007
                | 0xc009
                | 0xc00a
                | 0xc011
                | 0xc012
                | 0xc013
                | 0xc014
                | 0xc023
                | 0xc027
                | 0xc02b
                | 0xc02c
                | 0xc02f
                | 0xc030
                | 0xcca8
                | 0xcca9
                | 0x1301
                | 0x1302
                | 0x1303
        )
    });
    let aes = hardware
        && known
            .is_some_and(|id| matches!(id, 0xc02b | 0xc02c | 0xc02f | 0xc030 | 0x1301 | 0x1302));
    let order = if aes {
        [
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014,
        ]
    } else {
        [
            0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014,
        ]
    };
    order.into_iter().filter(|id| ids.contains(id)).collect()
}
pub(super) fn compatible_schemes(
    ids: &[u16],
    offered_ciphers: &[u16],
    offered_schemes: &[SignatureScheme],
) -> Vec<SignatureScheme> {
    let available = allowed(ids);
    let rsa = available
        .iter()
        .any(|s| s.family == Family::Rsa && offered_ciphers.contains(&s.id));
    let ec = available
        .iter()
        .any(|s| s.family == Family::Ec && offered_ciphers.contains(&s.id));
    let rsa_schemes = if rsa {
        schemes(Family::Rsa, offered_schemes)
    } else {
        Vec::new()
    };
    let ec_schemes = if ec {
        schemes(Family::Ec, offered_schemes)
    } else {
        Vec::new()
    };
    offered_schemes
        .iter()
        .copied()
        .filter(|s| rsa_schemes.contains(s) || ec_schemes.contains(s))
        .collect()
}
#[derive(Clone)]
pub(super) enum Sessions {
    Cache(native_ssl_tls::ServerSessions),
    Tickets(native_ssl_tls::ServerTickets),
}
impl Sessions {
    pub(super) fn resumed_group(&self) -> Option<i64> {
        match self {
            Self::Cache(s) => s.resumed_group(),
            Self::Tickets(s) => s.resumed_group(),
        }
    }
    fn configure(
        &self,
        ctx: &mut SslContextBuilder,
        binding: &[u8; 32],
        gate: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> io::Result<()> {
        match self {
            Self::Cache(s) => s.configure(ctx, binding, gate),
            Self::Tickets(s) => s.configure(ctx, binding),
        }
    }
}
/// Called only inside ServerStream::prepare's bounded CPU factory. No source
/// I/O, new publication or automatic acquisition is possible in this function.
pub(super) fn engine(
    selection: crate::tls_resolver::CertificateSelection,
    config: Arc<rustls::ServerConfig>,
    suites: Vec<u16>,
    auth: ServerClientAuth,
    sessions: Option<(Sessions, [u8; 32])>,
) -> io::Result<ServerEngine> {
    let native = selection.native.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "selected key has no native SSL credential capability",
        )
    })?;
    if !native.admitted() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "selected TLS key withdrawn",
        ));
    }
    let prepared = Arc::new(native.private.prepare().map_err(|e| {
        io::Error::new(
            if crate::cert_transient::is_resource(&e) {
                io::ErrorKind::OutOfMemory
            } else {
                io::ErrorKind::InvalidData
            },
            e,
        )
    })?);
    let credential = prepared.key().to_owned();
    let status = native.clone();
    let staple_gate: Arc<dyn Fn() -> bool + Send + Sync> =
        Arc::new(move || status.leaf.admission().allow_staple);
    let gate: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
        let _ = &prepared;
        native.admitted()
    });
    engine_with_key(
        selection.key,
        config,
        suites,
        auth,
        sessions,
        credential,
        gate,
        staple_gate,
    )
}
/// Same complete SSL policy engine for a pinned ACME proof generation. Its
/// caller supplies the real proof lease gate, never a business KeyState shim.
pub(super) fn engine_with_key(
    key: Arc<rustls::sign::CertifiedKey>,
    config: Arc<rustls::ServerConfig>,
    suites: Vec<u16>,
    auth: ServerClientAuth,
    sessions: Option<(Sessions, [u8; 32])>,
    credential: openssl::pkey::PKey<openssl::pkey::Private>,
    admission: Arc<dyn Fn() -> bool + Send + Sync>,
    staple_gate: Arc<dyn Fn() -> bool + Send + Sync>,
) -> io::Result<ServerEngine> {
    let mut ctx = SslContextBuilder::new(SslMethod::tls_server()).map_err(io::Error::other)?;
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(io::Error::other)?;
    ctx.set_max_proto_version(Some(SslVersion::TLS1_2))
        .map_err(io::Error::other)?;
    ctx.set_security_level(1);
    // The selected chain is authoritative; never auto-build or reorder it.
    ctx.set_mode(openssl::ssl::SslMode::NO_AUTO_CHAIN);
    ctx.set_options(
        SslOptions::NO_RENEGOTIATION
            | SslOptions::NO_COMPRESSION
            | SslOptions::NO_TICKET
            | SslOptions::CIPHER_SERVER_PREFERENCE,
    );
    ctx.set_session_cache_mode(SslSessionCacheMode::OFF);
    let family = match key.key.algorithm() {
        SignatureAlgorithm::RSA => Family::Rsa,
        SignatureAlgorithm::ECDSA | SignatureAlgorithm::ED25519 => Family::Ec,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SSL certificate signing algorithm unavailable",
            ));
        }
    };
    let ciphers = allowed(&suites)
        .into_iter()
        .filter(|s| s.family == family)
        .map(|s| s.ssl)
        .collect::<Vec<_>>()
        .join(":");
    if ciphers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no policy cipher matches selected key",
        ));
    }
    ctx.set_cipher_list(&ciphers).map_err(io::Error::other)?;
    let groups = config
        .crypto_provider()
        .kx_groups
        .iter()
        .map(|g| match u16::from(g.name()) {
            29 => Ok("X25519"),
            23 => Ok("P-256"),
            24 => Ok("P-384"),
            25 => Ok("P-521"),
            4588 => Ok("X25519MLKEM768"),
            4587 => Ok("SecP256r1MLKEM768"),
            4589 => Ok("SecP384r1MLKEM1024"),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "policy key exchange group unavailable to SSL",
            )),
        })
        .collect::<io::Result<Vec<_>>>()?
        .join(":");
    ctx.set_groups_list(&groups).map_err(io::Error::other)?;
    let signature_schemes = crate::crypto::provider()
        .signature_verification_algorithms
        .supported_schemes()
        .into_iter()
        .map(|s| {
            native_ssl_tls::signature_scheme_name(s).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "policy signature scheme unavailable to SSL",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?
        .join(":");
    ctx.set_sigalgs_list(&signature_schemes)
        .map_err(io::Error::other)?;
    let leaf = key.cert.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "selected certificate leaf missing",
        )
    })?;
    let leaf = X509::from_der(leaf.as_ref()).map_err(io::Error::other)?;
    ctx.set_certificate(&leaf).map_err(io::Error::other)?;
    for der in &key.cert[1..] {
        ctx.add_extra_chain_cert(X509::from_der(der.as_ref()).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    ctx.set_private_key(&credential).map_err(io::Error::other)?;
    ctx.check_private_key().map_err(io::Error::other)?;
    let alpn = config.clone();
    ctx.set_alpn_select_callback(move |ssl, offered| {
        if alpn.alpn_protocols.is_empty() {
            return Err(AlpnError::NOACK);
        }
        let cipher = native_ssl_tls::pending_cipher(ssl).ok_or(AlpnError::ALERT_FATAL)?;
        for wanted in &alpn.alpn_protocols {
            if wanted == b"h2" && cbc_id(cipher) {
                continue;
            }
            let mut rest = offered;
            while let Some((&size, tail)) = rest.split_first() {
                let n = usize::from(size);
                let value = tail.get(..n).ok_or(AlpnError::ALERT_FATAL)?;
                if value == wanted.as_slice() {
                    return Ok(value);
                }
                rest = &tail[n..];
            }
        }
        Err(AlpnError::ALERT_FATAL)
    });
    let staple = key.clone();
    let status = admission.clone();
    ctx.set_status_callback(move |ssl| {
        if !status() {
            return Ok(false);
        }
        if staple_gate() {
            if let Some(ocsp) = staple.ocsp.as_deref() {
                ssl.set_ocsp_status(ocsp)?;
                return Ok(true);
            }
        }
        Ok(false)
    })
    .map_err(io::Error::other)?;
    if let Some((sessions, binding)) = &sessions {
        sessions.configure(&mut ctx, binding, admission.clone())?;
    }
    auth.configure(&mut ctx)?;
    let context = ctx.build();
    let mut ssl = Ssl::new(&context).map_err(io::Error::other)?;
    auth.bind(&mut ssl)?;
    ServerEngine::new(ssl, admission)
}

// Preserve the same native h1-only ClientHello exception as the Rustls path.
pub(super) fn alpn_config(
    config: &rustls::ServerConfig,
    offered: &[&[u8]],
) -> rustls::ServerConfig {
    let mut config = config.clone();
    if offered.contains(&b"http/1.1".as_slice())
        && config.alpn_protocols.iter().any(|p| p == b"h2")
        && !offered
            .iter()
            .any(|offer| config.alpn_protocols.iter().any(|p| p.as_slice() == *offer))
    {
        config.alpn_protocols.clear();
    }
    config
}
