use super::{
    decode::{Object, Result, discriminator},
    error::{ConfigError, pointer},
    model::{AcmeSettings, Issuer},
    schema::ObjectKind,
};
use crate::{
    cert_automation::{AcmeIssuerConfig, ChallengeType, ExternalAccountBinding},
    local_pki::InternalIssuerOptions,
};
use serde_json::Value;
use std::time::Duration;

pub(super) fn parse(value: &Value, path: &str) -> Result<Issuer> {
    let normalized = crate::module_json::inline(value, "module", false)
        .map_err(|_| ConfigError::invalid(path.to_owned()))?;
    let value = normalized.as_ref();
    match discriminator(value, "module", path)? {
        "acme" => acme(value, path),
        "internal" => {
            let object = Object::new(Some(value), ObjectKind::Internal, path)?;
            let ca = object.string("ca")?;
            let mut options = InternalIssuerOptions::default();
            let lifetime = object.duration_ns("lifetime")?;
            if lifetime < 0 {
                return Err(ConfigError::invalid(object.at("lifetime")));
            }
            if lifetime > 0 {
                options.lifetime = Duration::from_nanos(lifetime as u64);
            }
            options.sign_with_root = object.boolean("sign_with_root")?.unwrap_or(false);
            Ok(Issuer::Internal {
                ca: if ca.is_empty() {
                    "local".into()
                } else {
                    ca.into()
                },
                options,
            })
        }
        "zerossl" => {
            Object::new(Some(value), ObjectKind::ZeroSsl, path)?;
            Err(ConfigError::unsupported(
                pointer(path, "module"),
                "zerossl_api_issuer",
            ))
        }
        _ => Err(ConfigError::unsupported(
            pointer(path, "module"),
            "issuer_module",
        )),
    }
}

fn acme(value: &Value, path: &str) -> Result<Issuer> {
    let object = Object::new(Some(value), ObjectKind::Acme, path)?;
    let mut config = AcmeIssuerConfig::lets_encrypt();
    let ca = object.string("ca")?;
    if !ca.is_empty() {
        validate_directory(ca, &object.at("ca"))?;
        config.wire.directory = ca.into();
    }
    config.email = object.string("email")?.into();
    for (field, feature) in [
        ("test_ca", "acme_test_ca_retry"),
        ("profile", "acme_profile"),
        ("account_key", "configured_acme_account_key"),
    ] {
        if !object.string(field)?.is_empty() {
            return Err(ConfigError::unsupported(object.at(field), feature));
        }
    }
    if let Some(binding) = object.value("external_account") {
        let binding = Object::new(
            Some(binding),
            ObjectKind::Eab,
            &object.at("external_account"),
        )?;
        let kid = binding.string("key_id")?;
        let key = binding.string("mac_key")?;
        if kid.is_empty() || key.is_empty() {
            return Err(ConfigError::invalid(object.at("external_account")));
        }
        config.eab = Some(ExternalAccountBinding {
            kid: kid.into(),
            hmac_key: key.into(),
        });
    }
    let timeout = object.duration_ns("acme_timeout")?;
    if timeout < 0 {
        return Err(ConfigError::invalid(object.at("acme_timeout")));
    }
    let timeout = (timeout > 0).then(|| Duration::from_nanos(timeout as u64));
    if object.duration_ns("certificate_lifetime")? != 0 {
        return Err(ConfigError::unsupported(
            object.at("certificate_lifetime"),
            "acme_requested_lifetime",
        ));
    }
    if let Some(chains) = object.value("preferred_chains") {
        let chains = Object::new(
            Some(chains),
            ObjectKind::PreferredChains,
            &object.at("preferred_chains"),
        )?;
        if chains.boolean("smallest")?.unwrap_or(false)
            || !chains.strings("root_common_name")?.is_empty()
            || !chains.strings("any_common_name")?.is_empty()
        {
            return Err(ConfigError::unsupported(
                object.at("preferred_chains"),
                "acme_alternate_chains",
            ));
        }
    }
    if object.value("network_proxy").is_some() {
        return Err(ConfigError::unsupported(
            object.at("network_proxy"),
            "acme_network_proxy_module",
        ));
    }
    let roots = object
        .strings("trusted_roots_pem_files")?
        .into_iter()
        .map(Into::into)
        .collect();
    let mut settings = AcmeSettings {
        config,
        roots,
        http_port: None,
        alpn_port: None,
        bind_host: String::new(),
        distributed: true,
        timeout,
    };
    let challenges = Object::new(
        object.value("challenges"),
        ObjectKind::Challenges,
        &object.at("challenges"),
    )?;
    settings.bind_host = challenges.string("bind_host")?.into();
    // The shared registry handles in-process listeners. Distributed challenge
    // material needs its own remote-registry adapter, not a discarded flag.
    settings.distributed = challenges.boolean("distributed")?.unwrap_or(true);
    if let Some(dns) = challenges.value("dns") {
        Object::new(Some(dns), ObjectKind::DnsChallenge, &challenges.at("dns"))?;
        return Err(ConfigError::unsupported(
            challenges.at("dns"),
            "acme_dns_challenge_provider",
        ));
    }
    let mut enabled = Vec::new();
    for (field, kind, port) in [
        ("http", ChallengeType::Http01, &mut settings.http_port),
        (
            "tls-alpn",
            ChallengeType::TlsAlpn01,
            &mut settings.alpn_port,
        ),
    ] {
        let challenge = Object::new(
            challenges.value(field),
            ObjectKind::Challenge,
            &challenges.at(field),
        )?;
        if let Some(value) = challenge.integer("alternate_port")? {
            if !(0..=65535).contains(&value) {
                return Err(ConfigError::invalid(challenge.at("alternate_port")));
            }
            if value != 0 {
                *port = Some(value as u16);
            }
        }
        if !challenge.boolean("disabled")?.unwrap_or(false) {
            enabled.push(kind);
        }
    }
    if enabled.is_empty() {
        return Err(ConfigError::invalid(object.at("challenges")));
    }
    settings.config.challenge_types = enabled;
    Ok(Issuer::Acme(Box::new(settings)))
}

fn validate_directory(value: &str, path: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| ConfigError::invalid(path.into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::invalid(path.into()));
    }
    Ok(())
}
