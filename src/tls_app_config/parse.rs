use super::{
    CertificateViews,
    decode::{Object, Result, discriminator},
    error::{ConfigError, pointer},
    issuer_parse,
    model::{
        Authority, CertificatePlan, Identity, Issuer, ManualSource, PermissionSetting, Policy,
    },
    pki_parse,
    schema::ObjectKind,
};
use crate::{
    acme_wire::KeyType,
    stek::{Provider as TicketProvider, Settings as TicketSettings, TicketMode},
};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
use zeroize::Zeroizing;

pub(super) fn parse(views: CertificateViews<'_>) -> Result<CertificatePlan> {
    let mut plan = CertificatePlan {
        storage: pki_parse::parse_storage(views.storage, "/storage")?,
        ..CertificatePlan::default()
    };
    let tls = Object::new(views.tls, ObjectKind::Tls, "/apps/tls")?;
    plan.disable_ocsp = tls.boolean("disable_ocsp_stapling")?.unwrap_or(false);
    plan.disable_storage_check = tls.boolean("disable_storage_check")?.unwrap_or(false);
    plan.disable_storage_clean = tls.boolean("disable_storage_clean")?.unwrap_or(false);
    for (field, feature) in [
        ("encrypted_client_hello", "encrypted_client_hello"),
        ("dns", "tls_dns_provider"),
    ] {
        if tls.value(field).is_some() {
            return Err(ConfigError::unsupported(tls.at(field), feature));
        }
    }
    if !tls.strings("resolvers")?.is_empty() {
        return Err(ConfigError::unsupported(
            tls.at("resolvers"),
            "custom_dns_resolvers",
        ));
    }
    if let Some(tickets) = tls.value("session_tickets") {
        plan.ticket_mode = parse_ticket_mode(tickets, &tls.at("session_tickets"))?;
    }
    let cache = Object::new(tls.value("cache"), ObjectKind::Cache, &tls.at("cache"))?;
    if let Some(value) = cache.integer("capacity")? {
        if value < 0 {
            return Err(ConfigError::invalid(cache.at("capacity")));
        }
        if value > 0 {
            plan.cache_capacity =
                usize::try_from(value).map_err(|_| ConfigError::invalid(cache.at("capacity")))?;
            if plan.cache_capacity > crate::tls_resolver::MAX_CERTIFICATES {
                return Err(ConfigError::invalid(cache.at("capacity")));
            }
        }
    }
    let certificates = Object::new(
        tls.value("certificates"),
        ObjectKind::Certificates,
        &tls.at("certificates"),
    )?;
    plan.automate = certificates
        .strings("automate")?
        .into_iter()
        .map(Into::into)
        .collect();
    for field in ["load_files", "load_pem"] {
        for (index, value) in certificates.array(field)?.iter().enumerate() {
            let path = pointer(&certificates.at(field), &index.to_string());
            let kind = if field == "load_files" {
                ObjectKind::FilePair
            } else {
                ObjectKind::PemPair
            };
            let pair = Object::new(Some(value), kind, &path)?;
            let certificate = pair.string("certificate")?;
            let key = pair.string("key")?;
            let tags = pair.strings("tags")?.into_iter().map(Into::into).collect();
            if certificate.is_empty() || key.is_empty() {
                return Err(ConfigError::invalid(path));
            }
            if field == "load_files" {
                if !matches!(pair.string("format")?, "" | "pem") {
                    return Err(ConfigError::invalid(pair.at("format")));
                }
                plan.manual.push(ManualSource::Files {
                    certificate: certificate.into(),
                    key: key.into(),
                    tags,
                });
            } else {
                plan.manual.push(ManualSource::Pem {
                    certificate: certificate.as_bytes().to_vec(),
                    key: Zeroizing::new(key.as_bytes().to_vec()),
                    tags,
                });
            }
        }
    }
    plan.manual.extend(
        certificates
            .strings("load_folders")?
            .into_iter()
            .map(|path| ManualSource::Folder(path.into())),
    );
    if let Some(storage) = certificates.value("load_storage") {
        let storage = Object::new(
            Some(storage),
            ObjectKind::StorageLoader,
            &certificates.at("load_storage"),
        )?;
        for (index, value) in storage.array("pairs")?.iter().enumerate() {
            let path = pointer(&storage.at("pairs"), &index.to_string());
            let pair = Object::new(Some(value), ObjectKind::FilePair, &path)?;
            let certificate = pair.string("certificate")?;
            let key = pair.string("key")?;
            if certificate.is_empty() || key.is_empty() {
                return Err(ConfigError::invalid(path));
            }
            if !matches!(pair.string("format")?, "" | "pem") {
                return Err(ConfigError::invalid(pair.at("format")));
            }
            let tags = pair.strings("tags")?.into_iter().map(Into::into).collect();
            plan.manual.push(ManualSource::Storage {
                certificate: certificate.into(),
                key: key.into(),
                tags,
            });
        }
    }
    let automation = Object::new(
        tls.value("automation"),
        ObjectKind::Automation,
        &tls.at("automation"),
    )?;
    for (field, target) in [
        ("ocsp_interval", &mut plan.ocsp_interval),
        ("renew_interval", &mut plan.renew_interval),
        ("storage_clean_interval", &mut plan.clean_interval),
    ] {
        let value = automation.duration_ns(field)?;
        if value < 0 {
            return Err(ConfigError::invalid(automation.at(field)));
        }
        if value > 0 {
            *target = Duration::from_nanos(value as u64);
        }
    }
    if let Some(on_demand) = automation.value("on_demand") {
        let on_demand = Object::new(
            Some(on_demand),
            ObjectKind::OnDemand,
            &automation.at("on_demand"),
        )?;
        let ask = on_demand.string("ask")?;
        if let Some(permission) = on_demand.value("permission") {
            if !ask.is_empty() {
                return Err(ConfigError::invalid(on_demand.at("permission")));
            }
            if discriminator(permission, "module", &on_demand.at("permission"))? != "http" {
                return Err(ConfigError::unsupported(
                    on_demand.at("permission"),
                    "on_demand_permission_module",
                ));
            }
            let permission = Object::new(
                Some(permission),
                ObjectKind::PermissionHttp,
                &on_demand.at("permission"),
            )?;
            plan.permission = Some(PermissionSetting {
                endpoint: permission.string("endpoint")?.into(),
                legacy: false,
            });
        } else if !ask.is_empty() {
            plan.permission = Some(PermissionSetting {
                endpoint: ask.into(),
                legacy: true,
            });
        }
    }
    for (index, value) in automation.array("policies")?.iter().enumerate() {
        let path = pointer(&automation.at("policies"), &index.to_string());
        plan.policies.push(policy(value, &path)?);
    }
    let pki = Object::new(views.pki, ObjectKind::Pki, "/apps/pki")?;
    if let Some(authorities) = pki.map("certificate_authorities")? {
        for (id, value) in authorities {
            let (config, storage) =
                pki_parse::parse_ca(id, value, &pointer(&pki.at("certificate_authorities"), id))?;
            plan.authorities
                .insert(id.clone(), Authority { config, storage });
        }
    }
    if views.pki.is_some() && plan.authorities.is_empty() {
        plan.authorities.insert(
            "local".into(),
            Authority {
                config: crate::local_pki::CaConfig::default(),
                storage: None,
            },
        );
    }
    let mut ca_paths = std::collections::HashSet::new();
    for id in plan.authorities.keys() {
        let safe = crate::certstore::safe(id);
        if !ca_paths.insert(safe) {
            return Err(ConfigError::invalid(pointer(
                &pki.at("certificate_authorities"),
                id,
            )));
        }
    }
    if let Some(identity) = views.identity.filter(|v| !v.is_null()) {
        let object = Object::new(Some(identity), ObjectKind::Identity, "/admin/identity")?;
        let identifiers: Vec<String> = object
            .strings("identifiers")?
            .into_iter()
            .map(Into::into)
            .collect();
        if identifiers.len() > 4096 {
            return Err(ConfigError::invalid(object.at("identifiers")));
        }
        let issuers = parse_issuers(&object)?;
        plan.identity = Some(Identity {
            identifiers,
            issuers,
        });
    }
    if plan.policies.len() > 1024
        || plan.authorities.len() > 256
        || plan.manual.len() > crate::tls_resolver::MAX_CERTIFICATES
        || plan.automate.len() > 65536
    {
        return Err(ConfigError::invalid("/apps/tls".into()));
    }
    for policy in &plan.policies {
        if policy.on_demand
            && policy.managers.is_empty()
            && plan.permission.is_none()
            && (policy.subjects.is_empty() || policy.subjects.iter().any(|name| name.contains('*')))
            && !(!policy.issuers.is_empty()
                && policy
                    .issuers
                    .iter()
                    .all(|issuer| matches!(issuer, Issuer::Internal { .. })))
        {
            return Err(ConfigError::invalid(
                "/apps/tls/automation/on_demand".into(),
            ));
        }
    }
    Ok(plan)
}

fn parse_issuers(object: &Object<'_>) -> Result<Vec<super::model::Issuer>> {
    let issuers = object.array("issuers")?;
    if issuers.len() > 16 {
        return Err(ConfigError::invalid(object.at("issuers")));
    }
    issuers
        .iter()
        .enumerate()
        .map(|(index, value)| {
            issuer_parse::parse(value, &pointer(&object.at("issuers"), &index.to_string()))
        })
        .collect()
}

fn policy(value: &Value, path: &str) -> Result<Policy> {
    let object = Object::new(Some(value), ObjectKind::Policy, path)?;
    let key_type = match object.string("key_type")? {
        "" | "p256" => KeyType::P256,
        "p384" => KeyType::P384,
        "rsa2048" => KeyType::Rsa2048,
        "rsa4096" => KeyType::Rsa4096,
        "ed25519" => KeyType::Ed25519,
        _ => return Err(ConfigError::invalid(object.at("key_type"))),
    };
    let mut policy = Policy {
        subjects: object
            .strings("subjects")?
            .into_iter()
            .map(Into::into)
            .collect(),
        issuers: parse_issuers(&object)?,
        storage: pki_parse::parse_storage(object.value("storage"), &object.at("storage"))?,
        key_type,
        on_demand: object.boolean("on_demand")?.unwrap_or(false),
        disable_ocsp: object.boolean("disable_ocsp_stapling")?.unwrap_or(false),
        ..Policy::default()
    };
    if let Some(value) = object.number("renewal_window_ratio")?
        && value > 0.0
        && value < 1.0
    {
        policy.renewal_ratio = value;
    }
    policy.must_staple=object.boolean("must_staple")?.unwrap_or(false);
    policy.reuse_private_keys=object.boolean("reuse_private_keys")?.unwrap_or(false);
    let managers = object.array("get_certificate")?;
    if managers.len() > 16 { return Err(ConfigError::invalid(object.at("get_certificate"))); }
    for (index, manager) in managers.iter().enumerate() {
        let path = pointer(&object.at("get_certificate"), &index.to_string());
        let parsed = match discriminator(manager, "via", &path)? {
            "http" => {
                let object = Object::new(Some(manager), ObjectKind::GetCertHttp, &path)?;
                let url = object.string("url")?;
                if url.is_empty() || url.len() > 1024 * 1024 {
                    return Err(ConfigError::invalid(object.at("url")));
                }
                super::external::Manager::Http(url.into())
            }
            "tailscale" => {
                Object::new(Some(manager), ObjectKind::Tailscale, &path)?;
                super::external::Manager::Tailscale
            }
            _ => return Err(ConfigError::unsupported(path, "external_certificate_manager_module")),
        };
        policy.managers.push(parsed);
    }
    // Caddy provisions a CertMagic OnDemandConfig for explicit managers even
    // when on_demand is false. They are queried at handshake time, never issued
    // eagerly while this generation is being prepared.
    policy.on_demand |= !policy.managers.is_empty();
    if let Some(overrides) = object.map("ocsp_overrides")? {
        let mut values = BTreeMap::new();
        for (key, value) in overrides {
            let value = match value {
                Value::Null => "",
                Value::String(value) => value,
                _ => {
                    return Err(ConfigError::invalid(pointer(
                        &object.at("ocsp_overrides"),
                        key,
                    )));
                }
            };
            values.insert(key.clone(), value.into());
        }
        policy.ocsp_overrides = values;
    }
    Ok(policy)
}

fn parse_ticket_mode(value: &Value, path: &str) -> Result<TicketMode> {
    let tickets = Object::new(Some(value), ObjectKind::Tickets, path)?;
    let provider = if let Some(source) = tickets.raw_value("key_source") {
        let path = tickets.at("key_source");
        match discriminator(source, "provider", &path)? {
            "standard" => {
                Object::new(Some(source), ObjectKind::StekStandard, &path)?;
                TicketProvider::Standard
            }
            "distributed" => {
                let source = Object::new(Some(source), ObjectKind::StekDistributed, &path)?;
                let storage = source.raw_value("storage");
                if storage.is_some_and(Value::is_null) {
                    return Err(ConfigError::invalid(source.at("storage")));
                }
                TicketProvider::Distributed {
                    storage: pki_parse::parse_storage(storage, &source.at("storage"))?,
                }
            }
            _ => return Err(ConfigError::unsupported(path, "session_ticket_key_source")),
        }
    } else {
        TicketProvider::Standard
    };
    TicketSettings::explicit(
        provider,
        tickets.duration_ns("rotation_interval")?,
        tickets.integer("max_keys")?,
        tickets.boolean("disable_rotation")?.unwrap_or(false),
        tickets.boolean("disabled")?.unwrap_or(false),
    )
    .map_err(|_| ConfigError::invalid(path.into()))
}
