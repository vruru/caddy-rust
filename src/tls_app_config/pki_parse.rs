use super::{
    decode::{Object, Result, discriminator},
    error::ConfigError,
    schema::ObjectKind,
};
use crate::local_pki::{CaConfig, KeyPairFiles};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

pub(super) fn parse_ca(id: &str, value: &Value, path: &str) -> Result<(CaConfig, Option<PathBuf>)> {
    let object = Object::new(Some(value), ObjectKind::Ca, path)?;
    let mut config = CaConfig {
        id: id.into(),
        ..CaConfig::default()
    };
    for (field, target) in [
        ("name", &mut config.name),
        ("root_common_name", &mut config.root_common_name),
        (
            "intermediate_common_name",
            &mut config.intermediate_common_name,
        ),
    ] {
        let value = object.string(field)?;
        if !value.is_empty() {
            *target = value.into();
        }
    }
    for (field, target) in [
        ("intermediate_lifetime", &mut config.intermediate_lifetime),
        ("maintenance_interval", &mut config.maintenance_interval),
    ] {
        let value = object.duration_ns(field)?;
        if value < 0 {
            return Err(ConfigError::invalid(object.at(field)));
        }
        if value > 0 {
            *target = Duration::from_nanos(value as u64);
        }
    }
    if let Some(ratio) = object.number("renewal_window_ratio")? {
        config.renewal_window_ratio = ratio;
    }
    if let Some(install) = object.boolean("install_trust")? {
        config.install_trust = install;
    }
    config.root = parse_pair(object.value("root"), &object.at("root"))?;
    config.intermediate = parse_pair(object.value("intermediate"), &object.at("intermediate"))?;
    Ok((
        config,
        parse_storage(object.value("storage"), &object.at("storage"))?,
    ))
}

fn parse_pair(value: Option<&Value>, path: &str) -> Result<Option<KeyPairFiles>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = Object::new(Some(value), ObjectKind::CaPair, path)?;
    let certificate = object.string("certificate")?;
    if certificate.is_empty() {
        return Err(ConfigError::invalid(object.at("certificate")));
    }
    let private_key = object.string("private_key")?;
    let format = object.string("format")?;
    if !matches!(format, "" | "pem_file") {
        return Err(ConfigError::unsupported(
            object.at("format"),
            "local_pki_keypair_format",
        ));
    }
    Ok(Some(KeyPairFiles {
        certificate: certificate.into(),
        private_key: (!private_key.is_empty()).then(|| private_key.into()),
        format: format.into(),
    }))
}

pub(super) fn parse_storage(value: Option<&Value>, path: &str) -> Result<Option<PathBuf>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let module = discriminator(value, "module", path)?;
    if module != "file_system" {
        return Err(ConfigError::unsupported(
            super::error::pointer(path, "module"),
            "storage_module",
        ));
    }
    let object = Object::new(Some(value), ObjectKind::FileSystem, path)?;
    let root = object.string("root")?;
    // An explicitly empty FileStorage.Path is relative to the captured cwd;
    // only an absent module inherits the enclosing/default storage.
    Ok(Some(root.into()))
}
