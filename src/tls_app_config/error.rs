use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigErrorKind {
    UnknownField,
    InvalidValue,
    UnsupportedFeature,
}

/// Diagnostics contain a field pointer and a static capability identifier,
/// never the configured value, PEM, account key or external-account secret.
#[derive(Clone, Debug)]
pub struct ConfigError {
    pub kind: ConfigErrorKind,
    pub path: String,
    pub feature: Option<&'static str>,
}

impl ConfigError {
    pub(super) fn unknown(path: String) -> Self {
        Self {
            kind: ConfigErrorKind::UnknownField,
            path,
            feature: None,
        }
    }
    pub(super) fn invalid(path: String) -> Self {
        Self {
            kind: ConfigErrorKind::InvalidValue,
            path,
            feature: None,
        }
    }
    pub(super) fn unsupported(path: String, feature: &'static str) -> Self {
        Self {
            kind: ConfigErrorKind::UnsupportedFeature,
            path,
            feature: Some(feature),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self.kind {
            ConfigErrorKind::UnknownField => "unknown certificate configuration field",
            ConfigErrorKind::InvalidValue => "invalid certificate configuration value",
            ConfigErrorKind::UnsupportedFeature => "certificate capability is not implemented",
        };
        write!(f, "{category} at {}", self.path)?;
        if let Some(feature) = self.feature {
            write!(f, " ({feature})")?;
        }
        Ok(())
    }
}
impl std::error::Error for ConfigError {}

pub(super) fn pointer(parent: &str, field: &str) -> String {
    format!("{parent}/{}", field.replace('~', "~0").replace('/', "~1"))
}
