//! Settings after decoding Caddy's signed duration, signed integer and module.
use anyhow::{Result, ensure};
use std::{path::PathBuf, time::Duration};

pub(super) const MAX_KEYS: usize = 64;
const DEFAULT_ROTATION: Duration = Duration::from_secs(12 * 60 * 60);
const DEFAULT_KEYS: usize = 4;
const MIN_ROTATION: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Provider {
    Standard,
    Distributed { storage: Option<PathBuf> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TicketMode {
    /// Omitted Caddy service, or explicit no-rotation: the provider is not run.
    RuntimeDefault,
    Disabled,
    Rotating(Settings),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    provider: Provider,
    rotation_interval: Duration,
    max_keys: usize,
}
impl Settings {
    pub fn explicit(
        provider: Provider,
        rotation_nanos: i64,
        max_keys: Option<i64>,
        disable_rotation: bool,
        disabled: bool,
    ) -> Result<TicketMode> {
        if disabled {
            return Ok(TicketMode::Disabled);
        }
        if disable_rotation {
            return Ok(TicketMode::RuntimeDefault);
        }
        ensure!(
            rotation_nanos >= 0,
            "invalid session ticket rotation interval"
        );
        let rotation_interval = if rotation_nanos == 0 {
            DEFAULT_ROTATION
        } else {
            Duration::from_nanos(rotation_nanos as u64)
        };
        ensure!(
            rotation_interval >= MIN_ROTATION,
            "session ticket rotation interval is too short"
        );
        let max_keys = max_keys
            .filter(|count| *count > 0)
            .unwrap_or(DEFAULT_KEYS as i64);
        ensure!(
            max_keys <= MAX_KEYS as i64,
            "session ticket key limit exceeded"
        );
        Ok(TicketMode::Rotating(Self {
            provider,
            rotation_interval,
            max_keys: max_keys as usize,
        }))
    }
    pub fn provider(&self) -> &Provider {
        &self.provider
    }
    pub fn rotation_interval(&self) -> Duration {
        self.rotation_interval
    }
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }
}
