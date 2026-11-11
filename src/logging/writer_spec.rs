// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
//! Typed writer configuration. Filename/endpoint replacement belongs to bounded
//! blocking preparation, not a request/emit or reactor thread.
use super::config;
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Map, Value};
use std::cell::Cell;
pub(super) enum WriterSpec {
    Stdout,
    Stderr,
    Discard,
    File(FileSpec),
    Net(NetSpec),
}
pub(super) struct FileSpec {
    pub filename: String,
    pub mode: u32,
    pub dir_mode: String,
    pub roll: bool,
    pub size_mb: i64,
    pub interval: i64,
    pub minutes: Vec<i64>,
    pub times: Vec<String>,
    pub compression: String,
    pub local: bool,
    pub keep: i64,
    pub keep_days: i64,
    pub backup_format: String,
}
pub(super) struct NetSpec {
    pub address: super::net_address::Address,
    pub dial_timeout: i64,
    pub soft_start: bool,
}
impl WriterSpec {
    pub(super) fn key(&self) -> String {
        match self {
            Self::Stdout => "std:out".into(),
            Self::Stderr => "std:err".into(),
            Self::Discard => "discard".into(),
            Self::File(spec) => format!("file:{}", spec.filename),
            Self::Net(spec) => spec.address.key(),
        }
    }
    pub(super) fn pinned(&self) -> bool {
        matches!(self, Self::Stdout | Self::Stderr | Self::Discard)
    }
    pub(super) fn parse(value: Option<Value>, limit: usize) -> Result<Self> {
        let Some(value) = value else {
            return Ok(Self::Stderr);
        };
        let (output, m) = super::module_config::inline(value, "output", limit, false)?;
        Ok(match output.as_str() {
            "stdout" => {
                known(&m, &[])?;
                Self::Stdout
            }
            "stderr" => {
                known(&m, &[])?;
                Self::Stderr
            }
            "discard" => {
                known(&m, &[])?;
                Self::Discard
            }
            "file" => Self::File(FileSpec::parse(m)?),
            "net" => Self::Net(NetSpec::parse(m)?),
            _ => bail!("unknown log writer module"),
        })
    }
}
impl FileSpec {
    fn parse(mut m: Map<String, Value>) -> Result<Self> {
        known(
            &m,
            &[
                "filename",
                "mode",
                "dir_mode",
                "roll",
                "roll_size_mb",
                "roll_interval",
                "roll_minutes",
                "roll_at",
                "roll_gzip",
                "roll_compression",
                "roll_local_time",
                "roll_keep",
                "roll_keep_days",
                "backup_time_format",
            ],
        )?;
        let filename = resolve_required(&config::string(m.remove("filename"))?)?;
        let mode = parse_mode(&config::string(m.remove("mode"))?)?;
        let dir_mode = config::string(m.remove("dir_mode"))?;
        let roll = match m.remove("roll") {
            None | Some(Value::Null) => true,
            some => config::boolean(some)?,
        };
        let raw_size = config::integer(m.remove("roll_size_mb"))?;
        let size_mb = if raw_size == 0 { 100 } else { raw_size };
        let interval = config::duration(m.remove("roll_interval"))?;
        let minutes = match m.remove("roll_minutes") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => {
                ensure!(a.len() <= 65536, "log rotation schedule limit exceeded");
                a.into_iter()
                    .map(|v| config::integer(Some(v)))
                    .collect::<Result<_>>()?
            }
            _ => bail!("log rotation minute array required"),
        };
        let times = config::strings(m.remove("roll_at"))?;
        let gzip = match m.remove("roll_gzip") {
            None | Some(Value::Null) => true,
            some => config::boolean(some)?,
        };
        let compression = config::string(m.remove("roll_compression"))?;
        let compression = if compression.is_empty() {
            if gzip { "gzip" } else { "none" }.into()
        } else {
            config::simple_lower(compression.trim())
        };
        if roll {
            ensure!(
                matches!(compression.as_str(), "gzip" | "none" | "zstd"),
                "invalid log rotation compression"
            );
        }
        let local = config::boolean(m.remove("roll_local_time"))?;
        let keep = config::integer(m.remove("roll_keep"))?;
        let keep_days = config::integer(m.remove("roll_keep_days"))?;
        let backup_format = config::string(m.remove("backup_time_format"))?;
        Ok(Self {
            filename,
            mode,
            dir_mode,
            roll,
            size_mb,
            interval,
            minutes,
            times,
            compression,
            local,
            keep: if keep == 0 { 10 } else { keep },
            keep_days: if keep_days == 0 { 90 } else { keep_days },
            backup_format,
        })
    }
}
impl NetSpec {
    fn parse(mut m: Map<String, Value>) -> Result<Self> {
        known(&m, &["address", "dial_timeout", "soft_start"])?;
        let address = super::net_address::Address::parse(&resolve_required(&config::string(
            m.remove("address"),
        )?)?)?;
        let dial_timeout = config::duration(m.remove("dial_timeout"))?;
        ensure!(dial_timeout >= 0, "negative log network dial timeout");
        let soft_start = config::boolean(m.remove("soft_start"))?;
        Ok(Self {
            address,
            dial_timeout,
            soft_start,
        })
    }
}
fn known(m: &Map<String, Value>, fields: &[&str]) -> Result<()> {
    crate::http_config::helpers::deny_unknown(m, fields, "/logging/writer")
}
pub(super) fn parse_mode(input: &str) -> Result<u32> {
    // strconv.ParseUint(base=8,bits=32) rejects signs and underscores. Width
    // four zero-padding means an empty JSON string is the valid zero mode.
    ensure!(
        !input.starts_with('+') && !input.starts_with('-'),
        "invalid log file mode"
    );
    if input.is_empty() {
        return Ok(0);
    }
    u32::from_str_radix(input, 8).map_err(|_| anyhow!("invalid log file mode"))
}
/// Translate Go os.FileMode, whose high special-mode flags are not POSIX octal
/// flags. For instance numeric 04000 is not Go ModeSetuid and contributes no
/// permissions; directly handing 04000 to OpenOptions::mode would change it.
pub(super) fn unix_mode(mode: u32) -> u32 {
    (mode & 0o777)
        | if mode & (1 << 23) != 0 { 0o4000 } else { 0 }
        | if mode & (1 << 22) != 0 { 0o2000 } else { 0 }
        | if mode & (1 << 20) != 0 { 0o1000 } else { 0 }
}
pub(super) fn resolve_required(input: &str) -> Result<String> {
    let failed = Cell::new(false);
    let count = Cell::new(0usize);
    let result = crate::http_config::helpers::replace(input, true, |name| {
        count.set(count.get().saturating_add(1));
        if count.get() > 4096 {
            failed.set(true);
            return None;
        }
        let value = if let Some(file) = crate::http_config::helpers::prepare_file_lookup(name) {
            match file {
                Ok(v) => Some(v),
                Err(_) => {
                    failed.set(true);
                    None
                }
            }
        } else {
            crate::http_config::helpers::global_lookup(name)
        };
        if value.as_ref().is_none_or(String::is_empty) {
            failed.set(true);
        }
        value
    })?;
    ensure!(
        !failed.get(),
        "unknown, empty or unsupported log placeholder"
    );
    Ok(result)
}
