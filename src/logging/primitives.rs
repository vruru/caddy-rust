// Copyright 2015 Matthew Holt and The Caddy Authors. Apache-2.0.
// Zap primitive encodings derived from Uber zap v1.28.0 (MIT).
use super::{
    bounded::Buffer, config, float, level::Level, time_components, time_layout::Layout,
    types::Timestamp,
};
use anyhow::{Result, anyhow};
use serde_json::{Map, Value};
pub(super) type LocalZone = fn(i64) -> Option<(i32, String)>;
pub(super) struct Common {
    pub message_key: String,
    pub level_key: String,
    pub time_key: String,
    pub name_key: String,
    pub caller_key: String,
    pub stacktrace_key: String,
    pub line_ending: String,
    pub time: TimeEncoding,
    pub duration: DurationEncoding,
    pub level: LevelEncoding,
}
pub(super) enum TimeEncoding {
    Seconds,
    Millis,
    Nanos,
    Layout { layout: Layout, local: bool },
}
#[derive(Clone, Copy)]
pub(super) enum DurationEncoding {
    Seconds,
    Millis,
    Nanos,
    String,
}
#[derive(Clone, Copy)]
pub(super) enum LevelEncoding {
    Lower,
    Upper,
    Color,
    Omit,
}
impl Common {
    pub(super) fn parse(fields: &mut Map<String, Value>, console: bool) -> Result<Self> {
        let mut key = |name: &str, default: &str| -> Result<String> {
            match fields.remove(name) {
                None | Some(Value::Null) => Ok(default.into()),
                some => config::string(some),
            }
        };
        let message_key = key("message_key", "msg")?;
        let level_key = key("level_key", "level")?;
        let time_key = key("time_key", "ts")?;
        let name_key = key("name_key", "logger")?;
        let caller_key = key("caller_key", "caller")?;
        let stacktrace_key = key("stacktrace_key", "stacktrace")?;
        let mut line_ending = key("line_ending", "\n")?;
        if line_ending.is_empty() {
            line_ending.push('\n');
        }
        let mut time = config::string(fields.remove("time_format"))?;
        if console && time.is_empty() {
            time = "wall_milli".into();
        }
        let local = config::boolean(fields.remove("time_local"))?;
        let time = TimeEncoding::parse(&time, local)?;
        let duration = match config::string(fields.remove("duration_format"))?.as_str() {
            "ns" | "nano" | "nanos" => DurationEncoding::Nanos,
            "ms" | "milli" | "millis" => DurationEncoding::Millis,
            "string" => DurationEncoding::String,
            _ => DurationEncoding::Seconds,
        };
        let mut level = config::string(fields.remove("level_format"))?;
        if console && level.is_empty() {
            level = "color".into();
        }
        let level = match level.as_str() {
            "" | "lower" => LevelEncoding::Lower,
            "upper" => LevelEncoding::Upper,
            "color" => LevelEncoding::Color,
            _ => LevelEncoding::Omit,
        };
        Ok(Self {
            message_key,
            level_key,
            time_key,
            name_key,
            caller_key,
            stacktrace_key,
            line_ending,
            time,
            duration,
            level,
        })
    }
}
impl TimeEncoding {
    pub(super) fn parse(format: &str, local: bool) -> Result<Self> {
        Ok(match format {
            "" | "unix_seconds_float" => Self::Seconds,
            "unix_milli_float" => Self::Millis,
            "unix_nano" => Self::Nanos,
            "iso8601" => Self::Layout {
                layout: Layout::compile("2006-01-02T15:04:05.000Z0700")?,
                local: true,
            },
            other => {
                let layout = match other {
                    "rfc3339" => "2006-01-02T15:04:05Z07:00",
                    "rfc3339_nano" => "2006-01-02T15:04:05.999999999Z07:00",
                    "wall" => "2006/01/02 15:04:05",
                    "wall_milli" => "2006/01/02 15:04:05.000",
                    "wall_nano" => "2006/01/02 15:04:05.000000000",
                    "common_log" => "02/Jan/2006:15:04:05 -0700",
                    _ => other,
                };
                Self::Layout {
                    layout: Layout::compile(layout)?,
                    local,
                }
            }
        })
    }
    pub(super) fn scalar(
        &self,
        time: Timestamp,
        max_bytes: usize,
        local_zone: LocalZone,
    ) -> Result<Scalar> {
        let nano = time_components::unix_nano(time);
        Ok(match self {
            Self::Seconds => Scalar::Float(nano as f64 / 1_000_000_000.0),
            Self::Millis => Scalar::Float(nano as f64 / 1_000_000.0),
            Self::Nanos => Scalar::Integer(nano),
            Self::Layout { layout, local } => {
                let (offset, zone) = if *local {
                    local_zone(time.seconds)
                        .ok_or_else(|| anyhow!("log local timezone unavailable"))?
                } else {
                    (0, "UTC".into())
                };
                Scalar::String(layout.format(&time_components::at(time, offset, zone)?, max_bytes)?)
            }
        })
    }
}
pub(super) enum Scalar {
    Integer(i64),
    Float(f64),
    String(String),
}
impl Scalar {
    pub(super) fn display(&self) -> Result<String> {
        match self {
            Self::Integer(n) => Ok(n.to_string()),
            Self::Float(n) => float::general_f64(*n),
            Self::String(s) => Ok(s.clone()),
        }
    }
    pub(super) fn json(&self, output: &mut Buffer) -> Result<()> {
        match self {
            Self::Integer(n) => output.bytes(n.to_string().as_bytes()),
            Self::Float(n) => output.bytes(float::f64_text(*n)?.as_bytes()),
            Self::String(s) => output.quoted(s.as_bytes()),
        }
    }
}
impl DurationEncoding {
    pub(super) fn scalar(self, nano: i64) -> Scalar {
        match self {
            Self::Seconds => Scalar::Float(nano as f64 / 1_000_000_000.0),
            Self::Millis => Scalar::Integer(nano / 1_000_000),
            Self::Nanos => Scalar::Integer(nano),
            Self::String => Scalar::String(duration_string(nano)),
        }
    }
}
impl LevelEncoding {
    pub(super) fn text(self, level: Level) -> Option<String> {
        Some(match self {
            Self::Omit => return None,
            Self::Lower => level.lower().into(),
            Self::Upper => level.upper().into(),
            Self::Color => {
                let color = match level {
                    Level::Debug => 35,
                    Level::Info => 34,
                    Level::Warn => 33,
                    _ => 31,
                };
                format!("\x1b[{color}m{}\x1b[0m", level.upper())
            }
        })
    }
}
/// Go time.Duration.String over the complete signed-nanosecond domain.
pub(super) fn duration_string(nano: i64) -> String {
    if nano == 0 {
        return "0s".into();
    }
    let negative = nano < 0;
    let value = nano.unsigned_abs();
    let mut result = if negative { "-" } else { "" }.to_owned();
    if value < 1_000_000_000 {
        let (scale, unit, width) = if value < 1000 {
            (1, "ns", 0)
        } else if value < 1_000_000 {
            (1000, "µs", 3)
        } else {
            (1_000_000, "ms", 6)
        };
        result.push_str(&(value / scale).to_string());
        fraction(&mut result, value % scale, width);
        result.push_str(unit);
        return result;
    }
    let seconds = value / 1_000_000_000;
    let hours = seconds / 3600;
    let minutes = (seconds / 60) % 60;
    if hours > 0 {
        result.push_str(&hours.to_string());
        result.push('h');
    }
    if hours > 0 || minutes > 0 {
        result.push_str(&minutes.to_string());
        result.push('m');
    }
    result.push_str(&(seconds % 60).to_string());
    fraction(&mut result, value % 1_000_000_000, 9);
    result.push('s');
    result
}
fn fraction(output: &mut String, value: u64, width: usize) {
    if value == 0 {
        return;
    }
    let mut digits = format!("{value:0width$}");
    while digits.ends_with('0') {
        digits.pop();
    }
    output.push('.');
    output.push_str(&digits);
}
