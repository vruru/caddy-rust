// Copyright 2015 Matthew Holt and The Caddy Authors
// SPDX-License-Identifier: Apache-2.0
//! Native structured logging levels; numeric ordering follows zapcore.Level.
use anyhow::{Result, bail};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(i8)]
pub enum Level {
    Debug = -1,
    Info = 0,
    Warn = 1,
    Error = 2,
    DPanic = 3,
    Panic = 4,
    Fatal = 5,
}
impl Level {
    /// Caddy's configuration accepts these six levels (not zap's DPanic).
    /// Resolve global placeholders before calling this parser.
    pub fn parse_config(input: &str) -> Result<Self> {
        // Go strings.ToLower uses Unicode simple lowercasing. U+0130 is the
        // only non-ASCII character whose lowercase is an ASCII letter used
        // by these level names; Rust's full lowercase would append a dot.
        if input.len() > 6 {
            bail!("unrecognized logging level");
        }
        let mut bytes = [0u8; 6];
        let mut count = 0;
        for c in input.chars() {
            let c = if c == '\u{0130}' { 'i' } else { c };
            if !c.is_ascii() {
                bail!("unrecognized logging level");
            }
            bytes[count] = (c as u8).to_ascii_lowercase();
            count += 1;
        }
        let lower = std::str::from_utf8(&bytes[..count]).expect("only ASCII bytes were inserted");
        Ok(match lower {
            "debug" => Self::Debug,
            "" | "info" => Self::Info,
            "warn" => Self::Warn,
            "error" => Self::Error,
            "panic" => Self::Panic,
            "fatal" => Self::Fatal,
            _ => bail!("unrecognized logging level"),
        })
    }
    pub const fn lower(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::DPanic => "dpanic",
            Self::Panic => "panic",
            Self::Fatal => "fatal",
        }
    }
    pub const fn upper(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::DPanic => "DPANIC",
            Self::Panic => "PANIC",
            Self::Fatal => "FATAL",
        }
    }
}
