use anyhow::{anyhow, ensure, Result};
use serde_json::{Map, Value};
use std::ops::{BitOr, BitOrAssign};

use super::helpers::{boolean, signed_duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub(crate) struct Keepalive {
    pub interval: i64,
    pub idle: i64,
    pub count: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub(crate) struct ProtocolSet {
    pub h1: bool,
    pub h2: bool,
    pub h2c: bool,
    pub h3: bool,
}

impl ProtocolSet {
    pub(crate) const fn default_global() -> Self {
        Self {
            h1: true,
            h2: true,
            h2c: false,
            h3: true,
        }
    }

    pub(crate) fn names(self) -> Vec<String> {
        let mut v = Vec::new();
        if self.h1 {
            v.push("h1".to_string());
        }
        if self.h2 {
            v.push("h2".to_string());
        }
        if self.h2c {
            v.push("h2c".to_string());
        }
        if self.h3 {
            v.push("h3".to_string());
        }
        v
    }

    pub(crate) fn bits(self) -> u8 {
        (self.h1 as u8)
            | ((self.h2 as u8) << 1)
            | ((self.h2c as u8) << 2)
            | ((self.h3 as u8) << 3)
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self {
            h1: self.h1 | other.h1,
            h2: self.h2 | other.h2,
            h2c: self.h2c | other.h2c,
            h3: self.h3 | other.h3,
        }
    }

    pub(crate) fn contains(self, name: &str) -> bool {
        match name {
            "h1" => self.h1,
            "h2" => self.h2,
            "h2c" => self.h2c,
            "h3" => self.h3,
            _ => false,
        }
    }
}

impl BitOr for ProtocolSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl BitOrAssign for ProtocolSet {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

fn parse_protocol_field(m: &Map<String, Value>, key: &str, path: &str) -> Result<Option<ProtocolSet>> {
    let v = match m.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };

    let arr = match v {
        Value::Array(arr) => arr,
        _ => return Err(anyhow!("{}: {} must be array", path, key)),
    };

    let mut set = ProtocolSet::default();
    for item in arr {
        let s = match item {
            Value::String(s) => s,
            _ => return Err(anyhow!("{}: {} entries must be strings", path, key)),
        };
        match s.as_str() {
            "h1" => set.h1 = true,
            "h2" => set.h2 = true,
            "h2c" => set.h2c = true,
            "h3" => set.h3 = true,
            _ => return Err(anyhow!("{}: {} unknown protocol: {}", path, key, s)),
        }
    }
    Ok(Some(set))
}

pub(crate) fn protocol_fields(
    m: &Map<String, Value>,
    listen_count: usize,
    path: &str,
) -> Result<(ProtocolSet, Vec<ProtocolSet>)> {
    let global_set = match parse_protocol_field(m, "protocols", path)? {
        Some(s) if s.bits()!=0 => s,
        _ => ProtocolSet::default_global(),
    };

    let listen_val = match m.get("listen_protocols") {
        None | Some(Value::Null) => {ensure!(listen_count<=1024,"listener count exceeds limit");let mut out=Vec::new();out.try_reserve_exact(listen_count)?;out.resize(listen_count,global_set);return Ok((global_set,out));},
        Some(v) => v,
    };

    let listen_arr = match listen_val {
        Value::Array(arr) => arr,
        _ => return Err(anyhow!("{}: listen_protocols must be array", path)),
    };

    ensure!(
        listen_arr.len() == listen_count,
        "{}: listen_protocols length {} != listen count {}",
        path,
        listen_arr.len(),
        listen_count
    );

    ensure!(listen_count<=1024,"listener count exceeds limit");
    let mut result = Vec::new();
    result.try_reserve_exact(listen_count)?;


    for item in listen_arr.iter() {
        let mut set = match item {
            Value::Null => global_set,
            Value::Array(arr) => {
                let mut s = ProtocolSet::default();
                for proto_val in arr.iter() {
                    let p = match proto_val {
                        Value::String(p) => p,
                        _ => return Err(anyhow!("{}: listen_protocols entries must be strings", path)),
                    };
                    match p.as_str() {
                        "" => s |= global_set,
                        "h1" => s.h1 = true,
                        "h2" => s.h2 = true,
                        "h2c" => s.h2c = true,
                        "h3" => s.h3 = true,
                        _ => return Err(anyhow!("{}: listen_protocols unknown protocol: {}", path, p)),
                    }
                }
                s
            }
            _ => return Err(anyhow!("{}: listen_protocols entries must be null or array", path)),
        };

        if matches!(item,Value::Array(values)if values.is_empty()){set=global_set;}
        result.push(set);
    }

    Ok((global_set, result))
}

#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub keepalive: Keepalive,
    pub max_header_bytes: usize,
    pub enable_full_duplex: bool,
    pub trusted_proxies_unix: bool,
    pub allow_0rtt: bool,
}

pub(crate) fn parse(m: &Map<String, Value>, path: &str) -> Result<Options> {
    let interval = match m.get("keepalive_interval") {
        Some(Value::Null) | None => 0,
        Some(v) => signed_duration(v, "keepalive_interval")?,
    };
    let idle = match m.get("keepalive_idle") {
        Some(Value::Null) | None => 0,
        Some(v) => signed_duration(v, "keepalive_idle")?,
    };
    let count = match m.get("keepalive_count") {
        Some(Value::Null) | None => 0,
        Some(v) => {
            let n = v
                .as_number().and_then(serde_json::Number::as_go_i64)
                .ok_or_else(|| anyhow!("{}: keepalive_count must be integer", path))?;
            n
        }
    };

    let keepalive = Keepalive {
        interval,
        idle,
        count,
    };

    let mhb_val = match m.get("max_header_bytes") {
        Some(Value::Null) | None => 0,
        Some(v) => {
            let n = v
                .as_number().and_then(serde_json::Number::as_go_i64)
                .ok_or_else(|| anyhow!("{}: max_header_bytes must be integer", path))?;
            n
        }
    };

    let max_header_bytes = if mhb_val <= 0 {
        16 * 1024
    } else {
        usize::try_from(mhb_val).map_err(|_| anyhow!("{}: max_header_bytes out of range", path))?
    };

    let enable_full_duplex = boolean(m.get("enable_full_duplex").filter(|v|!v.is_null()), false, "enable_full_duplex")?;
    let trusted_proxies_unix =
        boolean(m.get("trusted_proxies_unix").filter(|v|!v.is_null()), false, "trusted_proxies_unix")?;

    // allow_0rtt defaults to true
    let allow_0rtt = match m.get("allow_0rtt") {
        Some(Value::Null) | None => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(anyhow!("{}: allow_0rtt must be boolean", path)),
    };

    Ok(Options {
        keepalive,
        max_header_bytes,
        enable_full_duplex,
        trusted_proxies_unix,
        allow_0rtt,
    })
}

impl Default for Options {
 fn default()->Self{Self{keepalive:Keepalive::default(),max_header_bytes:16*1024,enable_full_duplex:false,trusted_proxies_unix:false,allow_0rtt:true}}
}
