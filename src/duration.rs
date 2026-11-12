// Copyright 2010 The Go Authors. All rights reserved.
// The time duration parser is derived from Go time/format.go under BSD-3-Clause.
// Caddy day-unit support derives from Caddy v2.11.7, Apache-2.0.
// See THIRD-PARTY-NOTICES for the applicable license texts.
use std::fmt;

// Source attribution: BSD 3-Clause, Go Authors
// This file is a mechanical translation of Go's time.ParseDuration
// and Caddy's ParseDuration logic to Rust, using only std, anyhow, and serde_json.

const MAX_INPUT_LEN: usize = 1024;

#[derive(Debug)]
struct ParseDurationError {
    message: String,
    value: String,
}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.message, &self.value);
        write!(f, "invalid duration")
    }
}

impl std::error::Error for ParseDurationError {}

fn quote(s: &str) -> String {
    format!("\"{}\"", s)
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn leading_int(s: &str) -> Result<(u64, &str), &'static str> {
    let mut x: u64 = 0;
    let mut rem = s;
    for (i, byte) in s.bytes().enumerate() {
        if !is_digit(byte) {
            break;
        }
        if x > (1u64 << 63) / 10 {
            return Err("overflow");
        }
        x = x * 10 + (byte - b'0') as u64;
        if x > (1u64 << 63) {
            return Err("overflow");
        }
        rem = &s[i + 1..];
    }
    Ok((x, rem))
}

fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut rem = s;

    for (i, byte) in s.bytes().enumerate() {
        if !is_digit(byte) {
            break;
        }
        if overflow {
            rem = &s[i + 1..];
            continue;
        }
        if x > ((1u64 << 63) - 1) / 10 {
            overflow = true;
            rem = &s[i + 1..];
            continue;
        }
        let y = x * 10 + (byte - b'0') as u64;
        if y > (1u64 << 63) {
            overflow = true;
            rem = &s[i + 1..];
            continue;
        }
        x = y;
        scale *= 10.0;
        rem = &s[i + 1..];
    }

    (x, scale, rem)
}

fn get_unit(u: &str) -> Option<u64> {
    match u {
        "ns" => Some(1),
        "us" | "µs" | "μs" => Some(1000),
        "ms" => Some(1_000_000),
        "s" => Some(1_000_000_000),
        "m" => Some(60_000_000_000),
        "h" => Some(3_600_000_000_000),
        _ => None,
    }
}

fn parse_duration_go(s: &str) -> Result<i64, ParseDurationError> {
    let orig = s;
    let mut s = s;
    let mut d: u64 = 0;
    let mut neg = false;

    if !s.is_empty() {
        let c = s.as_bytes()[0];
        if c == b'-' || c == b'+' {
            neg = c == b'-';
            s = &s[1..];
        }
    }

    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(ParseDurationError {
            message: "invalid duration".to_string(),
            value: orig.to_string(),
        });
    }

    while !s.is_empty() {
        let mut f: u64 = 0; // integers after decimal point
        let mut scale: f64 = 1.0; // value = v + f/scale

        let first_byte = s.as_bytes()[0];
        if !(first_byte == b'.' || is_digit(first_byte)) {
            return Err(ParseDurationError {
                message: "invalid duration".to_string(),
                value: orig.to_string(),
            });
        }

        let pl = s.len();
        let (v_parsed, s_rem) = leading_int(s).map_err(|_| ParseDurationError {
            message: "invalid duration".to_string(),
            value: orig.to_string(),
        })?;
        let mut v = v_parsed;
        s = s_rem;
        let pre = pl != s.len();

        let mut post = false;
        if !s.is_empty() && s.as_bytes()[0] == b'.' {
            s = &s[1..];
            let pl = s.len();
            let (f_parsed, scale_parsed, s_rem) = leading_fraction(s);
            f = f_parsed;
            scale = scale_parsed;
            s = s_rem;
            post = pl != s.len();
        }

        if !pre && !post {
            return Err(ParseDurationError {
                message: "invalid duration".to_string(),
                value: orig.to_string(),
            });
        }

        let mut i = 0;
        for (idx, byte) in s.bytes().enumerate() {
            if byte == b'.' || is_digit(byte) {
                break;
            }
            i = idx + 1;
        }
        if i == 0 {
            return Err(ParseDurationError {
                message: "missing unit in duration".to_string(),
                value: orig.to_string(),
            });
        }
        let u = &s[..i];
        s = &s[i..];

        let unit = get_unit(u).ok_or_else(|| ParseDurationError {
            message: format!("unknown unit {} in duration", quote(u)),
            value: orig.to_string(),
        })?;

        if v > (1u64 << 63) / unit {
            return Err(ParseDurationError {
                message: "invalid duration".to_string(),
                value: orig.to_string(),
            });
        }
        v *= unit;

        if f > 0 {
            let add = (f as f64) * ((unit as f64) / scale);
            let add_u64 = add as u64;
            v = v.checked_add(add_u64).ok_or_else(|| ParseDurationError {
                message: "overflow".into(),
                value: String::new(),
            })?;
            if v > (1u64 << 63) {
                return Err(ParseDurationError {
                    message: "invalid duration".to_string(),
                    value: orig.to_string(),
                });
            }
        }

        d = d.checked_add(v).ok_or_else(|| ParseDurationError {
            message: "overflow".into(),
            value: String::new(),
        })?;
        if d > (1u64 << 63) {
            return Err(ParseDurationError {
                message: "invalid duration".to_string(),
                value: orig.to_string(),
            });
        }
    }

    if neg {
        if d == 0 {
            return Ok(0);
        }
        if d == (1u64 << 63) {
            return Ok(i64::MIN);
        }
        return Ok(-(d as i64));
    }

    if d > (1u64 << 63) - 1 {
        return Err(ParseDurationError {
            message: "invalid duration".to_string(),
            value: orig.to_string(),
        });
    }

    Ok(d as i64)
}

fn format_float_f(v: f64) -> String {
    debug_assert!(v.is_finite());
    // Go's shortest binary64 conversion uses Ryu's nearest/ties-even choice.
    // Rust Display has a different tie rule; expand the shortest Ryu digits
    // without re-rounding them, preserving the sign of negative zero.
    let mut buffer = ryu::Buffer::new();
    let shortest = buffer.format_finite(v);
    let (negative, raw) = shortest
        .strip_prefix('-')
        .map_or((false, shortest), |s| (true, s));
    let (mantissa, exponent) = raw.split_once('e').map_or((raw, 0i32), |(m, e)| {
        (m, e.parse::<i32>().expect("Ryu exponent"))
    });
    let decimal = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let mut out = String::with_capacity(330);
    if negative {
        out.push('-');
    }
    if decimal <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-decimal) as usize));
        out.push_str(&digits);
    } else if decimal as usize >= digits.len() {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n('0', decimal as usize - digits.len()));
    } else {
        let point = decimal as usize;
        out.push_str(&digits[..point]);
        out.push('.');
        out.push_str(&digits[point..]);
    }
    if out.contains('.') {
        while out.ends_with('0') {
            out.pop();
        }
        if out.ends_with('.') {
            out.pop();
        }
    }
    out
}

/// CEL uses Go time.ParseDuration, without Caddy's extra day-unit syntax.
/// Its caller prepays the input scan and allocation budget before invoking it.
pub(crate) fn parse_cel_nanos(raw: &str) -> Result<i64, &'static str> {
    parse_duration_go(raw).map_err(|_| "invalid CEL duration")
}

/// Retain the previously supported, complete scientific-number and signed
/// component syntax as a CEL enhancement. An ignored trailing suffix is not a
/// duration component. This check allocates nothing; the vendor supplies the
/// existing arithmetic/range behavior after the caller's prepayment.
pub(crate) fn cel_extension_syntax(raw: &str) -> bool {
    let bytes=raw.as_bytes();let mut i=0;let mut components=0;
    while i<bytes.len() {
        if matches!(bytes[i],b'+'|b'-') {i+=1;}
        let mut digits=0;
        while i<bytes.len() && bytes[i].is_ascii_digit(){i+=1;digits+=1;}
        if i<bytes.len() && bytes[i]==b'.' {i+=1;while i<bytes.len() && bytes[i].is_ascii_digit(){i+=1;digits+=1;}}
        if digits==0{return false;}
        if i<bytes.len() && matches!(bytes[i],b'e'|b'E') {
            i+=1;if i<bytes.len() && matches!(bytes[i],b'+'|b'-'){i+=1;}
            let start=i;while i<bytes.len() && bytes[i].is_ascii_digit(){i+=1;}
            if start==i{return false;}
        }
        let rest=&bytes[i..];
        if rest.starts_with(b"ms")||rest.starts_with(b"us")||rest.starts_with(b"ns"){i+=2;}
        else if rest.first().is_some_and(|c|matches!(c,b'h'|b'm'|b's')){i+=1;}
        else{return false;}
        components+=1;
    }
    components!=0
}

pub fn parse_str(raw: &str) -> anyhow::Result<i64> {
    if raw.len() > MAX_INPUT_LEN {
        return Err(anyhow::anyhow!("parsing duration: input string too long"));
    }

    let mut s = raw.to_string();
    let mut i = 0;
    let mut in_number = false;
    let mut num_start = 0;

    while i < s.len() {
        let ch = s.as_bytes()[i];
        if ch == b'd' {
            let days_str = s
                .get(num_start..i)
                .ok_or_else(|| anyhow::anyhow!("invalid duration"))?;
            let days = days_str
                .parse::<f64>()
                .map_err(|_| anyhow::anyhow!("parsing duration: invalid day syntax"))?;

            if !days.is_finite() {
                return Err(anyhow::anyhow!("parsing duration: non-finite day value"));
            }

            let hours = days * 24.0;
            if !hours.is_finite() {
                anyhow::bail!("duration overflow");
            }
            let hours_str = format_float_f(hours);

            let prefix = &s[..num_start];
            let suffix = &s[i + 1..];

            s = format!("{}{}h{}", prefix, hours_str, suffix);

            continue;
        }

        if !in_number {
            num_start = i;
        }
        in_number = ch.is_ascii_digit() || ch == b'.' || ch == b'-' || ch == b'+';

        i += 1;
    }

    parse_duration_go(&s).map_err(|e| anyhow::anyhow!("{}", e))
}

pub fn parse_value(value: &serde_json::Value) -> anyhow::Result<i64> {
    match value {
        serde_json::Value::Null => Ok(0),
        serde_json::Value::Number(n) => n
            .as_go_i64()
            .ok_or_else(|| anyhow::anyhow!("parsing duration: number overflow")),
        serde_json::Value::String(s) => parse_str(s),
        _ => Err(anyhow::anyhow!("parsing duration: invalid value type")),
    }
}

/// Standard Go duration parser, without Caddy's additional day unit.
pub(crate) fn parse_go(raw:&str)->anyhow::Result<i64>{
    anyhow::ensure!(raw.len()<=MAX_INPUT_LEN,"duration input limit exceeded");
    parse_duration_go(raw).map_err(|e|anyhow::anyhow!("{e}"))
}
pub(crate) fn format(nano: i64) -> String {
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
        append_fraction(&mut result, value % scale, width);
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
    append_fraction(&mut result, value % 1_000_000_000, 9);
    result.push('s');
    result
}
fn append_fraction(output: &mut String, value: u64, width: usize) {
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
