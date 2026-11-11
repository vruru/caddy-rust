// Copyright 2009 The Go Authors. All rights reserved.
// Derived from time/format.go (Go 1.27.3), BSD-3-Clause.
//! Compiled Go reference-time layouts; these are not strftime strings.
use anyhow::{Result, ensure};
use std::ops::Range;
#[path = "time_layout_parse.rs"]
mod parse;
pub(super) struct Components {
    pub year: i128,
    pub month: u8,
    pub day: u8,
    pub weekday: u8,
    pub ordinal: u16,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
    pub offset: i32,
    pub zone: String,
}
enum Token {
    Literal(Range<usize>),
    Standard(&'static str),
    Fraction {
        separator: u8,
        digits: usize,
        trim: bool,
    },
}
pub(super) struct Layout {
    input: String,
    tokens: Vec<Token>,
}
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
impl Layout {
    pub(super) fn parse_timestamp(
        &self,
        input: &str,
        local: bool,
    ) -> Option<super::types::Timestamp> {
        parse::parse(self, input, local)
    }
    pub(super) fn compile(input: &str) -> Result<Self> {
        ensure!(
            input.len() <= 1 << 20,
            "log time layout byte limit exceeded"
        );
        let bytes = input.as_bytes();
        let mut tokens = Vec::new();
        let (mut i, mut literal) = (0, 0);
        while i < bytes.len() {
            let next = scan(&bytes[i..]);
            if let Some((length, token)) = next {
                if literal < i {
                    push(&mut tokens, Token::Literal(literal..i))?;
                }
                push(&mut tokens, token)?;
                i += length;
                literal = i;
            } else {
                i += 1;
            }
        }
        if literal < bytes.len() {
            push(&mut tokens, Token::Literal(literal..bytes.len()))?;
        }
        Ok(Self {
            input: input.into(),
            tokens,
        })
    }
    pub(super) fn format(&self, c: &Components, max_bytes: usize) -> Result<String> {
        ensure!(
            (1..=12).contains(&c.month) && c.weekday < 7 && c.nanosecond < 1_000_000_000,
            "invalid log time components"
        );
        let mut output = String::new();
        for token in &self.tokens {
            match token {
                Token::Literal(range) => {
                    append(&mut output, &self.input[range.clone()], max_bytes)?
                }
                Token::Fraction {
                    separator,
                    digits,
                    trim,
                } => {
                    if *trim && (*digits == 0 || c.nanosecond == 0) {
                        continue;
                    }
                    let mut part = format!("{}{:09}", char::from(*separator), c.nanosecond);
                    part.truncate(1 + (*digits).min(9));
                    if *trim {
                        while part.ends_with('0') {
                            part.pop();
                        }
                        if part.len() == 1 {
                            part.clear();
                        }
                    }
                    append(&mut output, &part, max_bytes)?;
                }
                Token::Standard(token) => {
                    let part = standard(token, c)?;
                    append(&mut output, &part, max_bytes)?;
                }
            }
        }
        Ok(output)
    }
}
fn push(tokens: &mut Vec<Token>, token: Token) -> Result<()> {
    ensure!(tokens.len() < 65536, "log time layout token limit exceeded");
    tokens.push(token);
    Ok(())
}
fn append(output: &mut String, piece: &str, max_bytes: usize) -> Result<()> {
    let needed = output
        .len()
        .checked_add(piece.len())
        .filter(|n| *n <= max_bytes)
        .ok_or(super::bounded::ByteLimit("log time output limit exceeded"))?;
    if needed > output.capacity() {
        let grown = output
            .capacity()
            .saturating_mul(2)
            .max(32)
            .min(max_bytes)
            .max(needed);
        output.try_reserve_exact(grown - output.len())?;
    }
    output.push_str(piece);
    Ok(())
}
fn scan(bytes: &[u8]) -> Option<(usize, Token)> {
    let first = *bytes.first()?;
    if matches!(first, b'.' | b',') && matches!(bytes.get(1), Some(b'0' | b'9')) {
        let digit = bytes[1];
        let count = bytes[1..].iter().take_while(|b| **b == digit).count();
        if !bytes.get(count + 1).is_some_and(u8::is_ascii_digit) {
            return Some((
                count + 1,
                Token::Fraction {
                    separator: first,
                    digits: count & 0xfff,
                    trim: digit == b'9',
                },
            ));
        }
    }
    let options: &[&str] = match first {
        b'J' => &["January", "Jan"],
        b'M' => &["Monday", "Mon", "MST"],
        b'0' => &["01", "02", "03", "04", "05", "06", "002"],
        b'1' => &["15", "1"],
        b'2' => &["2006", "2"],
        b'_' => &["__2", "_2"],
        b'3' => &["3"],
        b'4' => &["4"],
        b'5' => &["5"],
        b'P' => &["PM"],
        b'p' => &["pm"],
        b'-' => &["-070000", "-07:00:00", "-0700", "-07:00", "-07"],
        b'Z' => &["Z070000", "Z07:00:00", "Z0700", "Z07:00", "Z07"],
        _ => &[],
    };
    for option in options {
        if !bytes.starts_with(option.as_bytes()) {
            continue;
        }
        if matches!(*option, "Jan" | "Mon") && bytes.get(3).is_some_and(u8::is_ascii_lowercase) {
            continue;
        }
        if *option == "_2" && bytes.starts_with(b"_2006") {
            continue;
        }
        return Some((option.len(), Token::Standard(option)));
    }
    None
}
fn integer(value: i128, width: usize) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut output = String::new();
    if value < 0 {
        output.push('-');
    }
    for _ in digits.len()..width {
        output.push('0');
    }
    output.push_str(&digits);
    output
}
fn standard(token: &str, c: &Components) -> Result<String> {
    Ok(match token {
        "January" => MONTHS[c.month as usize - 1].into(),
        "Jan" => MONTHS[c.month as usize - 1][..3].into(),
        "Monday" => DAYS[c.weekday as usize].into(),
        "Mon" => DAYS[c.weekday as usize][..3].into(),
        "2006" => integer(c.year, 4),
        "06" => integer((c.year.unsigned_abs() % 100) as i128, 2),
        "1" => c.month.to_string(),
        "01" => integer(c.month.into(), 2),
        "2" => c.day.to_string(),
        "02" => integer(c.day.into(), 2),
        "_2" => format!("{:2}", c.day),
        "002" => integer(c.ordinal.into(), 3),
        "__2" => format!("{:3}", c.ordinal),
        "15" => integer(c.hour.into(), 2),
        "3" => (if c.hour.is_multiple_of(12) {
            12
        } else {
            c.hour % 12
        })
        .to_string(),
        "03" => integer(
            (if c.hour.is_multiple_of(12) {
                12
            } else {
                c.hour % 12
            })
            .into(),
            2,
        ),
        "4" => c.minute.to_string(),
        "04" => integer(c.minute.into(), 2),
        "5" => c.second.to_string(),
        "05" => integer(c.second.into(), 2),
        "PM" => if c.hour >= 12 { "PM" } else { "AM" }.into(),
        "pm" => if c.hour >= 12 { "pm" } else { "am" }.into(),
        "MST" if !c.zone.is_empty() => c.zone.clone(),
        _ => zone(token, c),
    })
}
fn zone(token: &str, c: &Components) -> String {
    if token.starts_with('Z') && c.offset == 0 {
        return "Z".into();
    }
    let zone = i64::from(c.offset) / 60;
    let negative = zone < 0;
    let minutes = zone.abs();
    let mut output = if negative { "-" } else { "+" }.to_owned();
    output.push_str(&integer((minutes / 60).into(), 2));
    let colon = token.contains(':');
    if colon {
        output.push(':');
    }
    if token != "-07" && token != "Z07" {
        output.push_str(&integer((minutes % 60).into(), 2));
    }
    if matches!(token, "-070000" | "Z070000" | "-07:00:00" | "Z07:00:00") {
        if colon {
            output.push(':');
        }
        let absolute = if negative {
            -i64::from(c.offset)
        } else {
            i64::from(c.offset)
        };
        output.push_str(&integer((absolute % 60).into(), 2));
    }
    output
}
