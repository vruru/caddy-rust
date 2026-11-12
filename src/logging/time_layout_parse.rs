// Copyright 2009 The Go Authors. All rights reserved.
// Derived from time/format.go (Go 1.27.3), BSD-3-Clause.
//! Parse the same compiled reference-time tokens used for backup names.
use super::{DAYS, Layout, MONTHS, Token};
use crate::logging::{
    time_components::{local_civil_to_unix, local_named_offset},
    types::Timestamp,
};
use chrono::{Datelike, NaiveDate};

#[derive(Default)]
struct Parsed<'a> {
    year: i32,
    month: Option<u32>,
    day: Option<u32>,
    ordinal: Option<u32>,
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
    utc: bool,
    offset: Option<i32>,
    zone: Option<&'a str>,
    am: bool,
    pm: bool,
}

pub(super) fn parse(layout: &Layout, input: &str, local: bool) -> Option<Timestamp> {
    parse_time(layout,input,local).map(|parsed|parsed.timestamp)
}
pub(super) fn parse_time(layout: &Layout, input: &str, local: bool) -> Option<super::ParsedTime> {
    let mut cursor = Cursor(input.as_bytes());
    let mut value = Parsed::default();
    let mut tokens = layout
        .tokens
        .iter()
        .filter(|t| !matches!(t, Token::Literal(_)))
        .peekable();
    for token in &layout.tokens {
        if let Token::Literal(range) = token {
            cursor.skip(&layout.input.as_bytes()[range.clone()])?;
            continue;
        }
        tokens.next();
        match token {
            Token::Literal(_) => unreachable!(),
            Token::Fraction { digits, trim, .. } => {
                if *trim {
                    if let Some(nanos) = cursor.optional_fraction()? {
                        value.nanos = nanos;
                    }
                } else {
                    value.nanos = cursor.fraction(*digits)?;
                }
            }
            Token::Standard(part) => match *part {
                "2006" => value.year = i32::try_from(cursor.number(4, 4)?).ok()?,
                "06" => {
                    let year = i32::try_from(cursor.number(2, 2)?).ok()?;
                    value.year = year + if year >= 69 { 1900 } else { 2000 };
                }
                "January" | "Jan" => {
                    value.month = Some(cursor.name(&MONTHS, *part == "Jan")? as u32 + 1);
                }
                "Monday" | "Mon" => {
                    cursor.name(&DAYS, *part == "Mon")?;
                }
                "1" | "01" => {
                    value.month = Some(range(
                        cursor.number(if *part == "01" { 2 } else { 1 }, 2)?,
                        1,
                        12,
                    )?);
                }
                "2" | "_2" | "02" => {
                    if *part == "_2" {
                        cursor.spaces(1);
                    }
                    value.day = Some(cursor.number(if *part == "02" { 2 } else { 1 }, 2)?);
                }
                "__2" | "002" => {
                    if *part == "__2" {
                        cursor.spaces(2);
                    }
                    value.ordinal = Some(cursor.number(if *part == "002" { 3 } else { 1 }, 3)?);
                }
                "15" | "3" | "03" => {
                    value.hour = range(
                        cursor.number(if *part == "03" { 2 } else { 1 }, 2)?,
                        0,
                        if *part == "15" { 23 } else { 12 },
                    )?;
                }
                "4" | "04" => {
                    value.minute =
                        range(cursor.number(if *part == "04" { 2 } else { 1 }, 2)?, 0, 59)?;
                }
                "5" | "05" => {
                    value.second =
                        range(cursor.number(if *part == "05" { 2 } else { 1 }, 2)?, 0, 59)?;
                    if !matches!(tokens.peek(), Some(Token::Fraction { .. }))
                        && let Some(nanos) = cursor.optional_fraction()?
                    {
                        value.nanos = nanos;
                    }
                }
                "PM" => match cursor.take(2)? {
                    b"AM" => value.am = true,
                    b"PM" => value.pm = true,
                    _ => return None,
                },
                "pm" => match cursor.take(2)? {
                    b"am" => value.am = true,
                    b"pm" => value.pm = true,
                    _ => return None,
                },
                "MST" => {
                    if cursor.0.starts_with(b"UTC") {
                        cursor.take(3)?;
                        value.utc = true;
                    } else {
                        let width = zone_name_len(cursor.0)?;
                        value.zone = Some(std::str::from_utf8(cursor.take(width)?).ok()?);
                    }
                }
                "-070000" | "-07:00:00" | "-0700" | "-07:00" | "-07" | "Z070000" | "Z07:00:00"
                | "Z0700" | "Z07:00" | "Z07" => {
                    if part.starts_with('Z') && cursor.0.first() == Some(&b'Z') {
                        cursor.take(1)?;
                        value.utc = true;
                    } else {
                        value.offset = Some(cursor.offset(part.as_bytes())?);
                    }
                }
                _ => return None,
            },
        }
    }
    if !cursor.0.is_empty() {
        return None;
    }
    value.finish(local)
}
impl Parsed<'_> {
    fn finish(mut self, local: bool) -> Option<super::ParsedTime> {
        if self.pm && self.hour < 12 {
            self.hour += 12;
        } else if self.am && self.hour == 12 {
            self.hour = 0;
        }
        let date = if let Some(ordinal) = self.ordinal {
            let date = NaiveDate::from_yo_opt(self.year, ordinal)?;
            if self.month.is_some_and(|m| m != date.month())
                || self.day.is_some_and(|d| d != date.day())
            {
                return None;
            }
            date
        } else {
            NaiveDate::from_ymd_opt(self.year, self.month.unwrap_or(1), self.day.unwrap_or(1))?
        };
        let civil = date
            .and_hms_opt(self.hour, self.minute, self.second)?
            .and_utc()
            .timestamp();
        let seconds = if self.utc {
            civil
        } else if let Some(offset) = self.offset.filter(|&x| x != -1) {
            civil.checked_sub(i64::from(offset))?
        } else if let Some(zone) = self.zone {
            // Go keeps the absolute timestamp unchanged for a fabricated
            // location. Even a "GMT+N" fallback only names a fixed location.
            let offset = if local {
                local_named_offset(civil, zone).unwrap_or(0)
            } else {
                0
            };
            civil.checked_sub(i64::from(offset))?
        } else if local {
            local_civil_to_unix(civil)?
        } else {
            civil
        };
        let offset = i32::try_from(civil.checked_sub(seconds)?).ok()?;
        let use_local = local && !self.utc && match (self.offset.filter(|&x|x != -1),self.zone) {
            (None,None)=>true,
            (Some(expected),name)=>crate::http_config::helpers::local_zone_info(seconds).is_some_and(|(actual,abbreviation)|actual==expected && name.is_none_or(|n|n==abbreviation)),
            (None,Some(name))=>local_named_offset(civil,name).is_some(),
        };
        Some(super::ParsedTime {
            timestamp:Timestamp { seconds, nanosecond:self.nanos },
            local:use_local, offset,
            zone:if self.utc {"UTC".into()}else{self.zone.unwrap_or("").into()},
        })
    }
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, width: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(width)?;
        self.0 = tail;
        Some(head)
    }
    fn spaces(&mut self, limit: usize) {
        let count = self
            .0
            .iter()
            .take(limit)
            .take_while(|&&b| b == b' ')
            .count();
        self.0 = &self.0[count..];
    }
    fn skip(&mut self, mut prefix: &[u8]) -> Option<()> {
        while let Some((&first, rest)) = prefix.split_first() {
            if first == b' ' {
                if self.0.first().is_some_and(|&b| b != b' ') {
                    return None;
                }
                self.spaces(usize::MAX);
                let run = rest.iter().take_while(|&&b| b == b' ').count();
                prefix = &rest[run..];
            } else {
                if self.take(1)?[0] != first {
                    return None;
                }
                prefix = rest;
            }
        }
        Some(())
    }
    fn name(&mut self, names: &[&str], short: bool) -> Option<usize> {
        for (index, name) in names.iter().enumerate() {
            let name = name.as_bytes();
            let name = if short { &name[..3] } else { name };
            if self
                .0
                .get(..name.len())
                .is_some_and(|value| value.eq_ignore_ascii_case(name))
            {
                self.take(name.len())?;
                return Some(index);
            }
        }
        None
    }
    fn number(&mut self, min: usize, max: usize) -> Option<u32> {
        let width = self
            .0
            .iter()
            .take(max)
            .take_while(|b| b.is_ascii_digit())
            .count();
        if width < min {
            return None;
        }
        self.take(width)?.iter().try_fold(0u32, |value, b| {
            value.checked_mul(10)?.checked_add(u32::from(*b - b'0'))
        })
    }
    fn optional_fraction(&mut self) -> Option<Option<u32>> {
        if !matches!(self.0.first(), Some(b'.' | b','))
            || !self.0.get(1).is_some_and(u8::is_ascii_digit)
        {
            return Some(None);
        }
        let width = self.0[1..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        self.fraction(width).map(Some)
    }
    fn fraction(&mut self, width: usize) -> Option<u32> {
        if width == 0 || !matches!(self.take(1)?[0], b'.' | b',') {
            return None;
        }
        let bytes = self.take(width)?;
        let significant = bytes.len().min(9);
        let mut digits = Cursor(&bytes[..significant]);
        let value = digits.number(significant, significant)?;
        Some(value * 10u32.pow((9 - significant) as u32))
    }
    fn offset(&mut self, part: &[u8]) -> Option<i32> {
        let sign = match self.take(1)?[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let hour = range(self.number(2, 2)?, 0, 24)?;
        let mut minute = 0;
        let mut second = 0;
        if part.len() > 3 {
            if part[3] == b':' {
                self.skip(b":")?;
            }
            minute = range(self.number(2, 2)?, 0, 60)?;
            if matches!(part.len(), 7 | 9) {
                if part[3] == b':' {
                    self.skip(b":")?;
                }
                second = range(self.number(2, 2)?, 0, 60)?;
            }
        }
        Some(sign * ((hour * 60 + minute) * 60 + second) as i32)
    }
}
fn range(value: u32, min: u32, max: u32) -> Option<u32> {
    (min..=max).contains(&value).then_some(value)
}
fn zone_name_len(value: &[u8]) -> Option<usize> {
    if value.len() < 3 {
        return None;
    }
    if value.starts_with(b"ChST") || value.starts_with(b"MeST") {
        return Some(4);
    }
    if value.starts_with(b"GMT") {
        return Some(3 + signed_zone_len(&value[3..]).unwrap_or(0));
    }
    if matches!(value.first(), Some(b'+' | b'-')) {
        return signed_zone_len(value);
    }
    let width = value
        .iter()
        .take(6)
        .take_while(|b| b.is_ascii_uppercase())
        .count();
    match width {
        3 => Some(3),
        4 if value[3] == b'T' || value.starts_with(b"WITA") => Some(4),
        5 if value[4] == b'T' => Some(5),
        _ => None,
    }
}
fn signed_zone_len(value: &[u8]) -> Option<usize> {
    if !matches!(value.first(), Some(b'+' | b'-')) {
        return None;
    }
    let mut cursor = Cursor(&value[1..]);
    range(cursor.number(1, usize::MAX)?, 0, 23)?;
    Some(value.len() - cursor.0.len())
}
