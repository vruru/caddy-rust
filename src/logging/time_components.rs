//! Proleptic Gregorian UTC/offset conversion over every signed Unix second.
//! Local timezone discovery is supplied by the shared provisioned helper.
use super::{time_layout::Components, types::Timestamp};
use anyhow::{Result, ensure};
pub(crate) fn at(time: Timestamp, offset: i32, zone: String) -> Result<Components> {
    ensure!(time.nanosecond < 1_000_000_000, "invalid log timestamp");
    let seconds = i128::from(time.seconds) + i128::from(offset);
    let day = seconds.div_euclid(86_400);
    let clock = seconds.rem_euclid(86_400);
    // March-based 400-year cycles avoid iterative year scanning and i64 overflow.
    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    let era_day = z.rem_euclid(146_097);
    let era_year = (era_day - era_day / 1460 + era_day / 36524 - era_day / 146096) / 365;
    let year_day = era_day - (365 * era_year + era_year / 4 - era_year / 100);
    let march_month = (5 * year_day + 2) / 153;
    let month = march_month + if march_month < 10 { 3 } else { -9 };
    let date = year_day - (153 * march_month + 2) / 5 + 1;
    let year = era_year + era * 400 + i128::from(month <= 2);
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    const BEFORE: [u16; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    Ok(Components {
        year,
        month: month as u8,
        day: date as u8,
        weekday: (day + 4).rem_euclid(7) as u8,
        ordinal: BEFORE[month as usize - 1] + date as u16 + u16::from(leap && month > 2),
        hour: (clock / 3600) as u8,
        minute: ((clock / 60) % 60) as u8,
        second: (clock % 60) as u8,
        nanosecond: time.nanosecond,
        offset,
        zone,
    })
}
pub(crate) fn unix_nano(time: Timestamp) -> i64 {
    time.seconds
        .wrapping_mul(1_000_000_000)
        .wrapping_add(i64::from(time.nanosecond))
}
pub(crate) fn is_zero(time: Timestamp) -> bool {
    time.seconds == -62_135_596_800 && time.nanosecond == 0
}

/// Go time.Date first looks up the civil instant interpreted as UTC. If
/// subtracting that offset crosses a zone change, it uses the offset at
/// the shifted instant instead. This also selects a side of a gap/fold.
pub(super) fn local_civil_to_unix(naive_seconds: i64) -> Option<i64> {
    use crate::http_config::helpers::local_zone_info;
    let (first, _) = local_zone_info(naive_seconds)?;
    let shifted = naive_seconds.checked_sub(i64::from(first))?;
    let (offset, _) = local_zone_info(shifted)?;
    naive_seconds.checked_sub(i64::from(offset))
}

/// Search the zone information near a recorded civil time for an abbreviation
/// in effect at that time. Test candidates at the corrected UTC instant so
/// both sides of a repeated civil hour can be resolved independently.
pub(super) fn local_named_offset(naive_seconds: i64, name: &str) -> Option<i32> {
    use crate::http_config::helpers::local_zone_info;
    for distance in [0, -6, 6, -24, 24, -48, 48, -168, 168] {
        let sample = naive_seconds.checked_add(distance * 3600)?;
        let (offset, abbreviation) = local_zone_info(sample)?;
        if abbreviation != name {
            continue;
        }
        let corrected = naive_seconds.checked_sub(i64::from(offset))?;
        let (actual, abbreviation) = local_zone_info(corrected)?;
        if actual == offset && abbreviation == name {
            return Some(offset);
        }
    }
    None
}
