// Copyright (c) 2025 Dean Ruina. MIT.
//! Wall-clock marks for idle and write-driven rotations. Only the active
//! physical writer owns rotation state; the actor's wait uses monotonic time.
use super::{
    time_components::{self, local_civil_to_unix},
    time_layout::Components,
    types::Timestamp,
};
use chrono::NaiveDate;
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

const DAY_MINUTES: usize = 24 * 60;
const SECOND_NS: i128 = 1_000_000_000;
const RETRY: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
pub(super) struct Moment {
    pub wall: Timestamp,
    pub monotonic: Instant,
}
impl Moment {
    pub(super) fn now() -> io::Result<Self> {
        Ok(Self {
            wall: Timestamp::now().map_err(io::Error::other)?,
            monotonic: Instant::now(),
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct RotationTime {
    pub wall_ns: i128,
    pub monotonic: Option<Instant>,
}
impl RotationTime {
    pub(super) fn write(now: Moment) -> Self {
        Self {
            wall_ns: nanos(now.wall),
            monotonic: Some(now.monotonic),
        }
    }
    pub(super) fn mark(seconds: i64) -> Self {
        Self {
            wall_ns: i128::from(seconds) * SECOND_NS,
            monotonic: None,
        }
    }
    pub(super) fn interval_due(self, now: Moment, interval: i64) -> bool {
        interval > 0
            && self.monotonic.map_or_else(
                || nanos(now.wall) - self.wall_ns >= i128::from(interval),
                |previous| {
                    now.monotonic.saturating_duration_since(previous)
                        >= Duration::from_nanos(interval as u64)
                },
            )
    }
    pub(super) fn before(self, seconds: i64) -> bool {
        self.wall_ns < i128::from(seconds) * SECOND_NS
    }
}
fn nanos(timestamp: Timestamp) -> i128 {
    i128::from(timestamp.seconds) * SECOND_NS + i128::from(timestamp.nanosecond)
}
pub(super) struct Schedule {
    slots: Vec<u16>,
    local: bool,
}
#[derive(Clone, Copy)]
pub(super) struct Due {
    pub mark: Option<i64>,
    pub deadline: Instant,
}
impl Schedule {
    pub(super) fn new(minutes: &[i64], times: &[String], local: bool) -> Self {
        let mut slots = [false; DAY_MINUTES];
        let mut invalid = false;
        for minute in minutes {
            if let Ok(minute) = usize::try_from(*minute)
                && minute < 60
            {
                for hour in 0..24 {
                    slots[hour * 60 + minute] = true;
                }
            } else {
                invalid = true;
            }
        }
        for time in times {
            if let Some(minute) = parse_mark(time) {
                slots[minute] = true;
            } else {
                invalid = true;
            }
        }
        if invalid {
            let _ = io::stderr()
                .lock()
                .write_all(b"timberjack: ignored invalid log rotation minute or time\n");
        }
        let slots = slots
            .into_iter()
            .enumerate()
            .filter_map(|(minute, set)| set.then_some(minute as u16))
            .collect();
        Self { slots, local }
    }
    pub(super) fn crossed(&self, now: Moment, last: RotationTime) -> Option<i64> {
        if self.slots.is_empty() {
            return None;
        }
        let civil = self.civil(now.wall.seconds)?;
        self.slots.iter().find_map(|&slot| {
            let mark = self.to_unix(civil.date, slot)?;
            (last.before(mark) && mark <= now.wall.seconds).then_some(mark)
        })
    }
    pub(super) fn next(&self, now: Moment) -> Option<Due> {
        if self.slots.is_empty() {
            return None;
        }
        let mark = self.next_mark(now.wall.seconds);
        let delay = mark
            .and_then(|mark| u64::try_from(i128::from(mark) * SECOND_NS - nanos(now.wall)).ok())
            .map_or(RETRY, Duration::from_nanos);
        Some(Due {
            mark,
            deadline: now.monotonic.checked_add(delay)?,
        })
    }
    fn next_mark(&self, now: i64) -> Option<i64> {
        let civil = self.civil(now)?;
        let base = self.to_unix(civil.date, u16::from(civil.hour) * 60)?;
        let mut previous = None;
        // Same dates as Timberjack's local-hour search; skip repeated dates
        // because the list of marks for any particular date is identical.
        for hour_offset in 0..=24 {
            let date = self.civil(base.checked_add(hour_offset * 3600)?)?.date;
            if previous == Some(date) {
                continue;
            }
            previous = Some(date);
            for &slot in &self.slots {
                if let Some(mark) = self.to_unix(date, slot)
                    && mark > now
                {
                    return Some(mark);
                }
            }
        }
        None
    }
    fn civil(&self, seconds: i64) -> Option<Civil> {
        let parts = components(
            Timestamp {
                seconds,
                nanosecond: 0,
            },
            self.local,
        )?;
        let date = NaiveDate::from_ymd_opt(
            i32::try_from(parts.year).ok()?,
            u32::from(parts.month),
            u32::from(parts.day),
        )?;
        Some(Civil {
            date,
            hour: parts.hour,
        })
    }
    fn to_unix(&self, day: NaiveDate, minute: u16) -> Option<i64> {
        let naive = day
            .and_hms_opt(u32::from(minute / 60), u32::from(minute % 60), 0)?
            .and_utc()
            .timestamp();
        if self.local {
            local_civil_to_unix(naive)
        } else {
            Some(naive)
        }
    }
}
struct Civil {
    date: NaiveDate,
    hour: u8,
}
fn parse_mark(value: &str) -> Option<usize> {
    let (hour, minute) = value.split_once(':')?;
    let hour: i64 = hour.parse().ok()?;
    let minute: i64 = minute.parse().ok()?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) {
        return None;
    }
    Some((hour * 60 + minute) as usize)
}
pub(super) fn components(timestamp: Timestamp, local: bool) -> Option<Components> {
    let (offset, zone) = if local {
        crate::http_config::helpers::local_zone_info(timestamp.seconds)?
    } else {
        (0, "UTC".into())
    };
    time_components::at(timestamp, offset, zone).ok()
}
