//! Bounded codec for the exact storage record written by Caddy's distributed
//! STEK provider. This is not a general-purpose Gob deserializer.
use super::config::MAX_KEYS;
use anyhow::{Result, anyhow, ensure};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub(super) const FILE_LIMIT: usize = 16 * 1024;
const RECORD_LIMIT: usize = 8 * 1024;
const GO_EPOCH_OFFSET: i64 = 62_135_596_800;
const EARLIEST_USER_TYPE: i64 = 64;
const ROOT: i64 = 64;
const SLICE: i64 = 66;
const ARRAY: i64 = 65;
const TIME: i64 = 67;
const STRUCT_HEAD: &[u8] = b"\x03\x01\x01\x0fdistributedSTEK\x01";
const STRUCT_KEYS: &[u8] = b"\x00\x01\x03\x01\x04Keys\x01";
const STRUCT_LAST: &[u8] = b"\x00\x01\x0cLastRotation\x01";
const STRUCT_NEXT: &[u8] = b"\x00\x01\x0cNextRotation\x01";
const SLICE_HEAD: &[u8] = b"\x02\x01\x01\x0b[][32]uint8\x01";
const ARRAY_HEAD: &[u8] = b"\x01\x01\x02";
const TIME_HEAD: &[u8] = b"\x05\x01\x01\x04Time\x01";
const COMMON_END: &[u8] = b"\x00\x00\x00";

pub(super) struct Persisted {
    pub(super) keys: Zeroizing<Vec<[u8; 32]>>,
    pub(super) last: SystemTime,
    pub(super) next: SystemTime,
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (value, remaining) = self.0.split_at_checked(n).ok_or_else(invalid)?;
        self.0 = remaining;
        Ok(value)
    }
    fn literal(&mut self, expected: &[u8]) -> Result<()> {
        ensure!(self.take(expected.len())? == expected, invalid());
        Ok(())
    }
    fn uint(&mut self) -> Result<u64> {
        let first = self.take(1)?[0];
        if first < 128 {
            return Ok(u64::from(first));
        }
        let n = 256 - usize::from(first);
        ensure!((1..=8).contains(&n), invalid());
        let bytes = self.take(n)?;
        ensure!(bytes[0] != 0 && (n != 1 || bytes[0] >= 128), invalid());
        let mut out = [0; 8];
        out[8 - n..].copy_from_slice(bytes);
        Ok(u64::from_be_bytes(out))
    }
    fn signed(&mut self) -> Result<i64> {
        let raw = self.uint()?;
        let magnitude = (raw >> 1) as i64;
        Ok(if raw & 1 == 0 { magnitude } else { !magnitude })
    }
    fn user_type(&mut self) -> Result<i64> {
        let id = self.signed()?;
        ensure!(
            (EARLIEST_USER_TYPE..=i64::from(i32::MAX)).contains(&id),
            invalid()
        );
        Ok(id)
    }
    fn declaration(&mut self, id: i64, head: &[u8]) -> Result<()> {
        ensure!(self.signed()? == -id, invalid());
        self.literal(head)?;
        ensure!(self.user_type()? == id, invalid());
        Ok(())
    }
    fn record(&mut self) -> Result<Cursor<'a>> {
        let n = usize::try_from(self.uint()?).map_err(|_| invalid())?;
        ensure!((1..=RECORD_LIMIT).contains(&n), invalid());
        Ok(Cursor(self.take(n)?))
    }
    fn done(&self) -> Result<()> {
        ensure!(self.0.is_empty(), invalid());
        Ok(())
    }
    fn timestamp(&mut self) -> Result<SystemTime> {
        let n = usize::try_from(self.uint()?).map_err(|_| invalid())?;
        ensure!(matches!(n, 15 | 16), invalid());
        let bytes = self.take(n)?;
        ensure!(matches!((bytes[0], n), (1, 15) | (2, 16)), invalid());
        let seconds = i64::from_be_bytes(bytes[1..9].try_into().map_err(|_| invalid())?)
            .checked_sub(GO_EPOCH_OFFSET)
            .ok_or_else(invalid)?;
        let nanos = u32::from_be_bytes(bytes[9..13].try_into().map_err(|_| invalid())?);
        ensure!(nanos < 1_000_000_000, invalid());
        // The zone controls formatting only. Rotation uses the absolute time.
        let second = if seconds >= 0 {
            UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
        }
        .ok_or_else(invalid)?;
        second
            .checked_add(Duration::from_nanos(nanos.into()))
            .ok_or_else(invalid)
    }
}

fn invalid() -> anyhow::Error {
    anyhow!("invalid distributed session ticket key record")
}

pub(super) fn decode(bytes: &[u8]) -> Result<Persisted> {
    ensure!(!bytes.is_empty() && bytes.len() <= FILE_LIMIT, invalid());
    let mut stream = Cursor(bytes);
    let mut root = stream.record()?;
    let id = root.signed()?.checked_neg().ok_or_else(invalid)?;
    ensure!(id >= EARLIEST_USER_TYPE, invalid());
    root.literal(STRUCT_HEAD)?;
    ensure!(root.user_type()? == id, invalid());
    root.literal(STRUCT_KEYS)?;
    let slice = root.user_type()?;
    root.literal(STRUCT_LAST)?;
    let time = root.user_type()?;
    root.literal(STRUCT_NEXT)?;
    ensure!(root.user_type()? == time, invalid());
    root.literal(COMMON_END)?;
    root.done()?;

    let mut slice_record = stream.record()?;
    slice_record.declaration(slice, SLICE_HEAD)?;
    slice_record.literal(b"\x00\x01")?;
    let array = slice_record.user_type()?;
    slice_record.literal(b"\x00\x00")?;
    slice_record.done()?;
    let mut ids = [id, slice, array, time];
    ids.sort_unstable();
    ensure!(ids.windows(2).all(|pair| pair[0] != pair[1]), invalid());

    let mut array_record = stream.record()?;
    array_record.declaration(array, ARRAY_HEAD)?;
    // Element type uint=3; signed 3 -> 6. The array length 32 is signed too.
    array_record.literal(b"\x00\x01\x06\x01\x40\x00\x00")?;
    array_record.done()?;
    let mut time_record = stream.record()?;
    time_record.declaration(time, TIME_HEAD)?;
    time_record.literal(COMMON_END)?;
    time_record.done()?;

    let mut value = stream.record()?;
    stream.done()?;
    ensure!(value.user_type()? == id && value.uint()? == 1, invalid());
    let count = usize::try_from(value.uint()?).map_err(|_| invalid())?;
    ensure!((1..=MAX_KEYS).contains(&count), invalid());
    // Allocate once at the validated count; secrets are zeroized on any error.
    let mut keys = Zeroizing::new(vec![[0; 32]; count]);
    for key in keys.iter_mut() {
        ensure!(value.uint()? == 32, invalid());
        for byte in key {
            *byte = u8::try_from(value.uint()?).map_err(|_| invalid())?;
        }
    }
    ensure!(value.uint()? == 1, invalid());
    let last = value.timestamp()?;
    ensure!(value.uint()? == 1, invalid());
    let next = value.timestamp()?;
    ensure!(last <= next && value.uint()? == 0, invalid());
    value.done()?;
    Ok(Persisted { keys, last, next })
}

fn uint(out: &mut Vec<u8>, n: u64) {
    if n < 128 {
        out.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let len = (u64::BITS - n.leading_zeros()).div_ceil(8) as usize;
        out.push((256 - len) as u8);
        out.extend_from_slice(&bytes[8 - len..]);
    }
}

fn signed(out: &mut Vec<u8>, n: i64) {
    let raw = if n < 0 {
        (!(n as u64) << 1) | 1
    } else {
        (n as u64) << 1
    };
    uint(out, raw);
}

fn timestamp(out: &mut Vec<u8>, time: SystemTime) -> Result<()> {
    let (seconds, nanos) = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (
            i64::try_from(duration.as_secs()).map_err(|_| invalid())?,
            duration.subsec_nanos(),
        ),
        Err(error) => {
            let duration = error.duration();
            let whole = i64::try_from(duration.as_secs()).map_err(|_| invalid())?;
            if duration.subsec_nanos() == 0 {
                (-whole, 0)
            } else {
                (-whole - 1, 1_000_000_000 - duration.subsec_nanos())
            }
        }
    };
    let go = seconds.checked_add(GO_EPOCH_OFFSET).ok_or_else(invalid)?;
    uint(out, 15);
    out.push(1); // time.Time binary v1
    out.extend_from_slice(&go.to_be_bytes());
    out.extend_from_slice(&nanos.to_be_bytes());
    out.extend_from_slice(&(-1_i16).to_be_bytes()); // Go's UTC zone sentinel
    Ok(())
}

fn public_declaration(out: &mut Vec<u8>, id: i64, head: &[u8], tail: impl FnOnce(&mut Vec<u8>)) {
    let mut record = Vec::with_capacity(128);
    signed(&mut record, -id);
    record.extend_from_slice(head);
    signed(&mut record, id);
    tail(&mut record);
    uint(out, record.len() as u64);
    out.extend_from_slice(&record);
}

pub(super) fn encode(state: &Persisted) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        (1..=MAX_KEYS).contains(&state.keys.len()) && state.last <= state.next,
        invalid()
    );
    let mut value = Zeroizing::new(Vec::with_capacity(64 + 65 * state.keys.len()));
    signed(&mut value, ROOT);
    uint(&mut value, 1);
    uint(&mut value, state.keys.len() as u64);
    for key in state.keys.iter() {
        uint(&mut value, 32);
        for byte in key {
            uint(&mut value, u64::from(*byte));
        }
    }
    uint(&mut value, 1);
    timestamp(&mut value, state.last)?;
    uint(&mut value, 1);
    timestamp(&mut value, state.next)?;
    uint(&mut value, 0);
    ensure!(value.len() <= RECORD_LIMIT, invalid());

    let mut out = Zeroizing::new(Vec::with_capacity(256 + value.len()));
    public_declaration(&mut out, ROOT, STRUCT_HEAD, |r| {
        r.extend_from_slice(STRUCT_KEYS);
        signed(r, SLICE);
        r.extend_from_slice(STRUCT_LAST);
        signed(r, TIME);
        r.extend_from_slice(STRUCT_NEXT);
        signed(r, TIME);
        r.extend_from_slice(COMMON_END);
    });
    public_declaration(&mut out, SLICE, SLICE_HEAD, |r| {
        r.extend_from_slice(b"\x00\x01");
        signed(r, ARRAY);
        r.extend_from_slice(b"\x00\x00");
    });
    public_declaration(&mut out, ARRAY, ARRAY_HEAD, |r| {
        r.extend_from_slice(b"\x00\x01\x06\x01\x40\x00\x00")
    });
    public_declaration(&mut out, TIME, TIME_HEAD, |r| {
        r.extend_from_slice(COMMON_END)
    });
    uint(&mut out, value.len() as u64);
    out.extend_from_slice(&value);
    ensure!(out.len() <= FILE_LIMIT, invalid());
    Ok(out)
}
