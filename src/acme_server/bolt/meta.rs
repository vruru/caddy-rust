//! Bolt v2, little-endian metadata. Fixed-size candidate scan, no allocation.
//! Layout and FNV-1a checksum follow bbolt 1.4.3 internal/common/meta.go.

use super::{Error, u16le, u32le, u64le};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub page_size: usize,
    pub root: u64,
    pub sequence: u64,
    pub freelist: u64,
    pub high_water: u64,
    pub txid: u64,
    pub slot: usize,
}

pub(super) fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(14695981039346656037u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(1099511628211)
    })
}

pub(super) fn encode(meta: &Meta) -> Result<[u8; 80], Error> {
    if ![1024, 2048, 4096, 8192, 16384, 32768, 65536].contains(&meta.page_size)
        || meta.txid % 2 != meta.slot as u64
        || meta.slot > 1
        || meta.high_water < 4
        || meta.root < 2
        || meta.root >= meta.high_water
        || (meta.freelist != u64::MAX && (meta.freelist < 2 || meta.freelist >= meta.high_water))
    {
        return Err(Error::Corrupt("invalid output metadata"));
    }
    let mut out = [0u8; 80];
    out[0..8].copy_from_slice(&(meta.slot as u64).to_le_bytes());
    out[8..10].copy_from_slice(&4u16.to_le_bytes());
    out[16..20].copy_from_slice(&0xed0cdaedu32.to_le_bytes());
    out[20..24].copy_from_slice(&2u32.to_le_bytes());
    out[24..28].copy_from_slice(&(meta.page_size as u32).to_le_bytes());
    for (at, value) in [
        (32, meta.root),
        (40, meta.sequence),
        (48, meta.freelist),
        (56, meta.high_water),
        (64, meta.txid),
    ] {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    let hash = checksum(&out[16..72]);
    out[72..80].copy_from_slice(&hash.to_le_bytes());
    Ok(out)
}

pub(super) fn select_meta(data: &[u8]) -> Result<Meta, Error> {
    let mut best: Option<Meta> = None;
    let mut conflicting = false;
    for page_size in [1024usize, 2048, 4096, 8192, 16384, 32768, 65536] {
        for slot in 0..2usize {
            let offset = slot * page_size;
            let Some(page) = data.get(offset..offset + 80) else {
                continue;
            };
            if u64le(page, 0)? != slot as u64
                || u16le(page, 8)? != 4
                || u16le(page, 10)? != 0
                || u32le(page, 12)? != 0
                || u32le(page, 16)? != 0xed0cdaed
                || u32le(page, 20)? != 2
                || u32le(page, 24)? as usize != page_size
                || u32le(page, 28)? != 0
                || checksum(&page[16..72]) != u64le(page, 72)?
            {
                continue;
            }
            let candidate = Meta {
                page_size,
                root: u64le(page, 32)?,
                sequence: u64le(page, 40)?,
                freelist: u64le(page, 48)?,
                high_water: u64le(page, 56)?,
                txid: u64le(page, 64)?,
                slot,
            };
            if candidate.txid % 2 != slot as u64
                || candidate.high_water < 4
                || candidate.root < 2
                || candidate.root >= candidate.high_water
                || (candidate.freelist != u64::MAX
                    && (candidate.freelist < 2 || candidate.freelist >= candidate.high_water))
                || candidate
                    .high_water
                    .checked_mul(page_size as u64)
                    .is_none_or(|end| end > data.len() as u64)
            {
                continue;
            }
            match &best {
                None => {
                    best = Some(candidate);
                    conflicting = false;
                }
                Some(old) if candidate.txid > old.txid => {
                    best = Some(candidate);
                    conflicting = false;
                }
                Some(old) if candidate.txid == old.txid && candidate != *old => conflicting = true,
                _ => {}
            }
        }
    }
    if conflicting {
        return Err(Error::Corrupt("conflicting metadata"));
    }
    best.ok_or(Error::Corrupt("no valid metadata"))
}
