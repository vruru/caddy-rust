//! Checked Bolt v2 codec. Foreign bytes are never mapped or converted to pointers.
//! The caller owns the immutable, prepaid input for the complete transaction.
//! This module does not publish a transaction or operate on a live file.

pub mod encode;
pub mod file;
mod meta;
pub mod owned;
pub use meta::Meta;

use std::{io, ops::Range};

#[derive(Debug)]
pub enum Error {
    Corrupt(&'static str),
    Limit,
    Cancelled,
    Timeout,
    Io(io::Error),
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt(reason) => write!(f, "invalid Bolt database: {reason}"),
            Self::Io(e) => write!(f, "Bolt I/O: {e}"),
            Self::Limit => f.write_str("Bolt capacity exceeded"),
            Self::Cancelled => f.write_str("Bolt operation cancelled"),
            Self::Timeout => f.write_str("Bolt operation timed out"),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Charges precede allocations. The enclosing operation owns all charged memory
/// until its actual buffers retire. Work also checks cancellation/deadline.
pub trait Budget {
    fn charge(&mut self, bytes: usize) -> Result<()>;
    fn work(&mut self, units: usize) -> Result<()>;
}

pub(crate) fn reserve<T>(v: &mut Vec<T>, count: usize, budget: &mut impl Budget) -> Result<()> {
    let needed = v.len().checked_add(count).ok_or(Error::Limit)?;
    if needed > v.capacity() {
        let capacity = needed.max(v.capacity().saturating_mul(2)).max(4);
        budget.charge(
            capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(Error::Limit)?,
        )?;
        v.try_reserve_exact(capacity - v.len())
            .map_err(|_| Error::Limit)?;
    }
    Ok(())
}

pub(crate) fn range(data: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    data.get(
        at..at
            .checked_add(len)
            .ok_or(Error::Corrupt("range overflow"))?,
    )
    .ok_or(Error::Corrupt("range outside image"))
}
pub(crate) fn u16le(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(data, at, 2)?
            .try_into()
            .map_err(|_| Error::Corrupt("short u16"))?,
    ))
}
pub(crate) fn u32le(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(data, at, 4)?
            .try_into()
            .map_err(|_| Error::Corrupt("short u32"))?,
    ))
}
pub(crate) fn u64le(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        range(data, at, 8)?
            .try_into()
            .map_err(|_| Error::Corrupt("short u64"))?,
    ))
}

#[derive(Debug)]
pub enum Value<'a> {
    Bytes(&'a [u8]),
    Bucket(usize),
}
#[derive(Debug)]
pub struct Entry<'a> {
    pub key: &'a [u8],
    pub value: Value<'a>,
}
#[derive(Debug)]
pub struct Bucket<'a> {
    pub sequence: u64,
    pub entries: Vec<Entry<'a>>,
}
#[derive(Debug)]
pub struct Snapshot<'a> {
    pub meta: Meta,
    /// Index zero is the transaction root. Bucket references are indices here.
    pub buckets: Vec<Bucket<'a>>,
    /// All currently reusable pages, excluding live tree/freelist pages.
    pub free: Vec<u64>,
}

enum Location {
    Page(u64),
    Inline(Range<usize>),
}
struct Visit<'a> {
    location: Location,
    bucket: usize,
    depth: usize,
    low: Option<&'a [u8]>,
    high: Option<&'a [u8]>,
}

fn page_span(data: &[u8], meta: &Meta, page: u64) -> Result<Range<usize>> {
    if page < 2 || page >= meta.high_water {
        return Err(Error::Corrupt("page id"));
    }
    let start = usize::try_from(page)
        .map_err(|_| Error::Limit)?
        .checked_mul(meta.page_size)
        .ok_or(Error::Corrupt("page offset"))?;
    if u64le(data, start)? != page {
        return Err(Error::Corrupt("page header id"));
    }
    let count = usize::try_from(u32le(data, start + 12)?)
        .map_err(|_| Error::Limit)?
        .checked_add(1)
        .ok_or(Error::Corrupt("overflow page count"))?;
    let end_page = page
        .checked_add(count as u64)
        .ok_or(Error::Corrupt("overflow page id"))?;
    if end_page > meta.high_water {
        return Err(Error::Corrupt("overflow high water"));
    }
    let len = count
        .checked_mul(meta.page_size)
        .ok_or(Error::Corrupt("overflow byte count"))?;
    range(data, start, len)?;
    Ok(start..start + len)
}

fn mark_span(mark: &mut [u8], span: &Range<usize>, page_size: usize) -> Result<()> {
    for id in span.start / page_size..span.end / page_size {
        let slot = mark.get_mut(id).ok_or(Error::Corrupt("mark range"))?;
        if *slot != 0 {
            return Err(Error::Corrupt("aliased or cyclic page"));
        }
        *slot = 1;
    }
    Ok(())
}

/// Parses every live tree and the freelist, with bounded iterative traversal.
/// No lossy string conversion is performed on bucket names, keys or values.
pub fn parse<'a>(data: &'a [u8], budget: &mut impl Budget) -> Result<Snapshot<'a>> {
    budget.work(1)?;
    let meta = meta::select_meta(data)?;
    let page_count = usize::try_from(meta.high_water).map_err(|_| Error::Limit)?;
    budget.charge(page_count)?;
    let mut marks = Vec::new();
    marks
        .try_reserve_exact(page_count)
        .map_err(|_| Error::Limit)?;
    marks.resize(page_count, 0u8);
    marks[0] = 1;
    marks[1] = 1;
    let mut buckets = Vec::new();
    reserve(&mut buckets, 1, budget)?;
    buckets.push(Bucket {
        sequence: meta.sequence,
        entries: Vec::new(),
    });
    let mut stack = Vec::new();
    reserve(&mut stack, 1, budget)?;
    stack.push(Visit {
        location: Location::Page(meta.root),
        bucket: 0,
        depth: 0,
        low: None,
        high: None,
    });
    while let Some(visit) = stack.pop() {
        budget.work(1)?;
        if visit.depth > 64 {
            return Err(Error::Corrupt("tree depth"));
        }
        let (span, inline) = match visit.location {
            Location::Page(id) => {
                let span = page_span(data, &meta, id)?;
                // Charge/check the marking loop before traversing overflow pages.
                budget.work((span.end - span.start) / meta.page_size)?;
                mark_span(&mut marks, &span, meta.page_size)?;
                (span, false)
            }
            Location::Inline(span) => {
                range(data, span.start, span.len())?;
                if span.len() < 16
                    || u64le(data, span.start)? != 0
                    || u32le(data, span.start + 12)? != 0
                {
                    return Err(Error::Corrupt("inline page header"));
                }
                (span, true)
            }
        };
        let page = &data[span.clone()];
        let flags = u16le(page, 8)?;
        let count = usize::from(u16le(page, 10)?);
        let payload = 16usize
            .checked_add(
                count
                    .checked_mul(16)
                    .ok_or(Error::Corrupt("element count"))?,
            )
            .ok_or(Error::Corrupt("element header"))?;
        range(page, 0, payload)?;
        if flags != 2 && (flags != 1 || inline || count == 0) {
            return Err(Error::Corrupt("tree page type"));
        }
        let mut previous: Option<&[u8]> = None;
        let mut previous_end = payload;
        if flags == 1 {
            reserve(&mut stack, count, budget)?;
        }
        // Parent separator keys are validated before any child is scheduled.
        for i in 0..count {
            budget.work(1)?;
            let element = 16 + i * 16;
            let (pos, key_len, value_len) = if flags == 2 {
                (
                    u32le(page, element + 4)? as usize,
                    u32le(page, element + 8)? as usize,
                    u32le(page, element + 12)? as usize,
                )
            } else {
                (
                    u32le(page, element)? as usize,
                    u32le(page, element + 4)? as usize,
                    0,
                )
            };
            let at = element
                .checked_add(pos)
                .ok_or(Error::Corrupt("element position"))?;
            let size = key_len
                .checked_add(value_len)
                .ok_or(Error::Corrupt("element size"))?;
            if key_len == 0 || at < previous_end {
                return Err(Error::Corrupt("overlapping element"));
            }
            let raw = range(page, at, size)?;
            let key = &raw[..key_len];
            if previous.is_some_and(|old| old >= key) {
                return Err(Error::Corrupt("key order"));
            }
            if visit.low.is_some_and(|low| key < low) || visit.high.is_some_and(|high| key >= high)
            {
                return Err(Error::Corrupt("separator range"));
            }
            if i == 0 && visit.low.is_some_and(|low| key != low) {
                return Err(Error::Corrupt("separator mismatch"));
            }
            previous = Some(key);
            previous_end = at + size;
            if flags == 1 {
                continue;
            }
            let entry_flags = u32le(page, element)?;
            if entry_flags > 1 {
                return Err(Error::Corrupt("leaf flags"));
            }
            let value = if entry_flags == 0 {
                if visit.bucket == 0 {
                    return Err(Error::Corrupt("value in transaction root"));
                }
                Value::Bytes(&raw[key_len..])
            } else {
                let value = &raw[key_len..];
                let root = u64le(value, 0)?;
                let sequence = u64le(value, 8)?;
                let location = if root == 0 {
                    let start = span.start + at + key_len + 16;
                    Location::Inline(start..span.start + at + size)
                } else {
                    if value.len() != 16 {
                        return Err(Error::Corrupt("external bucket header"));
                    }
                    Location::Page(root)
                };
                let child = buckets.len();
                reserve(&mut buckets, 1, budget)?;
                buckets.push(Bucket {
                    sequence,
                    entries: Vec::new(),
                });
                reserve(&mut stack, 1, budget)?;
                stack.push(Visit {
                    location,
                    bucket: child,
                    depth: visit.depth + 1,
                    low: None,
                    high: None,
                });
                Value::Bucket(child)
            };
            let entries = &mut buckets[visit.bucket].entries;
            if entries.last().is_some_and(|e| e.key >= key) {
                return Err(Error::Corrupt("leaf sequence"));
            }
            reserve(entries, 1, budget)?;
            entries.push(Entry { key, value });
        }
        if flags == 1 {
            // LIFO gives left-to-right leaf order without recursion or sorting.
            for i in (0..count).rev() {
                let element = 16 + i * 16;
                let at = element + u32le(page, element)? as usize;
                let key = &page[at..at + u32le(page, element + 4)? as usize];
                let high = if i + 1 < count {
                    let next = element + 16;
                    let start = next + u32le(page, next)? as usize;
                    Some(&page[start..start + u32le(page, next + 4)? as usize])
                } else {
                    visit.high
                };
                stack.push(Visit {
                    location: Location::Page(u64le(page, element + 8)?),
                    bucket: visit.bucket,
                    depth: visit.depth + 1,
                    low: Some(key),
                    high,
                });
            }
        }
    }
    let mut free = Vec::new();
    if meta.freelist != u64::MAX {
        let span = page_span(data, &meta, meta.freelist)?;
        budget.work(span.len() / meta.page_size)?;
        mark_span(&mut marks, &span, meta.page_size)?;
        let page = &data[span];
        if u16le(page, 8)? != 16 {
            return Err(Error::Corrupt("freelist page type"));
        }
        let count = usize::from(u16le(page, 10)?);
        let (count, at) = if count == 0xffff {
            (
                usize::try_from(u64le(page, 16)?).map_err(|_| Error::Limit)?,
                24,
            )
        } else {
            (count, 16)
        };
        if count > page_count {
            return Err(Error::Corrupt("freelist count"));
        }
        range(
            page,
            at,
            count
                .checked_mul(8)
                .ok_or(Error::Corrupt("freelist size"))?,
        )?;
        reserve(&mut free, count, budget)?;
        let mut previous = 1;
        for i in 0..count {
            budget.work(1)?;
            let id = u64le(page, at + i * 8)?;
            if id <= previous || id >= meta.high_water {
                return Err(Error::Corrupt("freelist order"));
            }
            let slot = &mut marks[usize::try_from(id).map_err(|_| Error::Limit)?];
            if *slot != 0 {
                return Err(Error::Corrupt("freelist contains live page"));
            }
            *slot = 2;
            free.push(id);
            previous = id;
        }
        for mark in &marks {
            budget.work(1)?;
            if *mark == 0 {
                return Err(Error::Corrupt("unreachable page"));
            }
        }
    } else {
        // NoFreelistSync databases reconstruct free pages from checked reachability.
        for (id, mark) in marks.iter().enumerate().skip(2) {
            budget.work(1)?;
            if *mark == 0 {
                reserve(&mut free, 1, budget)?;
                free.push(id as u64);
            }
        }
    }
    Ok(Snapshot {
        meta,
        buckets,
        free,
    })
}
