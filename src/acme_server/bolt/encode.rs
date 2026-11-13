//! Full-tree COW encoder. Only pages free in the current committed transaction
//! may be overwritten. Current live pages become free in the NEXT meta, after
//! all replacement data is durable. This also preserves the previous valid
//! meta during data writes. Contiguous-page fragmentation is capacity bounded.
use super::{
    Budget, Error, Meta, Result, Snapshot,
    owned::{Model, OwnedEntry, OwnedValue},
    reserve,
};

pub struct PageWrite {
    pub id: u64,
    pub bytes: Vec<u8>,
}
pub struct Plan {
    pub base: Meta,
    pub meta: Meta,
    pub pages: Vec<PageWrite>,
    pub metadata: [u8; 80],
}
impl Plan {
    /// Independent checked parse before publication. The caller drops this
    /// temporary image before writing; its prepaid lease remains operation-owned.
    pub fn preview(&self, old: &[u8], budget: &mut impl Budget) -> Result<Vec<u8>> {
        let len = usize::try_from(self.meta.high_water)
            .map_err(|_| Error::Limit)?
            .checked_mul(self.meta.page_size)
            .ok_or(Error::Limit)?;
        let mut image = zeros(len.max(old.len()), budget)?;
        budget.work(old.len().div_ceil(64).max(1))?;
        image[..old.len()].copy_from_slice(old);
        for page in &self.pages {
            budget.work(page.bytes.len().div_ceil(64).max(1))?;
            let at = usize::try_from(page.id)
                .map_err(|_| Error::Limit)?
                .checked_mul(self.meta.page_size)
                .ok_or(Error::Limit)?;
            let end = at.checked_add(page.bytes.len()).ok_or(Error::Limit)?;
            image
                .get_mut(at..end)
                .ok_or(Error::Corrupt("preview write range"))?
                .copy_from_slice(&page.bytes);
        }
        let at = self.meta.slot * self.meta.page_size;
        image
            .get_mut(at..at + 80)
            .ok_or(Error::Corrupt("preview meta range"))?
            .copy_from_slice(&self.metadata);
        let parsed = super::parse(&image, budget)?;
        if parsed.meta != self.meta {
            return Err(Error::Corrupt("preview metadata mismatch"));
        }
        drop(parsed);
        Ok(image)
    }
}

struct FreeRun {
    start: usize,
    len: usize,
}
struct Allocator {
    slots: Vec<u8>,
    runs: Vec<FreeRun>,
    cursor: usize,
    page_size: usize,
    max_pages: usize,
}
impl Allocator {
    fn new(snapshot: &Snapshot<'_>, max_bytes: usize, budget: &mut impl Budget) -> Result<Self> {
        let page_size = snapshot.meta.page_size;
        let high = usize::try_from(snapshot.meta.high_water).map_err(|_| Error::Limit)?;
        if high > max_bytes / page_size {
            return Err(Error::Limit);
        }
        budget.charge(high)?;
        let mut slots = Vec::new();
        slots.try_reserve_exact(high).map_err(|_| Error::Limit)?;
        slots.resize(high, 0);
        let mut runs: Vec<FreeRun> = Vec::new();
        for id in &snapshot.free {
            budget.work(1)?;
            let id = usize::try_from(*id).map_err(|_| Error::Limit)?;
            let slot = slots
                .get_mut(id)
                .ok_or(Error::Corrupt("allocator free id"))?;
            if id < 2 || *slot != 0 {
                return Err(Error::Corrupt("allocator duplicate id"));
            }
            *slot = 1;
            if let Some(last) = runs.last_mut().filter(|last| last.start + last.len == id) {
                last.len += 1;
            } else {
                reserve(&mut runs, 1, budget)?;
                runs.push(FreeRun { start: id, len: 1 });
            }
        }
        Ok(Self {
            slots,
            runs,
            cursor: 0,
            page_size,
            max_pages: max_bytes / page_size,
        })
    }
    fn allocate(&mut self, pages: usize, budget: &mut impl Budget) -> Result<u64> {
        if pages == 0 {
            return Err(Error::Corrupt("zero page allocation"));
        }
        while self.cursor < self.runs.len() && self.runs[self.cursor].len == 0 {
            self.cursor += 1;
        }
        for run in &mut self.runs[self.cursor..] {
            budget.work(1)?;
            if run.len >= pages {
                let start = run.start;
                run.start += pages;
                run.len -= pages;
                budget.work(pages)?;
                self.slots[start..start + pages].fill(2);
                return Ok(start as u64);
            }
        }
        let old = self.slots.len();
        let end = old.checked_add(pages).ok_or(Error::Limit)?;
        if end > self.max_pages {
            return Err(Error::Limit);
        }
        reserve(&mut self.slots, pages, budget)?;
        self.slots.resize(end, 2);
        Ok(old as u64)
    }
}

fn zeros(size: usize, budget: &mut impl Budget) -> Result<Vec<u8>> {
    budget.work(size.div_ceil(64).max(1))?;
    budget.charge(size)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Error::Limit)?;
    bytes.resize(size, 0);
    Ok(bytes)
}
fn set16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn set32(bytes: &mut [u8], at: usize, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| Error::Limit)?;
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn set64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn header(bytes: &mut [u8], id: u64, flags: u16, count: usize, page_size: usize) -> Result<()> {
    set64(bytes, 0, id);
    set16(bytes, 8, flags);
    set16(bytes, 10, u16::try_from(count).map_err(|_| Error::Limit)?);
    set32(bytes, 12, bytes.len() / page_size - 1)?;
    Ok(())
}
#[derive(Clone, Copy)]
struct Child<'a> {
    key: &'a [u8],
    id: u64,
}

fn leaf<'a>(
    entries: &'a [OwnedEntry],
    roots: &[u64],
    model: &Model,
    alloc: &mut Allocator,
    writes: &mut Vec<PageWrite>,
    budget: &mut impl Budget,
) -> Result<Vec<Child<'a>>> {
    let mut children = Vec::new();
    let mut first = 0;
    loop {
        let mut end = first;
        let mut size = 16usize;
        while end < entries.len() && end - first < 65535 {
            budget.work(1)?;
            let value_size = match &entries[end].value {
                OwnedValue::Bytes(v) => v.len(),
                OwnedValue::Bucket(_) => 16,
            };
            let next = size
                .checked_add(16)
                .and_then(|n| n.checked_add(entries[end].key.len()))
                .and_then(|n| n.checked_add(value_size))
                .ok_or(Error::Limit)?;
            if end > first && next > alloc.page_size {
                break;
            }
            size = next;
            end += 1;
        }
        let pages = size.div_ceil(alloc.page_size);
        let id = alloc.allocate(pages, budget)?;
        let mut bytes = zeros(
            pages.checked_mul(alloc.page_size).ok_or(Error::Limit)?,
            budget,
        )?;
        header(&mut bytes, id, 2, end - first, alloc.page_size)?;
        let mut at = 16 + (end - first) * 16;
        for (i, entry) in entries[first..end].iter().enumerate() {
            budget.work(entry.key.len().div_ceil(64).max(1))?;
            let element = 16 + i * 16;
            set32(&mut bytes, element + 4, at - element)?;
            set32(&mut bytes, element + 8, entry.key.len())?;
            bytes[at..at + entry.key.len()].copy_from_slice(&entry.key);
            at += entry.key.len();
            match &entry.value {
                OwnedValue::Bytes(value) => {
                    budget.work(value.len().div_ceil(64).max(1))?;
                    set32(&mut bytes, element + 12, value.len())?;
                    bytes[at..at + value.len()].copy_from_slice(value);
                    at += value.len();
                }
                OwnedValue::Bucket(child) => {
                    set32(&mut bytes, element, 1)?;
                    set32(&mut bytes, element + 12, 16)?;
                    set64(&mut bytes, at, roots[*child]);
                    set64(&mut bytes, at + 8, model.buckets[*child].sequence);
                    at += 16;
                }
            }
        }
        reserve(writes, 1, budget)?;
        writes.push(PageWrite { id, bytes });
        reserve(&mut children, 1, budget)?;
        children.push(Child {
            key: entries.get(first).map_or(&[], |entry| entry.key.as_slice()),
            id,
        });
        if end == entries.len() {
            break;
        }
        first = end;
    }
    Ok(children)
}

fn branch<'a>(
    children: &[Child<'a>],
    alloc: &mut Allocator,
    writes: &mut Vec<PageWrite>,
    budget: &mut impl Budget,
) -> Result<Vec<Child<'a>>> {
    let mut parents = Vec::new();
    let mut first = 0;
    while first < children.len() {
        let mut end = first;
        let mut size = 16usize;
        while end < children.len() && end - first < 65535 {
            budget.work(1)?;
            let next = size
                .checked_add(16)
                .and_then(|n| n.checked_add(children[end].key.len()))
                .ok_or(Error::Limit)?;
            // At least two children when available ensures the next level shrinks.
            if end - first >= 2 && next > alloc.page_size {
                break;
            }
            size = next;
            end += 1;
        }
        let pages = size.div_ceil(alloc.page_size);
        let id = alloc.allocate(pages, budget)?;
        let mut bytes = zeros(
            pages.checked_mul(alloc.page_size).ok_or(Error::Limit)?,
            budget,
        )?;
        header(&mut bytes, id, 1, end - first, alloc.page_size)?;
        let mut at = 16 + (end - first) * 16;
        for (i, child) in children[first..end].iter().enumerate() {
            budget.work(child.key.len().div_ceil(64).max(1))?;
            let element = 16 + i * 16;
            set32(&mut bytes, element, at - element)?;
            set32(&mut bytes, element + 4, child.key.len())?;
            set64(&mut bytes, element + 8, child.id);
            bytes[at..at + child.key.len()].copy_from_slice(child.key);
            at += child.key.len();
        }
        reserve(writes, 1, budget)?;
        writes.push(PageWrite { id, bytes });
        reserve(&mut parents, 1, budget)?;
        parents.push(Child {
            key: children[first].key,
            id,
        });
        first = end;
    }
    Ok(parents)
}

pub fn build(
    snapshot: &Snapshot<'_>,
    model: &Model,
    max_file_bytes: usize,
    budget: &mut impl Budget,
) -> Result<Plan> {
    budget.work(1)?;
    if model.buckets.is_empty() {
        return Err(Error::Corrupt("missing writer root"));
    }
    let mut references = zeros(model.buckets.len(), budget)?;
    references[0] = 1;
    for (id, bucket) in model.buckets.iter().enumerate() {
        let mut previous: Option<&[u8]> = None;
        for entry in &bucket.entries {
            budget.work(entry.key.len().div_ceil(64).max(1))?;
            if entry.key.is_empty()
                || entry.key.len() > 32768
                || previous.is_some_and(|p| p >= entry.key.as_slice())
            {
                return Err(Error::Corrupt("writer key order"));
            }
            previous = Some(&entry.key);
            match entry.value {
                OwnedValue::Bucket(child) => {
                    if child <= id || child >= model.buckets.len() || references[child] != 0 {
                        return Err(Error::Corrupt("writer bucket graph"));
                    }
                    references[child] = 1;
                }
                OwnedValue::Bytes(_) if id == 0 => return Err(Error::Corrupt("writer root value")),
                _ => {}
            }
        }
    }
    if references.contains(&0) {
        return Err(Error::Corrupt("writer orphan bucket"));
    }
    let mut alloc = Allocator::new(snapshot, max_file_bytes, budget)?;
    let mut roots = Vec::new();
    reserve(&mut roots, model.buckets.len(), budget)?;
    roots.resize(model.buckets.len(), 0u64);
    let mut pages = Vec::new();
    for id in (0..model.buckets.len()).rev() {
        budget.work(1)?;
        let mut children = leaf(
            &model.buckets[id].entries,
            &roots,
            model,
            &mut alloc,
            &mut pages,
            budget,
        )?;
        let mut depth = 0;
        while children.len() > 1 {
            budget.work(1)?;
            depth += 1;
            if depth > 64 {
                return Err(Error::Limit);
            }
            children = branch(&children, &mut alloc, &mut pages, budget)?;
        }
        roots[id] = children[0].id;
    }
    // Conservative upper bound includes possible appended freelist pages. Any
    // padding is legal overflow space; it does not create an endless append loop.
    let free_bytes = alloc
        .slots
        .len()
        .checked_mul(8)
        .and_then(|n| n.checked_add(24))
        .ok_or(Error::Limit)?;
    let free_pages = free_bytes.div_ceil(alloc.page_size - 8).max(1);
    let freelist = alloc.allocate(free_pages, budget)?;
    budget.work(alloc.slots.len())?;
    let count = alloc.slots.iter().skip(2).filter(|v| **v != 2).count();
    let mut bytes = zeros(
        free_pages
            .checked_mul(alloc.page_size)
            .ok_or(Error::Limit)?,
        budget,
    )?;
    header(&mut bytes, freelist, 16, count.min(65535), alloc.page_size)?;
    let mut at = 16;
    if count >= 65535 {
        set64(&mut bytes, at, count as u64);
        at += 8;
    }
    if count
        .checked_mul(8)
        .and_then(|n| n.checked_add(at))
        .is_none_or(|n| n > bytes.len())
    {
        return Err(Error::Limit);
    }
    for (id, state) in alloc.slots.iter().enumerate().skip(2) {
        budget.work(1)?;
        if *state != 2 {
            set64(&mut bytes, at, id as u64);
            at += 8;
        }
    }
    reserve(&mut pages, 1, budget)?;
    pages.push(PageWrite {
        id: freelist,
        bytes,
    });
    let txid = snapshot.meta.txid.checked_add(1).ok_or(Error::Limit)?;
    let meta = Meta {
        page_size: alloc.page_size,
        root: roots[0],
        sequence: model.buckets[0].sequence,
        freelist,
        high_water: alloc.slots.len() as u64,
        txid,
        slot: (txid % 2) as usize,
    };
    let metadata = super::meta::encode(&meta)?;
    Ok(Plan {
        base: snapshot.meta.clone(),
        meta,
        pages,
        metadata,
    })
}
