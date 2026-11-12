// Behavioral port of regexp2 v2.2.1 capture histories (MIT).
#[derive(Debug, serde::Serialize)]
pub enum Error {
    Resource,
    Invalid(String),
    Charge(String),
}
impl From<&str> for Error {
    fn from(x: &str) -> Self {
        Self::Invalid(x.to_owned())
    }
}
impl From<String> for Error {
    fn from(x: String) -> Self {
        Self::Invalid(x)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub struct Captures {
    counts: Vec<usize>,
    matches: Vec<Vec<i32>>,
    crawl: Vec<usize>,
    allocated_words: usize,
    reserved_words: usize,
    max_words: usize,
    balancing: bool,
}
const USIZE_WORDS: usize = std::mem::size_of::<usize>() / 4;
impl Captures {
    pub fn empty() -> Self {
        Self {
            counts: Vec::new(),
            matches: Vec::new(),
            crawl: Vec::new(),
            allocated_words: 0,
            reserved_words: 0,
            max_words: 0,
            balancing: false,
        }
    }
    pub fn new(
        slots: usize,
        max_words: usize,
        charge: &mut dyn FnMut(usize) -> Result<(), String>,
    ) -> Result<Self, Error> {
        let base = slots
            .checked_mul(USIZE_WORDS + std::mem::size_of::<Vec<i32>>() / 4)
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>() / 4))
            .ok_or(Error::Resource)?;
        if base > max_words {
            return Err(Error::Resource);
        }
        charge(base).map_err(Error::Charge)?;
        Ok(Self {
            counts: vec![0; slots],
            matches: (0..slots).map(|_| Vec::new()).collect(),
            crawl: Vec::new(),
            allocated_words: base,
            reserved_words: base,
            max_words,
            balancing: false,
        })
    }
    pub fn reset(&mut self) {
        self.balancing = false;
        self.counts.fill(0);
        self.crawl.clear();
    }
    pub fn is_matched(&self, slot: usize) -> bool {
        self.counts
            .get(slot)
            .is_some_and(|n| *n > 0 && self.matches[slot][*n * 2 - 1] != -2)
    }
    fn indirect(&self, slot: usize, index: usize) -> Result<i32, Error> {
        let values = self.matches.get(slot).ok_or("capture slot out of range")?;
        let value = *values.get(index).ok_or("capture history out of range")?;
        if value >= 0 {
            return Ok(value);
        }
        let index: usize = (-3i64 - i64::from(value))
            .try_into()
            .map_err(|_| "invalid capture history link")?;
        values
            .get(index)
            .copied()
            .filter(|v| *v >= 0)
            .ok_or_else(|| "invalid capture history link".into())
    }
    pub fn last(&self, slot: usize) -> Result<Option<(usize, usize)>, Error> {
        let count = *self.counts.get(slot).ok_or("capture slot out of range")?;
        if !self.is_matched(slot) {
            return Ok(None);
        }
        let index = self.indirect(slot, count * 2 - 2)?;
        let length = self.indirect(slot, count * 2 - 1)?;
        Ok(Some((index as usize, length as usize)))
    }
    fn reserve(
        &mut self,
        adds: &[(usize, usize)],
        crawl_add: usize,
        charge: &mut dyn FnMut(usize) -> Result<(), String>,
    ) -> Result<(), Error> {
        if adds.len() > 2 {
            return Err("capture reservation arity".into());
        }
        let mut plans = [(0usize, 0usize); 2];
        let mut plan_count = 0usize;
        for &(slot, add) in adds {
            let old = *self.counts.get(slot).ok_or("capture slot out of range")?;
            if let Some((_, n)) = plans[..plan_count].iter_mut().find(|(s, _)| *s == slot) {
                *n = n.checked_add(add).ok_or(Error::Resource)?;
            } else {
                plans[plan_count] = (slot, old.checked_add(add).ok_or(Error::Resource)?);
                plan_count += 1;
            }
        }
        let mut delta = 0usize;
        for (slot, count) in &mut plans[..plan_count] {
            let need = count.checked_mul(2).ok_or(Error::Resource)?;
            *count = if need > self.matches[*slot].len() {
                need.checked_next_power_of_two()
                    .ok_or(Error::Resource)?
                    .max(2)
            } else {
                self.matches[*slot].len()
            };
            delta = delta
                .checked_add(if *count > self.matches[*slot].capacity() { *count } else { 0 })
                .ok_or(Error::Resource)?;
        }
        let crawl_need = self
            .crawl
            .len()
            .checked_add(crawl_add)
            .ok_or(Error::Resource)?;
        let crawl_cap = if crawl_need > self.crawl.capacity() {
            crawl_need
                .checked_next_power_of_two()
                .ok_or(Error::Resource)?
        } else {
            self.crawl.capacity()
        };
        delta = delta
            .checked_add(
                (if crawl_cap > self.crawl.capacity() { crawl_cap } else { 0 })
                    .checked_mul(USIZE_WORDS)
                    .ok_or(Error::Resource)?,
            )
            .ok_or(Error::Resource)?;
        let total = self
            .reserved_words
            .checked_add(delta)
            .ok_or(Error::Resource)?;
        if total > self.max_words {
            return Err(Error::Resource);
        }
        charge(delta).map_err(Error::Charge)?;
        // Reserve the complete new buffers while old allocations remain live.
        // This is a cumulative attempt quota, not a live-allocation counter.
        // A successful reservation remains consumed even if an allocator fails;
        // partial capacities never permit a later uncharged publication.
        self.reserved_words = total;
        // Only capacities may change if a later allocator operation fails.
        for &(slot, len) in &plans[..plan_count] {
            let values = &mut self.matches[slot];
            let old = values.capacity();
            if len > values.len() {
                values
                    .try_reserve_exact(len - values.len())
                    .map_err(|_| Error::Resource)?;
            }
            self.allocated_words += values.capacity() - old;
        }
        let old = self.crawl.capacity();
        if crawl_need > old {
            self.crawl
                .try_reserve_exact(crawl_cap - self.crawl.len())
                .map_err(|_| Error::Resource)?;
        }
        self.allocated_words += (self.crawl.capacity() - old) * USIZE_WORDS;
        if self.allocated_words > self.reserved_words {
            return Err(Error::Resource);
        }
        for &(slot, len) in &plans[..plan_count] {
            self.matches[slot].resize(len, 0);
        }
        Ok(())
    }
    fn add_reserved(&mut self, slot: usize, start: i32, length: i32) {
        let count = self.counts[slot];
        self.matches[slot][count * 2] = start;
        self.matches[slot][count * 2 + 1] = length;
        self.counts[slot] += 1;
    }
    pub fn capture(
        &mut self,
        slot: usize,
        start: i32,
        end: i32,
        charge: &mut dyn FnMut(usize) -> Result<(), String>,
    ) -> Result<(), Error> {
        if start < 0 || end < 0 {
            return Err("negative capture position".into());
        }
        let (start, end) = (start.min(end), start.max(end));
        self.reserve(&[(slot, 1)], 1, charge)?;
        self.crawl.push(slot);
        self.add_reserved(slot, start, end - start);
        Ok(())
    }
    pub fn transfer(
        &mut self,
        capnum: i32,
        uncapnum: usize,
        start: i32,
        end: i32,
        charge: &mut dyn FnMut(usize) -> Result<(), String>,
    ) -> Result<(), Error> {
        if capnum < -1 || start < 0 || end < 0 {
            return Err("invalid capture transfer".into());
        }
        let (mut start, mut end) = (start.min(end), start.max(end));
        let (start2, length2) = self
            .last(uncapnum)?
            .ok_or("capture transfer source is unmatched")?;
        let start2 = i32::try_from(start2).map_err(|_| "capture position overflow")?;
        let end2 = start2
            .checked_add(i32::try_from(length2).map_err(|_| "capture length overflow")?)
            .ok_or("capture position overflow")?;
        if start >= end2 {
            end = start;
            start = end2;
        } else if end <= start2 {
            start = start2;
        } else {
            end = end.min(end2);
            start = start.max(start2);
        }
        let mut target =
            i64::try_from(self.counts[uncapnum] * 2 - 2).map_err(|_| "capture size overflow")?;
        let raw = self.matches[uncapnum][target as usize];
        if raw < 0 {
            target = -3 - i64::from(raw);
        }
        target -= 2;
        let (a, b) = if target >= 0 {
            let at = usize::try_from(target).map_err(|_| "capture link overflow")?;
            let a = *self.matches[uncapnum]
                .get(at)
                .ok_or("capture link out of range")?;
            if a < 0 {
                (
                    a,
                    *self.matches[uncapnum]
                        .get(at + 1)
                        .ok_or("capture link out of range")?,
                )
            } else {
                (
                    i32::try_from(-3 - target).map_err(|_| "capture link overflow")?,
                    i32::try_from(-4 - target).map_err(|_| "capture link overflow")?,
                )
            }
        } else {
            (
                i32::try_from(-3 - target).map_err(|_| "capture link overflow")?,
                i32::try_from(-4 - target).map_err(|_| "capture link overflow")?,
            )
        };
        let adds = [(uncapnum, 1), (capnum.max(0) as usize, 1)];
        let n = if capnum >= 0 { 2 } else { 1 };
        self.reserve(&adds[..n], n, charge)?;
        self.balancing = true;
        self.crawl.push(uncapnum);
        self.add_reserved(uncapnum, a, b);
        if capnum >= 0 {
            self.crawl.push(capnum as usize);
            self.add_reserved(capnum as usize, start, end - start);
        }
        Ok(())
    }
    pub fn tidy(
        &mut self,
        check: &mut dyn FnMut(usize) -> Result<(), String>,
    ) -> Result<(), Error> {
        if !self.balancing {
            return Ok(());
        }
        for slot in 0..self.counts.len() {
            let limit = self.counts[slot] * 2;
            check(limit).map_err(Error::Charge)?;
            let values = &mut self.matches[slot];
            let mut i = 0;
            while i < limit && values[i] >= 0 {
                i += 1;
            }
            let mut j = i;
            while i < limit {
                if values[i] < 0 {
                    j = j.checked_sub(1).ok_or("invalid balanced capture history")?;
                } else {
                    if i != j {
                        values[j] = values[i];
                    }
                    j += 1;
                }
                i += 1;
            }
            if j % 2 != 0 {
                return Err("odd balanced capture history".into());
            }
            self.counts[slot] = j / 2;
        }
        self.balancing = false;
        Ok(())
    }
    pub fn uncapture(&mut self) -> Result<(), Error> {
        let slot = *self.crawl.last().ok_or("capture crawl underflow")?;
        if self.counts[slot] == 0 {
            return Err("capture count underflow".into());
        }
        self.crawl.pop();
        self.counts[slot] -= 1;
        Ok(())
    }
    pub fn crawl_pos(&self) -> usize {
        self.crawl.len()
    }
    pub fn uncapture_until(&mut self, pos: usize) -> Result<(), Error> {
        if pos > self.crawl.len() {
            return Err("capture crawl position out of range".into());
        }
        while self.crawl.len() > pos {
            self.uncapture()?;
        }
        Ok(())
    }
}
