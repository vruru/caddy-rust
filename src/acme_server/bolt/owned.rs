//! Owned, non-recursive transaction model. Raw unknown records are preserved.
use super::{Budget, Error, Result, Snapshot, Value, reserve};

#[derive(Debug)]
pub struct Model {
    pub buckets: Vec<OwnedBucket>,
}
#[derive(Debug)]
pub struct OwnedBucket {
    pub sequence: u64,
    pub entries: Vec<OwnedEntry>,
}
#[derive(Debug)]
pub struct OwnedEntry {
    pub key: Vec<u8>,
    pub value: OwnedValue,
}
#[derive(Debug)]
pub enum OwnedValue {
    Bytes(Vec<u8>),
    Bucket(usize),
}

fn copy_bytes(src: &[u8], budget: &mut impl Budget) -> Result<Vec<u8>> {
    budget.work(src.len().div_ceil(64).max(1))?;
    budget.charge(src.len())?;
    let mut dst = Vec::new();
    dst.try_reserve_exact(src.len()).map_err(|_| Error::Limit)?;
    dst.extend_from_slice(src);
    Ok(dst)
}

impl Model {
    pub fn copy(snapshot: &Snapshot<'_>, budget: &mut impl Budget) -> Result<Self> {
        if snapshot.buckets.is_empty() {
            return Err(Error::Corrupt("missing root"));
        }
        let mut buckets = Vec::new();
        reserve(&mut buckets, snapshot.buckets.len(), budget)?;
        for old in &snapshot.buckets {
            budget.work(1)?;
            let mut entries = Vec::new();
            reserve(&mut entries, old.entries.len(), budget)?;
            for entry in &old.entries {
                budget.work(1)?;
                let key = copy_bytes(entry.key, budget)?;
                let value = match entry.value {
                    Value::Bytes(raw) => OwnedValue::Bytes(copy_bytes(raw, budget)?),
                    Value::Bucket(index) => OwnedValue::Bucket(index),
                };
                entries.push(OwnedEntry { key, value });
            }
            buckets.push(OwnedBucket {
                sequence: old.sequence,
                entries,
            });
        }
        Ok(Self { buckets })
    }

    pub fn root_bucket(&self, name: &[u8]) -> Option<usize> {
        let entries = &self.buckets.first()?.entries;
        let index = entries
            .binary_search_by(|entry| entry.key.as_slice().cmp(name))
            .ok()?;
        match entries[index].value {
            OwnedValue::Bucket(id) => Some(id),
            _ => None,
        }
    }

    pub fn ensure_root_bucket(&mut self, name: &[u8], budget: &mut impl Budget) -> Result<usize> {
        budget.work(1)?;
        if name.is_empty() || name.len() > 32768 {
            return Err(Error::Corrupt("bucket name"));
        }
        let root = self.buckets.first().ok_or(Error::Corrupt("missing root"))?;
        let index = match root
            .entries
            .binary_search_by(|entry| entry.key.as_slice().cmp(name))
        {
            Ok(index) => {
                return match root.entries[index].value {
                    OwnedValue::Bucket(id) => Ok(id),
                    _ => Err(Error::Corrupt("bucket is value")),
                };
            }
            Err(index) => index,
        };
        let key = copy_bytes(name, budget)?;
        reserve(&mut self.buckets[0].entries, 1, budget)?;
        reserve(&mut self.buckets, 1, budget)?;
        // All fallible steps are complete before changing the logical model.
        let id = self.buckets.len();
        self.buckets.push(OwnedBucket {
            sequence: 0,
            entries: Vec::new(),
        });
        self.buckets[0].entries.insert(
            index,
            OwnedEntry {
                key,
                value: OwnedValue::Bucket(id),
            },
        );
        Ok(id)
    }

    pub fn put(
        &mut self,
        bucket: usize,
        key: &[u8],
        value: &[u8],
        budget: &mut impl Budget,
    ) -> Result<()> {
        budget.work(1)?;
        if bucket == 0 || key.is_empty() || key.len() > 32768 {
            return Err(Error::Corrupt("value key"));
        }
        let entries = &mut self
            .buckets
            .get_mut(bucket)
            .ok_or(Error::Corrupt("bucket index"))?
            .entries;
        let found = entries.binary_search_by(|entry| entry.key.as_slice().cmp(key));
        if found.is_ok_and(|i| matches!(entries[i].value, OwnedValue::Bucket(_))) {
            return Err(Error::Corrupt("value is bucket"));
        }
        let value = OwnedValue::Bytes(copy_bytes(value, budget)?);
        match found {
            Ok(index) => entries[index].value = value,
            Err(index) => {
                let key = copy_bytes(key, budget)?;
                reserve(entries, 1, budget)?;
                entries.insert(index, OwnedEntry { key, value });
            }
        }
        Ok(())
    }

    pub fn delete(&mut self, bucket: usize, key: &[u8], budget: &mut impl Budget) -> Result<bool> {
        budget.work(1)?;
        let entries = &mut self
            .buckets
            .get_mut(bucket)
            .ok_or(Error::Corrupt("bucket index"))?
            .entries;
        let Ok(index) = entries.binary_search_by(|entry| entry.key.as_slice().cmp(key)) else {
            return Ok(false);
        };
        if matches!(entries[index].value, OwnedValue::Bucket(_)) {
            return Err(Error::Corrupt("cannot delete bucket"));
        }
        entries.remove(index);
        Ok(true)
    }
}
