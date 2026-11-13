//! Synchronous, exclusively-owned transaction engine. Its serving actor must
//! retain the operation's byte/work owner through the real worker and output.
//! No user callback is admitted; callers are the closed native controller.
use super::{
    bolt::{
        self, Budget,
        owned::{Model, OwnedValue},
    },
    records::Record,
};
use std::{
    io::{self, Write},
    path::Path,
    time::Duration,
};

#[derive(Debug)]
pub enum Error {
    Storage(bolt::Error),
    Record(&'static str),
    Json(serde_json::Error),
}
impl From<bolt::Error> for Error {
    fn from(e: bolt::Error) -> Self {
        Self::Storage(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Record(s) => write!(f, "invalid ACME record: {s}"),
            Self::Json(_) => f.write_str("invalid ACME record JSON"),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub(super) struct Database {
    file: bolt::file::LockedFile,
    max_file: usize,
    max_record: usize,
}
impl Database {
    pub fn retained_bytes(&self) -> usize {
        self.file.retained_bytes() + std::mem::size_of::<Self>()
    }
    pub fn open(
        path: &Path,
        max_file: usize,
        max_record: usize,
        timeout: Duration,
        budget: &mut impl Budget,
    ) -> Result<Self> {
        if max_file < 16384 || max_record == 0 || max_record > max_file {
            return Err(bolt::Error::Limit.into());
        }
        let mut file = bolt::file::LockedFile::open(path, true, timeout, budget)?;
        let image = file.snapshot(max_file, budget)?;
        if image.is_empty() {
            file.initialize(4096, budget)?;
        } else {
            drop(bolt::parse(&image, budget)?);
        }
        Ok(Self {
            file,
            max_file,
            max_record,
        })
    }
    pub fn transaction<B: Budget, R: Send + 'static>(
        &mut self,
        budget: &mut B,
        operation: impl FnOnce(&mut Transaction<'_, B>) -> Result<R>,
    ) -> Result<R> {
        self.file.recover_if_needed(self.max_file, budget)?;
        let image = self.file.snapshot(self.max_file, budget)?;
        let snapshot = bolt::parse(&image, budget)?;
        let mut model = Model::copy(&snapshot, budget)?;
        let (result, dirty) = {
            let mut tx = Transaction {
                model: &mut model,
                budget,
                max_record: self.max_record,
                dirty: false,
            };
            let result = operation(&mut tx)?;
            (result, tx.dirty)
        };
        if dirty {
            let plan = bolt::encode::build(&snapshot, &model, self.max_file, budget)?;
            self.file.commit(&image, &plan, budget)?;
        }
        Ok(result)
    }
}

pub(super) struct Transaction<'a, B> {
    model: &'a mut Model,
    budget: &'a mut B,
    max_record: usize,
    dirty: bool,
}
impl<B: Budget> Transaction<'_, B> {
    pub fn bind_authority(&mut self, authority: &str) -> Result<()> {
        const TABLE: &[u8] = b"_native_caddy_acme_metadata_v1";
        if let Some(stored) = self.bytes(TABLE, b"authority")? {
            if stored != authority.as_bytes() {
                return Err(Error::Record("authority storage identity mismatch"));
            }
            return Ok(());
        }
        // Old Caddy databases have no native marker. Check their actual account
        // provenance before adopting one sanitized path; never silently import a
        // different CA's accounts after a case/punctuation collision.
        if let Some(id) = self.model.root_bucket(b"acme_accounts") {
            for entry in &self
                .model
                .buckets
                .get(id)
                .ok_or(Error::Record("account table index"))?
                .entries
            {
                self.budget.work(1)?;
                let OwnedValue::Bytes(bytes) = &entry.value else {
                    return Err(Error::Record("account is nested bucket"));
                };
                if bytes.len() > self.max_record {
                    return Err(bolt::Error::Limit.into());
                }
                self.budget.charge(
                    bytes
                        .len()
                        .checked_mul(64)
                        .and_then(|n| n.checked_add(4096))
                        .ok_or(bolt::Error::Limit)?,
                )?;
                let account: super::records::DbAccount =
                    serde_json::from_slice(bytes).map_err(Error::Json)?;
                if account.provisioner_name != authority {
                    return Err(Error::Record(
                        "legacy account authority cannot be established",
                    ));
                }
            }
        }
        self.put_raw(TABLE, b"authority", authority.as_bytes())
    }
    pub fn authorizes_names(
        &mut self,
        account: &str,
        needed: &mut Vec<(String, String)>,
    ) -> Result<bool> {
        let Some(id) = self.model.root_bucket(b"acme_authzs") else {
            return Ok(needed.is_empty());
        };
        for entry in &self
            .model
            .buckets
            .get(id)
            .ok_or(Error::Record("authorization table index"))?
            .entries
        {
            if needed.is_empty() {
                return Ok(true);
            }
            self.budget.work(1)?;
            let OwnedValue::Bytes(bytes) = &entry.value else {
                return Err(Error::Record("authorization is nested bucket"));
            };
            if bytes.len() > self.max_record {
                return Err(bolt::Error::Limit.into());
            }
            self.budget.charge(
                bytes
                    .len()
                    .checked_mul(64)
                    .and_then(|n| n.checked_add(4096))
                    .ok_or(bolt::Error::Limit)?,
            )?;
            let authorization: super::records::DbAuthz =
                serde_json::from_slice(bytes).map_err(Error::Json)?;
            if authorization.account_id != account || authorization.status != "valid" {
                continue;
            }
            let expires = time::OffsetDateTime::parse(
                &authorization.expires_at,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| Error::Record("authorization expiry"))?;
            if expires < time::OffsetDateTime::now_utc() {
                continue;
            }
            let value = if authorization.wildcard {
                format!("*.{}", authorization.identifier.value)
            } else {
                authorization.identifier.value
            };
            needed.retain(|(kind, name)| {
                if *kind != authorization.identifier.kind {
                    return true;
                }
                if kind == "ip" {
                    return name
                        .parse::<std::net::IpAddr>()
                        .ok()
                        .map(|ip| ip.to_canonical())
                        != value
                            .parse::<std::net::IpAddr>()
                            .ok()
                            .map(|ip| ip.to_canonical());
                }
                !name.eq_ignore_ascii_case(&value)
            });
        }
        Ok(needed.is_empty())
    }
    fn bytes(&mut self, table: &[u8], key: &[u8]) -> Result<Option<&[u8]>> {
        self.budget.work(1)?;
        let Some(id) = self.model.root_bucket(table) else {
            return Ok(None);
        };
        let entries = &self
            .model
            .buckets
            .get(id)
            .ok_or(Error::Record("table index"))?
            .entries;
        let Ok(i) = entries.binary_search_by(|entry| entry.key.as_slice().cmp(key)) else {
            return Ok(None);
        };
        match &entries[i].value {
            OwnedValue::Bytes(value) => Ok(Some(value)),
            OwnedValue::Bucket(_) => Err(Error::Record("nested value in record table")),
        }
    }
    pub fn contains(&mut self, table: &[u8], key: &[u8]) -> Result<bool> {
        Ok(self.bytes(table, key)?.is_some())
    }
    pub fn get<T: Record>(&mut self, table: &[u8], key: &[u8]) -> Result<Option<T>> {
        self.budget.work(1)?;
        let Some(id) = self.model.root_bucket(table) else {
            return Ok(None);
        };
        let entries = &self
            .model
            .buckets
            .get(id)
            .ok_or(Error::Record("table index"))?
            .entries;
        let Ok(index) = entries.binary_search_by(|entry| entry.key.as_slice().cmp(key)) else {
            return Ok(None);
        };
        let OwnedValue::Bytes(bytes) = &entries[index].value else {
            return Err(Error::Record("record is nested bucket"));
        };
        if bytes.len() > self.max_record {
            return Err(bolt::Error::Limit.into());
        }
        self.budget.work(bytes.len().div_ceil(16).max(1))?;
        self.budget.charge(
            bytes
                .len()
                .checked_mul(64)
                .and_then(|n| n.checked_add(4096))
                .ok_or(bolt::Error::Limit)?,
        )?;
        serde_json::from_slice(bytes).map(Some).map_err(Error::Json)
    }
    pub fn index(&mut self, table: &[u8], key: &[u8]) -> Result<Option<String>> {
        self.budget.work(1)?;
        let Some(id) = self.model.root_bucket(table) else {
            return Ok(None);
        };
        let entries = &self
            .model
            .buckets
            .get(id)
            .ok_or(Error::Record("table index"))?
            .entries;
        let Ok(index) = entries.binary_search_by(|entry| entry.key.as_slice().cmp(key)) else {
            return Ok(None);
        };
        let OwnedValue::Bytes(bytes) = &entries[index].value else {
            return Err(Error::Record("index is bucket"));
        };
        if bytes.is_empty() || bytes.len() > 128 || !bytes.iter().all(u8::is_ascii_alphanumeric) {
            return Err(Error::Record("index account identifier"));
        }
        self.budget.charge(bytes.len())?;
        let mut value = String::new();
        value
            .try_reserve_exact(bytes.len())
            .map_err(|_| bolt::Error::Limit)?;
        value.push_str(
            std::str::from_utf8(bytes).map_err(|_| Error::Record("index account identifier"))?,
        );
        Ok(Some(value))
    }
    pub fn put<T: Record>(&mut self, table: &[u8], key: &[u8], record: &T) -> Result<()> {
        let bytes = encode(record, self.max_record, self.budget)?;
        self.put_raw(table, key, &bytes)
    }
    pub fn put_raw(&mut self, table: &[u8], key: &[u8], value: &[u8]) -> Result<()> {
        if value.len() > self.max_record {
            return Err(bolt::Error::Limit.into());
        }
        let id = self.model.ensure_root_bucket(table, self.budget)?;
        self.model.put(id, key, value, self.budget)?;
        self.dirty = true;
        Ok(())
    }
    pub fn delete(&mut self, table: &[u8], key: &[u8]) -> Result<bool> {
        let Some(id) = self.model.root_bucket(table) else {
            return Ok(false);
        };
        let deleted = self.model.delete(id, key, self.budget)?;
        self.dirty |= deleted;
        Ok(deleted)
    }
    pub fn consume_nonce(&mut self, key: &[u8]) -> Result<bool> {
        // Pinned Smallstep only checks existence and deletes in one transaction; it
        // does not decode CreatedAt or impose a TTL. Preserve that old-state behavior.
        if !self.contains(b"nonces", key)? {
            return Ok(false);
        };
        self.delete(b"nonces", key)
    }
}

struct Output<'a, B> {
    bytes: Vec<u8>,
    limit: usize,
    budget: &'a mut B,
    failure: Option<bolt::Error>,
}
impl<B: Budget> Write for Output<'_, B> {
    fn write(&mut self, chunk: &[u8]) -> io::Result<usize> {
        let fail = || io::Error::other("ACME output capacity exceeded");
        if let Err(e) = self.budget.work(chunk.len().div_ceil(64).max(1)) {
            self.failure = Some(e);
            return Err(fail());
        }
        let Some(size) = self
            .bytes
            .len()
            .checked_add(chunk.len())
            .filter(|n| *n <= self.limit)
        else {
            self.failure = Some(bolt::Error::Limit);
            return Err(fail());
        };
        if size > self.bytes.capacity() {
            let capacity = size
                .max(self.bytes.capacity().saturating_mul(2))
                .max(256)
                .min(self.limit);
            if let Err(e) = self.budget.charge(capacity) {
                self.failure = Some(e);
                return Err(fail());
            }
            if self
                .bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .is_err()
            {
                self.failure = Some(bolt::Error::Limit);
                return Err(fail());
            }
        }
        self.bytes.extend_from_slice(chunk);
        Ok(chunk.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode<T: Record>(record: &T, limit: usize, budget: &mut impl Budget) -> Result<Vec<u8>> {
    budget.work(1)?;
    budget.charge(record.scratch_bytes().ok_or(bolt::Error::Limit)?)?;
    let mut output = Output {
        bytes: Vec::new(),
        limit,
        budget,
        failure: None,
    };
    let result = serde_json::to_writer(&mut output, record);
    if let Some(e) = output.failure {
        return Err(e.into());
    };
    result.map_err(Error::Json)?;
    Ok(output.bytes)
}
