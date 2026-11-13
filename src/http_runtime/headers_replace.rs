//! Ordered byte-preserving HeaderOps replacement with real allocation owners.
use super::{
    placeholder_value::{self, Dynamic},
    request::{Context, ReplacerView, failure},
    resource_budget::BlockingBudget,
};
use crate::{
    go_regexp::{GoRegexp, ReplaceBudget, Replacement},
    http_config::{helpers::replace_bytes_accounted, types::HeaderOps},
};
use anyhow::{Result, ensure};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use native_write_policy::{Lease, Pool};
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
const CAP: usize = 4 << 20;
#[derive(Clone, Copy)]
pub(super) enum Scope {
    Original,
    Request,
}
struct Ledger {
    pool: Pool,
    leases: RefCell<Vec<Lease>>,
}
impl Ledger {
    fn new(pool: Pool) -> Self {
        Self {
            pool,
            leases: RefCell::new(Vec::new()),
        }
    }
    fn pay(&self, n: usize) -> Result<()> {
        self.leases
            .borrow_mut()
            .push(self.pool.reserve(n.checked_add(128).ok_or_else(limit)?)?);
        Ok(())
    }
}
struct Expanded {
    bytes: Vec<u8>,
    _leases: Vec<Lease>,
}
#[derive(Clone, Copy)]
enum Entry {
    Value(usize, usize),
    Unknown,
    Header,
    Global,
    Dynamic,
}
struct Snapshot {
    data: Vec<u8>,
    entries: Vec<Entry>,
    keys: Arc<[String]>,
    dynamic: Dynamic,
    pool: Pool,
    // Immutable after capture: real arena/entry allocations precede credits.
    _leases: Vec<Lease>,
}

fn limit() -> anyhow::Error {
    failure(StatusCode::SERVICE_UNAVAILABLE)
}
fn join(fields: &HeaderMap, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, v) in fields.get_all(name).iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(v.as_bytes());
    }
    out
}
impl Snapshot {
    async fn capture(
        view: ReplacerView<'_>,
        ops: &HeaderOps,
        scope: Scope,
        pool: Pool,
        dynamic: Dynamic,
    ) -> Result<Self> {
        let ledger = Ledger::new(pool.clone());
        ledger.pay(ops.replace_keys.len() * std::mem::size_of::<Entry>() + 1024)?;
        let mut this = Self {
            data: Vec::new(),
            entries: Vec::with_capacity(ops.replace_keys.len()),
            keys: ops.replace_keys.clone(),
            dynamic,
            pool,
            _leases: Vec::new(),
        };
        for (index, name) in ops.replace_keys.iter().enumerate() {
            if index > 0 && index.is_multiple_of(128) {
                tokio::task::yield_now().await;
            }
            let entry = if placeholder_value::is_global(name) {
                Entry::Global
            } else if let Some(value) = view
                .value(name)
                .filter(|_| !name.starts_with("http.regexp."))
            {
                ensure!(value.len() <= CAP, "header placeholder exceeds limit");
                this.store(value.as_bytes(), &ledger)?
            } else if matches!(scope, Scope::Request) && name.starts_with("http.request.header.") {
                Entry::Header
            } else if this.dynamic.get(name).is_some() {
                Entry::Dynamic
            } else {
                let _temporary = this.pool.reserve(8 << 20)?;
                let value = if let Some(field) = name.strip_prefix("http.request.header.") {
                    Some(if field.eq_ignore_ascii_case("Host") {
                        Vec::new()
                    } else {
                        view.headers()
                            .map_or_else(Vec::new, |fields| join(fields, field))
                    })
                } else {
                    view.lookup_bytes(name)
                };
                if let Some(value) = value {
                    this.store(&value, &ledger)?
                } else {
                    Entry::Unknown
                }
            };
            this.entries.push(entry);
        }
        this._leases = ledger.leases.into_inner();
        Ok(this)
    }
    fn store(&mut self, value: &[u8], ledger: &Ledger) -> Result<Entry> {
        let at = self.data.len();
        let size = at
            .checked_add(value.len())
            .filter(|n| *n <= CAP)
            .ok_or_else(limit)?;
        if size > self.data.capacity() {
            let next = self
                .data
                .capacity()
                .saturating_mul(2)
                .max(size)
                .max(64)
                .min(CAP);
            ledger.pay(next * 2)?;
            self.data.try_reserve_exact(next - self.data.len())?;
        }
        self.data.extend_from_slice(value);
        Ok(Entry::Value(at, value.len()))
    }
    fn get(&self, fields: &HeaderMap, name: &str, ledger: &Ledger) -> Result<Option<Vec<u8>>> {
        let Some(i) = self
            .keys
            .binary_search_by(|key| key.as_str().cmp(name))
            .ok()
        else {
            return Ok(None);
        };
        Ok(match self.entries[i] {
            Entry::Unknown => None,
            Entry::Value(at, n) => {
                ledger.pay(n * 2)?;
                Some(self.data[at..at + n].to_vec())
            }
            Entry::Header => {
                let key = name.strip_prefix("http.request.header.").unwrap();
                let n = fields
                    .get_all(key)
                    .iter()
                    .try_fold(0usize, |n, v| n.checked_add(v.len() + 1))
                    .filter(|n| *n <= CAP)
                    .ok_or_else(limit)?;
                ledger.pay(n * 2 + 64)?;
                Some(join(fields, key))
            }
            Entry::Global => {
                let _temporary = self.pool.reserve(4 << 20)?;
                let value =
                    crate::http_config::helpers::global_lookup(name).map(String::into_bytes);
                if let Some(v) = &value {
                    ensure!(v.len() <= CAP, "header global placeholder exceeds limit");
                    ledger.pay(v.len() * 2)?;
                }
                value
            }
            Entry::Dynamic => {
                use placeholder_value::Value;
                let value = match self.dynamic.get(name) {
                    Some(Value::Bool(v)) => v.to_string(),
                    Some(Value::Duration(v)) => crate::duration::format(v),
                    Some(Value::Double(v)) => v.to_string(),
                    Some(Value::Null) => String::new(),
                    _ => return Ok(None),
                };
                ledger.pay(value.len() * 2)?;
                Some(value.into_bytes())
            }
        })
    }
    fn expand(&self, text: &str, fields: &HeaderMap) -> Result<Arc<Expanded>> {
        let ledger = Ledger::new(self.pool.clone());
        ledger.pay(256)?;
        let failed = Cell::new(false);
        let bytes = replace_bytes_accounted(
            text,
            false,
            |name| match self.get(fields, name, &ledger) {
                Ok(v) => v,
                Err(_) => {
                    failed.set(true);
                    None
                }
            },
            |n| ledger.pay(n),
        )?;
        if failed.get() {
            return Err(limit());
        }
        Ok(Arc::new(Expanded {
            bytes,
            _leases: ledger.leases.into_inner(),
        }))
    }
}
struct TextInput {
    text: String,
    _credit: Lease,
}
struct Overlay {
    headers: HeaderMap,
    _leases: Vec<Lease>,
}
async fn expand_owned(
    snapshot: &Arc<Snapshot>,
    text: &str,
    fields: &HeaderMap,
    lane: &BlockingBudget,
    pool: &Pool,
) -> Result<Arc<Expanded>> {
    // Small expressions have a bounded scanner. Large placeholder programs
    // must not turn the service poll into a CPU worker.
    if text.len() <= 4096 {
        return snapshot.expand(text, fields);
    }
    ensure!(text.len() <= 1 << 20, "replacement input exceeds limit");
    let credit = pool.reserve(text.len() * 2 + 1024)?;
    let input = TextInput {
        text: text.to_owned(),
        _credit: credit,
    };
    let overlay = header_overlay(snapshot, fields, pool).await?;
    let snapshot = snapshot.clone();
    lane.run(move || {
        let _input = input;
        let _overlay = overlay;
        snapshot.expand(&_input.text, &_overlay.headers)
    })
    .await
    .map_err(|_| limit())?
    .map_err(|_| limit())
}
async fn header_overlay(snapshot: &Snapshot, fields: &HeaderMap, pool: &Pool) -> Result<Overlay> {
    let ledger = Ledger::new(pool.clone());
    ledger.pay(4096)?;
    let mut overlay = HeaderMap::new();
    for (index, name) in snapshot.keys.iter().enumerate() {
        if index > 0 && index.is_multiple_of(128) {
            tokio::task::yield_now().await;
        }
        if !matches!(snapshot.entries[index], Entry::Header) {
            continue;
        }
        let key = name
            .strip_prefix("http.request.header.")
            .expect("captured header key");
        if overlay.contains_key(key) {
            continue;
        }
        let n = fields
            .get_all(key)
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(v.len() + 1))
            .filter(|n| *n <= CAP)
            .ok_or_else(limit)?;
        if n == 0 {
            continue;
        }
        ledger.pay(n * 4 + key.len() * 4 + 512)?;
        overlay.insert(
            http::HeaderName::from_bytes(key.as_bytes())?,
            HeaderValue::from_bytes(&join(fields, key))?,
        );
    }
    Ok(Overlay {
        headers: overlay,
        _leases: ledger.leases.into_inner(),
    })
}
struct OwnedValue {
    bytes: Vec<u8>,
    _credit: Lease,
}
impl AsRef<[u8]> for OwnedValue {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
struct Input {
    index: usize,
    bytes: Vec<u8>,
    sensitive: bool,
}
struct Output {
    index: usize,
    value: HeaderValue,
    old_len: usize,
    new_len: usize,
}
struct Source {
    inputs: Vec<Input>,
    _credit: Lease,
}
struct Batch {
    values: Vec<Output>,
    _source: Source,
}
fn literal_len(input: &[u8], find: &[u8], with: &[u8], maximum: usize) -> Result<usize> {
    let count = if find.is_empty() {
        input
            .utf8_chunks()
            .map(|chunk| chunk.valid().chars().count() + chunk.invalid().len())
            .sum::<usize>()
            + 1
    } else {
        memchr::memmem::Finder::new(find).find_iter(input).count()
    };
    let len = input
        .len()
        .checked_sub(count.checked_mul(find.len()).ok_or_else(limit)?)
        .and_then(|n| count.checked_mul(with.len()).and_then(|m| n.checked_add(m)))
        .filter(|n| *n <= maximum)
        .ok_or_else(limit)?;
    Ok(len)
}
fn process(
    mut source: Source,
    pool: Pool,
    search: Arc<Expanded>,
    with: Arc<Expanded>,
    pattern: Option<Arc<Expanded>>,
    precompiled: Option<Arc<GoRegexp>>,
    maximum: usize,
    deadline: Instant,
) -> Result<Batch> {
    ensure!(
        Instant::now() < deadline,
        "header replacement work deadline exceeded"
    );
    let dynamic = if let Some(pattern) = pattern {
        let Ok(pattern) = std::str::from_utf8(&pattern.bytes) else {
            return Ok(Batch {
                values: Vec::new(),
                _source: source,
            });
        };
        match crate::http_config::header_compile::compile_dynamic(pattern, &pool) {
            Ok(value) => Some(value),
            Err(error) if crate::http_config::header_compile::is_resource(&error) => {
                return Err(limit());
            }
            Err(_) => {
                return Ok(Batch {
                    values: Vec::new(),
                    _source: source,
                });
            }
        }
    } else {
        None
    };
    let compiled = dynamic
        .as_ref()
        .map(|value| value.regex.clone())
        .or(precompiled);
    let _regex = compiled
        .as_ref()
        .map(|r| pool.reserve(r.search_memory() * 2 + r.memory_usage() * 2))
        .transpose()?;
    let _workspace = pool.reserve(
        maximum
            .checked_mul(3)
            .and_then(|n| n.checked_add(with.bytes.len().saturating_mul(8)))
            .and_then(|n| {
                source
                    .inputs
                    .iter()
                    .try_fold(n + (8 << 20), |n, v| n.checked_add(v.bytes.len() * 32))
            })
            .ok_or_else(limit)?,
    )?;
    let replacement = compiled
        .as_ref()
        .map(|re| Replacement::compile_bytes(re, with.bytes.clone(), CAP))
        .transpose()?;
    let mut left = maximum;
    let mut values = Vec::with_capacity(source.inputs.len());
    for input in source.inputs.drain(..) {
        if Instant::now() >= deadline {
            return Err(limit());
        }
        let old_len = input.bytes.len();
        let output = if let (Some(re), Some(replacement)) = (&compiled, &replacement) {
            let mut budget = ReplaceBudget::new(
                re.search_memory() + input.bytes.len() * 32 + left,
                Some(deadline),
            );
            re.replace_all(&input.bytes, replacement, left, false, &mut budget)?
        } else {
            literal_len(&input.bytes, &search.bytes, &with.bytes, left)?;
            super::rewrite_ops::replace(&input.bytes, &search.bytes, &with.bytes, -1)?
        };
        if Instant::now() >= deadline {
            return Err(limit());
        }
        left = left.checked_sub(output.len()).ok_or_else(limit)?;
        let new_len = output.len();
        let credit = pool.reserve(new_len * 2 + 256)?;
        let mut value = HeaderValue::from_maybe_shared(Bytes::from_owner(OwnedValue {
            bytes: output,
            _credit: credit,
        }))?;
        value.set_sensitive(input.sensitive);
        values.push(Output {
            index: input.index,
            value,
            old_len,
            new_len,
        });
    }
    Ok(Batch {
        values,
        _source: source,
    })
}
/// Capture only Sync metadata references in the returned Send future. The real request
/// metadata stays visible while a worker is suspended, cancelled or retired.
pub(super) fn apply<'a>(
    headers: &'a mut HeaderMap,
    ops: &'a HeaderOps,
    ctx: &'a Context,
    scope: Scope,
    maximum: Option<usize>,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
    match prepare_owned(ops, ctx, scope) {
        Ok(prepared) => apply_owned(headers, ops, prepared, maximum),
        Err(error) => Box::pin(async move { Err(error) }),
    }
}
pub(super) struct Prepared<'a> {
    capture: Option<Pin<Box<dyn Future<Output = Result<Snapshot>> + Send + 'a>>>,
    lane: BlockingBudget,
    pool: Pool,
    _capture_credit: Option<Lease>,
}
pub(super) fn prepare_owned<'a>(
    ops: &'a HeaderOps,
    ctx: &'a Context,
    scope: Scope,
) -> Result<Prepared<'a>> {
    let pool = ctx.resources.header_replacements.clone();
    let active = ops.replace.iter().any(|(_, rules)| {
        rules
            .iter()
            .any(|r| !r.search.is_empty() || !r.search_regexp.is_empty() || !r.replace.is_empty())
    });
    let credit = if active {
        Some(pool.reserve(8192)?)
    } else {
        None
    };
    let capture = if active {
        let view = ctx.lookup_view();
        let dynamic = Dynamic::capture(ctx);
        let p = pool.clone();
        Some(Box::pin(Snapshot::capture(view, ops, scope, p, dynamic))
            as Pin<
                Box<dyn Future<Output = Result<Snapshot>> + Send + 'a>,
            >)
    } else {
        None
    };
    Ok(Prepared {
        capture,
        lane: ctx.resources.request_regexp.clone(),
        pool,
        _capture_credit: credit,
    })
}
pub(super) fn apply_owned<'a>(
    headers: &'a mut HeaderMap,
    ops: &'a HeaderOps,
    prepared: Prepared<'a>,
    maximum: Option<usize>,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
    if prepared.capture.is_none() {
        return Box::pin(async { Ok(()) });
    }
    Box::pin(async move {
        // Keep the future allocation credit behind the actual captured future.
        let mut prepared = prepared;
        let snapshot = prepared
            .capture
            .as_mut()
            .expect("active capture")
            .as_mut()
            .await
            .map_err(|_| limit())?;
        let snapshot = Arc::new(snapshot);
        let lane = prepared.lane.clone();
        let pool = prepared.pool.clone();
        let maximum = maximum.unwrap_or(CAP).min(CAP);
        let mut total = 0usize;
        for (index, (key, value)) in headers.iter().enumerate() {
            if index > 0 && index.is_multiple_of(128) {
                tokio::task::yield_now().await;
            }
            total = total
                .checked_add(key.as_str().len() + value.len() + 32)
                .ok_or_else(limit)?;
        }
        if total > maximum {
            return Err(limit());
        }
        let deadline = Instant::now() + Duration::from_millis(150);
        let _names_credit = pool.reserve(headers.len() * 128 + total * 2 + 4096)?;
        let mut names = Vec::with_capacity(headers.len());
        for (index, key) in headers.keys().enumerate() {
            if index > 0 && index.is_multiple_of(128) {
                tokio::task::yield_now().await;
            }
            names.push(key.as_str().to_owned());
        }
        let mut operations = 0usize;
        for (selector, rules) in ops.replace.iter() {
            operations += 1;
            if operations.is_multiple_of(128) {
                tokio::task::yield_now().await;
            }
            let selector = expand_owned(&snapshot, selector, headers, &lane, &pool).await?;
            for rule in rules.iter() {
                if Instant::now() >= deadline {
                    return Err(limit());
                }
                operations += 1;
                if operations.is_multiple_of(128) {
                    tokio::task::yield_now().await;
                }
                if rule.search.is_empty()
                    && rule.search_regexp.is_empty()
                    && rule.replace.is_empty()
                {
                    continue;
                }
                let search = expand_owned(&snapshot, &rule.search, headers, &lane, &pool).await?;
                let with = expand_owned(&snapshot, &rule.replace, headers, &lane, &pool).await?;
                let dynamic = !rule.search_regexp.is_empty() && rule.regex.is_none();
                for name in names.iter().filter(|name| {
                    selector.bytes == b"*" || name.as_bytes().eq_ignore_ascii_case(&selector.bytes)
                }) {
                    let count = headers.get_all(name.as_str()).iter().count();
                    let mut at = 0;
                    while at < count {
                        if Instant::now() >= deadline {
                            return Err(limit());
                        }
                        let pattern = if dynamic {
                            Some(
                                expand_owned(&snapshot, &rule.search_regexp, headers, &lane, &pool)
                                    .await?,
                            )
                        } else {
                            None
                        };
                        let amount = if dynamic { 1 } else { 256 };
                        let lengths = headers
                            .get_all(name.as_str())
                            .iter()
                            .skip(at)
                            .take(amount)
                            .scan(0usize, |n, v| {
                                if *n > 0 && *n + v.len() > 64 << 10 {
                                    return None;
                                }
                                *n += v.len();
                                Some(v.len())
                            })
                            .collect::<Vec<_>>();
                        let size = lengths.iter().sum::<usize>();
                        let credit = pool.reserve(size * 2 + lengths.len() * 128 + 1024)?;
                        let inputs = headers
                            .get_all(name.as_str())
                            .iter()
                            .skip(at)
                            .take(lengths.len())
                            .enumerate()
                            .map(|(i, v)| Input {
                                index: at + i,
                                bytes: v.as_bytes().to_vec(),
                                sensitive: v.is_sensitive(),
                            })
                            .collect();
                        let allowed = maximum.checked_sub(total - size).ok_or_else(limit)?;
                        let source = Source {
                            inputs,
                            _credit: credit,
                        };
                        let worker_pool = pool.clone();
                        let search = search.clone();
                        let with = with.clone();
                        let regex = rule.regex.clone();
                        let result = lane
                            .run(move || {
                                process(
                                    source,
                                    worker_pool,
                                    search,
                                    with,
                                    pattern,
                                    regex,
                                    allowed,
                                    deadline,
                                )
                            })
                            .await
                            .map_err(|_| limit())?
                            .map_err(|_| limit())?;
                        if !result.values.is_empty() {
                            let key = http::HeaderName::try_from(name.as_str())?;
                            if let http::header::Entry::Occupied(mut entry) = headers.entry(key) {
                                for (slot, out) in entry.iter_mut().skip(at).zip(result.values) {
                                    debug_assert!(out.index >= at);
                                    total = total - out.old_len + out.new_len;
                                    *slot = out.value;
                                }
                            }
                        }
                        at += lengths.len();
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(limit());
        }
        Ok(())
    })
}
