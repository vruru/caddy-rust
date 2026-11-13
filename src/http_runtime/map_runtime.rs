//! One actually-requested map destination. The worker receives no Context/body.
use super::{request::LazyMap, resource_budget::Resources};
use crate::go_regexp::{ReplaceBudget, Replacement};
use anyhow::{Result, ensure};
use bytes::Bytes;
use native_write_policy::{Lease, Pool};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
pub(super) const CAP: usize = 4 << 20;
struct Output {
    bytes: Vec<u8>,
    _credit: Lease,
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
pub(super) fn owned(bytes: Vec<u8>, credit: Lease) -> Bytes {
    Bytes::from_owner(Output {
        bytes,
        _credit: credit,
    })
}
// These are lifetime guards, never a value cache. String copies stored in
// Context retire before this arena; upstream attempt views move it unchanged.
enum TextKeep {
    Value(Bytes),
    Copy(Lease),
}
struct KeepState {
    values: Vec<TextKeep>,
    _capacity: Lease,
}
pub(super) struct TextRetentions {
    state: Mutex<KeepState>,
    pool: Pool,
    _base: Lease,
}
impl TextRetentions {
    pub(super) fn new(pool: &Pool) -> Result<Arc<Self>> {
        let base = pool.reserve(8192)?;
        let capacity = pool.reserve(4 * std::mem::size_of::<TextKeep>() * 2 + 1024)?;
        Ok(Arc::new(Self {
            state: Mutex::new(KeepState {
                values: Vec::with_capacity(4),
                _capacity: capacity,
            }),
            pool: pool.clone(),
            _base: base,
        }))
    }
    fn push(&self, value: TextKeep) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("map string ownership poisoned"))?;
        if state.values.len() == state.values.capacity() {
            let cap = state
                .values
                .capacity()
                .checked_mul(2)
                .ok_or_else(|| anyhow::anyhow!("map string ownership size overflow"))?;
            let credit = self.pool.reserve(
                cap.checked_mul(std::mem::size_of::<TextKeep>() * 2)
                    .and_then(|n| n.checked_add(1024))
                    .ok_or_else(|| anyhow::anyhow!("map string ownership size overflow"))?,
            )?;
            let len = state.values.len();
            state.values.try_reserve_exact(cap - len)?;
            state._capacity = credit;
        }
        state.values.push(value);
        Ok(())
    }
    pub(super) fn retain(&self, value: Bytes) -> Result<()> {
        self.push(TextKeep::Value(value))
    }
    pub(super) fn reserve_copy(&self, bytes: usize) -> Result<()> {
        self.push(TextKeep::Copy(
            self.pool.reserve(bytes.saturating_add(1024))?,
        ))
    }
}
pub(super) struct Selection {
    pub bytes: Bytes,
    pub expand: bool,
    pub null: bool,
}
struct Program {
    replacement: Replacement,
    _credit: Lease,
}
impl AsRef<Replacement> for Program {
    fn as_ref(&self) -> &Replacement {
        &self.replacement
    }
}
struct TaskOwner {
    credits: Mutex<Vec<Lease>>,
    pool: Pool,
    cancelled: AtomicBool,
    external: Option<tokio_util::sync::CancellationToken>,
    _base: Lease,
}
impl crate::cert_cpu::MaterialOwner for TaskOwner {
    fn reserve(&self, bytes: usize) -> Result<()> {
        let credit = self.pool.reserve(bytes.saturating_add(1024))?;
        let mut credits = self
            .credits
            .lock()
            .map_err(|_| anyhow::anyhow!("map task ownership poisoned"))?;
        ensure!(credits.len() < 4, "map task ownership reservation count");
        credits.push(credit);
        Ok(())
    }
}
struct CancelOnDrop(Arc<TaskOwner>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release)
    }
}
// Only immutable JSON configuration values are measured. Scalar formatter
// temporaries are bounded by f64's textual size and the already-paid job base.
fn shape(value: &serde_json::Value, nested: bool, depth: usize) -> Result<(usize, usize)> {
    ensure!(depth <= 256, "map output nesting limit");
    let scalar = match value {
        serde_json::Value::String(s) => return Ok((s.len(), 1)),
        serde_json::Value::Null => return Ok((if nested { 5 } else { 0 }, 1)),
        serde_json::Value::Bool(v) => return Ok((if *v { 4 } else { 5 }, 1)),
        serde_json::Value::Number(_) => {
            if nested {
                crate::http_config::helpers::value_string(&serde_json::Value::Array(vec![
                    value.clone(),
                ]))
                .len()
                .saturating_sub(2)
            } else {
                crate::http_config::helpers::value_string(value).len()
            }
        }
        serde_json::Value::Array(values) => {
            let (mut size, mut nodes) = (2usize + values.len().saturating_sub(1), 1usize);
            for value in values {
                let (n, c) = shape(value, true, depth + 1)?;
                size = size
                    .checked_add(n)
                    .ok_or_else(|| anyhow::anyhow!("map output size overflow"))?;
                nodes = nodes
                    .checked_add(c)
                    .ok_or_else(|| anyhow::anyhow!("map output size overflow"))?;
            }
            return Ok((size, nodes));
        }
        serde_json::Value::Object(values) => {
            let (mut size, mut nodes) = (5usize + values.len().saturating_sub(1), 1usize);
            for (key, value) in values {
                let (n, c) = shape(value, true, depth + 1)?;
                size = size
                    .checked_add(key.len())
                    .and_then(|v| v.checked_add(n + 1))
                    .ok_or_else(|| anyhow::anyhow!("map output size overflow"))?;
                nodes = nodes
                    .checked_add(c)
                    .ok_or_else(|| anyhow::anyhow!("map output size overflow"))?;
            }
            return Ok((size, nodes));
        }
    };
    Ok((scalar, 1))
}
fn format_value(pool: &Pool, value: &serde_json::Value) -> Result<(String, Lease)> {
    let (size, nodes) = shape(value, false, 0)?;
    ensure!(size <= CAP, "map output exceeds limit");
    let work = size
        .checked_mul(8)
        .and_then(|n| n.checked_add(nodes.saturating_mul(128)))
        .and_then(|n| n.checked_add(16384))
        .ok_or_else(|| anyhow::anyhow!("map output size overflow"))?;
    let _format = pool.reserve(work)?;
    let text = crate::http_config::helpers::value_string(value);
    ensure!(text.len() == size, "map output measurement invariant");
    let retained = pool.reserve(text.capacity().saturating_mul(2).saturating_add(1024))?;
    Ok((text, retained))
}
struct Job {
    input: Bytes,
    map: LazyMap,
    index: usize,
    owner: Arc<TaskOwner>,
    deadline: Option<Instant>,
}
impl Job {
    fn execute(self) -> Result<Selection> {
        let deadline = self
            .deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(5));
        let pool = &self.owner.pool;
        let normalized = if std::str::from_utf8(&self.input).is_ok() {
            0
        } else {
            self.input
                .len()
                .checked_mul(7)
                .ok_or_else(|| anyhow::anyhow!("map source size overflow"))?
        };
        for entry in self.map.mappings.iter() {
            ensure!(
                !self.owner.cancelled.load(Ordering::Acquire)
                    && !self
                        .owner
                        .external
                        .as_ref()
                        .is_some_and(|token| token.is_cancelled()),
                "map lookup cancelled"
            );
            ensure!(Instant::now() < deadline, "map work deadline exceeded");
            let Some(output) = entry.outputs.get(self.index).filter(|v| !v.is_null()) else {
                continue;
            };
            if let Some(regex) = &entry.regex {
                let (template, template_credit) = format_value(pool, output)?;
                let search = normalized
                    .checked_add(regex.search_memory())
                    .and_then(|n| n.checked_add(regex.capture_memory_upper()))
                    .ok_or_else(|| anyhow::anyhow!("map search size overflow"))?;
                let _search = pool.reserve(search)?;
                let mut budget = ReplaceBudget::new(search, Some(deadline));
                if let Some((bytes, output_credit)) =
                    regex.expand_first_lazy(&self.input, CAP, &mut budget, || {
                        let construction =
                            pool.reserve(regex.replacement_compile_upper(template.as_bytes())?)?;
                        let replacement = Replacement::compile(regex, template, 64 << 20)?;
                        let retained =
                            pool.reserve(replacement.memory_usage().saturating_add(4096))?;
                        let program = Program {
                            replacement,
                            _credit: retained,
                        };
                        drop(construction);
                        let output_credit = pool.reserve(2 * CAP + 1024)?;
                        Ok((program, output_credit))
                    })?
                {
                    drop(template_credit);
                    return Ok(Selection {
                        bytes: owned(bytes, output_credit),
                        expand: false,
                        null: false,
                    });
                }
            } else if entry.input.as_deref().unwrap_or_default().as_bytes() == self.input.as_ref() {
                let (text, credit) = format_value(pool, output)?;
                return Ok(Selection {
                    bytes: owned(text.into_bytes(), credit),
                    expand: true,
                    null: false,
                });
            }
        }
        let Some(output) = self.map.defaults.get(self.index).and_then(|v| v.as_str()) else {
            return Ok(Selection {
                bytes: Bytes::new(),
                expand: false,
                null: true,
            });
        };
        let credit = pool.reserve(output.len().saturating_mul(2) + 1024)?;
        Ok(Selection {
            bytes: owned(output.as_bytes().to_vec(), credit),
            expand: true,
            null: false,
        })
    }
}
pub(super) async fn select_until(
    resources: &Resources,
    map: &LazyMap,
    index: usize,
    input: Bytes,
    deadline: Instant,
) -> Result<Selection> {
    ensure!(input.len() <= CAP, "map source exceeds limit");
    let base = resources.map_bytes.reserve(8192)?;
    let owner = Arc::new(TaskOwner {
        credits: Mutex::new(Vec::with_capacity(4)),
        pool: resources.map_bytes.clone(),
        cancelled: AtomicBool::new(false),
        external: None,
        _base: base,
    });
    let _cancel = CancelOnDrop(owner.clone());
    let job = Job {
        input,
        map: map.clone(),
        index,
        owner: owner.clone(),
        deadline: Some(deadline),
    };
    let result = resources
        .map_lookup
        .run_retained(owner, move || job.execute())
        .await
        .map_err(|_| super::request::failure(http::StatusCode::SERVICE_UNAVAILABLE))?;
    match result.get() {
        Ok(value) => Ok(Selection {
            bytes: value.bytes.clone(),
            expand: value.expand,
            null: value.null,
        }),
        Err(_) => Err(super::request::failure(
            http::StatusCode::SERVICE_UNAVAILABLE,
        )),
    }
}

/// An owned definition graph, not an eagerly evaluated map. The primitive
/// callback belongs to the current controlled template/header receiver.
pub(super) struct Provider {
    maps: Vec<LazyMap>,
    pool: Pool,
    _credit: Lease,
}
impl Provider {
    pub(super) async fn capture(
        view: super::request::ReplacerView<'_>,
    ) -> Result<Option<Arc<Self>>> {
        let plans = view.map_plans();
        if plans.is_empty() {
            return Ok(None);
        }
        let credit = view.pool().reserve(
            plans
                .len()
                .saturating_mul(std::mem::size_of::<LazyMap>() * 2)
                .saturating_add(8192),
        )?;
        let mut maps = Vec::with_capacity(plans.len());
        for (i, plan) in plans.iter().enumerate() {
            if i > 0 && i.is_multiple_of(128) {
                tokio::task::yield_now().await;
            }
            maps.push(plan.clone());
        }
        Ok(Some(Arc::new(Self {
            maps,
            pool: view.pool().clone(),
            _credit: credit,
        })))
    }
    pub(super) fn pool(&self) -> &Pool {
        &self.pool
    }
    pub(super) fn lookup(
        &self,
        name: &str,
        mut primitive: impl FnMut(&str) -> Result<Option<Bytes>>,
    ) -> Result<Option<Bytes>> {
        self.lookup_controlled(
            name,
            primitive,
            None,
            Instant::now() + Duration::from_secs(5),
        )
    }
    pub(super) fn lookup_controlled(
        &self,
        name: &str,
        mut primitive: impl FnMut(&str) -> Result<Option<Bytes>>,
        cancel: Option<tokio_util::sync::CancellationToken>,
        deadline: Instant,
    ) -> Result<Option<Bytes>> {
        let base = self.pool.reserve(8192)?;
        let owner = Arc::new(TaskOwner {
            credits: Mutex::new(Vec::with_capacity(4)),
            pool: self.pool.clone(),
            cancelled: AtomicBool::new(false),
            external: cancel,
            _base: base,
        });
        self.resolve(
            name,
            &mut primitive,
            0,
            deadline.min(Instant::now() + Duration::from_secs(5)),
            &owner,
        )
    }
    fn resolve(
        &self,
        name: &str,
        primitive: &mut impl FnMut(&str) -> Result<Option<Bytes>>,
        depth: usize,
        deadline: Instant,
        owner: &Arc<TaskOwner>,
    ) -> Result<Option<Bytes>> {
        ensure!(
            Instant::now() < deadline
                && !owner
                    .external
                    .as_ref()
                    .is_some_and(|token| token.is_cancelled()),
            "map work cancelled or deadline exceeded"
        );
        if depth > 64 {
            return Ok(None);
        }
        if let Some(value) = primitive(name)? {
            return Ok(Some(value));
        }
        for map in &self.maps {
            let Some(index) = map.destinations.iter().position(|dest| dest == name) else {
                continue;
            };
            let input = self.expand(&map.source, primitive, depth, deadline, owner)?;
            let selected = Job {
                input,
                map: map.clone(),
                index,
                owner: owner.clone(),
                deadline: Some(deadline),
            }
            .execute()?;
            if !selected.expand {
                return Ok(Some(selected.bytes));
            }
            return self
                .expand(
                    std::str::from_utf8(&selected.bytes)?,
                    primitive,
                    depth,
                    deadline,
                    owner,
                )
                .map(Some);
        }
        Ok(None)
    }
    fn expand(
        &self,
        text: &str,
        primitive: &mut impl FnMut(&str) -> Result<Option<Bytes>>,
        depth: usize,
        deadline: Instant,
        owner: &Arc<TaskOwner>,
    ) -> Result<Bytes> {
        let primitive = std::cell::RefCell::new(primitive);
        let error = std::cell::RefCell::new(None);
        let ledger = SyncLedger::new(&self.pool)?;
        let value = crate::http_config::helpers::replace_bytes_accounted(
            text,
            true,
            |name| {
                if error.borrow().is_some() {
                    return None;
                }
                match self.resolve(
                    name,
                    &mut **primitive.borrow_mut(),
                    depth + 1,
                    deadline,
                    owner,
                ) {
                    Ok(Some(value)) => {
                        if let Err(e) = ledger.pay(value.len().saturating_mul(2) + 1024) {
                            *error.borrow_mut() = Some(e);
                            return None;
                        }
                        Some(value.to_vec())
                    }
                    Ok(None) => None,
                    Err(e) => {
                        *error.borrow_mut() = Some(e);
                        None
                    }
                }
            },
            |bytes| ledger.pay(bytes),
        );
        if let Some(error) = error.into_inner() {
            return Err(error);
        }
        let bytes = value?;
        ensure!(Instant::now() < deadline, "map work deadline exceeded");
        Ok(Bytes::from_owner(SyncOutput {
            bytes,
            _ledger: ledger,
        }))
    }
}
struct SyncLedger {
    credits: std::cell::RefCell<Vec<Lease>>,
    capacity: std::cell::RefCell<Lease>,
    pool: Pool,
    _base: Lease,
}
impl SyncLedger {
    fn new(pool: &Pool) -> Result<Self> {
        let base = pool.reserve(8192)?;
        let capacity = pool.reserve(4 * std::mem::size_of::<Lease>() * 2 + 1024)?;
        Ok(Self {
            credits: std::cell::RefCell::new(Vec::with_capacity(4)),
            capacity: std::cell::RefCell::new(capacity),
            pool: pool.clone(),
            _base: base,
        })
    }
    fn pay(&self, bytes: usize) -> Result<()> {
        let credit = self.pool.reserve(bytes.saturating_add(256))?;
        let mut credits = self.credits.borrow_mut();
        if credits.len() == credits.capacity() {
            let cap = credits
                .capacity()
                .checked_mul(2)
                .ok_or_else(|| anyhow::anyhow!("map expansion accounting overflow"))?;
            let metadata = self
                .pool
                .reserve(cap.saturating_mul(std::mem::size_of::<Lease>() * 2) + 1024)?;
            let len = credits.len();
            credits.try_reserve_exact(cap - len)?;
            *self.capacity.borrow_mut() = metadata;
        }
        credits.push(credit);
        Ok(())
    }
}
struct SyncOutput {
    bytes: Vec<u8>,
    _ledger: SyncLedger,
}
impl AsRef<[u8]> for SyncOutput {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Definition-only dependency metadata for a detached CPU consumer. This never
/// evaluates a regex/provider or caches a selected Map value. Globals/dynamic
/// primitives remain tokens and are read at the actual get, not captured here.
pub(super) struct DependencyKeys {
    pub keys: Arc<[String]>,
    _credits: Vec<Lease>,
    _capacity: Lease,
    _base: Lease,
}
impl Provider {
    pub(super) fn dependencies(&self, roots: &[String]) -> Result<DependencyKeys> {
        use std::collections::BTreeSet;
        let ledger = SyncLedger::new(&self.pool)?;
        ledger.pay(4096 * std::mem::size_of::<String>() * 2 + 1024)?;
        let mut names = BTreeSet::new();
        let mut pending = Vec::with_capacity(4096);
        fn insert(
            name: &str,
            names: &mut BTreeSet<String>,
            pending: &mut Vec<String>,
            ledger: &SyncLedger,
        ) -> Result<()> {
            if names.contains(name) {
                return Ok(());
            }
            ensure!(names.len() < 4096, "map dependency count exceeds limit");
            // Include whole new BTree node, both String owners and Vec slots before
            // insertion. Capacity is separately prepaid, including the first node.
            ledger.pay(name.len().saturating_mul(4).saturating_add(2048))?;
            names.insert(name.to_owned());
            pending.push(name.to_owned());
            Ok(())
        }
        fn scan(
            text: &str,
            names: &mut BTreeSet<String>,
            pending: &mut Vec<String>,
            ledger: &SyncLedger,
        ) -> Result<()> {
            let bytes = text.as_bytes();
            let mut at = 0;
            while at < bytes.len() {
                if bytes[at] != b'{' || (at > 0 && bytes[at - 1] == b'\\') {
                    at += 1;
                    continue;
                }
                let mut end = at + 1;
                while end < bytes.len()
                    && (bytes[end] != b'}' || (bytes[end - 1] == b'\\' && end + 1 < bytes.len()))
                {
                    end += 1;
                }
                if end < bytes.len() {
                    insert(&text[at + 1..end], names, pending, ledger)?;
                }
                at += 1;
            }
            Ok(())
        }
        for root in roots {
            insert(root, &mut names, &mut pending, &ledger)?;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut at = 0;
        while at < pending.len() {
            ensure!(
                Instant::now() < deadline,
                "map dependency preparation deadline exceeded"
            );
            let name = &pending[at];
            let selected = self.maps.iter().find_map(|map| {
                map.destinations
                    .iter()
                    .position(|dest| dest == name)
                    .map(|index| (map, index))
            });
            if let Some((map, index)) = selected {
                scan(&map.source, &mut names, &mut pending, &ledger)?;
                for entry in map.mappings.iter().filter(|entry| entry.regex.is_none()) {
                    if let Some(output) = entry.outputs.get(index).filter(|value| !value.is_null())
                    {
                        let (text, _temporary) = format_value(&self.pool, output)?;
                        scan(&text, &mut names, &mut pending, &ledger)?;
                    }
                }
                if let Some(value) = map.defaults.get(index).and_then(|value| value.as_str()) {
                    scan(value, &mut names, &mut pending, &ledger)?;
                }
            }
            at += 1;
        }
        ledger.pay(
            names
                .len()
                .saturating_mul(std::mem::size_of::<String>() * 2)
                .saturating_add(1024),
        )?;
        let keys = names.into_iter().collect::<Vec<_>>().into();
        let SyncLedger {
            credits,
            capacity,
            pool: _,
            _base,
        } = ledger;
        Ok(DependencyKeys {
            keys,
            _credits: credits.into_inner(),
            _capacity: capacity.into_inner(),
            _base,
        })
    }
}

/// A closed metadata/template producer retains its actual capture and any
/// unconsumed worker result. Successful handoff is only to the same Context
/// arena which already owns all derived String copies. No Context is sent.
struct TextWork<F> {
    operation: F,
    owner: Option<Arc<TextRetentions>>,
}
pub(super) struct TextResult<T> {
    value: T,
    owner: Option<Arc<TextRetentions>>,
}
impl<T> TextResult<T> {
    pub(super) fn into_context(self, ctx: &super::request::Context) -> Result<T> {
        if let Some(owner) = &self.owner {
            ensure!(
                ctx.text_owner()
                    .is_some_and(|current| Arc::ptr_eq(&current, owner)),
                "map text handoff owner mismatch"
            );
        }
        Ok(self.value)
    }
}
impl<F> TextWork<F> {
    fn execute<T>(self) -> TextResult<T>
    where
        F: FnOnce() -> T,
    {
        let Self { operation, owner } = self;
        TextResult {
            value: operation(),
            owner,
        }
    }
}
pub(super) fn text_job<T, F>(
    owner: Option<Arc<TextRetentions>>,
    operation: F,
) -> Result<impl FnOnce() -> TextResult<T> + Send + 'static>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    if let Some(owner) = &owner {
        owner
            .reserve_copy(
                std::mem::size_of::<F>()
                    .saturating_add(std::mem::size_of::<T>())
                    .saturating_add(2048),
            )
            .map_err(|_| super::request::failure(http::StatusCode::SERVICE_UNAVAILABLE))?;
    }
    let job = TextWork { operation, owner };
    Ok(move || job.execute())
}

/// Cache/connector metadata contains only closed atomic lease ownership.
/// Cached copies use the independent optional cache pool; actual NSS/attempt
/// work always uses the runtime Map pool and never the FastCGI DNS lane.
pub(super) struct DialOwner {
    pub(super) work_pool: Pool,
    _metadata: Arc<Lease>,
}
impl DialOwner {
    pub(super) fn new(work_pool: Pool, metadata: Arc<Lease>) -> Arc<Self> {
        Arc::new(Self {
            work_pool,
            _metadata: metadata,
        })
    }
    pub(super) fn tls_credits(&self, workspace:Arc<Lease>, output:Arc<Lease>)->Arc<native_ssl_tls::ConnectionCredits>{
        // The per-attempt workspace prepays this finite three-element Vec and
        // Arc header; it is itself retained until all detached owners finish.
        Arc::new(native_ssl_tls::ConnectionCredits::new(vec![self._metadata.clone(),workspace,output]))
    }
    pub(super) fn dns_work(self: &Arc<Self>, name_bytes: usize) -> Result<Arc<DialDnsOwner>> {
        let base = self.work_pool.reserve(
            name_bytes
                .checked_mul(4)
                .and_then(|n| n.checked_add(65536))
                .and_then(|n| n.checked_add(
                    super::mapped_dns::MAX_ADDRS
                        .checked_mul(std::mem::size_of::<std::net::SocketAddr>())?
                        .checked_mul(2)?
                ))
                .ok_or_else(|| anyhow::anyhow!("Map DNS metadata overflow"))?,
        )?;
        let task = Arc::new(TaskOwner {
            credits: Mutex::new(Vec::with_capacity(4)),
            pool: self.work_pool.clone(),
            cancelled: AtomicBool::new(false),
            external: None,
            _base: base,
        });
        Ok(Arc::new(DialDnsOwner {
            task,
            _dial: self.clone(),
        }))
    }
}
pub(super) struct DialDnsOwner {
    task: Arc<TaskOwner>,
    _dial: Arc<DialOwner>,
}
impl crate::cert_cpu::MaterialOwner for DialDnsOwner {
    fn reserve(&self, bytes: usize) -> Result<()> {
        crate::cert_cpu::MaterialOwner::reserve(&*self.task, bytes)
    }
}
