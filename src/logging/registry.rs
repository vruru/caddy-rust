//! Provision candidate loggers without changing the live generation.
use super::{
    activity::{Activity, Token},
    caller::{Captured, Options, SymbolCache},
    config::{self, BaseLog},
    cpu::Cpu,
    credits::{AdmissionError, Credits},
    dispatch::{self, DeliveryTicket},
    encoder::Encoder,
    level::Level,
    limits::RuntimeLimits,
    module_config,
    resolver_lane::Resolver,
    routing::Routing,
    sampling::Sampler,
    types::Event,
    writer_io,
    writer_pool::{Budgets, Done, Exit, Lease, Pool},
    writer_spec::{WriterSpec, resolve_required},
};
use anyhow::{Result, anyhow, bail, ensure};
use futures_util::{
    StreamExt,
    future::{join_all, try_join_all},
    stream::FuturesUnordered,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub struct LoggingRegistry {
    pub(super) limits: RuntimeLimits,
    pub(super) credits: Arc<Credits>,
    pub(super) cpu: Arc<Cpu>,
    pub(super) prep: Arc<Cpu>,
    pub(super) symbols: Arc<Cpu>,
    pub(super) symbol_cache: Mutex<SymbolCache>,
    resolver: Arc<Resolver>,
    pool: Arc<Pool>,
    plans: Arc<Activity>,
}
impl LoggingRegistry {
    pub fn new(limits: RuntimeLimits) -> Result<Arc<Self>> {
        limits.validate()?;
        let credits = Credits::new(&limits)?;
        let pool = Pool::new(
            limits.max_writer_actors,
            limits.max_queue_messages_per_writer,
            limits.max_config_bytes,
            Budgets {
                buffered: limits.max_buffered_bytes_per_writer,
                event: (limits.max_pending_event_bytes / 2).max(1),
                jobs: (limits.max_queued_jobs / 2).max(1),
                workspace: (limits.max_encoding_workspace_bytes / 2).max(1),
            },
        )?;
        let cpu = Cpu::new(limits.max_queued_jobs)?;
        let prep = Cpu::new_capped(limits.max_queued_jobs, "caddy-log-prep", 4)?;
        let symbols = Cpu::new_capped(limits.max_queued_jobs, "caddy-log-symbols", 1)?;
        let symbol_cache = Mutex::new(SymbolCache::new(8192, 8 << 20)?);
        let resolver = Resolver::new(limits.max_writer_actors.min(limits.max_queued_jobs))?;
        let plans = Activity::new(limits.max_writer_actors.max(4))?;
        Ok(Arc::new(Self {
            limits,
            credits,
            cpu,
            prep,
            symbols,
            symbol_cache,
            resolver,
            pool,
            plans,
        }))
    }
    /// Close the registry after closing the plan(s) which still own it. A
    /// timeout leaves real jobs and handles owned; callers may wait again.
    pub async fn shutdown(&self, deadline: Instant) -> ShutdownReport {
        self.plans.close();
        let deadline = tokio::time::Instant::from_std(deadline);
        let result = tokio::time::timeout_at(deadline, async {
            self.plans.drained().await;
            self.credits.close();
            self.pool.close();
            let (_, encode, prep, symbols, dns) = tokio::join!(
                self.pool.drained(),
                self.cpu.shutdown(),
                self.prep.shutdown(),
                self.symbols.shutdown(),
                self.resolver.shutdown(),
            );
            encode.is_ok() && prep.is_ok() && symbols.is_ok() && dns.is_ok()
        })
        .await;
        let pending = self.plans.active().saturating_add(self.pool.active())
            + usize::from(!self.cpu.quiesced())
            + usize::from(!self.prep.quiesced())
            + usize::from(!self.symbols.quiesced())
            + usize::from(!self.resolver.quiesced());
        let exits = self.pool.exits();
        let failed = exits[1]
            .saturating_add(exits[2])
            .saturating_add(usize::from(matches!(result, Ok(false))));
        ShutdownReport {
            complete: matches!(result, Ok(true)),
            pending,
            failed,
        }
    }
    pub fn status(&self) -> RegistryStatus {
        let (available_event_bytes, available_jobs, available_workspace_bytes) =
            self.credits.available();
        RegistryStatus {
            encoding_workers: self.cpu.workers(),
            writer_keys: self.pool.keys(),
            available_writer_slots: self.pool.allowance(),
            available_event_bytes,
            available_jobs,
            available_workspace_bytes,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryStatus {
    pub encoding_workers: usize,
    pub writer_keys: usize,
    pub available_writer_slots: usize,
    pub available_event_bytes: usize,
    pub available_jobs: usize,
    pub available_workspace_bytes: usize,
}

pub(super) struct Destination {
    pub name: Arc<str>,
    pub writer: usize,
    pub level: Level,
    pub options: Options,
    pub sampler: Option<Sampler>,
    pub routing: Option<Routing>,
    pub encoder: Encoder,
    pub static_bytes: usize,
    pub dynamic_count: usize,
    pub regexp_search: usize,
    pub discard: bool,
}
struct WriterCandidate {
    spec: WriterSpec,
    fingerprint: [u8; 32],
}
struct Candidate {
    sink: Option<usize>,
    default: usize,
    logs: Vec<Destination>,
    writers: BTreeMap<String, (usize, WriterCandidate)>,
}

pub(super) struct Scope {
    pub registry: Arc<LoggingRegistry>,
    pub(super) writers: Vec<Lease>,
    pub(super) logs: Vec<Destination>,
    pub(super) sink: Option<usize>,
    pub(super) default: usize,
    retirement: watch::Sender<Option<Arc<Vec<Done>>>>,
    _plan: Arc<Token>,
}
impl Drop for Scope {
    fn drop(&mut self) {
        // An actor or worker may run this Drop. Release lease claims without
        // waiting on an actor (possibly ourselves), then expose the true waits.
        self.logs.clear();
        let retiring = self.writers.drain(..).filter_map(Lease::retire).collect();
        self.retirement.send_replace(Some(Arc::new(retiring)));
    }
}

pub struct Logging {
    scope: Mutex<Option<Arc<Scope>>>,
    retirement: watch::Receiver<Option<Arc<Vec<Done>>>>,
    changed_writer_options: usize,
    reused_writers: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownReport {
    pub complete: bool,
    pub pending: usize,
    pub failed: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushReport {
    pub flushed: usize,
    pub failed: usize,
    pub pending: usize,
}
impl Logging {
    fn current(&self) -> Option<Arc<Scope>> {
        self.scope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    pub fn changed_writer_options(&self) -> usize {
        self.changed_writer_options
    }
    pub fn reused_writers(&self) -> usize {
        self.reused_writers
    }
    pub fn failed_writers(&self) -> usize {
        self.current().map_or(0, |scope| {
            scope
                .writers
                .iter()
                .filter(|writer| matches!(writer.core.exit(), Some(Exit::Failed(_))))
                .count()
        })
    }
    #[track_caller]
    pub fn try_emit(&self, event: Event) -> std::result::Result<DeliveryTicket, AdmissionError> {
        let scope = self.current().ok_or(AdmissionError::Closed)?;
        dispatch::emit(scope, event, std::panic::Location::caller())
    }
    /// Stop admitting a generation immediately, without closing writers
    /// shared by the next generation. Already accepted jobs own their scope.
    pub fn retire(&self) {
        let scope = self
            .scope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(scope);
    }
    pub async fn flush(&self, cancel: CancellationToken) -> FlushReport {
        let Some(scope) = self.current() else {
            return FlushReport {
                flushed: 0,
                failed: 1,
                pending: 0,
            };
        };
        let mut report = FlushReport {
            flushed: 0,
            failed: 0,
            pending: 0,
        };
        let mut receivers = FuturesUnordered::new();
        for writer in &scope.writers {
            match writer.core.reserve().and_then(|reserve| reserve.flush()) {
                Ok(receiver) => receivers.push(receiver),
                Err(_) => report.failed += 1,
            }
        }
        while !receivers.is_empty() {
            tokio::select! {
                biased;
                next = receivers.next() => {
                    if matches!(next, Some(Ok(Ok(())))) {
                        report.flushed += 1;
                    } else {
                        report.failed += 1;
                    }
                },
                _ = cancel.cancelled() => {
                    report.pending = receivers.len();
                    break;
                },
            }
        }
        report
    }
    pub async fn shutdown(&self, deadline: Instant) -> ShutdownReport {
        self.retire();
        let deadline = tokio::time::Instant::from_std(deadline);
        let mut retired = self.retirement.clone();
        let outcomes = tokio::time::timeout_at(deadline, async {
            loop {
                if let Some(outcomes) = retired.borrow_and_update().clone() {
                    return Some(outcomes);
                }
                if retired.changed().await.is_err() {
                    return None;
                }
            }
        })
        .await;
        let Ok(Some(outcomes)) = outcomes else {
            return ShutdownReport {
                complete: false,
                pending: 1,
                failed: 0,
            };
        };
        let all = tokio::time::timeout_at(
            deadline,
            join_all(outcomes.iter().cloned().map(wait_writer)),
        )
        .await;
        let (pending, failed) = if let Ok(exits) = all {
            (
                0,
                exits
                    .into_iter()
                    .filter(|exit| !matches!(exit, Some(Exit::Clean)))
                    .count(),
            )
        } else {
            outcomes
                .iter()
                .fold((0, 0), |(pending, failed), done| match *done.borrow() {
                    Some(Exit::Clean) => (pending, failed),
                    Some(Exit::Failed(_)) => (pending, failed + 1),
                    None => (pending + 1, failed),
                })
        };
        ShutdownReport {
            complete: pending == 0,
            pending,
            failed,
        }
    }
}
async fn wait_writer(mut done: Done) -> Option<Exit> {
    loop {
        if let Some(exit) = *done.borrow_and_update() {
            return Some(exit);
        }
        if done.changed().await.is_err() {
            return None;
        }
    }
}

pub async fn prepare(
    config: Option<Value>,
    registry: Arc<LoggingRegistry>,
    cancel: CancellationToken,
) -> Result<Arc<Logging>> {
    let token = registry.plans.begin()?;
    let worker_registry = registry.clone();
    let worker_token = token.clone();
    let prepared = registry
        .prep
        .try_submit(move || {
            let _token = worker_token;
            prepare_candidate(config, &worker_registry.limits)
        })
        .map_err(|_| anyhow!("logging preparation queue unavailable"))?;
    let candidate = tokio::select! {
        biased;
        _ = cancel.cancelled() => bail!("logging preparation canceled"),
        done = prepared => done.map_err(|_| anyhow!("logging preparation worker ended"))??,
    };
    let Candidate {
        sink,
        default,
        logs,
        writers,
    } = candidate;
    let resolver = registry.resolver.clone();
    let acquisitions = writers.into_iter().map(|(key, (index, writer))| {
        let pool = registry.pool.clone();
        let resolver = resolver.clone();
        let pinned = writer.spec.pinned();
        async move {
            let lease = pool
                .acquire(
                    key,
                    writer.fingerprint,
                    pinned,
                    Box::new(move || writer_io::open(writer.spec, resolver)),
                )
                .await
                .map_err(|error| anyhow!("logging writer unavailable: {error:?}"))?;
            Ok::<_, anyhow::Error>((index, lease))
        }
    });
    let mut leases = tokio::select! {
        biased;
        _ = cancel.cancelled() => bail!("logging writer opening canceled"),
        leases = try_join_all(acquisitions) => leases?,
    };
    leases.sort_unstable_by_key(|(index, _)| *index);
    let writers: Vec<_> = leases.into_iter().map(|(_, lease)| lease).collect();
    let changed_writer_options = writers.iter().filter(|lease| lease.changed_options).count();
    let reused_writers = writers.iter().filter(|lease| lease.reused).count();
    let (retirement, observe) = watch::channel(None);
    let scope = Scope {
        registry,
        writers,
        logs,
        sink,
        default,
        retirement,
        _plan: token,
    };
    Ok(Arc::new(Logging {
        scope: Mutex::new(Some(Arc::new(scope))),
        retirement: observe,
        changed_writer_options,
        reused_writers,
    }))
}

fn prepare_candidate(config: Option<Value>, limits: &RuntimeLimits) -> Result<Candidate> {
    crate::http_config::helpers::initialize_globals();
    let mut config = config::parse(config, limits)?;
    let mut candidate = Candidate {
        sink: None,
        default: 0,
        logs: Vec::new(),
        writers: BTreeMap::new(),
    };
    let mut provision_bytes = 0usize;
    if let Some(base) = config.sink {
        candidate.sink =
            candidate.append("sink", base, None, true, limits, &mut provision_bytes)?;
    }
    let default = config
        .logs
        .remove("default")
        .ok_or_else(|| anyhow!("default logger missing"))?;
    // Discard default remains as a real logical destination even though it
    // does not allocate frames, so direct core emits still have a logger.
    candidate.default = candidate
        .append(
            "default",
            default.base,
            Some(default.routing),
            true,
            limits,
            &mut provision_bytes,
        )?
        .ok_or_else(|| anyhow!("default logger missing"))?;
    for (name, log) in config.logs {
        candidate.append(
            &name,
            log.base,
            Some(log.routing),
            false,
            limits,
            &mut provision_bytes,
        )?;
    }
    Ok(candidate)
}
impl Candidate {
    fn append(
        &mut self,
        name: &str,
        base: BaseLog,
        routing: Option<Routing>,
        mandatory: bool,
        limits: &RuntimeLimits,
        provision_bytes: &mut usize,
    ) -> Result<Option<usize>> {
        let writer_options = base.writer.as_ref().unwrap_or(&Value::Null);
        let mut hasher = Sha256::new();
        crate::admin_json::encoded_len_typed(writer_options, limits.max_config_bytes)
            .map_err(|_| anyhow!("log writer options limit exceeded"))?;
        hasher.update(
            crate::admin_json::encoded_typed(writer_options)
                .map_err(|_| anyhow!("invalid log writer options"))?,
        );
        let fingerprint = hasher.finalize().into();
        let writer = WriterSpec::parse(base.writer, limits.max_config_bytes)?;
        let level = Level::parse_config(&resolve_required(&base.level)?)?;
        let stacktrace = if base.with_stacktrace.is_empty() {
            None
        } else {
            let level = resolve_required(&base.with_stacktrace)
                .and_then(|level| Level::parse_config(&level));
            if mandatory { Some(level?) } else { level.ok() }
        };
        let options = Options {
            with_caller: base.with_caller,
            caller_skip: base.with_caller_skip,
            stacktrace,
        };
        ensure!(
            !options.nonempty() || Captured::supported(),
            "log caller capture unsupported on this target"
        );
        let static_bytes = crate::admin_json::encoded_len_typed(
            base.encoder.as_ref().unwrap_or(&Value::Null),
            limits.max_config_bytes,
        )
        .map_err(|_| anyhow!("log encoder options limit exceeded"))?;
        let terminal = match writer {
            WriterSpec::Stdout => io::stdout().is_terminal(),
            WriterSpec::Stderr => io::stderr().is_terminal(),
            _ => false,
        };
        let coloring = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
            && std::env::var_os("TERM").is_none_or(|v| v != "xterm-mono");
        let regexp_budget = limits
            .max_config_owned_bytes
            .checked_sub(*provision_bytes)
            .ok_or_else(|| anyhow!("log provisioning memory limit exceeded"))?;
        let encoder = Encoder::prepare(
            base.encoder,
            terminal,
            coloring,
            limits.max_encoded_bytes,
            regexp_budget,
        )?;
        let (regexp_compiled, regexp_search) = encoder.regexp_memory();
        if let Some(core) = base.core {
            let (module, fields) =
                module_config::inline(core, "module", limits.max_config_bytes, false)?;
            ensure!(module == "mock", "unsupported native logging core module");
            crate::http_config::helpers::deny_unknown(&fields, &[], "/logging/core")?;
            // The native mock is a genuine no-op tee branch.
        }
        let discard = matches!(writer, WriterSpec::Discard);
        if discard && !mandatory {
            return Ok(None);
        }
        *provision_bytes = provision_bytes
            .checked_add(regexp_compiled)
            .filter(|n| *n <= limits.max_config_owned_bytes)
            .ok_or_else(|| anyhow!("log regexp configuration memory limit exceeded"))?;
        let sampler = if !discard && let Some(sampling) = base.sampling {
            *provision_bytes = provision_bytes
                .checked_add(Sampler::allocation_bytes())
                .filter(|n| *n <= limits.max_config_owned_bytes)
                .ok_or_else(|| anyhow!("log sampling memory limit exceeded"))?;
            Some(Sampler::new(sampling))
        } else {
            None
        };
        let key = writer.key();
        let proposed = self.writers.len();
        let (writer_index, _) = self.writers.entry(key).or_insert((
            proposed,
            WriterCandidate {
                spec: writer,
                fingerprint,
            },
        ));
        let dynamic_count = encoder.dynamic_count();
        let position = self.logs.len();
        self.logs.push(Destination {
            name: Arc::from(name),
            writer: *writer_index,
            level,
            options,
            sampler,
            routing,
            encoder,
            static_bytes,
            dynamic_count,
            regexp_search,
            discard,
        });
        Ok(Some(position))
    }
}
