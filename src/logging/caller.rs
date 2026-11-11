//! Capture is deliberately separate from symbolization. On the explicitly
//! supported Unix backends trace_unsynchronized visits only the current stack
//! through _Unwind_Backtrace; its callback stores bounded PCs and cannot panic.
//! Symbol resolution and its global backtrace lock run on a dedicated worker.
use super::{level::Level, types::Caller};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::{HashMap, VecDeque},
    fmt::Write,
    panic::Location,
    path::Path,
    sync::Arc,
};
const MAX_CAPTURE: usize = 128;
const MAX_INLINE: usize = 64;
const MAX_SYMBOL_BYTES: usize = 8192;
pub(super) struct Captured {
    ips: [usize; MAX_CAPTURE],
    count: usize,
    truncated: bool,
    site: Option<&'static Location<'static>>,
}
impl Captured {
    pub(super) const fn supported() -> bool {
        cfg!(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "musl"),
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))
    }
    #[inline(never)]
    pub(super) fn capture() -> Result<Self> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "musl"),
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            let mut captured = Self {
                ips: [0; MAX_CAPTURE],
                count: 0,
                truncated: false,
                site: None,
            };
            // SAFETY: in these exact cfgs pinned backtrace 0.3.76 uses its
            // libunwind backend. trace_imp holds a stack-local callback/context;
            // _Unwind_Backtrace traverses this thread, and Frame::ip performs
            // _Unwind_GetIP without touching backtrace's symbol cache. The
            // callback allocates nothing, invokes no user code and cannot panic.
            // It accepts at most 128 PCs and observes one extra frame to report
            // actual truncation. Neither symbol_address nor Frame cloning is
            // requested. Native unwind/loader internals are not hard realtime.
            unsafe {
                backtrace::trace_unsynchronized(|frame| {
                    if captured.count == MAX_CAPTURE {
                        captured.truncated = true;
                        return false;
                    }
                    captured.ips[captured.count] = frame.ip() as usize;
                    captured.count += 1;
                    true
                });
            }
            Ok(captured)
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "musl"),
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            Err(anyhow!("log caller capture unsupported on this target"))
        }
    }
    pub(super) fn with_site(mut self, site: &'static Location<'static>) -> Self {
        self.site = Some(site);
        self
    }
    pub(super) fn byte_cost(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
#[derive(Clone, Copy)]
pub(super) struct Options {
    pub with_caller: bool,
    pub caller_skip: i64,
    pub stacktrace: Option<Level>,
}
impl Options {
    pub(super) fn needed(self, level: Level) -> bool {
        self.with_caller || self.stacktrace.is_some_and(|minimum| level >= minimum)
    }
    pub(super) fn nonempty(self) -> bool {
        self.with_caller || self.stacktrace.is_some()
    }
}
struct SymbolFrame {
    function: String,
    file: String,
    line: u32,
}
impl SymbolFrame {
    fn placeholder() -> Self {
        Self {
            function: String::new(),
            file: String::new(),
            line: 0,
        }
    }
}
struct Group {
    frames: Vec<SymbolFrame>,
    degraded: bool,
    lost_frames: bool,
}
struct Cached {
    group: Arc<Group>,
    bytes: usize,
}
pub(super) struct SymbolCache {
    entries: HashMap<usize, Cached>,
    fifo: VecDeque<usize>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}
pub(super) struct Resolved {
    pub caller: Option<Caller>,
    pub stacktrace: Option<String>,
    pub incomplete: bool,
}
struct Text {
    text: String,
    limit: usize,
}
impl std::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let Some(needed) = self
            .text
            .len()
            .checked_add(s.len())
            .filter(|n| *n <= self.limit)
        else {
            return Err(std::fmt::Error);
        };
        if needed > self.text.capacity() {
            let grown = self
                .text
                .capacity()
                .saturating_mul(2)
                .max(32)
                .min(self.limit)
                .max(needed);
            self.text
                .try_reserve_exact(grown - self.text.len())
                .map_err(|_| std::fmt::Error)?;
        }
        self.text.push_str(s);
        Ok(())
    }
}
fn limited(limit: usize, write: impl FnOnce(&mut Text) -> std::fmt::Result) -> Option<String> {
    let mut output = Text {
        text: String::new(),
        limit,
    };
    write(&mut output).ok().map(|_| output.text)
}
impl Resolved {
    pub(super) fn unresolved(
        site: Option<&'static Location<'static>>,
        options: Options,
        level: Level,
        max_stack_bytes: usize,
    ) -> Self {
        let site = effective_site(site, options);
        Self {
            caller: site.filter(|_| options.with_caller).map(|site| Caller {
                file: site.file().into(),
                line: site.line(),
                function: String::new(),
            }),
            stacktrace: site
                .filter(|_| options.stacktrace.is_some_and(|minimum| level >= minimum))
                .and_then(|site| {
                    limited(max_stack_bytes, |out| {
                        write!(out, "<caller>\n\t{}:{}", site.file(), site.line())
                    })
                }),
            incomplete: true,
        }
    }
}
fn effective_site(
    site: Option<&'static Location<'static>>,
    options: Options,
) -> Option<&'static Location<'static>> {
    site.filter(|site| {
        (!options.with_caller || options.caller_skip == 0) && site.file().len() <= MAX_SYMBOL_BYTES
    })
}
fn same_site(frame: &SymbolFrame, site: &Location<'_>) -> bool {
    if frame.file.is_empty() || frame.line != site.line() {
        return false;
    }
    let (symbol_file, tracked_file) = (Path::new(&frame.file), Path::new(site.file()));
    symbol_file.ends_with(tracked_file) || tracked_file.ends_with(symbol_file)
}
impl SymbolCache {
    pub(super) fn new(max_entries: usize, max_bytes: usize) -> Result<Self> {
        let minimum = std::mem::size_of::<Cached>()
            + std::mem::size_of::<Group>()
            + std::mem::size_of::<SymbolFrame>();
        ensure!(
            max_entries > 0 && max_bytes >= minimum,
            "invalid log symbol cache limits"
        );
        Ok(Self {
            entries: HashMap::new(),
            fifo: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
        })
    }
    fn get(&mut self, ip: usize) -> Result<Arc<Group>> {
        if let Some(entry) = self.entries.get(&ip) {
            return Ok(entry.group.clone());
        }
        let base = std::mem::size_of::<Cached>() + std::mem::size_of::<Group>();
        let unit = std::mem::size_of::<SymbolFrame>();
        let limit = (self.max_bytes - base).min(65536);
        let (mut frames, mut degraded, mut charged) = (Vec::new(), false, 0usize);
        let mut lost_frames = false;
        backtrace::resolve(ip as *mut std::ffi::c_void, |symbol| {
            if frames.len() >= MAX_INLINE || charged > limit - unit {
                degraded = true;
                lost_frames = true;
                return;
            }
            let available = limit - charged - unit;
            let function = match symbol.name() {
                Some(name) => limited(available.min(MAX_SYMBOL_BYTES), |out| {
                    write!(out, "{name:#}")
                }),
                None => Some(String::new()),
            };
            let file = match symbol.filename() {
                Some(path) => limited(
                    available
                        .saturating_sub(function.as_ref().map_or(0, String::len))
                        .min(MAX_SYMBOL_BYTES),
                    |out| write!(out, "{}", path.display()),
                ),
                None => Some(String::new()),
            };
            let frame = match (function, file) {
                (Some(function), Some(file)) => SymbolFrame {
                    function,
                    file,
                    line: symbol.lineno().unwrap_or(0),
                },
                _ => {
                    degraded = true;
                    SymbolFrame::placeholder()
                }
            };
            charged += frame.function.len() + frame.file.len() + unit;
            frames.push(frame);
        });
        if frames.is_empty() {
            frames.push(SymbolFrame::placeholder());
            degraded = true;
            charged = unit;
        }
        let cost = base
            .checked_add(charged)
            .ok_or_else(|| anyhow!("log symbol cache size overflow"))?;
        let group = Arc::new(Group {
            frames,
            degraded,
            lost_frames,
        });
        // Negative/limited results are cached too, preventing repeated expensive
        // DWARF queries for a permanently unresolvable PC or enormous symbol.
        while self.entries.len() >= self.max_entries || self.bytes > self.max_bytes - cost {
            let key = self
                .fifo
                .pop_front()
                .ok_or_else(|| anyhow!("log symbol cache accounting error"))?;
            if let Some(entry) = self.entries.remove(&key) {
                self.bytes -= entry.bytes;
            }
        }
        self.entries.insert(
            ip,
            Cached {
                group: group.clone(),
                bytes: cost,
            },
        );
        self.fifo.push_back(ip);
        self.bytes += cost;
        Ok(group)
    }
    /// Only the dedicated resolver worker calls this. Limits preserve the useful
    /// caller and return an explicitly incomplete trace instead of losing a log.
    pub(super) fn resolve(
        &mut self,
        captured: &Captured,
        options: Options,
        level: Level,
        max_stack_bytes: usize,
    ) -> Result<Resolved> {
        let mut groups = Vec::with_capacity(captured.count);
        let (mut resolved_bytes, mut budget_hit) = (0usize, false);
        'ips: for ip in &captured.ips[..captured.count] {
            let group = self.get(*ip)?;
            for frame in &group.frames {
                let Some(cost) = resolved_bytes
                    .checked_add(frame.function.len())
                    .and_then(|n| n.checked_add(frame.file.len()))
                    .and_then(|n| n.checked_add(std::mem::size_of::<SymbolFrame>()))
                    .filter(|n| *n <= self.max_bytes)
                else {
                    budget_hit = true;
                    break 'ips;
                };
                resolved_bytes = cost;
            }
            groups.push(group);
        }
        let mut frames = Vec::new();
        let mut prior_lost = false;
        for group in &groups {
            for frame in &group.frames {
                frames.push((frame, group.degraded, prior_lost));
            }
            prior_lost |= group.lost_frames;
        }
        let anchor = frames.iter().position(|(f, _, _)| {
            f.function.contains("::logging::caller::Captured")
                && (f.function.ends_with(">::capture") || f.function.ends_with("::capture"))
        });
        let Some(anchor) = anchor else {
            return Ok(Resolved::unresolved(
                captured.site,
                options,
                level,
                max_stack_bytes,
            ));
        };
        let marker = "::logging::caller::Captured";
        let function = frames[anchor].0.function.trim_start_matches('<');
        let Some(position) = function.find(marker) else {
            return Err(anyhow!("log caller anchor malformed"));
        };
        let prefix = format!("{}::logging::", &function[..position]);
        let mut base = anchor + 1;
        while base < frames.len()
            && frames[base]
                .0
                .function
                .trim_start_matches('<')
                .starts_with(&prefix)
        {
            base += 1;
        }
        // Caddy logging.go buildOptions appends AddCallerSkip only inside the
        // WithCaller branch, even though zap itself has a general skip option.
        let skip = if options.with_caller {
            options.caller_skip
        } else {
            0
        };
        let index = (base as i128) + i128::from(skip);
        if index < 0 || index >= frames.len() as i128 {
            return Ok(Resolved::unresolved(
                captured.site,
                options,
                level,
                max_stack_bytes,
            ));
        }
        let index = index as usize;
        let (frame, degraded, prior_lost) = frames[index];
        if prior_lost {
            return Ok(Resolved::unresolved(
                captured.site,
                options,
                level,
                max_stack_bytes,
            ));
        }
        let site = effective_site(captured.site, options);
        let matching_site = site.is_none_or(|site| same_site(frame, site));
        let mut incomplete = !matching_site
            || degraded
            || frame.function.is_empty()
            || frame.file.is_empty()
            || frame.line == 0;
        let caller = if !options.with_caller {
            None
        } else if let Some(site) = site {
            Some(Caller {
                file: site.file().into(),
                line: site.line(),
                function: if matching_site {
                    frame.function.clone()
                } else {
                    String::new()
                },
            })
        } else if !frame.file.is_empty() {
            Some(Caller {
                file: frame.file.clone(),
                line: frame.line,
                function: frame.function.clone(),
            })
        } else {
            None
        };
        let stacktrace = if options.stacktrace.is_some_and(|minimum| level >= minimum) {
            let mut output = Text {
                text: String::new(),
                limit: max_stack_bytes,
            };
            let mut cut = captured.truncated || budget_hit;
            if let Some(site) = site.filter(|_| !matching_site)
                && write!(output, "<caller>\n\t{}:{}", site.file(), site.line()).is_err()
            {
                output.text.clear();
                cut = true;
            }
            for (frame, degraded, _) in &frames[index..] {
                cut |= *degraded
                    || frame.function.is_empty()
                    || frame.file.is_empty()
                    || frame.line == 0;
                let separator = if output.text.is_empty() { "" } else { "\n" };
                let checkpoint = output.text.len();
                if write!(
                    &mut output,
                    "{separator}{}\n\t{}:{}",
                    frame.function, frame.file, frame.line
                )
                .is_err()
                {
                    output.text.truncate(checkpoint);
                    cut = true;
                    break;
                }
            }
            incomplete |= cut;
            Some(output.text)
        } else {
            None
        };
        Ok(Resolved {
            caller,
            stacktrace,
            incomplete,
        })
    }
}
