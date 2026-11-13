pub(crate) mod allowed;
mod budget;
mod connection;
pub(crate) use budget::Metadata;
pub(crate) mod config;
mod console;
mod console_writer;
#[doc(hidden)]
pub use console_writer::{native_console_entry, register_native_console_helper};
pub(crate) mod discarded;
mod encode;
mod export;
mod export_retirement;
mod facts;
mod globals;
mod grpc;
mod negotiation;
pub(crate) mod observe;
pub(crate) mod process;
mod prometheus;
mod reader;
mod registry;
mod scrape;
mod snapshot;
mod transport;
pub(crate) mod upstream;
pub use process::Process;
pub use registry::Registry;

/// Independent admission snapshots; these counters do not claim a process RSS bound.
#[derive(Debug, serde::Serialize)]
pub struct Diagnostics {
    pub labels_remaining_bytes: usize,
    pub label_admission_remaining_bytes: usize,
    pub reserved_for_generation_bytes: usize,
    pub request_state_remaining_bytes: usize,
    pub snapshot_workspace_remaining_bytes: usize,
    pub encoded_output_remaining_bytes: usize,
    pub observations_dropped: u64,
    pub exports_failed: u64,
}

pub(crate) const SERIES_LIMIT: usize = 2048;

pub(crate) mod distributed_trace;

/// Independent tracing admission snapshots; no payload, identity or endpoint is
/// exposed, and these budgets are not a whole-process RSS guarantee.
#[derive(Debug,serde::Serialize)]pub struct TracingDiagnostics{
 pub retained_source_bytes:usize,
 pub live_span_owners:usize,
 pub workspace_remaining_bytes:usize,
 pub encoded_output_remaining_bytes:usize,
 pub observations_dropped:u64,
 pub exports_failed:u64,
}
