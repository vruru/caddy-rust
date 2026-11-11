//! Native Caddy logging. Provisioned generations share only actual writer
//! resources; event and rendering jobs retain the generation they admitted.
#[path = "logging/activity.rs"]
mod activity;
#[path = "logging/bounded.rs"]
mod bounded;
#[path = "logging/caller.rs"]
mod caller;
#[path = "logging/config.rs"]
mod config;
#[path = "logging/console_encoder.rs"]
mod console_encoder;
#[path = "logging/cpu.rs"]
mod cpu;
#[path = "logging/credits.rs"]
mod credits;
#[path = "logging/dispatch.rs"]
mod dispatch;
#[path = "logging/encoder.rs"]
mod encoder;
#[path = "logging/file_open.rs"]
mod file_open;
#[path = "logging/filter_cookie.rs"]
mod filter_cookie;
#[path = "logging/filter_query.rs"]
mod filter_query;
#[path = "logging/filter_simple.rs"]
mod filter_simple;
#[path = "logging/float.rs"]
mod float;
#[path = "logging/json_encoder.rs"]
mod json_encoder;
#[path = "logging/level.rs"]
mod level;
#[path = "logging/limits.rs"]
mod limits;
#[path = "logging/module_config.rs"]
mod module_config;
#[path = "logging/net_address.rs"]
mod net_address;
#[path = "logging/net_writer.rs"]
mod net_writer;
#[path = "logging/primitives.rs"]
mod primitives;
#[path = "logging/registry.rs"]
mod registry;
#[path = "logging/resolver_lane.rs"]
mod resolver_lane;
#[path = "logging/rotation_fs.rs"]
mod rotation_fs;
#[path = "logging/rotation_mill.rs"]
mod rotation_mill;
#[path = "logging/rotation_schedule.rs"]
mod rotation_schedule;
#[path = "logging/rotation_writer.rs"]
mod rotation_writer;
#[path = "logging/routing.rs"]
mod routing;
#[path = "logging/sampling.rs"]
mod sampling;
#[path = "logging/tcp_dial.rs"]
mod tcp_dial;
#[path = "logging/time_components.rs"]
mod time_components;
#[path = "logging/time_layout.rs"]
mod time_layout;
#[path = "logging/types.rs"]
mod types;
#[path = "logging/writer_io.rs"]
mod writer_io;
#[path = "logging/writer_pool.rs"]
mod writer_pool;
#[path = "logging/writer_spec.rs"]
mod writer_spec;

pub use credits::AdmissionError;
pub use dispatch::{Delivery, DeliveryReport, DeliveryTicket, DestinationReport};
pub use level::Level;
pub use limits::RuntimeLimits;
pub use registry::{
    FlushReport, Logging, LoggingRegistry, RegistryStatus, ShutdownReport, prepare,
};
pub use types::{Caller, Event, Field, FieldValue, Origin, Timestamp};
