//! Configuration and rotation for TLS session ticket keys.
mod config;
mod go_gob;
mod owner;
mod ring;
mod runtime;
pub mod ticket;

pub use config::{Provider, Settings, TicketMode};
pub use owner::{Activation, Owner};
#[cfg(feature = "native-run")]
pub(crate) use runtime::TicketOwners;
pub(crate) use runtime::TicketRuntime;
