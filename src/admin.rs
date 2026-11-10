//! Native Caddy administrative control plane. Local transport restrictions are
//! not authentication substitutes for a remotely exposed endpoint. Activation
//! callbacks must provision and transactionally replace the data plane before
//! returning success. Unimplemented remote identity settings fail validation.
#[path = "admin/inherited.rs"]
mod inherited;
/// Capture configured inherited sockets before creating the async runtime.
pub use inherited::capture as capture_inherited;
#[path = "admin/controller.rs"]
mod controller;
#[path = "admin/files.rs"]
mod files;
#[path = "admin/ids.rs"]
mod ids;
#[path = "admin/loader.rs"]
mod loader;
#[path = "admin/loader_schema.rs"]
mod loader_schema;
#[path = "admin/policy.rs"]
mod policy;
#[path = "admin/remote.rs"]
mod remote;
#[path = "admin/remote_pin.rs"]
mod remote_pin;
#[path = "admin/server.rs"]
mod server;
pub use controller::AdminController;
use serde_json::Value;
pub use server::AdminServerHandle;
use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminStopOutcome {
    Complete,
    DrainIncomplete,
    BackendStopFailed,
}

pub type AdminFuture<T> = Pin<Box<dyn Future<Output = Result<T, AdminError>> + Send>>;
/// Invoked after candidate apps and identity are ready, before publication.
pub type AdminFinisher = Box<dyn FnOnce() -> AdminFuture<()> + Send>;

/// Backends return safe categories and optional source lines, never raw config,
/// keys, filesystem paths, upstream errors or credential-bearing strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminError {
    pub status: u16,
    pub category: &'static str,
    pub line: Option<usize>,
}
impl AdminError {
    pub const fn new(status: u16, category: &'static str) -> Self {
        Self {
            status,
            category,
            line: None,
        }
    }
}
impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.category)
    }
}
impl std::error::Error for AdminError {}

pub struct AdaptedConfig {
    pub result: Value,
    pub warnings: Vec<Value>,
}
pub trait AdminBackend: Send + Sync + 'static {
    fn apply(&self, config: Value, force: bool) -> AdminFuture<()>;
    /// Stage the candidate; commit only after finisher succeeds, otherwise restore old apps.
    fn apply_with_finisher(
        &self,
        _config: Value,
        _force: bool,
        _finisher: AdminFinisher,
    ) -> AdminFuture<()> {
        Box::pin(async { Err(AdminError::new(400, "staged_backend_unavailable")) })
    }
    /// Identity credentials with clientAuth usage, refreshed by the backend resolver.
    fn identity_client(
        &self,
        _candidate: Value,
    ) -> AdminFuture<Arc<dyn rustls::client::ResolvesClientCert>> {
        Box::pin(async {
            Err(AdminError::new(
                400,
                "admin_client_identity_backend_unavailable",
            ))
        })
    }
    fn adapt(
        &self,
        input: Vec<u8>,
        adapter: Option<String>,
        filename: Option<String>,
    ) -> AdminFuture<AdaptedConfig>;
    fn stop(&self) -> AdminFuture<()>;
    /// Prepare and maintain all admin.identity identifiers before publication.
    /// The returned resolver must observe renewals without replacing listeners.
    fn identity(
        &self,
        _candidate: Value,
    ) -> AdminFuture<Arc<dyn rustls::server::ResolvesServerCert>> {
        Box::pin(async { Err(AdminError::new(400, "admin_identity_backend_unavailable")) })
    }
}

#[derive(Clone)]
pub struct AdminOptions {
    pub autosave: Option<PathBuf>,
    pub body_limit: usize,
    pub queue_capacity: usize,
    pub max_connections: usize,
    pub max_requests: usize,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
}
impl Default for AdminOptions {
    fn default() -> Self {
        Self {
            autosave: None,
            body_limit: 16 * 1024 * 1024,
            queue_capacity: 32,
            max_connections: 128,
            max_requests: 64,
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
        }
    }
}
impl AdminOptions {
    fn validate(&self) -> Result<(), AdminError> {
        if !(1..=100 * 1024 * 1024).contains(&self.body_limit)
            || !(1..=4096).contains(&self.queue_capacity)
            || !(1..=4096).contains(&self.max_connections)
            || !(1..=4096).contains(&self.max_requests)
            || self.header_timeout.is_zero()
            || self.body_timeout.is_zero()
            || self.header_timeout > Duration::from_secs(300)
            || self.body_timeout > Duration::from_secs(300)
        {
            return Err(AdminError::new(400, "invalid_admin_resource_limits"));
        }
        Ok(())
    }
}

/// Resolve --resume without mutating an active process. Missing autosave falls
/// back to the supplied config; a present corrupt or unsafe file is an error.
pub fn resume_config(autosave: &std::path::Path, fallback: &Value) -> Result<Value, AdminError> {
    files::resume(autosave, fallback)
}

/// Validate the local administrative schema without binding a listener.
pub fn validate(config: &Value) -> Result<(), AdminError> {
    policy::LocalPolicy::parse(config).map(|_| ())
}
