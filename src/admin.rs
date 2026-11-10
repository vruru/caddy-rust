//! Native Caddy administrative control plane. Local transport restrictions are
//! not authentication substitutes for a remotely exposed endpoint. Activation
//! callbacks must provision and transactionally replace the data plane before
//! returning success. Unimplemented remote identity settings fail validation.
#[path = "admin/inherited.rs"]
mod inherited;
/// Capture configured inherited sockets before creating the async runtime.
pub use inherited::capture as capture_inherited;
#[path = "admin/candidate.rs"]
mod candidate;
pub use candidate::{CandidateHandle, CandidateOwner, CandidateScope};
#[path = "admin/activation.rs"]
mod activation;
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
#[path = "admin/local_access.rs"]
mod local_access;
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
    TransactionFailed,
}

pub type AdminFuture<T> = Pin<Box<dyn Future<Output = Result<T, AdminError>> + Send>>;
/// Invoked after candidate listeners are staged, before atomic publication.
/// Identity acquisition must use this candidate's explicit capability.
pub type AdminFinisher = Box<dyn FnOnce(CandidateHandle) -> AdminFuture<()> + Send>;

#[derive(Clone)]
pub struct AdminTransaction {
    pub config: Value,
    pub force: bool,
    pub expected_generation: Option<u64>,
    /// Compensation may only reuse retained valid certificate material. It
    /// must never issue a new certificate or run external configuration loaders.
    /// The backend validates all required business AND administrative identities
    /// before its finisher; rollback finishers perform no identity acquisition.
    pub restore_only: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Committed {
    pub generation: u64,
    pub stop_pending: bool,
}
#[derive(Clone, Copy, Debug)]
pub enum StopMode {
    Graceful(Duration),
    Force,
}

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
    /// Cheap synchronous availability fence; never wait for a transaction or IO.
    /// A forced root must stop control-plane reads before asynchronous cleanup.
    fn check_available(&self) -> Result<(), AdminError> {
        Ok(())
    }

    /// Stage apps, invoke the finisher once, then publish synchronously. Errors
    /// preserve the predecessor. Close candidate capabilities on every outcome.
    /// StopRequested may still publish an accepted candidate; forced stop must
    /// discard it. Ok identifies the actual monotonically increasing generation.
    /// A mismatched expected_generation rejects before the finisher or any
    /// publication. The finisher must complete/drop before this future resolves;
    /// never detach it. Post-publication internal failure must force-stop Root.
    fn transact(
        &self,
        transaction: AdminTransaction,
        finisher: AdminFinisher,
    ) -> AdminFuture<Committed>;
    /// Stateless adaptation; never obtain the Root transaction lock here,
    /// because a candidate's delay-zero loader may call it from its finisher.
    fn adapt(
        &self,
        input: Vec<u8>,
        adapter: Option<String>,
        filename: Option<String>,
    ) -> AdminFuture<AdaptedConfig>;
    /// Read the committed clientAuth identity without obtaining a transaction lock.
    fn active_identity_client(&self) -> Option<Arc<dyn rustls::client::ResolvesClientCert>> {
        None
    }
    /// Force must synchronously fence publication/admission when called; its
    /// future owns the bounded join. This also holds during runtime teardown;
    /// the call must not wait for a lock held by a suspended transaction.
    fn stop(&self, mode: StopMode) -> AdminFuture<()>;
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

/// Share the validated loader schema with the root lifecycle, including delayed
/// loaders whose client identity must be ready before configuration publication.
pub fn client_identity_required(config: &Value) -> Result<bool, AdminError> {
    Ok(policy::LocalPolicy::parse(config)?
        .loader
        .is_some_and(|plan| plan.http.tls.is_some_and(|tls| tls.use_server_identity)))
}
