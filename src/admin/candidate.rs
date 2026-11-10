//! Explicit candidate capabilities. Backends retain the non-cloneable owner
//! until publication or abort; finishers receive only a cloneable handle.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::client::ResolvesClientCert;
use rustls::server::ResolvesServerCert;
use tokio_util::sync::CancellationToken;

use super::{AdminError, AdminFuture};

/// A capability scope for candidate-specific async operations.
///
/// Implementations are responsible for managing their own lifecycle,
/// including any necessary background task supervision and cancellation.
pub trait CandidateScope: Send + Sync + 'static {
    /// Resolve a server certificate.
    fn identity(&self) -> AdminFuture<Arc<dyn ResolvesServerCert>>;

    /// Resolve a client certificate.
    fn identity_client(&self) -> AdminFuture<Arc<dyn ResolvesClientCert>>;

    /// Get a cancellation token for the scope.
    fn cancellation(&self) -> CancellationToken;

    /// Capture a read-only completion signal while this exact candidate is
    /// open. The future may outlive the owner but grants no identity, listener
    /// or publication capability. Backends without delayed retirement complete
    /// immediately. A finisher captures this future; it must not await it before
    /// the candidate is published.
    fn publication_completion(&self) -> AdminFuture<()> {
        Box::pin(async { Ok(()) })
    }
}

struct State {
    scope: Arc<dyn CandidateScope>,
    closed: AtomicBool,
}

/// A handle to a candidate capability.
///
/// Closing the owner prevents new uses of this handle, returning
/// a 409 error, but does not forcibly cancel ongoing background
/// tasks managed by the underlying scope.
#[derive(Clone)]
pub struct CandidateHandle(Arc<State>);

/// The owner of a candidate handle.
///
/// Closing this owner (explicitly or via Drop) marks the associated
/// handles as closed. It does not perform I/O, cancel the root,
/// spawn tasks, or modify the scope's own state.
pub struct CandidateOwner {
    state: Arc<State>,
}

impl CandidateOwner {
    /// Create a new owner from a given scope.
    pub fn new(scope: Arc<dyn CandidateScope>) -> Self {
        Self {
            state: Arc::new(State {
                scope,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Get a cloneable handle to this owner's state.
    pub fn handle(&self) -> CandidateHandle {
        CandidateHandle(Arc::clone(&self.state))
    }

    /// Mark the owner as closed. Idempotent.
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Release);
    }
}

impl Drop for CandidateOwner {
    fn drop(&mut self) {
        self.close();
    }
}

impl CandidateHandle {
    /// Asynchronously resolve a server certificate.
    pub fn identity(&self) -> AdminFuture<Arc<dyn ResolvesServerCert>> {
        let state = Arc::clone(&self.0);
        Box::pin(async move {
            check_open(&state)?;
            let result = state.scope.identity().await;
            check_open(&state)?;
            result
        })
    }

    /// Asynchronously resolve a client certificate.
    pub fn identity_client(&self) -> AdminFuture<Arc<dyn ResolvesClientCert>> {
        let state = Arc::clone(&self.0);
        Box::pin(async move {
            check_open(&state)?;
            let result = state.scope.identity_client().await;
            check_open(&state)?;
            result
        })
    }

    /// Get a cancellation token from the scope, if the handle is open.
    pub fn cancellation(&self) -> Result<CancellationToken, AdminError> {
        check_open(&self.0)?;
        Ok(self.0.scope.cancellation())
    }

    pub fn publication_completion(&self) -> Result<AdminFuture<()>, AdminError> {
        check_open(&self.0)?;
        Ok(self.0.scope.publication_completion())
    }
}

fn check_open(state: &State) -> Result<(), AdminError> {
    if state.closed.load(Ordering::Acquire) {
        Err(AdminError::new(409, "candidate_handle_closed"))
    } else {
        Ok(())
    }
}
