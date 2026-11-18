//! Optional transport observation of the HTTP client protocol phase.
use std::{fmt, sync::Arc};

/// Observes whether an HTTP client connection is between exchanges.
///
/// The callback is synchronous and must not block or re-enter the connection.
/// HTTP/1 upgrades remain active. Multiplexed clients report aggregate activity.
#[derive(Clone)]
pub struct NativeClientActivity(Arc<dyn Fn(bool) + Send + Sync>);

impl NativeClientActivity {
    /// Creates an observer. `true` denotes idle and `false` an active exchange.
    pub fn new(callback: impl Fn(bool) + Send + Sync + 'static) -> Self {
        Self(Arc::new(callback))
    }

    pub(crate) fn notify(&self, idle: bool) {
        (self.0)(idle);
    }
}

impl fmt::Debug for NativeClientActivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeClientActivity")
    }
}
