//! One owned ACME TXT lookup through the existing Go-compatible DNS engine.
//! This entry returns only a scalar; no unleased raw DNS/hosts graph escapes.
use super::{
    proxy_dynamic::{DnsLimits, DnsShared},
    resource_budget::BlockingBudget,
};
use anyhow::{Result, anyhow};
use std::{
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
pub(crate) fn validate_resolvers(addresses: &[String]) -> Result<()> {
    super::proxy_dynamic::validate_acme_resolvers(addresses)
}

struct Lookup {
    name: String,
    resolvers: Arc<[String]>,
    expected: Vec<u8>,
    dns: Arc<DnsShared>,
    metadata: BlockingBudget,
    cancel: CancellationToken,
    timeout: Duration,
    _owner: Arc<dyn crate::cert_cpu::MaterialOwner>,
}
impl Lookup {
    async fn execute(self) -> Result<bool> {
        let result = tokio::select! {biased;
            _=self.cancel.cancelled()=>Err(anyhow!("ACME DNS lookup cancelled")),
            _=tokio::time::sleep(self.timeout)=>Err(anyhow!("ACME DNS lookup deadline exceeded")),
            result=self.dns.lookup_txt(&self.name,self.resolvers.clone())=>result.map(|values|values.iter().any(|value|value==&self.expected)),
        };
        // Stop logical transport producers before closing their metadata lane.
        // Accepted blocking work and background futures each hold the same
        // owner, so an outer cancellation/panic cannot refund beneath them.
        self.dns.shutdown().await;
        let tasks = self.metadata.tasks();
        tasks.close();
        tasks.wait().await;
        result
    }
}
impl Drop for Lookup {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.dns.close();
        self.metadata.tasks().close();
    }
}
pub(crate) fn matches(
    name: String,
    resolvers: Arc<[String]>,
    expected: Vec<u8>,
    owner: Arc<dyn crate::cert_cpu::MaterialOwner>,
    cancel: CancellationToken,
    timeout: Duration,
) -> Result<impl std::future::Future<Output = Result<bool>> + Send> {
    owner.reserve(12 * 1024 * 1024)?;
    let cancel = cancel.child_token();
    let tasks = TaskTracker::new();
    let stop = cancel.clone();
    let metadata = BlockingBudget::new(1, 4, Duration::from_secs(1))?;
    let dns = DnsShared::new(
        tasks,
        stop,
        Arc::new(Semaphore::new(4)),
        Arc::new(AtomicU64::new(0)),
        DnsLimits {
            lookup_concurrency: 1,
            max_queued: 1,
        },
        Arc::new(|raw| {
            crate::http_config::helpers::replace(
                raw,
                true,
                crate::http_config::helpers::global_lookup,
            )
        }),
        metadata.clone(),
        None,
    )?
    .with_retained_owner(owner.clone())?;
    // Construct the aggregate before first poll. Its actual data fields retire
    // before the credit even if the task is never polled.
    Ok(Lookup {
        name,
        resolvers,
        expected,
        dns,
        metadata,
        cancel,
        timeout,
        _owner: owner,
    }
    .execute())
}
