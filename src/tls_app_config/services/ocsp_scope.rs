//! One OCSP scope owns its actual runner and event watcher. Closing a tracker
//! alone does not prohibit spawn; the shared admission check is the spawn gate.
use super::*;
use futures_util::FutureExt;
use std::ops::Deref;

#[derive(Clone)]
pub(super) struct OcspScope(Arc<Inner>);
struct Inner {
    manager: OcspManager,
    cancel: CancellationToken,
    tasks: TaskTracker,
    admission: Mutex<bool>,
    names: Vec<String>,
}
impl OcspScope {
    pub(super) fn new(
        manager: OcspManager,
        names: Vec<String>,
        parent: &CancellationToken,
    ) -> Self {
        Self(Arc::new(Inner {
            manager,
            names,
            cancel: parent.child_token(),
            tasks: TaskTracker::new(),
            admission: Mutex::new(false),
        }))
    }
    pub(super) fn start(&self, service: &Arc<CertificateServices>) -> Result<()> {
        let _parent = service
            .admission
            .lock()
            .map_err(|_| anyhow!("certificate service admission unavailable"))?;
        let mut started = self
            .0
            .admission
            .lock()
            .map_err(|_| anyhow!("OCSP scope admission unavailable"))?;
        if service.context.cancel.is_cancelled() || self.0.cancel.is_cancelled() || *started {
            return Ok(());
        }
        *started = true;
        let mut receiver = self.0.manager.subscribe();
        let resources = service.context.resources.clone();
        let cancel = self.0.cancel.clone();
        self.0.tasks.spawn(service.tasks.track_future(async move {loop {tokio::select! {biased;
            _=cancel.cancelled()=>break,
            event=receiver.recv()=>match event {
                Ok(event)=>if event.status.is_some_and(|status|status.state==OcspState::Revoked){resources.revoked.notify_waiters();},
                Err(broadcast::error::RecvError::Lagged(_))=>resources.revoked.notify_waiters(),
                Err(broadcast::error::RecvError::Closed)=>break,
            }
        }}}));
        let manager = self.0.manager.clone();
        let cancel = self.0.cancel.clone();
        let events = service.events.clone();
        let names = self.0.names.clone();
        self.0.tasks.spawn(service.tasks.track_future(async move {
            let result = std::panic::AssertUnwindSafe(manager.run(cancel.clone()))
                .catch_unwind()
                .await;
            cancel.cancel();
            if !matches!(result, Ok(Ok(()))) {
                let _ = events.send(CertificateEvent {
                    kind: "ocsp_maintenance_failed",
                    names,
                });
            }
        }));
        self.0.tasks.close();
        Ok(())
    }
    pub(super) async fn stop(&self) -> Result<()> {
        {
            let _guard = self
                .0
                .admission
                .lock()
                .map_err(|_| anyhow!("OCSP scope admission unavailable"))?;
            self.0.cancel.cancel();
            self.0.tasks.close();
        }
        self.0.tasks.wait().await;
        Ok(())
    }
}
impl Deref for OcspScope {
    type Target = OcspManager;
    fn deref(&self) -> &Self::Target {
        &self.0.manager
    }
}
