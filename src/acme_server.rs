//! Native ACME server. Cryptographic verification and Bolt transactions run in
//! an independent owned lane, with original Smallstep record compatibility.
#[path = "acme_server/actor.rs"]
mod actor;
#[path = "acme_server/bolt/mod.rs"]
mod bolt;
#[path = "acme_server/config.rs"]
mod config;
#[path = "acme_server/controller.rs"]
mod controller;
#[path = "acme_server/finalize.rs"]
mod finalize;
#[path = "acme_server/jws.rs"]
mod jws;
#[path = "acme_server/key_change.rs"]
mod key_change;
#[path = "acme_server/orders.rs"]
mod orders;
#[path = "acme_server/policy.rs"]
mod policy;
#[path = "acme_server/problems.rs"]
mod problems;
#[path = "acme_server/records.rs"]
mod records;
#[path = "acme_server/registry.rs"]
mod registry;
#[path = "acme_server/resources.rs"]
mod resources;
#[path = "acme_server/revoke.rs"]
mod revoke;
#[path = "acme_server/store.rs"]
mod store;
#[path = "acme_server/validate.rs"]
mod validate;
#[path = "acme_server/views.rs"]
mod views;
use anyhow::{Result, ensure};
pub use config::Config;
pub(crate) use config::parse;
pub use controller::Controller;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

pub(crate) struct Shared {
    registry: registry::Registry,
    resources: Arc<resources::Resources>,
}
impl Shared {
    pub(crate) fn new() -> Arc<Self> {
        let resources =
            resources::Resources::new(Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)));
        Arc::new(Self {
            registry: registry::Registry::new(resources.clone()),
            resources,
        })
    }
    pub(crate) async fn prepare(
        &self,
        config: Arc<Config>,
        pki: crate::local_pki::LocalPki,
        root: &Path,
        cancel: CancellationToken,
    ) -> Result<Arc<Controller>> {
        let path = database_path(root, &config.ca)?;
        let directory = path.parent().expect("database has parent").to_owned();
        let token = cancel.clone();
        crate::cert_cpu::run(self.resources.cpu.clone(), cancel.clone(), move || {
            ensure!(!token.is_cancelled(), "ACME preparation cancelled");
            std::fs::create_dir_all(directory)?;
            Ok(())
        })
        .await?;
        let database = self
            .registry
            .open(&path, &config.ca, cancel.clone())
            .await?;
        let scope = self.resources.scope(cancel, false)?;
        let authority = config.ca.clone();
        let bound = database
            .call(scope, move |database, meter| {
                database
                    .transaction(meter, |tx| tx.bind_authority(&authority))
                    .map_err(Into::into)
            })
            .await?;
        drop(bound);
        Ok(Arc::new(Controller::new(
            config,
            pki,
            database,
            self.resources.clone(),
        )))
    }
    pub(crate) async fn shutdown(&self) -> Result<()> {
        self.resources.shutdown().await?;
        self.registry.clear();
        Ok(())
    }
    pub(crate) async fn wait_for_retirement(&self) -> Result<()> {
        self.resources.wait_for_retirement().await
    }
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.resources.cancel.cancel();
    }
}
fn database_path(root: &Path, ca: &str) -> Result<PathBuf> {
    // Preserve the original ASCII regexp's .-_ range, but never let its slash
    // or backslash acceptance escape the application-owned database directory.
    let lower = ca.trim().to_lowercase();
    let key = lower
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || *b == b'-' || (b'.'..=b'_').contains(b))
        .map(char::from)
        .collect::<String>();
    ensure!(
        !ca.is_empty() && key != "." && key != ".." && !key.contains(['/', '\\']),
        "unsafe ACME authority storage component"
    );
    ensure!(root.is_absolute(), "ACME storage root must be absolute");
    // A Unicode-only original identifier sanitizes to empty. Its legacy file
    // is acme_server/db (still inside the owned root); the raw authority marker
    // prevents a second, colliding CA from silently sharing that database.
    Ok(root.join("acme_server").join(key).join("db"))
}
