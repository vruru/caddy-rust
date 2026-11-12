//! Generation-scoped preparation of a secret account-key configuration value.
use crate::cert_automation::ConfiguredAccountKey;
use anyhow::{Result, anyhow, ensure};
use std::{cell::Cell, sync::Arc};
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const MAX_PEM: usize = 128 * 1024;
pub(super) struct Input {
    raw: Arc<Zeroizing<String>>,
    ready: OnceCell<Arc<ConfiguredAccountKey>>,
}
impl Input {
    pub(super) fn new(raw: &str) -> Result<Self> {
        ensure!(
            !raw.is_empty() && raw.len() <= MAX_PEM,
            "configured ACME account key input exceeds bounds"
        );
        Ok(Self {
            raw: Arc::new(Zeroizing::new(raw.to_owned())),
            ready: OnceCell::new(),
        })
    }
    pub(super) async fn prepare(
        &self,
        cpu: Arc<Semaphore>,
        cancel: CancellationToken,
    ) -> Result<Arc<ConfiguredAccountKey>> {
        self.ready
            .get_or_try_init(|| {
                let raw = self.raw.clone();
                crate::cert_cpu::run(cpu, cancel, move || {
                    // Includes the bounded file provider's temporary input and
                    // placeholder old/new output buffers. No network uses this
                    // loan, and it is not retained by the prepared signing key.
                    let _credit = crate::cert_transient::reserve(4 * 1024 * 1024)?;
                    let invalid = Cell::new(false);
                    let resolved = crate::http_config::helpers::replace_accounted(
                        &raw,
                        false,
                        |name| {
                            let value = match crate::http_config::helpers::prepare_file_lookup(name)
                            {
                                Some(value) => value.ok(),
                                None => crate::http_config::helpers::global_lookup(name),
                            };
                            if value.as_ref().is_none_or(String::is_empty) {
                                invalid.set(true);
                            }
                            value
                        },
                        |capacity| {
                            ensure!(
                                capacity <= 4 * MAX_PEM,
                                "configured ACME account key expansion exceeds bounds"
                            );
                            Ok(())
                        },
                    )
                    .map_err(|_| anyhow!("configured ACME account key expansion failed"))?;
                    let resolved = Zeroizing::new(resolved);
                    ensure!(
                        !invalid.get() && !resolved.is_empty() && resolved.len() <= MAX_PEM,
                        "configured ACME account key expansion failed"
                    );
                    // Go defers private-key parsing until this issuer is used.
                    // Preserve issuer fallback for an invalid PEM while still
                    // rejecting unknown/empty placeholders during provisioning.
                    let key = ConfiguredAccountKey::from_pem(resolved.as_bytes())
                        .unwrap_or_else(|_| ConfiguredAccountKey::invalid(resolved.as_bytes()));
                    Ok(Arc::new(key))
                })
            })
            .await
            .cloned()
    }
}
