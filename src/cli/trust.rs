//! Normal-CLI capability only. Configuration gates each installation before
//! this lazy adapter is called. Validation and candidates rejected before
//! activation do not enter it; post-activation compensation cannot undo trust.
use anyhow::Result;
use caddy_compat_native::local_pki::{SystemTrustInstaller, TrustInstaller};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

pub(super) fn installer() -> Arc<dyn TrustInstaller> {
    Arc::new(CliTrustInstaller {
        discovered: OnceCell::new(),
    })
}

struct CliTrustInstaller {
    // One successful discovery/command pool per CLI Root. No Root/Services
    // backlink; all actual installation remains in the existing adapter.
    discovered: OnceCell<SystemTrustInstaller>,
}

impl TrustInstaller for CliTrustInstaller {
    fn install<'a>(
        &'a self,
        root_pem: &'a [u8],
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            anyhow::ensure!(!cancel.is_cancelled(), "trust installation cancelled");
            // Do not select away a discovery or installation future. The
            // existing LocalPki task owns and joins it through shutdown.
            let installer = match self
                .discovered
                .get_or_try_init(SystemTrustInstaller::discover)
                .await
            {
                Ok(installer) => installer,
                Err(error) => {
                    failure("discovery", &error);
                    return Err(error);
                }
            };
            let result = installer.install(root_pem, cancel).await;
            if let Err(error) = &result {
                failure("installation", error);
            }
            // LocalPki reports the original error nonfatally and keeps serving.
            result
        })
    }
}

fn failure(phase: &'static str, error: &anyhow::Error) {
    // Adapter errors can contain command output (tee may echo public PEM).
    // Keep the original cause on the returned error, but log only closed
    // stage/class and numeric OS facts, never arbitrary Display text.
    if let Some(io) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
    {
        eprintln!(
            "pki event=pki_trust_install_failed phase={phase} cause=io kind={:?} errno={:?}",
            io.kind(),
            io.raw_os_error()
        );
    } else {
        eprintln!("pki event=pki_trust_install_failed phase={phase} cause=adapter");
    }
}
