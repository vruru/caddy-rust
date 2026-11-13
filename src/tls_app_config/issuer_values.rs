//! Generation-owned ACME global values. Raw/admin configuration stays raw;
//! preparation performs bounded provider work once before activation.
use super::model::{CertificatePlan, Issuer};
use crate::{
    acme_wire::chain_memory::{Lease, Pool},
    cert_automation::{AcmeIssuerConfig, ExternalAccountBinding},
};
use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::{cell::Cell, sync::Arc};
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
const FIELD: usize = 1 << 20;
const SCRATCH: usize = 16 * FIELD + 16384;

struct Raw {
    directory: Zeroizing<String>,
    email: Zeroizing<String>,
    eab: Option<(Zeroizing<String>, Zeroizing<String>)>,
}
pub(super) struct Input {
    raw: Arc<Raw>,
    id: [u8; 32],
    ready: OnceCell<Arc<Prepared>>,
}
pub(super) struct Prepared {
    pub directory: String,
    pub email: String,
    pub eab: Option<ExternalAccountBinding>,
    // Strings/secret fields retire before the callback-free resident allowance.
    _memory: Lease,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.email.zeroize();
        if let Some(eab) = self.eab.as_mut() {
            eab.kid.zeroize();
            eab.hmac_key.zeroize();
        }
    }
}
impl Prepared {
    pub(super) fn apply(&self, config: &mut AcmeIssuerConfig) {
        config.wire.directory = self.directory.clone();
        config.email = self.email.clone();
        config.eab = self.eab.clone();
    }
    /// Peak includes the manager's three simultaneous config copies, later WireOptions
    /// and parsed/request URL copies. It covers Caddy-owned configured strings,
    /// not remote bodies or third-party provider/TLS heaps.
    pub(super) fn copy_upper(&self) -> Result<usize> {
        let bytes = self
            .directory
            .len()
            .checked_add(self.email.len())
            .and_then(|n| {
                n.checked_add(
                    self.eab
                        .as_ref()
                        .map_or(0, |e| e.kid.len() + e.hmac_key.len()),
                )
            })
            .ok_or(crate::acme_wire::chain_memory::MemoryDenied)?;
        bytes
            .checked_mul(12)
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(|| crate::acme_wire::chain_memory::MemoryDenied.into())
    }
}
fn expand(raw: &str, field: &'static str) -> Result<String> {
    // Go skips replacement for raw empty fields, but a placeholder yielding
    // empty or unknown is an error (ReplaceOrErr true,true).
    if raw.is_empty() {
        return Ok(String::new());
    }
    let invalid = Cell::new(false);
    let value = crate::http_config::helpers::replace_accounted(
        raw,
        false,
        |name| {
            let value = match crate::http_config::helpers::prepare_file_lookup(name) {
                Some(v) => v.ok(),
                None => crate::http_config::helpers::global_lookup(name),
            };
            if value.as_ref().is_none_or(String::is_empty) {
                invalid.set(true)
            }
            value
        },
        |capacity| {
            ensure!(capacity <= 2 * FIELD, "ACME configured value exceeds limit");
            Ok(())
        },
    )
    .map_err(|_| anyhow!("ACME configured {field} expansion failed"))?;
    ensure!(
        !invalid.get() && value.len() <= FIELD,
        "ACME configured {field} expansion failed"
    );
    Ok(value)
}
impl Input {
    pub(super) fn take(config: &mut AcmeIssuerConfig) -> Result<Option<Arc<Self>>> {
        let dynamic = config.wire.directory.contains('{')
            || config.email.contains('{')
            || config
                .eab
                .as_ref()
                .is_some_and(|e| e.kid.contains('{') || e.hmac_key.contains('{'));
        if !dynamic {
            return Ok(None);
        }
        let raw = Raw {
            directory: Zeroizing::new(std::mem::take(&mut config.wire.directory)),
            email: Zeroizing::new(std::mem::take(&mut config.email)),
            eab: config.eab.take().map(|mut e| {
                (
                    Zeroizing::new(std::mem::take(&mut e.kid)),
                    Zeroizing::new(std::mem::take(&mut e.hmac_key)),
                )
            }),
        };
        let mut hash = Sha256::new();
        hash.update(b"acme-configured-fields-v1");
        for value in [&*raw.directory, &*raw.email] {
            hash.update(value.len().to_be_bytes());
            hash.update(value.as_bytes());
        }
        if let Some((kid, key)) = &raw.eab {
            hash.update([1]);
            for value in [&**kid, &**key] {
                hash.update(value.len().to_be_bytes());
                hash.update(value.as_bytes());
            }
        } else {
            hash.update([0]);
        }
        Ok(Some(Arc::new(Self {
            raw: Arc::new(raw),
            id: hash.finalize().into(),
            ready: OnceCell::new(),
        })))
    }
    pub(super) async fn prepare(
        &self,
        cpu: Arc<Semaphore>,
        pool: Arc<Pool>,
        cancel: CancellationToken,
    ) -> Result<Arc<Prepared>> {
        self.ready
            .get_or_try_init(|| {
                let raw = self.raw.clone();
                crate::cert_cpu::run(cpu, cancel, move || {
                    let _scratch = crate::cert_transient::reserve(SCRATCH)?;
                    let directory = expand(&raw.directory, "CA")?;
                    let directory =
                        crate::acme_wire::directory_url::normalize(&directory)?.to_string();
                    ensure!(directory.len() <= FIELD, "ACME configured CA exceeds limit");
                    let email = expand(&raw.email, "email")?;
                    let eab = raw
                        .eab
                        .as_ref()
                        .map(|(kid, key)| {
                            Ok::<_, anyhow::Error>(ExternalAccountBinding {
                                kid: expand(kid, "EAB key ID")?,
                                hmac_key: expand(key, "EAB MAC key")?,
                            })
                        })
                        .transpose()?;
                    let bytes = directory
                        .capacity()
                        .checked_add(email.capacity())
                        .and_then(|n| {
                            n.checked_add(
                                eab.as_ref()
                                    .map_or(0, |e| e.kid.capacity() + e.hmac_key.capacity()),
                            )
                        })
                        .and_then(|n| n.checked_add(std::mem::size_of::<Prepared>() + 512))
                        .ok_or(crate::acme_wire::chain_memory::MemoryDenied)?;
                    let memory = pool.reserve(bytes)?;
                    Ok(Arc::new(Prepared {
                        directory,
                        email,
                        eab,
                        _memory: memory,
                    }))
                })
            })
            .await
            .cloned()
    }
    pub(super) fn get(&self) -> Result<&Arc<Prepared>> {
        self.ready
            .get()
            .ok_or_else(|| anyhow!("ACME configured values are not prepared"))
    }
}
fn inputs(plan: &CertificatePlan) -> impl Iterator<Item = &Arc<Input>> {
    plan.policies
        .iter()
        .flat_map(|p| p.issuers.iter())
        .chain(plan.identity.iter().flat_map(|i| i.issuers.iter()))
        .filter_map(|issuer| match issuer {
            Issuer::Acme(settings) => settings.values.as_ref(),
            _ => None,
        })
}
pub(super) async fn prepare_all(
    plan: &CertificatePlan,
    cpu: Arc<Semaphore>,
    pool: Arc<Pool>,
    cancel: CancellationToken,
) -> Result<()> {
    use futures_util::{StreamExt, stream::FuturesUnordered};
    if inputs(plan).next().is_none() {
        return Ok(());
    }
    // Fixed queue/future metadata is prepaid before creating the rolling set.
    // Four 16MiB+16KiB jobs cannot fit the existing 64MiB scratch aggregate;
    // derive the actual window (three) without weakening an individual bound.
    const WINDOW_MEMORY: usize = 32 * 1024;
    let _window_memory = crate::cert_transient::reserve(WINDOW_MEMORY)?;
    let window = 4
        .min((crate::acme_wire::chain_memory::SCRATCH_LIMIT - WINDOW_MEMORY) / SCRATCH)
        .max(1);
    let work_cancel = cancel.child_token();
    let _cancel_on_drop = work_cancel.clone().drop_guard();
    let mut remaining = inputs(plan);
    let mut running = FuturesUnordered::new();
    for input in remaining.by_ref().take(window) {
        running.push(input.prepare(cpu.clone(), pool.clone(), work_cancel.clone()));
    }
    let mut failure = None;
    let mut completed = 0usize;
    while let Some(result) = running.next().await {
        if let Err(error) = result {
            if failure.is_none() {
                failure = Some(error);
                work_cancel.cancel();
            }
        }
        // A failed window starts no further work. Drain the already accepted
        // futures; cert_cpu::run joins a started blocking worker when cancelled.
        if failure.is_none() {
            if let Some(input) = remaining.next() {
                running.push(input.prepare(cpu.clone(), pool.clone(), work_cancel.clone()));
            }
        }
        completed += 1;
        if completed.is_multiple_of(32) {
            tokio::task::yield_now().await;
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
struct Snapshot {
    id: [u8; 32],
    value: Arc<Prepared>,
}
pub(super) struct Retained {
    values: Vec<Snapshot>,
    _memory: Lease,
}
pub(super) fn retain(plan: &CertificatePlan, pool: &Arc<Pool>) -> Result<Option<Arc<Retained>>> {
    let count = inputs(plan).count();
    if count == 0 {
        return Ok(None);
    }
    let bytes = count
        .checked_mul(std::mem::size_of::<Snapshot>())
        .and_then(|n| n.checked_add(std::mem::size_of::<Retained>() + 256))
        .ok_or(crate::acme_wire::chain_memory::MemoryDenied)?;
    let memory = pool.reserve(bytes)?;
    let mut values = Vec::new();
    values.try_reserve_exact(count)?;
    for input in inputs(plan) {
        values.push(Snapshot {
            id: input.id,
            value: input.get()?.clone(),
        });
    }
    Ok(Some(Arc::new(Retained {
        values,
        _memory: memory,
    })))
}
pub(super) fn restore(plan: &CertificatePlan, retained: Option<&Retained>) -> Result<()> {
    let expected = inputs(plan).count();
    let stored = retained.map_or(&[][..], |r| r.values.as_slice());
    ensure!(
        expected == stored.len(),
        "retained ACME configured value count changed"
    );
    for (input, saved) in inputs(plan).zip(stored) {
        ensure!(
            input.id == saved.id,
            "retained ACME configured value identity changed"
        );
        input
            .ready
            .set(saved.value.clone())
            .map_err(|_| anyhow!("ACME configured values already prepared"))?;
    }
    Ok(())
}
