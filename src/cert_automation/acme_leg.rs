//! Root-owned ACME legs retire their concrete client before fallback.
//! Public standalone managers keep their existing caller-owned lifetime.
use super::*;
use super::backend::{Backend, BackendKind};

/// An old active remote order cannot be retired by an unrelated directory
/// rejection. Keep the original typed cause; only reconciliation may clear it.
#[derive(Debug)]
pub(super) struct ExistingActiveOrder;
impl std::fmt::Display for ExistingActiveOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("existing ACME order must be reconciled before issuer fallback") }
}
impl std::error::Error for ExistingActiveOrder {}

/// The existing configured-key PreCheck can fail before any request exists.
#[derive(Debug)]
pub(super) struct PrecheckUnavailable;
impl std::fmt::Display for PrecheckUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("configured ACME credential unavailable before request") }
}
impl std::error::Error for PrecheckUnavailable {}

/// Constructible only after a read-only leg's real work has been joined.
/// The original cause remains available without changing public wire errors.
#[derive(Debug)]
pub(super) struct RetiredReadTimeout(anyhow::Error);
impl std::fmt::Display for RetiredReadTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("retired ACME read-only leg timed out")
    }
}
impl std::error::Error for RetiredReadTimeout {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(self.0.as_ref()) }
}

pub(super) struct Leg {
    owner: crate::outgoing_tls::ScopeOwner,
    cleanup: Arc<crate::acme_wire::ChainCleanup>,
    writes: Arc<std::sync::atomic::AtomicBool>,
    // Data and the actual closed scope precede their construction allowance.
    _memory: crate::acme_wire::chain_memory::Scratch,
}
impl Leg {
    fn new(manager: &CertificateManager) -> Result<Self> {
        let memory = crate::cert_transient::reserve(
            std::mem::size_of::<Self>() + std::mem::size_of::<crate::acme_wire::ChainCleanup>() + 2048,
        )?;
        let parent = manager.inner.leg_parent.as_ref().ok_or_else(|| anyhow!("native issuer leg parent missing"))?;
        let owner = manager.inner.outgoing_tls.as_ref().ok_or_else(|| anyhow!("native issuer leg scope missing"))?.issuer_leg()?;
        Ok(Self { owner, cleanup: Arc::new(crate::acme_wire::ChainCleanup::with_parent(parent.clone())),
            writes: Arc::new(std::sync::atomic::AtomicBool::new(false)), _memory: memory })
    }
    pub(super) async fn wire(&self, manager: &CertificateManager, issuer: &IssuerState,
        cancel: &CancellationToken) -> Result<AcmeWire> {
                // Reserve the concrete option copy before Clone, and retain it
                // through the client/connector/IO lifetime using the old pool.
                let text = issuer.config.wire.directory.len()
                    .checked_add(issuer.config.wire.extra_ca_pem.iter().try_fold(0usize, |n, b| n.checked_add(b.len())).ok_or(crate::cert_transient::ResourceDenied)?)
                    .and_then(|n| issuer.config.wire.trusted_ca_origins.iter().try_fold(n, |n, s| n.checked_add(s.len())))
                    .ok_or(crate::cert_transient::ResourceDenied)?;
                let proxy = issuer.config.wire.network_proxy.as_ref().map_or(0, |p| { let (a,b)=p.fingerprint(); a.len()+b.len() });
                let bytes = text.checked_add(proxy).and_then(|n| n.checked_mul(4)).and_then(|n| n.checked_add(16384))
                    .ok_or(crate::cert_transient::ResourceDenied)?;
                let credit = Arc::new(manager.inner.chain_memory.payload.reserve(bytes)?);
                let owner = manager.wire_client_owner_for(issuer).with_additional_values_credit(credit)?;
                AcmeWire::connect_with_client_tls_scope(issuer.config.wire.clone(), manager.inner.local.clone(),
                    manager.inner.chain_memory.clone(), Some(self.owner.scope()), owner, cancel).await?
                    .with_native_leg(self.writes.clone(), self.cleanup.clone())
    }
    async fn retire(&self) {
        // The calling owned task has already consumed and dropped the complete
        // operation. A retained metadata-only error is not an IO receipt.
        self.owner.close();
        self.cleanup.drain().await;
        self.owner.scope().wait_physical().await;
    }
}

impl CertificateManager {
    pub(super) fn scoped_acme_legs(&self) -> bool {
        self.inner.outgoing_tls.is_some() && self.inner.leg_parent.is_some()
    }

    pub(super) async fn issue_scoped_acme_leg(
        &self, names: &[String], backend: &Backend, attempt_id: &str,
        input: &Arc<attempt::RuntimeInput>, previous: &mut Option<Replacement>,
        lifecycle: &crate::cert_events::Attempt, cancel: &CancellationToken,
        storage_check: &mut storage_check::CheckState, produced: &std::sync::atomic::AtomicBool,
        round: retry_operation::AcmeRound<'_>, can_try_next: bool,
    ) -> Result<ManagedCertificate> {
        let BackendKind::Acme(index) = backend.kind else { bail!("native ACME leg backend changed") };
        let issuer = &self.inner.issuers[index];
        let leg = Leg::new(self)?;
        let work = cancel.child_token();
        let mut lease = None;
        let mut old_reservation = true;
        let mut deadline_fired = false;
        let budget = (self.inner.options.job_timeout / (self.inner.backends.len() as u32 + 1))
            .min(Duration::from_secs(120)).max(Duration::from_secs(1));
        let result = {
            let operation = async {
                // Unknown is not absence. Validate the durable reservation
                // before any network operation can time out.
                let reservation = self.read_reservation(names, issuer).await?;
                old_reservation = reservation.is_some();
                let state = self.load_attempt(names).await?.ok_or_else(|| anyhow!("certificate attempt disappeared"))?;
                old_reservation |= state.acme_phase.is_some();
                let test_driver = self.uses_test_driver(index, &state);
                if let Some(key) = &issuer.config.account_key {
                    match key.signer() {
                        Ok(_) => {},
                        Err(error) if error.is::<super::account_key::CredentialUnavailable>() => return Err(error.context(PrecheckUnavailable)),
                        Err(error) => return Err(error),
                    }
                }
                let allowed = issuer.ca.next_allowed_unix.load(Ordering::Acquire);
                if !test_driver && allowed > now() { return Err(RetryAfterError(allowed).into()); }
                let session = if test_driver { None } else {
                    let network = self.net_permit(issuer, &work).await?;
                    let wire = leg.wire(self, issuer, &work).await?;
                    let session = self.account(issuer, &wire, reservation.as_ref().map(|r| r.account_location.as_str()), &work).await?;
                    // Account confirmation cannot clear the separate durable
                    // old-order/phase barrier maintained above.
                    wire.account_setup_confirmed();
                    drop(network);
                    Some(session)
                };
                lease = Some(self.inner.store.lock(&format!("issue_cert_{}", names[0]), cancel.clone()).await?);
                let lease = lease.as_ref().ok_or_else(|| anyhow!("native issuer lease missing"))?;
                let lost = lease.lost();
                let issuance = async {
                let (ready, replacement) = self.load_state(names, lease, &work, storage_check).await?;
                if let Some(ready) = ready { return Ok(ready); }
                if replacement.is_some() { *previous = replacement; }
                let active = self.load_attempt(names).await?.ok_or_else(|| anyhow!("certificate attempt disappeared"))?;
                ensure!(active.attempt_id == attempt_id && active.winner.is_none(), "certificate attempt superseded");
                self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;
                self.inner.store.recover_certificate_with_lease(&backend.storage_key, &names_key(names)?, lease).await?;
                let _ = self.read_issuer_certificate(&backend.storage_key, &names_key(names)?, &work).await?;
                if test_driver {
                    return self.issue_test_ca_leg(index, names, attempt_id, input, previous.as_ref(), lease,
                        lifecycle, &work, round, produced, Some(&leg)).await;
                }
                let session = session.as_ref().ok_or_else(|| anyhow!("ACME account preparation missing"))?;
                let current = self.read_reservation(names, issuer).await?;
                ensure!(current.as_ref().map(|r|r.job_id.as_str()) == reservation.as_ref().map(|r|r.job_id.as_str()),
                    "issuer reservation changed during account preparation");
                if let Some(current) = &current { ensure!(current.account_location == session.location(), "ACME account identity changed"); }
                let current = if let Some(marker) = current {
                    if self.retire_compromised_job(&marker, lease, &work).await? { None } else { Some(marker) }
                } else { None };
                let leg_input = match current.as_ref() {
                    Some(current) => self.input_for_job(current, attempt_id, input.clone(), &work).await?,
                    None => input.clone(),
                };
                let _network = self.net_permit(issuer, &work).await?;
                let allowed = issuer.ca.next_allowed_unix.load(Ordering::Acquire);
                if allowed > now() { return Err(RetryAfterError(allowed).into()); }
                self.issue(names, issuer, session, lease, (previous.as_ref(), current.as_ref(), attempt_id),
                    None, lifecycle, &work, Some(&leg_input), Some(produced), round.ordinal).await
                };
                tokio::pin!(issuance);
                tokio::select! {
                    value = &mut issuance => value,
                    _ = lost.cancelled() => {
                        work.cancel(); let _ = issuance.await;
                        Err(anyhow!("certificate storage lease lost"))
                    }
                }
            };
            tokio::pin!(operation);
            tokio::select! {
                value = &mut operation => value,
                _ = cancel.cancelled() => {
                    work.cancel(); let _ = operation.await;
                    Err(anyhow!("certificate acquisition cancelled"))
                },
                _ = tokio::time::sleep(budget) => {
                    deadline_fired = true; work.cancel(); operation.await
                },
            }
            // The Pin and its whole future, account, response and graph data
            // are destroyed here, before retiring any physical scope token.
        };
        work.cancel();
        leg.retire().await;
        let result = if old_reservation {
            result.map_err(|error| {
                if super::backend::unavailable(&error, cancel) || error.is::<RetryAfterError>() {
                    error.context(ExistingActiveOrder)
                } else { error }
            })
        } else { result };
        let read_timeout = result.as_ref().is_err_and(|error| {
            let wire_cancel = error.is::<crate::acme_wire::AcmeRequestCancelled>();
            let wire_timeout = error.chain().any(|cause| cause.downcast_ref::<reqwest::Error>().is_some_and(reqwest::Error::is_timeout));
            !cancel.is_cancelled() && !old_reservation && !produced.load(Ordering::Acquire)
                && !leg.writes.load(Ordering::Acquire)
                && ((deadline_fired && wire_cancel) || wire_timeout)
                && !crate::cert_transient::is_resource(error) && !error.is::<retry_operation::NoRetry>()
        });
        let fallback = !cancel.is_cancelled() && result.as_ref().is_err_and(|error|
            !old_reservation && !error.is::<ExistingActiveOrder>()
                && (read_timeout || super::backend::unavailable(error, cancel) || error.is::<RetryAfterError>()));
        if let Some(lease) = lease {
            // Classification is provisional until the required transaction
            // retirement and explicit heartbeat release have both succeeded.
            let abandoned = if can_try_next && fallback {
                self.abandon_leg(names, attempt_id, &lease).await
            } else { Ok(()) };
            let released = lease.release().await;
            abandoned?;
            released?;
        }
        match result {
            Err(error) if read_timeout && !cancel.is_cancelled() => Err(anyhow::Error::new(RetiredReadTimeout(error))),
            Err(error) if deadline_fired => Err(error.context(super::backend::LegDeadline)),
            result => result,
        }
    }
}
