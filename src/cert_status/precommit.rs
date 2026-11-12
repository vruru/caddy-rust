//! Read-only, non-queuing cache authentication for configuration candidates.
use super::*;

#[derive(Debug)]
pub struct OcspProbeBusy;
impl std::fmt::Display for OcspProbeBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OCSP candidate cache verification is busy; retry configuration")
    }
}
impl std::error::Error for OcspProbeBusy {}

impl OcspManager {
    /// Authenticate a candidate's existing raw DER without taking a storage
    /// lease or queuing behind an online request. Real local IO and admitted
    /// crypto are awaited to completion; this is not a hung-disk deadline.
    /// Cancellation never rolls back an already authenticated leaf fact.
    pub async fn probe_cached_one(
        &self,
        certificate: OcspCertificate,
        cancel: CancellationToken,
    ) -> Result<CacheRestore> {
        self.probe_cached(certificate, cancel, false).await
    }

    /// Dynamic acquisition queues within its existing bounded flight/group
    /// admission. This remains a read-only local cache authentication: no
    /// responder request, issuance lease or inline crypto fallback.
    pub(crate) async fn prime_cached_one(
        &self,
        certificate: OcspCertificate,
        cancel: CancellationToken,
    ) -> Result<CacheRestore> {
        self.probe_cached(certificate, cancel, true).await
    }

    async fn probe_cached(
        &self,
        certificate: OcspCertificate,
        cancel: CancellationToken,
        queued: bool,
    ) -> Result<CacheRestore> {
        ensure!(!cancel.is_cancelled(), "OCSP cache probe cancelled");
        if !(self.inner.inventory)(&certificate) {
            return Ok(CacheRestore::NotApplicable);
        }
        let slot = if queued {
            tokio::select! { biased;
                _ = cancel.cancelled() => return Err(anyhow!("OCSP cache probe cancelled")),
                slot = self.inner.restore_slots.clone().acquire_owned() =>
                    slot.map_err(|_| anyhow!("OCSP cache restoration stopped"))?,
            }
        } else {
            self.inner.restore_slots.clone().try_acquire_owned()
                .map_err(|_| anyhow::Error::new(OcspProbeBusy))?
        };
        let gate = self.certificate_gate(&certificate)?;
        let _guard = if queued {
            tokio::select! { biased;
                _ = cancel.cancelled() => return Err(anyhow!("OCSP cache probe cancelled")),
                guard = gate.lock() => guard,
            }
        } else {
            gate.try_lock().map_err(|_| anyhow::Error::new(OcspProbeBusy))?
        };
        let config = self.configuration(&certificate)?;
        if config.disable_stapling {
            self.inner
                .resolver
                .set_ocsp(&certificate.identity, certificate.generation, None)?;
            self.record(&certificate, None, None)?;
            return Ok(CacheRestore::Disabled);
        }
        ensure!(
            !certificate.chain_der.is_empty(),
            "OCSP certificate chain empty"
        );
        let chain=certificate.chain_der.clone();
        let cpu=tokio::select!{biased;_=cancel.cancelled()=>return Err(anyhow!("OCSP cache probe cancelled")),slot=self.inner.cpu_slots.clone().acquire_owned()=>slot.map_err(|_|anyhow!("OCSP CPU dispatch stopped"))?};
        let (inspection,slot)=tokio::task::spawn_blocking(move || {
            let _cpu=cpu;
            let inspection=inspect_certificate(&chain)?;
            Ok::<_,anyhow::Error>((inspection,slot))
        }).await??;
        ensure!(!cancel.is_cancelled(),"OCSP cache probe cancelled");
        let quiet=inspection.quiet;
        if inspection.responder.is_none() {
            if inspection.must_staple {
                self.emit(&certificate, "ocsp_must_staple_unavailable", None, false);
            }
            self.inner.resolver.set_ocsp(&certificate.identity,certificate.generation,None)?;
            self.record(&certificate,None,None)?;
            return Ok(CacheRestore::NotApplicable);
        }
        if certificate.chain_der.len() < 2 {
            return Ok(CacheRestore::NeedsIssuer);
        }
        let key = inspection.cache_key;
        let Some(raw) = self.inner.store.load(&key).await? else {
            self.reconcile_known_negative(&certificate, quiet).await?;
            return Ok(CacheRestore::Missing);
        };
        if raw.len() > 1024 * 1024 {
            self.reconcile_known_negative(&certificate, quiet).await?;
            return Ok(CacheRestore::Invalid);
        }
        ensure!(!cancel.is_cancelled(), "OCSP cache probe cancelled");
        // The owned slot moves into the actual blocking verifier. Dropping a
        // caller's waiter cannot release CPU admission before crypto finishes.
        let verified = verify_owned(
            raw.to_vec(),
            certificate.chain_der[0].clone(),
            certificate.chain_der[1].clone(),
            config.no_next_update_max_age,
            Some(slot),
            None,
            acquire_cpu(self.inner.cpu_slots.clone(), &cancel).await?,
        )
        .await;
        let (status, proof) = match verified {
            Ok(status) => status,
            Err(error) => {
                self.reconcile_known_negative(&certificate, quiet).await?;
                return Ok(if error.is::<verify::ExpiredStatus>() {
                    CacheRestore::Expired
                } else {
                    CacheRestore::Invalid
                });
            }
        };
        self.note_key_compromise(proof, &certificate, quiet);
        // From here all side effects are joined, even if cancellation arrives.
        // Authentication remains a cross-generation fact if the config aborts.
        if let Err(error) = record_leaf(&certificate, &status) {
            self.preserve_negative(&certificate, &status, quiet, None)
                .await?;
            return Err(error);
        }
        if status.state == OcspState::Good && !certificate.leaf_state.admission().allow_staple {
            self.reconcile_known_negative(&certificate, quiet).await?;
            return Ok(CacheRestore::StaleStatus);
        }
        let accepted = match self.observe(&certificate, &status, true) {
            Ok(accepted) => accepted,
            Err(error) => {
                self.preserve_negative(&certificate, &status, quiet, None)
                    .await?;
                return Err(error);
            }
        };
        if !accepted {
            self.reconcile_known_negative(&certificate, quiet).await?;
            return Ok(CacheRestore::StaleStatus);
        }
        if status.state == OcspState::Good {
            if !self.inner.resolver.set_ocsp(
                &certificate.identity,
                certificate.generation,
                Some((raw.to_vec(), status.valid_until)),
            )? {
                return Ok(CacheRestore::StaleGeneration);
            }
            // Another generation can learn R between the first admission read
            // and this CAS. Serving already checks Guard atomically; this second
            // read also prevents reporting a stale Good as candidate readiness.
            if !certificate.leaf_state.admission().allow_staple {
                let cleared = self.inner.resolver.set_ocsp(
                    &certificate.identity,
                    certificate.generation,
                    None,
                )?;
                self.reconcile_known_negative(&certificate, quiet).await?;
                return Ok(if cleared {
                    CacheRestore::StaleStatus
                } else {
                    CacheRestore::StaleGeneration
                });
            }
            self.record(&certificate, Some(status.clone()), None)?;
        } else {
            self.apply_negative(&certificate, &status, quiet).await?;
            if !self
                .inner
                .resolver
                .set_ocsp(&certificate.identity, certificate.generation, None)?
            {
                return Ok(CacheRestore::StaleGeneration);
            }
        }
        Ok(CacheRestore::Restored { status })
    }
}
