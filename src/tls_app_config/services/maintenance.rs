use super::*;
use futures_util::FutureExt;

impl CertificateServices {
    pub(super) async fn maintenance(self: Arc<Self>) {
        let eviction = self.clone();
        self.tasks.spawn(async move {
            eviction.run_cache_evictions().await;
        });
        let revoked = self.clone();
        self.tasks.spawn(async move { revoked.run_revoked_business().await; });
        if self.restore.is_some() {
            // Restore-only preparation is deliberately memory-only. Rebuild the
            // maintenance handles only after commit, without tying activation
            // success to storage/network availability at this later point.
            let this = self.clone();
            self.tasks.spawn(async move {
                this.restore_maintenance().await;
            });
        }
        if self.restore.is_none() {
            let this = self.clone();
            self.tasks.spawn(async move {
                this.attach_shared_maintenance().await;
            });
            let this = self.clone();
            self.tasks.spawn(async move {
                this.restore_pending_cache().await;
            });
        }
        let mut pki_started = std::collections::HashSet::new();
        loop {
            if self.context.cancel.is_cancelled() {
                break;
            }
            let changed = self.maintenance_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.reconcile_physical_ocsp().await.is_err() {
                let _ = self.events.send(CertificateEvent {
                    kind: "ocsp_maintenance_prepare_failed", names: Vec::new(),
                });
            }
            let (groups, pki, ocsp) = {
                let state = self.state.lock().await;
                (
                    state
                        .groups
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>(),
                    state
                        .pki
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>(),
                    state
                        .ocsp
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>(),
                )
            };
            for (_, group) in groups {
                if group.policy.on_demand
                    || !group.background.load(Ordering::Acquire)
                    || group.restoring.load(Ordering::Acquire)
                {
                    continue;
                }
                if self.start_group(group).is_err() {
                    let _ = self.events.send(CertificateEvent {
                        kind: "certificate_maintenance_failed",
                        names: Vec::new(),
                    });
                }
            }
            for (key, pki) in pki {
                if !pki_started.insert(key) {
                    continue;
                }
                let cancel = self.context.cancel.child_token();
                let installer = self.context.trust_installer.clone();
                let events = self.events.clone();
                self.tasks.spawn(async move {
                    if pki.run(cancel, installer).await.is_err() {
                        let _ = events.send(CertificateEvent {
                            kind: "pki_maintenance_failed",
                            names: Vec::new(),
                        });
                    }
                });
            }
            for (_, manager) in ocsp {
                if manager.start(&self).is_err() {
                    let _ = self.events.send(CertificateEvent {
                        kind: "ocsp_maintenance_failed",
                        names: Vec::new(),
                    });
                }
            }

            tokio::select! { biased;
                _ = self.context.cancel.cancelled() => break,
                _ = &mut changed => {},
                _ = tokio::time::sleep(self.plan.ocsp_interval) => {},
            }
        }
    }

    async fn restore_maintenance(self: Arc<Self>) {
        let (mut pending, bound) = {
            let state = self.state.lock().await;
            (
                state
                    .material
                    .iter()
                    .filter_map(|item| {
                        item.managed_names.as_ref().map(|names| {
                            (
                                names.clone(),
                                item.identity,
                                item.material.clone(),
                                item.origin.clone(),
                            )
                        })
                    })
                    .collect::<Vec<_>>(),
                state.bound.clone().unwrap_or_default(),
            )
        };
        let mut manual_pending = true;
        let mut authorities_pending = self.plan.authorities.keys().cloned().collect::<Vec<_>>();
        let mut failures = 0u32;
        loop {
            if self.context.cancel.is_cancelled() {
                return;
            }
            let completed = stream::iter(pending)
                .map(|(names, identity, material, origin)| {
                    let this = self.clone();
                    let bound = &bound;
                    async move {
                        let result: Result<()> = async {
                            let group = this
                                .group_with_origin(
                                    names.clone(),
                                    identity,
                                    bound,
                                    this.context.cancel.child_token(),
                                    origin.clone(),
                                )
                                .await?;
                            let (_, end) = material.times()?;
                            let leaf = this.context.leaf_guard.intern(material.leaf_id, end)?;
                            *group.spki.lock().map_err(|_| anyhow!("certificate key state unavailable"))? =
                                Some(material.spki_der.clone());
                            *group
                                .leaf_state
                                .lock()
                                .map_err(|_| anyhow!("certificate leaf state unavailable"))? =
                                Some(leaf);
                            this.ocsp_manager(&group).await?;
                            Ok(())
                        }
                        .await;
                        (names, identity, material, origin, result)
                    }
                })
                .buffer_unordered(8)
                .collect::<Vec<_>>()
                .await;
            pending = completed
                .into_iter()
                .filter_map(|(names, identity, material, origin, result)| {
                    result.err().map(|_| (names, identity, material, origin))
                })
                .collect();
            let completed = stream::iter(authorities_pending)
                .map(|id| {
                    let this = self.clone();
                    async move {
                        let result = this.authority(&id, this.context.cancel.child_token()).await;
                        (id, result)
                    }
                })
                .buffer_unordered(8)
                .collect::<Vec<_>>()
                .await;
            authorities_pending = completed
                .into_iter()
                .filter_map(|(id, result)| result.err().map(|_| id))
                .collect();
            if manual_pending {
                manual_pending = self
                    .manual_ocsp(self.context.cancel.child_token())
                    .await
                    .is_err();
            }
            if pending.is_empty() && authorities_pending.is_empty() && !manual_pending {
                return;
            }
            failures = failures.saturating_add(1);
            let _ = self.events.send(CertificateEvent {
                kind: "restored_maintenance_prepare_failed",
                names: Vec::new(),
            });
            let delay = cert_automation::retry_backoff(failures, &[]);
            tokio::select! { biased; _ = self.context.cancel.cancelled() => return, _ = tokio::time::sleep(delay) => {} }
        }
    }

    fn start_group(self: &Arc<Self>, group: Arc<Group>) -> Result<()> {
        let _admission = self
            .admission
            .lock()
            .map_err(|_| anyhow!("certificate service admission unavailable"))?;
        let mut started = group
            .started
            .lock()
            .map_err(|_| anyhow!("certificate scope admission unavailable"))?;
        if *_admission || self.context.cancel.is_cancelled()
            || group.cancel.is_cancelled()
            || *started
            || group
                .residency
                .lock()
                .is_ok_and(|binding| binding.as_ref().is_some_and(|binding| !binding.slot.live()))
        {
            return Ok(());
        }
        *started = true;
        let this = self.clone();
        let worker = group.clone();
        let task=group.tasks.track_future(self.tasks.track_future(async move {
            this.run_group(worker).await;
        }));
        drop(started);
        drop(_admission);
        tokio::spawn(task);
        group.tasks.close();
        Ok(())
    }
    pub(super) async fn stop_group(&self, group: Arc<Group>) -> Result<()> {
        {
            let mut admission = group
                .started
                .lock()
                .map_err(|_| anyhow!("certificate scope admission unavailable"))?;
            *admission = true;
        }
        group.cancel.cancel();
        group.tasks.close();
        // The gate is released only after actual acquisition, native lease and
        // solver cleanup are joined. A stopped waiter cannot start new work.
        {
            let _gate = group.gate.lock().await;
        }
        group.tasks.wait().await;
        Ok(())
    }
    async fn run_group(self: Arc<Self>, group: Arc<Group>) {
        let cancel = group.cancel.clone();
        let mut failures = 0u32;
        let mut key_changes = self.context.leaf_guard.key_deny().subscribe();
        let key_pending = || group.spki.lock().map(|spki| spki.as_ref().is_some_and(|spki|
            self.context.leaf_guard.key_deny().check_spki_der(spki).is_err())).unwrap_or(true);
        loop {
            if cancel.is_cancelled() {
                break;
            }
            let changed = self.context.resources.revoked.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let refreshed = if group.renew_at.load(Ordering::Acquire) > 0
                && group.ari_after.load(Ordering::Acquire) <= now().unwrap_or(i64::MAX)
            {
                // Most scopes sleep until their scheduled check. Allocate
                // the larger acquisition/ARI state only while it is needed.
                match Box::pin(self.refresh_cached_schedule(&group, cancel.clone())).await {
                    Err(error) if error.is::<cert_automation::PendingPromotion>() => {
                        // Explicit non-on-demand groups can resume their
                        // interrupted attempt through the normal lease path.
                        group.renew_at.store(0, Ordering::Release);
                        Ok(())
                    }
                    result => result.map(|_| ()),
                }
            } else {
                Ok(())
            };
            let cached_deadline = group.renew_at.load(Ordering::Acquire);
            let pending = group
                .leaf_state
                .lock()
                .map(|leaf| leaf.as_ref().is_some_and(|leaf| leaf.needs_renewal()))
                .unwrap_or(true) || key_pending();
            let result = if let Err(error) = refreshed {
                Err(error)
            } else if pending && !group.identity
                && group.publication.lock().is_ok_and(|publication|publication.is_some()) {
                // The service-owned physical worker resolves current Name0
                // policy and exact old receipt. A historical publisher job
                // cannot renew the revoked chain under its old policy.
                Ok(now().unwrap_or(i64::MAX).saturating_add(
                    self.plan.renew_interval.as_secs().max(1) as i64))
            } else if cached_deadline > now().unwrap_or(i64::MAX) && !pending {
                Ok(cached_deadline)
            } else {
                std::panic::AssertUnwindSafe(Box::pin(self.ensure_group(
                    group.clone(),
                    false,
                    cancel.clone(),
                )))
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(anyhow!("certificate maintenance worker panicked")))
            };
            let delay = match result {
                Ok(renew_at) => {
                    failures = 0;
                    Duration::from_secs(
                        renew_at.saturating_sub(now().unwrap_or(renew_at)).max(1) as u64
                    )
                    .min(self.plan.renew_interval)
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    let _ = self.events.send(CertificateEvent {
                        kind: "certificate_maintenance_failed",
                        names: group.names.clone(),
                    });
                    cert_automation::retry_backoff(failures, &group.names)
                        .max(cert_automation::error_retry_delay(&error))
                }
            };
            let deadline = tokio::time::Instant::now() + delay;
            loop {
                tokio::select! { biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep_until(deadline) => break,
                    _ = key_changes.changed() => { if key_pending() { break; } },
                    _ = &mut changed => {
                        let pending = group.leaf_state.lock().map(|state| state.as_ref().is_some_and(|leaf| leaf.needs_renewal())).unwrap_or(true);
                        if pending { break; }
                        changed.set(self.context.resources.revoked.notified());
                        changed.as_mut().enable();
                    },
                }
            }
        }
    }
}
