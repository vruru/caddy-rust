use super::*;
use futures_util::FutureExt;

impl CertificateServices {
    pub(super) async fn maintenance(self: Arc<Self>) {
        if self.restore.is_some() {
            // Restore-only preparation is deliberately memory-only. Rebuild the
            // maintenance handles only after commit, without tying activation
            // success to storage/network availability at this later point.
            let this = self.clone();
            self.tasks.spawn(async move {
                this.restore_maintenance().await;
            });
        }
        let mut groups_started = std::collections::HashSet::new();
        let mut pki_started = std::collections::HashSet::new();
        let mut ocsp_started = std::collections::HashSet::new();
        loop {
            if self.context.cancel.is_cancelled() {
                break;
            }
            let changed = self.maintenance_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
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
            for (key, group) in groups {
                if !groups_started.insert(key) {
                    continue;
                }
                let this = self.clone();
                self.tasks.spawn(async move {
                    this.run_group(group).await;
                });
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
            for (key, manager) in ocsp {
                if !ocsp_started.insert(key) {
                    continue;
                }
                let cancel = self.context.cancel.child_token();
                let this = self.clone();
                let mut events = manager.subscribe();
                let event_cancel = cancel.clone();
                self.tasks.spawn(async move {
                    loop { tokio::select! { biased;
                        _ = event_cancel.cancelled() => break,
                        event = events.recv() => match event {
                            Ok(event) => if event.status.is_some_and(|status| status.state == OcspState::Revoked) { this.context.resources.revoked.notify_waiters(); },
                            Err(broadcast::error::RecvError::Lagged(_)) => this.context.resources.revoked.notify_waiters(),
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }}
                });
                let events = self.events.clone();
                self.tasks.spawn(async move {
                    if manager.run(cancel).await.is_err() {
                        let _ = events.send(CertificateEvent {
                            kind: "ocsp_maintenance_failed",
                            names: Vec::new(),
                        });
                    }
                });
            }
            tokio::select! { biased;
                _ = self.context.cancel.cancelled() => break,
                _ = &mut changed => {},
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
                        item.managed_names
                            .as_ref()
                            .map(|names| (names.clone(), item.identity, item.material.clone()))
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
                .map(|(names, identity, material)| {
                    let this = self.clone();
                    let bound = &bound;
                    async move {
                        let result: Result<()> = async {
                            let group = this
                                .group(
                                    names.clone(),
                                    identity,
                                    bound,
                                    this.context.cancel.child_token(),
                                )
                                .await?;
                            let (_, end) = material.times()?;
                            let leaf = this.context.leaf_guard.intern(material.leaf_id, end)?;
                            *group
                                .leaf_state
                                .lock()
                                .map_err(|_| anyhow!("certificate leaf state unavailable"))? =
                                Some(leaf);
                            this.ocsp_manager(&group).await?;
                            Ok(())
                        }
                        .await;
                        (names, identity, material, result)
                    }
                })
                .buffer_unordered(8)
                .collect::<Vec<_>>()
                .await;
            pending = completed
                .into_iter()
                .filter_map(|(names, identity, material, result)| {
                    result.err().map(|_| (names, identity, material))
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

    async fn run_group(self: Arc<Self>, group: Arc<Group>) {
        let cancel = self.context.cancel.child_token();
        let mut failures = 0u32;
        loop {
            if cancel.is_cancelled() {
                break;
            }
            let changed = self.context.resources.revoked.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let result = std::panic::AssertUnwindSafe(self.ensure_group(
                group.clone(),
                false,
                cancel.clone(),
            ))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(anyhow!("certificate maintenance worker panicked")));
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
