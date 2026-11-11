use super::super::{loaders, model::AcmeSettings, storage::absolute};
use super::*;
use crate::cert_automation::AcmeIssuerConfig;
use crate::local_pki::CaConfig;

impl CertificateServices {
    pub(super) async fn group(
        &self,
        names: Vec<String>,
        identity: bool,
        bound: &[StagedAddress],
        cancel: CancellationToken,
    ) -> Result<Arc<Group>> {
        self.group_inner(names, identity, bound, cancel, true, None)
            .await
    }
    pub(super) async fn storage_probe_group(
        &self,
        names: Vec<String>,
        bound: &[StagedAddress],
        cancel: CancellationToken,
    ) -> Result<Arc<Group>> {
        self.group_inner(names, false, bound, cancel, false, None)
            .await
    }
    pub(super) async fn seeded_group(
        &self,
        seed: Arc<super::super::resident_cache::CacheEntry>,
        bound: &[StagedAddress],
        cancel: CancellationToken,
        background: bool,
    ) -> Result<Arc<Group>> {
        ensure!(seed.slot.live(), super::super::resident_cache::CacheChanged);
        self.group_inner(
            seed.material.names.clone(),
            false,
            bound,
            cancel,
            background,
            Some(seed),
        )
        .await
    }
    async fn group_inner(
        &self,
        names: Vec<String>,
        identity: bool,
        bound: &[StagedAddress],
        cancel: CancellationToken,
        background: bool,
        seed: Option<Arc<super::super::resident_cache::CacheEntry>>,
    ) -> Result<Arc<Group>> {
        let key = group_key(&names, identity);
        let restoring = seed.is_some() && !background;
        let background = background || seed.is_some();
        let (retired, retired_ocsp) = {
            let mut state = self.state.lock().await;
            let retired = state.groups.get(&key).is_some_and(|group| {
                group.cancel.is_cancelled()
                    || group.residency.lock().is_ok_and(|binding| {
                        binding.as_ref().is_some_and(|binding| !binding.slot.live())
                    })
            });
            if retired {
                if let Some(group) = state.groups.get(&key) {
                    group.cancel.cancel();
                }
                (state.groups.remove(&key), state.ocsp.remove(&key))
            } else {
                (None, None)
            }
        };
        let (joined, stopped) = tokio::join!(
            async {
                if let Some(group) = retired {
                    self.stop_group(group).await
                } else {
                    Ok(())
                }
            },
            async {
                if let Some(scope) = retired_ocsp {
                    scope.stop().await
                } else {
                    Ok(())
                }
            },
        );
        joined?;
        stopped?;
        let existing = {
            let state = self.state.lock().await;
            let existing = state.groups.get(&key).cloned();
            if let Some(group) = &existing {
                if let Some(seed) = &seed {
                    let material = &seed.material;
                    let mut binding = group
                        .residency
                        .lock()
                        .map_err(|_| anyhow!("certificate residency unavailable"))?;
                    if binding.is_none() {
                        *binding = Some(ResidencyBinding::shared(&seed.slot));
                    }
                    let mut leaf = group
                        .leaf_state
                        .lock()
                        .map_err(|_| anyhow!("certificate leaf state unavailable"))?;
                    if leaf.is_none() {
                        *leaf = Some(
                            self.context
                                .leaf_guard
                                .intern(material.leaf_id, material.times()?.1)?,
                        );
                    }
                }
                if restoring {
                    group.restoring.store(true, Ordering::Release);
                }
                if background {
                    group.background.store(true, Ordering::Release);
                }
            }
            existing
        };
        if let Some(group) = existing {
            if background {
                self.maintenance_changed.notify_one();
            }
            return Ok(group);
        }
        let group_admission = self
            .group_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("certificate live-scope capacity exceeded"))?;
        let mut policy = if identity {
            let config = self
                .plan
                .identity
                .as_ref()
                .ok_or_else(|| anyhow!("administrative identity is not configured"))?;
            Policy {
                issuers: config.issuers.clone(),
                ..Policy::default()
            }
        } else {
            self.policy(&names[0])
        };

        if policy.issuers.is_empty() {
            if !identity && self.policy_index(&names[0]).is_none() && internal_name(&names[0]) {
                policy.issuers.push(Issuer::Internal {
                    ca: "local".into(),
                    options: InternalIssuerOptions::default(),
                });
            } else {
                // admin.go defaults to one ACME module; it does not call the
                // business email-based DefaultIssuers factory.
                policy.issuers = vec![Issuer::Acme(Box::new(AcmeSettings {
                    config: AcmeIssuerConfig::lets_encrypt(),
                    roots: Vec::new(),
                    http_port: None,
                    alpn_port: None,
                    bind_host: String::new(),
                    distributed: true,
                    timeout: None,
                }))];
            }
        }
        let storage = if identity {
            self.context.paths.default_storage.clone()
        } else {
            policy
                .storage
                .as_ref()
                .or(self.plan.storage.as_ref())
                .unwrap_or(&self.context.paths.default_storage)
                .clone()
        };
        let store = self
            .context
            .resources
            .store(storage, &self.context.paths, cancel.clone())
            .await?;
        let resolver = if identity {
            self.identity_resolver.clone()
        } else {
            self.context.resolver.clone()
        };
        let mut solver = None;
        let issuer = if policy
            .issuers
            .iter()
            .all(|issuer| matches!(issuer, Issuer::Acme(_)))
        {
            let mut issuers = Vec::new();
            let mut timeout = Duration::from_secs(1200);
            for issuer in &policy.issuers {
                let Issuer::Acme(settings) = issuer else {
                    unreachable!()
                };
                let mut issuer = settings.config.clone();
                issuer.leaf_key_type = policy.key_type;
                for path in &settings.roots {
                    let path = absolute(&self.context.paths.cwd, path);
                    let root = loaders::blocking(
                        self.context.resources.io.clone(),
                        cancel.clone(),
                        move || loaders::read(&path),
                    )
                    .await?;
                    issuer.wire.extra_ca_pem.push(root);
                }
                if let Some(value) = settings.timeout {
                    timeout = timeout.min(value);
                }
                issuers.push(issuer);
            }
            let settings = policy
                .issuers
                .iter()
                .filter_map(|issuer| {
                    if let Issuer::Acme(settings) = issuer {
                        Some(settings.as_ref().clone())
                    } else {
                        None
                    }
                })
                .collect();
            let broker = solver::SolverBroker::new(
                settings,
                bound.to_vec(),
                self.context.listener_provider.clone(),
            )?;
            let (max_concurrent, max_concurrent_per_ca) = self.context.resources.issuance.limits();
            let options = AutomationOptions {
                issuers,
                renewal_window_ratio: policy.renewal_ratio,
                max_concurrent,
                max_concurrent_per_ca,
                poll_interval: self.plan.renew_interval,
                job_timeout: timeout,
            };
            let manager = CertificateManager::with_resources_and_solver(
                store.fs.clone(),
                self.context.challenges.clone(),
                resolver.clone(),
                options,
                self.context.resources.issuance.clone(),
                Some(broker.callback()),
            )?
            .storage_only()?;
            solver = Some(broker);
            GroupIssuer::Acme(manager)
        } else if policy.issuers.len() == 1 {
            let Issuer::Internal { ca, options } = &policy.issuers[0] else {
                return Err(anyhow!("mixed issuer fallback is not yet integrated"));
            };
            let pki = self.authority(ca, cancel.clone()).await?;
            GroupIssuer::Internal {
                pki,
                ca: ca.clone(),
                options: options.clone(),
            }
        } else {
            return Err(anyhow!("mixed issuer fallback is not yet integrated"));
        };
        let retained = self
            .state
            .lock()
            .await
            .material
            .iter()
            .find(|item| item.identity == identity && item.managed_names.as_ref() == Some(&names))
            .map(|item| item.material.clone());
        let seed_binding = seed
            .as_ref()
            .map(|entry| ResidencyBinding::shared(&entry.slot));
        let leaf_state = seed
            .map(|entry| entry.material.clone())
            .or(retained)
            .map(|material| {
                let (_, end) = material.times()?;
                self.context.leaf_guard.intern(material.leaf_id, end)
            })
            .transpose()?;
        let imported = if identity {
            None
        } else {
            self.on_demand.imported_binding(&names)
        };
        let group = Arc::new(Group {
            names,
            policy,
            store,
            resolver,
            issuer,
            identity,
            gate: AsyncMutex::new(()),
            solver,
            leaf_state: Mutex::new(leaf_state),
            scope: imported
                .as_ref()
                .map(|binding| binding.0.clone())
                .unwrap_or_default(),
            residency: Mutex::new(
                imported
                    .as_ref()
                    .map(|binding| binding.4.clone())
                    .or(seed_binding),
            ),
            publication: Arc::new(Mutex::new(
                imported.as_ref().map(|binding| binding.1.clone()),
            )),
            renew_at: AtomicI64::new(imported.as_ref().map_or(0, |binding| binding.2)),
            ari_after: AtomicI64::new(imported.as_ref().map_or(i64::MAX, |binding| binding.3)),
            background: AtomicBool::new(background),
            restoring: AtomicBool::new(restoring),
            cancel: self.context.cancel.child_token(),
            tasks: TaskTracker::new(),
            started: Mutex::new(false),
            _admission: group_admission,
        });
        let mut state = self.state.lock().await;
        ensure!(
            state.groups.len() < super::capacity::GROUP_LIMIT,
            "certificate group capacity exceeded"
        );
        let candidate = group;
        let group = state
            .groups
            .entry(key)
            .or_insert_with(|| candidate.clone())
            .clone();
        if !Arc::ptr_eq(&group, &candidate) && restoring {
            let mut current = group
                .leaf_state
                .lock()
                .map_err(|_| anyhow!("certificate leaf state unavailable"))?;
            if current.is_none() {
                *current = candidate
                    .leaf_state
                    .lock()
                    .map_err(|_| anyhow!("certificate leaf state unavailable"))?
                    .clone();
            }
            group.restoring.store(true, Ordering::Release);
        }
        if background {
            group.background.store(true, Ordering::Release);
        }
        drop(state);
        self.maintenance_changed.notify_one();
        Ok(group)
    }

    pub(super) async fn provision_authorities(&self, cancel: CancellationToken) -> Result<()> {
        let ids = self.plan.authorities.keys().cloned().collect::<Vec<_>>();
        let results = stream::iter(ids)
            .map(|id| {
                let cancel = cancel.clone();
                async move {
                    let pki = self.authority(&id, cancel.clone()).await?;
                    pki.provision(&id, cancel).await.map(|_| ())
                }
            })
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;
        for result in results {
            result?;
        }
        Ok(())
    }

    pub(super) async fn authority(&self, ca: &str, cancel: CancellationToken) -> Result<LocalPki> {
        if let Some(pki) = self.state.lock().await.pki.get(ca).cloned() {
            return Ok(pki);
        }
        let (mut config, storage) = match self.plan.authorities.get(ca) {
            Some(authority) => (
                authority.config.clone(),
                authority
                    .storage
                    .as_ref()
                    .or(self.plan.storage.as_ref())
                    .unwrap_or(&self.context.paths.default_storage)
                    .clone(),
            ),
            None if ca == "local" => (
                CaConfig::default(),
                self.plan
                    .storage
                    .as_ref()
                    .unwrap_or(&self.context.paths.default_storage)
                    .clone(),
            ),
            None => return Err(anyhow!("internal issuer references an unknown authority")),
        };
        for pair in [&mut config.root, &mut config.intermediate]
            .into_iter()
            .flatten()
        {
            pair.certificate = absolute(&self.context.paths.cwd, &pair.certificate);
            pair.private_key = pair
                .private_key
                .as_ref()
                .map(|path| absolute(&self.context.paths.cwd, path));
        }
        let store = self
            .context
            .resources
            .store(storage, &self.context.paths, cancel)
            .await?;
        let pki = LocalPki::with_resources(
            store.fs.clone(),
            vec![config],
            self.context.resources.pki.clone(),
        )?;
        let mut state = self.state.lock().await;
        let pki = state.pki.entry(ca.into()).or_insert(pki).clone();
        drop(state);
        self.maintenance_changed.notify_one();
        Ok(pki)
    }

    pub(super) async fn discard_storage_probe(&self, group: Arc<Group>) -> Result<()> {
        let key = group_key(&group.names, group.identity);
        let removed = {
            let mut state = self.state.lock().await;
            let owns = state
                .groups
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &group))
                && !group.background.load(Ordering::Acquire)
                && group
                    .publication
                    .lock()
                    .map(|receipt| receipt.is_none())
                    .unwrap_or(false);
            if owns {
                state.groups.remove(&key);
                true
            } else {
                false
            }
        };
        if removed {
            self.stop_group(group).await?;
        }
        Ok(())
    }
    pub(super) async fn discard_failed_on_demand(&self, group: Arc<Group>) -> Result<()> {
        let key = group_key(&group.names, group.identity);
        let (removed, ocsp) = {
            let mut state = self.state.lock().await;
            let owns = state
                .groups
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &group))
                && !group.restoring.load(Ordering::Acquire)
                && group
                    .publication
                    .lock()
                    .map(|receipt| receipt.is_none())
                    .unwrap_or(false)
                && !self.on_demand.references_group(&group);
            if owns {
                (state.groups.remove(&key).is_some(), state.ocsp.remove(&key))
            } else {
                (false, None)
            }
        };
        if removed {
            let (a, b) = tokio::join!(self.stop_group(group), async {
                if let Some(scope) = ocsp {
                    scope.stop().await
                } else {
                    Ok(())
                }
            });
            a?;
            b?;
        }
        Ok(())
    }
    pub(super) async fn discard_failed_restore(&self, group: Arc<Group>) -> Result<()> {
        let key = group_key(&group.names, group.identity);
        let removed = {
            let mut state = self.state.lock().await;
            let owns = state
                .groups
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &group))
                && group.restoring.load(Ordering::Acquire)
                && group
                    .publication
                    .lock()
                    .map(|receipt| receipt.is_none())
                    .unwrap_or(false);
            if owns {
                state.groups.remove(&key);
                true
            } else {
                false
            }
        };
        if removed {
            self.stop_group(group).await?;
        }
        Ok(())
    }
    pub(super) async fn refresh_cached_schedule(
        &self,
        group: &Group,
        cancel: CancellationToken,
    ) -> Result<Option<i64>> {
        let GroupIssuer::Acme(manager) = &group.issuer else {
            return Ok(Some(group.renew_at.load(Ordering::Acquire)));
        };
        let slot = group
            .residency
            .lock()
            .map_err(|_| anyhow!("certificate residency unavailable"))?
            .as_ref()
            .map(|binding| binding.slot.clone());
        let retired = async {
            if let Some(slot) = slot {
                slot.retired().await
            } else {
                std::future::pending::<()>().await
            }
        };
        let work = cancel.child_token();
        let refresh = manager.refresh_cached(&group.names, work.clone());
        tokio::pin!(refresh);
        let refreshed = tokio::select! {biased;
            _=group.cancel.cancelled()=>{
                work.cancel();let _=refresh.await;
                return Err(super::super::resident_cache::CacheChanged.into());
            },
            _=retired=>{
                work.cancel();let _=refresh.await;
                return Err(super::super::resident_cache::CacheChanged.into());
            },
            outcome=&mut refresh=>outcome?,
        };
        match refreshed {
            cert_automation::RefreshOutcome::Usable {
                certificate,
                ari_after,
            } => {
                group
                    .renew_at
                    .store(certificate.renew_at_unix, Ordering::Release);
                group.ari_after.store(ari_after, Ordering::Release);
                Ok(Some(certificate.renew_at_unix))
            }
            cert_automation::RefreshOutcome::Unusable
            | cert_automation::RefreshOutcome::Missing => {
                group.renew_at.store(0, Ordering::Release);
                Ok(None)
            }
        }
    }

    pub(super) async fn ensure_group(
        &self,
        group: Arc<Group>,
        cached_first: bool,
        cancel: CancellationToken,
    ) -> Result<i64> {
        let _gate = tokio::select! { biased; _ = cancel.cancelled() => return Err(anyhow!("certificate acquisition cancelled")),_=group.cancel.cancelled()=>return Err(anyhow!("certificate scope retired")), gate = group.gate.lock() => gate };
        ensure!(!group.cancel.is_cancelled(), "certificate scope retired");
        let previous = group
            .leaf_state
            .lock()
            .map_err(|_| anyhow!("certificate leaf state unavailable"))?
            .clone();
        let pending = match previous {
            Some(leaf) => leaf.pending_revocation()?.map(|version| (leaf, version)),
            None => None,
        };
        let work = cancel.child_token();
        let stop_watch = CancellationToken::new();
        let _watch_guard = stop_watch.clone().drop_guard();
        let stop = stop_watch.clone();
        let scoped = group.cancel.clone();
        let worker = work.clone();
        let watcher = group.tasks.spawn(async move {
            tokio::select! {biased;_=scoped.cancelled()=>worker.cancel(),_=stop.cancelled()=>{}}
        });
        let slot = group
            .residency
            .lock()
            .map_err(|_| anyhow!("certificate residency unavailable"))?
            .clone();
        let retirement = slot.map(|binding| {
            let work = work.clone();
            let stop = stop_watch.clone();
            group.tasks.spawn(async move {
                tokio::select! {biased;_ = binding.slot.retired() => work.cancel(),_ = stop.cancelled() => {}}
            })
        });
        let result = self.acquire(&group, cached_first, work.clone()).await;
        work.cancel();
        stop_watch.cancel();
        let _ = watcher.await;
        if let Some(retirement) = retirement {
            let _ = retirement.await;
        }
        let released = match &group.solver {
            Some(solver) => solver.release().await,
            None => Ok(()),
        };
        if released.is_err() {
            let _ = self.events.send(CertificateEvent {
                kind: "certificate_solver_release_failed",
                names: group.names.clone(),
            });
        }
        let outcome = async {
            let (managed, material) = result?;
            ensure!(!group.cancel.is_cancelled(), "certificate scope retired");
            group.renew_at.store(managed, Ordering::Release);
            self.remember_material(&group, material).await?;
            Ok(managed)
        }
        .await;
        // Caller/generation/queue-budget cancellation is not a failed CA
        // replacement and must not change a different generation's leaf guard.
        // Actual issuer/transport/publish errors still withdraw this exact R.
        if outcome.as_ref().is_err_and(|error| {
            !error.is::<super::super::resident_cache::CacheChanged>()
                && !error.is::<crate::tls_resolver::CertificatePublicationConflict>()
        }) && !cancel.is_cancelled()
            && !group.cancel.is_cancelled()
            && group
                .residency
                .lock()
                .is_ok_and(|binding| binding.as_ref().is_none_or(|binding| binding.slot.live()))
            && let Some((leaf, version)) = pending
        {
            leaf.withdraw_if_current(&version)?;
        }
        outcome
    }

    async fn remember_material(&self, group: &Arc<Group>, mut material: Material) -> Result<()> {
        material.names = group.names.clone();
        material.validate_at(now()?, false)?;
        reject_revoked(&material, &self.context.leaf_guard)?;
        let (_, expiry) = material.times()?;
        let leaf = self.context.leaf_guard.intern(material.leaf_id, expiry)?;
        *group
            .leaf_state
            .lock()
            .map_err(|_| anyhow!("certificate leaf state unavailable"))? = Some(leaf);
        if group.renew_at.load(Ordering::Acquire) == 0 {
            let (begin, end) = material.times()?;
            group.renew_at.store(
                cert_automation::renewal_time(
                    begin,
                    end,
                    group.policy.renewal_ratio,
                    None,
                    &group_key(&group.names, group.identity),
                )?,
                Ordering::Release,
            );
        }
        let material = if group.identity {
            Arc::new(material)
        } else {
            self.on_demand
                .bound_material(&group.names, material.identity)
                .ok_or(super::super::resident_cache::CacheChanged)?
        };
        let mut state = self.state.lock().await;
        if !group.identity
            && self
                .on_demand
                .bound_material(&group.names, material.identity)
                .is_none_or(|current| !Arc::ptr_eq(&current, &material))
        {
            return Err(super::super::resident_cache::CacheChanged.into());
        }
        state.material.retain(|item| {
            !(item.identity == group.identity && item.managed_names.as_ref() == Some(&group.names))
        });
        state.material.push(RetainedMaterial {
            material: material.clone(),
            identity: group.identity,
            managed_names: Some(group.names.clone()),
            renew_at: group.renew_at.load(Ordering::Acquire),
            ari_after: group.ari_after.load(Ordering::Acquire),
        });
        let ocsp = state
            .ocsp
            .get(&group_key(&group.names, group.identity))
            .cloned();
        drop(state);
        if let Some(ocsp) = ocsp {
            ocsp.notify_changed();
        }
        if group.identity {
            self.refresh_client_keys().await?;
        }
        let _ = self.events.send(CertificateEvent {
            kind: "certificate_published",
            names: group.names.clone(),
        });
        Ok(())
    }

    /// A candidate's cache preparation never waits for an old generation's
    /// issuance lease. An active miss instead pins the scope until the ready
    /// bundle is published, so it cannot reintroduce a just-renewed leaf.
    pub(super) async fn probe_group(
        &self,
        group: Arc<Group>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let _gate = tokio::select! {biased;
            _=cancel.cancelled()=>return Err(anyhow!("certificate probe cancelled")),
            _=group.cancel.cancelled()=>return Err(super::super::resident_cache::CacheChanged.into()),
            gate=group.gate.lock()=>gate,
        };
        if self.on_demand.active.load(Ordering::Acquire) {
            let lease = group
                .store
                .fs
                .lock(&format!("issue_cert_{}", group.names[0]), cancel.clone())
                .await?;
            let result = self.probe_group_pinned(&group, Some(&lease), cancel).await;
            self.finish_publication_lease(&group, lease, result).await
        } else {
            self.probe_group_pinned(&group, None, cancel).await
        }
    }

    async fn probe_group_pinned(
        &self,
        group: &Arc<Group>,
        lease: Option<&crate::certstore::StorageLease>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let bundle = match &group.issuer {
            GroupIssuer::Acme(manager) => {
                match manager.probe_cached(&group.names, cancel.clone()).await? {
                    cert_automation::CachedProbe::Busy => {
                        let _ = self.events.send(CertificateEvent {
                            kind: "certificate_cache_busy",
                            names: group.names.clone(),
                        });
                        return Ok(());
                    }
                    cert_automation::CachedProbe::Missing => None,
                    cert_automation::CachedProbe::Material { usable, bundle } => {
                        if let Some(info) = usable {
                            group.renew_at.store(info.renew_at_unix, Ordering::Release);
                        }
                        Some(bundle)
                    }
                }
            }
            GroupIssuer::Internal { ca, .. } => {
                group
                    .store
                    .fs
                    .load_certificate(ca, &names_key(&group.names)?)
                    .await?
            }
        };
        let Some(bundle) = bundle else {
            let _ = self.events.send(CertificateEvent {
                kind: "certificate_pending",
                names: group.names.clone(),
            });
            return Ok(());
        };
        if matches!(group.issuer, GroupIssuer::Acme(_)) {
            group.ari_after.store(
                cert_automation::ari_refresh_time(&bundle.metadata).unwrap_or(0),
                Ordering::Release,
            );
        }
        let mut material = self
            .parse_material(bundle.chain_pem, bundle.private_key_pem, cancel.clone())
            .await?;
        material.names = group.names.clone();
        let (begin, end) = material.times()?;
        let leaf = self.context.leaf_guard.intern(material.leaf_id, end)?;
        let revoked = leaf.revocation()?.is_some();
        *group
            .leaf_state
            .lock()
            .map_err(|_| anyhow!("certificate leaf state unavailable"))? = Some(leaf);
        let at = now()?;
        if begin > at || end <= at || revoked {
            let _ = self.events.send(CertificateEvent {
                kind: "certificate_pending",
                names: group.names.clone(),
            });
            return Ok(());
        }
        material.validate_at(at, false)?;
        let due = group.renew_at.load(Ordering::Acquire);
        let due = if due > 0 {
            due
        } else {
            cert_automation::renewal_time(
                begin,
                end,
                group.policy.renewal_ratio,
                None,
                &group_key(&group.names, group.identity),
            )?
        };
        let ari_after = group.ari_after.load(Ordering::Acquire);
        self.publish_group(
            group,
            Arc::new(material.clone()),
            due,
            ari_after,
            cancel.clone(),
            lease,
        )
        .await?;
        self.remember_material(group, material).await
    }

    async fn acquire(
        &self,
        group: &Arc<Group>,
        cached_first: bool,
        cancel: CancellationToken,
    ) -> Result<(i64, Material)> {
        match &group.issuer {
            GroupIssuer::Acme(manager) => {
                let loaded = if cached_first {
                    manager.load_cached(&group.names, cancel.clone()).await?
                } else {
                    None
                };
                let info = match loaded {
                    Some(info) => info,
                    None => manager.ensure(&group.names, cancel.clone()).await?,
                };
                // Manager released its native lease after producing the
                // durable bundle. Pin that same storage scope through scoped
                // publication; a different intervening winner must be retried.
                let lease = group
                    .store
                    .fs
                    .lock(&format!("issue_cert_{}", group.names[0]), cancel.clone())
                    .await?;
                let result = async {
                    let bundle = group
                        .store
                        .fs
                        .load_certificate(&info.issuer_key, &names_key(&group.names)?)
                        .await?
                        .ok_or_else(|| anyhow!("managed certificate is missing"))?;
                    let ari_after =
                        cert_automation::ari_refresh_time(&bundle.metadata).unwrap_or(0);
                    let mut material = self
                        .parse_material(bundle.chain_pem, bundle.private_key_pem, cancel.clone())
                        .await?;
                    ensure!(
                        material
                            .leaf_id
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                            == info.leaf_sha256,
                        "managed certificate changed before publication; retry required"
                    );
                    material.validate_at(now()?, false)?;
                    reject_revoked(&material, &self.context.leaf_guard)?;
                    material.names = group.names.clone();
                    lease.check().await?;
                    self.publish_group(
                        group,
                        Arc::new(material.clone()),
                        info.renew_at_unix,
                        ari_after,
                        cancel.clone(),
                        Some(&lease),
                    )
                    .await?;
                    Ok((info.renew_at_unix, material))
                }
                .await;
                self.finish_publication_lease(group, lease, result).await
            }
            GroupIssuer::Internal { pki, ca, options } => {
                let lease = group
                    .store
                    .fs
                    .lock(&format!("issue_cert_{}", group.names[0]), cancel.clone())
                    .await?;
                let result = async {
                    let key = names_key(&group.names)?;
                    group
                        .store
                        .fs
                        .recover_certificate_with_lease(ca, &key, &lease)
                        .await?;
                    if let Some(bundle) = group.store.fs.load_certificate(ca, &key).await? {
                        let mut material = self
                            .parse_material(
                                bundle.chain_pem,
                                bundle.private_key_pem,
                                cancel.clone(),
                            )
                            .await?;
                        material.names = group.names.clone();
                        let (begin, end) = material.times()?;
                        if begin > now()? {
                            return Err(cert_automation::FutureCertificate(begin).into());
                        }
                        let due = cert_automation::renewal_time(
                            begin,
                            end,
                            group.policy.renewal_ratio,
                            None,
                            &key,
                        )?;
                        if material.validate_at(now()?, false).is_ok()
                            && reject_revoked(&material, &self.context.leaf_guard).is_ok()
                            && (cached_first || due > now()?)
                        {
                            self.publish_group(
                                group,
                                Arc::new(material.clone()),
                                due,
                                i64::MAX,
                                cancel.clone(),
                                Some(&lease),
                            )
                            .await?;
                            return Ok((due, material));
                        }
                    }
                    // LocalPki registration/provisioning precedes issuance and
                    // never installs trust; trust is a post-commit operation.
                    pki.provision(ca, cancel.clone()).await?;
                    let names = group.names.clone();
                    let kind = group.policy.key_type;
                    let (csr, private_key_pem) = loaders::blocking(
                        self.context.resources.io.clone(),
                        cancel.clone(),
                        move || cert_automation::generate_csr(&names, kind),
                    )
                    .await?;
                    let chain_pem = pki.issue(ca, csr, options.clone(), cancel.clone()).await?;
                    let mut material = self
                        .parse_material(chain_pem.clone(), private_key_pem.clone(), cancel.clone())
                        .await?;
                    material.names = group.names.clone();
                    material.validate_at(now()?, false)?;
                    let bundle = CertificateBundle {
                        chain_pem,
                        private_key_pem,
                        metadata: json!({"sans":group.names,"issuer_data":{"ca":ca}}),
                    };
                    lease.check().await?;
                    group
                        .store
                        .fs
                        .save_certificate(ca, &key, &bundle, &lease)
                        .await?;
                    lease.check().await?;
                    let (begin, end) = material.times()?;
                    let due = cert_automation::renewal_time(
                        begin,
                        end,
                        group.policy.renewal_ratio,
                        None,
                        &key,
                    )?;
                    self.publish_group(
                        group,
                        Arc::new(material.clone()),
                        due,
                        i64::MAX,
                        cancel.clone(),
                        Some(&lease),
                    )
                    .await?;
                    Ok((due, material))
                }
                .await;
                self.finish_publication_lease(group, lease, result).await
            }
        }
    }

    async fn finish_publication_lease<T>(
        &self,
        group: &Group,
        lease: crate::certstore::StorageLease,
        result: Result<T>,
    ) -> Result<T> {
        if lease.release().await.is_err() {
            // Scope admission and resolver CAS happened before release. A
            // cleanup failure is observable but cannot undo publication or
            // be mistaken for a failed revocation replacement.
            let _ = self.events.send(CertificateEvent {
                kind: "certificate_storage_release_failed",
                names: group.names.clone(),
            });
        }
        result
    }

    pub(super) async fn restore_ocsp(
        &self,
        identity_scope: bool,
        cancel: CancellationToken,
    ) -> Result<()> {
        if self.plan.disable_ocsp {
            return Ok(());
        }
        let groups =
            self.state
                .lock()
                .await
                .groups
                .values()
                .filter(|group| group.identity == identity_scope)
                .filter(|group| {
                    group.residency.lock().is_ok_and(|binding| {
                        binding.as_ref().is_none_or(|binding| binding.slot.live())
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
        let managers = stream::iter(groups)
            .map(|group| async move { self.ocsp_manager(&group).await })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        for manager in managers {
            manager?;
        }
        let resolver = if identity_scope {
            self.identity_resolver.clone()
        } else {
            self.context.resolver.clone()
        };
        let manual_resolver = self.manual_resolver.clone();
        let (managed, manual) = loaders::blocking(
            self.context.resources.cpu.clone(),
            cancel.clone(),
            move || {
                let managed = resolver
                    .ocsp_certificates()?
                    .into_iter()
                    .map(|certificate| {
                        (group_key(certificate.names(), identity_scope), certificate)
                    })
                    .collect::<Vec<_>>();
                let manual = if identity_scope {
                    Vec::new()
                } else {
                    manual_resolver.ocsp_certificates()?
                };
                Ok((managed, manual))
            },
        )
        .await?;
        let jobs = {
            let state = self.state.lock().await;
            let mut jobs = managed
                .into_iter()
                .filter_map(|(key, certificate)| {
                    state
                        .ocsp
                        .get(&key)
                        .cloned()
                        .map(|manager| (manager, certificate))
                })
                .collect::<Vec<_>>();
            if let Some(manager) = state.ocsp.get("manual:false") {
                jobs.extend(
                    manual
                        .into_iter()
                        .map(|certificate| (manager.clone(), certificate)),
                );
            }
            jobs
        };
        // Drain the admitted operations even if another certificate failed.
        // The separate restore admission budget remains shared across scopes.
        let outcomes = stream::iter(jobs)
            .map(|(manager, certificate)| {
                let cancel = cancel.clone();
                async move { manager.probe_cached_one(certificate, cancel).await }
            })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        for status in outcomes {
            if matches!(status?, crate::cert_status::CacheRestore::Restored { status } if status.state == OcspState::Revoked)
            {
                self.context.resources.revoked.notify_waiters();
            }
        }
        Ok(())
    }

    pub(super) async fn manual_ocsp(&self, cancel: CancellationToken) -> Result<()> {
        if self.plan.disable_ocsp {
            return Ok(());
        }
        let resolver = self.manual_resolver.clone();
        let inventory = super::super::loaders::blocking(
            self.context.resources.cpu.clone(),
            cancel.clone(),
            move || resolver.ocsp_certificates(),
        )
        .await?;
        if inventory.is_empty() {
            return Ok(());
        }
        let identities = inventory
            .iter()
            .map(|certificate| certificate.identity())
            .collect::<std::collections::HashSet<_>>();
        let storage = self
            .plan
            .storage
            .as_ref()
            .unwrap_or(&self.context.paths.default_storage)
            .clone();
        let store = self
            .context
            .resources
            .store(storage, &self.context.paths, cancel)
            .await?;
        let (max_concurrent, max_concurrent_per_responder) = self.context.resources.ocsp.limits();
        let manager = OcspManager::with_resources_and_inventory_cpu(
            store.fs.clone(),
            self.manual_resolver.clone(),
            OcspOptions {
                check_interval: self.plan.ocsp_interval,
                max_concurrent,
                max_concurrent_per_responder,
                ..OcspOptions::default()
            },
            Arc::new(move |_| Ok(OcspConfig::default())),
            Arc::new(move |certificate| identities.contains(&certificate.identity())),
            self.context.resources.ocsp.clone(),
            self.context.resources.cpu.clone(),
        )?;
        self.state.lock().await.ocsp.insert(
            "manual:false".into(),
            OcspScope::new(manager, Vec::new(), &self.context.cancel),
        );
        self.maintenance_changed.notify_one();
        Ok(())
    }

    pub(super) async fn reconcile_revoked(
        &self,
        identity_scope: bool,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut groups = Vec::new();
        for (identity, resolver) in [
            (false, &self.context.resolver),
            (true, &self.identity_resolver),
        ] {
            if identity != identity_scope {
                continue;
            }
            for certificate in resolver.ocsp_certificates()? {
                if certificate.leaf_state.revocation()?.is_none() {
                    continue;
                }
                let key = group_key(certificate.names(), identity);
                let group = self.state.lock().await.groups.get(&key).cloned();
                match group {
                    Some(group) => groups.push(group),
                    None => {
                        // CertMagic certShouldBeForceRenewed explicitly limits
                        // automatic replacement/removal to managed material.
                        let _ = self.events.send(CertificateEvent {
                            kind: "manual_certificate_revoked",
                            names: certificate.names().to_vec(),
                        });
                    }
                }
            }
        }
        let outcomes = stream::iter(groups)
            .map(|group| self.ensure_group(group, false, cancel.clone()))
            .buffer_unordered(10)
            .collect::<Vec<_>>()
            .await;
        for outcome in outcomes {
            outcome?;
        }
        Ok(())
    }

    pub(super) async fn ocsp_manager(&self, group: &Group) -> Result<Option<OcspScope>> {
        // No certificate status work or per-group event ring is necessary
        // when this policy disables OCSP. A shared authenticated LeafGuard
        // fact still applies independently of the stapling policy.
        if self.plan.disable_ocsp || group.policy.disable_ocsp {
            return Ok(None);
        }
        let key = group_key(&group.names, group.identity);
        {
            let state = self.state.lock().await;
            ensure!(
                state
                    .groups
                    .get(&key)
                    .is_some_and(|current| std::ptr::eq(current.as_ref(), group))
                    && !group.cancel.is_cancelled(),
                "certificate status scope retired"
            );
            if let Some(manager) = state.ocsp.get(&key).cloned() {
                return Ok(Some(manager));
            }
        }
        let overrides: std::collections::HashMap<String, String> =
            group.policy.ocsp_overrides.clone().into_iter().collect();
        let policy = Arc::new(move |_: &crate::tls_resolver::OcspCertificate| {
            Ok(OcspConfig {
                responder_overrides: overrides.clone(),
                ..OcspConfig::default()
            })
        });
        let (max_concurrent, max_concurrent_per_responder) = self.context.resources.ocsp.limits();
        let options = OcspOptions {
            check_interval: self.plan.ocsp_interval,
            max_concurrent,
            max_concurrent_per_responder,
            ..OcspOptions::default()
        };
        let names = group.names.clone();
        let inventory = Arc::new(move |certificate: &crate::tls_resolver::OcspCertificate| {
            certificate.names().len() == names.len()
                && certificate.names().iter().all(|name| names.contains(name))
        });
        let manager = OcspManager::with_resources_and_inventory_cpu(
            group.store.fs.clone(),
            group.resolver.clone(),
            options,
            policy,
            inventory,
            self.context.resources.ocsp.clone(),
            self.context.resources.cpu.clone(),
        )?
        .with_names_scope(group.names.clone())?;
        let mut state = self.state.lock().await;
        ensure!(
            state
                .groups
                .get(&key)
                .is_some_and(|current| std::ptr::eq(current.as_ref(), group))
                && !group.cancel.is_cancelled()
                && group.residency.lock().is_ok_and(|binding| binding
                    .as_ref()
                    .is_none_or(|binding| binding.slot.live())),
            "certificate status scope retired"
        );
        let scope = OcspScope::new(manager, group.names.clone(), &group.cancel);
        let manager = state.ocsp.entry(key).or_insert(scope).clone();
        drop(state);
        self.maintenance_changed.notify_one();
        Ok(Some(manager))
    }
}

fn internal_name(name: &str) -> bool {
    name == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}
