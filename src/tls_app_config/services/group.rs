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
        let key = group_key(&names, identity);
        if let Some(group) = self.state.lock().await.groups.get(&key).cloned() {
            return Ok(group);
        }
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
        ensure!(
            !policy.on_demand,
            "on-demand certificate acquisition requires handshake integration"
        );
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
            )?;
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
        let leaf_state = retained
            .map(|material| {
                let (_, end) = material.times()?;
                self.context.leaf_guard.intern(material.leaf_id, end)
            })
            .transpose()?;
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
        });
        let mut state = self.state.lock().await;
        ensure!(
            state.groups.len() < 4096,
            "certificate group capacity exceeded"
        );
        let group = state.groups.entry(key).or_insert(group).clone();
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

    pub(super) async fn ensure_group(
        &self,
        group: Arc<Group>,
        cached_first: bool,
        cancel: CancellationToken,
    ) -> Result<i64> {
        let _gate = tokio::select! { biased; _ = cancel.cancelled() => return Err(anyhow!("certificate acquisition cancelled")), gate = group.gate.lock() => gate };
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
        let result = self.acquire(&group, cached_first, work.clone()).await;
        work.cancel();
        let released = match &group.solver {
            Some(solver) => solver.release().await,
            None => Ok(()),
        };
        let result = result.and_then(|value| released.map(|_| value));
        match result {
            Ok((managed, material)) => {
                self.remember_material(&group, material).await?;
                Ok(managed)
            }
            Err(error) => {
                if let Some((leaf, version)) = pending {
                    leaf.withdraw_if_current(&version)?;
                }
                Err(error)
            }
        }
    }

    async fn remember_material(&self, group: &Group, mut material: Material) -> Result<()> {
        material.names = group.names.clone();
        material.validate_at(now()?, false)?;
        reject_revoked(&material, &self.context.leaf_guard)?;
        let (_, expiry) = material.times()?;
        let leaf = self.context.leaf_guard.intern(material.leaf_id, expiry)?;
        *group
            .leaf_state
            .lock()
            .map_err(|_| anyhow!("certificate leaf state unavailable"))? = Some(leaf);
        let mut state = self.state.lock().await;
        state.material.retain(|item| {
            !(item.identity == group.identity && item.managed_names.as_ref() == Some(&group.names))
        });
        state.material.push(RetainedMaterial {
            material: Arc::new(material),
            identity: group.identity,
            managed_names: Some(group.names.clone()),
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

    /// Candidate business preparation is strictly read-only: it never waits
    /// for the old generation's issuance lease or starts/reconciles an order.
    pub(super) async fn probe_group(
        &self,
        group: Arc<Group>,
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
                    cert_automation::CachedProbe::Material { bundle, .. } => Some(bundle),
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
        self.publish_material(
            Arc::new(material.clone()),
            group.resolver.clone(),
            cancel.clone(),
        )
        .await?;
        self.remember_material(&group, material).await
    }

    async fn acquire(
        &self,
        group: &Group,
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
                let bundle = group
                    .store
                    .fs
                    .load_certificate(&info.issuer_key, &names_key(&group.names)?)
                    .await?
                    .ok_or_else(|| anyhow!("published managed certificate is missing"))?;
                Ok((
                    info.renew_at_unix,
                    self.parse_material(bundle.chain_pem, bundle.private_key_pem, cancel.clone())
                        .await?,
                ))
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
                            self.publish_material(
                                Arc::new(material.clone()),
                                group.resolver.clone(),
                                cancel.clone(),
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
                    self.publish_material(
                        Arc::new(material.clone()),
                        group.resolver.clone(),
                        cancel.clone(),
                    )
                    .await?;
                    let (begin, end) = material.times()?;
                    Ok((
                        cert_automation::renewal_time(
                            begin,
                            end,
                            group.policy.renewal_ratio,
                            None,
                            &key,
                        )?,
                        material,
                    ))
                }
                .await;
                let released = lease.release().await;
                result.and_then(|value| released.map(|_| value))
            }
        }
    }

    pub(super) async fn restore_ocsp(
        &self,
        identity_scope: bool,
        cancel: CancellationToken,
    ) -> Result<()> {
        let groups = self
            .state
            .lock()
            .await
            .groups
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for group in groups
            .into_iter()
            .filter(|group| group.identity == identity_scope)
        {
            self.ocsp_manager(&group).await?;
        }
        for (identity, resolver) in [
            (false, &self.context.resolver),
            (true, &self.identity_resolver),
        ] {
            if identity != identity_scope {
                continue;
            }
            for certificate in resolver.ocsp_certificates()? {
                let key = group_key(certificate.names(), identity);
                let manager = {
                    let state = self.state.lock().await;
                    state
                        .ocsp
                        .get(&key)
                        .or_else(|| {
                            if !identity {
                                state.ocsp.get("manual:false")
                            } else {
                                None
                            }
                        })
                        .cloned()
                };
                if let Some(manager) = manager {
                    let status = manager
                        .probe_cached_one(certificate, cancel.clone())
                        .await?;
                    if matches!(status, crate::cert_status::CacheRestore::Restored { status } if status.state == OcspState::Revoked)
                    {
                        self.context.resources.revoked.notify_waiters();
                    }
                }
            }
        }
        let manual = if identity_scope {
            None
        } else {
            self.state.lock().await.ocsp.get("manual:false").cloned()
        };
        if let Some(manager) = manual {
            for certificate in self.manual_resolver.ocsp_certificates()? {
                let status = manager
                    .probe_cached_one(certificate, cancel.clone())
                    .await?;
                if matches!(status, crate::cert_status::CacheRestore::Restored { status } if status.state == OcspState::Revoked)
                {
                    self.context.resources.revoked.notify_waiters();
                }
            }
        }
        Ok(())
    }

    pub(super) async fn manual_ocsp(&self, cancel: CancellationToken) -> Result<()> {
        let inventory = self.manual_resolver.ocsp_certificates()?;
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
        let disable = self.plan.disable_ocsp;
        let (max_concurrent, max_concurrent_per_responder) = self.context.resources.ocsp.limits();
        let manager = OcspManager::with_resources_and_inventory(
            store.fs.clone(),
            self.manual_resolver.clone(),
            OcspOptions {
                check_interval: self.plan.ocsp_interval,
                max_concurrent,
                max_concurrent_per_responder,
                ..OcspOptions::default()
            },
            Arc::new(move |_| {
                Ok(OcspConfig {
                    disable_stapling: disable,
                    ..OcspConfig::default()
                })
            }),
            Arc::new(move |certificate| identities.contains(&certificate.identity())),
            self.context.resources.ocsp.clone(),
        )?;
        self.state
            .lock()
            .await
            .ocsp
            .insert("manual:false".into(), manager);
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

    pub(super) async fn ocsp_manager(&self, group: &Group) -> Result<OcspManager> {
        let key = group_key(&group.names, group.identity);
        if let Some(manager) = self.state.lock().await.ocsp.get(&key).cloned() {
            return Ok(manager);
        }
        let disable = self.plan.disable_ocsp || group.policy.disable_ocsp;
        let overrides: std::collections::HashMap<String, String> =
            group.policy.ocsp_overrides.clone().into_iter().collect();
        let policy = Arc::new(move |_: &crate::tls_resolver::OcspCertificate| {
            Ok(OcspConfig {
                disable_stapling: disable,
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
        let manager = OcspManager::with_resources_and_inventory(
            group.store.fs.clone(),
            group.resolver.clone(),
            options,
            policy,
            inventory,
            self.context.resources.ocsp.clone(),
        )?
        .with_names_scope(group.names.clone())?;
        let mut state = self.state.lock().await;
        let manager = state.ocsp.entry(key).or_insert(manager).clone();
        drop(state);
        self.maintenance_changed.notify_one();
        Ok(manager)
    }
}

fn internal_name(name: &str) -> bool {
    name == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}
