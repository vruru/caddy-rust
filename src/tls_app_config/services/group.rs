use super::super::{loaders, model::AcmeSettings, storage::absolute};
use super::*;
use crate::cert_automation::AcmeIssuerConfig;
use crate::local_pki::CaConfig;


/// A concrete large acquisition future retires before its prepayment, including
/// caller abort. Only its pointer enters the outer Flight/SNI future layout.
struct AcquisitionFrame<F>{future:std::pin::Pin<Box<F>>,_memory:crate::acme_wire::chain_memory::Scratch}
impl<F:std::future::Future> std::future::Future for AcquisitionFrame<F>{
    type Output=F::Output;
    fn poll(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<Self::Output>{
        self.get_mut().future.as_mut().poll(cx)
    }
}
fn acquisition_frame<F:std::future::Future>(future:F)->Result<AcquisitionFrame<F>>{
    let bytes=std::mem::size_of_val(&future).checked_add(std::mem::align_of_val(&future))
        .and_then(|n|n.checked_add(2*std::mem::size_of::<usize>()+64)).ok_or(crate::cert_transient::ResourceDenied)?;
    let memory=crate::cert_transient::reserve(bytes)?;
    Ok(AcquisitionFrame{future:Box::pin(future),_memory:memory})
}

/// Additional concrete constructor copies/hash scratch. Original expanded-value
/// producer credit is separate and must accompany the input/result as well.
struct ManagerConstructionOwner {
    _memory:crate::acme_wire::chain_memory::Scratch,
    _root_inputs:Vec<crate::acme_wire::chain_memory::Scratch>,
    _test_inputs:crate::acme_wire::chain_memory::Scratch,
    _root_input_metadata:crate::acme_wire::chain_memory::Scratch,
    // Keep producer credit through the actual queued worker and retained error
    // or unconsumed manager; constructor admission does not replace this loan.
    issuer_values_credit:Option<Arc<crate::acme_wire::chain_memory::Lease>>,
}
impl crate::cert_cpu::MaterialOwner for ManagerConstructionOwner {
    fn reserve(&self,bytes:usize)->Result<()> {
        ensure!(bytes==0,crate::cert_transient::ResourceDenied);Ok(())
    }
}
struct ManagerBuildInput {
    store:crate::certstore::FsStore,
    registry:ChallengeRegistry,
    resolver:Arc<HotCertificateResolver>,
    options:AutomationOptions,
    resources:Arc<cert_automation::AutomationResources>,
    prepared:Vec<cert_automation::PreparedBackend>,
    solvers:Vec<cert_automation::SolverPreparation>,
    test_directories:Vec<Option<String>>,
    test_solvers:Vec<Option<cert_automation::SolverPreparation>>,
    events:Option<Arc<crate::events::EventsApp>>,
    key_type:crate::acme_wire::KeyType,
    must_staple:bool,
    reuse_private_keys:bool,
    tasks:TaskTracker,
    #[cfg(feature="native-run")]
    scope:Option<Arc<crate::outgoing_tls::Scope>>,
    // The actual queued closure and an unconsumed successful/error result keep
    // the same owner; no waiting-future drop can retire input/copy credit early.
    owner:Arc<ManagerConstructionOwner>,
}
impl ManagerBuildInput {
    fn copy_cost(prepared:&[cert_automation::PreparedBackend],test_directories:&[Option<String>],client_inputs:usize)->Result<usize>{
        let mut acme_index=0usize;
        let mut bytes=65536usize.checked_add(cert_automation::test_ca::plan_metadata_cost(test_directories.len())?).ok_or(crate::cert_transient::ResourceDenied)?;
        for item in prepared {
            match item {
                cert_automation::PreparedBackend::Internal{ca,..}=>{bytes=bytes.checked_add(ca.len().checked_mul(4).ok_or(crate::cert_transient::ResourceDenied)?).ok_or(crate::cert_transient::ResourceDenied)?;},
                cert_automation::PreparedBackend::Acme(config)=>{
                    let mut text=config.wire.directory.len().checked_add(config.email.len()).and_then(|n|n.checked_add(config.profile.len())).ok_or(crate::cert_transient::ResourceDenied)?;
                    for value in &config.wire.extra_ca_pem {text=text.checked_add(value.len()).ok_or(crate::cert_transient::ResourceDenied)?;}
                    for value in &config.wire.trusted_ca_origins {text=text.checked_add(value.len()).ok_or(crate::cert_transient::ResourceDenied)?;}
                    if let Some(eab)=&config.eab{text=text.checked_add(eab.kid.len()).and_then(|n|n.checked_add(eab.hmac_key.len())).ok_or(crate::cert_transient::ResourceDenied)?;}
                    let test=test_directories.get(acme_index).ok_or_else(||anyhow!("test CA index count changed"))?;
                    acme_index+=1;
                    bytes=bytes.checked_add(cert_automation::test_ca::copy_cost(config,test.as_deref(),client_inputs)?).ok_or(crate::cert_transient::ResourceDenied)?;
                    bytes=bytes.checked_add(text.checked_mul(4).and_then(|n|n.checked_add(16384)).ok_or(crate::cert_transient::ResourceDenied)?).ok_or(crate::cert_transient::ResourceDenied)?;
                },
            }
        }
        ensure!(acme_index==test_directories.len(),"test CA index count changed");
        Ok(bytes)
    }
    fn execute(self)->Result<CertificateManager>{
        let owner=self.owner.clone();
        match self.construct(){
            Ok(manager)=>Ok(manager),
            Err(error)=>Err(crate::cert_cpu::retained_error(error,owner)),
        }
    }
    fn construct(self)->Result<CertificateManager>{
        let issuer_values_credit=self.owner.issuer_values_credit.clone();
        let resources=self.resources.clone();
        let manager=CertificateManager::with_ordered_backends(self.store,self.registry,self.resolver,
            self.options,self.resources,None,self.prepared,self.key_type)?
            .with_construction_owner(self.owner.clone())?
            .with_issuer_values_credit(issuer_values_credit)?
            .with_prepared_test_cas(self.test_directories,&resources)?
            .with_test_ca_solvers(self.test_solvers)?
            .with_issuer_solvers(self.solvers)?.with_events(self.events)?;
        #[cfg(feature="native-run")]
        let manager=manager.with_client_tls_scope(self.scope)?;
        manager.with_csr_options(self.must_staple,self.reuse_private_keys)?.with_chain_tasks(self.tasks)?.storage_only()
    }
}

impl CertificateServices {
    pub(super) fn current_renewal_time(&self, material: &Material, policy: &Policy,kind:cert_automation::ManagedKind) -> Result<i64> {
        let (begin, end) = material.times()?;
        let ordinary = cert_automation::renewal_time(begin, end, policy.renewal_ratio, None, "")?;
        if kind!=cert_automation::ManagedKind::Internal {
            return Ok(ordinary);
        }
        // CertMagic's emergency window applies even to exceptionally short
        // internal certificates. Keep this same calculation inside the lease,
        // so preflight cannot ask early and then republish unchanged material.
        let interval = self.plan.renew_interval.checked_mul(5).unwrap_or(Duration::MAX);
        let seconds = interval.as_secs().saturating_add(u64::from(interval.subsec_nanos() > 0));
        let emergency = end.saturating_sub(i64::try_from(seconds).unwrap_or(i64::MAX));
        let fraction = cert_automation::renewal_time(begin, end, 1.0 / 50.0, None, "")?;
        Ok(ordinary.min(emergency).min(fraction))
    }
    pub(super) async fn group(
        &self,
        names: Vec<String>,
        identity: bool,
        bound: &[StagedAddress],
        cancel: CancellationToken,
    ) -> Result<Arc<Group>> {
        self.group_inner(names, identity, bound, cancel, true, None, None)
            .await
    }
    pub(super) async fn storage_probe_group(
        &self,
        names: Vec<String>,
        bound: &[StagedAddress],
        cancel: CancellationToken,
    ) -> Result<Arc<Group>> {
        self.group_inner(names, false, bound, cancel, false, None, None)
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
            Some(seed.clone()),
            Some(seed.origin.clone()),
        )
        .await
    }
    pub(super) async fn group_with_origin(
        &self,
        names: Vec<String>,
        identity: bool,
        bound: &[StagedAddress],
        cancel: CancellationToken,
        origin: String,
    ) -> Result<Arc<Group>> {
        self.group_inner(names, identity, bound, cancel, true, None, Some(origin))
            .await
    }
    pub(super) async fn replacement_group(
        &self,
        names: Vec<String>,
        bound: &[StagedAddress],
        cancel: CancellationToken,
        origin: String,
    ) -> Result<Arc<Group>> {
        self.group_inner(names, false, bound, cancel, false, None, Some(origin)).await
    }

    /// This path is entered only after this flight's permission check. Reuse a
    /// scope only under the same immutable policy; a due handover joins the old
    /// owner before the replacement can perform storage or signing work.
    fn residency_current(&self, group: &Group) -> Result<bool> {
        let binding = group.residency.lock()
            .map_err(|_| anyhow!("certificate residency unavailable"))?;
        Ok(binding.as_ref().is_none_or(|binding| binding.slot.live()))
    }

    pub(super) async fn authorized_on_demand_group(
        &self,
        names: Vec<String>,
        bound: &[StagedAddress],
        cancel: CancellationToken,
        origin: String,
        seed: Option<Arc<super::super::resident_cache::CacheEntry>>,
    ) -> Result<Arc<Group>> {
        self.group_inner(names, false, bound, cancel, true, seed, Some(origin)).await
    }

    async fn group_inner(
        &self,
        names: Vec<String>,
        identity: bool,
        bound: &[StagedAddress],
        cancel: CancellationToken,
        background: bool,
        seed: Option<Arc<super::super::resident_cache::CacheEntry>>,
        origin: Option<String>,
    ) -> Result<Arc<Group>> {
        let origin = origin.unwrap_or_else(|| names[0].clone());
        let key = self.management_key(&names, identity, &origin)?;
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
                        *binding = Some(ResidencyBinding::shared(seed));
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
            if !identity && self.policy_index(&group.origin)? != self.policy_index(&origin)? {
                return Err(anyhow!(
                    "certificate group origin changed; authorized replacement required"
                ));
            }
            if background {
                self.maintenance_changed.notify_one();
            }
            return Ok(group);
        }
        let candidate = self
            .build_candidate(
                names,
                identity,
                bound,
                cancel,
                background,
                restoring,
                seed,
                origin.clone(),
            )
            .await?;
        let mut state = self.state.lock().await;
        ensure!(
            state.groups.len() < super::capacity::GROUP_LIMIT,
            "certificate group capacity exceeded"
        );
        let group = state
            .groups
            .entry(key)
            .or_insert_with(|| candidate.clone())
            .clone();
        ensure!(
            self.residency_current(&group)?,
            super::super::resident_cache::CacheChanged
        );
        if !identity
            && !Arc::ptr_eq(&group, &candidate)
            && self.policy_index(&group.origin)? != self.policy_index(&origin)?
        {
            return Err(anyhow!(
                "certificate group origin changed; authorized replacement required"
            ));
        }
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

    #[allow(clippy::too_many_arguments)]
    async fn build_candidate(
        &self,
        names: Vec<String>,
        identity: bool,
        bound: &[StagedAddress],
        cancel: CancellationToken,
        background: bool,
        restoring: bool,
        seed: Option<Arc<super::super::resident_cache::CacheEntry>>,
        origin: String,
    ) -> Result<Arc<Group>> {
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
            self.policy_for_origin(&origin)?
        };

        if policy.issuers.is_empty() {
            if !identity && self.policy_index(&origin)?.is_none() && internal_name(&names[0]) {
                policy.issuers.push(Issuer::Internal {
                    ca: "local".into(),
                    options: InternalIssuerOptions::default(),
                });
            } else {
                // admin.go defaults to one ACME module; it does not call the
                // business email-based DefaultIssuers factory.
                policy.issuers = vec![Issuer::Acme(Box::new(AcmeSettings {
                    test_ca:Some(String::new()),
                    values:None,
                    config: AcmeIssuerConfig::lets_encrypt(),
                    account_key: None,
                    roots: Vec::new(),
                    http_port: None,
                    alpn_port: None,
                    bind_host: String::new(),
                    distributed: true,
                    timeout: None,
                }))];
            }
        }
        // HTTP application's internal port overrides are defaults for business
        // ACME solvers only. Explicit issuer alternate ports retain priority,
        // and the independently managed Admin identity is unaffected.
        if !identity {
            for issuer in &mut policy.issuers {
                if let Issuer::Acme(settings)=issuer {
                    if settings.http_port.is_none(){settings.http_port=self.plan.http_challenge_port;}
                    if settings.alpn_port.is_none(){settings.alpn_port=self.plan.alpn_challenge_port;}
                }
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
        let group_tasks=TaskTracker::new();
        let copy_bytes=policy.issuers.iter().try_fold(0usize,|sum,issuer|{
            let bytes=match issuer {Issuer::Acme(settings)=>settings.values.as_ref().map(|v|v.get().and_then(|p|p.copy_upper(self.context.resources.issuance.client_build_input_upper()))).transpose()?.unwrap_or(0),_=>0};
            sum.checked_add(bytes).ok_or_else(||anyhow!("ACME configured value copy budget overflow"))
        })?;
        let issuer_values_credit=if copy_bytes==0{None}else{Some(Arc::new(self.context.resources.issuer_values.reserve(copy_bytes)?))};
        // Temporary endpoint vector is admitted before any String clone and
        // survives the real constructor worker/error/output, not just its await.
        let test_bytes=policy.issuers.iter().try_fold(1024usize,|n,issuer|{
            let Issuer::Acme(settings)=issuer else{return Ok::<_,anyhow::Error>(n)};
            let value=if let Some(values)=&settings.values {values.get()?.test_ca.as_deref()}else{settings.test_ca.as_deref()};
            n.checked_add(value.map_or(0,str::len)).and_then(|n|n.checked_add(std::mem::size_of::<Option<String>>()+64))
                .ok_or_else(||crate::cert_transient::ResourceDenied.into())
        })?;
        let test_inputs=crate::cert_transient::reserve(test_bytes)?;
        let test_directories=policy.issuers.iter().filter_map(|issuer|match issuer {
            Issuer::Acme(settings)=>Some((||{
                Ok(if let Some(values)=&settings.values {values.get()?.test_ca.clone()}else{settings.test_ca.clone()})
            })()),_=>None,
        }).collect::<Result<Vec<_>>>()?;
        let root_count=policy.issuers.iter().try_fold(0usize,|sum,issuer|{
            let Issuer::Acme(settings)=issuer else{return Ok::<_,anyhow::Error>(sum)};
            let count=settings.roots.len();
            ensure!(count.checked_add(settings.config.wire.extra_ca_pem.len())
                .is_some_and(|n|n<=32),"ACME trust configuration exceeds bounds");
            sum.checked_add(count).ok_or_else(||crate::cert_transient::ResourceDenied.into())
        })?;
        let root_metadata=root_count.checked_mul(std::mem::size_of::<crate::acme_wire::chain_memory::Scratch>())
            .and_then(|n|n.checked_add(std::mem::size_of::<Vec<crate::acme_wire::chain_memory::Scratch>>()))
            .ok_or(crate::cert_transient::ResourceDenied)?;
        let root_input_metadata=crate::cert_transient::reserve(root_metadata)?;
        let mut root_inputs=Vec::new();
        root_inputs.try_reserve_exact(root_count)?;
        let mut prepared=Vec::new();
        let mut timeout=Duration::from_secs(1200);
        for issuer in &policy.issuers {
            match issuer {
                Issuer::Internal{ca,options}=>prepared.push(cert_automation::PreparedBackend::Internal {
                    pki:self.authority(ca,cancel.clone()).await?,ca:ca.clone(),options:options.clone(),
                }),
                Issuer::Acme(settings)=>{
                    let mut issuer=settings.config.clone();
                    if let Some(values)=&settings.values {values.get()?.apply(&mut issuer);}
                    if let Some(input)=&settings.account_key {
                        issuer.account_key=Some(input.prepare(self.context.resources.cpu.clone(),cancel.clone()).await?);
                    }
                    issuer.leaf_key_type=policy.key_type;
                    for path in &settings.roots {
                        let path=absolute(&self.context.paths.cwd,path);
                        let (root,memory)=loaders::blocking(self.context.resources.io.clone(),
                            cancel.clone(),move||loaders::read_root_input(&path)).await?;
                        root_inputs.push(memory);
                        issuer.wire.extra_ca_pem.push(root);
                    }
                    if let Some(value)=settings.timeout{timeout=timeout.min(value);}
                    prepared.push(cert_automation::PreparedBackend::Acme(issuer));
                },
            }
        }
        let settings=policy.issuers.iter().filter_map(|i|match i {
            Issuer::Acme(settings)=>Some((||{
                let mut settings=settings.as_ref().clone();
                if let Some(values)=&settings.values {let values=values.get()?;settings.config.wire.directory=values.directory.clone();settings.test_ca=values.test_ca.clone();}
                Ok(settings)
            })()),_=>None,
        }).collect::<Result<Vec<_>>>()?;
        if !settings.is_empty(){solver=Some(solver::SolverBroker::new(settings,bound.to_vec(),self.context.listener_provider.clone())?
            .with_issuer_values_credit(issuer_values_credit.clone())?);}
        let(max_concurrent,max_concurrent_per_ca)=self.context.resources.issuance.limits();
        let options=AutomationOptions{issuers:Vec::new(),renewal_window_ratio:policy.renewal_ratio,
            max_concurrent,max_concurrent_per_ca,poll_interval:self.plan.renew_interval,job_timeout:timeout};
        let bytes=ManagerBuildInput::copy_cost(&prepared,&test_directories,self.context.resources.issuance.client_build_input_upper())?;
        let owner=Arc::new(ManagerConstructionOwner{_memory:crate::cert_transient::reserve(bytes)?,
            _root_inputs:root_inputs,_test_inputs:test_inputs,_root_input_metadata:root_input_metadata,issuer_values_credit});
        let input=ManagerBuildInput{store:store.fs.clone(),registry:self.context.challenges.clone(),resolver:resolver.clone(),
            options,resources:self.context.resources.issuance.clone(),prepared,
            solvers:solver.as_ref().map(|b|b.callbacks()).transpose()?.unwrap_or_default(),
            test_solvers:solver.as_ref().map(|b|b.test_callbacks()).transpose()?.unwrap_or_default(),test_directories,
            events:(!identity).then(||self.context.events.clone()).flatten(),key_type:policy.key_type,
            must_staple:policy.must_staple,reuse_private_keys:policy.reuse_private_keys,tasks:group_tasks.clone(),
            #[cfg(feature="native-run")] scope:self.outgoing_tls.clone(),owner};
        // Hashing full root sets, typed identity and cooldown construction all
        // execute here, never after an async shell returns to the reactor.
        let manager=loaders::blocking(self.context.resources.cpu.clone(),cancel.clone(),move||input.execute()).await?;
        let issuer=GroupIssuer::Acme(manager);
        let selected_backend=seed.as_ref().map(|entry|cert_automation::BackendSelection::historical(entry.kind,&entry.issuer)).transpose()?;
        let seed_identity = seed.as_ref().map(|entry| entry.material.identity);
        let retained = self
            .state
            .lock()
            .await
            .material
            .iter()
            .find(|item| (identity || !policy.on_demand)
                && item.identity == identity && item.managed_names.as_ref() == Some(&names))
            .map(|item| item.material.clone());
        let seed_binding = seed
            .as_ref()
            .map(|entry| ResidencyBinding::shared(entry));
        let seed_material = seed.map(|entry| entry.material.clone()).or(retained);
        let spki = seed_material.as_ref().map(|material| material.spki_der.clone());
        let leaf_state = seed_material.map(|material| {
                let (_, end) = material.times()?;
                self.context.leaf_guard.intern(material.leaf_id, end)
            })
            .transpose()?;
        let imported = if identity || (policy.on_demand && seed_identity.is_none()) {
            None
        } else {
            self.on_demand.imported_binding(&names, seed_identity)
        };
        let group = Arc::new(Group {
            key: self.management_key(&names, identity, &origin)?,
            names,
            origin: origin.clone(),
            policy,
            store,
            resolver,
            issuer,
            selected_backend:Mutex::new(selected_backend),
            identity,
            gate: AsyncMutex::new(()),
            solver,
            leaf_state: Mutex::new(leaf_state),
            spki: Mutex::new(spki),
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
            cache_event_emitted: AtomicBool::new(restoring || imported.is_some()),
            cancel: self.context.cancel.child_token(),
            tasks: group_tasks,
            started: Mutex::new(false),
            _admission: group_admission,
        });
        ensure!(
            self.residency_current(&group)?,
            super::super::resident_cache::CacheChanged
        );
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
        let key = group.key.clone();
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
        let key = group.key.clone();
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
        let key = group.key.clone();
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
                group.select(manager.selection_for(&certificate.names,&certificate.issuer_key,&certificate.leaf_sha256).await?)?;
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
        self.ensure_group_target(group, cached_first, None, cancel).await
    }
    pub(super) async fn ensure_group_target(
        &self,
        group: Arc<Group>,
        cached_first: bool,
        target: Option<RenewalTarget>,
        cancel: CancellationToken,
    ) -> Result<i64> {
        self.ensure_group_target_for_round(group,cached_first,target,cancel,cert_automation::retry_operation::AcmeRound::default()).await
    }
    pub(super) async fn ensure_group_target_for_round(&self,group:Arc<Group>,cached_first:bool,target:Option<RenewalTarget>,cancel:CancellationToken,round:cert_automation::retry_operation::AcmeRound<'_>)->Result<i64> {
        self.ensure_group_target_operation(group,cached_first,target,cancel,round,None).await
    }
    pub(super) async fn ensure_group_target_with_operation(&self,group:Arc<Group>,cached_first:bool,target:Option<RenewalTarget>,cancel:CancellationToken,operation:&mut cert_automation::retry_operation::RetryOperation)->Result<i64> {
        self.ensure_group_target_operation(group,cached_first,target,cancel,cert_automation::retry_operation::AcmeRound::default(),Some(operation)).await
    }
    async fn ensure_group_target_operation(&self,group:Arc<Group>,cached_first:bool,target:Option<RenewalTarget>,cancel:CancellationToken,round:cert_automation::retry_operation::AcmeRound<'_>,mut retry:Option<&mut cert_automation::retry_operation::RetryOperation>)->Result<i64> {
        let _gate = tokio::select! { biased; _ = cancel.cancelled() => return Err(anyhow!("certificate acquisition cancelled")),_=group.cancel.cancelled()=>return Err(anyhow!("certificate scope retired")), gate = group.gate.lock() => gate };
        ensure!(!group.cancel.is_cancelled(), "certificate scope retired");
        if let Some(target) = &target {
            ensure!(target.receipt.identity() == target.material.identity,
                super::super::resident_cache::CacheChanged);
            ensure!(group.resolver.receipt_current(&target.receipt, &target.binding.slot)?,
                super::super::resident_cache::CacheChanged);
        }
        let previous = if let Some(target) = &target { Some(target.leaf.clone()) } else {
            group.leaf_state.lock()
                .map_err(|_| anyhow!("certificate leaf state unavailable"))?.clone()
        };
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
        let slot = if target.is_some() { None } else {
            group.residency.lock()
                .map_err(|_| anyhow!("certificate residency unavailable"))?.clone()
        };
        let retirement = slot.map(|binding| {
            let work = work.clone();
            let stop = stop_watch.clone();
            group.tasks.spawn(async move {
                tokio::select! {biased;_ = binding.slot.retired() => work.cancel(),_ = stop.cancelled() => {}}
            })
        });
        // A warm Flight owns this retry operation and its existing absolute
        // deadline. Re-run only the real acquire boundary; authorization and
        // group/target selection outside this method are not repeated.
        let result=if let Some(operation)=retry.as_deref_mut(){
            let mut failures=0u32;
            loop {
                if let Some(target)=&target {
                    match group.resolver.receipt_current(&target.receipt,&target.binding.slot) {
                        Ok(true)=>{},
                        Ok(false)=>break Err(super::super::resident_cache::CacheChanged.into()),
                        Err(error)=>break Err(error),
                    }
                }
                let entered=std::sync::atomic::AtomicBool::new(false);
                let selected=match operation.round(self.plan.renew_interval,&entered){
                    Ok(Some(round))=>round,
                    Ok(None)=>break Err(anyhow!("warm issuance operation ended")),
                    Err(error)=>break Err(error),
                };
                let outcome=match acquisition_frame(self.acquire(&group,cached_first,target.as_ref(),work.clone(),selected)){
                    Ok(future)=>future.await,Err(error)=>break Err(error),
                };
                let Err(error)=&outcome else{operation.close();break outcome};
                if work.is_cancelled()||group.cancel.is_cancelled()
                    ||error.is::<super::super::resident_cache::CacheChanged>()
                    ||error.is::<crate::tls_resolver::CertificatePublicationConflict>() {break outcome}
                operation.failed(entered.load(Ordering::Acquire),error,self.plan.renew_interval);
                if !operation.wait().is_zero(){break outcome}
                failures=failures.saturating_add(1);
                let delay=cert_automation::retry_backoff(failures,&group.names)
                    .max(cert_automation::error_retry_delay(error));
                // Proof listeners do not stay occupied through retry sleeps.
                if let Some(solver)=&group.solver {if solver.release().await.is_err(){break outcome}}
                tokio::select!{biased;
                    _=work.cancelled()=>break Err(anyhow!("warm certificate acquisition cancelled")),
                    _=group.cancel.cancelled()=>break Err(anyhow!("certificate scope retired")),
                    _=tokio::time::sleep(delay)=>{},
                }
            }
        }else{match acquisition_frame(self.acquire(&group,cached_first,target.as_ref(),work.clone(),round)){
            Ok(future)=>future.await,Err(error)=>Err(error),
        }};
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

    async fn remember_material(&self, group: &Arc<Group>, material: Arc<Material>) -> Result<()> {
        ensure!(material.names == group.names, "managed material aliases changed before retention");
        material.validate_at(now()?, false)?;
        reject_revoked(&material, &self.context.leaf_guard, true)?;
        *group.spki.lock().map_err(|_| anyhow!("certificate key state unavailable"))? = Some(material.spki_der.clone());
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
            material
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
        if group.identity {
            state.material.retain(|item| !(item.identity
                && item.managed_names.as_ref() == Some(&group.names)));
        }
        if group.identity || !state.material.iter().any(|item| !item.identity
            && item.material.identity == material.identity)
        {
            state.material.push(RetainedMaterial {
                material: material.clone(), identity: group.identity,
                managed_names: Some(group.names.clone()), origin: group.origin.clone(),
                renew_at: group.renew_at.load(Ordering::Acquire),
                ari_after: group.ari_after.load(Ordering::Acquire),
                kind:Some(group.selected_kind()?),
            });
        }
        let ocsp = group.publication.lock().ok().and_then(|receipt|
            receipt.as_ref().and_then(|receipt| state.ocsp
                .get(&physical_ocsp_key(group.identity, receipt.identity())).cloned()));
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

    async fn read_group_issuer_material(&self,group:&Group,issuer:&str,key:&str,cancel:CancellationToken)
        ->Result<(Option<CertificateBundle>,Option<(crate::certstore::InitialPrivateKey,crate::cert_automation::ReusableKey)>)> {
        if !group.policy.reuse_private_keys {return Ok((group.store.fs.load_certificate(issuer,key).await?,None));}
        let (bundle,initial)=group.store.fs.load_certificate_for_key_reuse(issuer,key).await?;
        let initial=if let Some(initial)=initial {
            let pem=initial.pem();let deny=self.context.leaf_guard.key_deny().clone();
            let reusable=crate::cert_cpu::run(self.context.resources.cpu.clone(),cancel,move||
                cert_automation::prepare_reusable_key(pem,&deny)).await?;
            Some((initial,reusable))
        }else{None};Ok((bundle,initial))
    }
    async fn probe_group_pinned(
        &self,
        group: &Arc<Group>,
        lease: Option<&crate::certstore::StorageLease>,
        cancel: CancellationToken,
    ) -> Result<()> {
        enum ProbeMaterial {
            Legacy(CertificateBundle),Owned(crate::certstore::OwnedCertificateBundle),
        }
        impl std::ops::Deref for ProbeMaterial {
            type Target=CertificateBundle;
            fn deref(&self)->&CertificateBundle{match self{Self::Legacy(bundle)=>bundle,Self::Owned(bundle)=>bundle}}
        }
        let bundle = match &group.issuer {
            GroupIssuer::Acme(manager) => {
                let(probe,index)=manager.probe_cached_selected(&group.names,cancel.clone()).await?;
                if let Some(index)=index{group.select(index)?;}
                match probe {
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
                        Some(ProbeMaterial::Owned(bundle))
                    }
                }
            }
            GroupIssuer::Internal { ca, .. } => {
                let key=names_key(&group.names)?;
                if group.store.fs.certificate_recovery_pending(ca,&key,&format!("issue_cert_{}",group.names[0])).await? {None}
                else {self.read_group_issuer_material(group,ca,&key,cancel.clone()).await?.0.map(ProbeMaterial::Legacy)}
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
        let mut material=match bundle{
            ProbeMaterial::Owned(bundle)=>self.parse_owned_material(bundle,group.clone(),cancel.clone()).await?,
            ProbeMaterial::Legacy(bundle)=>self.parse_material(bundle.chain_pem,bundle.private_key_pem,cancel.clone()).await?,
        };
        if material.names != group.names { material.names = group.names.clone(); }
        let material=Arc::new(material);
        self.prime_material_status(material.clone(), group.identity, cancel.clone()).await?;
        *group.spki.lock().map_err(|_| anyhow!("certificate key state unavailable"))? = Some(material.spki_der.clone());
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
            material.clone(),
            due,
            ari_after,
            PublishIntent::Insert,
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
        target: Option<&RenewalTarget>,
        cancel: CancellationToken,
        round:cert_automation::retry_operation::AcmeRound<'_>,
    ) -> Result<(i64, Arc<Material>)> {
        let intent = if cached_first || group.identity || target.is_some() {
            PublishIntent::Insert
        } else {
            group.residency.lock()
                .map_err(|_| anyhow!("certificate residency unavailable"))?
                .as_ref().and_then(|binding| binding.receipt.clone())
                .map_or(PublishIntent::Insert, |old| PublishIntent::Renew { old })
        };
        let intent_for = |material: &Material| -> Result<PublishIntent> {
            let Some(target) = target else { return Ok(intent.clone()); };
            ensure!(material.identity != target.material.identity,
                "managed warm certificate made no publication progress");
            if target.leaf.revocation()?.is_some_and(|revoked| revoked.version.reason == Some(1)) {
                ensure!(material.spki_id != target.material.spki_id,
                    "compromised certificate replacement reused the old public key");
            }
            let preserved_name0 = group.names.as_slice() == [target.material.management_name.as_ref()]
                && material.san_names() == target.material.san_names();
            ensure!(material.san_names() == group.names || preserved_name0,
                "managed warm certificate SAN does not match authorized subjects");
            if material.san_names() == target.material.san_names()
                && let Some(old) = &target.binding.receipt
            {
                return Ok(PublishIntent::ReplaceTarget {
                    old: old.clone(), binding: target.binding.clone(), selection: target.selection.clone(),
                });
            }
            // The new material covers a separately authorized Hello subject.
            // Retain every other alias and authority of the observed old chain.
            Ok(PublishIntent::WarmInsert { selection: target.selection.clone() })
        };
        match &group.issuer {
            GroupIssuer::Acme(manager) => {
                let mut authenticated_retry = false;
                loop {
                let loaded = if cached_first && !authenticated_retry {
                    manager.load_cached(&group.names, cancel.clone()).await?
                } else {
                    None
                };
                let info = match loaded {
                    Some(info) => info,
                    None => manager.ensure_for_round(&group.names,cancel.clone(),round).await?,
                };
                group.select(manager.selection_for(&info.names,&info.issuer_key,&info.leaf_sha256).await?)?;
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
                        .load_certificate_owned(&info.issuer_key, &names_key(&group.names)?)
                        .await?
                        .ok_or_else(|| anyhow!("managed certificate is missing"))?;
                    let ari_after =
                        cert_automation::ari_refresh_time(&bundle.metadata).unwrap_or(0);
                    let mut material = self
                        .parse_owned_material(bundle,group.clone(),cancel.clone())
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
                    if material.names != group.names { material.names = group.names.clone(); }
        let material=Arc::new(material);
                    self.prime_material_status(material.clone(), group.identity,
                        cancel.clone()).await?;
                    if self.context.leaf_guard.key_deny().check_spki_der(&material.spki_der).is_err()
                        || self.context.leaf_guard.intern(material.leaf_id, material.times()?.1)?
                        .revocation()?.is_some()
                    {
                        // Release this actual lease before the manager's
                        // next fresh-key ensure, which takes the same lease.
                        return Ok(None);
                    }
                    lease.check().await?;
                    self.publish_group(
                        group,
                        material.clone(),
                        info.renew_at_unix,
                        ari_after,
                        intent_for(&material)?,
                        cancel.clone(),
                        Some(&lease),
                    )
                    .await?;
                    Ok(Some((info.renew_at_unix, material)))
                }
                .await;
                match self.finish_publication_lease(group, lease, result).await? {
                    Some(material) => return Ok(material),
                    None if !info.obtained && !authenticated_retry => authenticated_retry = true,
                    None => return Err(anyhow!("managed certificate remains revoked after fresh acquisition")),
                }
                }
            }
            GroupIssuer::Internal { pki, ca, options } => {
                let lease = group
                    .store
                    .fs
                    .lock(&format!("issue_cert_{}", group.names[0]), cancel.clone())
                    .await?;
                let result = async {
                    let key = names_key(&group.names)?;
                    let mut previous_event = None;
                    group
                        .store
                        .fs
                        .recover_certificate_with_lease(ca, &key, &lease)
                        .await?;
                    let mut renewal_names = None;
                    let mut reuse_key=None;
                    let mut _reuse_key_state=None;
                    let (stored,initial)=self.read_group_issuer_material(group,ca,&key,cancel.clone()).await?;
                    let mut initial_snapshot=None;
                    if let Some((snapshot,reusable))=initial {
                        if reusable.state.banned() {
                            let archived=group.store.fs.archive_initial_private_key(ca,&key,&snapshot,
                                <sha2::Sha256 as sha2::Digest>::digest(&reusable.spki).into(),&group.names,&lease).await;
                            let _=self.events.send(CertificateEvent{names:group.names.clone(),kind:match archived {
                                Ok(true)=>"compromised_key_archived",Ok(false)=>"compromised_key_not_archived",Err(_)=>"compromised_key_archive_failed",
                            }});
                        }
                        _reuse_key_state=Some(reusable.state);
                        reuse_key=Some(reusable.pem);initial_snapshot=Some(snapshot);
                    }
                    if let Some(bundle) = stored {
                        let preserved = crate::certstore::name0_renewal_names(&bundle, &key)?;
                        let mut material = self
                            .parse_material(
                                bundle.chain_pem,
                                bundle.private_key_pem,
                                cancel.clone(),
                            )
                            .await?;
                        if material.names != group.names { material.names = group.names.clone(); }
        let material=Arc::new(material);
                        self.prime_material_status(material.clone(), group.identity, cancel.clone()).await?;
                        if self.context.leaf_guard.key_deny().check_spki_der(&material.spki_der)
                            .is_err_and(|error| error.is::<crate::key_compromise::KeyCompromised>()) {
                            let archived = group.store.fs.archive_compromised_key(ca, &key,
                                material.spki_id, &group.names, &lease).await;
                            let _ = self.events.send(CertificateEvent {
                                names: group.names.clone(), kind: match archived {
                                    Ok(true) => "compromised_key_archived",
                                    Ok(false) => "compromised_key_not_archived",
                                    Err(_) => "compromised_key_archive_failed",
                                },
                            });
                        }
                        if group.policy.reuse_private_keys && material.key_allowed(self.context.leaf_guard.key_deny()) {
                            _reuse_key_state=Some(material.register_key(self.context.leaf_guard.key_deny())?);
                            reuse_key=Some(zeroize::Zeroizing::new(material.key.to_vec()));
                        }
                        if material.key_allowed(self.context.leaf_guard.key_deny()) && !self.context.leaf_guard.intern(material.leaf_id, material.times()?.1)?.revocation()?.is_some_and(|r| r.version.reason == Some(1)) {
                            renewal_names = preserved;
                        }
                        let (begin, end) = material.times()?;
                        if begin > now()? {
                            return Err(cert_automation::FutureCertificate(begin).into());
                        }
                        let due = self.current_renewal_time(&material, &group.policy,cert_automation::ManagedKind::Internal)?;
                        let revoked = reject_revoked(&material, &self.context.leaf_guard, true).is_err();
                        if material.validate_at(now()?, false).is_ok()
                            && !revoked
                            && (cached_first || due > now()?)
                        {
                            self.publish_group(
                                group,
                                material.clone(),
                                due,
                                i64::MAX,
                                intent_for(&material)?,
                        cancel.clone(),
                                Some(&lease),
                            )
                            .await?;
                            return Ok((due, material));
                        }
                        previous_event=Some((end,revoked));
                    }
                    // LocalPki registration/provisioning precedes issuance and
                    // never installs trust; trust is a post-commit operation.
                    pki.provision(ca, cancel.clone()).await?;
                    let lifecycle=crate::cert_events::Attempt::new(&group.names[0],previous_event.map(|p|p.0));
                    let events=(!group.identity).then(||self.context.events.as_ref()).flatten();
                    lifecycle.obtaining(events,ca,previous_event.is_some_and(|p|p.1),&cancel).await?;
                    let issuance_names = renewal_names.unwrap_or_else(|| group.names.clone());
                    let names = issuance_names.clone();
                    let kind = group.policy.key_type;
                    let key_registry=self.context.leaf_guard.key_deny().clone();
                    let must_staple=group.policy.must_staple;
                    let (csr,private_key_pem,_key_reservation)=loaders::blocking(
                        self.context.resources.cpu.clone(),
                        cancel.clone(),
                        move || cert_automation::generate_csr_with_options(&names,kind,&key_registry,must_staple,reuse_key),
                    )
                    .await?;
                    let event_csr=csr.clone();
                    let chain_pem = match pki.issue(ca, csr, options.clone(), cancel.clone()).await {
                        Ok(chain)=>chain,
                        Err(error)=>{lifecycle.failed(events,std::slice::from_ref(ca),&error,&cancel).await;return Err(error)},
                    };
                    let mut material = self
                        .parse_material(chain_pem.clone(), private_key_pem.clone(), cancel.clone())
                        .await?;
                    if material.names != group.names { material.names = group.names.clone(); }
        let material=Arc::new(material);
                    material.validate_at(now()?, false)?;
                    let bundle = CertificateBundle {
                        chain_pem,
                        private_key_pem,
                        metadata: json!({"sans":issuance_names,"issuer_data":{"ca":ca}}),
                    };
                    lease.check().await?;
                    if let Some(initial)=initial_snapshot {
                        group.store.fs.save_certificate_with_initial_key(ca,&key,&bundle,&lease,&initial).await?;
                    } else {group.store.fs.save_certificate(ca,&key,&bundle,&lease).await?;}
                    lifecycle.obtained(events,ca,&group.names,&event_csr,&cancel).await;
                    lease.check().await?;
                    let due = self.current_renewal_time(&material, &group.policy,cert_automation::ManagedKind::Internal)?;
                    self.publish_group(
                        group,
                        material.clone(),
                        due,
                        i64::MAX,
                        intent_for(&material)?,
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
                        (physical_ocsp_key(identity_scope, certificate.identity()), certificate)
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
        let identity = if group.identity {
            self.state.lock().await.material.iter()
                .find(|item| item.identity && item.material.names == group.names)
                .map(|item| item.material.identity)
        } else {
            group.publication.lock()
                .map_err(|_| anyhow!("certificate publication unavailable"))?
                .as_ref().map(ScopedCertificate::identity)
        };
        match identity {
            Some(identity) => self.prepare_physical_ocsp(group.identity, identity).await,
            None => Ok(None),
        }
    }

}

pub(super) fn internal_name(name: &str) -> bool {
    name == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}
