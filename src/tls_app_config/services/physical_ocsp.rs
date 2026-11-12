//! Status maintenance follows one real chain in one resolver generation.
//! Certificate jobs are not status ownership or issuance authority.
use super::*;

pub(super) fn physical_ocsp_key(identity: bool, chain: [u8; 32]) -> String {
    let hash = chain.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("physical:{identity}:{hash}")
}

impl CertificateServices {
    pub(super) async fn prepare_physical_ocsp(
        &self,
        administrative: bool,
        chain: [u8; 32],
    ) -> Result<Option<OcspScope>> {
        if self.plan.disable_ocsp || self.context.cancel.is_cancelled() { return Ok(None); }
        let key = physical_ocsp_key(administrative, chain);
        let old = self.state.lock().await.ocsp.get(&key).cloned();
        if let Some(old) = old {
            if !old.is_cancelled() { return Ok(Some(old)); }
            // A late old runner cannot overlap a new installer for this key.
            old.stop().await?;
            let mut state = self.state.lock().await;
            if state.ocsp.get(&key).is_some_and(|current| current.same(&old)) {
                state.ocsp.remove(&key);
            }
        }
        let resolver = if administrative { self.identity_resolver.clone() }
            else { self.context.resolver.clone() };
        let Some(descriptor) = resolver.ocsp_descriptor(&chain)? else { return Ok(None); };
        let Some(manager) = self.physical_status_manager(administrative, chain,
            descriptor.management_name.clone(), self.context.cancel.clone()).await?
        else { return Ok(None); };
        let scope = OcspScope::new(manager, vec![descriptor.management_name.to_string()],
            &self.context.cancel);
        let mut state = self.state.lock().await;
        if self.context.cancel.is_cancelled() || resolver.ocsp_descriptor(&chain)?.is_none() {
            return Ok(None);
        }
        if let Some(current) = state.ocsp.get(&key) {
            if !current.is_cancelled() { return Ok(Some(current.clone())); }
            // Another preparer is joining this runner. Reconciliation retries
            // after the next notification/interval; never overlap installers.
            return Ok(None);
        }
        ensure!(state.ocsp.len() < 2 * crate::tls_resolver::MAX_CERTIFICATES + 1,
            "certificate status scope capacity exceeded");
        state.ocsp.insert(key, scope.clone());
        Ok(Some(scope))
    }

    async fn physical_status_manager(
        &self,
        administrative: bool,
        chain: [u8; 32],
        name0: Arc<str>,
        cancel: CancellationToken,
    ) -> Result<Option<OcspManager>> {
        if self.plan.disable_ocsp { return Ok(None); }
        let resolver = if administrative { self.identity_resolver.clone() }
            else { self.context.resolver.clone() };
        // Administrative identity keeps its independent default configuration.
        // Business status uses actual certificate Name0 in the current plan.
        let policy = if administrative { Policy::default() }
            else { self.policy(&name0) };
        if policy.disable_ocsp { return Ok(None); }
        let root = if administrative { self.context.paths.default_storage.clone() } else {
            policy.storage.as_ref().or(self.plan.storage.as_ref())
                .unwrap_or(&self.context.paths.default_storage).clone()
        };
        let store = self.context.resources.store(root, &self.context.paths,
            cancel.child_token()).await?;
        let overrides = policy.ocsp_overrides.clone().into_iter().collect::<HashMap<_, _>>();
        let policy = Arc::new(move |_: &crate::tls_resolver::OcspCertificate| Ok(OcspConfig {
            responder_overrides: overrides.clone(), ..OcspConfig::default()
        }));
        let selected_name = name0.clone();
        let inventory = Arc::new(move |certificate: &crate::tls_resolver::OcspCertificate|
            certificate.identity() == chain && certificate.management_name() == selected_name.as_ref());
        let (max_concurrent, max_concurrent_per_responder) = self.context.resources.ocsp.limits();
        let manager = OcspManager::with_resources_and_inventory_cpu(
            store.fs.clone(), resolver, OcspOptions {
                check_interval: self.plan.ocsp_interval, max_concurrent,
                max_concurrent_per_responder, ..OcspOptions::default()
            }, policy, inventory, self.context.resources.ocsp.clone(),
            self.context.resources.cpu.clone(),
        )?.with_identity_scope(chain)?;
        Ok(Some(manager))
    }

    /// Authenticate raw cached status before publishing dynamic or imported
    /// material. Generation zero is deliberately not a loaded instance: this
    /// probe may merge authenticated leaf facts but cannot attach a staple.
    pub(super) async fn prime_material_status(
        &self,
        material: Arc<Material>,
        administrative: bool,
        cancel: CancellationToken,
    ) -> Result<()> {
        let key_state=material.register_key(self.context.leaf_guard.key_deny())?;
        let Some(manager) = self.physical_status_manager(administrative,
            material.identity, material.management_name.clone(), cancel.clone()).await?
        else { return Ok(()); };
        let guard = self.context.leaf_guard.clone();
        let certificate = crate::cert_cpu::run(self.context.resources.cpu.clone(),
            cancel.clone(), move || {
                let key = material.certified_key()?;
                let chain_bytes=key.cert.iter().try_fold(0usize,|sum,der|sum.checked_add(der.len())
                    .ok_or_else(||anyhow!("OCSP preparation size overflow")))?;
                let names_bytes=material.names.iter().try_fold(0usize,|sum,name|sum.checked_add(name.len()+std::mem::size_of::<String>())
                    .ok_or_else(||anyhow!("OCSP preparation size overflow")))?;
                let cost=chain_bytes.checked_mul(8).and_then(|n|n.checked_add(names_bytes.checked_mul(4)?))
                    .and_then(|n|n.checked_add(8192)).ok_or_else(||anyhow!("OCSP preparation size overflow"))?;
                // A separate probe owner is not released by a concurrent cache
                // publication of the same Material. It follows actual copied
                // chain/result/verification owners until they are destroyed.
                let preparation=super::super::resident_cache::Preparation::reserve(cost)?;
                Ok(crate::tls_resolver::OcspCertificate {
                    preparation: Some(preparation),
                    identity: material.identity, generation: 0,
                    names: material.names.clone(), management_name: material.management_name.clone(),
                    chain_der: key.cert.iter().map(|der| der.as_ref().to_vec()).collect(),
                    leaf_state: guard.intern(material.leaf_id, material.times()?.1)?,
                    leaf_sha256: material.leaf_id,
                    key_state,
                })
            }).await?;
        let leaf = certificate.leaf_state.clone();
        manager.prime_cached_one(certificate, cancel).await?;
        if leaf.revocation()?.is_some() { self.context.resources.revoked.notify_waiters(); }
        Ok(())
    }

    pub(super) async fn reconcile_physical_ocsp(&self) -> Result<()> {
        let business = self.context.resolver.clone();
        let administrative = self.identity_resolver.clone();
        let descriptors = crate::cert_cpu::run(self.context.resources.cpu.clone(),
            self.context.cancel.clone(), move || {
                Ok((business.ocsp_descriptors()?, administrative.ocsp_descriptors()?))
            }).await?;
        let mut wanted = std::collections::HashSet::new();
        let mut candidates = Vec::new();
        for (identity, descriptors) in [(false, descriptors.0), (true, descriptors.1)] {
            for descriptor in descriptors {
                wanted.insert(physical_ocsp_key(identity, descriptor.identity));
                candidates.push((identity, descriptor.identity));
            }
        }
        let retired = {
            let mut state = self.state.lock().await;
            let keys = state.ocsp.iter().filter(|(key, scope)| key.starts_with("physical:")
                && (!wanted.contains(*key) || scope.is_cancelled()))
                .map(|(key, _)| key.clone()).collect::<Vec<_>>();
            keys.into_iter().filter_map(|key| state.ocsp.remove(&key)).collect::<Vec<_>>()
        };
        for scope in &retired { scope.cancel(); }
        let results = stream::iter(retired).map(|scope| async move { scope.stop().await })
            .buffer_unordered(8).collect::<Vec<_>>().await;
        let mut error = results.into_iter().find_map(Result::err);
        let results = stream::iter(candidates).map(|(identity, chain)| async move {
            self.prepare_physical_ocsp(identity, chain).await.map(|_| ())
        }).buffer_unordered(8).collect::<Vec<_>>().await;
        if error.is_none() { error = results.into_iter().find_map(Result::err); }
        match error { Some(error) => Err(error), None => Ok(()) }
    }
}
