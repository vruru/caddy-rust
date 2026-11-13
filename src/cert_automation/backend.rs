//! Closed native issuers share a durable attempt, never a pluggable callback.
use super::*;
pub(super) use super::attempt::{BackendId, InputBinding};

pub(crate) enum PreparedBackend {
    Acme(AcmeIssuerConfig),
    Internal { pki: crate::local_pki::LocalPki, ca: String,
        options: crate::local_pki::InternalIssuerOptions },
}
pub(super) struct Backend {
    pub id: BackendId,
    pub storage_key: String,
    pub kind: BackendKind,
}
fn identity_bytes(id:&BackendId)->Result<usize>{
    let(a,b)=match id {BackendId::Acme{directory,config_identity}=>(directory,config_identity),BackendId::Internal{ca,options_identity}=>(ca,options_identity)};
    a.len().checked_add(b.len()).and_then(|n|n.checked_add(std::mem::size_of::<BackendId>()+64)).ok_or_else(||crate::cert_transient::ResourceDenied.into())
}
pub(super) struct BackendIdentity {pub id:BackendId,_memory:crate::acme_wire::chain_memory::Scratch}
impl BackendIdentity {pub(super) fn copy(id:&BackendId)->Result<Arc<Self>>{
    let memory=crate::cert_transient::reserve(identity_bytes(id)?.checked_add(64).ok_or(crate::cert_transient::ResourceDenied)?)?;
    Ok(Arc::new(Self{id:id.clone(),_memory:memory}))
}}
#[derive(Clone)]
pub(crate) enum BackendSelection {Configured(usize),Historical(Arc<HistoricalSelection>)}
pub(crate) struct HistoricalSelection {kind:ManagedKind,class:String,_memory:crate::acme_wire::chain_memory::Scratch}
impl BackendSelection {
    pub(crate) fn historical(kind:ManagedKind,class:&str)->Result<Self>{
        let memory=crate::cert_transient::reserve(class.len().checked_add(std::mem::size_of::<HistoricalSelection>()+64)
            .ok_or(crate::cert_transient::ResourceDenied)?)?;
        Ok(Self::Historical(Arc::new(HistoricalSelection{kind,class:class.to_owned(),_memory:memory})))
    }
}
pub(super) enum BackendKind {
    Acme(usize),
    Internal { pki: crate::local_pki::LocalPki, ca: String,
        options: crate::local_pki::InternalIssuerOptions },
}
impl Backend {
    pub(super) fn issuer_class(&self) -> &str {
        match &self.kind {BackendKind::Acme(_)=>"",BackendKind::Internal{ca,..}=>ca}
    }
    pub(super) fn acme<'a>(&self, issuers: &'a [IssuerState]) -> Option<&'a IssuerState> {
        match self.kind {BackendKind::Acme(index)=>issuers.get(index),_=>None}
    }
    pub(super) fn renewal(&self, info:&MaterialInfo, ratio:f64, ari:Option<&AriWindow>, interval:Duration)->Result<i64> {
        let ordinary=renewal_time(info.not_before,info.not_after,ratio,ari,&info.leaf_sha256)?;
        if matches!(self.kind,BackendKind::Acme(_)){return Ok(ordinary)}
        let interval=interval.checked_mul(5).unwrap_or(Duration::MAX);
        let seconds=interval.as_secs().saturating_add(u64::from(interval.subsec_nanos()>0));
        Ok(ordinary.min(info.not_after.saturating_sub(i64::try_from(seconds).unwrap_or(i64::MAX)))
            .min(renewal_time(info.not_before,info.not_after,1.0/50.0,None,&info.leaf_sha256)?))
    }
}

/// The operation was cancelled and awaited, but this is not a receipt for a
/// possibly still-running TLS verifier. Deadline failures stay terminal.
#[derive(Debug)]
pub(super) struct LegDeadline;
impl std::fmt::Display for LegDeadline {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("certificate issuer leg deadline exceeded")}}
impl std::error::Error for LegDeadline {}

/// Call only at a remote issuer boundary. Unknown/local failures stay terminal.
pub(super) fn unavailable(error:&anyhow::Error,cancel:&CancellationToken)->bool {
    unavailable_at(error,cancel,0)
}
fn unavailable_at(error:&anyhow::Error,cancel:&CancellationToken,depth:usize)->bool {
    if depth>=16{return false}
    if cancel.is_cancelled() || crate::cert_transient::is_resource(error)
        ||error.is::<crate::cert_transient::ResourceDenied>()
        ||error.is::<crate::acme_wire::chain_memory::MemoryDenied>()
        ||error.is::<LegDeadline>()||error.is::<ExpiredStoredCandidate>()||error.is::<FutureCertificate>()
        ||error.is::<crate::acme_wire::AcmeRequestCancelled>() {
        return false
    }
    #[cfg(feature="native-run")]
    if error.is::<crate::outgoing_tls::ConnectionControl>()
        ||error.chain().any(|cause|cause.is::<crate::outgoing_tls::ConnectionControl>()) {return false}
    if error.is::<crate::key_compromise::KeyCompromised>()
        ||error.is::<crate::key_compromise::KeyCompromiseNotDurable>()
        ||error.is::<crate::key_compromise::KeyRegistryError>()
        ||error.chain().any(|cause|cause.is::<crate::key_compromise::KeyCompromised>()
            ||cause.is::<crate::key_compromise::KeyCompromiseNotDurable>()||cause.is::<crate::key_compromise::KeyRegistryError>()) {return false}
    // This known wrapper owns another anyhow table. Its std source alone
    // erases context payload downcasts; recurse only through this closed type.
    if let Some(active)=error.downcast_ref::<ActiveOrderError>()
        .or_else(||error.chain().find_map(|cause|cause.downcast_ref::<ActiveOrderError>())) {
        return unavailable_at(&active.0,cancel,depth+1)
    }
    // A request timeout may have dropped a waiting TLS future while its native
    // verifier still runs. This package has no per-call retirement receipt.
    if error.downcast_ref::<reqwest::Error>().is_some_and(reqwest::Error::is_timeout)
        ||error.chain().any(|cause|cause.downcast_ref::<reqwest::Error>().is_some_and(reqwest::Error::is_timeout)) {
        return false
    }
    if error.is::<crate::local_pki::SignerUnavailable>()
        ||error.chain().any(|cause|cause.is::<crate::local_pki::SignerUnavailable>()) {return true}
    // Actual HTTP responses follow a completed handshake; local controls above
    // must be excluded before a ProtocolError context grants this permission.
    if let Some(protocol)=error.downcast_ref::<ProtocolError>()
        &&protocol.status()>0
        &&error.root_cause().downcast_ref::<ProtocolError>().is_some_and(|root|std::ptr::eq(root,protocol)) {return true}
    // Only a pre-TLS kernel connect failure is proven here. Generic request,
    // body, TLS and DNS errors cannot stand in for an actual completion fence.
    let connect=error.downcast_ref::<reqwest::Error>().is_some_and(reqwest::Error::is_connect)
        ||error.chain().any(|cause|cause.downcast_ref::<reqwest::Error>().is_some_and(reqwest::Error::is_connect));
    connect&&error.chain().any(|cause|cause.downcast_ref::<std::io::Error>().is_some_and(|error|
        matches!(error.kind(),std::io::ErrorKind::ConnectionRefused|std::io::ErrorKind::AddrNotAvailable
            |std::io::ErrorKind::NetworkUnreachable|std::io::ErrorKind::HostUnreachable)))
}

pub(super) fn acme_id(config:&AcmeIssuerConfig)->Result<BackendId> {
    let mut h=Sha256::new();
    fn frame(h:&mut Sha256,b:&[u8]){h.update((b.len()as u64).to_be_bytes());h.update(b)}
    frame(&mut h,config.wire.directory.as_bytes());frame(&mut h,config.email.as_bytes());
    if let Some(key)=&config.account_key {frame(&mut h,key.fingerprint().as_bytes())}
    frame(&mut h,config.profile.as_bytes());h.update(config.certificate_lifetime_ns.to_be_bytes());
    frame(&mut h,&serde_json::to_vec(&(config.account_key_type,config.leaf_key_type,&config.challenge_types,&config.preferred_chains))?);
    h.update([u8::from(config.terms_of_service_agreed),u8::from(config.wire.allow_insecure_loopback)]);
    h.update(config.wire.request_timeout.as_nanos().to_be_bytes());
    if let Some(proxy)=&config.wire.network_proxy{let(k,v)=proxy.fingerprint();frame(&mut h,k);frame(&mut h,v)}
    for root in &config.wire.extra_ca_pem{frame(&mut h,root)}
    for origin in &config.wire.trusted_ca_origins{frame(&mut h,origin.as_bytes())}
    if let Some(eab)=&config.eab{frame(&mut h,eab.kid.as_bytes());frame(&mut h,eab.hmac_key.as_bytes())}
    Ok(BackendId::Acme{directory:config.wire.directory.clone(),config_identity:format!("{:x}",h.finalize())})
}
pub(super) fn internal_id(ca:&str,options:&crate::local_pki::InternalIssuerOptions)->BackendId {
    let mut h=Sha256::new();h.update(options.lifetime.as_nanos().to_be_bytes());h.update([u8::from(options.sign_with_root)]);
    BackendId::Internal{ca:ca.to_owned(),options_identity:format!("{:x}",h.finalize())}
}

pub(super) fn subjects(input:&[String])->Result<Vec<String>> {
    ensure!(!input.is_empty()&&input.len()<=100,"certificate name count outside bounds");
    let mut names=Vec::with_capacity(input.len());
    for name in input {
        let name=name.trim().trim_end_matches('.');
        let name=if let Ok(ip)=name.parse::<std::net::IpAddr>() {
            crate::tls_resolver::canonical_certificate_ip(ip)
        }else{
            let (wildcard,dns)=match name.strip_prefix("*.") {
                Some(suffix)=>(true,suffix),None=>(false,name),
            };
            // Keep the existing DNS path's IDNA conversion before applying
            // the shared ASCII challenge identifier checks. A wildcard's
            // suffix must still be a DNS name, never an IP address.
            let url::Host::Domain(dns)=url::Host::parse(dns)
                .map_err(|_|anyhow!("invalid certificate DNS identifier"))? else {
                    bail!("wildcard certificate suffix must be a DNS name")
                };
            let dns=crate::challenge::normalize_domain(&dns)?;
            if wildcard {format!("*.{dns}")}else{dns}
        };
        names.push(name);
    }
    names.sort();names.dedup();Ok(names)
}

impl CertificateManager {
    pub(super) fn issuer_identity(&self,issuer:&IssuerState)->Result<&BackendId>{
        self.inner.backends.iter().find(|backend|match backend.kind {
            BackendKind::Acme(index)=>self.inner.issuers.get(index).is_some_and(|actual|std::ptr::eq(actual,issuer)),_=>false,
        }).map(|backend|&backend.id).ok_or_else(||anyhow!("ACME issuer identity missing"))
    }
    pub(crate) async fn selection_for(&self,names:&[String],storage_key:&str,leaf:&str)->Result<BackendSelection>{
        if let Some(state)=self.load_attempt(names).await? {
            let id=if let Some(winner)=state.winner {
                ensure!(winner.leaf_sha256==leaf&&winner.issuer_key==storage_key,"selected certificate winner changed");
                winner.backend
            }else if state.base_leaf.as_deref()==Some(leaf){state.base_backend}else{None};
            if let Some(id)=id {
                if let Some(index)=self.inner.backends.iter().position(|b|b.id==id){return Ok(BackendSelection::Configured(index))}
                let (kind,class)=match &id {
                    BackendId::Acme{..}=>(ManagedKind::Acme,""),BackendId::Internal{ca,..}=>(ManagedKind::Internal,ca.as_str()),
                };
                ensure!(self.inner.backends.iter().any(|b|b.issuer_class()==class
                    &&matches!((&b.kind,kind),(BackendKind::Acme(_),ManagedKind::Acme)|(BackendKind::Internal{..},ManagedKind::Internal))),
                    "stored winner is outside current issuer policy");
                return BackendSelection::historical(kind,class)
            }
        }
        // Legacy records contain no typed identity. Preserve only the old
        // first-same-storage recovery, never manufacture a typed winner.
        self.inner.backends.iter().position(|b|b.storage_key==storage_key).map(BackendSelection::Configured)
            .ok_or_else(||anyhow!("selected issuer is outside this manager"))
    }
    pub(crate) fn selection_class<'a>(&'a self,selection:&'a BackendSelection)->Result<&'a str>{match selection {
        BackendSelection::Configured(index)=>self.selected_class(*index),BackendSelection::Historical(value)=>Ok(&value.class),
    }}
    pub(crate) fn selection_kind(&self,selection:&BackendSelection)->Result<ManagedKind>{match selection {
        BackendSelection::Configured(index)=>self.selected_kind(*index),BackendSelection::Historical(value)=>Ok(value.kind),
    }}
    pub(crate) fn index_for_class(&self,class:&str,kind:ManagedKind)->Result<usize>{
        self.inner.backends.iter().enumerate().find(|(_,b)|b.issuer_class()==class
            &&matches!((&b.kind,kind),(BackendKind::Acme(_),ManagedKind::Acme)|(BackendKind::Internal{..},ManagedKind::Internal)))
            .map(|(i,_)|i).ok_or_else(||anyhow!("cached issuer is outside this policy"))
    }
    pub(crate) fn selected_kind(&self,index:usize)->Result<ManagedKind>{
        let backend=self.inner.backends.get(index).ok_or_else(||anyhow!("selected issuer not initialized"))?;
        Ok(match backend.kind{BackendKind::Acme(_)=>ManagedKind::Acme,BackendKind::Internal{..}=>ManagedKind::Internal})
    }
    pub(crate) fn selected_class(&self,index:usize)->Result<&str>{
        self.inner.backends.get(index).map(Backend::issuer_class).ok_or_else(||anyhow!("selected issuer not initialized"))
    }
    pub(crate) fn issuer_class_for(&self,info:&ManagedCertificate)->Result<&str> {
        self.inner.backends.iter().find(|b|b.storage_key==info.issuer_key)
            .map(Backend::issuer_class).ok_or_else(||anyhow!("selected issuer is outside this manager"))
    }
    async fn make_unified_attempt(&self,names:&[String],id:&str,previous:Option<&Replacement>,first:Option<usize>,
        cancel:&CancellationToken)->Result<Attempt>{
        let mut bytes=32768usize;
        for backend in &self.inner.backends {bytes=bytes.checked_add(identity_bytes(&backend.id)?.checked_mul(2).ok_or(crate::cert_transient::ResourceDenied)?).ok_or(crate::cert_transient::ResourceDenied)?;}
        for issuer in &self.inner.issuers {bytes=bytes.checked_add(issuer.config.wire.directory.len()+64).ok_or(crate::cert_transient::ResourceDenied)?;}
        for name in names {bytes=bytes.checked_add(name.len()*2+128).ok_or(crate::cert_transient::ResourceDenied)?;}
        if let Some(identity)=previous.and_then(|p|p.backend_identity.as_ref()){bytes=bytes.checked_add(identity_bytes(&identity.id)?).ok_or(crate::cert_transient::ResourceDenied)?;}
        let memory=crate::acme_wire::chain_memory::scratch(bytes,cancel.clone()).await?;
        let names=names.to_vec();let id=id.to_owned();let manager=self.clone();
        let base_leaf=previous.map(|p|p.previous_leaf.clone());let base_backend=previous.and_then(|p|p.backend_identity.clone());
        self.cpu(cancel,move||{
            let mut ordered=manager.inner.backends.iter().map(|b|b.id.clone()).collect::<Vec<_>>();
            if let Some(index)=first {let value=ordered.remove(index);ordered.insert(0,value);}
            Ok(Attempt{version:2,retired:false,names,attempt_id:id.clone(),
                issuer_sequence:manager.inner.issuers.iter().map(|i|i.config.wire.directory.clone()).collect(),
                current_job_id:None,base_leaf,base_backend:base_backend.map(|b|b.id.clone()),winner:None,
                backend_sequence:ordered,configured_sequence:manager.inner.backends.iter().map(|b|b.id.clone()).collect(),
                input_id:Some(format!("input-v2-{id}")),current_backend:None,current_input:None,acme_phase:None,_phase_memory:None,_memory:Some(memory)})
        }).await
    }
    pub(super) async fn ensure_unified(&self,names:Vec<String>,cancel:CancellationToken,round:retry_operation::AcmeRound<'_>)->Result<ManagedCertificate> {
        let lease=self.inner.store.lock(&format!("issue_cert_{}",names[0]),cancel.clone()).await?;
        let initial=async {
            let (ready,previous)=self.load_state_for_round(&names,&lease,&cancel,round).await?;
            if let Some(ready)=ready{return Ok((Some(ready),previous,None,None,None))}
            round.enter();
            let old=self.load_attempt(&names).await?;
            if let Some(old)=old.filter(|a|a.unified()&&!a.retired&&a.winner.is_none()) {
                ensure!(old.configured_sequence.iter().eq(self.inner.backends.iter().map(|b|&b.id)),
                    "active certificate issuer sequence changed; resume the original policy");
                let id=old.input_id.as_deref().ok_or_else(||anyhow!("active attempt input missing"))?;
                match self.load_input(id,&old.attempt_id,&cancel).await {
                    Ok(input)=>{
                        let lifecycle=crate::cert_events::Attempt::new(&names[0],previous.as_ref().map(|p|p.not_after));
                        return Ok((None,previous,Some(old.attempt_id),Some(lifecycle),Some(input)))
                    },
                    Err(error)if error.is::<crate::key_compromise::KeyCompromised>()=>{
                        self.archive_compromised_attempt(old,&lease,&cancel).await?;
                    },
                    Err(error)=>return Err(error),
                }
            }
            let lifecycle=self.emit_obtaining(&names,previous.as_ref(),&cancel).await?;
            let initial=if previous.is_none(){self.initial_reuse_plan(&names,&cancel).await?}else{None};
            let reuse=previous.as_ref().and_then(|p|p.reuse_key.as_ref()).or(initial.as_ref().map(|p|&p.0));
            use p256::elliptic_curve::rand_core::RngCore;
            let mut random=[0u8;32];p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut random);
            let attempt_id=digest(&random);
            let issue_names=previous.as_ref().and_then(|p|p.renewal_names.as_deref()).unwrap_or(&names);
            let input=self.make_input(&attempt_id,issue_names,reuse,&cancel,&lease).await?;
            let state=self.make_unified_attempt(&names,&attempt_id,previous.as_ref(),initial.as_ref().map(|(_,index)|*index),&cancel).await?;
            self.save_attempt(state,&lease).await?;
            Ok::<_,anyhow::Error>((None,previous,Some(attempt_id),Some(lifecycle),Some(input)))
        }.await;
        let released=lease.release().await;
        let (ready,mut previous,attempt_id,lifecycle,input)=initial?;released?;
        if let Some(ready)=ready{return Ok(ready)}
        let attempt_id=attempt_id.ok_or_else(||anyhow!("certificate attempt missing"))?;
        let lifecycle=lifecycle.ok_or_else(||anyhow!("certificate lifecycle missing"))?;
        let input=input.ok_or_else(||anyhow!("certificate attempt input missing"))?;
        let state=self.load_attempt(&names).await?.ok_or_else(||anyhow!("certificate attempt disappeared"))?;
        let produced=std::sync::atomic::AtomicBool::new(false);
        let mut entered=0usize;
        let result=async {
        let mut last=None;
        for (rank,backend_id) in state.backend_sequence.iter().enumerate() {
            ensure!(!cancel.is_cancelled(),"certificate acquisition cancelled");
            let backend=self.inner.backends.iter().find(|b|&b.id==backend_id)
                .ok_or_else(||anyhow!("certificate attempt backend no longer configured"))?;
            if rank>0{sleep_cancel(Duration::from_millis(250u64<<rank.min(5)),&cancel).await?}
            entered=rank+1;
            let mut account=None;let mut reservation=None;
            let test_driver=match backend.kind{BackendKind::Acme(index)=>self.uses_test_driver(index,&state),_=>false};
            if let Some(issuer)=backend.acme(&self.inner.issuers) {
                // Subject incompatibility is one issuer's PreCheck, not loss of
                // the already authorized Internal capability or ask decision.
                if normalize_names(&input.record.names).is_err(){last=Some(anyhow!("ACME issuer does not support these authorized identifier types"));continue}
                let allowed=issuer.ca.next_allowed_unix.load(Ordering::Acquire);
                if !test_driver&&allowed>now(){last=Some(RetryAfterError(allowed).into());continue}
                if let Some(key)=&issuer.config.account_key {
                    match key.signer(){Ok(_)=>{},
                        Err(error)if error.is::<super::account_key::CredentialUnavailable>()=>{
                            last=Some(error.context("configured ACME issuer credential unavailable"));continue
                        },
                        Err(error)=>return Err(error),
                    }
                }
                if !test_driver {
                let network=self.net_permit(issuer,&cancel).await?;
                let setup=async {
                    let wire=issuer.wire.get_or_try_init(||async {
                        AcmeWire::connect_with_client_tls_scope(
                            issuer.config.wire.clone(),self.inner.local.clone(),self.inner.chain_memory.clone(),
                            #[cfg(feature="native-run")] self.inner.outgoing_tls.clone(),self.wire_client_owner(),&cancel)
                            .await
                    }).await?;
                    let marker=self.read_reservation(&names,issuer).await?;
                    let session=self.account(issuer,wire,marker.as_ref().map(|m|m.account_location.as_str()),&cancel).await?;
                    Ok::<_,anyhow::Error>((session,marker))
                }.await;
                drop(network);
                match setup {Ok((session,marker))=>{account=Some(session);reservation=marker},
                    Err(error) if unavailable(&error,&cancel)=>{record_issuer_error(issuer,&error);last=Some(error);continue},
                    Err(error)=>return Err(error),}
                }
            }
            let lease=self.inner.store.lock(&format!("issue_cert_{}",names[0]),cancel.clone()).await?;
            let work=cancel.child_token();let lost=lease.lost();
            let result={
            let operation=async {
                let (ready,replacement)=self.load_state(&names,&lease,&work).await?;
                if let Some(ready)=ready{return Ok(ready)}
                if replacement.is_some(){previous=replacement}
                let active=self.load_attempt(&names).await?.ok_or_else(||anyhow!("certificate attempt disappeared"))?;
                ensure!(active.attempt_id==attempt_id&&active.winner.is_none(),"certificate attempt superseded");
                self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;
                match &backend.kind {
                    BackendKind::Internal{..}=>self.issue_internal(&names,backend,input.clone(),&attempt_id,&lease,&lifecycle,&work,true,Some(&produced)).await,
                    BackendKind::Acme(index)=>{
                        let issuer=&self.inner.issuers[*index];
                        self.inner.store.recover_certificate_with_lease(&backend.storage_key,&names_key(&names)?,&lease).await?;
                        let _=self.read_issuer_certificate(&backend.storage_key,&names_key(&names)?,&work).await?;
                        if test_driver {
                            return self.issue_test_ca_leg(*index,&names,&attempt_id,&input,previous.as_ref(),&lease,&lifecycle,&work,round,&produced).await;
                        }
                        let current=self.read_reservation(&names,issuer).await?;
                        ensure!(current.as_ref().map(|v|v.job_id.as_str())==reservation.as_ref().map(|v|v.job_id.as_str()),
                            "issuer reservation changed during account preparation");
                        let session=account.as_ref().ok_or_else(||anyhow!("ACME account preparation missing"))?;
                        if let Some(current)=&current {ensure!(current.account_location==session.location(),"ACME account identity changed")}
                        let current=if let Some(marker)=current {
                            if self.retire_compromised_job(&marker,&lease,&work).await?{None}else{Some(marker)}
                        }else{None};
                        let leg_input=match current.as_ref(){Some(current)=>self.input_for_job(current,&attempt_id,input.clone(),&work).await?,None=>input.clone()};
                        let _network=self.net_permit(issuer,&work).await?;
                        let allowed=issuer.ca.next_allowed_unix.load(Ordering::Acquire);
                        if allowed>now(){return Err(RetryAfterError(allowed).into())}
                        self.issue(&names,issuer,session,&lease,(previous.as_ref(),current.as_ref(),&attempt_id),
                            None,&lifecycle,&work,Some(&leg_input),Some(&produced),round.ordinal).await
                    },
                }
            };
            tokio::pin!(operation);
            let budget=(self.inner.options.job_timeout/(self.inner.backends.len()as u32+1))
                .min(Duration::from_secs(120)).max(Duration::from_secs(1));
            let result=tokio::select!{
                value=&mut operation=>value,
                _=cancel.cancelled()=>{work.cancel();let _=operation.await;Err(anyhow!("certificate acquisition cancelled"))},
                _=lost.cancelled()=>{work.cancel();let _=operation.await;Err(anyhow!("certificate storage lease lost"))},
                _=tokio::time::sleep(budget)=>{work.cancel();operation.await.map_err(|error|error.context(LegDeadline))},
            };
            result
            };
            work.cancel();
            let fallthrough=result.as_ref().is_err_and(|error|!cancel.is_cancelled()
                &&!error.is::<LegDeadline>()
                &&(unavailable(error,&cancel)||error.is::<RetryAfterError>()));
            if fallthrough&&rank+1<state.backend_sequence.len()&&matches!(backend.kind,BackendKind::Acme(_)) {
                self.abandon_leg(&names,&attempt_id,&lease).await?;
            }
            let release=lease.release().await;release?;
            match result {
                Ok(value)=>return Ok(value),
                Err(error) if error.is::<test_ca_driver::RetiredProbe>()=>{last=Some(error.context(retry_operation::NoRetry));},
                Err(error) if unavailable(&error,&cancel)||error.is::<RetryAfterError>()=>{
                    if !error.is::<test_ca_driver::TestEndpoint>()&&let Some(issuer)=backend.acme(&self.inner.issuers){record_issuer_error(issuer,&error)}last=Some(error)
                },
                Err(error)=>return Err(error),
            }
        }
        Err(last.unwrap_or_else(||anyhow!("no configured issuer available")))
        }.await;
        if let Err(error)=&result
            &&entered>0&&!produced.load(Ordering::Acquire)&&!cancel.is_cancelled() {
            struct FailedIssuers {keys:Vec<String>,_memory:crate::acme_wire::chain_memory::Scratch}
            let bytes=state.backend_sequence.iter().take(entered).try_fold(512usize,|n,id|{
                let backend=self.inner.backends.iter().find(|b|&b.id==id).ok_or(crate::cert_transient::ResourceDenied)?;
                n.checked_add(backend.storage_key.len()*2+2*std::mem::size_of::<String>()).ok_or(crate::cert_transient::ResourceDenied)
            });
            // Diagnostics are best-effort, like the existing event contract;
            // a failed diagnostic admission must preserve the original error.
            if let Ok(bytes)=bytes&&let Ok(memory)=crate::cert_transient::reserve(bytes) {
                let packet=FailedIssuers{keys:state.backend_sequence.iter().take(entered).filter_map(|id|
                    self.inner.backends.iter().find(|b|&b.id==id).map(|b|b.storage_key.clone())).collect(),_memory:memory};
                lifecycle.failed(self.inner.lifecycle_events.as_ref(),&packet.keys,error,&cancel).await;
            }
        }
        result
    }
}
