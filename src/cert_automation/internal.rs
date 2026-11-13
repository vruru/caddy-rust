//! Native internal issuance joins the manager's real transaction, not a Group.
use super::*;
use super::attempt::{InputRecord,RuntimeInput,InternalLeg};

/// Small fixed metadata; dynamic scratch is admitted before each producer.
/// The actual CSR/PKI closure/result holds this owner after its waiter is gone.
struct Credits {
    _input:Arc<RuntimeInput>,
    slots:std::sync::Mutex<[Option<crate::acme_wire::chain_memory::Scratch>;16]>,
    _shell:crate::acme_wire::chain_memory::Scratch,
}
impl crate::cert_cpu::MaterialOwner for Credits {
    fn reserve(&self,bytes:usize)->Result<()> {
        let credit=crate::cert_transient::reserve(bytes)?;
        let mut slots=self.slots.lock().map_err(|_|anyhow!("internal material credit unavailable"))?;
        if let Some(slot)=slots.iter_mut().find(|s|s.is_none()){*slot=Some(credit);Ok(())}
        else{drop(slots);drop(credit);Err(crate::cert_transient::ResourceDenied.into())}
    }
}
struct SpkiHash {
    spki:Arc<[u8]>,
    _key:Arc<crate::key_compromise::KeyState>,
    _input:Arc<RuntimeInput>,
}
impl SpkiHash {fn execute(self)->String{digest(&self.spki)}}
impl CertificateManager {
    pub(super) async fn retire_compromised_job(&self,marker:&Reservation,lease:&StorageLease,
        cancel:&CancellationToken)->Result<bool> {
        lease.check().await?;
        let mut job=self.load_job(&marker.job_id).await?.ok_or_else(||anyhow!("retiring ACME job missing"))?;
        validate_reservation_job(marker,&job)?;
        if job.phase=="stored"{return Ok(false)}
        match self.check_job_key(job.private_key_pem.as_bytes(),cancel).await {
            Ok(_)=>return Ok(false),
            Err(error)if error.is::<crate::key_compromise::KeyCompromised>()=>{},
            Err(error)=>return Err(error),
        }
        // Preserve the original CSR/key/order URL. This is an audited local
        // key retirement, not permission to fall through to a different CA.
        job.abandoned=true;self.save_job(&marker.job_id,&job,lease).await?;
        let mut retired=marker.clone();retired.active=false;retired.retired=true;
        let id=reservation_id(&retired.names,&retired.directory)?;let name=lease.name().to_owned();
        let encoded=self.cpu(cancel,move||job_codec::encode_record(&retired,&name)).await?;
        self.inner.store.journal_store_encoded_fenced(&id,encoded,lease).await?;Ok(true)
    }
    pub(super) async fn archive_compromised_attempt(&self,state:Attempt,lease:&StorageLease,
        cancel:&CancellationToken)->Result<()> {
        ensure!(state.unified()&&state.winner.is_none(),"cannot retire committed attempt");
        let id=format!("retired-input-attempt-v2-{}",state.attempt_id);let name=lease.name().to_owned();
        let encoded=self.cpu(cancel,move||job_codec::encode_record(&state,&name)).await?;
        self.inner.store.journal_store_encoded_fenced(&id,encoded,lease).await
    }
    pub(super) async fn input_for_job(&self,marker:&Reservation,attempt_id:&str,shared:Arc<RuntimeInput>,
        cancel:&CancellationToken)->Result<Arc<RuntimeInput>> {
        let job=self.load_job(&marker.job_id).await?.ok_or_else(||anyhow!("reserved ACME job missing"))?;
        validate_reservation_job(marker,&job)?;
        self.validate_job_renewal_scope(&job).await?;
        let memory=Arc::new(crate::acme_wire::chain_memory::scratch(512*1024,cancel.clone()).await?);
        let deny=self.inner.resolver.leaf_guard().key_deny().clone();let id=marker.job_id.clone();
        let original=job.attempt_id.clone();let marker=marker.clone();
        let attempt_id=attempt_id.to_owned();
        self.cpu(cancel,move||{
            let same=digest(&job.csr_der)==shared.record.csr_hash
                &&job.private_key_pem.as_bytes()==shared.record.private_key_pem.as_bytes();
            if job.attempt_id==attempt_id {
                ensure!(same,"active ACME job input changed");return Ok(shared)
            }
            let scope=digest(&serde_json::to_vec(&marker)?);
            let record=InputRecord{version:2,retired:false,attempt_id,
                names:job.renewal_names.as_ref().unwrap_or(&job.names).clone(),csr_der:job.csr_der.clone(),
                private_key_pem:job.private_key_pem.clone(),spki_der:Vec::new(),csr_hash:digest(&job.csr_der),spki_hash:String::new()};
            let reusable=prepare_reusable_key(Zeroizing::new(record.private_key_pem.as_bytes().to_vec()),&deny)?;
            let mut record=record;record.spki_der=reusable.spki.to_vec();record.spki_hash=digest(&record.spki_der);
            let mut input=RuntimeInput::validate(record,&format!("legacy-{id}"),memory,&deny)?;
            input.binding=attempt::InputBinding::LegacyJob{job_id:id,original_attempt_id:original,
                csr_hash:input.record.csr_hash.clone(),spki_hash:input.record.spki_hash.clone(),reservation_hash:scope};
            Ok(Arc::new(input))
        }).await
    }
    pub(super) async fn activate_backend(&self,names:&[String],attempt_id:&str,job_id:&str,
        backend:attempt::BackendId,input:attempt::InputBinding,lease:&StorageLease)->Result<()> {
        lease.check().await?;
        let mut state=self.load_attempt(names).await?.ok_or_else(||anyhow!("certificate attempt missing"))?;
        ensure!(state.unified()&&state.attempt_id==attempt_id&&state.winner.is_none()
            &&state.backend_sequence.contains(&backend),"certificate attempt was superseded");
        if let Some(phase)=&state.acme_phase {
            ensure!(phase.step==acme_probe::PhaseStep::PendingPrimary&&phase.owner==backend&&phase.input==input,
                "active probe cannot become an unrelated primary");
            state.acme_phase=None;state._phase_memory=None;
        }
        state.current_job_id=Some(job_id.to_owned());state.current_backend=Some(backend);state.current_input=Some(input);
        self.save_attempt(state,lease).await
    }
    pub(super) async fn require_active_backend(&self,names:&[String],attempt_id:&str,job_id:&str,
        backend:&attempt::BackendId,input:&attempt::InputBinding,lease:&StorageLease)->Result<()> {
        lease.check().await?;
        let state=self.load_attempt(names).await?.ok_or_else(||anyhow!("certificate attempt missing"))?;
        ensure!(state.unified()&&state.attempt_id==attempt_id&&state.current_job_id.as_deref()==Some(job_id)
            &&state.current_backend.as_ref()==Some(backend)&&state.current_input.as_ref()==Some(input)
            &&state.winner.is_none(),"certificate attempt changed before commit");Ok(())
    }
    pub(super) async fn make_input(&self,attempt_id:&str,names:&[String],reuse:Option<&ReusableKey>,
        cancel:&CancellationToken,lease:&StorageLease)->Result<Arc<RuntimeInput>> {
        let cost=names.iter().try_fold(512*1024usize,|n,s|n.checked_add(s.len()*8+std::mem::size_of::<String>()*4)
            .ok_or(crate::cert_transient::ResourceDenied))?;
        let memory=Arc::new(crate::acme_wire::chain_memory::scratch(cost,cancel.clone()).await?);
        let names=names.to_vec();let reusable=reuse.map(|key|key.pem.clone());let attempt_id=attempt_id.to_owned();
        let input_id=format!("input-v2-{attempt_id}");let id=input_id.clone();
        let deny=self.inner.resolver.leaf_guard().key_deny().clone();let kind=self.inner.unified_key
            .ok_or_else(||anyhow!("unified certificate key policy missing"))?;let must_staple=self.inner.must_staple;
        let input=self.cpu(cancel,move||{
            let (csr,key,_state)=generate_csr_with_options(&names,kind,&deny,must_staple,reusable)?;
            let signer=crate::crypto::x509_signer::X509Signer::from_private_key(&key)?;
            use rcgen::PublicKeyData;
            let spki=signer.subject_public_key_info();
            let record=InputRecord{version:2,retired:false,attempt_id,names,csr_hash:digest(&csr),spki_hash:digest(&spki),
                csr_der:csr,spki_der:spki,private_key_pem:std::str::from_utf8(&key)?.to_owned()};
            Ok(Arc::new(RuntimeInput::validate(record,&id,memory,&deny)?))
        }).await?;
        self.save_input(&input_id,input.clone(),lease).await?;Ok(input)
    }
    async fn save_input(&self,id:&str,input:Arc<RuntimeInput>,lease:&StorageLease)->Result<()> {
        let lease_name=lease.name().to_owned();
        let encoded=self.cpu(&CancellationToken::new(),move||job_codec::encode_record(&input.record,&lease_name)).await?;
        self.inner.store.journal_store_encoded_fenced(id,encoded,lease).await
    }
    pub(super) async fn load_input(&self,id:&str,attempt_id:&str,cancel:&CancellationToken)->Result<Arc<RuntimeInput>> {
        let value=self.inner.store.journal_decode_admitted(id,move|raw|{
            let credit=Arc::new(job_codec::decode_credit(raw.len())?);
            let record:InputRecord=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid attempt input record"))?;
            record.validate()?;Ok((record,credit))
        }).await?.ok_or_else(||anyhow!("attempt input record missing"))?;
        ensure!(value.0.attempt_id==attempt_id,"attempt input belongs to another attempt");
        let deny=self.inner.resolver.leaf_guard().key_deny().clone();let id=id.to_owned();
        self.cpu(cancel,move||Ok(Arc::new(RuntimeInput::validate(value.0,&id,value.1,&deny)?))).await
    }
    /// Winner is durable first. Replacing the same journal atomically retires
    /// its secret; recovery repeats this step if interrupted after the CAS.
    pub(super) async fn retire_input(&self,state:&Attempt,lease:&StorageLease)->Result<()> {
        if !state.unified()||(state.winner.is_none()&&!state.retired){return Ok(())}
        if state.retired {self.expired_archive(state).await?;}
        let id=state.input_id.as_deref().ok_or_else(||anyhow!("winner input missing"))?;
        let value=self.inner.store.journal_decode_admitted(id,|raw|{
            let memory=job_codec::decode_credit(raw.len())?;
            let record:InputRecord=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid winner input"))?;
            record.validate()?;Ok((record,memory))
        }).await?.ok_or_else(||anyhow!("winner input journal missing"))?;
        ensure!(value.0.attempt_id==state.attempt_id,"winner input identity changed");
        if value.0.retired{return Ok(())}
        let name=lease.name().to_owned();
        let encoded=self.cpu(&CancellationToken::new(),move||{
            let (mut record,_memory)=value;
            record.private_key_pem.zeroize();record.private_key_pem.clear();
            record.csr_der.clear();record.spki_der.clear();record.retired=true;
            record.validate()?;job_codec::encode_record(&record,&name)
        }).await?;
        self.inner.store.journal_store_encoded_fenced(id,encoded,lease).await
    }
    pub(super) async fn save_attempt(&self,attempt:Attempt,lease:&StorageLease)->Result<()> {
        attempt.validate_protocol()?;
        let id=attempt_key(&attempt.names)?;let name=lease.name().to_owned();
        let encoded=self.cpu(&CancellationToken::new(),move||job_codec::encode_record(&attempt,&name)).await?;
        self.inner.store.journal_store_encoded_fenced(&id,encoded,lease).await
    }
    async fn save_internal(&self,id:&str,leg:InternalLeg,lease:&StorageLease)->Result<()> {
        leg.validate()?;let name=lease.name().to_owned();
        let encoded=self.cpu(&CancellationToken::new(),move||job_codec::encode_record(&leg,&name)).await?;
        self.inner.store.journal_store_encoded_fenced(id,encoded,lease).await
    }
    async fn load_internal(&self,id:&str)->Result<Option<InternalLeg>> {
        self.inner.store.journal_decode_admitted(id,|raw|{
            let memory=Arc::new(job_codec::decode_credit(raw.len())?);
            let mut leg:InternalLeg=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid internal leg record"))?;
            leg.validate()?;leg._memory=Some(memory);Ok(leg)
        }).await
    }
    pub(super) async fn issue_internal(&self,names:&[String],backend:&backend::Backend,
        input:Arc<RuntimeInput>,attempt_id:&str,lease:&StorageLease,
        lifecycle:&crate::cert_events::Attempt,cancel:&CancellationToken,report_obtained:bool,
        produced:Option<&std::sync::atomic::AtomicBool>)->Result<ManagedCertificate> {
        let backend::BackendKind::Internal{pki,ca,options}=&backend.kind else{bail!("not an internal issuer")};
        let attempt::BackendId::Internal{options_identity,..}=&backend.id else{bail!("internal backend identity mismatch")};
        let id=digest(format!("internal-v2\0{attempt_id}\0{}\0{options_identity}",backend.storage_key).as_bytes());
        let key=names_key(names)?;
        self.inner.store.recover_certificate_with_lease(ca,&key,lease).await?;
        let mut leg=match self.load_internal(&id).await? {
            Some(leg)=>{ensure!(leg.attempt_id==attempt_id&&leg.names==names&&leg.backend==backend.id
                &&leg.input==input.binding,"internal leg identity changed");leg},
            None=>{
                let initial_hash=self.initial_key(ca,&key,cancel).await?.map(|(snapshot,_)|snapshot.digest().to_owned());
                InternalLeg{version:2,attempt_id:attempt_id.to_owned(),names:names.to_vec(),backend:backend.id.clone(),
                    input:input.binding.clone(),phase:"prepared".to_owned(),downloaded_pem:None,
                    stored_leaf_sha256:None,initial_key_hash:initial_hash,_memory:None}
            },
        };
        self.activate_backend(names,attempt_id,&id,backend.id.clone(),input.binding.clone(),lease).await?;
        if leg.phase=="prepared" {
            pki.provision(ca,cancel.clone()).await?;
            self.save_internal(&id,leg,lease).await?;
            let credits=Arc::new(Credits{_input:input.clone(),slots:std::sync::Mutex::new(std::array::from_fn(|_|None)),
                _shell:crate::cert_transient::reserve(std::mem::size_of::<Credits>()+64)?});
            let csr=crate::cert_cpu::RetainedBytes::copy(&input.record.csr_der,credits)?;
            let chain=pki.issue_retained(ca,csr,options.clone(),cancel.clone()).await?;
            // This concrete signer validated the CSR and produced its signed
            // result. Buffer/checkpoint/assets failures after it are not a new
            // issuer failure event, and never permission to try another CA.
            if let Some(produced)=produced{produced.store(true,Ordering::Release);}
            let pem=Arc::new(crate::acme_wire::chain_memory::Buffer::assemble(&self.inner.chain_memory.payload,&[chain.as_bytes()])?);
            leg=self.load_internal(&id).await?.ok_or_else(||anyhow!("internal prepared leg disappeared"))?;
            leg.downloaded_pem=Some(pem);leg.phase="issued".to_owned();
            self.save_internal(&id,leg,lease).await?;
            leg=self.load_internal(&id).await?.ok_or_else(||anyhow!("internal issued leg disappeared"))?;
        }
        // A completed store is recovered by exact fingerprint before any signer.
        if let Some(expected)=leg.stored_leaf_sha256.as_deref()
            && let Some(bundle)=self.read_issuer_certificate(ca,&key,cancel).await? {
            let info=self.inspect_material(&bundle,names,cancel).await?;
            if info.leaf_sha256==expected {
                ensure!(info.spki_der.as_ref()==input.record.spki_der,"stored internal candidate public key changed");
                self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;
                stored_candidate_time(&info)?;
                ensure!(self.claim_winner(names,attempt_id,&id,ca,expected,lease).await?,"internal attempt lost publication CAS");
                return Ok(ManagedCertificate{names:names.to_vec(),issuer_key:ca.clone(),not_after_unix:info.not_after,
                    renew_at_unix:backend.renewal(&info,self.inner.options.renewal_window_ratio,None,self.inner.options.poll_interval)?,
                    leaf_sha256:info.leaf_sha256,obtained:false})
            }
        }
        let chain=leg.downloaded_pem.as_ref().ok_or_else(||anyhow!("internal leg lost signed candidate"))?;
        let mut bundle=DownloadedBundle::new(chain.as_slice(),input.record.private_key_pem.as_bytes(),&input.record.names,None,ca,"")?;
        if let Some(meta)=bundle.bundle.metadata.get_mut("issuer_data").and_then(Value::as_object_mut){meta.remove("url");meta.remove("account");}
        let info=self.inspect_material(&bundle,names,cancel).await?;
        ensure!(info.spki_der.as_ref()==input.record.spki_der,"internal issuer returned a different public key");
        self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;
        stored_candidate_time(&info)?;
        leg.phase="store_intent".to_owned();leg.stored_leaf_sha256=Some(info.leaf_sha256.clone());
        let initial_hash=leg.initial_key_hash.clone();self.save_internal(&id,leg,lease).await?;
        self.require_active_backend(names,attempt_id,&id,&backend.id,&input.binding,lease).await?;
        self.save_issued_certificate(ca,&key,&bundle,lease,initial_hash.as_deref()).await?;
        ensure!(self.claim_winner(names,attempt_id,&id,ca,&info.leaf_sha256,lease).await?,"internal attempt lost publication CAS");
        if report_obtained {lifecycle.obtained(self.inner.lifecycle_events.as_ref(),ca,names,&input.record.csr_der,cancel).await;}
        let mut leg=self.load_internal(&id).await?.ok_or_else(||anyhow!("internal stored leg disappeared"))?;
        leg.phase="stored".to_owned();leg.downloaded_pem=None;self.save_internal(&id,leg,lease).await?;
        Ok(ManagedCertificate{names:names.to_vec(),issuer_key:ca.clone(),not_after_unix:info.not_after,
            renew_at_unix:backend.renewal(&info,self.inner.options.renewal_window_ratio,None,self.inner.options.poll_interval)?,
            leaf_sha256:info.leaf_sha256,obtained:true})
    }
    pub(super) async fn recover_unified(&self,names:&[String],state:&Attempt,lease:&StorageLease,
        cancel:&CancellationToken)->Result<()> {
        state.validate_protocol()?;
        if state.acme_phase.is_some() {
            return self.recover_test_ca_phase(names,state,lease,cancel).await;
        }
        if state.winner.is_some(){return Ok(())}
        let Some(id)=state.current_job_id.as_deref()else{return Ok(())};
        let Some(selected)=state.current_backend.as_ref()else{return Ok(())};
        let backend=self.inner.backends.iter().find(|b|&b.id==selected)
            .ok_or_else(||anyhow!("active certificate backend changed; resume original policy"))?;
        match &backend.kind {
            backend::BackendKind::Internal{..}=>{
                let leg=self.load_internal(id).await?.ok_or_else(||anyhow!("active internal leg missing"))?;
                ensure!(leg.attempt_id==state.attempt_id&&leg.names==names&&&leg.backend==selected
                    &&state.current_input.as_ref()==Some(&leg.input),"active internal leg identity changed");
                if leg.phase=="prepared" {return Ok(())}
                let input_id=state.input_id.as_deref().ok_or_else(||anyhow!("internal attempt input missing"))?;
                let input=self.load_input(input_id,&state.attempt_id,cancel).await?;
                let lifecycle=crate::cert_events::Attempt::new(&names[0],None);
                self.issue_internal(names,backend,input,&state.attempt_id,lease,&lifecycle,cancel,false,None).await?;
            },
            backend::BackendKind::Acme(index)=>{
                let issuer=&self.inner.issuers[*index];
                // Verify the durable attempt input before old recovery code is
                // allowed to mutate certificate storage or claim publication.
                let input_id=state.input_id.as_deref().ok_or_else(||anyhow!("active ACME input missing"))?;
                let shared=self.load_input(input_id,&state.attempt_id,cancel).await?;
                let marker_id=reservation_id(names,&issuer.config.wire.directory)?;
                let (marker,_marker_memory)=self.inner.store.journal_decode_admitted(&marker_id,|raw|{
                    let memory=job_codec::decode_credit(raw.len())?;
                    let marker:Reservation=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid active ACME reservation"))?;
                    Ok((marker,memory))
                }).await?.ok_or_else(||anyhow!("active ACME reservation missing"))?;
                ensure!(marker.job_id==id,"active ACME reservation changed");
                let job=self.load_job(id).await?.ok_or_else(||anyhow!("active ACME job missing"))?;
                ensure!(marker.version==1&&marker.names==names&&marker.directory==issuer.config.wire.directory,
                    "active ACME reservation scope changed");
                validate_reservation_job(&marker,&job)?;
                let binding=state.current_input.as_ref().ok_or_else(||anyhow!("active ACME input binding missing"))?;
                if job.phase!="stored" {
                    let input=self.input_for_job(&marker,&state.attempt_id,shared.clone(),cancel).await?;
                    ensure!(binding==&input.binding,"active ACME input binding changed");
                }else{match binding {
                    attempt::InputBinding::Shared{..}=>ensure!(binding==&shared.binding&&job.attempt_id==state.attempt_id,
                        "stored shared ACME input identity changed"),
                    attempt::InputBinding::LegacyJob{job_id,original_attempt_id,..}=>ensure!(job_id==id&&original_attempt_id==&job.attempt_id,
                        "stored legacy ACME input identity changed"),
                }}
                // A native asset transaction is recovered only after the input
                // CSR/key scope above is verified. Neither old recovery CAS nor
                // publication can precede the actual stored SPKI check.
                self.inner.store.recover_certificate_with_lease(&backend.storage_key,&names_key(names)?,lease).await?;
                if let Some(expected)=job.stored_leaf_sha256.as_deref() {
                    let bundle=self.read_issuer_certificate(&backend.storage_key,&names_key(names)?,cancel).await?;
                    if let Some(bundle)=bundle {
                        let info=self.inspect_material(&bundle,names,cancel).await?;
                        if info.leaf_sha256==expected {
                            let expected_spki=match binding {attempt::InputBinding::Shared{spki_hash,..}|attempt::InputBinding::LegacyJob{spki_hash,..}=>spki_hash};
                            let job=SpkiHash{spki:info.spki_der.clone(),_key:info._key_state.clone(),_input:shared.clone()};
                            let actual=self.cpu(cancel,move||Ok(job.execute())).await?;
                            ensure!(&actual==expected_spki,"stored ACME candidate differs from bound input public key");
                            self.inner.resolver.leaf_guard().key_deny().check_state(&info._key_state)?;
                            stored_candidate_time(&info)?;
                        }else{ensure!(job.phase!="stored","stored ACME candidate fingerprint changed")}
                    }else{ensure!(job.phase!="stored","stored ACME candidate assets missing")}
                }else{ensure!(job.phase!="stored","stored ACME candidate fingerprint missing")}
                self.recover_candidate(names,issuer,lease,cancel).await?;
                // A legacy order keeps its original attempt_id. The adapter
                // can claim THIS attempt only from its exact stored fingerprint
                // and registered SPKI, never by retagging the old order.
                if let Some(attempt::InputBinding::LegacyJob{spki_hash,..})=&state.current_input {
                    let job=self.load_job(id).await?.ok_or_else(||anyhow!("legacy active job disappeared"))?;
                    if job.phase=="stored"&&let Some(expected)=job.stored_leaf_sha256.as_deref()
                        &&let Some(bundle)=self.read_issuer_certificate(&backend.storage_key,&names_key(names)?,cancel).await? {
                        let info=self.inspect_material(&bundle,names,cancel).await?;
                        ensure!(&info.leaf_sha256==expected&&digest(&info.spki_der)==*spki_hash,
                            "legacy stored input fingerprint changed");
                        let deny=self.inner.resolver.leaf_guard().key_deny().clone();
                        deny.check_state(&info._key_state)?;
                        stored_candidate_time(&info)?;
                        ensure!(self.claim_winner(names,&state.attempt_id,id,&backend.storage_key,expected,lease).await?,
                            "legacy candidate lost publication CAS");
                    }
                }
            },
        }
        Ok(())
    }
}

impl CertificateManager {
    async fn expired_archive(&self,state:&Attempt)->Result<()> {
        ensure!(state.retired&&state.winner.is_none()&&state.current_job_id.is_none()
            &&state.current_backend.is_none()&&state.current_input.is_none(),"invalid retired attempt pointer");
        let id=format!("expired-input-attempt-v{}-{}",state.version,state.attempt_id);
        let expected_names=state.names.clone();let expected_id=state.attempt_id.clone();let input=state.input_id.clone();
        self.inner.store.journal_decode_admitted(&id,move|raw|{
            let _memory=job_codec::decode_credit(raw.len())?;
            let old:Attempt=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid expired attempt archive"))?;
            ensure!(!old.retired&&old.winner.is_none()&&old.names==expected_names&&old.attempt_id==expected_id
                &&old.input_id==input&&old.current_job_id.is_some(),"expired attempt archive binding changed");
            ensure!(old.version==1||(old.unified()&&old.current_backend.is_some()&&old.current_input.is_some()),
                "expired archive has no original leg binding");
            Ok(())
        }).await?.ok_or_else(||anyhow!("expired attempt archive missing"))
    }
    /// Archive first, then fence the old reservation and publish a retired
    /// attempt pointer. Crash recovery repeats these idempotent writes. No old
    /// order URL/CSR/private key is rewritten into a fresh order identity.
    pub(super) async fn retire_expired_attempt(&self,names:&[String],expected:&Attempt,
        lease:&StorageLease,cancel:&CancellationToken)->Result<()> {
        lease.check().await?;
        let state=self.load_attempt(names).await?.ok_or_else(||anyhow!("expired attempt missing"))?;
        ensure!(state.attempt_id==expected.attempt_id&&state.winner.is_none(),"expired attempt changed");
        if state.retired {return self.retire_input(&state,lease).await}
        let id=state.current_job_id.as_deref().ok_or_else(||anyhow!("expired attempt job missing"))?;
        let internal=matches!(state.current_backend,Some(attempt::BackendId::Internal{..}));
        let (expected_leaf,storage_key)=if internal {
            let leg=self.load_internal(id).await?.ok_or_else(||anyhow!("expired internal leg missing"))?;
            ensure!(leg.attempt_id==state.attempt_id&&leg.names==names
                &&Some(&leg.backend)==state.current_backend.as_ref()
                &&Some(&leg.input)==state.current_input.as_ref(),"expired internal binding changed");
            let attempt::BackendId::Internal{ca,..}=&leg.backend else{bail!("expired internal kind changed")};
            (leg.stored_leaf_sha256,ca.clone())
        }else{
            let job=self.load_job(id).await?.ok_or_else(||anyhow!("expired ACME job missing"))?;
            ensure!(job.names==names,"expired ACME subject changed");
            (job.stored_leaf_sha256.clone(),issuer_key(&job.directory)?)
        };
        // A signed candidate in a journal is not evidence that the asset
        // transaction committed. Preserve an older base unless an actual
        // settled asset matches this candidate's hash, SPKI and current denial
        // state. Never manufacture Replacement from a downloaded candidate.
        self.inner.store.recover_certificate_with_lease(&storage_key,&names_key(names)?,lease).await?;
        let mut materialized=None;
        if let Some(expected_leaf)=expected_leaf
            &&let Some(bundle)=self.read_issuer_certificate(&storage_key,&names_key(names)?,cancel).await? {
            let info=self.inspect_material(&bundle,names,cancel).await?;
            if info.leaf_sha256==expected_leaf {
                self.inner.resolver.leaf_guard().key_deny().check_state(&info._key_state)?;
                ensure!(info.not_after<=now(),"retiring certificate is not expired");
                if let Some(binding)=&state.current_input {
                    let expected=match binding {attempt::InputBinding::Shared{spki_hash,..}|attempt::InputBinding::LegacyJob{spki_hash,..}=>spki_hash};
                    let actual=self.cpu(cancel,move||Ok(digest(&info.spki_der))).await?;
                    ensure!(&actual==expected,"expired stored candidate input SPKI changed");
                }
                materialized=Some(expected_leaf);
            }
        }
        let archive=format!("expired-input-attempt-v{}-{}",state.version,state.attempt_id);
        let name=lease.name().to_owned();
        let encoded=self.cpu(cancel,move||job_codec::encode_record(&state,&name)).await?;
        self.inner.store.journal_store_encoded_fenced(&archive,encoded,lease).await?;
        if !internal {self.abandon_leg(names,&expected.attempt_id,lease).await?;}
        let mut state=self.load_attempt(names).await?.ok_or_else(||anyhow!("expired attempt disappeared"))?;
        ensure!(state.attempt_id==expected.attempt_id&&state.winner.is_none(),"expired attempt superseded");
        if let Some(leaf)=materialized {
            state.base_leaf=Some(leaf);state.base_backend=state.current_backend.take();
        }else{state.current_backend=None;}
        state.current_job_id=None;state.current_input=None;state.retired=true;
        self.save_attempt(state,lease).await?;
        let state=self.load_attempt(names).await?.ok_or_else(||anyhow!("retired attempt disappeared"))?;
        self.retire_input(&state,lease).await
    }
}
