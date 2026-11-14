//! Backend-local test-CA phase. Completed probe material is retained only in its
//! private journal; production commit remains exclusively in acme_candidate.
use super::*;
use super::{acme_probe::{PhaseBinding,PhaseStep,ProbeJobRecord},attempt::{BackendId,RuntimeInput}};
pub(super) struct OwnedPhase {pub binding:PhaseBinding,_memory:crate::acme_wire::chain_memory::Scratch}
fn backend_fields(id:&BackendId)->Result<(&str,&str)>{match id{BackendId::Acme{directory,config_identity}=>Ok((directory,config_identity)),_=>bail!("test CA backend kind changed")}}
fn phase_cost(owner:&BackendId,endpoint:&BackendId,input:&attempt::InputBinding)->Result<usize>{
    let(a,b)=backend_fields(owner)?;let(c,d)=backend_fields(endpoint)?;
    let attempt::InputBinding::Shared{input_id,csr_hash,spki_hash}=input else{bail!("legacy known input cannot become probe")};
    [a.len(),b.len(),c.len(),d.len(),input_id.len(),csr_hash.len(),spki_hash.len(),std::mem::size_of::<OwnedPhase>()+4096]
        .into_iter().try_fold(0usize,|n,v|n.checked_add(v).ok_or_else(||crate::cert_transient::ResourceDenied.into()))
}
pub(super) fn probe_id(attempt_id:&str,index:u8,operation:&str,names:&[String],owner:&BackendId,endpoint:&BackendId,input:&attempt::InputBinding,policy:&str)->Result<String>{
    let mut hash=Sha256::new();hash.update(b"acme-probe-job-v1");hash.update([index]);
    fn frame(h:&mut Sha256,bytes:&[u8]){h.update((bytes.len()as u64).to_be_bytes());h.update(bytes)}
    let(a,b)=backend_fields(owner)?;let(c,d)=backend_fields(endpoint)?;
    let attempt::InputBinding::Shared{input_id,csr_hash,spki_hash}=input else{bail!("legacy known input cannot become probe")};
    for text in [attempt_id,operation,a,b,c,d,input_id,csr_hash,spki_hash,policy]{frame(&mut hash,text.as_bytes())}
    for name in names{frame(&mut hash,name.as_bytes())}
    Ok(format!("acme-probe-v1-job-{:x}",hash.finalize()))
}
impl CertificateManager {
    pub(super) fn new_probe_phase(&self,index:usize,names:&[String],attempt_id:&str,input:&RuntimeInput,operation:&[u8;32])->Result<OwnedPhase>{
        let Some(super::test_ca::TestPolicy::Separate(test))=self.inner.test_policies.get(index)else{bail!("test CA phase not configured")};
        let owner=self.inner.backends.iter().find(|b|matches!(b.kind,backend::BackendKind::Acme(i)if i==index))
            .ok_or_else(||anyhow!("test CA production identity missing"))?;
        let memory=crate::cert_transient::reserve(phase_cost(&owner.id,&test.id,&input.binding)?)?;
        let mut operation_id=String::with_capacity(64);
        use std::fmt::Write as _;
        for byte in operation {write!(&mut operation_id,"{byte:02x}")?;}
        let binding=PhaseBinding{version:1,owner_acme_index:u8::try_from(index)?,owner:owner.id.clone(),endpoint:test.id.clone(),
            input:input.binding.clone(),test_policy:test.policy.clone(),step:PhaseStep::Probe,
            probe_job_id:probe_id(attempt_id,u8::try_from(index)?,&operation_id,names,&owner.id,&test.id,&input.binding,&test.policy)?,operation_id};
        binding.validate()?;Ok(OwnedPhase{binding,_memory:memory})
    }
    pub(super) async fn verify_probe_receipt(&self,names:&[String],attempt_id:&str,input:&Arc<RuntimeInput>,
        binding:&PhaseBinding,record:&ProbeJobRecord,cancel:&CancellationToken)->Result<()> {
        binding.validate()?;record.validate()?;let probe=&record.binding;
        ensure!(probe.step==PhaseStep::Probe&&record.job.phase=="probe_validated"
            &&probe.owner==binding.owner&&probe.input==binding.input&&probe.owner_acme_index==binding.owner_acme_index
            &&probe.test_policy==binding.test_policy&&probe.operation_id==binding.operation_id&&probe.probe_job_id==binding.probe_job_id,
            "probe receipt phase identity changed");
        ensure!(probe.probe_job_id==probe_id(attempt_id,probe.owner_acme_index,&probe.operation_id,names,&probe.owner,&probe.endpoint,&probe.input,&probe.test_policy)?,"probe receipt namespace identity changed");
        ensure!(record.job.names==names&&record.job.attempt_id==attempt_id&&input.binding==binding.input
            &&digest(&record.job.csr_der)==input.record.csr_hash&&record.job.csr_der==input.record.csr_der
            &&record.job.renewal_names.as_ref().unwrap_or(&record.job.names)==&input.record.names,
            "probe receipt CSR/subject binding changed");
        self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)?;
        let chain=record.job.downloaded_pem.as_ref().ok_or_else(||anyhow!("probe validation receipt lost downloaded material"))?;
        let bundle=DownloadedBundle::new(chain.as_slice(),input.record.private_key_pem.as_bytes(),&input.record.names,
            record.job.certificate_url.as_deref(),&record.job.directory,&record.job.account_location)?;
        let facts=self.inspect_material(&bundle,names,cancel).await?;
        ensure!(facts.spki_der.as_ref()==input.record.spki_der.as_slice()
            &&record.validated_leaf.as_deref()==Some(facts.leaf_sha256.as_str()),"probe receipt key/leaf binding changed");
        let validated_at=record.validated_at.ok_or_else(||anyhow!("probe receipt validation time missing"))?;
        ensure!(facts.not_before<=validated_at&&validated_at<facts.not_after&&validated_at<=now(),"probe receipt historical validation time changed");
        // This is historical completion evidence, never material eligible for
        // serving. Natural expiry after completion does not rerun a probe or
        // publish its leaf; key-veto is rechecked at the current instant.
        self.inner.resolver.leaf_guard().key_deny().check_spki_der(&facts.spki_der)?;
        self.verify_probe_signature_links(chain.clone(),cancel).await?;
        self.inner.resolver.leaf_guard().key_deny().check_state(&input.key_state)
    }
    pub(super) async fn verify_probe_signature_links(&self,chain:Arc<crate::acme_wire::chain_memory::Buffer>,cancel:&CancellationToken)->Result<()> {
        let bytes=chain.len().checked_mul(8).and_then(|n|n.checked_add(65536)).ok_or(crate::cert_transient::ResourceDenied)?;
        let credit=crate::cert_transient::reserve(bytes)?;
        struct Input{chain:Arc<crate::acme_wire::chain_memory::Buffer>,_credit:crate::acme_wire::chain_memory::Scratch}
        let input=Input{chain,_credit:credit};
        self.cpu(cancel,move||{
            let input=input;let blocks=crate::cert_transient::certificate_blocks(input.chain.as_slice())?;
            ensure!(!blocks.is_empty(),"probe chain is empty");
            for pair in blocks.windows(2){
                let(_,child)=crate::cert_transient::parse_certificate(&pair[0].1)?;
                let(_,issuer)=crate::cert_transient::parse_certificate(&pair[1].1)?;
                ensure!(child.issuer()==issuer.subject(),"probe chain issuer order changed");
                crate::cert_status::verify_x509_signature(issuer.public_key(),&child.signature_algorithm,
                    &child.signature_value.data,child.tbs_certificate.as_ref(),true)?;
            }
            // A missing issuer/anchor is not invented. Provided links are
            // checked; this does not claim system trust or a new PKIX policy.
            Ok(())
        }).await
    }
    pub(super) async fn complete_probe(&self,names:&[String],attempt_id:&str,binding:&PhaseBinding,
        lease:&StorageLease,candidate:acme_candidate::AcmeCandidate)->Result<()> {
        ensure!(candidate.purpose()==acme_candidate::AcmePurpose::Probe,"primary candidate cannot be discarded as a probe");
        let mut candidate=candidate;
        let acme_candidate::AcmeCandidate::Downloaded{job,id,info,..}=&mut candidate else{bail!("probe cannot contain stored production assets")};
        let info=info.as_ref().ok_or_else(||anyhow!("probe candidate facts missing"))?;
        ensure!(id==&binding.probe_job_id&&job.names==names&&job.attempt_id==attempt_id,"probe candidate identity changed");
        self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der)?;
        let validated_at=now();
        ensure!(info.not_before<=validated_at&&validated_at<info.not_after,"probe completion is outside its leaf validity");
        // The candidate owns real bundle/proofs/CSR input until the durable
        // private receipt and pending-primary transition have completed.
        job.phase="probe_validated".to_owned();job.private_key_pem.zeroize();job.private_key_pem.clear();
        self.save_probe_job(id,binding,job,Some((&info.leaf_sha256,validated_at)),lease).await?;
        self.save_probe_reservation(binding,job,lease).await?;
        self.inner.resolver.leaf_guard().key_deny().check_spki_der(&info.spki_der)?;
        self.pending_primary(names,attempt_id,binding,lease).await
    }
    pub(super) async fn pending_primary(&self,names:&[String],attempt_id:&str,binding:&PhaseBinding,lease:&StorageLease)->Result<()> {
        lease.check().await?;let mut state=self.load_attempt(names).await?.ok_or_else(||anyhow!("probe attempt missing"))?;
        ensure!(state.attempt_id==attempt_id&&state.winner.is_none()&&state.acme_phase.as_ref()==Some(binding)
            &&state.current_job_id.as_deref()==Some(binding.probe_job_id.as_str()),"probe completion lost phase CAS");
        let memory=crate::cert_transient::reserve(phase_cost(&binding.owner,&binding.owner,&binding.input)?
            .checked_add(binding.copy_cost()?).ok_or(crate::cert_transient::ResourceDenied)?)?;
        let mut pending=binding.clone();pending.step=PhaseStep::PendingPrimary;pending.endpoint=pending.owner.clone();
        state.acme_phase=Some(pending);state.current_job_id=None;state._phase_memory=Some(memory);
        self.save_attempt(state,lease).await
    }
}


impl CertificateManager {
    pub(super) async fn recover_test_ca_phase(&self,names:&[String],state:&Attempt,lease:&StorageLease,cancel:&CancellationToken)->Result<()> {
        state.validate_protocol()?;let phase=state.acme_phase.as_ref().ok_or_else(||anyhow!("test CA recovery phase missing"))?;
        let backend=self.inner.backends.iter().find(|backend|backend.id==phase.owner)
            .ok_or_else(||anyhow!("active test CA production backend changed"))?;
        ensure!(matches!(backend.kind,backend::BackendKind::Acme(index)if index==usize::from(phase.owner_acme_index)),"active test CA owner index changed");
        let input=self.load_input(state.input_id.as_deref().ok_or_else(||anyhow!("active test CA input missing"))?,&state.attempt_id,cancel).await?;
        ensure!(input.binding==phase.input,"active test CA input binding changed");
        if phase.step==PhaseStep::Probe {
            let Some(super::test_ca::TestPolicy::Separate(test))=self.inner.test_policies.get(usize::from(phase.owner_acme_index))else{bail!("active probe original policy missing")};
            self.validate_probe_binding(&test.state,phase)?;
        }
        let record=self.load_probe_job(&phase.probe_job_id).await?.ok_or_else(||anyhow!("active probe checkpoint missing"))?;
        ensure!(record.job.names==names&&record.job.attempt_id==state.attempt_id,"probe recovery name/attempt changed");
        let marker=self.load_probe_reservation(&record.binding).await?.ok_or_else(||anyhow!("active probe reservation missing"))?;
        let current=marker.matches_job(&record.job)?;
        if phase.step==PhaseStep::PendingPrimary {
            ensure!(!record.job.abandoned,"pending primary retained a retired probe");
            self.verify_probe_receipt(names,&state.attempt_id,&input,phase,&record,cancel).await?;
            if !current{self.save_probe_reservation(&record.binding,&record.job,lease).await?;}
            return Ok(())
        }
        ensure!(&record.binding==phase,"active probe checkpoint binding changed");
        if record.job.abandoned {
            return self.abandon_probe_phase(names,&state.attempt_id,lease).await
        }
        if record.job.phase=="probe_validated" {
            self.verify_probe_receipt(names,&state.attempt_id,&input,phase,&record,cancel).await?;
            if !current{self.save_probe_reservation(phase,&record.job,lease).await?;}
            return self.pending_primary(names,&state.attempt_id,phase,lease).await
        }
        ensure!(record.job.csr_der==input.record.csr_der
            &&record.job.private_key_pem.as_bytes()==input.record.private_key_pem.as_bytes(),"active probe restored input changed");
        self.validate_probe_renewal_scope(&record.job,phase).await?;
        if !current{self.save_probe_reservation(phase,&record.job,lease).await?;}
        // An unvalidated probe remains private and resumes only through the
        // backend-local protocol driver, never ordinary stored promotion.
        Ok(())
    }
    pub(super) async fn abandon_probe_phase(&self,names:&[String],attempt_id:&str,lease:&StorageLease)->Result<()> {
        lease.check().await?;let mut state=self.load_attempt(names).await?.ok_or_else(||anyhow!("retiring probe attempt missing"))?;
        ensure!(state.attempt_id==attempt_id&&state.winner.is_none(),"retiring probe attempt superseded");
        let phase=state.acme_phase.as_ref().ok_or_else(||anyhow!("retiring probe phase missing"))?;
        let mut record=self.load_probe_job(&phase.probe_job_id).await?.ok_or_else(||anyhow!("retiring probe checkpoint missing"))?;
        let marker=self.load_probe_reservation(&record.binding).await?.ok_or_else(||anyhow!("retiring probe reservation missing"))?;
        marker.matches_job(&record.job)?;
        if phase.step==PhaseStep::Probe {
            ensure!(record.binding==*phase&&record.job.phase!="probe_validated","completed probe requires pending-primary recovery");
            record.job.abandoned=true;
            self.save_probe_job(&phase.probe_job_id,&record.binding,&record.job,None,lease).await?;
            self.save_probe_reservation(&record.binding,&record.job,lease).await?;
        }else{
            let input=self.load_input(state.input_id.as_deref().ok_or_else(||anyhow!("retiring pending primary input missing"))?,attempt_id,&CancellationToken::new()).await?;
            self.verify_probe_receipt(names,attempt_id,&input,phase,&record,&CancellationToken::new()).await?;
        }
        state.acme_phase=None;state.current_job_id=None;state.current_backend=None;state.current_input=None;
        state._phase_memory=None;self.save_attempt(state,lease).await
    }
}

/// A closed no-IO disposition: this exact operation/leg was already retired.
/// The unified caller may continue other backends without reactivating it.
#[derive(Debug)]pub(super) struct RetiredProbe;
impl std::fmt::Display for RetiredProbe{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("probe leg already retired in this issuance operation")}}
impl std::error::Error for RetiredProbe{}
#[derive(Debug)]pub(super) struct TestEndpoint;
impl std::fmt::Display for TestEndpoint{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("test CA protocol phase failed")}}
impl std::error::Error for TestEndpoint{}
impl CertificateManager {
    pub(super) fn uses_test_driver(&self,index:usize,state:&Attempt)->bool{
        matches!(self.inner.test_policies.get(index),Some(super::test_ca::TestPolicy::Separate(_)))
            ||state.acme_phase.as_ref().is_some_and(|phase|usize::from(phase.owner_acme_index)==index)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn issue_test_ca_leg(&self,index:usize,names:&[String],attempt_id:&str,input:&Arc<RuntimeInput>,
        replacement:Option<&Replacement>,lease:&StorageLease,lifecycle:&crate::cert_events::Attempt,
        cancel:&CancellationToken,round:retry_operation::AcmeRound<'_>,produced:&std::sync::atomic::AtomicBool)->Result<ManagedCertificate>{
        let primary=self.inner.issuers.get(index).ok_or_else(||anyhow!("test CA production index missing"))?;
        let state=self.load_attempt(names).await?.ok_or_else(||anyhow!("test CA attempt missing"))?;
        ensure!(state.attempt_id==attempt_id&&state.winner.is_none(),"test CA attempt superseded");
        let owner=self.issuer_identity(primary)?;
        let current=self.read_reservation(names,primary).await?;
        let mut after_probe=false;
        if let Some(phase)=&state.acme_phase {
            ensure!(&phase.owner==owner&&usize::from(phase.owner_acme_index)==index&&phase.input==input.binding,"active test CA owner/input changed");
            if phase.step==PhaseStep::PendingPrimary {
                let record=self.load_probe_job(&phase.probe_job_id).await?.ok_or_else(||anyhow!("pending primary proof missing"))?;
                self.verify_probe_receipt(names,attempt_id,input,phase,&record,cancel).await?;
                after_probe=true;
            }
        }
        // Existing actual primary orders (including uncertain newOrder intent)
        // retain their old account/CSR/parameters instead of switching to test.
        let should_probe=!after_probe&&current.is_none()&&round.ordinal>0;
        if state.acme_phase.as_ref().is_some_and(|phase|phase.step==PhaseStep::Probe)||should_probe {
            let Some(super::test_ca::TestPolicy::Separate(test))=self.inner.test_policies.get(index)else{bail!("active test CA policy missing")};
            let fresh;
            let binding=if let Some(phase)=&state.acme_phase {phase}else{
                fresh=self.new_probe_phase(index,names,attempt_id,input,&round.operation_id.ok_or_else(||anyhow!("probe retry operation identity missing"))?)?;
                &fresh.binding
            };
            self.validate_probe_binding(&test.state,binding)?;
            let old=self.load_probe_job(&binding.probe_job_id).await?;
            if let Some(record)=&old {
                ensure!(&record.binding==binding,"probe checkpoint belongs to another operation");
                let marker=self.load_probe_reservation(binding).await?.ok_or_else(||anyhow!("probe reservation missing"))?;
                marker.matches_job(&record.job)?;
                if record.job.abandoned{return Err(RetiredProbe.into())}
                if record.job.phase=="probe_validated" {
                    // Reattach only this exact already-completed probe. It is
                    // never a current-order replacement or a new random ID.
                    if state.acme_phase.is_none(){self.activate_probe(names,attempt_id,binding,lease).await?;}
                    self.verify_probe_receipt(names,attempt_id,input,binding,record,cancel).await?;
                    self.pending_primary(names,attempt_id,binding,lease).await?;
                    after_probe=true;
                }
            }
            if !after_probe {
                let result=async {
                    let issuer=&test.state;
                    let _network=self.net_permit(issuer,cancel).await?;
                    let allowed=issuer.ca.next_allowed_unix.load(Ordering::Acquire);
                    if allowed>now(){return Err(RetryAfterError(allowed).into())}
                    let wire=issuer.wire.get_or_try_init(||async{
                        AcmeWire::connect_with_client_tls_scope(issuer.config.wire.clone(),self.inner.local.clone(),self.inner.chain_memory.clone(),
                            #[cfg(feature="native-run")] self.inner.outgoing_tls.clone(),self.wire_client_owner_for(issuer),cancel).await
                    }).await?;
                    let session=self.account(issuer,wire,old.as_ref().map(|record|record.job.account_location.as_str()),cancel).await?;
                    let candidate=self.issue_candidate(names,issuer,&session,lease,(replacement,None,attempt_id),None,cancel,Some(input),
                        acme_journal::AcmeJournal::Probe(binding)).await?;
                    self.complete_probe(names,attempt_id,binding,lease,candidate).await
                }.await;
                if let Err(error)=result{record_issuer_error(&test.state,&error);return Err(error.context(TestEndpoint))}
                after_probe=true;
            }
        }
        let result=async{
            let _network=self.net_permit(primary,cancel).await?;
            let allowed=primary.ca.next_allowed_unix.load(Ordering::Acquire);
            if allowed>now(){return Err(RetryAfterError(allowed).into())}
            let wire=primary.wire.get_or_try_init(||async{
                AcmeWire::connect_with_client_tls_scope(primary.config.wire.clone(),self.inner.local.clone(),self.inner.chain_memory.clone(),
                    #[cfg(feature="native-run")] self.inner.outgoing_tls.clone(),self.wire_client_owner_for(primary),cancel).await
            }).await?;
            let current=self.read_reservation(names,primary).await?;
            let session=self.account(primary,wire,current.as_ref().map(|marker|marker.account_location.as_str()),cancel).await?;
            let current=if let Some(marker)=current {
                if self.retire_compromised_job(&marker,lease,cancel).await?{None}else{Some(marker)}
            }else{None};
            let leg_input=if let Some(marker)=&current{self.input_for_job(marker,attempt_id,input.clone(),cancel).await?}else{input.clone()};
            // PendingPrimary always records the original separate-test decision:
            // effective0 and usingTest=false, even if TestPolicy changed later.
            let effective=if after_probe{0}else{round.ordinal};
            let using_test=if after_probe{false}else{self.same_test_endpoint(index)};
            let candidate=self.issue_candidate(names,primary,&session,lease,(replacement,current.as_ref(),attempt_id),None,cancel,Some(&leg_input),
                acme_journal::AcmeJournal::Primary{effective_ordinal:effective,using_test_endpoint:using_test}).await?;
            self.commit_primary_candidate(names,primary,lease,attempt_id,lifecycle,cancel,Some(&leg_input),Some(produced),candidate).await
        }.await;
        result.map_err(|error|{
            let retry=error.is::<RetryAfterError>()||error.downcast_ref::<ProtocolError>().is_some_and(|p|p.status()==429);
            if after_probe&&!retry{error.context(retry_operation::NoRetry)}else{error}
        })
    }
}
