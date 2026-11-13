//! Explicit protocol disposition shared by issuance and its polling checkpoints.
//! Probe writes never reach ordinary Job/Reservation or production assets.
use super::*;
use super::acme_probe::{PhaseBinding,PhaseStep};
#[derive(Clone,Copy)]
pub(super) enum AcmeJournal<'a> {
    Primary {effective_ordinal:u32,using_test_endpoint:bool},
    Probe(&'a PhaseBinding),
}
impl AcmeJournal<'_> {
    pub(super) fn purpose(self)->acme_candidate::AcmePurpose {match self {
        Self::Primary{..}=>acme_candidate::AcmePurpose::Primary,
        Self::Probe(_)=>acme_candidate::AcmePurpose::Probe,
    }}
    pub(super) fn suppress_replaces(self)->bool {match self {
        Self::Primary{effective_ordinal,using_test_endpoint}=>using_test_endpoint||effective_ordinal==2,
        Self::Probe(_)=>true,
    }}
    pub(super) async fn load(self,manager:&CertificateManager,id:&str)->Result<Option<Job>> {match self {
        Self::Primary{..}=>manager.load_job(id).await,
        Self::Probe(binding)=>match manager.load_probe_job(id).await? {
            None=>Ok(None),Some(record)=>{
                ensure!(&record.binding==binding,"active probe binding changed");
                ensure!(!record.job.abandoned,"retired probe cannot be reactivated");
                ensure!(record.job.phase!="probe_validated","completed probe must use its validation receipt");
                Ok(Some(record.job))
            },
        },
    }}
    pub(super) async fn save(self,manager:&CertificateManager,id:&str,job:&Job,lease:&StorageLease)->Result<()> {match self {
        Self::Primary{..}=>manager.save_job(id,job,lease).await,
        Self::Probe(binding)=>{
            manager.save_probe_job(id,binding,job,None,lease).await?;
            manager.save_probe_reservation(binding,job,lease).await
        },
    }}
}
impl CertificateManager {
    pub(super) async fn activate_probe(&self,names:&[String],attempt_id:&str,binding:&PhaseBinding,lease:&StorageLease)->Result<()> {
        binding.validate()?;ensure!(binding.step==PhaseStep::Probe,"probe activation step changed");
        let Some(super::test_ca::TestPolicy::Separate(test))=self.inner.test_policies.get(usize::from(binding.owner_acme_index))else{bail!("probe activation original policy missing")};
        self.validate_probe_binding(&test.state,binding)?;
        let _identity=crate::cert_transient::reserve(256)?;
        ensure!(binding.probe_job_id==super::test_ca_driver::probe_id(attempt_id,binding.owner_acme_index,&binding.operation_id,names,
            &binding.owner,&binding.endpoint,&binding.input,&binding.test_policy)?,"probe activation namespace changed");
        lease.check().await?;
        let record=self.load_probe_job(&binding.probe_job_id).await?.ok_or_else(||anyhow!("probe activation checkpoint missing"))?;
        ensure!(&record.binding==binding&&record.job.names==names&&record.job.attempt_id==attempt_id&&!record.job.abandoned,
            "probe activation checkpoint scope changed");
        let marker=self.load_probe_reservation(binding).await?.ok_or_else(||anyhow!("probe activation reservation missing"))?;
        ensure!(marker.matches_job(&record.job)?,"probe activation reservation activity changed");
        let mut state=self.load_attempt(names).await?.ok_or_else(||anyhow!("certificate attempt missing"))?;
        ensure!(state.unified()&&state.attempt_id==attempt_id&&state.winner.is_none()
            &&state.backend_sequence.contains(&binding.owner),"probe attempt superseded");
        if let Some(active)=&state.acme_phase {ensure!(active==binding,"another ACME phase is active");}
        else if let Some(previous)=&state.current_job_id {
            ensure!(!super::acme_probe::is_probe_id(previous),"unbound probe pointer cannot become active");
            let job=self.load_job(previous).await?.ok_or_else(||anyhow!("previous production checkpoint missing"))?;
            let marker_id=reservation_id(names,&job.directory)?;
            let (marker,_credit)=self.inner.store.journal_decode_admitted(&marker_id,|raw|{
                let credit=job_codec::decode_credit(raw.len())?;
                let marker:Reservation=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid previous production reservation"))?;
                Ok((marker,credit))
            }).await?.ok_or_else(||anyhow!("previous production reservation missing"))?;
            ensure!(marker.job_id==*previous,"previous production job pointer changed");
            validate_reservation_job(&marker,&job)?;
            ensure!((job.phase=="prepared"&&job.order_url.is_none())||(marker.retired&&job.abandoned&&!marker.active),
                "known production order cannot become a probe");
        }
        let memory=crate::cert_transient::reserve(binding.activation_copy_cost()?)?;
        state.version=3;state.current_job_id=Some(binding.probe_job_id.clone());
        state.current_backend=Some(binding.owner.clone());state.current_input=Some(binding.input.clone());
        state.acme_phase=Some(binding.clone());state._phase_memory=Some(memory);
        self.save_attempt(state,lease).await
    }
    pub(super) async fn validate_probe_renewal_scope(&self,job:&Job,binding:&PhaseBinding)->Result<()> {
        if let Some(sans)=&job.renewal_names {
            ensure!(job.names.len()==1,"probe Name0 scope has multiple storage subjects");
            let attempt::BackendId::Acme{directory,..}=&binding.owner else{bail!("probe production backend missing")};
            let issuer=issuer_key(directory)?;let name=names_key(&job.names)?;
            let old=self.inner.store.load_certificate_owned(&issuer,&name).await?
                .ok_or_else(||anyhow!("probe Name0 scope lost its production signed resource"))?;
            ensure!(crate::certstore::name0_renewal_names(&old,&name)?.as_ref()==Some(sans),"probe Name0 signed scope changed");
        }Ok(())
    }
}
