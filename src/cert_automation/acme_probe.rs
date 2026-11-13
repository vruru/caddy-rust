//! Closed test-CA journal records. These are not ordinary certificate jobs and
//! cannot be decoded by the legacy Job/Reservation schema or published as assets.
use super::*;
use super::attempt::{BackendId,InputBinding};
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub(super) enum PhaseStep {Probe,PendingPrimary}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
pub(super) struct PhaseBinding {
    pub version:u8,
    pub owner_acme_index:u8,
    pub owner:BackendId,
    pub input:InputBinding,
    pub endpoint:BackendId,
    #[serde(deserialize_with="super::job_codec::text")]
    pub test_policy:String,
    #[serde(deserialize_with="super::job_codec::text")]
    pub operation_id:String,
    #[serde(deserialize_with="super::job_codec::text")]
    pub probe_job_id:String,
    pub step:PhaseStep,
}
fn backend_text(id:&BackendId)->Result<usize>{match id {
    BackendId::Acme{directory,config_identity}=>directory.len().checked_add(config_identity.len()),
    BackendId::Internal{ca,options_identity}=>ca.len().checked_add(options_identity.len()),
}.ok_or_else(||crate::cert_transient::ResourceDenied.into())}
fn input_text(input:&InputBinding)->Result<usize>{
    let fields:&[&str]=match input {
        InputBinding::Shared{input_id,csr_hash,spki_hash}=>&[input_id,csr_hash,spki_hash],
        InputBinding::LegacyJob{job_id,original_attempt_id,csr_hash,spki_hash,reservation_hash}=>
            &[job_id,original_attempt_id,csr_hash,spki_hash,reservation_hash],
    };
    fields.iter().try_fold(0usize,|n,v|n.checked_add(v.len()).ok_or_else(||crate::cert_transient::ResourceDenied.into()))
}
impl PhaseBinding {
    pub(super) fn validate(&self)->Result<()> {
        ensure!(self.operation_id.len()==64&&self.operation_id.bytes().all(|byte|byte.is_ascii_hexdigit()),"invalid probe operation identity");
        ensure!(is_job_id(&self.probe_job_id),"invalid probe witness namespace");
        ensure!(self.version==1&&self.owner_acme_index<16,"invalid ACME phase version/index");
        ensure!(matches!(self.owner,BackendId::Acme{..})&&matches!(self.endpoint,BackendId::Acme{..}),"ACME phase backend kind changed");
        ensure!(self.test_policy.len()==64&&self.test_policy.bytes().all(|b|b.is_ascii_hexdigit()),"invalid test CA policy identity");
        ensure!(matches!(self.input,InputBinding::Shared{..}),"test CA phase cannot reinterpret a legacy input");
        if self.step==PhaseStep::PendingPrimary {ensure!(self.owner==self.endpoint,"pending primary endpoint changed");}
        Ok(())
    }
    /// The new phase and the three separate Attempt pointers coexist. The
    /// loaded Attempt's existing bytes keep their own decode credit; no raw
    /// decode multiplier or fixed slack is borrowed for these new clones.
    pub(super) fn activation_copy_cost(&self)->Result<usize>{
        self.copy_cost()?.checked_add(backend_text(&self.owner)?)
            .and_then(|n|input_text(&self.input).ok().and_then(|v|n.checked_add(v)))
            .and_then(|n|n.checked_add(self.probe_job_id.len()))
            .and_then(|n|n.checked_add(std::mem::size_of::<BackendId>()+std::mem::size_of::<InputBinding>()+std::mem::size_of::<String>()+192))
            .ok_or_else(||crate::cert_transient::ResourceDenied.into())
    }
    pub(super) fn copy_cost(&self)->Result<usize>{
        self.validate()?;
        backend_text(&self.owner)?.checked_add(backend_text(&self.endpoint)?)
            .and_then(|n|input_text(&self.input).ok().and_then(|v|n.checked_add(v)))
            .and_then(|n|n.checked_add(self.test_policy.len()))
            .and_then(|n|n.checked_add(self.operation_id.len()))
            .and_then(|n|n.checked_add(self.probe_job_id.len()))
            .and_then(|n|n.checked_add(std::mem::size_of::<Self>()+2048))
            .ok_or_else(||crate::cert_transient::ResourceDenied.into())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProbeJobRecord {
    version:u8,
    #[serde(deserialize_with="super::job_codec::text")]
    kind:String,
    #[serde(deserialize_with="super::job_codec::text")]
    lease_name:String,
    pub binding:PhaseBinding,
    pub job:Job,
    #[serde(default,deserialize_with="super::job_codec::optional_text")]
    pub validated_leaf:Option<String>,
    pub validated_at:Option<i64>,
    // All actual decoded fields retire before their callback-free allowance.
    #[serde(skip)]
    _memory:Option<crate::acme_wire::chain_memory::Lease>,
}
impl ProbeJobRecord {
    pub(super) fn validate(&self)->Result<()> {
        ensure!(self.version==1&&self.kind=="acme_probe_job","invalid probe job protocol");
        validate_job_parts(&self.binding,&self.job,self.validated_leaf.as_deref(),self.validated_at)?;
        ensure!(self.lease_name==format!("issue_cert_{}",self.job.names[0]),"probe job lease scope changed");
        Ok(())
    }
}

fn validate_job_parts(binding:&PhaseBinding,job:&Job,validated_leaf:Option<&str>,validated_at:Option<i64>)->Result<()> {
        binding.validate()?;
        ensure!(binding.step==PhaseStep::Probe,"probe job step changed");
        job_codec::validate(&job)?;
        ensure!(!job.names.is_empty(),"probe job has no storage name");
        ensure!(job.version==1&&job.initial_key_hash.is_none()&&job.stored_leaf_sha256.is_none(),"probe job contains production state");
        let BackendId::Acme{directory,..}=&binding.endpoint else{bail!("probe endpoint kind changed")};
        ensure!(&job.directory==directory,"probe job endpoint changed");
        ensure!(matches!(job.phase.as_str(),"prepared"|"new_order_intent"|"order_created"|"order_recovered"|"authorizing"|"finalize_intent"|"finalized"|"downloaded"|"probe_validated"),"invalid probe job phase");
        if matches!(job.phase.as_str(),"downloaded"|"probe_validated") {ensure!(job.downloaded_pem.is_some(),"probe downloaded material missing");}
        if job.phase=="probe_validated" {
            ensure!(validated_leaf.is_some_and(|v|v.len()==64&&v.bytes().all(|b|b.is_ascii_hexdigit()))
                &&validated_at.is_some_and(|v|v>=0)&&job.private_key_pem.is_empty(),"invalid completed probe receipt");
        }else{ensure!(validated_leaf.is_none()&&validated_at.is_none(),"unvalidated probe contains a validation receipt");}
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProbeReservationRecord {
    version:u8,
    #[serde(deserialize_with="super::job_codec::text")]
    kind:String,
    #[serde(deserialize_with="super::job_codec::text")]
    lease_name:String,
    binding:PhaseBinding,
    marker:Reservation,
    #[serde(skip)]
    _memory:Option<crate::acme_wire::chain_memory::Lease>,
}
impl ProbeReservationRecord {
    fn validate(&self)->Result<()>{
        ensure!(self.version==1&&self.kind=="acme_probe_reservation"&&self.marker.version==1,"invalid probe reservation protocol");self.binding.validate()?;
        ensure!(!self.marker.names.is_empty()&&self.lease_name==format!("issue_cert_{}",self.marker.names[0]),"probe reservation lease scope changed");
        ensure!(self.binding.step==PhaseStep::Probe&&self.marker.job_id==self.binding.probe_job_id,"invalid probe reservation scope");
        let BackendId::Acme{directory,..}=&self.binding.endpoint else{bail!("probe endpoint kind changed")};
        ensure!(&self.marker.directory==directory,"probe reservation endpoint changed");Ok(())
    }
}
pub(super) fn is_probe_id(id:&str)->bool{id.starts_with("acme-probe-v1-")}
fn is_job_id(id:&str)->bool{id.strip_prefix("acme-probe-v1-job-").is_some_and(|hash|hash.len()==64&&hash.bytes().all(|b|b.is_ascii_hexdigit()))}
pub(super) fn job_id(identity:&[u8])->String{format!("acme-probe-v1-job-{}",digest(identity))}
pub(super) fn marker_id(identity:&[u8])->String{format!("acme-probe-v1-marker-{}",digest(identity))}
struct ProbeEncodeInput {
    binding:PhaseBinding,
    snapshot:job_codec::Snapshot,
    validated_leaf:Option<String>,
    validated_at:Option<i64>,
    _memory:crate::acme_wire::chain_memory::Scratch,
}
impl ProbeEncodeInput {
    async fn new(binding:&PhaseBinding,job:&Job,validated:Option<(&str,i64)>,lease_name:&str)->Result<Self>{
        validate_job_parts(binding,job,validated.map(|(leaf,_)|leaf),validated.map(|(_,at)|at))?;
        let bytes=binding.copy_cost()?.checked_add(validated.map_or(0,|(s,_)|s.len()))
            .and_then(|n|n.checked_add(std::mem::size_of::<Self>()+256)).ok_or(crate::cert_transient::ResourceDenied)?;
        let memory=crate::cert_transient::reserve(bytes)?;
        let binding=binding.clone();let validated_leaf=validated.map(|(s,_)|s.to_owned());let validated_at=validated.map(|(_,at)|at);
        let snapshot=job_codec::snapshot(job,lease_name).await?;
        Ok(Self{binding,snapshot,validated_leaf,validated_at,_memory:memory})
    }
    fn encode(self)->Result<job_codec::Encoded>{
        #[derive(Serialize)]struct Record<'a>{version:u8,kind:&'static str,binding:&'a PhaseBinding,job:&'a Job,validated_leaf:&'a Option<String>,validated_at:Option<i64>}
        let input=self;
        job_codec::encode_record(&Record{version:1,kind:"acme_probe_job",binding:&input.binding,job:input.snapshot.job(),validated_leaf:&input.validated_leaf,validated_at:input.validated_at},input.snapshot.lease_name())
    }
}
impl CertificateManager {
    pub(super) async fn load_probe_job(&self,id:&str)->Result<Option<ProbeJobRecord>>{
        ensure!(is_job_id(id),"probe journal namespace changed");
        let copy=crate::cert_transient::reserve(256)?;
        let witness=id.to_owned();
        self.inner.store.journal_decode_admitted(id,move|raw|{
            let _copy=copy;
            let _scratch=job_codec::decode_credit(raw.len())?;
            let mut value:ProbeJobRecord=serde_json::from_slice(raw).map_err(|error|{if error.to_string().contains("native checkpoint payload admission denied"){crate::cert_transient::ResourceDenied.into()}else{anyhow!("invalid probe checkpoint")}})?;
            value.validate()?;
            ensure!(witness==value.binding.probe_job_id,"probe job witness changed");
            job_codec::admit_restored(&mut value.job)?;
            let cost=value.binding.copy_cost()?.checked_add(value.kind.len()).and_then(|n|n.checked_add(value.lease_name.len()))
                .and_then(|n|n.checked_add(value.validated_leaf.as_ref().map_or(0,String::len)))
                .and_then(|n|n.checked_add(std::mem::size_of::<ProbeJobRecord>()+256))
                .ok_or(crate::cert_transient::ResourceDenied)?;
            value._memory=Some(crate::acme_wire::chain_memory::shared().payload.reserve(cost).map_err(|_|crate::cert_transient::ResourceDenied)?);
            Ok(value)
        }).await
    }
    pub(super) async fn save_probe_job(&self,id:&str,binding:&PhaseBinding,job:&Job,
        validated:Option<(&str,i64)>,lease:&StorageLease)->Result<()> {
        ensure!(is_probe_id(id),"probe journal namespace changed");
        ensure!(id==binding.probe_job_id,"probe job witness changed");
        validate_job_parts(binding,job,validated.map(|(leaf,_)|leaf),validated.map(|(_,at)|at))?;
        ensure!(lease.name()==format!("issue_cert_{}",job.names[0]),"probe job lease scope changed");
        let input=ProbeEncodeInput::new(binding,job,validated,lease.name()).await?;
        let encoded=self.cpu(&CancellationToken::new(),move||input.encode()).await?;
        self.inner.store.journal_store_encoded_fenced(id,encoded,lease).await
    }
}


struct ReservationEncodeInput {
    binding:PhaseBinding,
    snapshot:job_codec::Snapshot,
    _memory:crate::acme_wire::chain_memory::Scratch,
}
impl ReservationEncodeInput {
    fn encode(self)->Result<job_codec::Encoded> {
        #[derive(Serialize)]struct Marker<'a>{version:u8,names:&'a[String],directory:&'a str,account_location:&'a str,
            config_email:&'a str,leaf_key_type:KeyType,must_staple:bool,reuse_private_keys:bool,
            certificate_lifetime_ns:i64,profile:&'a str,job_id:&'a str,active:bool,retired:bool}
        #[derive(Serialize)]struct Record<'a>{version:u8,kind:&'static str,binding:&'a PhaseBinding,marker:Marker<'a>}
        let input=self;let job=input.snapshot.job();
        let marker=Marker{version:1,names:&job.names,directory:&job.directory,account_location:&job.account_location,
            config_email:&job.config_email,leaf_key_type:job.leaf_key_type,must_staple:job.must_staple,
            reuse_private_keys:job.reuse_private_keys,certificate_lifetime_ns:job.certificate_lifetime_ns,
            profile:&job.profile,job_id:&input.binding.probe_job_id,
            active:!job.abandoned&&!["prepared","probe_validated"].contains(&job.phase.as_str()),retired:job.abandoned};
        job_codec::encode_record(&Record{version:1,kind:"acme_probe_reservation",binding:&input.binding,marker},input.snapshot.lease_name())
    }
}
fn reservation_key(binding:&PhaseBinding)->Result<String>{
    binding.validate()?;
    let hash=binding.probe_job_id.strip_prefix("acme-probe-v1-job-").ok_or_else(||anyhow!("invalid probe witness"))?;
    Ok(format!("acme-probe-v1-marker-{hash}"))
}
impl CertificateManager {
    pub(super) async fn save_probe_reservation(&self,binding:&PhaseBinding,job:&Job,lease:&StorageLease)->Result<()> {
        binding.validate()?;ensure!(binding.step==PhaseStep::Probe,"probe reservation step changed");
        ensure!(lease.name()==format!("issue_cert_{}",job.names.first().ok_or_else(||anyhow!("probe has no storage name"))?),"probe reservation lease changed");
        let memory=crate::cert_transient::reserve(binding.copy_cost()?.checked_add(std::mem::size_of::<ReservationEncodeInput>()+256).ok_or(crate::cert_transient::ResourceDenied)?)?;
        let key=reservation_key(binding)?;
        let binding=binding.clone();let snapshot=job_codec::snapshot(job,lease.name()).await?;
        let input=ReservationEncodeInput{binding,snapshot,_memory:memory};
        let encoded=self.cpu(&CancellationToken::new(),move||input.encode()).await?;
        self.inner.store.journal_store_encoded_fenced(&key,encoded,lease).await
    }
    pub(super) async fn load_probe_reservation(&self,binding:&PhaseBinding)->Result<Option<ProbeReservationRecord>> {
        let memory=crate::cert_transient::reserve(binding.copy_cost()?.checked_add(256).ok_or(crate::cert_transient::ResourceDenied)?)?;
        let key=reservation_key(binding)?;let expected=binding.clone();
        self.inner.store.journal_decode_admitted(&key,move|raw|{
            let _memory=memory;let _scratch=job_codec::decode_credit(raw.len())?;
            let mut value:ProbeReservationRecord=serde_json::from_slice(raw).map_err(|_|anyhow!("invalid probe reservation checkpoint"))?;
            value.validate()?;ensure!(value.binding==expected,"probe reservation binding changed");
            // All strings in the decoded marker are bounded by raw admission;
            // this owner survives the worker and any unconsumed result.
            value._memory=Some(crate::acme_wire::chain_memory::shared().payload.reserve(raw.len().checked_mul(2)
                .and_then(|n|n.checked_add(std::mem::size_of::<ProbeReservationRecord>()+2048))
                .ok_or(crate::cert_transient::ResourceDenied)?).map_err(|_|crate::cert_transient::ResourceDenied)?);
            Ok(value)
        }).await
    }
}


impl ProbeReservationRecord {
    /// Static identity must always agree. Only derived activity may lag a
    /// separately fenced job write across a crash; it never invents an order.
    pub(super) fn matches_job(&self,job:&Job)->Result<bool>{
        self.validate()?;let marker=&self.marker;
        ensure!(job.version==1&&job.names==marker.names&&job.directory==marker.directory
            &&job.account_location==marker.account_location&&job.config_email==marker.config_email
            &&job.leaf_key_type==marker.leaf_key_type&&job.must_staple==marker.must_staple
            &&job.reuse_private_keys==marker.reuse_private_keys&&job.certificate_lifetime_ns==marker.certificate_lifetime_ns
            &&job.profile==marker.profile,"probe reservation checkpoint identity changed");
        ensure!(!marker.retired||job.abandoned,"retired probe job cannot be revived");
        let active=!job.abandoned&&!["prepared","probe_validated"].contains(&job.phase.as_str());
        Ok(marker.active==active&&marker.retired==job.abandoned)
    }
}
