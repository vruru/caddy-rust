//! Root front authentication: bind raw occurrences, then consume prepared sources.
use super::*;
use crate::tls_policy::prepared_auth::{AuthBudget,AuthInputs,RetainedAuth,ResolvedFrontCa,AuthSources};
impl CertificateServices{
    #[cfg(feature="native-run")]
    pub(super) async fn begin_front_auth(self:&Arc<Self>,config:crate::http_config::PreparedConfig,cancel:CancellationToken)->Result<crate::http_config::PreparedConfig>{
        let this=self.clone();crate::cert_cpu::run(self.context.resources.cpu.clone(),cancel,move||{
            let mut config=config;
            if let Some(retained)=&this.restore{
                if let Some(saved)=&retained.client_auth{saved.install(&mut config)?;}else{RetainedAuth::validate_empty(&config)?;}
                if this.client_auth_accepted.get().is_none(){this.client_auth_accepted.set(retained.client_auth.clone()).map_err(|_|anyhow!("client authentication snapshot publication raced"))?;}return Ok(config)
            }
            let budget=AuthBudget::Root(this.context.resources.external_bytes.clone());
            let inputs=if let Some(old)=this.client_auth_inputs.get(){old.clone()}else{let inputs=AuthInputs::from_http(&config,budget)?;this.client_auth_inputs.set(inputs.clone()).map_err(|_|anyhow!("client authentication input publication raced"))?;inputs};
            if let Some(inputs)=inputs{inputs.install_ready(&mut config)?;}else{RetainedAuth::validate_empty(&config)?;}Ok(config)
        }).await
    }
    #[cfg(feature="native-run")]
    pub(super) async fn finish_front_auth(self:&Arc<Self>,config:crate::http_config::PreparedConfig,cancel:CancellationToken)->Result<crate::http_config::PreparedConfig>{
        if self.restore.is_some(){return Ok(config)}
        let inputs=self.client_auth_inputs.get().cloned().ok_or_else(||anyhow!("client authentication inputs not initialized"))?;
        let budget=AuthBudget::Root(self.context.resources.external_bytes.clone());
        if let Some(inputs)=&inputs{for entry in inputs.entries(){
            let k=entry.key();
            let ca=config.servers.get(k.server_ordinal).and_then(|s|s.tls_policies.get(k.policy_ordinal)).ok_or_else(||anyhow!("client authentication source topology changed"))?.prepared_ca.clone();
            let services=self.clone();let source_budget=budget.clone();
            entry.prepare_from(budget.clone(),self.context.resources.cpu.clone(),cancel.clone(),move|entry,token|async move{
                let ca=ca.map(|source|entry.binding().map(|binding|ResolvedFrontCa::new(entry.key(),binding,source))).transpose()?;
                let leaf=crate::tls_policy::leaf_sources::prepare(entry,services.context.paths.cwd.clone(),services.context.resources.io.clone(),services.context.resources.cpu.clone(),source_budget,token).await?;
                Ok(AuthSources{ca,leaf})
            }).await?;
        }}
        let this=self.clone();crate::cert_cpu::run(self.context.resources.cpu.clone(),cancel,move||{
            let mut config=config;
            let saved=if let Some(previous)=this.client_auth_accepted.get(){previous.clone()}else{inputs.as_ref().map(|v|v.retain()).transpose()?};
            if let Some(saved)=&saved{saved.install(&mut config)?;}else{RetainedAuth::validate_empty(&config)?;}
            // Source DOM/loans retire on this actual CPU job only after the
            // immutable verifier owns its independently charged DER.
            for s in &mut config.servers{let s=Arc::get_mut(s).ok_or_else(||anyhow!("client authentication source retirement requires unique plan"))?;for p in &mut s.tls_policies{p.prepared_ca=None;}}
            if this.client_auth_accepted.get().is_none(){this.client_auth_accepted.set(saved).map_err(|_|anyhow!("client authentication snapshot publication raced"))?;}Ok(config)
        }).await
    }
}
