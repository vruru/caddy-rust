//! Optional storage probe belongs to one actual issuance invocation, never a
//! global cache or one issuer/test-CA leg. It does not replace real persistence.
use super::*;
#[derive(Clone,Copy)]
pub(super) enum CheckState{Needed,Disabled,Passed}
impl CertificateManager{
    pub(crate) fn with_storage_check_disabled(mut self,disabled:bool)->Result<Self>{
        let inner=Arc::get_mut(&mut self.inner).ok_or_else(||anyhow!("certificate manager is already shared"))?;
        inner.disable_storage_check=disabled;Ok(self)
    }
    pub(super) async fn check_storage_once(&self,state:&mut CheckState,cancel:&CancellationToken)->Result<()>{
        if !matches!(state,CheckState::Needed){return Ok(())}
        self.inner.store.check_read_write(cancel.clone(),self.inner.chain_cleanup.clone()).await
            .map_err(|error|error.context("failed certificate storage check"))?;
        *state=CheckState::Passed;Ok(())
    }
}
