//! Distributed proof readers follow the first accepted automation policy.
//! Writers do not authorize a store as a global proof lookup source.
use super::*;
pub(super) struct Sources {_reader:Option<Arc<crate::challenge::ZeroSslReader>>}
impl CertificateServices {
    pub(super) async fn prepare_zerossl_sources(&self,cancel:CancellationToken)->Result<()> {
        self.zerossl_sources.get_or_try_init(||async {
            if !self.plan.policies.iter().any(|p|p.issuers.iter().any(|i|matches!(i,Issuer::ZeroSsl(_)))) {
                return Ok(Sources{_reader:None})
            }
            let count=self.plan.policies.len();
            let bytes=count.checked_mul(std::mem::size_of::<crate::challenge::ZeroSslReaderPolicy>())
                .and_then(|n|n.checked_add(1024)).ok_or(crate::cert_transient::ResourceDenied)?;
            let memory=crate::cert_transient::reserve(bytes)?;
            let mut policies=Vec::new();policies.try_reserve_exact(count).map_err(|_|crate::cert_transient::ResourceDenied)?;
            ensure!(policies.capacity()<=count.saturating_add(1024/std::mem::size_of::<crate::challenge::ZeroSslReaderPolicy>()),"ZeroSSL reader metadata exceeds limit");
            for policy in &self.plan.policies {
                let subjects=super::super::PreparedSubjectMatcher::new(policy.subjects.get()?.clone());
                let source=if policy.issuers.iter().any(|i|matches!(i,Issuer::ZeroSsl(_))){
                    let path=policy.storage.as_ref().or(self.plan.storage.as_ref()).unwrap_or(&self.context.paths.default_storage).clone();
                    let store=self.context.resources.store(path,&self.context.paths,cancel.clone()).await?;
                    Some(self.context.challenges.zerossl_source(store.fs.clone(),self.context.resources.cpu.clone())?)
                }else{None};
                policies.push(crate::challenge::ZeroSslReaderPolicy{subjects,source});
            }
            let reader=self.context.challenges.zerossl_reader(policies,self.context.cancel.clone(),memory)?;
            Ok::<_,anyhow::Error>(Sources{_reader:Some(reader)})
        }).await?;Ok(())
    }
}
