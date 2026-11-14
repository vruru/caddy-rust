//! Generation-owned ECH snapshots. Restore uses accepted memory; periodic
//! storage refresh starts independently only after the Root commit signal.
use super::*;
impl CertificateServices{
    pub(super)async fn prepare_ech(&self,cancel:CancellationToken)->Result<()>{
        self.ech.get_or_try_init(||async{
            if let Some(retained)=&self.restore{
                ensure!(self.plan.ech.is_some()==retained.ech.is_some(),"retained ECH topology differs");
                return Ok(retained.ech.clone().map(super::super::ech::Runtime::new))
            }
            let Some(settings)=&self.plan.ech else{return Ok(None)};
            let root=self.plan.storage.as_ref().unwrap_or(&self.context.paths.default_storage);
            let store=self.context.resources.store(root.clone(),&self.context.paths,cancel.clone()).await?;
            let snapshot=super::super::ech::prepare(settings,&store.fs,self.context.resources.cpu.clone(),cancel.clone()).await?;
            Ok::<_,anyhow::Error>(Some(super::super::ech::Runtime::new(Arc::new(snapshot))))
        }).await?;Ok(())
    }
    pub(crate)fn ech_runtime(&self)->Option<Arc<super::super::ech::Runtime>>{self.ech.get().cloned().flatten()}
    pub(super)async fn maintain_ech(self:Arc<Self>){
        let Some(runtime)=self.ech_runtime()else{return};
        let Some(settings)=&self.plan.ech else{return};
        loop{
            tokio::select!{biased;_=self.context.cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3600))=>{}}
            let result:Result<_>=async{
                let root=self.plan.storage.as_ref().unwrap_or(&self.context.paths.default_storage);
                let store=self.context.resources.store(root.clone(),&self.context.paths,self.context.cancel.clone()).await?;
                let snapshot=super::super::ech::prepare(settings,&store.fs,self.context.resources.cpu.clone(),self.context.cancel.clone()).await?;
                ensure!(!self.context.cancel.is_cancelled(),"ECH refresh cancelled");Ok(snapshot)
            }.await;
            match result{
                Ok(snapshot)=>runtime.publish(Arc::new(snapshot)),
                Err(_)if !self.context.cancel.is_cancelled()=>{let _=self.events.send(CertificateEvent{kind:"ech_rotation_failed",names:Vec::new()});},
                Err(_)=>break,
            }
        }
    }
}
