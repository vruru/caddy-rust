//! Rotation holds one real storage lease. Preparation and periodic refresh use
//! the same path; an interrupted publish never replaces the accepted snapshot.
use super::{Key,Settings,Snapshot};
use anyhow::{Result,anyhow,ensure};
use crate::certstore::{FsStore,StorageLease};
use std::{collections::BTreeSet,sync::Arc};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
const PREFIX:&str="ech/configs";
const ROTATE:i64=30*86400;
const EXPIRE:i64=90*86400;
pub(crate)async fn prepare(settings:&Settings,store:&FsStore,cpu:Arc<Semaphore>,cancel:CancellationToken)->Result<Snapshot>{
    let lease=store.lock("ech_rotation",cancel.clone()).await?;
    let result=reconcile(settings,store,&lease,cpu,cancel).await;
    let released=lease.release().await;
    match result{Err(e)=>{let _=released;Err(e)},Ok(value)=>{released?;Ok(value)}}
}
async fn reconcile(settings:&Settings,store:&FsStore,lease:&StorageLease,cpu:Arc<Semaphore>,cancel:CancellationToken)->Result<Snapshot>{
    ensure!(!cancel.is_cancelled(),"ECH preparation cancelled");
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs().try_into()?;
    let paths=store.list(PREFIX,false).await?;ensure!(paths.len()<=256,"ECH config inventory exceeds 256 IDs");
    let _scratch=crate::cert_transient::reserve(1024*1024)?;
    let mut keys=Vec::<Arc<Key>>::with_capacity(paths.len().saturating_add(settings.names.len()).min(256));
    let mut used=BTreeSet::new();
    for path in paths{
        ensure!(!cancel.is_cancelled(),"ECH preparation cancelled");
        let Some(raw)=path.strip_prefix("ech/configs/")else{return Err(anyhow!("invalid ECH storage key"))};
        let id=raw.parse::<u8>().map_err(|_|anyhow!("invalid ECH storage ID"))?;
        ensure!(id.to_string()==raw&&used.insert(id),"invalid or duplicate ECH storage ID");
        let private=store.load(&format!("{path}/key.bin")).await?;
        let config=store.load(&format!("{path}/config.bin")).await?;
        let metadata=store.load(&format!("{path}/meta.json")).await?;
        let parsed=if let(Some(private),Some(config))=(private,config){
            let parsed_cancel=cancel.clone();
            crate::cert_cpu::run(cpu.clone(),parsed_cancel,move||Ok((||{
                ensure!(config.len()<=4096&&private.len()==32&&metadata.as_ref().is_none_or(|m|m.len()<=1024*1024),"ECH storage input exceeds limits");
                let metadata=crate::cert_transient::json_value(metadata.as_deref().map(|m|m.as_slice()).unwrap_or(b"{}"),Some(crate::cert_transient::Lifetime::Persistent))?;
                Key::parse(id,config.to_vec(),private,metadata).map(Arc::new)
            })())).await?.map(Some)
        }else{Ok(None)};
        match parsed{
            Ok(Some(key))=>{keys.push(key)},
            Err(error)if crate::cert_transient::is_resource(&error)||cancel.is_cancelled()=>return Err(error),
            Ok(None)|Err(_)=>{
                // Like CertMagic, incomplete/corrupt immutable config folders
                // are repairable. I/O, admission and cancellation failures above
                // never grant permission to delete a valid key.
                store.delete_fenced(&path,lease).await?;used.remove(&id);
            },
        }
    }
    for name in settings.names.iter(){
        if !keys.iter().any(|key|key.public_name.as_ref()==name){
            let key=create(name,now,&mut used,store,lease,cpu.clone(),cancel.clone()).await?;keys.push(key);
        }
    }
    // Retain every still-live old key for clients with cached configurations.
    // Only the current key is advertised as retry configuration.
    let original=keys.clone();
    for key in original{
        ensure!(!cancel.is_cancelled(),"ECH preparation cancelled");
        if key.replaced.is_some()&&now.saturating_sub(key.created)>=EXPIRE{
            store.delete_fenced(&format!("{PREFIX}/{}",key.id),lease).await?;keys.retain(|k|k.id!=key.id);used.remove(&key.id);continue
        }
        if key.replaced.is_none()&&now.saturating_sub(key.created)>=ROTATE{
            // If a previous interrupted rotation already persisted a newer
            // key, reuse it instead of generating another one on every retry.
            if !keys.iter().any(|new|new.id!=key.id&&new.public_name==key.public_name&&new.replaced.is_none()&&new.created>key.created){
                let new=create(&key.public_name,now,&mut used,store,lease,cpu.clone(),cancel.clone()).await?;keys.push(new);
            }
            let old=key.clone();let replacement=crate::cert_cpu::run(cpu.clone(),cancel.clone(),move||old.mark_replaced(now).map(Arc::new)).await?;
            write_meta(store,lease,&replacement).await?;
            if let Some(item)=keys.iter_mut().find(|k|k.id==key.id){*item=replacement}
        }
    }
    ensure!(!cancel.is_cancelled(),"ECH preparation cancelled");
    crate::cert_cpu::run(cpu,cancel,move||{keys.sort_by_key(|key|key.id);Snapshot::new(keys)}).await
}
async fn create(name:&str,now:i64,used:&mut BTreeSet<u8>,store:&FsStore,lease:&StorageLease,cpu:Arc<Semaphore>,cancel:CancellationToken)->Result<Arc<Key>>{
    let mut entropy=[0u8;1];getrandom::fill(&mut entropy)?;let start=entropy[0];
    let id=(0..=255u16).map(|i|start.wrapping_add(i as u8)).find(|id|!used.contains(id)).ok_or_else(||anyhow!("ECH config IDs exhausted"))?;
    let name=name.to_owned();let key=Arc::new(crate::cert_cpu::run(cpu,cancel.clone(),move||Key::generate(id,&name,now)).await?);
    ensure!(!cancel.is_cancelled(),"ECH preparation cancelled");
    store.store_fenced(&format!("{PREFIX}/{id}/key.bin"),key.private_bytes(),lease).await?;
    store.store_fenced(&format!("{PREFIX}/{id}/config.bin"),&key.config,lease).await?;
    write_meta(store,lease,&key).await?;used.insert(id);Ok(key)
}
async fn write_meta(store:&FsStore,lease:&StorageLease,key:&Key)->Result<()>{
    let encoded=crate::cert_transient::encode_json(&*key.metadata)?;
    store.store_fenced(&format!("{PREFIX}/{}/meta.json",key.id),&encoded,lease).await
}
