//! Exact-certificate removal shares the installer locks and atomic Java edits.
use super::*;
#[cfg(target_os="linux")]use std::io::Read;

impl SystemTrustInstaller {
    pub async fn uninstall(&self,pem:&[u8],cancel:CancellationToken)->Result<()>{
        ensure!(!cancel.is_cancelled(),"trust removal cancelled");
        let pem=pem.to_vec();
        let certificate=Arc::new(tokio::task::spawn_blocking(move||Root::parse_for_removal(&pem)).await??);
        ensure!(self.targets.iter().any(matches_system),"no supported system trust backend discovered");
        let mut jobs=stream::iter(self.targets.clone())
            .map(|target|self.remove_target(target,certificate.clone(),cancel.clone())).buffer_unordered(8);
        let mut errors=Vec::new();
        while let Some(result)=jobs.next().await{if let Err(error)=result{errors.push(error.to_string());}}
        ensure!(errors.is_empty(),"trust removal incomplete: {}",errors.join("; "));
        Ok(())
    }

    async fn remove_target(&self,target:Target,certificate:Arc<Root>,cancel:CancellationToken)->Result<()>{
        let key=match &target{
            #[cfg(target_os="linux")]
            Target::System{..}=>"system".into(),
            #[cfg(target_os="macos")]
            Target::Mac{..}=>"system".into(),
            Target::Java{store,..}=>format!("java:{}",store.display()),
            Target::Nss{database,..}=>format!("nss:{}",database.display()),
        };
        let lock=target_lock(key)?;
        let _guard=tokio::select!{_=cancel.cancelled()=>return Err(anyhow!("trust removal cancelled")),guard=lock.lock()=>guard};
        ensure!(!cancel.is_cancelled(),"trust removal cancelled");
        match target{
            #[cfg(target_os="linux")]
            Target::System{directory,extension,updater,args,..}=>{
                let _java=self.java_hook_guards(cancel.clone()).await?;
                let destination=checked_anchor(&directory,&certificate.name,extension)?;
                let read_path=destination.clone();
                let expected=certificate.sha256.clone();
                let exists=tokio::task::spawn_blocking(move||->Result<bool>{
                    let file=match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(read_path){
                        Ok(file)=>file,Err(e)if e.kind()==std::io::ErrorKind::NotFound=>return Ok(false),Err(e)=>return Err(e.into()),
                    };
                    ensure!(file.metadata()?.is_file()&&file.metadata()?.len()<=1024*1024,"system trust anchor must be a bounded regular file");
                    let mut bytes=Vec::new();file.take(1024*1024+1).read_to_end(&mut bytes)?;
                    ensure!(bytes.len()<=1024*1024,"system trust anchor changed during read");
                    let chain=material::chain(&bytes)?;
                    ensure!(chain.len()==1&&hex(&Sha256::digest(&chain[0]))==expected,"system trust alias refers to a different certificate");
                    Ok(true)
                }).await??;
                if !exists{return Ok(())}
                let rm=executable("rm").ok_or_else(||anyhow!("rm unavailable for trust removal"))?;
                success(self.command(&rm,vec!["-f".into(),"--".into(),destination.into_os_string()],None,true,cancel.clone(),true).await?,"remove system root")?;
                success(self.command(&updater,args,None,true,cancel,true).await?,"update system trust after removal")
            },
            #[cfg(target_os="macos")]
            Target::Mac{security}=>{
                let result=self.command(&security,vec!["delete-certificate".into(),"-Z".into(),certificate.sha1.clone().into(),"/Library/Keychains/System.keychain".into()],None,true,cancel,true).await?;
                if result.status.code()==Some(44){return Ok(())}
                success(result,"remove Keychain root")
            },
            Target::Java{tool,store}=>self.uninstall_java(&tool,&store,certificate,cancel).await,
            Target::Nss{tool,database,format}=>{
                if rustix::process::geteuid().is_root(){
                    root_secure(&database)?;
                    for name in ["cert9.db","cert8.db","key4.db","key3.db","pkcs11.txt","secmod.db"]{
                        let file=database.join(name);if file.exists(){root_secure(&file)?;}
                    }
                }
                let db=format!("{format}{}",database.display());
                let exported=self.command(&tool,vec!["-L".into(),"-d".into(),db.clone().into(),"-n".into(),certificate.name.clone().into(),"-a".into()],None,false,cancel.clone(),false).await?;
                if !exported.status.success(){
                    let reason=String::from_utf8_lossy(&exported.stderr);
                    if reason.contains("SEC_ERROR_UNKNOWN_CERT")||reason.to_ascii_lowercase().contains("could not find cert"){return Ok(())}
                    return Err(anyhow!("NSS root export failed during removal"))
                }
                let chain=material::chain(&exported.stdout)?;
                ensure!(chain.len()==1&&hex(&Sha256::digest(&chain[0]))==certificate.sha256,"NSS alias refers to a different certificate");
                success(self.command(&tool,vec!["-D".into(),"-d".into(),db.into(),"-n".into(),certificate.name.clone().into()],None,true,cancel,false).await?,"remove NSS root")
            },
        }
    }
}
