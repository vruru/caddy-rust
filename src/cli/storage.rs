//! Offline storage transfer uses the actual safe file-store implementation.
use super::*;
use caddy_compat_native::certstore::FsStore;
use sha2::{Digest,Sha256};
use std::os::unix::fs::{PermissionsExt,MetadataExt};

const VALUE_LIMIT:u64=12*1024*1024;
const TRANSFER_LIMIT:u64=8*1024*1024*1024;

pub(super) fn command(input:&[OsString])->Result<i32>{
    let Some(action)=input.first().and_then(|v|v.to_str())else{bail!("storage requires import or export")};
    ensure!(matches!(action,"import"|"export"),"unknown storage command");
    let mut specs=COMMON.to_vec();
    specs.extend([
        Flag{name:"input",short:None,kind:Kind::Text},
        Flag{name:"output",short:None,kind:Kind::Text},
    ]);
    let flags=args::parse(&input[1..],&specs)?;
    if flags.boolean("help"){
        println!("Usage: caddy-compat-native storage {action} --config PATH --{} PATH",if action=="import"{"input"}else{"output"});
        return Ok(0)
    }
    ensure!(flags.positional.is_empty(),"storage accepts no positional arguments");
    let config_path=nonempty(flags.text("config")).context("--config is required")?;
    let stream_path=nonempty(flags.text(if action=="import"{"input"}else{"output"})).context("storage input/output is required")?;
    let loaded=config::load(Some(config_path),None)?;
    let raw=admin_json::decoded_typed(&loaded).map_err(|e|anyhow!(e.category))?;
    let cwd=std::env::current_dir()?;
    let mut root=paths::data(&cwd)?;
    if let Some(storage)=raw.get("storage").filter(|v|!v.is_null()){
        let storage=storage.as_object().context("storage must be an object")?;
        ensure!(storage.keys().all(|key|matches!(key.as_str(),"module"|"root")),"unknown storage field");
        ensure!(storage.get("module").and_then(serde_json::Value::as_str)==Some("file_system"),"storage module unavailable");
        root=cwd.join(storage.get("root").filter(|v|!v.is_null()).map(|v|v.as_str().context("storage root must be text")).transpose()?.unwrap_or(""));
    }
    root=caddy_compat_native::process_path::resolve_application_root(&root)?;
    let storage_id=format!("{:x}",Sha256::digest(root.as_os_str().as_encoded_bytes()));
    let state=paths::config(&cwd)?.join("native-state/certificate-stores").join(storage_id);
    let store=FsStore::open(root.clone(),state)?;
    let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    if action=="import"{
        let reader:Box<dyn Read>=if stream_path==OsStr::new("-"){Box::new(std::io::stdin())}else{Box::new(std::fs::File::open(stream_path)?)};
        import(reader,&store,&runtime)?;
        println!("Successfully imported storage");
    }else{
        // A previous archive in the store could otherwise recursively export
        // itself. The archive is an external artifact, never a storage key.
        if stream_path!=OsStr::new("-"){
            let output=std::path::absolute(stream_path)?;
            let parent=std::fs::canonicalize(output.parent().context("archive has no parent")?)?;
            let output=parent.join(output.file_name().context("archive has no filename")?);
            ensure!(!output.starts_with(std::fs::canonicalize(&root)?),"storage archive must be outside storage root");
            let mut options=std::fs::OpenOptions::new();
            options.create(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK);
            let file=options.open(output)?;
            ensure!(file.metadata()?.is_file()&&file.metadata()?.nlink()==1,"archive output must be an unshared regular file");
            file.set_len(0)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            export(file,&store,&root,&runtime)?;
        }else{export(std::io::stdout().lock(),&store,&root,&runtime)?;}
    }
    Ok(0)
}

fn import(reader:Box<dyn Read>,store:&FsStore,runtime:&tokio::runtime::Runtime)->Result<()>{
    let mut archive=tar::Archive::new(reader);
    let mut count=0usize;let mut total=0u64;
    for entry in archive.entries()?{
        let mut entry=entry?;
        ensure!(entry.header().entry_type().is_file(),"storage archive must contain regular values only");
        count+=1;ensure!(count<=50_000,"storage archive entry limit exceeded");
        let size=entry.size();ensure!(size<=VALUE_LIMIT,"storage value size limit exceeded");
        total=total.checked_add(size).context("storage archive size overflow")?;
        ensure!(total<=TRANSFER_LIMIT,"storage archive total size limit exceeded");
        let key=entry.path_bytes();
        let key=std::str::from_utf8(&key).context("storage key must be UTF-8")?;
        ensure!(!key.is_empty()&&key.len()<=4096&&!key.contains('\\')
            &&!Path::new(key).is_absolute()
            &&Path::new(key).components().all(|p|matches!(p,std::path::Component::Normal(_))),"invalid storage archive key");
        let key=key.to_owned();
        let mut value=zeroize::Zeroizing::new(Vec::new());
        value.try_reserve_exact(usize::try_from(size)?)?;
        entry.read_to_end(&mut value)?;
        ensure!(value.len()as u64==size,"truncated storage value");
        runtime.block_on(store.import_offline_value(&key,&value))?;
    }
    Ok(())
}

fn export(writer:impl Write,store:&FsStore,root:&Path,runtime:&tokio::runtime::Runtime)->Result<()>{
    let keys=runtime.block_on(store.list("",true))?;
    let mut archive=tar::Builder::new(writer);let mut total=0u64;
    for key in keys{
        if key=="locks"||key.starts_with("locks/"){continue}
        let metadata=match std::fs::symlink_metadata(root.join(&key)){
            Ok(value)=>value,Err(e)if e.kind()==std::io::ErrorKind::NotFound=>continue,Err(e)=>return Err(e.into()),
        };
        if metadata.is_dir(){continue}
        ensure!(metadata.is_file(),"storage archive input must be regular");
        let Some(value)=runtime.block_on(store.load(&key))?else{continue};
        total=total.checked_add(value.len()as u64).context("storage archive size overflow")?;
        ensure!(total<=TRANSFER_LIMIT,"storage archive total size limit exceeded");
        let mut header=tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);header.set_mode(0o600);header.set_size(value.len()as u64);
        header.set_mtime(metadata.modified()?.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
        header.set_cksum();
        archive.append_data(&mut header,key,&value[..])?;
    }
    archive.finish()?;
    Ok(())
}
