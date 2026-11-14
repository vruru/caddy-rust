//! Narrow safe-UTF8 global ReplaceKnown entry for Provision leaf inputs.
use anyhow::{Result,ensure};
use std::path::Path;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
pub(crate) struct Expanded {bytes:Zeroizing<Vec<u8>>,_memory:super::manual_values::ScratchBudget}
impl Expanded {pub(crate) fn as_bytes(&self)->&[u8]{&self.bytes}}
pub(crate) fn expand(raw:&str,cwd:&Path,cancel:&CancellationToken)->Result<Expanded>{
    let mut memory=super::manual_values::ScratchBudget::new();
    let bytes=crate::http_config::helpers::replace_secret_bytes_accounted(raw,false,16<<20,16<<20,|name|{
        ensure!(!cancel.is_cancelled(),"leaf input preparation cancelled");
        if let Some(path)=name.strip_prefix("file."){super::manual_values::lookup_file(path,cwd)}
        else{super::manual_values::lookup_global(name)}
    },|capacity|memory.grow(capacity))?;
    Ok(Expanded{bytes,_memory:memory})
}

pub(crate) fn open(bytes:&[u8],cwd:&Path)->Result<std::fs::File>{
    let path=super::manual_values::path(bytes,cwd)?;
    Ok(crate::http_config::helpers::open_regular_file(path.path.as_path())?)
}
