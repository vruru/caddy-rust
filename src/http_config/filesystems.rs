//! Standard filesystem application. The standard module inventory registers
//! no caddy.fs backend; its default filesystem is the local OS filesystem.
use super::*;

pub(super) fn validate(value:Option<&Value>)->Result<()> {
    let Some(value)=value.filter(|v|!v.is_null())else{return Ok(())};
    let app=object(value,"/apps/caddy.filesystems")?;
    deny_unknown(app,&["filesystems"],"/apps/caddy.filesystems")?;
    let Some(entries)=app.get("filesystems").filter(|v|!v.is_null())else{return Ok(())};
    let entries=entries.as_array().ok_or_else(||anyhow::anyhow!("filesystem entries must be an array"))?;
    ensure!(entries.len()<=1024,"filesystem entry count exceeds limit");
    for entry in entries {
        let entry=object(entry,"filesystem entry")?;
        deny_unknown(entry,&["name","file_system"],"filesystem entry")?;
        if let Some(name)=entry.get("name").filter(|v|!v.is_null()) {
            let name=string(name,"filesystem name")?;
            ensure!(name.len()<=4096,"filesystem name exceeds limit");
        }
        if let Some(backend)=entry.get("file_system").filter(|v|!v.is_null()) {
            // Missing implementations stay closed. A nil entry merely removes
            // that name; removing default restores the standard OS fallback.
            object(backend,"filesystem backend")?;
            return Err(unsupported("/apps/caddy.filesystems/filesystems/file_system/backend"));
        }
    }
    Ok(())
}
