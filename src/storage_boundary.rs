//! Shared, narrow traversal rule for private stores on mounted filesystems.
//! This never authorizes writes inside a shared mount root: every caller must
//! immediately require a private user-owned directory before continuing.
use rustix::fs::{FileType,Stat};
pub(crate) fn shared_mount_root(parent:&Stat,child:&Stat)->bool {
    FileType::from_raw_mode(child.st_mode)==FileType::Directory
        && child.st_uid==0 && child.st_mode&0o002==0
        && child.st_mode&0o020!=0 && child.st_dev!=parent.st_dev
}
pub(crate) fn private_anchor(st:&Stat,uid:u32)->bool {
    FileType::from_raw_mode(st.st_mode)==FileType::Directory
        && st.st_uid==uid && st.st_mode&0o077==0
}

/// Sticky shared parents (for example /tmp) prevent other users from replacing
/// the next component. Only trusted ownership and an immediate private anchor
/// make traversal admissible; this never permits using that parent as a store.
pub(crate) fn sticky_parent(st:&Stat,uid:u32)->bool {
    FileType::from_raw_mode(st.st_mode)==FileType::Directory
        && (st.st_uid==0 || st.st_uid==uid) && st.st_mode&0o1000!=0
}

/// macOS exposes protected system directories through root-owned aliases.
/// Resolve only these fixed first components, never an arbitrary user symlink.
/// The caller still opens and validates every resulting directory with NOFOLLOW.
pub(crate) fn system_absolute(path:&std::path::Path)->std::io::Result<std::borrow::Cow<'_,std::path::Path>> {
    #[cfg(target_os="macos")]
    {
        use std::os::unix::fs::MetadataExt;
        for (alias,target) in [("/var","/private/var"),("/tmp","/private/tmp"),("/etc","/private/etc")] {
            if let Ok(rest)=path.strip_prefix(alias) {
                let parent=std::fs::symlink_metadata("/")?;
                let link=std::fs::symlink_metadata(alias)?;
                if parent.uid()!=0 || parent.mode()&0o022!=0 || link.uid()!=0
                    || !link.file_type().is_symlink() {
                    return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,"untrusted system directory alias"));
                }
                let destination=std::fs::read_link(alias)?;
                if destination!=std::path::Path::new(target)
                    && destination!=std::path::Path::new(target.trim_start_matches('/')) {
                    return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,"untrusted system directory alias"));
                }
                return Ok(std::borrow::Cow::Owned(std::path::Path::new(target).join(rest)));
            }
        }
    }
    Ok(std::borrow::Cow::Borrowed(path))
}
