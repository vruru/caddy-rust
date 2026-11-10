//! Process-owned PID file, published before starting the application.
use super::*;
use std::os::unix::fs::MetadataExt;

pub(super) struct PidFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl PidFile {
    pub(super) fn publish(path: PathBuf) -> Result<Self> {
        let parent = path.parent().context("invalid PID file path")?;
        let name = path.file_name().context("invalid PID file path")?;
        let mut nonce = [0u8; 16];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut nonce)
            .map_err(|_| anyhow!("PID file nonce unavailable"))?;
        let mut temporary = OsString::from(".");
        temporary.push(name);
        temporary.push(format!(".{:032x}.tmp", u128::from_ne_bytes(nonce)));
        let temporary = parent.join(temporary);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&temporary)
            .context("creating PID file")?;
        let publication = (|| {
            write!(file, "{}", std::process::id())?;
            file.sync_all()?;
            let metadata = file.metadata()?;
            std::fs::rename(&temporary, &path)?;
            Ok(Self {
                path,
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
        })();
        if publication.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        publication
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == self.dev && metadata.ino() == self.ino)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
