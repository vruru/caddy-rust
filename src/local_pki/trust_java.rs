//! keytool writes only a private candidate. Publishing a validated candidate is
//! a same-filesystem atomic rename; killing keytool cannot truncate cacerts.
use super::{Root, SystemTrustInstaller, executable, message, root_secure, success};
use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};
const STORE_LIMIT: u64 = 16 * 1024 * 1024;
struct Candidate(PathBuf, Option<Arc<Root>>);
impl Drop for Candidate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _keep_alive = &self.1;
    }
}
struct Snapshot {
    bytes: Zeroizing<Vec<u8>>,
    hash: Vec<u8>,
    uid: u32,
    gid: u32,
    mode: u32,
    dev: u64,
}
fn snapshot(path: &Path) -> Result<Snapshot> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.len() <= STORE_LIMIT,
        "Java store is not a bounded regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(STORE_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= STORE_LIMIT, "Java store size changed");
    Ok(Snapshot {
        hash: Sha256::digest(&bytes).to_vec(),
        bytes,
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o777,
        dev: m.dev(),
    })
}
fn unchanged(path: &Path, old: &Snapshot) -> Result<()> {
    let now = snapshot(path)?;
    ensure!(
        now.hash == old.hash
            && now.uid == old.uid
            && now.gid == old.gid
            && now.mode == old.mode
            && now.dev == old.dev,
        "Java trust store changed outside this installer"
    );
    Ok(())
}
fn atomic_native(store: &Path, data: &[u8], old: &Snapshot, id: &str) -> Result<()> {
    unchanged(store, old)?;
    let directory = store
        .parent()
        .ok_or_else(|| anyhow!("Java store has no parent"))?;
    ensure!(
        fs::metadata(directory)?.dev() == old.dev,
        "Java store requires same-filesystem atomic publication"
    );
    let temporary_path = directory.join(format!(".caddy-trust-{id}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&temporary_path)?;
    let temporary = Candidate(temporary_path, None);
    file.write_all(data)?;
    rustix::fs::fchown(
        &file,
        if rustix::process::geteuid().is_root() {
            Some(rustix::fs::Uid::from_raw(old.uid))
        } else {
            None
        },
        Some(rustix::fs::Gid::from_raw(old.gid)),
    )?;
    file.set_permissions(fs::Permissions::from_mode(old.mode))?;
    file.sync_all()?;
    unchanged(store, old)?;
    fs::rename(&temporary.0, store)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
impl SystemTrustInstaller {
    pub(super) async fn install_java(
        &self,
        tool: &Path,
        store: &Path,
        root: Arc<Root>,
        cancel: CancellationToken,
    ) -> Result<()> {
        // A trusted keytool must validate any candidate later published with
        // privilege. Never turn JAVA_HOME -> user tool -> sudo mv into an
        // arbitrary privileged-file replacement capability.
        if rustix::process::geteuid().is_root()
            || fs::metadata(store)?.uid() != rustix::process::geteuid().as_raw()
        {
            root_secure(tool)?;
            root_secure(store)?;
        }
        let args = vec![
            "-list".into(),
            "-keystore".into(),
            store.as_os_str().to_owned(),
            "-storepass".into(),
            "changeit".into(),
        ];
        let listed = self
            .command(tool, args, None, false, cancel.clone(), false)
            .await?;
        ensure!(
            listed.status.success(),
            "Java trust listing failed: {}",
            message(&listed)
        );
        let mut text = listed.stdout;
        text.extend(listed.stderr);
        let text = String::from_utf8_lossy(&text)
            .replace(':', "")
            .to_uppercase();
        if text.contains(&root.sha1) || text.contains(&root.sha256) {
            return Ok(());
        }
        let path = store.to_path_buf();
        let candidate_path = root.temp.directory.join("java-cacerts");
        let path_for_copy = candidate_path.clone();
        let holder = root.clone();
        let (old, candidate) =
            tokio::task::spawn_blocking(move || -> Result<(Snapshot, Candidate)> {
                let old = snapshot(&path)?;
                let mut copy = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                    .open(&path_for_copy)?;
                let candidate = Candidate(path_for_copy, Some(holder));
                copy.write_all(&old.bytes)?;
                copy.sync_all()?;
                Ok((old, candidate))
            })
            .await??;
        let args = vec![
            "-importcert".into(),
            "-noprompt".into(),
            "-keystore".into(),
            candidate.0.as_os_str().to_owned(),
            "-storepass".into(),
            "changeit".into(),
            "-file".into(),
            root.temp.file.as_os_str().to_owned(),
            "-alias".into(),
            root.name.clone().into(),
        ];
        success(
            self.command(tool, args, None, true, cancel.clone(), false)
                .await?,
            "import Java candidate",
        )?;
        let args = vec![
            "-list".into(),
            "-v".into(),
            "-alias".into(),
            root.name.clone().into(),
            "-keystore".into(),
            candidate.0.as_os_str().to_owned(),
            "-storepass".into(),
            "changeit".into(),
        ];
        let checked = self
            .command(tool, args, None, false, cancel.clone(), false)
            .await?;
        ensure!(
            checked.status.success(),
            "Java candidate verification failed"
        );
        let mut checked_text = checked.stdout;
        checked_text.extend(checked.stderr);
        ensure!(
            String::from_utf8_lossy(&checked_text)
                .replace(':', "")
                .to_uppercase()
                .contains(&root.sha256),
            "Java candidate fingerprint mismatch"
        );
        ensure!(
            !cancel.is_cancelled(),
            "Java installation cancelled before publication"
        );
        let candidate_path = candidate.0.clone();
        let data = tokio::task::spawn_blocking(move || snapshot(&candidate_path)).await??;
        let data = data.bytes;
        let id = root
            .temp
            .directory
            .file_name()
            .ok_or_else(|| anyhow!("missing candidate identity"))?
            .to_string_lossy()
            .to_string();
        if rustix::process::geteuid().is_root() || old.uid == rustix::process::geteuid().as_raw() {
            let path = store.to_path_buf();
            tokio::task::spawn_blocking(move || atomic_native(&path, &data, &old, &id)).await??;
            return Ok(());
        }
        // Non-root installations retain the original sudo capability, but keytool
        // never runs privileged and never edits the active store in place.
        root_secure(store)?;
        let directory = store
            .parent()
            .ok_or_else(|| anyhow!("Java store has no parent"))?;
        ensure!(
            fs::metadata(directory)?.dev() == old.dev,
            "Java store cannot be atomically published"
        );
        let mktemp = executable("mktemp").ok_or_else(|| anyhow!("mktemp unavailable"))?;
        let output = self
            .command(
                &mktemp,
                vec![
                    directory
                        .join(format!(".caddy-trust-{id}.XXXXXX"))
                        .into_os_string(),
                ],
                None,
                true,
                cancel.clone(),
                true,
            )
            .await?;
        ensure!(
            output.status.success(),
            "Java protected staging creation failed"
        );
        let staging = PathBuf::from(String::from_utf8(output.stdout)?.trim());
        ensure!(
            staging.parent() == Some(directory)
                && staging.file_name().is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with(&format!(".caddy-trust-{id}."))),
            "unexpected protected Java stage"
        );
        root_secure(&staging)?;
        let publication: Result<()> = async {
            let tee = executable("tee").ok_or_else(|| anyhow!("tee unavailable"))?;
            let mut output = self
                .command(
                    &tee,
                    vec!["--".into(), staging.as_os_str().to_owned()],
                    Some(data.to_vec()),
                    true,
                    cancel.clone(),
                    true,
                )
                .await?;
            output.stdout.zeroize();
            output.stdout.clear();
            success(output, "write protected Java candidate")?;
            let chmod = executable("chmod").ok_or_else(|| anyhow!("chmod unavailable"))?;
            success(
                self.command(
                    &chmod,
                    vec![
                        format!("{:o}", old.mode).into(),
                        staging.as_os_str().to_owned(),
                    ],
                    None,
                    true,
                    cancel.clone(),
                    true,
                )
                .await?,
                "set Java candidate permissions",
            )?;
            let chown = executable("chown").ok_or_else(|| anyhow!("chown unavailable"))?;
            success(
                self.command(
                    &chown,
                    vec![
                        format!("{}:{}", old.uid, old.gid).into(),
                        staging.as_os_str().to_owned(),
                    ],
                    None,
                    true,
                    cancel.clone(),
                    true,
                )
                .await?,
                "set Java candidate ownership",
            )?;
            let stage_for_sync = staging.clone();
            tokio::task::spawn_blocking(move || fs::File::open(stage_for_sync)?.sync_all())
                .await??;
            let path = store.to_path_buf();
            tokio::task::spawn_blocking(move || unchanged(&path, &old)).await??;
            let mv = executable("mv").ok_or_else(|| anyhow!("mv unavailable"))?;
            success(
                self.command(
                    &mv,
                    vec![
                        "-f".into(),
                        "--".into(),
                        staging.as_os_str().to_owned(),
                        store.as_os_str().to_owned(),
                    ],
                    None,
                    true,
                    cancel.clone(),
                    true,
                )
                .await?,
                "publish Java candidate",
            )?;
            Ok(())
        }
        .await;
        let rm =
            executable("rm").ok_or_else(|| anyhow!("rm unavailable for Java staging cleanup"))?;
        let cleanup = self
            .command(
                &rm,
                vec!["-f".into(), "--".into(), staging.into_os_string()],
                None,
                true,
                CancellationToken::new(),
                true,
            )
            .await
            .and_then(|v| success(v, "cleanup protected Java stage"));
        publication?;
        cleanup?;
        let parent = directory.to_path_buf();
        tokio::task::spawn_blocking(move || fs::File::open(parent)?.sync_all()).await??;
        Ok(())
    }
}
