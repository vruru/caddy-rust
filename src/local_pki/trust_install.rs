//! Explicit system/Java/NSS trust adapter. Discovery only reads the host.
//! Call `install` only where system trust changes have been authorized. Services
//! use noninteractive sudo; CLI callers may preauthenticate sudo separately.
#[path = "trust_java.rs"]
mod java;
use super::{
    TrustInstaller, material,
    trust_command::{self, Output},
};
use anyhow::{Result, anyhow, ensure};
use futures_util::{StreamExt, stream};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
enum Target {
    #[cfg(target_os = "linux")]
    System {
        directory: PathBuf,
        extension: &'static str,
        updater: PathBuf,
        args: Vec<OsString>,
        verifier: PathBuf,
    },
    #[cfg(target_os = "macos")]
    Mac {
        security: PathBuf,
    },
    Java {
        tool: PathBuf,
        store: PathBuf,
    },
    Nss {
        tool: PathBuf,
        database: PathBuf,
        format: &'static str,
    },
}
/// Native Unix trust installer. Targets are discovered from the original
/// platform locations, never supplied by untrusted application configuration.
/// Separate targets run concurrently; each actual store is globally serialized.
#[derive(Clone)]
pub struct SystemTrustInstaller {
    targets: Vec<Target>,
    pool: Arc<Semaphore>,
    sudo: Option<PathBuf>,
    deadline: Duration,
}
static LOCKS: OnceLock<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>> = OnceLock::new();
fn target_lock(key: String) -> Result<Arc<AsyncMutex<()>>> {
    let mut locks = LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| anyhow!("trust lock registry poisoned"))?;
    locks.retain(|_, v| v.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    ensure!(locks.len() < 4096, "trust target registry full");
    let lock = Arc::new(AsyncMutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    Ok(lock)
}
fn executable(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|p| p.join(name))
        .find_map(|p| {
            let m = fs::metadata(&p).ok()?;
            (m.is_file() && m.mode() & 0o111 != 0)
                .then(|| fs::canonicalize(p).ok())
                .flatten()
        })
}
fn root_secure(path: &Path) -> Result<()> {
    let path = fs::canonicalize(path)?;
    for ancestor in path.ancestors() {
        let metadata = fs::metadata(ancestor)?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "privileged trust path is not root controlled"
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn checked_anchor(directory: &Path, name: &str, extension: &str) -> Result<PathBuf> {
    root_secure(directory)?;
    let path = directory.join(format!("{}.{}", name.replace(' ', "_"), extension));
    match fs::symlink_metadata(&path) {
        Ok(m) => {
            ensure!(
                m.is_file() && !m.file_type().is_symlink(),
                "trust anchor is not a regular file"
            );
            root_secure(&path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(path)
}
impl SystemTrustInstaller {
    /// Read-only discovery; it neither starts Java nor writes any trust store.
    pub async fn discover() -> Result<Self> {
        let mut this = tokio::task::spawn_blocking(|| -> Result<Self> {
            let mut targets = Vec::new();
            #[cfg(target_os = "linux")]
            {
                let locations = [
                    (
                        "/etc/pki/ca-trust/source/anchors",
                        "pem",
                        "update-ca-trust",
                        vec!["extract"],
                    ),
                    (
                        "/usr/local/share/ca-certificates",
                        "crt",
                        "update-ca-certificates",
                        vec![],
                    ),
                    (
                        "/usr/share/pki/trust/anchors",
                        "crt",
                        "update-ca-certificates",
                        vec![],
                    ),
                    (
                        "/etc/ca-certificates/trust-source/anchors",
                        "crt",
                        "trust",
                        vec!["extract-compat"],
                    ),
                    ("/etc/ssl/certs", "crt", "trust", vec!["extract-compat"]),
                ];
                if let Some((directory, extension, command, args)) = locations
                    .into_iter()
                    .find(|(p, _, _, _)| Path::new(p).is_dir())
                {
                    if let (Some(updater), Some(verifier)) =
                        (executable(command), executable("openssl"))
                    {
                        root_secure(Path::new(directory))?;
                        root_secure(&updater)?;
                        root_secure(&verifier)?;
                        targets.push(Target::System {
                            directory: directory.into(),
                            extension,
                            updater,
                            args: args.into_iter().map(Into::into).collect(),
                            verifier,
                        });
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                let security = PathBuf::from("/usr/bin/security");
                root_secure(&security)?;
                targets.push(Target::Mac { security });
            }
            if let Some(home) = std::env::var_os("JAVA_HOME") {
                let home = PathBuf::from(home);
                let tool = home.join("bin/keytool");
                let current = home.join("lib/security/cacerts");
                let old = home.join("jre/lib/security/cacerts");
                let store = if old.is_file() { old } else { current };
                if tool.is_file() && store.is_file() {
                    targets.push(Target::Java {
                        tool: fs::canonicalize(tool)?,
                        store: fs::canonicalize(store)?,
                    });
                }
            }
            let sudo = executable("sudo");
            if let Some(sudo) = &sudo {
                root_secure(sudo)?;
            }
            let mut this = Self {
                targets,
                pool: Arc::new(Semaphore::new(8)),
                sudo,
                deadline: Duration::from_secs(30),
            };
            if let Some(tool) = executable("certutil") {
                this.add_nss(tool)?;
            }
            Ok(this)
        })
        .await??;
        #[cfg(target_os = "macos")]
        if !this.targets.iter().any(|t| matches!(t, Target::Nss { .. }))
            && let Some(brew) = executable("brew")
        {
            let output = trust_command::execute(
                &brew,
                &["--prefix".into(), "nss".into()],
                None,
                false,
                CancellationToken::new(),
                this.pool.clone(),
                this.deadline,
            )
            .await?;
            if output.status.success() {
                let tool =
                    PathBuf::from(String::from_utf8(output.stdout)?.trim()).join("bin/certutil");
                if tool.is_file() {
                    this.add_nss(fs::canonicalize(tool)?)?;
                }
            }
        }
        this.targets.shrink_to_fit();
        Ok(this)
    }
    fn add_nss(&mut self, tool: PathBuf) -> Result<()> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(());
        };
        let mut profiles = vec![home.join(".pki/nssdb")];
        match fs::read_dir(home.join(".mozilla/firefox")) {
            Ok(entries) => {
                for entry in entries.take(1025) {
                    ensure!(profiles.len() < 1024, "too many NSS profiles");
                    profiles.push(entry?.path());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        for profile in profiles {
            if !profile.is_dir() {
                continue;
            }
            let format = if profile.join("cert9.db").is_file() {
                "sql:"
            } else if profile.join("cert8.db").is_file() {
                "dbm:"
            } else {
                continue;
            };
            self.targets.push(Target::Nss {
                tool: tool.clone(),
                database: fs::canonicalize(profile)?,
                format,
            });
        }
        Ok(())
    }
    async fn command(
        &self,
        program: &Path,
        args: Vec<OsString>,
        input: Option<Vec<u8>>,
        mutating: bool,
        cancel: CancellationToken,
        privileged: bool,
    ) -> Result<Output> {
        if rustix::process::geteuid().is_root() {
            root_secure(program)?;
        }
        let (program, args) = if privileged {
            root_secure(program)?;
            if rustix::process::geteuid().is_root() {
                (program.to_path_buf(), args)
            } else {
                let sudo = self.sudo.clone().ok_or_else(|| {
                    anyhow!("trust installation requires permission; sudo unavailable")
                })?;
                root_secure(&sudo)?;
                let mut actual = vec!["-n".into(), "--".into(), program.as_os_str().to_owned()];
                actual.extend(args);
                (sudo, actual)
            }
        } else {
            (program.to_path_buf(), args)
        };
        trust_command::execute(
            &program,
            &args,
            input,
            mutating,
            cancel,
            self.pool.clone(),
            if mutating {
                self.deadline
            } else {
                self.deadline.max(Duration::from_secs(10))
            },
        )
        .await
    }
    async fn system_trusted(
        &self,
        target: &Target,
        certificate: &Root,
        cancel: CancellationToken,
    ) -> Result<bool> {
        match target {
            #[cfg(target_os = "linux")]
            Target::System { verifier, .. } => {
                let output = self
                    .command(
                        verifier,
                        vec![
                            "verify".into(),
                            certificate.temp.file.as_os_str().to_owned(),
                        ],
                        None,
                        false,
                        cancel,
                        false,
                    )
                    .await?;
                Ok(output.status.success()
                    && String::from_utf8_lossy(&output.stdout).trim()
                        == format!("{}: OK", certificate.temp.file.display()))
            }
            #[cfg(target_os = "macos")]
            Target::Mac { security } => Ok(self
                .command(
                    security,
                    vec![
                        "verify-cert".into(),
                        "-c".into(),
                        certificate.temp.file.as_os_str().to_owned(),
                        "-n".into(),
                        "-L".into(),
                    ],
                    None,
                    false,
                    cancel,
                    false,
                )
                .await?
                .status
                .success()),
            _ => Err(anyhow!("not a system trust target")),
        }
    }
    #[cfg(target_os = "linux")]
    async fn java_hook_guards(
        &self,
        cancel: CancellationToken,
    ) -> Result<Vec<tokio::sync::OwnedMutexGuard<()>>> {
        // Distribution system updaters can run a Java-keystore hook. These are
        // the same physical resource as the explicit Java backend. Order is
        // always system -> sorted Java; Java never waits for system.
        let mut keys = self
            .targets
            .iter()
            .filter_map(|target| match target {
                Target::Java { store, .. } => Some(format!("java:{}", store.display())),
                _ => None,
            })
            .collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        let mut guards = Vec::new();
        for key in keys {
            let lock = target_lock(key)?;
            let guard = tokio::select! {_=cancel.cancelled()=>return Err(anyhow!("system trust cancelled waiting for Java hook")),guard=lock.lock_owned()=>guard};
            guards.push(guard);
        }
        Ok(guards)
    }
    async fn install_target(
        &self,
        target: Target,
        certificate: Arc<Root>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let lock_key = match &target {
            #[cfg(target_os = "linux")]
            Target::System { .. } => "system".into(),
            #[cfg(target_os = "macos")]
            Target::Mac { .. } => "system".into(),
            Target::Java { store, .. } => format!("java:{}", store.display()),
            Target::Nss { database, .. } => format!("nss:{}", database.display()),
        };
        let lock = target_lock(lock_key)?;
        let _guard = tokio::select! {_=cancel.cancelled()=>return Err(anyhow!("trust installation cancelled")),g=lock.lock()=>g};
        ensure!(!cancel.is_cancelled(), "trust installation cancelled");
        match target {
            #[cfg(target_os = "linux")]
            Target::System {
                directory,
                extension,
                updater,
                args,
                verifier,
            } => {
                let file = certificate.temp.file.as_os_str().to_owned();
                let output = self
                    .command(
                        &verifier,
                        vec!["verify".into(), file],
                        None,
                        false,
                        cancel.clone(),
                        false,
                    )
                    .await?;
                if output.status.success()
                    && String::from_utf8_lossy(&output.stdout).trim()
                        == format!("{}: OK", certificate.temp.file.display())
                {
                    return Ok(());
                }
                let _java_hook_guards = self.java_hook_guards(cancel.clone()).await?;
                let destination = checked_anchor(&directory, &certificate.name, extension)?;
                let tee = executable("tee").ok_or_else(|| anyhow!("tee is unavailable"))?;
                let output = self
                    .command(
                        &tee,
                        vec!["--".into(), destination.into_os_string()],
                        Some(certificate.pem.clone()),
                        true,
                        cancel.clone(),
                        true,
                    )
                    .await?;
                success(output, "write system root")?;
                // Cancellation after writing an anchor is deliberately reported, never
                // mistaken for successful trust. The next invocation rechecks real trust.
                root_secure(&directory)?;
                success(
                    self.command(&updater, args, None, true, cancel.clone(), true)
                        .await?,
                    "update system trust",
                )?;
                let checked = self
                    .command(
                        &verifier,
                        vec![
                            "verify".into(),
                            certificate.temp.file.as_os_str().to_owned(),
                        ],
                        None,
                        false,
                        cancel,
                        false,
                    )
                    .await?;
                ensure!(
                    checked.status.success()
                        && String::from_utf8_lossy(&checked.stdout).trim()
                            == format!("{}: OK", certificate.temp.file.display()),
                    "system updater did not establish trust for this certificate"
                );
                Ok(())
            }
            #[cfg(target_os = "macos")]
            Target::Mac { security } => {
                let check = self
                    .command(
                        &security,
                        vec![
                            "verify-cert".into(),
                            "-c".into(),
                            certificate.temp.file.as_os_str().to_owned(),
                            "-n".into(),
                            "-L".into(),
                        ],
                        None,
                        false,
                        cancel.clone(),
                        false,
                    )
                    .await?;
                if check.status.success() {
                    return Ok(());
                }
                success(
                    self.command(
                        &security,
                        vec![
                            "add-trusted-cert".into(),
                            "-d".into(),
                            "-r".into(),
                            if certificate.self_signed {
                                "trustRoot".into()
                            } else {
                                "trustAsRoot".into()
                            },
                            "-k".into(),
                            "/Library/Keychains/System.keychain".into(),
                            certificate.temp.file.as_os_str().to_owned(),
                        ],
                        None,
                        true,
                        cancel,
                        true,
                    )
                    .await?,
                    "install Keychain root",
                )
            }
            Target::Java { tool, store } => {
                self.install_java(&tool, &store, certificate, cancel).await
            }
            Target::Nss {
                tool,
                database,
                format,
            } => {
                if rustix::process::geteuid().is_root() {
                    root_secure(&database)?;
                    for name in [
                        "cert9.db",
                        "cert8.db",
                        "key4.db",
                        "key3.db",
                        "pkcs11.txt",
                        "secmod.db",
                    ] {
                        let file = database.join(name);
                        if file.exists() {
                            root_secure(&file)?;
                        }
                    }
                }
                let db = format!("{format}{}", database.display());
                let check = vec![
                    "-V".into(),
                    "-d".into(),
                    db.clone().into(),
                    "-u".into(),
                    "L".into(),
                    "-n".into(),
                    certificate.name.clone().into(),
                ];
                if self
                    .command(&tool, check.clone(), None, false, cancel.clone(), false)
                    .await?
                    .status
                    .success()
                {
                    let exported = self
                        .command(
                            &tool,
                            vec![
                                "-L".into(),
                                "-d".into(),
                                db.clone().into(),
                                "-n".into(),
                                certificate.name.clone().into(),
                                "-a".into(),
                            ],
                            None,
                            false,
                            cancel.clone(),
                            false,
                        )
                        .await?;
                    ensure!(exported.status.success(), "NSS root export failed");
                    let stored = material::chain(&exported.stdout)?;
                    ensure!(
                        stored.len() == 1 && hex(&Sha256::digest(&stored[0])) == certificate.sha256,
                        "NSS alias refers to a different certificate"
                    );
                    return Ok(());
                }
                let add = vec![
                    "-A".into(),
                    "-d".into(),
                    db.into(),
                    "-t".into(),
                    "C,,".into(),
                    "-n".into(),
                    certificate.name.clone().into(),
                    "-i".into(),
                    certificate.temp.file.as_os_str().to_owned(),
                ];
                success(
                    self.command(&tool, add, None, true, cancel.clone(), false)
                        .await?,
                    "install NSS root",
                )?;
                success(
                    self.command(&tool, check, None, false, cancel, false)
                        .await?,
                    "verify NSS root",
                )
            }
        }
    }
}
fn matches_system(target: &Target) -> bool {
    match target {
        #[cfg(target_os = "linux")]
        Target::System { .. } => true,
        #[cfg(target_os = "macos")]
        Target::Mac { .. } => true,
        Target::Java { .. } | Target::Nss { .. } => false,
    }
}

impl TrustInstaller for SystemTrustInstaller {
    fn install<'a>(
        &'a self,
        root_pem: &'a [u8],
        cancel: CancellationToken,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            ensure!(!cancel.is_cancelled(), "trust installation cancelled");
            let input = root_pem.to_vec();
            let certificate =
                Arc::new(tokio::task::spawn_blocking(move || Root::parse(&input)).await??);
            let system = self
                .targets
                .iter()
                .find(|target| matches_system(target))
                .ok_or_else(|| anyhow!("no supported system trust backend discovered"))?;
            // Caddy skips the complete WithAll installation when its root is
            // already accepted by the system, including auxiliary stores.
            if self
                .system_trusted(system, &certificate, cancel.clone())
                .await?
            {
                return Ok(());
            }
            let mut jobs = stream::iter(self.targets.clone())
                .map(|target| self.install_target(target, certificate.clone(), cancel.clone()))
                .buffer_unordered(8);
            let mut errors = Vec::new();
            while let Some(result) = jobs.next().await {
                if let Err(error) = result {
                    errors.push(error.to_string());
                }
            }
            ensure!(
                errors.is_empty(),
                "trust installation incomplete: {}",
                errors.join("; ")
            );
            Ok(())
        })
    }
}
fn message(output: &Output) -> String {
    let mut bytes = output.stderr.clone();
    bytes.extend(&output.stdout);
    String::from_utf8_lossy(&bytes).chars().take(2048).collect()
}
fn success(output: Output, step: &str) -> Result<()> {
    ensure!(
        output.status.success(),
        "{step} failed: {}",
        message(&output)
    );
    Ok(())
}
struct Temp {
    directory: PathBuf,
    file: PathBuf,
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_dir(&self.directory);
    }
}
struct Root {
    #[cfg(target_os = "linux")]
    pem: Vec<u8>,
    name: String,
    #[cfg(target_os = "macos")]
    self_signed: bool,
    sha1: String,
    sha256: String,
    temp: Temp,
}
impl Root {
    fn parse(input: &[u8]) -> Result<Self> {
        let chain = material::chain(input)?;
        ensure!(
            chain.len() == 1,
            "trust installation requires exactly one root certificate"
        );
        let pair = material::Pair {
            explicit_anchor: true,
            chain_pem: input.to_vec(),
            private_key_pem: None,
        };
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?;
        material::validate(&pair, None, now, false)?;
        let der = &chain[0];
        let (_, cert) =
            x509_parser::parse_x509_certificate(der).map_err(|_| anyhow!("invalid trust root"))?;
        let cn = cert
            .subject()
            .iter_common_name()
            .last()
            .map(|a| dn_string(a.attr_value()))
            .transpose()?
            .unwrap_or_else(|| "Truststore Development CA".into());
        let serial = rsa::BigUint::from_bytes_be(cert.raw_serial()).to_str_radix(10);
        let name = format!("{cn} {serial}");
        ensure!(
            name.len() <= 240
                && !name
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\'))
                && !matches!(cn.as_str(), "." | ".."),
            "unsafe trust certificate alias"
        );
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", der.clone())).into_bytes();
        let mut random = [0; 16];
        aws_lc_rs::rand::SecureRandom::fill(&aws_lc_rs::rand::SystemRandom::new(), &mut random)
            .map_err(|_| anyhow!("trust temporary randomness failed"))?;
        let parent = fs::canonicalize(std::env::temp_dir())?;
        // A non-root caller can later publish through controlled sudo too.
        // Every ancestor must protect this directory from third-party rename.
        let uid = rustix::process::geteuid().as_raw();
        for ancestor in parent.ancestors() {
            let m = fs::metadata(ancestor)?;
            ensure!(
                (m.uid() == 0 || m.uid() == uid)
                    && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0),
                "unsafe privileged trust temporary directory"
            );
        }
        let directory = parent.join(format!("caddy-trust-{}", super::journal::hash(&random)));
        let mut builder = fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700).create(&directory)?;
        let temp = Temp {
            file: directory.join("root.pem"),
            directory,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&temp.file)?;
        file.write_all(&pem)?;
        file.sync_all()?;
        #[cfg(target_os = "macos")]
        let self_signed = cert.issuer().as_raw() == cert.subject().as_raw()
            && crate::cert_status::verify_x509_signature(
                cert.public_key(),
                &cert.signature_algorithm,
                &cert.signature_value.data,
                cert.tbs_certificate.as_ref(),
                true,
            )
            .is_ok();
        Ok(Self {
            #[cfg(target_os = "macos")]
            self_signed,
            #[cfg(target_os = "linux")]
            pem,
            name,
            sha1: hex(&Sha1::digest(der)),
            sha256: hex(&Sha256::digest(der)),
            temp,
        })
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
fn dn_string(value: &x509_parser::der_parser::asn1_rs::Any<'_>) -> Result<String> {
    use x509_parser::der_parser::asn1_rs::Tag;
    match value.tag() {
        Tag::T61String => Ok(value.data.iter().map(|b| char::from(*b)).collect()),
        Tag::BmpString => {
            ensure!(value.data.len().is_multiple_of(2), "invalid BMP name");
            String::from_utf16(
                &value
                    .data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|v| u16::from_be_bytes([v[0], v[1]]))
                    .collect::<Vec<_>>(),
            )
            .map_err(Into::into)
        }
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::NumericString => {
            Ok(std::str::from_utf8(value.data)?.into())
        }
        // Go preserves unfamiliar attribute tags as RawValue. An escaped alias
        // avoids rejecting an otherwise usable explicit trust anchor.
        _ => Ok(format!("#{}:{}", value.tag().0, hex(value.data))),
    }
}
