//! A cancellable OS stdout owner. Only the native CLI registers this capability;
//! an embedded runtime never launches an unknown host executable.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
const FLAG: &str = "--internal-metrics-console-writer-v1";
const MAGIC: &[u8; 8] = b"CDMETR01";
const MAX: usize = 64 << 20;
static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
static SERIAL: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Native CLI startup only: call before runtime/configuration initialization.
/// The same executable must dispatch `native_console_entry` before any work.
#[doc(hidden)]
pub fn register_native_console_helper() -> Result<()> {
    let path = std::env::current_exe().context("native console executable unavailable")?;
    if let Some(previous) = EXECUTABLE.get() {
        ensure!(*previous == path, "console capability already registered");
    } else {
        let _ = EXECUTABLE.set(path);
    }
    Ok(())
}
/// Strict private protocol entry, before CLI environment files or runtimes.
#[doc(hidden)]
pub fn native_console_entry(args: &[OsString]) -> Option<i32> {
    if args.first().is_none_or(|v| v != FLAG) {
        return None;
    }
    if args.len() != 1 {
        return Some(2);
    }
    Some(if helper().is_ok() { 0 } else { 2 })
}
fn helper() -> std::io::Result<()> {
    use std::io::{Read, Write};
    let mut input = std::io::stdin().lock();
    let mut header = [0u8; 16];
    input.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(std::io::Error::other("invalid metrics protocol"));
    }
    let length = u64::from_be_bytes(header[8..].try_into().expect("fixed header"));
    if length > MAX as u64 {
        return Err(std::io::Error::other("metrics output too large"));
    }
    let mut output = std::io::stdout().lock();
    let mut left = length;
    let mut buffer = [0u8; 16 << 10];
    while left != 0 {
        let n = left.min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..n])?;
        output.write_all(&buffer[..n])?;
        left -= n as u64;
    }
    let mut extra = [0u8; 1];
    if input.read(&mut extra)? != 0 {
        return Err(std::io::Error::other("metrics protocol trailing bytes"));
    }
    output.flush()
}

pub(super) struct Batch {
    pub bytes: bytes::Bytes,
    /// Trace pins own this permit until their final CPU byte retirement.
    /// Ordinary metrics retain the original direct Batch owner.
    pub output: Option<OwnedSemaphorePermit>,
    pub credit: Arc<super::transport::Credit>,
    pub serial: OwnedSemaphorePermit,
}
pub(super) struct Writer {
    executable: PathBuf,
    cancel: CancellationToken,
    active: Arc<Mutex<Option<CancellationToken>>>,
    tasks: TaskTracker,
}
impl Writer {
    pub fn prepare() -> Result<Arc<Self>> {
        let executable = EXECUTABLE
            .get()
            .context("console exporter requires the native CLI console-writer capability")?
            .clone();
        Ok(Arc::new(Self {
            executable,
            cancel: CancellationToken::new(),
            active: Default::default(),
            tasks: TaskTracker::new(),
        }))
    }
    pub fn admit(&self) -> Result<OwnedSemaphorePermit> {
        ensure!(!self.cancel.is_cancelled(), "console exporter stopped");
        SERIAL
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .try_acquire_owned()
            .context("console writer occupied")
    }
    /// A bounded caller may await the single physical stdout owner without
    /// dropping a healthy batch merely because another exporter is writing.
    /// The caller retains its batch credits and its original absolute deadline.
    pub async fn admit_until(&self, deadline: tokio::time::Instant) -> Result<OwnedSemaphorePermit> {
        let serial=SERIAL.get_or_init(||Arc::new(Semaphore::new(1))).clone();
        tokio::select! { biased;
            _=self.cancel.cancelled()=>anyhow::bail!("console exporter stopped"),
            result=tokio::time::timeout_at(deadline,serial.acquire_owned())=>result.context("console admission deadline")?.context("console admission unavailable"),
        }
    }
    pub async fn send(&self, batch: Batch, timeout: Duration) -> Result<()> {
        ensure!(batch.bytes.len() <= MAX, "console output limit exceeded");
        let stop = self.cancel.child_token();
        *self.active.lock().unwrap_or_else(|e| e.into_inner()) = Some(stop.clone());
        let active = self.active.clone();
        let executable = self.executable.clone();
        let (mut sender, receiver) = oneshot::channel();
        // Dropping the JoinHandle never aborts the OS owner. Receiver loss,
        // stop, or absolute deadline all kill+wait before batch credits drop.
        self.tasks.spawn(async move {
            let result = own(executable, &batch, timeout, stop, &mut sender).await;
            active.lock().unwrap_or_else(|e| e.into_inner()).take();
            drop(batch);
            let _ = sender.send(result);
        });
        receiver.await.context("console owner unavailable")?
    }
    pub fn cancel_active(&self) {
        if let Some(active) = self
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            active.cancel();
        }
    }
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
async fn own(
    executable: PathBuf,
    batch: &Batch,
    timeout: Duration,
    stop: CancellationToken,
    sender: &mut oneshot::Sender<Result<()>>,
) -> Result<()> {
    use std::process::Stdio;
    let deadline = batch
        .credit
        .created
        .checked_add(timeout)
        .context("console timeout out of range")?;
    ensure!(
        tokio::time::Instant::now() < deadline,
        "console deadline elapsed"
    );
    let mut child = tokio::process::Command::new(executable)
        .arg(FLAG)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("console writer unavailable")?;
    let mut input = child.stdin.take().expect("piped input");
    let mut header = [0u8; 16];
    header[..8].copy_from_slice(MAGIC);
    header[8..].copy_from_slice(&(batch.bytes.len() as u64).to_be_bytes());
    let timer = tokio::time::sleep_until(deadline);
    tokio::pin!(timer);
    let sent = tokio::select! { biased;
        _ = stop.cancelled() => Err(anyhow::anyhow!("console export stopped")),
        _ = sender.closed() => Err(anyhow::anyhow!("console caller cancelled")),
        _ = &mut timer => Err(anyhow::anyhow!("console export deadline")),
        result = async { input.write_all(&header).await?; input.write_all(&batch.bytes).await?; input.shutdown().await } => result.map_err(Into::into),
    };
    drop(input);
    let result = if sent.is_ok() {
        tokio::select! { biased;
            _ = stop.cancelled() => Err(anyhow::anyhow!("console export stopped")),
            _ = sender.closed() => Err(anyhow::anyhow!("console caller cancelled")),
            _ = &mut timer => Err(anyhow::anyhow!("console export deadline")),
            result = child.wait() => match result { Ok(status) if status.success() => Ok(()), Ok(_) => Err(anyhow::anyhow!("console writer failed")), Err(error) => Err(error.into()) },
        }
    } else {
        sent
    };
    if result.is_err() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    // These fields deliberately remain borrowed/live through actual child wait.
    let _ = (&batch.output, &batch.serial);
    result
}
