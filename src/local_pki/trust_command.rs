//! Bounded noninteractive commands. Never invoke a shell or detach a child.
use anyhow::{Result, anyhow, ensure};
use rustix::process::{Pid, Signal, kill_process_group};
use std::{
    ffi::OsString,
    path::Path,
    process::{ExitStatus, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

pub(super) struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
struct KillGroup(Option<Pid>);
impl KillGroup {
    fn signal(&self, s: Signal) {
        if let Some(pid) = self.0 {
            let _ = kill_process_group(pid, s);
        }
    }
}
impl Drop for KillGroup {
    fn drop(&mut self) {
        self.signal(Signal::KILL);
    }
}
enum Pipe {
    Out(Vec<u8>),
    Err(Vec<u8>),
    Input,
}
async fn drain(mut pipe: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut bytes = [0; 8192];
    loop {
        let n = pipe.read(&mut bytes).await?;
        if n == 0 {
            break;
        }
        let keep = n.min((65536_usize).saturating_sub(result.len()));
        result.extend_from_slice(&bytes[..keep]);
    }
    Ok(result)
}
pub(super) async fn execute(
    program: &Path,
    args: &[OsString],
    input: Option<Vec<u8>>,
    mutating: bool,
    cancel: CancellationToken,
    pool: Arc<Semaphore>,
    deadline: Duration,
) -> Result<Output> {
    let _permit = tokio::select! {_=cancel.cancelled()=>return Err(anyhow!("trust command cancelled before admission")),v=pool.acquire()=>v?};
    ensure!(
        !cancel.is_cancelled(),
        "trust command cancelled before spawn"
    );
    let mut command = Command::new(program);
    command
        .env_clear()
        .args(args)
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    command.as_std_mut().process_group(0);
    let mut child = command.spawn()?;
    let pid = Pid::from_raw(i32::try_from(
        child
            .id()
            .ok_or_else(|| anyhow!("trust child has no PID"))?,
    )?)
    .ok_or_else(|| anyhow!("invalid trust child PID"))?;
    let mut group = KillGroup(Some(pid));
    let mut pipes = JoinSet::new();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("stderr unavailable"))?;
    pipes.spawn(async move { Ok::<_, anyhow::Error>(Pipe::Out(drain(stdout).await?)) });
    pipes.spawn(async move { Ok::<_, anyhow::Error>(Pipe::Err(drain(stderr).await?)) });
    if let Some(input) = input {
        let input = zeroize::Zeroizing::new(input);
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("stdin unavailable"))?;
        pipes.spawn(async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok(Pipe::Input)
        });
    }
    let mut stopped = None;
    let status = tokio::select! {
     result=child.wait()=>result,
     _=cancel.cancelled(),if !mutating=>{stopped=Some("trust command cancelled");group.signal(Signal::TERM);tokio::time::sleep(Duration::from_secs(2)).await;group.signal(Signal::KILL);child.wait().await},
     _=tokio::time::sleep(deadline)=>{stopped=Some("trust command deadline exceeded");group.signal(Signal::TERM);tokio::time::sleep(Duration::from_secs(2)).await;group.signal(Signal::KILL);child.wait().await}
    };
    // The leader has been reaped: never signal this PID again.
    if status.is_ok() {
        group.0 = None;
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut pipe_error = None;
    let joined = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(result) = pipes.join_next().await {
            match result {
                Ok(Ok(Pipe::Out(v))) => out = v,
                Ok(Ok(Pipe::Err(v))) => err = v,
                Ok(Ok(Pipe::Input)) => {}
                Ok(Err(e)) => pipe_error = Some(e),
                Err(e) => pipe_error = Some(e.into()),
            }
        }
    })
    .await;
    if joined.is_err() {
        pipes.abort_all();
        while pipes.join_next().await.is_some() {}
        return Err(anyhow!(
            "trust pipes remained open: possible_leaked_privileged_child"
        ));
    }
    let status = status?;
    if let Some(reason) = stopped {
        return Err(anyhow!(reason));
    }
    if let Some(error) = pipe_error {
        return Err(error.context("trust command pipe failed"));
    }
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}
use std::os::unix::process::CommandExt;
