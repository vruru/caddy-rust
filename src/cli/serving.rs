//! Opt-in native process lifecycle, using the same transaction path as Admin.
use super::*;
use caddy_compat_native::{
    admin::{AdminBackend, AdminController, AdminOptions, AdminStopOutcome, StopMode},
    root_backend::{NativeBackend, RootOptions},
    tls_app_config::CertificatePaths,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    signal::unix::{Signal, SignalKind, signal},
};
use tokio_util::sync::CancellationToken;
#[path = "serve_client.rs"]
mod client;
#[path = "file_limit.rs"]
mod file_limit;
#[path = "serving_flags.rs"]
mod flags;
#[path = "serve_pid.rs"]
mod pid;

pub(super) fn specs(name: &str) -> Option<Vec<Flag>> {
    flags::specs(name)
}

pub(super) fn help(name: &str) {
    let extra = match name {
        "run" => "[--envfile PATH] [--environ] [--resume] [--watch] [--pidfile PATH]",
        "start" => "[--envfile PATH] [--watch] [--pidfile PATH]",
        "reload" => "[--address ADDR] [--force]",
        _ => "[--address ADDR]",
    };
    println!("Usage: caddy-compat-native {name} [--config PATH] [--adapter NAME] {extra}");
}

/// # Safety
/// The executable must call this before worker threads or runtimes start.
pub(super) unsafe fn command(name: &str, parsed: args::Flags) -> Result<i32> {
    if parsed.boolean("help") {
        help(name);
        return Ok(0);
    }
    ensure!(parsed.positional.is_empty(), "unexpected serving argument");
    match name {
        "run" => {
            // SAFETY: this private dispatch is called in the early startup boundary.
            unsafe {
                environment(parsed.list("envfile"))?;
            }
            run(parsed)
        }
        "start" => start(parsed),
        "stop" | "reload" => client::command(name, parsed),
        _ => bail!("unknown serving command"),
    }
}

fn parse_run(bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    admin_json::decoded(bytes).map_err(|e| anyhow!(e.category))
}

#[derive(Clone)]
struct Source {
    path: PathBuf,
    adapter: Option<String>,
    initial: [u8; 32],
}

fn run(parsed: args::Flags) -> Result<i32> {
    caddy_compat_native::process_notify::initialize();
    let pingback = nonempty(parsed.text("pingback"));
    ensure!(
        pingback.is_none() || nonempty(parsed.text("config")) != Some(OsStr::new("-")),
        "readiness and stdin configuration cannot share stdin"
    );
    let limits = file_limit::prepare_open_file_limit()?;
    if let Some(error) = limits.set_error_code {
        eprintln!("run event=descriptor_limit_unchanged errno={error}");
    }
    if parsed.boolean("environ") {
        for (key, value) in std::env::vars_os() {
            println!("{}={}", key.to_string_lossy(), value.to_string_lossy());
        }
    }
    let cwd = std::env::current_dir().context("capturing application directory")?;
    let config_dir = paths::config(&cwd)?;
    let autosave = config_dir.join("autosave.json");
    let resumed = if parsed.boolean("resume") {
        caddy_compat_native::admin::read_autosave(&autosave)?
    } else {
        None
    };
    let (raw, source) = if let Some(raw) = resumed {
        if nonempty(parsed.text("config")).is_some() {
            eprintln!("run event=resume_ignored_config_flag");
        }
        (raw, None)
    } else {
        let loaded = config::load_with_source(parsed.text("config"), parsed.text("adapter"))?;
        let raw = parse_run(&loaded.bytes)?;
        let source = loaded
            .path
            .filter(|p| p != Path::new("-"))
            .map(|path| Source {
                path,
                adapter: loaded.adapter,
                initial: Sha256::digest(&*loaded.bytes).into(),
            });
        (raw, source)
    };
    let ready = pingback
        .map(|raw| -> Result<Ready> {
            let address = raw
                .to_str()
                .context("invalid readiness address")?
                .parse::<SocketAddr>()
                .context("invalid readiness address")?;
            ensure!(
                address.ip().is_loopback(),
                "readiness address must be loopback"
            );
            let mut nonce = zeroize::Zeroizing::new([0u8; 32]);
            std::io::stdin()
                .lock()
                .read_exact(&mut *nonce)
                .context("reading readiness nonce")?;
            Ok((address, nonce))
        })
        .transpose()?;
    caddy_compat_native::admin::capture_inherited(&raw)?;
    caddy_compat_native::crypto::install_default()?;
    let pidfile = nonempty(parsed.text("pidfile")).map(|path| cwd.join(path));
    let root = Arc::new(NativeBackend::new(RootOptions {
        paths: CertificatePaths {
            default_storage: paths::data(&cwd)?,
            state_root: config_dir.join("native-state"),
            cwd: cwd.clone(),
        },
        trust_installer: None,
    })?);
    let runtime = caddy_compat_native::runtime::build()?;
    let result = runtime.block_on(supervise(
        root,
        RunSetup {
            raw,
            autosave,
            cwd,
            source,
            watch: parsed.boolean("watch"),
            ready,
            pidfile,
        },
    ));
    // Bounded runtime teardown after application owners have joined. A stuck
    // OS blocking syscall is not reported as a clean application drain.
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

struct Signals {
    interrupt: Signal,
    term: Signal,
    quit: Signal,
    usr1: Signal,
    _hup: Signal,
    _usr2: Signal,
}
enum Event {
    Interrupt,
    Terminate,
    Force,
    Reload,
}
impl Signals {
    fn new() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            term: signal(SignalKind::terminate())?,
            quit: signal(SignalKind::quit())?,
            usr1: signal(SignalKind::user_defined1())?,
            _hup: signal(SignalKind::hangup())?,
            _usr2: signal(SignalKind::user_defined2())?,
        })
    }
    async fn next(&mut self) -> Event {
        tokio::select! {biased;
            _=self.quit.recv()=>Event::Force,
            _=self.interrupt.recv()=>Event::Interrupt,
            _=self.term.recv()=>Event::Terminate,
            _=self.usr1.recv()=>Event::Reload,
        }
    }
}

type Ready = (SocketAddr, zeroize::Zeroizing<[u8; 32]>);

struct RunSetup {
    raw: serde_json::Value,
    autosave: PathBuf,
    cwd: PathBuf,
    source: Option<Source>,
    watch: bool,
    ready: Option<Ready>,
    pidfile: Option<PathBuf>,
}
async fn supervise(root: Arc<NativeBackend>, setup: RunSetup) -> Result<i32> {
    let RunSetup {
        raw,
        autosave,
        cwd,
        source,
        watch,
        ready,
        pidfile,
    } = setup;
    let mut signals = Signals::new()?;
    // Signal handling is installed before the owned PID file becomes visible.
    let _pid = pidfile.and_then(|path| match pid::PidFile::publish(path) {
        Ok(owner) => Some(owner),
        Err(_) => {
            eprintln!("run event=pidfile_failed");
            None
        }
    });
    let controller = AdminController::new_with_source(
        raw,
        AdminOptions {
            autosave: Some(autosave),
            ..AdminOptions::default()
        },
        root.clone(),
        source
            .as_ref()
            .map(|s| (cwd, s.path.clone(), s.adapter.clone())),
    )?;
    let mut stops = controller.stop_events();
    caddy_compat_native::process_notify::send(caddy_compat_native::process_notify::State::Reloading).await;
    let startup = controller.start();
    tokio::pin!(startup);
    loop {
        tokio::select! {
            event=signals.next()=>match event {
                Event::Force=>return force(&controller).await,
                Event::Interrupt|Event::Terminate=>{
                    let first_interrupt=matches!(event,Event::Interrupt);
                    return drain(&controller,&root,&mut signals,first_interrupt).await;
                }
                Event::Reload=>{},
            },
            result=&mut startup=>{
                if let Err(error)=result {
                    caddy_compat_native::process_notify::send(caddy_compat_native::process_notify::State::ReloadFailed).await;
                    let (_,_) = tokio::join!(controller.shutdown(),root.stop(StopMode::Force));
                    return Err(error.into());
                }
                break;
            }
        }
    }
    if let Some((address, nonce)) = ready {
        let ping = tokio::time::timeout(Duration::from_secs(3), async {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            socket.write_all(&*nonce).await?;
            socket.shutdown().await
        })
        .await;
        if !matches!(ping, Ok(Ok(()))) {
            let (_, _) = tokio::join!(controller.shutdown(), root.stop(StopMode::Force));
            bail!("failed to report native startup readiness");
        }
    }
    caddy_compat_native::process_notify::send(caddy_compat_native::process_notify::State::Ready).await;
    eprintln!("run event=serving_initial_configuration");
    let cancel = CancellationToken::new();
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
    let watcher = source.map(|source| {
        tokio::spawn(watch_source(
            controller.clone(),
            source,
            watch,
            reload_rx,
            cancel.clone(),
        ))
    });
    let mut forced = false;
    let terminal: Result<i32> = loop {
        tokio::select! {biased;
            event=signals.next()=>match event {
                Event::Reload=>{ let _=reload_tx.try_send(()); },
                Event::Force=>{forced=true;cancel.cancel();break force(&controller).await;},
                Event::Interrupt|Event::Terminate=>{
                    cancel.cancel();
                    let first_interrupt=matches!(event,Event::Interrupt);
                    break drain(&controller,&root,&mut signals,first_interrupt).await;
                },
            },
            changed=stops.changed()=>{
                if changed.is_err() {
                    cancel.cancel();
                    let _=force(&controller).await;
                    break Err(anyhow!("admin stop status unavailable"));
                }
                let observed=*stops.borrow_and_update();
                match observed {
                    Some(AdminStopOutcome::Complete)=>break Ok(0),
                    Some(_)=>{
                        let _=root.stop(StopMode::Force).await;
                        break Err(anyhow!("native shutdown did not complete cleanly"));
                    }
                    None=>{}
                }
            }
        }
    };
    cancel.cancel();
    if let Some(watcher) = watcher {
        if forced || terminal.as_ref().is_ok_and(|code| *code == 2) {
            watcher.abort();
        }
        let _ = watcher.await;
    }
    terminal
}

async fn drain(
    controller: &AdminController,
    root: &NativeBackend,
    signals: &mut Signals,
    mut interrupted: bool,
) -> Result<i32> {
    caddy_compat_native::process_notify::send(caddy_compat_native::process_notify::State::Stopping).await;
    let owned = async {
        let (admin, application) = tokio::join!(controller.shutdown(), root.stop_unbounded());
        admin?;
        application?;
        Ok(0)
    };
    tokio::pin!(owned);
    loop {
        tokio::select! { biased;
            event=signals.next()=> match event {
                Event::Force=>return force(controller).await,
                Event::Interrupt if interrupted=>return force(controller).await,
                Event::Interrupt=>interrupted=true,
                Event::Reload|Event::Terminate=>{}
            },
            outcome=&mut owned=>return outcome,
        }
    }
}

async fn force(controller: &AdminController) -> Result<i32> {
    caddy_compat_native::process_notify::send(caddy_compat_native::process_notify::State::Stopping).await;
    if controller.force_shutdown().await.is_err() {
        eprintln!("run event=forced_shutdown_incomplete");
    }
    Ok(2)
}

async fn watch_source(
    controller: AdminController,
    source: Source,
    watch: bool,
    mut reload: tokio::sync::mpsc::Receiver<()>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous = source.initial;
    let mut file_error = false;
    let mut transient = None;
    loop {
        let force = tokio::select! {biased;
            _=cancel.cancelled()=>return,
            request=reload.recv()=>match request {Some(())=>true,None=>return},
            _=ticker.tick(), if watch=>false,
        };
        if !controller.source_active() {
            return;
        }
        let path = source.path.clone();
        let adapter = source.adapter.clone();
        let job = tokio::task::spawn_blocking(move || {
            let loaded = config::load_with_source(
                Some(path.as_os_str()),
                adapter.as_deref().map(OsStr::new),
            )?;
            let digest = Sha256::digest(&*loaded.bytes).into();
            Ok::<_, anyhow::Error>((digest, parse_run(&loaded.bytes)?))
        });
        let loaded = tokio::select! {biased;
            _=cancel.cancelled()=>return,
            loaded=job=>loaded,
        };
        let Ok(Ok((digest, raw))) = loaded else {
            if !file_error || force {
                eprintln!("run event=source_read_failed");
            }
            file_error = true;
            continue;
        };
        file_error = false;
        if !force && digest == previous {
            continue;
        }
        match controller.reload_from_source(raw, force).await {
            Ok(()) => {
                previous = digest;
                transient = None;
            }
            Err(error) if error.category == "process_config_source_changed" => return,
            Err(error) if (400..500).contains(&error.status) => {
                previous = digest;
                transient = None;
                eprintln!("run event=source_reload_rejected");
            }
            Err(_) if force && (!watch || digest == previous) => {
                // A one-shot signal is not requeued when there is no changed
                // file for the watcher to apply on its next tick.
                eprintln!("run event=source_reload_failed");
            }
            Err(_) => {
                // A transient admission or publication error must not mark
                // an unchanged file as already applied. Coalesce diagnostics
                // while the one watcher retries at its existing cadence.
                if transient != Some(digest) {
                    eprintln!("run event=source_reload_retry_pending");
                    transient = Some(digest);
                }
            }
        }
    }
}

fn start(parsed: args::Flags) -> Result<i32> {
    ensure!(
        nonempty(parsed.text("config")) != Some(OsStr::new("-")),
        "background start requires a file, not stdin"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(_) => tokio::net::TcpListener::bind("[::1]:0").await?,
        };
        let mut nonce = zeroize::Zeroizing::new([0u8; 32]);
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut *nonce)
            .map_err(|_| anyhow!("readiness nonce unavailable"))?;
        let mut command = tokio::process::Command::new(std::env::current_exe()?);
        command
            .arg("run")
            .arg("--pingback")
            .arg(listener.local_addr()?.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for flag in ["config", "adapter", "pidfile"] {
            if let Some(value) = nonempty(parsed.text(flag)) {
                command.arg(format!("--{flag}")).arg(value);
            }
        }
        for path in parsed.list("envfile") {
            let mut quoted = vec![b'"'];
            for &byte in path.as_bytes() {
                quoted.push(byte);
                if byte == b'"' {
                    quoted.push(byte);
                }
            }
            quoted.push(b'"');
            command.arg("--envfile").arg(OsString::from_vec(quoted));
        }
        if parsed.boolean("watch") {
            command.arg("--watch");
        }
        let mut signals = Signals::new()?;
        let mut child = command.spawn().context("starting native process")?;
        let started = async {
            let mut input = child
                .stdin
                .take()
                .context("child readiness input unavailable")?;
            input.write_all(&*nonce).await?;
            drop(input);
            let accept = async {
                loop {
                    let (mut socket, _) = listener.accept().await?;
                    let mut actual = zeroize::Zeroizing::new([0u8; 32]);
                    if tokio::time::timeout(
                        Duration::from_millis(250),
                        socket.read_exact(&mut *actual),
                    )
                    .await
                    .is_ok_and(|r| r.is_ok())
                        && openssl::memcmp::eq(&*nonce, &*actual)
                    {
                        return Ok::<(), std::io::Error>(());
                    }
                }
            };
            tokio::select! {biased;
                status=child.wait()=>bail!("native process exited before readiness: {}",status?),
                _=async {loop { if !matches!(signals.next().await, Event::Reload) {break;} }}=>
                    bail!("background startup interrupted"),
                outcome=accept=>{outcome?;Ok(())}
            }
        }
        .await;
        if let Err(error) = started {
            if child.try_wait()?.is_none() {
                if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
                    // SAFETY: pid is the positive identifier of this still
                    // owned, unreaped child, never read from a PID file.
                    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
                }
                match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
                    Ok(result) => {
                        result?;
                    }
                    Err(_) => child.kill().await?,
                }
            }
            return Err(error);
        }
        println!(
            "Successfully started Caddy (pid={}) - Caddy is running in the background",
            child.id().context("child process unavailable")?
        );
        Ok(0)
    })
}
