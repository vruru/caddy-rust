mod cli;
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::{Read, Write},
    path::Path,
};

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    // SAFETY: this entry has not initialized crypto libraries, workers, runtimes
    // or other threads. Env files are applied only inside this startup boundary.
    match unsafe { cli::dispatch_early(&args) } {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::exit(1);
        }
    }
    if run().is_err() {
        eprintln!(
            "native compatibility inspection failed; configuration and private material are not printed"
        );
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let report = match args.as_slice() {
        [flag] if flag == "--help" => {
            println!(
                "caddy-compat-native fmt [FLAGS] [FILE] | adapt [FLAGS] | validate [FLAGS] | hash-password [FLAGS] | inspect-config FILE | inspect-storage CERTMAGIC_ROOT"
            );
            if cfg!(feature = "native-run") {
                println!(
                    "Development serving commands: run | start | reload | stop. Compatibility acceptance is incomplete."
                );
            } else {
                println!(
                    "This build does not serve traffic. Provisioning and experimental serving require native-run."
                );
            }
            return Ok(());
        }
        [flag] if flag == "--version" || flag == "version" => {
            println!(
                "caddy-compat-native {} (development candidate)",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        [command, path] if command == "inspect-config" => {
            let file = std::fs::File::open(path).context("input unavailable")?;
            ensure!(file.metadata()?.is_file(), "input must be a regular file");
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            caddy_compat_native::surface::inspect(&bytes)?
        }
        [command, path] if command == "inspect-storage" => {
            caddy_compat_native::crypto::install_default()?;
            caddy_compat_native::certmagic::inspect(Path::new(path))?
        }
        _ => bail!("unknown inspection command"),
    };
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, &report)?;
    writeln!(lock)?;
    Ok(())
}
