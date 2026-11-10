//! CLI startup happens before runtime/worker construction, including env files.
#[path = "cli/args.rs"]
mod args;
#[path = "cli/config.rs"]
mod config;
#[path = "cli/envfile.rs"]
mod envfile;
#[path = "cli/json_indent.rs"]
mod json_indent;
#[path = "cli/line_diff.rs"]
mod line_diff;
#[cfg(feature = "native-run")]
#[path = "cli/paths.rs"]
mod paths;
#[path = "cli/validation.rs"]
mod validation;
use anyhow::{Context, Result, anyhow, bail, ensure};
use args::{Flag, Kind};
use caddy_compat_native::{admin_json, caddyfile_adapter, caddyfile_parser};
use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
};
const INPUT_LIMIT: usize = 16 * 1024 * 1024;
const OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const COMMON: &[Flag] = &[
    Flag {
        name: "config",
        short: Some(b'c'),
        kind: Kind::Text,
    },
    Flag {
        name: "help",
        short: Some(b'h'),
        kind: Kind::Bool,
    },
];
fn read(input: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if input == Path::new("-") {
        std::io::stdin()
            .lock()
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .context("reading stdin")?;
    } else {
        return read_file(input, limit);
    }
    ensure!(bytes.len() <= limit, "input limit exceeded");
    Ok(bytes)
}
fn read_file(input: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(input)
        .context("opening input")?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .context("reading input")?;
    ensure!(bytes.len() <= limit, "input limit exceeded");
    Ok(bytes)
}

/// # Safety
/// Only call before this process constructs worker threads, runtimes or foreign
/// libraries that may read the process environment. The binary entry owns this.
unsafe fn environment(paths: &[OsString]) -> Result<()> {
    for path in paths {
        let raw = zeroize::Zeroizing::new(read_file(Path::new(path), 64 * 1024 * 1024)?);
        let variables = envfile::parse(&raw)?;
        for (key, value) in variables {
            let value = zeroize::Zeroizing::new(value);
            ensure!(
                !key.is_empty() && !key.contains(&0) && !key.contains(&b'='),
                "invalid process environment entry"
            );
            let key = OsString::from_vec(key);
            if std::env::var_os(&key).is_none() {
                ensure!(!value.contains(&0), "invalid process environment value");
                // SAFETY: required by this private startup function's contract.
                unsafe {
                    std::env::set_var(key, OsStr::from_bytes(&value));
                }
            }
        }
    }
    Ok(())
}
fn help(command: &str) {
    match command {
        "fmt" => println!(
            "Usage: caddy-compat-native fmt [--overwrite] [--diff] [<path>]\n  -c, --config PATH\n  -w, --overwrite\n  -d, --diff\n  -h, --help"
        ),
        "adapt" => println!(
            "Usage: caddy-compat-native adapt [--config PATH] [--adapter caddyfile] [--pretty] [--validate] [--envfile PATH]\n  -c, --config PATH\n  -a, --adapter NAME\n  -p, --pretty\n      --validate\n      --envfile PATHS\n  -h, --help"
        ),
        "validate" => println!(
            "Usage: caddy-compat-native validate [--config PATH] [--adapter caddyfile] [--envfile PATH]\n  -c, --config PATH\n  -a, --adapter NAME\n      --envfile PATHS\n  -h, --help"
        ),
        _ => {}
    }
}
fn nonempty(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|s| !s.is_empty())
}
fn default_config(value: Option<&OsStr>) -> Result<PathBuf> {
    if let Some(path) = nonempty(value) {
        return Ok(path.into());
    }
    match std::fs::metadata("Caddyfile") {
        Ok(_) => Ok("Caddyfile".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("input configuration required")
        }
        Err(error) => Err(error).context("checking default Caddyfile"),
    }
}
fn format(flags: args::Flags) -> Result<i32> {
    if flags.boolean("help") {
        help("fmt");
        return Ok(0);
    }
    let explicit = nonempty(flags.text("config"));
    let positional = nonempty(flags.positional.first().map(OsString::as_os_str));
    ensure!(
        flags.positional.len() <= 1 && !(explicit.is_some() && positional.is_some()),
        "fmt requires at most one input"
    );
    let path = positional.or(explicit).unwrap_or(OsStr::new("Caddyfile"));
    let input = read(Path::new(path), INPUT_LIMIT)?;
    let output = caddyfile_adapter::format_caddyfile(&input, OUTPUT_LIMIT)?;
    if path == OsStr::new("-") {
        std::io::stdout().lock().write_all(&output)?;
        return Ok(0);
    }
    if flags.boolean("overwrite") {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .context("opening formatted output")?;
        file.write_all(&output)
            .context("writing formatted output")?;
        file.sync_all().context("syncing formatted output")?;
        return Ok(0);
    }
    if flags.boolean("diff") {
        std::io::stdout()
            .lock()
            .write_all(&line_diff::diff(&input, &output, OUTPUT_LIMIT)?)?;
    } else {
        std::io::stdout().lock().write_all(&output)?;
    }
    if let Some(line) = caddyfile_adapter::formatting_difference(&input, INPUT_LIMIT)? {
        eprintln!(
            "{}:{line}: Caddyfile input is not formatted; use --overwrite to update it",
            Path::new(path).display()
        );
        return Ok(1);
    };
    Ok(0)
}
/// # Safety
/// Same startup-only environment contract as `environment`.
unsafe fn adapt(flags: args::Flags) -> Result<i32> {
    if flags.boolean("help") {
        help("adapt");
        return Ok(0);
    }
    // Original adapt resolves an adjacent Caddyfile before loading env files.
    let path = default_config(flags.text("config"))?;
    // SAFETY: forwarded from the entry point before threads are started.
    unsafe {
        environment(flags.list("envfile"))?;
    }
    let adapter = flags.text("adapter").unwrap_or(OsStr::new("caddyfile"));
    ensure!(
        adapter == OsStr::new("caddyfile"),
        "unknown configuration adapter"
    );
    let input = zeroize::Zeroizing::new(read(&path, INPUT_LIMIT)?);
    let logical_name = path.to_string_lossy();
    let result = caddyfile_adapter::adapt(
        &caddyfile_parser::ParseOptions::capture()?,
        &input,
        &logical_name,
    )?;
    let mut output = admin_json::encoded_typed(&result.config).map_err(|e| anyhow!(e.category))?;
    // The shared Admin encoder includes a transport newline; CLI adds its own.
    if output.last() == Some(&b'\n') {
        output.pop();
    }
    let output = if flags.boolean("pretty") {
        json_indent::indent(&output, OUTPUT_LIMIT - 1)?
    } else {
        output
    };
    {
        let mut out = std::io::stdout().lock();
        out.write_all(&output)?;
        out.write_all(b"\n")?;
        out.flush()?;
    }
    emit_warnings(result.warnings);
    if flags.boolean("validate") {
        validation::configuration(result.config)?;
    }
    Ok(0)
}
fn emit_warnings(warnings: Vec<caddyfile_adapter::Warning>) {
    for warning in warnings {
        let message = if warning.directive.is_empty() {
            warning.message
        } else {
            format!("{}: {}", warning.directive, warning.message)
        };
        eprintln!(
            "{}",
            serde_json::json!({"level":"warn","logger":"caddyfile","msg":message,"file":warning.file,"line":warning.line})
        );
    }
}
/// Dispatch only implemented CLI commands. Inspectors and serving commands have
/// separate entry paths. Provisioning creates its runtime only after env files.
/// # Safety
/// Must run before any threads or foreign runtimes can observe the environment.
pub unsafe fn dispatch_early(input: &[OsString]) -> Result<Option<i32>> {
    let Some(command) = input.first().and_then(|s| s.to_str()) else {
        return Ok(None);
    };
    match command {
        "fmt" => {
            let mut specs = COMMON.to_vec();
            specs.extend([
                Flag {
                    name: "overwrite",
                    short: Some(b'w'),
                    kind: Kind::Bool,
                },
                Flag {
                    name: "diff",
                    short: Some(b'd'),
                    kind: Kind::Bool,
                },
            ]);
            Ok(Some(format(args::parse(&input[1..], &specs)?)?))
        }
        "adapt" => {
            let mut specs = COMMON.to_vec();
            specs.extend([
                Flag {
                    name: "adapter",
                    short: Some(b'a'),
                    kind: Kind::Text,
                },
                Flag {
                    name: "pretty",
                    short: Some(b'p'),
                    kind: Kind::Bool,
                },
                Flag {
                    name: "validate",
                    short: None,
                    kind: Kind::Bool,
                },
                Flag {
                    name: "envfile",
                    short: None,
                    kind: Kind::List,
                },
            ]);
            // SAFETY: caller provides the single-threaded startup boundary.
            Ok(Some(unsafe { adapt(args::parse(&input[1..], &specs)?)? }))
        }
        "validate" => {
            let mut specs = COMMON.to_vec();
            specs.extend([
                Flag {
                    name: "adapter",
                    short: Some(b'a'),
                    kind: Kind::Text,
                },
                Flag {
                    name: "envfile",
                    short: None,
                    kind: Kind::List,
                },
            ]);
            // SAFETY: same single-threaded startup boundary as adapt.
            Ok(Some(unsafe {
                validation::command(args::parse(&input[1..], &specs)?)?
            }))
        }
        _ => Ok(None),
    }
}
