use super::*;

/// Native module registration directory for this binary.
/// This is NOT a declaration that all fields are compatible.
static STANDARD_MODULES: &[&str] = &[
    "admin.api.load",
    "admin.api.metrics",
    "admin.api.pki",
    "admin.api.reverse_proxy",
    "caddy.adapters.caddyfile",
    "caddy.config_loaders.http",
    "caddy.filesystems",
    "caddy.listeners.http_redirect",
    "caddy.listeners.proxy_protocol",
    "caddy.listeners.tls",
    "caddy.logging.cores.mock",
    "caddy.logging.encoders.append",
    "caddy.logging.encoders.console",
    "caddy.logging.encoders.filter",
    "caddy.logging.encoders.filter.cookie",
    "caddy.logging.encoders.filter.delete",
    "caddy.logging.encoders.filter.hash",
    "caddy.logging.encoders.filter.ip_mask",
    "caddy.logging.encoders.filter.multi_regexp",
    "caddy.logging.encoders.filter.query",
    "caddy.logging.encoders.filter.regexp",
    "caddy.logging.encoders.filter.rename",
    "caddy.logging.encoders.filter.replace",
    "caddy.logging.encoders.filter.set_cookie",
    "caddy.logging.encoders.journald",
    "caddy.logging.encoders.json",
    "caddy.logging.writers.discard",
    "caddy.logging.writers.file",
    "caddy.logging.writers.net",
    "caddy.logging.writers.stderr",
    "caddy.logging.writers.stdout",
    "caddy.network_proxy.none",
    "caddy.network_proxy.url",
    "caddy.storage.file_system",
    "events",
    "http",
    "http.authentication.hashes.argon2id",
    "http.authentication.hashes.bcrypt",
    "http.authentication.providers.http_basic",
    "http.encoders.gzip",
    "http.encoders.zstd",
    "http.handlers.acme_server",
    "http.handlers.authentication",
    "http.handlers.copy_response",
    "http.handlers.copy_response_headers",
    "http.handlers.encode",
    "http.handlers.error",
    "http.handlers.file_server",
    "http.handlers.headers",
    "http.handlers.intercept",
    "http.handlers.invoke",
    "http.handlers.log_append",
    "http.handlers.map",
    "http.handlers.metrics",
    "http.handlers.push",
    "http.handlers.request_body",
    "http.handlers.reverse_proxy",
    "http.handlers.rewrite",
    "http.handlers.static_response",
    "http.handlers.subroute",
    "http.handlers.templates",
    "http.handlers.timeouts",
    "http.handlers.tracing",
    "http.handlers.vars",
    "http.ip_sources.static",
    "http.matchers.client_ip",
    "http.matchers.expression",
    "http.matchers.file",
    "http.matchers.header",
    "http.matchers.header_regexp",
    "http.matchers.host",
    "http.matchers.method",
    "http.matchers.not",
    "http.matchers.path",
    "http.matchers.path_regexp",
    "http.matchers.protocol",
    "http.matchers.query",
    "http.matchers.remote_ip",
    "http.matchers.tls",
    "http.matchers.url_pattern",
    "http.matchers.vars",
    "http.matchers.vars_regexp",
    "http.precompressed.br",
    "http.precompressed.gzip",
    "http.precompressed.zstd",
    "http.reverse_proxy.selection_policies.client_ip_hash",
    "http.reverse_proxy.selection_policies.cookie",
    "http.reverse_proxy.selection_policies.first",
    "http.reverse_proxy.selection_policies.header",
    "http.reverse_proxy.selection_policies.ip_hash",
    "http.reverse_proxy.selection_policies.least_conn",
    "http.reverse_proxy.selection_policies.query",
    "http.reverse_proxy.selection_policies.random",
    "http.reverse_proxy.selection_policies.random_choose",
    "http.reverse_proxy.selection_policies.round_robin",
    "http.reverse_proxy.selection_policies.uri_hash",
    "http.reverse_proxy.selection_policies.weighted_round_robin",
    "http.reverse_proxy.transport.fastcgi",
    "http.reverse_proxy.transport.http",
    "http.reverse_proxy.upstreams.a",
    "http.reverse_proxy.upstreams.multi",
    "http.reverse_proxy.upstreams.srv",
    "pki",
    "tls",
    "tls.ca_pool.source.combined",
    "tls.ca_pool.source.file",
    "tls.ca_pool.source.http",
    "tls.ca_pool.source.inline",
    "tls.ca_pool.source.pki_intermediate",
    "tls.ca_pool.source.pki_root",
    "tls.ca_pool.source.storage",
    "tls.ca_pool.source.system",
    "tls.certificates.automate",
    "tls.certificates.load_files",
    "tls.certificates.load_folders",
    "tls.certificates.load_pem",
    "tls.certificates.load_storage",
    "tls.client_auth.verifier.leaf",
    "tls.get_certificate.http",
    "tls.get_certificate.tailscale",
    "tls.handshake_match.local_ip",
    "tls.handshake_match.remote_ip",
    "tls.handshake_match.sni",
    "tls.handshake_match.sni_regexp",
    "tls.issuance.acme",
    "tls.issuance.internal",
    "tls.leaf_cert_loader.file",
    "tls.leaf_cert_loader.folder",
    "tls.leaf_cert_loader.pem",
    "tls.leaf_cert_loader.storage",
    "tls.permission.http",
    "tls.stek.distributed",
    "tls.stek.standard",
];

pub(super) unsafe fn command(name: &str, input: &[OsString]) -> Result<i32> {
    match name {
        "environ" => {
            let specs = [
                Flag {
                    name: "help",
                    short: Some(b'h'),
                    kind: Kind::Bool,
                },
                Flag {
                    name: "envfile",
                    short: None,
                    kind: Kind::List,
                },
            ];
            let flags = args::parse(input, &specs)?;
            if !flags.positional.is_empty() {
                bail!("environ: unexpected positional arguments");
            }
            if flags.boolean("help") {
                println!("Usage: caddy-compat-native environ [--envfile PATH]");
                return Ok(0);
            }
            unsafe { environment(flags.list("envfile"))?; }

            let cwd = std::env::current_dir()?;
            let home = std::env::var_os("HOME")
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_default();
            let app_data = paths::data(&cwd)?;
            let app_config = paths::config(&cwd)?;
            let autosave = app_config.join("autosave.json");
            let num_cpu = std::thread::available_parallelism()?.get();

            println!("caddy.HomeDir={}", home);
            println!("caddy.AppDataDir={}", app_data.display());
            println!("caddy.AppConfigDir={}", app_config.display());
            println!("caddy.ConfigAutosavePath={}", autosave.display());
            println!("caddy.Version={}", env!("CARGO_PKG_VERSION"));
            println!("native.OS={}", std::env::consts::OS);
            println!("native.ARCH={}", std::env::consts::ARCH);
            println!(
                "native.Compiler={}",
                option_env!("CADDY_RUST_COMPILER").unwrap_or("unknown")
            );
            println!("native.NumCPU={}", num_cpu);
            println!("os.Getwd={}", cwd.display());
            println!();
            for (key, value) in std::env::vars_os() {
                println!("{}={}", key.to_string_lossy(), value.to_string_lossy());
            }
            Ok(0)
        }
        "build-info" => {
            let specs = [Flag {
                name: "help",
                short: Some(b'h'),
                kind: Kind::Bool,
            }];
            let flags = args::parse(input, &specs)?;
            if !flags.positional.is_empty() {
                bail!("build-info: unexpected positional arguments");
            }
            if flags.boolean("help") {
                println!("Usage: caddy-compat-native build-info");
                return Ok(0);
            }

            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            println!(
                "Source: {}",
                option_env!("CADDY_SOURCE_REV").unwrap_or("unknown")
            );
            println!(
                "Compiler: {}",
                option_env!("CADDY_RUST_COMPILER").unwrap_or("unknown")
            );
            println!(
                "Target: {}",
                option_env!("CADDY_BUILD_TARGET").unwrap_or("unknown")
            );
            println!(
                "Profile: {}",
                option_env!("CADDY_BUILD_PROFILE").unwrap_or("unknown")
            );
            println!();
            println!("Dependencies (from Cargo.lock):");
            let lock_str = include_str!("../../Cargo.lock");
            let lock: toml::Value = toml::from_str(lock_str)?;
            let packages = lock
                .get("package")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("Cargo.lock missing package array"))?;
            for pkg in packages {
                let name = pkg
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let version = pkg
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                println!("  {} {}", name, version);
            }
            Ok(0)
        }
        "list-modules" => {
            let specs = [
                Flag {
                    name: "help",
                    short: Some(b'h'),
                    kind: Kind::Bool,
                },
                Flag {
                    name: "packages",
                    short: None,
                    kind: Kind::Bool,
                },
                Flag {
                    name: "versions",
                    short: None,
                    kind: Kind::Bool,
                },
                Flag {
                    name: "skip-standard",
                    short: None,
                    kind: Kind::Bool,
                },
                Flag {
                    name: "json",
                    short: None,
                    kind: Kind::Bool,
                },
            ];
            let flags = args::parse(input, &specs)?;
            if !flags.positional.is_empty() {
                bail!("list-modules: unexpected positional arguments");
            }
            if flags.boolean("help") {
                println!("Usage: caddy-compat-native list-modules [--packages] [--versions] [--skip-standard] [--json]");
                return Ok(0);
            }

            let skip_standard = flags.boolean("skip-standard");
            let want_json = flags.boolean("json");
            let want_versions = flags.boolean("versions");
            let want_packages = flags.boolean("packages");
            let count = STANDARD_MODULES.len();

            if want_json {
                if skip_standard {
                    println!("[]");
                } else {
                    let mut entries = Vec::with_capacity(count);
                    for id in STANDARD_MODULES {
                        entries.push(serde_json::json!({
                            "module_name": id,
                            "module_type": "standard",
                            "version": env!("CARGO_PKG_VERSION"),
                            "package_url": "github.com/vruru/caddy-rust",
                        }));
                    }
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                }
                return Ok(0);
            }

            if skip_standard {
                return Ok(0);
            }

            for id in STANDARD_MODULES {
                let mut line = String::from(*id);
                if want_versions {
                    line.push_str(&format!("  {}", env!("CARGO_PKG_VERSION")));
                }
                if want_packages {
                    line.push_str("  github.com/vruru/caddy-rust");
                }
                println!("{}", line);
            }
            println!();
            println!("  Standard modules: {}", count);
            Ok(0)
        }
        _ => bail!("unknown information subcommand: {}", name),
    }
}
