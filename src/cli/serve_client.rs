//! Local administration client; do not proxy, redirect or print response data.
use super::*;
use caddy_compat_native::admin_json;
use std::net::{Ipv6Addr, SocketAddr};

pub(super) fn command(name: &str, flags: args::Flags) -> Result<i32> {
    let explicit = nonempty(flags.text("address"));
    let force = flags.boolean("force");
    let selected_file = nonempty(flags.text("config"));
    let loaded = if name == "reload" || explicit.is_none() && selected_file.is_some() {
        Some(config::load_with_source(
            selected_file,
            flags.text("adapter"),
        )?)
    } else {
        None
    };
    if name == "reload" {
        ensure!(
            loaded.as_ref().is_some_and(|v| v.path.is_some()),
            "no configuration file to load"
        );
    }
    let configured = loaded
        .as_ref()
        .filter(|_| explicit.is_none())
        .filter(|loaded| !loaded.bytes.is_empty())
        .map(|loaded| -> Result<Option<String>> {
            let value =
                admin_json::decoded_typed(&loaded.bytes).map_err(|e| anyhow!(e.category))?;
            let value = value
                .get("admin")
                .and_then(|v| v.get("listen"))
                .filter(|v| !v.is_null());
            match value {
                Some(v) => Ok(Some(
                    v.as_str()
                        .context("invalid admin listen address")?
                        .to_owned(),
                )),
                None => Ok(None),
            }
        })
        .transpose()?
        .flatten();
    let default = std::env::var("CADDY_ADMIN").unwrap_or_else(|_| "localhost:2019".into());
    let address = match explicit {
        Some(address) => address.to_str().context("invalid admin address")?,
        None => configured
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or(&default),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (client, origin, unix) = endpoint(address)?;
        let operation = if name == "reload" { "/load" } else { "/stop" };
        let mut request = client.post(format!("{origin}{operation}"));
        if !unix {
            request = request.header("Origin", &origin);
        }
        if name == "reload" {
            let loaded = loaded.context("missing reload configuration")?;
            let path = loaded.path.context("missing reload source")?;
            let path = if path == Path::new("-") {
                path
            } else {
                std::env::current_dir()?.join(path)
            };
            request = request
                .header("Content-Type", "application/json")
                .header("Caddy-Config-Source-File", path.as_os_str().as_bytes())
                .header(
                    "Caddy-Config-Source-Adapter",
                    loaded.adapter.as_deref().unwrap_or(""),
                );
            if force {
                request = request.header("Cache-Control", "must-revalidate");
            }
            let mut bytes = loaded.bytes;
            request = request.body(std::mem::take(&mut *bytes));
        }
        let response = request
            .send()
            .await
            .map_err(|_| anyhow!("admin request failed"))?;
        ensure!(
            response.status().is_success(),
            "admin request failed: HTTP {}",
            response.status().as_u16()
        );
        Ok(0)
    })
}

fn endpoint(raw: &str) -> Result<(reqwest::Client, String, bool)> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10));
    if let Some(raw) = raw.strip_prefix("unix/") {
        let path = if let Some(name) = raw.strip_prefix('@') {
            ensure!(
                cfg!(target_os = "linux")
                    && !name.is_empty()
                    && name.len() <= 107
                    && !name.contains(['|', '\0']),
                "invalid or unsupported abstract admin socket"
            );
            // Tokio's Linux Unix connector accepts a NUL prefix for the
            // abstract namespace. This is never interpreted as a file path.
            let mut bytes = vec![0];
            bytes.extend_from_slice(name.as_bytes());
            PathBuf::from(OsString::from_vec(bytes))
        } else {
            let path = raw.rsplit_once('|').map_or(raw, |(path, _)| path);
            ensure!(
                path.starts_with('/'),
                "admin Unix socket path must be absolute"
            );
            PathBuf::from(path)
        };
        builder = builder.unix_socket(path);
        return Ok((builder.build()?, "http://127.0.0.1".into(), true));
    }
    let raw = raw.strip_prefix("tcp/").unwrap_or(raw);
    ensure!(
        !raw.contains(['/', '?', '#', '@', '%', '\\']),
        "unsupported admin endpoint"
    );
    let authority = if raw.parse::<SocketAddr>().is_ok() {
        raw.to_owned()
    } else if let Ok(ip) = raw.parse::<Ipv6Addr>() {
        format!("[{ip}]:2019")
    } else if raw.starts_with(':') {
        format!("localhost{raw}")
    } else if raw.contains(':') {
        raw.to_owned()
    } else {
        format!("{raw}:2019")
    };
    let origin = format!("http://{authority}");
    let uri = origin
        .parse::<http::Uri>()
        .context("invalid admin address")?;
    ensure!(
        uri.authority().is_some_and(|a| a.port_u16().is_some()),
        "invalid admin port"
    );
    Ok((builder.build()?, origin, false))
}
