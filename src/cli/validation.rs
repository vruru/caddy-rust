use super::*;

#[cfg(feature = "native-run")]
pub fn configuration(raw: serde_json::Value) -> Result<()> {
    use caddy_compat_native::{
        admin::AdminBackend,
        root_backend::{NativeBackend, RootOptions},
        tls_app_config::CertificatePaths,
    };
    // The pinned Go validate command dereferences a nil Config for literal
    // null. Reject it explicitly rather than reproduce a process panic or
    // incorrectly claim that a missing typed configuration was provisioned.
    ensure!(raw.is_object(), "configuration must be an object");
    caddy_compat_native::crypto::install_default()?;
    let cwd = std::env::current_dir().context("capturing application directory")?;
    let root = NativeBackend::new(RootOptions {
        paths: CertificatePaths {
            default_storage: paths::data(&cwd),
            state_root: paths::config(&cwd).join("native-state"),
            cwd,
        },
        trust_installer: None,
    })?;
    caddy_compat_native::runtime::build()?.block_on(async move {
        let result = root.validate_configuration(raw).await;
        // Join the actual application resources on validation failure as well.
        // No graceful listeners were started by provision-only validation.
        let stopped = root.stop_unbounded().await;
        result.and(stopped).map_err(anyhow::Error::from)
    })
}
#[cfg(not(feature = "native-run"))]
pub fn configuration(_: serde_json::Value) -> Result<()> {
    bail!("native provisioning validation requires the native-run development feature")
}

/// # Safety
/// Environment files must be applied before runtime or crypto construction.
pub unsafe fn command(flags: args::Flags) -> Result<i32> {
    if flags.boolean("help") {
        help("validate");
        return Ok(0);
    }
    // Validate loads env files before resolving the adjacent default config.
    unsafe {
        environment(flags.list("envfile"))?;
    }
    let path = default_config(flags.text("config"))?;
    let loaded = config::load(Some(path.as_os_str()), flags.text("adapter"))?;
    let stripped = zeroize::Zeroizing::new(config::strip_metadata(&loaded)?);
    let raw = admin_json::decoded_typed(&stripped).map_err(|e| anyhow!(e.category))?;
    configuration(raw)?;
    println!("Valid configuration");
    Ok(0)
}
