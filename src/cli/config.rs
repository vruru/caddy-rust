//! Original command configuration loading and raw metadata removal semantics.
use super::*;

pub fn load(path: Option<&OsStr>, adapter: Option<&OsStr>) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(load_with_source(path, adapter)?.bytes)
}

pub struct LoadedConfig {
    pub bytes: zeroize::Zeroizing<Vec<u8>>,
    #[cfg(feature = "native-run")]
    pub path: Option<PathBuf>,
    #[cfg(feature = "native-run")]
    pub adapter: Option<String>,
}

pub fn load_with_source(path: Option<&OsStr>, adapter: Option<&OsStr>) -> Result<LoadedConfig> {
    let explicit = nonempty(path);
    let adapter = nonempty(adapter);
    ensure!(
        explicit.is_some() || adapter.is_none(),
        "cannot adapt config without config file"
    );
    let path = if let Some(path) = explicit {
        Some(PathBuf::from(path))
    } else {
        match std::fs::metadata("Caddyfile") {
            Ok(_) => Some(PathBuf::from("Caddyfile")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("checking adjacent Caddyfile"),
        }
    };
    let mut bytes = zeroize::Zeroizing::new(match &path {
        Some(path) => read(path, INPUT_LIMIT)?,
        None => Vec::new(),
    });
    let inferred = path.as_ref().is_some_and(|path| {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        !name.ends_with(".json") && (name.starts_with("caddyfile") || name.ends_with(".caddyfile"))
    });
    let adapter = if adapter == Some(OsStr::new("caddyfile")) || adapter.is_none() && inferred {
        Some("caddyfile".to_owned())
    } else {
        adapter.map(|s| s.to_string_lossy().into_owned())
    };
    if let Some(adapter) = &adapter {
        ensure!(adapter == "caddyfile", "unknown configuration adapter");
        let logical = path
            .as_deref()
            .unwrap_or_else(|| Path::new("Caddyfile"))
            .to_string_lossy();
        let result = caddyfile_adapter::adapt(
            &caddyfile_parser::ParseOptions::capture()?,
            &bytes,
            &logical,
        )?;
        emit_warnings(result.warnings);
        *bytes = admin_json::encoded_typed(&result.config).map_err(|e| anyhow!(e.category))?;
    } else if !bytes.is_empty() {
        // LoadConfig's initial JSON syntax check decodes into Go any, including
        // overflow rejection, but retains the original bytes for typed decode.
        let _ = admin_json::decoded(&bytes).map_err(|e| anyhow!(e.category))?;
    }
    Ok(LoadedConfig {
        bytes,
        #[cfg(feature = "native-run")]
        path,
        #[cfg(feature = "native-run")]
        adapter,
    })
}

pub fn strip_metadata(input: &[u8]) -> Result<Vec<u8>> {
    // Go's regexp uses ASCII \s, and intentionally does not parse JSON escapes
    // inside an ID string. Preserve that raw behavior, including malformed
    // trailing remnants being rejected by the subsequent typed decoder.
    let expression=regex::bytes::RegexBuilder::new(r#",?[\t\n\x0C\r ]*"@id"[\t\n\x0C\r ]*:[\t\n\x0C\r ]*(-?[0-9]+(\.[0-9]+)?|".*?")[\t\n\x0C\r ]*,?"#)
        .unicode(false).build()?;
    Ok(expression
        .replace_all(input, |captures: &regex::bytes::Captures<'_>| {
            let matched = &captures[0];
            if matched.starts_with(b",") && matched.ends_with(b",") {
                b",".as_slice()
            } else {
                b"".as_slice()
            }
        })
        .into_owned())
}
