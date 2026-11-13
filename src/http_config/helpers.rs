use anyhow::{Result, ensure};
use serde_json::{Map, Value};
use std::time::Duration;

pub(crate) fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("object required at {path}"))
}
pub(crate) fn deny_unknown(map: &Map<String, Value>, allowed: &[&str], path: &str) -> Result<()> {
    ensure!(
        map.keys()
            .all(|k| k == "@id" || allowed.contains(&k.as_str())),
        "unknown configuration field at {path}"
    );
    Ok(())
}
pub(crate) fn unsupported(path: &str) -> anyhow::Error {
    anyhow::anyhow!("unsupported configuration capability at {path}")
}
pub(crate) fn string(value: &Value, path: &str) -> Result<String> {
    let s = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("string required at {path}"))?;
    ensure!(s.len() <= 1024 * 1024, "string limit exceeded at {path}");
    Ok(s.to_owned())
}
pub(crate) fn strings(value: &Value, path: &str) -> Result<Vec<String>> {
    let list = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("array required at {path}"))?;
    ensure!(list.len() <= 65536, "array limit exceeded at {path}");
    list.iter().map(|x| string(x, path)).collect()
}
pub(crate) fn boolean(value: Option<&Value>, default: bool, path: &str) -> Result<bool> {
    value.map_or(Ok(default), |v| {
        v.as_bool()
            .ok_or_else(|| anyhow::anyhow!("boolean required at {path}"))
    })
}
pub(crate) fn duration(value: &Value, path: &str) -> Result<Duration> {
    let ns = signed_duration(value, path)?;
    ensure!(ns >= 0, "negative duration at {path}");
    Ok(Duration::from_nanos(ns as u64))
}
pub(crate) fn signed_duration(value: &Value, path: &str) -> Result<i64> {
    crate::duration::parse_value(value).map_err(|_| anyhow::anyhow!("invalid duration at {path}"))
}

/// Caddy ReplaceAll (unknown -> empty) and ReplaceKnown (unknown preserved).
/// A placeholder ends at the first unescaped close brace, not a nested pair.
pub(crate) fn replace(
    input: &str,
    unknown_empty: bool,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String> {
    replace_accounted(input, unknown_empty, lookup, |_| Ok(()))
}

fn append_replacement(
    output: &mut Vec<u8>,
    text: &[u8],
    charge: &mut impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    let length = output.len().checked_add(text.len()).ok_or_else(|| anyhow::anyhow!("replacement length overflow"))?;
    ensure!(length <= 4 * 1024 * 1024, "replacement output exceeds limit");
    if length > output.capacity() {
        let capacity = output.capacity().saturating_mul(2).max(length).min(4 * 1024 * 1024);
        // The old and new buffers may coexist during a reallocation. Reserve
        // twice the requested capacity before growth and retain that credit.
        charge(capacity * 2)?;
        output.try_reserve_exact(capacity - output.len()).map_err(|_| anyhow::anyhow!("replacement allocation unavailable"))?;
    }
    output.extend_from_slice(text);
    Ok(())
}

pub(crate) fn replace_accounted(
    input: &str,
    unknown_empty: bool,
    lookup: impl Fn(&str) -> Option<String>,
    charge: impl FnMut(usize) -> Result<()>,
) -> Result<String> {
    let bytes=replace_bytes_accounted(input,unknown_empty,|name|lookup(name).map(String::into_bytes),charge)?;
    String::from_utf8(bytes).map_err(|_|anyhow::anyhow!("invalid UTF-8 replacement"))
}

/// Byte-valued network addresses retain their original bytes in Go strings.
/// Both entry points use the same scanner, escaping rules and allocation bounds.
pub(crate) fn replace_bytes(input:&str,unknown_empty:bool,lookup:impl Fn(&str)->Option<Vec<u8>>)->Result<Vec<u8>>{
    replace_bytes_accounted(input,unknown_empty,lookup,|_|Ok(()))
}
pub(crate) fn replace_bytes_accounted(input:&str,unknown_empty:bool,lookup:impl Fn(&str)->Option<Vec<u8>>,mut charge:impl FnMut(usize)->Result<()>)->Result<Vec<u8>>{
    ensure!(
        input.len() <= 1024 * 1024,
        "replacement input exceeds limit"
    );
    let bytes = input.as_bytes();
    charge(input.len().checked_mul(2).ok_or_else(|| anyhow::anyhow!("replacement capacity overflow"))?)?;
    let mut out = Vec::new();
    out.try_reserve_exact(input.len()).map_err(|_| anyhow::anyhow!("replacement allocation unavailable"))?;
    let mut cursor = 0;
    let mut i = 0;
    let mut unclosed = 0;
    while i < bytes.len() {
        if i > 0 && bytes[i - 1] == b'\\' && matches!(bytes[i], b'{' | b'}') {
            append_replacement(&mut out, &bytes[cursor..i - 1], &mut charge)?;
            cursor = i;
            i += 1;
            continue;
        }
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        ensure!(unclosed <= 100, "too many unclosed placeholders");
        let mut end = i + 1;
        while end < bytes.len()
            && (bytes[end] != b'}' || (end > 0 && bytes[end - 1] == b'\\' && end < bytes.len() - 1))
        {
            end += 1;
        }
        if end == bytes.len() {
            unclosed += 1;
            i += 1;
            continue;
        }
        append_replacement(&mut out, &bytes[cursor..i], &mut charge)?;
        match lookup(&input[i + 1..end]) {
            Some(value) => append_replacement(&mut out, &value, &mut charge)?,
            None if !unknown_empty => {
                cursor = i;
                i += 1;
                continue;
            }
            None => {}
        }
        i = end + 1;
        cursor = i;
    }
    append_replacement(&mut out, &bytes[cursor..], &mut charge)?;
    Ok(out)
}

pub(crate) fn process_elapsed() -> std::time::Duration { PROCESS_CLOCK.get_or_init(std::time::Instant::now).elapsed() }

static PROCESS_CLOCK: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
/// Call during blocking configuration preparation to warm local timezone data.
/// Monotonic formatting uses this process-local Rust Instant, never wall-clock deltas.
pub(crate) fn initialize_globals() {
    PROCESS_CLOCK.get_or_init(std::time::Instant::now);
    let now = chrono::Local::now();
    let _ = local_zone_name(now.timestamp(), &now.format("%z").to_string());
}
/// Local UTC offset in seconds east of UTC and the platform timezone abbreviation.
/// Call only during blocking preparation/encoding after timezone initialization.
#[cfg(unix)]
#[allow(deprecated)] // Use libc's exact declared time_t ABI, including musl targets.
pub(crate) fn local_zone_info(timestamp: i64) -> Option<(i32, String)> {
    // time_t may be narrower on other Unix targets.
    #[allow(clippy::useless_conversion)]
    let timestamp: libc::time_t = timestamp.try_into().ok()?;
    let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
    // localtime_r writes a complete caller-owned tm on success. The timezone
    // database is warmed in blocking provisioning, never from request input.
    let result = unsafe { libc::localtime_r(&timestamp, local.as_mut_ptr()) };
    if result.is_null() {
        return None;
    }
    // A non-null result establishes initialization; libc owns the zone string.
    let local = unsafe { local.assume_init() };
    if local.tm_zone.is_null() {
        return None;
    }
    // POSIX localtime_r supplies a valid NUL-terminated abbreviation in tm_zone.
    let zone = unsafe { std::ffi::CStr::from_ptr(local.tm_zone) }.to_string_lossy();
    if zone.is_empty() {
        return None;
    }
    Some((local.tm_gmtoff.try_into().ok()?, zone.into_owned()))
}
#[cfg(not(unix))]
pub(crate) fn local_zone_info(_timestamp: i64) -> Option<(i32, String)> {
    None
}
fn local_zone_name(timestamp: i64, fallback: &str) -> String {
    local_zone_info(timestamp)
        .map(|(_, zone)| zone)
        .unwrap_or_else(|| fallback.to_owned())
}
pub(crate) fn global_lookup(name: &str) -> Option<String> {
    Some(match name {
        _ if name.starts_with("env.") => std::env::var(&name[4..]).unwrap_or_default(),
        "system.hostname" => hostname::get()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "system.slash" => std::path::MAIN_SEPARATOR.to_string(),
        "system.os" => if std::env::consts::OS == "macos" {
            "darwin"
        } else {
            std::env::consts::OS
        }
        .into(),
        "system.arch" => match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            "wasm32" => "wasm",
            "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
            "powerpc64" => "ppc64",
            other => other,
        }
        .into(),
        "system.wd" => std::env::current_dir()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "time.now" => {
            let local = chrono::Local::now();
            let nanos = format!("{:09}", local.timestamp_subsec_nanos());
            let fraction = nanos.trim_end_matches('0');
            let fraction = if fraction.is_empty() {
                String::new()
            } else {
                format!(".{fraction}")
            };
            let elapsed = PROCESS_CLOCK.get_or_init(std::time::Instant::now).elapsed();
            format!(
                "{}{fraction} {} {} m=+{}.{:09}",
                local.format("%Y-%m-%d %H:%M:%S"),
                local.format("%z"),
                local_zone_name(local.timestamp(), &local.format("%z").to_string()),
                elapsed.as_secs(),
                elapsed.subsec_nanos()
            )
        }
        "time.now.http" => chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string(),
        "time.now.common_log" => chrono::Local::now()
            .format("%d/%b/%Y:%H:%M:%S %z")
            .to_string(),
        "time.now.year" => chrono::Local::now().format("%Y").to_string(),
        "time.now.unix" => chrono::Utc::now().timestamp().to_string(),
        "time.now.unix_ms" => {
            let now = chrono::Utc::now();
            let nanos = i128::from(now.timestamp()) * 1_000_000_000
                + i128::from(now.timestamp_subsec_nanos());
            (nanos / 1_000_000).to_string()
        }
        _ => return None,
    })
}
/// File providers are intentionally separate from the fast global provider.
/// Call only from a bounded blocking preparation task or a dedicated async worker.
/// Read failures are recognized-empty, as in Caddy. Non-UTF8 contents remain an
/// explicit compatibility gap rather than being silently changed by lossy decoding.
pub(crate) fn prepare_file_lookup(name: &str) -> Option<Result<String>> {
    let path = name.strip_prefix("file.")?;
    Some((|| {
        use std::io::Read;
        let Ok(file) = open_regular_file(path) else {
            return Ok(String::new());
        };
        let mut bytes = Vec::new();
        if file.take(1024 * 1024).read_to_end(&mut bytes).is_err() {
            return Ok(String::new());
        }
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        String::from_utf8(bytes).map_err(|_| unsupported("/placeholder/file/non_utf8_bytes"))
    })())
}

/// Opens without waiting for a FIFO writer, then validates the actual opened
/// descriptor. Ordinary symlink rotation is allowed; path metadata is not used
/// as an authorization or file-type check. Call from a blocking I/O worker.
pub(crate) fn open_regular_file(
    path: impl AsRef<std::path::Path>,
) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "regular file required",
        ));
    }
    Ok(file)
}

pub(crate) fn value_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.as_f64().map(|f| f.to_string()).unwrap_or_default(),
        Value::Bool(b) => b.to_string(),
        other => fmt_collection(other),
    }
}
fn fmt_collection(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(fmt_collection)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::Object(values) => format!(
            "map[{}]",
            values
                .iter()
                .map(|(k, v)| format!("{k}:{}", fmt_collection(v)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or_default();
            if f.abs() >= 1e6 || (f.abs() > 0.0 && f.abs() < 1e-4) {
                let fixed = f.abs().to_string();
                let exponent = if f.abs() >= 1.0 {
                    fixed.find('.').unwrap_or(fixed.len()) as i32 - 1
                } else {
                    -(fixed[2..].chars().take_while(|c| *c == '0').count() as i32) - 1
                };
                let digits = fixed
                    .replace('.', "")
                    .trim_start_matches('0')
                    .trim_end_matches('0')
                    .to_owned();
                if digits.is_empty() {
                    return "0".into();
                }
                let mantissa = if digits.len() > 1 {
                    format!("{}.{}", &digits[..1], &digits[1..])
                } else {
                    digits
                };
                format!(
                    "{}{mantissa}e{exponent:+03}",
                    if f.is_sign_negative() { "-" } else { "" }
                )
            } else {
                f.to_string()
            }
        }
    }
}
