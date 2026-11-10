use super::request::{Context, decoded_path, failure, safe_join};
use super::*;
use futures_util::stream;
use http::{HeaderValue, Method};
use http_body_util::StreamBody;
use std::{
    io,
    ops::RangeInclusive,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) async fn serve(
    ctx: &mut Context,
    root: Option<&str>,
    hide: &[String],
    indices: &[String],
) -> Result<Option<Response<Body>>> {
    let root = ctx.expand(root.unwrap_or("{http.vars.root}"))?;
    let decoded = decoded_path(ctx.req().uri().path())?;
    let mut path = safe_join(std::path::Path::new(&root), &decoded)?;
    let stat_path = path.clone();
    let mut metadata = match ctx
        .resources
        .metadata
        .run(move || std::fs::metadata(stat_path))
        .await
        .map_err(|error| super::request::budget_failure(ctx, error))?
    {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Err(failure(StatusCode::FORBIDDEN));
        }
        Err(error) => return Err(super::request::file_io_failure(ctx, &error)),
    };
    if hidden(ctx, &path, hide)? {
        return Ok(None);
    }
    let mut implicit_index = false;
    if metadata.is_dir() {
        for index in indices {
            let candidate = path.join(ctx.expand(index)?);
            if hidden(ctx, &candidate, hide)? {
                continue;
            }
            let stat_path = candidate.clone();
            let lookup = ctx
                .resources
                .metadata
                .run(move || std::fs::metadata(stat_path))
                .await
                .map_err(|error| super::request::budget_failure(ctx, error))?;
            if let Err(error) = &lookup
                && super::request::descriptor_exhausted(error)
            {
                return Err(super::request::file_io_failure(ctx, error));
            }
            if let Ok(meta) = lookup
                && meta.is_file()
            {
                path = candidate;
                metadata = meta;
                implicit_index = true;
                break;
            }
        }
        if !implicit_index {
            return Ok(None);
        }
    }
    let original = decoded_path(ctx.original_uri.path())?;
    let current = decoded_path(ctx.req().uri().path())?;
    let base = |path: &str| {
        path.trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_owned()
    };
    if base(&original) == base(&current) {
        if implicit_index && !original.ends_with('/') {
            return Ok(Some(redirect(ctx, &format!("{original}/"))?));
        } else if !implicit_index && original.ends_with('/') {
            return Ok(Some(redirect(ctx, original.trim_end_matches('/'))?));
        }
    }
    if !metadata.is_file() {
        return Ok(None);
    }
    ctx.immediate.append(
        http::header::VARY,
        HeaderValue::from_static("Accept-Encoding"),
    );
    // Bound open descriptors before opening; queued bodies hold no file FD.
    // This slot is independent of per-chunk read work and slow network writes.
    let admission = Arc::new(
        ctx.resources
            .streams
            .acquire()
            .await
            .map_err(|error| super::request::budget_failure(ctx, error))?,
    );
    let open_admission = admission.clone();
    let opened_path = path.clone();
    let (file, opened_metadata, admission) = ctx
        .resources
        .metadata
        .run(move || {
            let file = crate::http_config::helpers::open_regular_file(opened_path)?;
            let metadata = file.metadata()?;
            Ok::<_, io::Error>((file, metadata, open_admission))
        })
        .await
        .map_err(|error| super::request::budget_failure(ctx, error))?
        .map_err(|error| super::request::file_io_failure(ctx, &error))?;
    let file = Arc::new(file);
    if !matches!(*ctx.req().method(), Method::GET | Method::HEAD)
        && !ctx.values.contains_key("http.error.status_code")
    {
        ctx.immediate
            .insert(http::header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return Err(failure(StatusCode::METHOD_NOT_ALLOWED));
    }
    // Use fstat after opening. A rename between metadata and open must not give
    // a new representation the old file's ETag/length.
    metadata = opened_metadata;
    let size = metadata.len();
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    let nanos = match modified.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    };
    let useful = !matches!(seconds(modified), 0 | 1);
    let etag = if !useful {
        String::new()
    } else {
        format!(
            "\"{}-{}\"",
            base36(nanos as i64 as i128),
            base36(size as i128)
        )
    };
    let last_modified = http_date(modified);
    let mut common = http::HeaderMap::new();
    if !etag.is_empty() {
        common.insert(http::header::ETAG, HeaderValue::from_str(&etag)?);
    }
    if useful && let Some(last_modified) = last_modified {
        common.insert(
            http::header::LAST_MODIFIED,
            HeaderValue::from_str(&last_modified)?,
        );
    }
    if let Some(status) = preconditions(ctx, &etag, modified) {
        let mut r = simple(status, Bytes::new());
        *r.headers_mut() = common;
        if status == StatusCode::NOT_MODIFIED && !etag.is_empty() {
            r.headers_mut().remove(http::header::LAST_MODIFIED);
        }
        return Ok(Some(r));
    }
    let content_type = super::mime::by_extension(&path).unwrap_or_default();
    if !content_type.is_empty() {
        common.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&content_type)?,
        );
    }
    let mut ranges = None;
    let mut range_selected = false;
    if let Some(value) = ctx
        .req()
        .headers()
        .get(http::header::RANGE)
        .and_then(|v| v.to_str().ok())
    {
        let allow = ctx
            .req()
            .headers()
            .get(http::header::IF_RANGE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| {
                if v.starts_with('"') {
                    v == etag
                } else {
                    useful
                        && httpdate::parse_http_date(v)
                            .is_ok_and(|t| seconds(modified) == seconds(t))
                }
            });
        if allow {
            match parse_ranges(value, size) {
                Ok(list) => {
                    if list
                        .iter()
                        .try_fold(0u64, |total, r| total.checked_add(r.end() - r.start() + 1))
                        .is_some_and(|total| total <= size)
                    {
                        ranges = Some(list);
                        range_selected = true;
                    }
                }
                Err(message) => {
                    let mut r = simple(StatusCode::RANGE_NOT_SATISFIABLE, format!("{message}\n"));
                    *r.headers_mut() = common;
                    r.headers_mut().remove(http::header::ETAG);
                    r.headers_mut().remove(http::header::LAST_MODIFIED);
                    r.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain; charset=utf-8"),
                    );
                    r.headers_mut().insert(
                        "x-content-type-options",
                        HeaderValue::from_static("nosniff"),
                    );
                    if message == "invalid range: failed to overlap" {
                        r.headers_mut().insert(
                            http::header::CONTENT_RANGE,
                            HeaderValue::from_str(&format!("bytes */{size}"))?,
                        );
                    }
                    return Ok(Some(r));
                }
            }
        }
    }
    common.insert(
        http::header::ACCEPT_RANGES,
        HeaderValue::from_static("bytes"),
    );
    let ranges = ranges.unwrap_or_else(|| {
        if size == 0 {
            vec![]
        } else {
            std::iter::once(0..=size - 1).collect()
        }
    });
    let partial = range_selected;
    let error_status = ctx
        .values
        .get("http.error.status_code")
        .and_then(|s| s.parse::<u16>().ok())
        .and_then(|s| StatusCode::from_u16(s).ok());
    if ranges.is_empty() {
        let mut r = simple(error_status.unwrap_or(StatusCode::OK), Bytes::new());
        *r.headers_mut() = common;
        r.headers_mut()
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return Ok(Some(r));
    }
    let multipart = ranges.len() > 1;
    let boundary = if multipart {
        let mut entropy = [0u8; 16];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut entropy)
            .map_err(|_| anyhow::anyhow!("range boundary generation failed"))?;
        entropy
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    } else {
        String::new()
    };
    let length = if multipart {
        ranges
            .iter()
            .map(|r| {
                part_header(&boundary, &content_type, r, size).len() as u64
                    + (r.end() - r.start() + 1)
                    + 2
            })
            .sum::<u64>()
            + format!("--{boundary}--\r\n").len() as u64
    } else {
        ranges[0].end() - ranges[0].start() + 1
    };
    let status = error_status.unwrap_or(if partial || multipart {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    });
    if multipart {
        common.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}"))?,
        );
    } else if partial {
        common.insert(
            http::header::CONTENT_RANGE,
            HeaderValue::from_str(&format!(
                "bytes {}-{}/{size}",
                ranges[0].start(),
                ranges[0].end()
            ))?,
        );
    }
    common.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string())?,
    );
    if ctx.req().method() == Method::HEAD {
        let mut r = simple(status, Bytes::new());
        *r.headers_mut() = common;
        return Ok(Some(r));
    }
    let initial = if multipart {
        Mode::Header
    } else {
        Mode::Body(ranges[0].end() - ranges[0].start() + 1)
    };
    let offset = *ranges[0].start();
    let state = FileState {
        file,
        admission,
        offset,
        read_timeout: ctx.resources.read_timeout,
        read_budget: ctx.resources.reads.clone(),
        ranges,
        index: 0,
        boundary,
        content_type,
        size,
        multipart,
        mode: initial,
    };
    let frames = stream::try_unfold(state, |mut state| async move {
        loop {
            match state.mode {
                Mode::Header => {
                    let range = &state.ranges[state.index];
                    let header =
                        part_header(&state.boundary, &state.content_type, range, state.size);
                    state.offset = *range.start();
                    state.mode = Mode::Body(range.end() - range.start() + 1);
                    return Ok::<_, io::Error>(Some((
                        hyper::body::Frame::data(Bytes::from(header)),
                        state,
                    )));
                }
                Mode::Body(remaining) if remaining > 0 => {
                    let bytes = super::resource_budget::read_chunk(
                        state.file.clone(),
                        state.admission.clone(),
                        state.read_budget.clone(),
                        state.offset,
                        remaining.min(64 * 1024) as usize,
                        state.read_timeout,
                    )
                    .await?;
                    let read = bytes.len();
                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "file changed during response",
                        ));
                    }
                    state.offset = state
                        .offset
                        .checked_add(read as u64)
                        .ok_or_else(|| io::Error::other("file offset overflow"))?;
                    state.mode = Mode::Body(remaining - read as u64);
                    return Ok(Some((hyper::body::Frame::data(Bytes::from(bytes)), state)));
                }
                Mode::Body(_) => {
                    if state.multipart {
                        state.mode = Mode::Separator;
                    } else {
                        state.mode = Mode::Done;
                    }
                }
                Mode::Separator => {
                    state.index += 1;
                    state.mode = if state.index < state.ranges.len() {
                        Mode::Header
                    } else {
                        Mode::Closing
                    };
                    return Ok(Some((
                        hyper::body::Frame::data(Bytes::from_static(b"\r\n")),
                        state,
                    )));
                }
                Mode::Closing => {
                    let end = format!("--{}--\r\n", state.boundary);
                    state.mode = Mode::Done;
                    return Ok(Some((hyper::body::Frame::data(Bytes::from(end)), state)));
                }
                Mode::Done => return Ok(None),
            }
        }
    });
    let body = StreamBody::new(frames)
        .map_err(|e| -> BoxError { e.into() })
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = common;
    Ok(Some(response))
}
enum Mode {
    Header,
    Body(u64),
    Separator,
    Closing,
    Done,
}
struct FileState {
    file: Arc<std::fs::File>,
    admission: Arc<tokio::sync::OwnedSemaphorePermit>,
    offset: u64,
    read_timeout: Duration,
    read_budget: super::resource_budget::BlockingBudget,
    ranges: Vec<RangeInclusive<u64>>,
    index: usize,
    boundary: String,
    content_type: String,
    size: u64,
    multipart: bool,
    mode: Mode,
}
fn part_header(boundary: &str, mime: &str, range: &RangeInclusive<u64>, size: u64) -> String {
    format!(
        "--{boundary}\r\nContent-Range: bytes {}-{}/{size}\r\nContent-Type: {mime}\r\n\r\n",
        range.start(),
        range.end()
    )
}
fn hidden(ctx: &Context, path: &std::path::Path, patterns: &[String]) -> Result<bool> {
    for pattern in patterns {
        let mut pattern = ctx.expand(pattern)?;
        if pattern.contains(std::path::MAIN_SEPARATOR) {
            let candidate = std::path::Path::new(&pattern);
            let absolute = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                std::env::current_dir()?.join(candidate)
            };
            let mut cleaned = std::path::PathBuf::new();
            for component in absolute.components() {
                if component == std::path::Component::ParentDir {
                    cleaned.pop();
                } else if component != std::path::Component::CurDir {
                    cleaned.push(component);
                }
            }
            pattern = cleaned.to_string_lossy().into_owned();
        }
        if pattern.is_empty() {
            continue;
        }
        if !pattern.contains(std::path::MAIN_SEPARATOR) {
            if path
                .components()
                .any(|part| go_path_glob(&pattern, &part.as_os_str().to_string_lossy()))
            {
                return Ok(true);
            }
        } else {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            if absolute.to_string_lossy() == pattern
                || absolute
                    .to_string_lossy()
                    .starts_with(&(pattern.clone() + "/"))
                || go_path_glob(&pattern, &absolute.to_string_lossy())
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn redirect(ctx: &Context, path: &str) -> Result<Response<Body>> {
    let path = format!("/{}", path.trim_start_matches('/'));
    let location = match ctx.req().uri().query() {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    let escaped = location
        .replace('&', "&amp;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let is_get = ctx.req().method() == Method::GET;
    let is_head = ctx.req().method() == Method::HEAD;
    let body = if is_get {
        format!("<a href=\"{escaped}\">Permanent Redirect</a>.\n\n")
    } else {
        String::new()
    };
    let mut response = simple(StatusCode::PERMANENT_REDIRECT, body);
    response
        .headers_mut()
        .insert(http::header::LOCATION, HeaderValue::from_str(&location)?);
    if is_get || is_head {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }
    Ok(response)
}
fn seconds(time: SystemTime) -> i64 {
    let seconds = match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i128::from(d.as_secs()),
        Err(e) => {
            -i128::from(e.duration().as_secs()) - i128::from(e.duration().subsec_nanos() != 0)
        }
    };
    seconds.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}
fn http_date(time: SystemTime) -> Option<String> {
    static FORMAT: std::sync::LazyLock<Vec<time::format_description::FormatItem<'static>>> =
        std::sync::LazyLock::new(|| {
            time::format_description::parse_borrowed::<1>("[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour]:[minute]:[second] GMT").expect("fixed HTTP date format")
        });
    time::OffsetDateTime::from_unix_timestamp(seconds(time))
        .ok()?
        .format(&FORMAT[..])
        .ok()
}

fn preconditions(ctx: &Context, etag: &str, modified: SystemTime) -> Option<StatusCode> {
    let headers = ctx.req().headers();
    if let Some(value) = headers
        .get(http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if value != "*"
            && !value
                .split(',')
                .any(|v| v.trim() == etag && !etag.is_empty())
        {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if let Some(value) = headers
        .get(http::header::IF_UNMODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        && !matches!(seconds(modified), 0 | 1)
        && httpdate::parse_http_date(value).is_ok_and(|t| seconds(modified) > seconds(t))
    {
        return Some(StatusCode::PRECONDITION_FAILED);
    }
    if let Some(value) = headers
        .get(http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if value == "*"
            || value.split(',').any(|v| {
                v.trim().strip_prefix("W/").unwrap_or(v.trim()) == etag && !etag.is_empty()
            })
        {
            return Some(StatusCode::NOT_MODIFIED);
        }
    } else if let Some(value) = headers
        .get(http::header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        && !matches!(seconds(modified), 0 | 1)
        && httpdate::parse_http_date(value).is_ok_and(|t| seconds(modified) <= seconds(t))
    {
        return Some(StatusCode::NOT_MODIFIED);
    }
    None
}
fn parse_ranges(
    value: &str,
    size: u64,
) -> std::result::Result<Vec<RangeInclusive<u64>>, &'static str> {
    let value = value.strip_prefix("bytes=").ok_or("invalid range")?;
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for part in value.split(',') {
        if part.trim().is_empty() {
            continue;
        }
        let (start, end) = part.trim().split_once('-').ok_or("invalid range")?;
        let range = if start.is_empty() {
            let suffix = end.parse::<u64>().map_err(|_| "invalid range")?;
            if suffix == 0 {
                continue;
            }
            if size == 0 {
                no_overlap = true;
                continue;
            }
            size.saturating_sub(suffix)..=size - 1
        } else {
            let start = start.parse::<u64>().map_err(|_| "invalid range")?;
            if start >= size {
                no_overlap = true;
                continue;
            }
            let end = if end.is_empty() {
                size - 1
            } else {
                end.parse::<u64>()
                    .map_err(|_| "invalid range")?
                    .min(size - 1)
            };
            if start > end {
                return Err("invalid range");
            }
            start..=end
        };
        ranges.push(range);
        if ranges.len() > 128 {
            return Err("invalid range");
        }
    }
    if ranges.is_empty() && no_overlap {
        return Err("invalid range: failed to overlap");
    }
    if ranges.is_empty() {
        return Err("invalid range");
    }
    Ok(ranges)
}
fn base36(value: i128) -> String {
    if value == 0 {
        return "0".into();
    }
    let negative = value < 0;
    let mut value = value.unsigned_abs();
    let mut out = Vec::new();
    while value > 0 {
        out.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[(value % 36) as usize]);
        value /= 36;
    }
    if negative {
        out.push(b'-');
    }
    out.reverse();
    String::from_utf8(out).expect("ASCII base36")
}
