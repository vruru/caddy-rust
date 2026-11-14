use super::file_sidecars::{OpenError, SidecarPlan};
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
    inner: &Arc<super::Inner>,
    server: &Arc<super::ActiveServer>,
    configured_status: &str,
    root: Option<&str>,
    hide: &[String],
    indices: &[String],
    canonical_uris: bool,
    sidecars: &SidecarPlan,
    browse: Option<&super::browse::BrowsePlan>,
) -> Result<Option<Response<Body>>> {
    let root = ctx.expand_text_resolved(root.unwrap_or("{http.vars.root}"),true).await?;
    let decoded = decoded_path(ctx.req().uri().path())?;
    ctx.reserve_text_copy(root.len().saturating_add(decoded.len()).saturating_mul(8).saturating_add(8192))?;
    let mut path = safe_join(std::path::Path::new(&root), &decoded)?;
    let stat_path = path.clone();
    let mut metadata = match ctx
        .resources
        .metadata
        .run(super::map_runtime::text_job(ctx.text_owner(),move || std::fs::metadata(stat_path))?)
        .await
        .map_err(|error| super::request::budget_failure(ctx, error))?.into_context(ctx)?
    {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Err(failure(StatusCode::FORBIDDEN));
        }
        Err(error) => return Err(super::request::file_io_failure(ctx, &error)),
    };
    let hidden = HiddenPaths::prepare(ctx, hide).await?;
    if hidden.matches(&path) {
        return Ok(None);
    }
    let mut implicit_index = false;
    if metadata.is_dir() {
        for index in indices {
            let index=ctx.expand_text_resolved(index,true).await?;
            ctx.reserve_text_copy(path.as_os_str().len().saturating_add(index.len()).saturating_mul(8).saturating_add(8192))?;
            let candidate = path.join(index);
            if hidden.matches(&candidate) {
                continue;
            }
            let stat_path = candidate.clone();
            let lookup = ctx
                .resources
                .metadata
                .run(super::map_runtime::text_job(ctx.text_owner(),move || std::fs::metadata(stat_path))?)
                .await
                .map_err(|error| super::request::budget_failure(ctx, error))?.into_context(ctx)?;
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
            if let Some(browse) = browse {
                let base = |path: &str| {
                    path.trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                };
                let original = decoded_path(ctx.original_uri.path())?;
                if (decoded.is_empty() || base(&original) == base(&decoded))
                    && !original.ends_with('/')
                {
                    return Ok(Some(redirect(
                        ctx,
                        &format!("{}/", ctx.original_uri.path()),
                    )?));
                }
                return super::browse::serve(ctx, inner, server, std::path::PathBuf::from(root), path, metadata, browse, hidden)
                    .await
                    .map(Some);
            }
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
    if canonical_uris && base(&original) == base(&current) {
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
    let choices = super::accepted_encodings::sidecar_choices(
        ctx.req().headers(),
        &sidecars.order,
        &sidecars.encodings,
    );
    let original_etag = ctx
        .immediate
        .get(http::header::ETAG)
        .filter(|tag| !tag.is_empty())
        .cloned();
    let suffixes = original_etag
        .is_none()
        .then(|| sidecars.etag_suffixes.clone());
    let (representation, admission) = ctx
        .resources
        .metadata
        .run(super::map_runtime::text_job(ctx.text_owner(),move || {
            let representation = super::file_sidecars::open(
                &opened_path,
                &choices,
                suffixes.as_deref().unwrap_or_default(),
            )?;
            Ok::<_, OpenError>((representation, open_admission))
        })?)
        .await
        .map_err(|error| super::request::budget_failure(ctx, error))?.into_context(ctx)?
        .map_err(|error| match error {
            OpenError::Body(error) => super::request::file_io_failure(ctx, &error),
            OpenError::Etag(error) if super::request::descriptor_exhausted(&error) => {
                super::request::file_io_failure(ctx, &error)
            }
            OpenError::Etag(_) => failure(StatusCode::INTERNAL_SERVER_ERROR),
        })?;
    let file = Arc::new(representation.file);
    if let Some(coding) = representation.coding {
        ctx.immediate.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static(coding.as_str()),
        );
    }
    if !matches!(*ctx.req().method(), Method::GET | Method::HEAD)
        && !ctx.values.contains_key("http.error.status_code")
    {
        ctx.immediate
            .insert(http::header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return Err(failure(StatusCode::METHOD_NOT_ALLOWED));
    }
    // fstat pins the actual representation size and validator; sidecars
    // are transparent to Last-Modified and use the source file's time.
    let size = representation.metadata.len();
    let representation_time = representation.metadata.modified().unwrap_or(UNIX_EPOCH);
    let modified = if representation.coding.is_some() {
        metadata.modified().unwrap_or(UNIX_EPOCH)
    } else {
        representation_time
    };
    let useful = !matches!(seconds(modified), 0 | 1);
    let etag = original_etag
        .as_ref()
        .map(|v| v.as_bytes().to_vec())
        .or(representation.explicit_etag)
        .unwrap_or_else(|| calculated_etag(representation_time, size).into_bytes());
    let mut common = http::HeaderMap::new();
    if !etag.is_empty() && original_etag.is_none() {
        let mut field = etag.clone();
        for b in &mut field {
            if *b == b'\r' {
                *b = b' ';
            }
        }
        common.insert(
            http::header::ETAG,
            HeaderValue::from_bytes(field.trim_ascii())?,
        );
    }
    if useful && let Some(last_modified) = http_date(modified) {
        ctx.immediate.remove(http::header::LAST_MODIFIED);
        common.insert(
            http::header::LAST_MODIFIED,
            HeaderValue::from_str(&last_modified)?,
        );
    }
    let content_type = if let Some(existing) = ctx
        .immediate
        .get(http::header::CONTENT_TYPE)
        .filter(|v| !v.is_empty())
    {
        existing.to_str().unwrap_or_default().to_owned()
    } else {
        let inferred = super::mime::by_extension(&path).unwrap_or_default();
        if !inferred.is_empty() {
            ctx.immediate.remove(http::header::CONTENT_TYPE);
            common.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_str(&inferred)?,
            );
        }
        inferred
    };
    // Match Caddy's writer installation point: earlier missing, browse,
    // canonical redirect, open and method branches never evaluate this value.
    let override_status = match content_status(ctx, configured_status).await {
        Ok(status) => status,
        Err(error) => {
            // Caddy installs these before parsing the configured status;
            // Last-Modified belongs to ServeContent, which has not run yet.
            for name in [http::header::ETAG, http::header::CONTENT_TYPE] {
                if let Some(value) = common.get(&name) {
                    ctx.immediate.insert(name, value.clone());
                }
            }
            return Err(error);
        }
    };
    if let Some(status) = super::file_preconditions::evaluate(
        ctx.req().headers(),
        ctx.req().method(),
        &etag,
        modified,
        useful,
    ) {
        let mut r = simple(status, Bytes::new());
        *r.headers_mut() = common;
        if status == StatusCode::NOT_MODIFIED {
            for name in [
                http::header::CONTENT_TYPE,
                http::header::CONTENT_LENGTH,
                http::header::CONTENT_ENCODING,
            ] {
                ctx.immediate.remove(&name);
                r.headers_mut().remove(name);
            }
            if !etag.is_empty() {
                ctx.immediate.remove(http::header::LAST_MODIFIED);
                r.headers_mut().remove(http::header::LAST_MODIFIED);
            }
        }
        return content_response(ctx, override_status, r, false).await;
    }
    let mut ranges = None;
    let mut range_selected = false;
    if let Some(value) = ctx.req().headers().get(http::header::RANGE) {
        let allow = super::file_preconditions::range_allowed(
            ctx.req().headers(),
            ctx.req().method(),
            &etag,
            modified,
            useful,
        );
        if allow {
            match parse_ranges(&String::from_utf8_lossy(value.as_bytes()), size) {
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
                Err("invalid range: failed to overlap") if size == 0 => {
                    // Go ServeContent treats an empty representation as an
                    // empty successful response, even for a non-overlap range.
                }
                Err(message) => {
                    let mut r = simple(StatusCode::RANGE_NOT_SATISFIABLE, format!("{message}\n"));
                    *r.headers_mut() = common;
                    for name in [
                        http::header::ETAG,
                        http::header::LAST_MODIFIED,
                        http::header::CONTENT_ENCODING,
                        http::header::CONTENT_TYPE,
                        http::header::CONTENT_LENGTH,
                        http::header::CACHE_CONTROL,
                    ] {
                        ctx.immediate.remove(&name);
                        r.headers_mut().remove(name);
                    }
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
                    return content_response(ctx, override_status, r, true).await;
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
    if ranges.is_empty() {
        let mut r = simple(StatusCode::OK, Bytes::new());
        *r.headers_mut() = common;
        r.headers_mut()
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return content_response(ctx, override_status, r, false).await;
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
    let status = if partial || multipart {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    if multipart {
        ctx.immediate.remove(http::header::CONTENT_TYPE);
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
    ctx.immediate.remove(http::header::CONTENT_LENGTH);
    common.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string())?,
    );
    if ctx.req().method() == Method::HEAD {
        let mut r = simple(status, Bytes::new());
        *r.headers_mut() = common;
        return content_response(ctx, override_status, r, false).await;
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
    content_response(ctx, override_status, response, true).await
}

// Go emits the final 200 only from net/http after this handler returns when
// ServeContent made no body Write after an informational WriteHeader.
#[derive(Clone, Copy)]
pub(super) struct FileResponseImplicit;

fn content_status<'a>(
    ctx: &'a Context,
    configured: &'a str,
) -> impl std::future::Future<Output = Result<Option<StatusCode>>> + Send + 'a {
    use futures_util::future::{Either, ready};
    if configured.is_empty() {
        return Either::Left(ready(Ok(ctx.error_status)));
    }
    if configured.len() <= 32
        && !configured.as_bytes().iter().any(|byte| matches!(byte, b'{' | b'}'))
    {
        return Either::Left(ready(parse_content_status(configured)));
    }
    Either::Right(expanded_content_status(ctx, configured))
}

#[cold]
fn expanded_content_status<'a>(
    ctx: &'a Context,
    configured: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<StatusCode>>> + Send + 'a>> {
    // Construct the existing Send lookup-view future before boxing; Context
    // itself contains a request Body and is intentionally not Sync.
    let expanded = ctx.expand_text_resolved(configured, true);
    Box::pin(async move {
        let expanded = expanded.await?;
        parse_content_status(&expanded)
    })
}

fn parse_content_status(expanded: &str) -> Result<Option<StatusCode>> {
    // Native-width signed decimal parsing has strconv.Atoi's sign, ASCII,
    // overflow and whitespace rules. Empty expanded text is a syntax error.
    let code = expanded.parse::<isize>()
        .map_err(|_| failure(StatusCode::INTERNAL_SERVER_ERROR))?;
    if code <= 0 {
        return Ok(None);
    }
    // Go panics on an out-of-range positive WriteHeader code. Fail this
    // request safely, preserving service for other connections.
    u16::try_from(code).ok().and_then(|code| StatusCode::from_u16(code).ok())
        .map(Some).ok_or_else(|| failure(StatusCode::INTERNAL_SERVER_ERROR))
}

fn content_response<'a>(
    ctx: &'a mut Context,
    override_status: Option<StatusCode>,
    mut response: Response<Body>,
    body_written: bool,
) -> impl std::future::Future<Output = Result<Option<Response<Body>>>> + Send + 'a {
    use futures_util::future::{Either, ready};
    let Some(status) = override_status else {
        return Either::Left(ready(Ok(Some(response))));
    };
    if status == StatusCode::SWITCHING_PROTOCOLS && ctx.req().version() != http::Version::HTTP_11 {
        return Either::Left(ready(Err(failure(StatusCode::INTERNAL_SERVER_ERROR))));
    }
    if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
        return Either::Right(informational_content_response(ctx, status, response, body_written));
    }
    *response.status_mut() = status;
    if status == StatusCode::NOT_MODIFIED {
        // net/http suppresses Content-Type for a final 304 even if
        // ServeContent itself selected a normal body representation.
        ctx.immediate.remove(http::header::CONTENT_TYPE);
        response.headers_mut().remove(http::header::CONTENT_TYPE);
    }
    Either::Left(ready(Ok(Some(response))))
}

// Keep the rare interim writer's HeaderMap/deferred suspension state out of
// the ordinary file response future, as for static_informational.
#[cold]
fn informational_content_response<'a>(
    ctx: &'a mut Context,
    status: StatusCode,
    mut response: Response<Body>,
    body_written: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Response<Body>>>> + Send + 'a>> {
    Box::pin(async move {
        super::request::file_informational(ctx, status, &mut response).await?;
        *response.status_mut() = StatusCode::OK;
        if !body_written {
            response.extensions_mut().insert(FileResponseImplicit);
        }
        Ok(Some(response))
    })
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
pub(super) struct HiddenPaths {
    patterns: Vec<String>,
    cwd: Option<std::path::PathBuf>,
}
impl HiddenPaths {
    fn prepare<'a>(ctx:&'a Context,patterns:&'a [String])->impl std::future::Future<Output=Result<Self>>+Send+'a{
        let view=ctx.lookup_view();async move {
        let mut cwd = None;
        let mut resolved = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let mut pattern = view.expand_text_resolved(pattern,true).await?;
            view.reserve_text_copy(pattern.len().saturating_mul(8).saturating_add(8192))?;
            if pattern.contains(std::path::MAIN_SEPARATOR) {
                let candidate = std::path::Path::new(&pattern);
                let absolute = if candidate.is_absolute() {
                    candidate.to_path_buf()
                } else {
                    if cwd.is_none() {
                        cwd = Some(std::env::current_dir()?);
                    }
                    cwd.as_ref().expect("loaded").join(candidate)
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
            if !pattern.is_empty() {
                resolved.push(pattern);
            }
        }
        if cwd.is_none()
            && resolved
                .iter()
                .any(|p| p.contains(std::path::MAIN_SEPARATOR))
        {
            cwd = Some(std::env::current_dir()?);
        }
        Ok(Self {
            patterns: resolved,
            cwd,
        })
    }}
    pub(super) fn matches(&self, path: &std::path::Path) -> bool {
        let absolute = self.cwd.as_ref().map(|cwd| cwd.join(path));
        let absolute = absolute.as_deref().unwrap_or(path).to_string_lossy();
        self.patterns.iter().any(|pattern| {
            if !pattern.contains(std::path::MAIN_SEPARATOR) {
                path.components()
                    .any(|part| go_path_glob(pattern, &part.as_os_str().to_string_lossy()))
            } else {
                absolute == *pattern
                    || absolute
                        .strip_prefix(pattern)
                        .is_some_and(|s| s.starts_with(std::path::MAIN_SEPARATOR))
                    || go_path_glob(pattern, &absolute)
            }
        })
    }
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
pub(super) fn seconds(time: SystemTime) -> i64 {
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

fn calculated_etag(modified: SystemTime, size: u64) -> String {
    if matches!(seconds(modified), 0 | 1) {
        return String::new();
    }
    let nanos = match modified.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    };
    format!(
        "\"{}-{}\"",
        base36(nanos as i64 as i128),
        base36(size as i128)
    )
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
