//! Native directory listing. Directory I/O and rendering never run on the
//! socket worker, and no directory descriptor is held during a response.
use super::request::{Context, budget_failure, failure, file_io_failure};
use super::{Body, simple};
use chrono::{DateTime, Timelike, Utc};
use http::{HeaderMap, HeaderValue, Response, StatusCode, header};
use serde::Serialize;
use std::{
    cmp::Ordering,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

const DEFAULT_ENTRIES: usize = 10_000;
const MAX_ENTRIES: usize = 100_000;
const MAX_OUTPUT: usize = 8 << 20;
pub(super) const LISTING_BYTES_UNITS: u32 = (64 << 20) / 4096;
const MAX_OUTPUT_UNITS: u32 = (MAX_OUTPUT / 4096) as u32;
const WORK_UNITS: u32 = (32 << 20) / 4096;

#[derive(Clone)]
pub(crate) struct BrowsePlan {
    pub(crate) file_limit: i64,
    pub(crate) reveal_symlinks: bool,
    pub(crate) sort: Vec<String>,
}

#[derive(Serialize)]
struct Item {
    name: String,
    size: u64,
    url: String,
    #[serde(rename = "mod_time", serialize_with = "serialize_time")]
    modified: DateTime<Utc>,
    mode: u32,
    is_dir: bool,
    is_symlink: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    symlink_path: String,
    #[serde(skip)]
    lower: String,
}

struct Listing {
    title: String,
    items: Vec<Item>,
    can_go_up: bool,
    last_modified: SystemTime,
}

#[derive(Clone, Copy)]
enum Format {
    Json,
    Text,
    Html,
}

struct Options {
    format: Format,
    sort: String,
    order: String,
    layout: String,
    offset: usize,
    limit: usize,
    cookies: Vec<HeaderValue>,
    since: Option<SystemTime>,
}

fn serialize_time<S: serde::Serializer>(value: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    let mut text = value.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = value.nanosecond();
    if nanos != 0 {
        let fraction = format!("{nanos:09}");
        text.push('.');
        text.push_str(fraction.trim_end_matches('0'));
    }
    text.push('Z');
    s.serialize_str(&text)
}

fn uri_entry(name: &str, dir: bool) -> String {
    // Go URL.String encodes path characters; './' also keeps names containing
    // ':' relative. Encode each component and keep the directory slash.
    let mut out = String::from("./");
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~$&+,;=:@".contains(&byte) {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "%{byte:02X}");
        }
    }
    if dir {
        out.push('/');
    }
    out
}

#[cfg(unix)]
pub(super) fn mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let native = meta.permissions().mode();
    let ty = meta.file_type();
    (native & 0o777)
        | (u32::from(ty.is_dir()) << 31)
        | (u32::from(ty.is_symlink()) << 27)
        | (u32::from(ty.is_block_device() || ty.is_char_device()) << 26)
        | (u32::from(ty.is_fifo()) << 25)
        | (u32::from(ty.is_socket()) << 24)
        | (u32::from(native & 0o4000 != 0) << 23)
        | (u32::from(native & 0o2000 != 0) << 22)
        | (u32::from(ty.is_char_device()) << 21)
        | (u32::from(native & 0o1000 != 0) << 20)
}

#[cfg(not(unix))]
pub(super) fn mode(meta: &fs::Metadata) -> u32 {
    let flags = (u32::from(meta.is_dir()) << 31) | (u32::from(meta.is_symlink()) << 27);
    flags
        | if meta.permissions().readonly() {
            0o444
        } else {
            0o666
        }
}

fn known_sort(s: &str) -> bool {
    matches!(s, "name" | "namedirfirst" | "size" | "time")
}

fn known_order(s: &str) -> bool {
    matches!(s, "asc" | "desc")
}

fn options(headers: &HeaderMap, query: &str, tls: bool, plan: &BrowsePlan) -> Options {
    let mut format = Format::Html;
    for value in headers.get_all(header::ACCEPT) {
        let value = String::from_utf8_lossy(value.as_bytes()).to_ascii_lowercase();
        if value.contains("application/json") {
            format = Format::Json;
            break;
        }
        if value.contains("text/plain") {
            format = Format::Text;
        }
    }
    let cookie = |name: &str| {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|v| v.trim().split_once('='))
            .find_map(|(k, v)| (k.trim() == name).then(|| v.trim_matches('"').to_owned()))
    };
    let query = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    let param = |key| {
        query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_ref())
            .unwrap_or_default()
    };
    let mut sort = "";
    let mut order = "";
    for field in plan.sort.iter().take(2) {
        if known_sort(field) {
            sort = field;
        }
        if known_order(field) {
            order = field;
        }
    }
    if !param("sort").is_empty() {
        sort = param("sort");
    }
    if !param("order").is_empty() {
        order = param("order");
    }
    let mut cookies = Vec::new();
    for (name, value, known) in [
        ("sort", sort, known_sort(sort)),
        ("order", order, known_order(order)),
    ] {
        if known {
            let secure = if tls { "; Secure" } else { "" };
            if let Ok(v) =
                HeaderValue::from_str(&format!("{name}={value}; HttpOnly{secure}; SameSite=Lax"))
            {
                cookies.push(v);
            }
        }
    }
    let layout = match param("layout") {
        "" | "list" | "grid" => param("layout"),
        _ => "list",
    };
    Options {
        format,
        sort: if sort.is_empty() {
            cookie("sort").unwrap_or_else(|| "namedirfirst".into())
        } else {
            sort.into()
        },
        order: if order.is_empty() {
            cookie("order").unwrap_or_else(|| "asc".into())
        } else {
            order.into()
        },
        layout: layout.into(),
        offset: param("offset").parse().unwrap_or(0),
        limit: param("limit").parse().unwrap_or(0),
        cookies,
        since: headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok()),
    }
}

fn scan(
    path: &Path,
    plan: &BrowsePlan,
    mut listing: Listing,
    hidden: impl Fn(&Path) -> bool,
) -> io::Result<Listing> {
    let limit = match plan.file_limit {
        0 => DEFAULT_ENTRIES,
        v if v < 0 => MAX_ENTRIES,
        v => usize::try_from(v).unwrap_or(MAX_ENTRIES).min(MAX_ENTRIES),
    };
    let mut names_bytes = 0usize;
    for (index, result) in fs::read_dir(path)?
        .take(limit + usize::from(plan.file_limit < 0))
        .enumerate()
    {
        if index == limit {
            return Err(io::Error::other("directory entry limit exceeded"));
        }
        let entry = result?;
        let path = entry.path();
        if hidden(&path) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let modified = meta.modified().unwrap_or(listing.last_modified);
        listing.last_modified = listing.last_modified.max(modified);
        let is_symlink = meta.is_symlink();
        let target = is_symlink.then(|| fs::metadata(&path).ok()).flatten();
        let is_dir = meta.is_dir() || target.as_ref().is_some_and(fs::Metadata::is_dir);
        let mut name = entry.file_name().to_string_lossy().into_owned();
        let url = uri_entry(&name, is_dir);
        if is_dir {
            name.push('/');
        }
        let symlink_path = if is_symlink && plan.reveal_symlinks {
            fs::read_link(&path)
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };
        names_bytes = names_bytes
            .saturating_add(name.len())
            .saturating_add(url.len())
            .saturating_add(symlink_path.len());
        if names_bytes > MAX_OUTPUT {
            return Err(io::Error::other("directory metadata byte limit exceeded"));
        }
        listing.items.push(Item {
            name,
            size: target.as_ref().unwrap_or(&meta).len(),
            url,
            modified: DateTime::from(modified),
            mode: mode(&meta),
            is_dir,
            is_symlink,
            symlink_path,
            lower: String::new(),
        });
    }
    Ok(listing)
}

fn sort_and_paginate(listing: &mut Listing, options: &Options) {
    if matches!(options.sort.as_str(), "name" | "namedirfirst" | "size") {
        for item in &mut listing.items {
            item.lower = item
                .name
                .chars()
                .map(|c| c.to_lowercase().next().unwrap_or(c))
                .collect();
        }
    }
    if known_sort(&options.sort) {
        listing.items.sort_by(|a, b| {
            let order = match options.sort.as_str() {
                "name" => a.lower.cmp(&b.lower),
                "namedirfirst" => b.is_dir.cmp(&a.is_dir).then_with(|| a.lower.cmp(&b.lower)),
                "size" if a.is_dir && b.is_dir => a.lower.cmp(&b.lower),
                "size" => b.is_dir.cmp(&a.is_dir).then_with(|| a.size.cmp(&b.size)),
                "time" => a.modified.cmp(&b.modified),
                _ => Ordering::Equal,
            };
            if options.order == "desc" {
                order.reverse()
            } else {
                order
            }
        });
    }
    if options.offset <= listing.items.len() {
        listing.items.drain(..options.offset);
    }
    if options.limit != 0 {
        listing.items.truncate(options.limit);
    }
}

struct Output(Vec<u8>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_OUTPUT.saturating_sub(self.0.len()) {
            return Err(io::Error::other("directory response byte limit exceeded"));
        }
        let len = self.0.len() + bytes.len();
        if len > self.0.capacity() {
            self.0
                .try_reserve_exact(len.next_power_of_two().min(MAX_OUTPUT) - self.0.len())
                .map_err(io::Error::other)?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn human_size(size: u64) -> String {
    if size < 1024 {
        return format!("{size} B");
    }
    let mut value = size as f64;
    for unit in ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"] {
        value /= 1024.;
        if value < 1024. || unit == "EiB" {
            return if value < 10. {
                format!("{value:.1} {unit}")
            } else {
                format!("{value:.0} {unit}")
            };
        }
    }
    unreachable!()
}

fn render_text(out: &mut impl Write, listing: &Listing) -> io::Result<()> {
    const TAB: usize = 8;
    let sizes = listing
        .items
        .iter()
        .map(|item| human_size(item.size))
        .collect::<Vec<_>>();
    let width1 = (listing
        .items
        .iter()
        .map(|v| v.name.chars().count())
        .max()
        .unwrap_or(0)
        .max(4)
        + 1)
    .div_ceil(TAB);
    let width2 = (sizes.iter().map(String::len).max().unwrap_or(0).max(4) + 1).div_ceil(TAB);
    let mut row = |name: &str, size: &str, modified: &str| {
        write!(out, "{name}")?;
        for _ in 0..width1.saturating_sub(name.chars().count() / TAB) {
            out.write_all(b"\t")?;
        }
        write!(out, "{size}")?;
        for _ in 0..width2.saturating_sub(size.len() / TAB) {
            out.write_all(b"\t")?;
        }
        writeln!(out, "{modified}")
    };
    row("Name", "Size", "Modified")?;
    row("----", "----", "--------")?;
    for (item, size) in listing.items.iter().zip(&sizes) {
        row(
            &item.name,
            size,
            &item.modified.format("%B %-d, %Y at %H:%M:%S").to_string(),
        )?;
    }
    Ok(())
}

// JSON's original HTML-safe representation preserves the exact decoded
// string while escaping reserved characters. Serde writes string fragments
// as UTF-8; token punctuation does not contain any of these characters.
struct GoJson<'a>(&'a mut Output);
impl Write for GoJson<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut rest = bytes;
        while let Some(index) = rest
            .iter()
            .position(|b| matches!(*b, b'&' | b'<' | b'>' | 0xe2))
        {
            self.0.write_all(&rest[..index])?;
            let (escaped, skip): (&[u8], usize) = match &rest[index..] {
                [b'&', ..] => (br"\u0026", 1),
                [b'<', ..] => (br"\u003c", 1),
                [b'>', ..] => (br"\u003e", 1),
                [0xe2, 0x80, 0xa8, ..] => (br"\u2028", 3),
                [0xe2, 0x80, 0xa9, ..] => (br"\u2029", 3),
                _ => (&rest[index..index + 1], 1),
            };
            self.0.write_all(escaped)?;
            rest = &rest[index + skip..];
        }
        self.0.write_all(rest)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

struct Rendered {
    status: StatusCode,
    body: Vec<u8>,
    modified: Option<String>,
}

fn render(mut listing: Listing, options: &Options) -> io::Result<Rendered> {
    if options.since.is_some_and(|since| {
        super::files::seconds(listing.last_modified) <= super::files::seconds(since)
    }) {
        return Ok(Rendered {
            status: StatusCode::NOT_MODIFIED,
            body: Vec::new(),
            modified: None,
        });
    }
    sort_and_paginate(&mut listing, options);
    let mut out = Output(Vec::new());
    match options.format {
        Format::Json => {
            serde_json::to_writer(GoJson(&mut out), &listing.items)?;
            writeln!(out)?;
        }
        Format::Text => render_text(&mut out, &listing)?,
        Format::Html => render_html(&mut out, &listing, options)?,
    }
    let stamp = DateTime::<Utc>::from(listing.last_modified)
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    Ok(Rendered {
        status: StatusCode::OK,
        body: out.0,
        modified: Some(stamp),
    })
}

pub(super) async fn serve(
    ctx: &mut Context,
    path: PathBuf,
    parent: fs::Metadata,
    plan: &BrowsePlan,
    hidden: super::files::HiddenPaths,
) -> anyhow::Result<Response<Body>> {
    let path_display = ctx.req().uri().path();
    let title = super::request::decoded_path(path_display)?
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_owned();
    let listing = Listing {
        title,
        items: Vec::new(),
        can_go_up: super::request::clean_path(path_display, true) != "/",
        last_modified: parent.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    };
    let options = options(
        ctx.req().headers(),
        ctx.req().uri().query().unwrap_or_default(),
        ctx.tls,
        plan,
    );
    let format = options.format;
    let cookies = options.cookies.clone();
    let plan = plan.clone();
    let memory = ctx
        .resources
        .directory_listing_bytes
        .clone()
        .try_acquire_many_owned(WORK_UNITS)
        .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))?;
    let (rendered, mut memory) = ctx
        .resources
        .directory_listing
        .run(move || {
            let listing = scan(&path, &plan, listing, |item| hidden.matches(item))?;
            render(listing, &options).map(|rendered| (rendered, memory))
        })
        .await
        .map_err(|e| budget_failure(ctx, e))?
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                failure(StatusCode::NOT_FOUND)
            } else if e.kind() == io::ErrorKind::PermissionDenied {
                failure(StatusCode::FORBIDDEN)
            } else {
                file_io_failure(ctx, &e)
            }
        })?;
    struct ListedBytes(Vec<u8>, tokio::sync::OwnedSemaphorePermit);
    impl AsRef<[u8]> for ListedBytes {
        fn as_ref(&self) -> &[u8] {
            let _ = &self.1;
            &self.0
        }
    }
    let used = u32::try_from(rendered.body.capacity().div_ceil(4096))
        .unwrap_or(MAX_OUTPUT_UNITS)
        .max(1);
    let body = if rendered.body.is_empty() {
        bytes::Bytes::new()
    } else {
        let memory = memory
            .split(usize::try_from(used).unwrap_or(MAX_OUTPUT_UNITS as usize))
            .ok_or_else(|| failure(StatusCode::SERVICE_UNAVAILABLE))?;
        bytes::Bytes::from_owner(ListedBytes(rendered.body, memory))
    };
    let mut res = simple(rendered.status, body);
    let headers = res.headers_mut();
    headers.append(
        header::VARY,
        HeaderValue::from_static("Accept, Accept-Encoding"),
    );
    if let Some(modified) = rendered.modified {
        headers.insert(header::LAST_MODIFIED, HeaderValue::from_str(&modified)?);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(match format {
                Format::Json => "application/json; charset=utf-8",
                Format::Text => "text/plain; charset=utf-8",
                Format::Html => "text/html; charset=utf-8",
            }),
        );
        for cookie in cookies {
            headers.append(header::SET_COOKIE, cookie);
        }
    }
    Ok(res)
}

fn escape_html(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            ch => escaped.push(ch),
        }
    }
    escaped
}
fn render_html(out: &mut impl Write, listing: &Listing, opts: &Options) -> io::Result<()> {
    let title = escape_html(&listing.title);
    let layout = if opts.layout == "grid" {
        "grid"
    } else {
        "list"
    };
    writeln!(
        out,
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<style>body{{font:1rem system-ui;margin:2rem auto;padding:0 1rem;max-width:72rem}}
a{{color:inherit}}nav{{display:flex;gap:1rem;flex-wrap:wrap}}ul{{list-style:none;padding:0}}
li{{display:grid;grid-template-columns:minmax(0,1fr) 7rem 14rem;gap:1rem;padding:.65rem;border-bottom:1px solid #9995}}
li a{{overflow-wrap:anywhere}}ul.grid{{display:grid;gap:1rem;grid-template-columns:repeat(auto-fill,minmax(13rem,1fr))}}
ul.grid li{{display:flex;flex-direction:column;border:1px solid #9995;border-radius:.5rem}}
@media(max-width:44rem){{li{{display:flex;flex-wrap:wrap}}}}</style></head>
<body><h1>{title}</h1><nav aria-label="Directory view">
<a href="?layout=list">List</a><a href="?layout=grid">Grid</a>"#
    )?;
    if listing.can_go_up {
        writeln!(out, r#"<a href="../">Up</a>"#)?;
    }
    for (field, label) in [("name", "Name"), ("size", "Size"), ("time", "Modified")] {
        let order = if opts.sort == field && opts.order != "desc" {
            "desc"
        } else {
            "asc"
        };
        writeln!(
            out,
            r#"<a href="?sort={field}&amp;order={order}&amp;layout={layout}">{label}</a>"#
        )?;
    }
    writeln!(out, r#"</nav><ul class="{layout}">"#)?;
    for item in &listing.items {
        let url = escape_html(&item.url);
        let name = escape_html(&item.name);
        let size = human_size(item.size);
        let modified = item.modified.format("%Y-%m-%d %H:%M:%S UTC");
        writeln!(
            out,
            r#"<li><a href="{url}">{name}</a><span>{size}</span><time>{modified}</time></li>"#
        )?;
    }
    writeln!(out, "</ul></body></html>")
}
