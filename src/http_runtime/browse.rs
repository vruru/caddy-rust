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
    pub(crate) template_file: String,
    pub(crate) file_limit: i64,
    pub(crate) reveal_symlinks: bool,
    pub(crate) sort: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct Item {
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) url: String,
    #[serde(rename = "mod_time", serialize_with = "serialize_time")]
    pub(super) modified: DateTime<Utc>,
    pub(super) mode: u32,
    pub(super) is_dir: bool,
    pub(super) is_symlink: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(super) symlink_path: String,
    #[serde(skip)]
    lower: String,
    #[serde(skip)]
    pub(super) raw_name: Vec<u8>,
    #[serde(skip)]
    pub(super) raw_symlink_path: Vec<u8>,
}

impl Item {
    pub(super) fn zero()->Self{Self{name:String::new(),size:0,url:String::new(),modified:DateTime::from_timestamp(-62135596800,0).expect("Go zero time"),mode:0,is_dir:false,is_symlink:false,symlink_path:String::new(),lower:String::new(),raw_name:Vec::new(),raw_symlink_path:Vec::new()}}
}

pub(super) struct Listing {
    pub(super) title: String,
    pub(super) items: Vec<Item>,
    pub(super) backing_capacity: usize,
    pub(super) can_go_up: bool,
    pub(super) last_modified: SystemTime,
    pub(super) path: String,
    pub(super) num_dirs: i64,
    pub(super) num_files: i64,
    pub(super) total_size: i64,
    pub(super) total_following_size: i64,
    pub(super) offset: usize,
    pub(super) limit: usize,
    pub(super) sort: Vec<u8>,
    pub(super) order: Vec<u8>,
    pub(super) layout: Vec<u8>,
}

// Declaration order is deliberate: abort drops owned source data before the
// directory credit. The worker retires the credit only after Tree accounting
// and the actual host view have both taken ownership.
pub(super) struct ListingSource {
    pub(super) listing: Option<Listing>,
    pub(super) memory: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(super) bytes: usize,
}
impl Listing {
    fn allocation_bytes(&self)->io::Result<usize>{
        let mut bytes=std::mem::size_of::<Self>().checked_add(self.items.capacity().checked_mul(std::mem::size_of::<Item>()).ok_or_else(||io::Error::other("listing capacity overflow"))?).ok_or_else(||io::Error::other("listing capacity overflow"))?;
        for size in [self.title.capacity(),self.path.capacity(),self.sort.capacity(),self.order.capacity(),self.layout.capacity()] {bytes=bytes.checked_add(size).ok_or_else(||io::Error::other("listing capacity overflow"))?;}
        for item in &self.items {for size in [item.name.capacity(),item.url.capacity(),item.symlink_path.capacity(),item.lower.capacity(),item.raw_name.capacity(),item.raw_symlink_path.capacity()] {bytes=bytes.checked_add(size).ok_or_else(||io::Error::other("listing capacity overflow"))?;}}
        Ok(bytes)
    }
}

#[derive(Clone, Copy)]
enum Format {
    Json,
    Text,
    Html,
}

struct Options {
    format: Format,
    sort: Vec<u8>,
    order: Vec<u8>,
    layout: Vec<u8>,
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

fn uri_entry(name: &[u8], dir: bool) -> String {
    // Go URL.String encodes path characters; './' also keeps names containing
    // ':' relative. Encode each component and keep the directory slash.
    let mut out = String::from("./");
    for byte in name.iter().copied() {
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

fn known_sort(s: &[u8]) -> bool {matches!(s,b"name"|b"namedirfirst"|b"size"|b"time")}
fn known_order(s: &[u8]) -> bool {matches!(s,b"asc"|b"desc")}

fn options(headers: &HeaderMap, query: &str, tls: bool, plan: &BrowsePlan) -> Options {
    let mut format=Format::Html;
    for value in headers.get_all(header::ACCEPT) {
        let value=gotmpl::go_utf8_text(value.as_bytes()).chars().map(|c|c.to_lowercase().next().unwrap_or(c)).collect::<String>();
        if value.contains("application/json"){format=Format::Json;break;}
        if value.contains("text/plain"){format=Format::Text;}
    }
    let cookie=|name:&[u8]|{
        headers.get_all(header::COOKIE).iter().flat_map(|field|field.as_bytes().split(|b|*b==b';')).find_map(|part|{
            let part=part.trim_ascii();let at=part.iter().position(|b|*b==b'=')?;
            if part[..at].trim_ascii()!=name{return None;}
            let value=&part[at+1..];
            let value=if value.len()>=2&&value.first()==Some(&b'"')&&value.last()==Some(&b'"'){&value[1..value.len()-1]}else{value};
            value.iter().all(|b|*b>=0x20&&*b<0x7f&&!b"\";\\".contains(b)).then(||value.to_vec())
        })
    };
    // Reuse the strict byte parser used by request Query. Retain only the six
    // first values needed here, including invalid-UTF8 values; malformed pairs
    // are skipped exactly as URL.Query does rather than decoded lossily.
    let mut query_values=std::collections::BTreeMap::<&str,Vec<u8>>::new();
    for part in query.as_bytes().split(|b|*b==b'&') {
        let Some((key,value))=super::query_match::query_pair(part)else{continue;};
        let key=match key.as_ref(){b"sort"=>"sort",b"order"=>"order",b"layout"=>"layout",b"offset"=>"offset",b"limit"=>"limit",_=>continue};
        query_values.entry(key).or_insert_with(||value.into_owned());
    }
    let param=|key:&str|query_values.get(key).map_or(&b""[..],Vec::as_slice);
    let mut sort=&b""[..];let mut order=&b""[..];
    for field in plan.sort.iter().take(2){if known_sort(field.as_bytes()){sort=field.as_bytes();}if known_order(field.as_bytes()){order=field.as_bytes();}}
    if !param("sort").is_empty(){sort=param("sort");}
    if !param("order").is_empty(){order=param("order");}
    let mut cookies=Vec::new();
    for(name,value,known)in[("sort",sort,known_sort(sort)),("order",order,known_order(order))]{
        if known {let value=std::str::from_utf8(value).expect("known ASCII browse option");let secure=if tls{"; Secure"}else{""};if let Ok(value)=HeaderValue::from_str(&format!("{name}={value}; HttpOnly{secure}; SameSite=Lax")){cookies.push(value);}}
    }
    let layout=match param("layout"){b""|b"list"|b"grid"=>param("layout"),_=>b"list"};
    Options{format,sort:if sort.is_empty(){cookie(b"sort").unwrap_or_else(||b"namedirfirst".to_vec())}else{sort.to_vec()},order:if order.is_empty(){cookie(b"order").unwrap_or_else(||b"asc".to_vec())}else{order.to_vec()},layout:layout.to_vec(),offset:std::str::from_utf8(param("offset")).ok().and_then(|s|s.parse().ok()).unwrap_or(0),limit:std::str::from_utf8(param("limit")).ok().and_then(|s|s.parse().ok()).unwrap_or(0),cookies,since:headers.get(header::IF_MODIFIED_SINCE).and_then(|v|v.to_str().ok()).and_then(|v|httpdate::parse_http_date(v).ok())}
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
    let mut metadata_bytes=0usize;
    for (index, result) in fs::read_dir(path)?
        .take(limit + usize::from(plan.file_limit < 0))
        .enumerate()
    {
        if index == limit {
            return Err(io::Error::other("directory entry limit exceeded"));
        }
        let entry = result?;
        listing.backing_capacity=index+1;
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
        let mut raw_name = entry.file_name().as_encoded_bytes().to_vec();
        let mut name = gotmpl::go_utf8_text(&raw_name).into_owned();
        let url = uri_entry(&raw_name, is_dir);
        if is_dir {
            name.push('/');
            raw_name.push(b'/');
        }
        let raw_symlink_path = if is_symlink && plan.reveal_symlinks {
            fs::read_link(&path).ok().map(|p|p.as_os_str().as_encoded_bytes().to_vec()).unwrap_or_default()
        } else {Vec::new()};
        let symlink_path = gotmpl::go_utf8_text(&raw_symlink_path).into_owned();
        if is_dir {listing.num_dirs+=1;} else {
            listing.num_files+=1;
            listing.total_size=listing.total_size.wrapping_add(meta.len() as i64);
            listing.total_following_size=listing.total_following_size.wrapping_add(target.as_ref().unwrap_or(&meta).len() as i64);
        }
        names_bytes = names_bytes
            .saturating_add(name.len())
            .saturating_add(url.len())
            .saturating_add(symlink_path.len());
        if names_bytes > MAX_OUTPUT {
            return Err(io::Error::other("directory metadata byte limit exceeded"));
        }
        // The permit covers32MiB for the native listing, separately from a
        // custom template's32MiB host graph. Include actual owned capacities,
        // the next Vec growth and a conservative lowercase-cache capacity.
        let next_capacity=if listing.items.len()==listing.items.capacity(){listing.items.capacity().max(8).saturating_mul(2).min(limit).max(listing.items.len()+1)}else{listing.items.capacity()};
        let retained=name.capacity().checked_add(url.capacity()).and_then(|v|v.checked_add(symlink_path.capacity())).and_then(|v|v.checked_add(raw_name.capacity())).and_then(|v|v.checked_add(raw_symlink_path.capacity())).and_then(|v|name.len().checked_mul(8)?.checked_add(v)).ok_or_else(||io::Error::other("directory metadata size overflow"))?;
        let next_metadata=metadata_bytes.checked_add(retained).ok_or_else(||io::Error::other("directory metadata size overflow"))?;
        let peak=next_capacity.checked_mul(2*std::mem::size_of::<Item>()).and_then(|v|v.checked_add(next_metadata)).and_then(|v|v.checked_add(2*MAX_OUTPUT+(8<<20)+32768)).ok_or_else(||io::Error::other("directory metadata size overflow"))?;
        if peak>WORK_UNITS as usize*4096{return Err(io::Error::other("directory metadata allocation budget exceeded"));}
        if next_capacity>listing.items.capacity(){listing.items.try_reserve_exact(next_capacity-listing.items.len()).map_err(io::Error::other)?;}
        metadata_bytes=next_metadata;
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
            raw_name, raw_symlink_path,
        });
    }
    Ok(listing)
}

fn sort_and_paginate(listing: &mut Listing, options: &Options, preserve_backing: bool) {
    if matches!(options.sort.as_slice(), b"name" | b"namedirfirst" | b"size") {
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
            let order = match options.sort.as_slice() {
                b"name" => a.lower.cmp(&b.lower),
                b"namedirfirst" => b.is_dir.cmp(&a.is_dir).then_with(|| a.lower.cmp(&b.lower)),
                b"size" if a.is_dir && b.is_dir => a.lower.cmp(&b.lower),
                b"size" => b.is_dir.cmp(&a.is_dir).then_with(|| a.size.cmp(&b.size)),
                b"time" => a.modified.cmp(&b.modified),
                _ => Ordering::Equal,
            };
            if options.order == b"desc" {
                order.reverse()
            } else {
                order
            }
        });
    }
    if options.offset>0 && options.offset <= listing.items.len() {
        if !preserve_backing {listing.items.drain(..options.offset);}
        listing.offset=options.offset;
    }
    let visible=listing.items.len().saturating_sub(if preserve_backing{listing.offset}else{0});
    if options.limit>0 && options.limit<=visible {
        if !preserve_backing {listing.items.truncate(options.limit);}
        listing.limit=options.limit;
    }
    listing.sort=options.sort.clone();listing.order=options.order.clone();listing.layout=options.layout.clone();
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

pub(super) fn human_size(size: u64) -> String {
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
    let mut row = |name: &[u8], size: &str, modified: &str| {
        out.write_all(name)?;
        for _ in 0..width1.saturating_sub(gotmpl::go_utf8_text(name).chars().count() / TAB) {
            out.write_all(b"\t")?;
        }
        write!(out, "{size}")?;
        for _ in 0..width2.saturating_sub(size.len() / TAB) {
            out.write_all(b"\t")?;
        }
        writeln!(out, "{modified}")
    };
    row(b"Name", "Size", "Modified")?;
    row(b"----", "----", "--------")?;
    for (item, size) in listing.items.iter().zip(&sizes) {
        row(
            &item.raw_name,
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
    sort_and_paginate(&mut listing, options, false);
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
    inner: &std::sync::Arc<super::Inner>,
    server: &std::sync::Arc<super::ActiveServer>,
    root: PathBuf,
    path: PathBuf,
    parent: fs::Metadata,
    plan: &BrowsePlan,
    hidden: super::files::HiddenPaths,
) -> anyhow::Result<Response<Body>> {
    let memory=ctx.resources.directory_listing_bytes.clone().try_acquire_many_owned(WORK_UNITS).map_err(|_|failure(StatusCode::SERVICE_UNAVAILABLE))?;
    let option_bytes=ctx.req().headers().iter().filter(|(name,_)|**name==header::ACCEPT||**name==header::COOKIE).try_fold(ctx.req().uri().query().map_or(0,str::len),|n,(_,value)|n.checked_add(value.as_bytes().len())).ok_or_else(||failure(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE))?;
    if option_bytes>1<<20{return Err(failure(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE));}
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
        backing_capacity:0,
        can_go_up: super::request::clean_path(path_display, true) != "/",
        last_modified: parent.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        path: {let p=super::request::clean_path(path_display,true);let p=p.trim_end_matches('/');if p.is_empty(){"/".into()}else{p.into()}},
        num_dirs:0,num_files:0,total_size:0,total_following_size:0,offset:0,limit:0,sort:Vec::new(),order:Vec::new(),layout:Vec::new(),
    };
    let options = options(
        ctx.req().headers(),
        ctx.req().uri().query().unwrap_or_default(),
        ctx.tls,
        plan,
    );
    let custom=matches!(options.format,Format::Html)&&!plan.template_file.is_empty();
    let format = options.format;
    let cookies = options.cookies.clone();
    let plan = plan.clone();
    enum Prepared {Rendered(Rendered),Custom(Listing,PathBuf,usize)}
    let (prepared, mut memory) = ctx
        .resources
        .directory_listing
        .run(move || {
            let mut listing = scan(&path, &plan, listing, |item| hidden.matches(item))?;
            let unchanged=options.since.is_some_and(|since|super::files::seconds(listing.last_modified)<=super::files::seconds(since));
            if custom&&!unchanged {
                sort_and_paginate(&mut listing,&options, true);
                let bytes=listing.allocation_bytes()?;
                Ok((Prepared::Custom(listing,PathBuf::from(plan.template_file),bytes),memory))
            } else {render(listing,&options).map(|rendered|(Prepared::Rendered(rendered),memory))}
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
    let rendered=match prepared {
        Prepared::Rendered(rendered)=>rendered,
        Prepared::Custom(listing,file,bytes)=>{
            let stamp=DateTime::<Utc>::from(listing.last_modified).format("%a, %d %b %Y %H:%M:%S GMT").to_string();
            let mut headers=std::mem::take(&mut ctx.immediate);
            headers.append(header::VARY,HeaderValue::from_static("Accept, Accept-Encoding"));
            headers.insert(header::LAST_MODIFIED,HeaderValue::from_str(&stamp)?);
            for cookie in &cookies {headers.append(header::SET_COOKIE,cookie.clone());}
            let source=ListingSource{listing:Some(listing),memory:Some(memory),bytes};
            let body=match super::templates::browse(ctx,inner,server,root,file,source,&mut headers).await {
                Ok(body)=>body,
                Err(error)=>{ctx.immediate=headers;return Err(failure(error.0));}
            };
            let length=body.len();
            let mut response=simple(StatusCode::OK,body);
            headers.insert(header::CONTENT_TYPE,HeaderValue::from_static("text/html; charset=utf-8"));
            *response.headers_mut()=headers;
            if ctx.req().method()==http::Method::HEAD {
                response.extensions_mut().insert(super::request::StaticHeadLength(length));
                response.extensions_mut().insert(super::request::RenderedTemplateHead);
            }
            return Ok(response);
        }
    };
    struct ListedBytes(Vec<u8>, tokio::sync::OwnedSemaphorePermit);
    impl AsRef<[u8]> for ListedBytes {
        fn as_ref(&self) -> &[u8] {
            let _ = &self.1;
            &self.0
        }
    }
    let prepared_length=rendered.body.len();
    let prepared_status=rendered.status;
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
    if ctx.req().method()==http::Method::HEAD&&prepared_status==StatusCode::OK {
        // This Vec was fully produced above; no body hint or stream is read to
        // discover a length. Enclosing templates may consume this finite entity.
        res.extensions_mut().insert(super::request::StaticHeadLength(prepared_length));
    }
    let headers = res.headers_mut();
    headers.append(header::VARY,HeaderValue::from_static("Accept, Accept-Encoding"));
    if let Some(modified)=&rendered.modified {
        headers.insert(header::LAST_MODIFIED,HeaderValue::from_str(modified)?);
        for cookie in &cookies {headers.append(header::SET_COOKIE,cookie.clone());}
    }
    if rendered.modified.is_some() {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(match format {
                Format::Json => "application/json; charset=utf-8",
                Format::Text => "text/plain; charset=utf-8",
                Format::Html => "text/html; charset=utf-8",
            }),
        );
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
    let layout = if opts.layout == b"grid" {
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
        let order = if opts.sort == field.as_bytes() && opts.order != b"desc" {
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
