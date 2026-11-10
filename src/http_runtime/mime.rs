// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Behavioral port of Go mime.TypeByExtension (go1.26.4).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::LazyLock;

const MAX_LINE_LENGTH: usize = 64 * 1024;
const MAX_TOTAL_SIZE: usize = 16 * 1024 * 1024;

const MIME_GLOBS: &[&str] = &["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"];

const MIME_TYPE_FILES: &[&str] = &[
    "/etc/mime.types",
    "/etc/apache2/mime.types",
    "/etc/apache/mime.types",
    "/etc/httpd/conf/mime.types",
];

const BUILTIN_TYPES: &[(&str, &str)] = &[
    (".ai", "application/postscript"),
    (".apk", "application/vnd.android.package-archive"),
    (".apng", "image/apng"),
    (".avif", "image/avif"),
    (".bin", "application/octet-stream"),
    (".bmp", "image/bmp"),
    (".com", "application/octet-stream"),
    (".css", "text/css; charset=utf-8"),
    (".csv", "text/csv; charset=utf-8"),
    (".doc", "application/msword"),
    (
        ".docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (".ehtml", "text/html; charset=utf-8"),
    (".eml", "message/rfc822"),
    (".eps", "application/postscript"),
    (".exe", "application/octet-stream"),
    (".flac", "audio/flac"),
    (".gif", "image/gif"),
    (".gz", "application/gzip"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".ico", "image/vnd.microsoft.icon"),
    (".ics", "text/calendar; charset=utf-8"),
    (".jfif", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".m4a", "audio/mp4"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".mp3", "audio/mpeg"),
    (".mp4", "video/mp4"),
    (".oga", "audio/ogg"),
    (".ogg", "audio/ogg"),
    (".ogv", "video/ogg"),
    (".opus", "audio/ogg"),
    (".pdf", "application/pdf"),
    (".pjp", "image/jpeg"),
    (".pjpeg", "image/jpeg"),
    (".png", "image/png"),
    (".ppt", "application/vnd.ms-powerpoint"),
    (
        ".pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    (".ps", "application/postscript"),
    (".rdf", "application/rdf+xml"),
    (".rtf", "application/rtf"),
    (".shtml", "text/html; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".text", "text/plain; charset=utf-8"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".txt", "text/plain; charset=utf-8"),
    (".vtt", "text/vtt; charset=utf-8"),
    (".wasm", "application/wasm"),
    (".wav", "audio/wav"),
    (".webm", "audio/webm"),
    (".webp", "image/webp"),
    (".xbl", "text/xml; charset=utf-8"),
    (".xbm", "image/x-xbitmap"),
    (".xht", "application/xhtml+xml"),
    (".xhtml", "application/xhtml+xml"),
    (".xls", "application/vnd.ms-excel"),
    (
        ".xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    (".xml", "text/xml; charset=utf-8"),
    (".xsl", "text/xml; charset=utf-8"),
    (".zip", "application/zip"),
];

struct CaseInsensitiveMap {
    exact: HashMap<String, String>,
    lower: HashMap<String, String>,
}

impl CaseInsensitiveMap {
    fn new() -> Self {
        Self {
            exact: HashMap::new(),
            lower: HashMap::new(),
        }
    }

    fn set_extension_type(&mut self, extension: &str, mime_type: &str) {
        if mime_type.parse::<mime_guess::mime::Mime>().is_err() {
            return;
        }
        let (just_type, has_charset) = parse_media_type_check_charset(mime_type);

        let final_mime = if just_type.starts_with("text/") && !has_charset {
            format!("{}; charset=utf-8", mime_type)
        } else {
            mime_type.to_string()
        };

        let key_exact = extension.to_string();
        let key_lower = extension.to_lowercase();

        self.exact.insert(key_exact, final_mime.clone());
        self.lower.insert(key_lower, final_mime);
    }

    fn get_exact(&self, ext: &str) -> Option<&String> {
        self.exact.get(ext)
    }

    fn get_lower(&self, ext_lower: &str) -> Option<&String> {
        self.lower.get(ext_lower)
    }

    fn contains_key_exact(&self, ext: &str) -> bool {
        self.exact.contains_key(ext)
    }
}

fn parse_media_type_check_charset(mime: &str) -> (String, bool) {
    let parts: Vec<&str> = mime.splitn(2, ';').collect();
    let just_type = parts[0].trim().to_lowercase();

    let has_charset = if parts.len() > 1 {
        parts[1].split(';').any(|p| {
            let kv: Vec<&str> = p.splitn(2, '=').collect();
            if kv.len() == 2 {
                let key = kv[0].trim().to_lowercase();
                let value = kv[1].trim();
                key == "charset" && !value.is_empty()
            } else {
                false
            }
        })
    } else {
        false
    };

    (just_type, has_charset)
}

fn load_mime_globs_file(
    filename: &str,
    map: &mut CaseInsensitiveMap,
) -> Result<(), std::io::Error> {
    let file = crate::http_config::helpers::open_regular_file(filename)?;
    let mut reader = BufReader::new(file).take(MAX_TOTAL_SIZE as u64);
    let mut total_size = 0usize;
    let mut buffer = Vec::with_capacity(MAX_LINE_LENGTH);

    loop {
        buffer.clear();
        let bytes_read = reader.read_until(b'\n', &mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        total_size += bytes_read;
        if total_size > MAX_TOTAL_SIZE {
            break;
        }

        if buffer.len() > MAX_LINE_LENGTH {
            // Truncate to max line length for processing, consume rest?
            // Go's bufio.Scanner discards lines that are too long.
            // We just skip processing this line if it exceeds limit.
            // Note: buffer includes newline. If buffer.len() > MAX_LINE_LENGTH, skip.
            continue;
        }

        // Remove trailing newline
        if buffer.ends_with(b"\n") {
            buffer.pop();
        }
        if buffer.ends_with(b"\r") {
            buffer.pop();
        }

        // Convert to string, handling invalid UTF-8 by skipping
        let line_str = match std::str::from_utf8(&buffer) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let fields: Vec<&str> = line_str.split(':').collect();
        if fields.len() < 3 {
            continue;
        }

        // fields[0] = weight
        // fields[1] = mimetype
        // fields[2] = glob

        if fields[0].is_empty() || fields[0].starts_with('#') {
            continue;
        }
        if fields[2].len() < 3 {
            continue;
        }
        if !fields[2].starts_with("*.") {
            continue;
        }

        let extension = &fields[2][1..];

        if extension.contains('?') || extension.contains('*') || extension.contains('[') {
            continue;
        }

        if map.contains_key_exact(extension) {
            continue;
        }

        map.set_extension_type(extension, fields[1]);
    }

    Ok(())
}

fn load_mime_file(filename: &str, map: &mut CaseInsensitiveMap) {
    let file = match crate::http_config::helpers::open_regular_file(filename) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut reader = BufReader::new(file).take(MAX_TOTAL_SIZE as u64);
    let mut total_size = 0usize;
    let mut buffer = Vec::with_capacity(MAX_LINE_LENGTH);

    loop {
        buffer.clear();
        let bytes_read = match reader.read_until(b'\n', &mut buffer) {
            Ok(n) => n,
            Err(_) => return,
        };
        if bytes_read == 0 {
            break;
        }
        total_size += bytes_read;
        if total_size > MAX_TOTAL_SIZE {
            break;
        }

        if buffer.len() > MAX_LINE_LENGTH {
            continue;
        }

        if buffer.ends_with(b"\n") {
            buffer.pop();
        }
        if buffer.ends_with(b"\r") {
            buffer.pop();
        }

        let line_str = match std::str::from_utf8(&buffer) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let fields: Vec<&str> = line_str.split_whitespace().collect();
        if fields.len() <= 1 {
            continue;
        }
        if fields[0].starts_with('#') {
            continue;
        }

        let mime_type = fields[0];
        for ext in &fields[1..] {
            if ext.starts_with('#') {
                break;
            }
            let extension = format!(".{}", ext);
            map.set_extension_type(&extension, mime_type);
        }
    }
}

static MIME_TYPES: LazyLock<CaseInsensitiveMap> = LazyLock::new(|| {
    let mut local = CaseInsensitiveMap::new();

    // Initialize from builtins
    for (k, v) in BUILTIN_TYPES {
        local.set_extension_type(k, v);
    }

    // Try globs files first
    let mut globs_loaded = false;
    for &filename in MIME_GLOBS {
        if load_mime_globs_file(filename, &mut local).is_ok() {
            globs_loaded = true;
            break;
        }
    }

    if !globs_loaded {
        for &filename in MIME_TYPE_FILES {
            load_mime_file(filename, &mut local);
        }
    }

    local
});

pub(super) fn by_extension(path: &Path) -> Option<String> {
    let ext_no_dot = path.extension()?.to_string_lossy().into_owned();

    let ext = format!(".{}", ext_no_dot);

    if let Some(v) = MIME_TYPES.get_exact(&ext) {
        return Some(v.clone());
    }

    let ext_lower = ascii_to_lowercase(&ext);

    if let Some(v) = MIME_TYPES.get_lower(&ext_lower) {
        return Some(v.clone());
    }

    None
}

fn ascii_to_lowercase(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut all_ascii = true;
    for &b in bytes {
        if b >= 0x80 {
            all_ascii = false;
            break;
        }
    }
    if all_ascii {
        let mut lower = String::with_capacity(s.len());
        for &b in bytes {
            if b.is_ascii_uppercase() {
                lower.push((b + (b'a' - b'A')) as char);
            } else {
                lower.push(b as char);
            }
        }
        lower
    } else {
        s.to_lowercase()
    }
}

pub(super) fn initialize() {
    std::sync::LazyLock::force(&MIME_TYPES);
}
