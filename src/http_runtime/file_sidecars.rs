//! Selection and opening of built-in encoded file representations.
use super::accepted_encodings::Coding;
use crate::http_config::helpers::open_regular_file;
use std::{
    fs::{File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

// The resulting value is an HTTP field, not a served file. Read at most
// this many bytes plus one to distinguish truncation from normal EOF.
const ETAG_BYTES_MAX: u64 = 64 * 1024;

#[derive(Clone, Default)]
pub(crate) struct SidecarPlan {
    pub(crate) encodings: Vec<Coding>,
    pub(crate) order: Vec<String>,
    pub(crate) etag_suffixes: Arc<[String]>,
}

pub(super) struct Representation {
    pub file: File,
    pub metadata: Metadata,
    pub coding: Option<Coding>,
    pub explicit_etag: Option<Vec<u8>>,
}

pub(super) enum OpenError {
    Body(io::Error),
    Etag(io::Error),
}

pub(super) fn open(
    identity: &Path,
    choices: &[Coding],
    etag_suffixes: &[String],
) -> Result<Representation, OpenError> {
    for &coding in choices {
        let candidate = append(
            identity,
            match coding {
                Coding::Gzip => ".gz",
                Coding::Zstd => ".zst",
                Coding::Brotli => ".br",
            },
        );
        match open_regular_file(&candidate) {
            Ok(file) => return representation(file, &candidate, Some(coding), etag_suffixes),
            Err(error) if super::request::descriptor_exhausted(&error) => {
                return Err(OpenError::Body(error));
            }
            // A broken optional representation must not hide the identity.
            // This includes a symlink loop and a valid NAME_MAX source whose
            // appended encoding suffix would exceed the filesystem limit.
            Err(_) => continue,
        }
    }
    let file = open_regular_file(identity).map_err(OpenError::Body)?;
    representation(file, identity, None, etag_suffixes)
}

fn representation(
    file: File,
    path: &Path,
    coding: Option<Coding>,
    etag_suffixes: &[String],
) -> Result<Representation, OpenError> {
    let metadata = file.metadata().map_err(OpenError::Body)?;
    let explicit_etag = read_etag(path, etag_suffixes).map_err(OpenError::Etag)?;
    Ok(Representation {
        file,
        metadata,
        coding,
        explicit_etag,
    })
}

fn append(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn read_etag(path: &Path, suffixes: &[String]) -> io::Result<Option<Vec<u8>>> {
    for suffix in suffixes {
        let file = match open_regular_file(append(path, suffix)) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let mut bytes = Vec::new();
        file.take(ETAG_BYTES_MAX + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > ETAG_BYTES_MAX {
            return Err(io::Error::other("file ETag limit exceeded"));
        }
        bytes.retain(|&b| b != b'\n');
        // An empty first sidecar triggers the generated tag, not the next
        // configured suffix (which would override administrator priority).
        return Ok((!bytes.is_empty()).then_some(bytes));
    }
    Ok(None)
}
