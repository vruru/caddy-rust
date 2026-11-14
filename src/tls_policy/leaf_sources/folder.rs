//! Bounded deterministic leaf-folder traversal, before verifier publication.
use super::*;

pub(super) struct Files {
    pub paths: Vec<PathBuf>,
    _credit: crate::acme_wire::chain_memory::Scratch,
}

struct Walk {
    files: Files,
    entries: usize,
    charged: usize,
}

impl Walk {
    fn admit(&mut self, path_bytes: usize) -> Result<()> {
        ensure!(path_bytes <= 4096, "leaf folder path exceeds limit");
        self.entries = self.entries.checked_add(1).ok_or(ResourceDenied)?;
        ensure!(self.entries <= 4096, "leaf folder entry count exceeds limit");
        // Covers this path and its temporary directory-list copy. The same
        // owner stays with the final list until every selected file is read.
        let bytes = path_bytes.checked_mul(2)
            .and_then(|n| n.checked_add(256)).ok_or(ResourceDenied)?;
        self.charged = self.charged.checked_add(bytes).ok_or(ResourceDenied)?;
        self.files._credit.grow_to(self.charged)?;
        Ok(())
    }

    fn visit(&mut self, path: PathBuf, depth: usize, cancel: &CancellationToken) -> Result<()> {
        ensure!(!cancel.is_cancelled(), "leaf input preparation cancelled");
        ensure!(depth <= 64, "leaf folder depth exceeds limit");
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(&path)? {
                ensure!(!cancel.is_cancelled(), "leaf input preparation cancelled");
                let entry = entry?;
                let name = entry.file_name();
                self.admit(path.as_os_str().as_encoded_bytes().len()
                    .checked_add(name.as_encoded_bytes().len() + 1).ok_or(ResourceDenied)?)?;
                entries.try_reserve(1).map_err(|_| ResourceDenied)?;
                entries.push(entry.path());
            }
            entries.sort();
            for path in entries { self.visit(path, depth + 1, cancel)?; }
        } else if path.file_name().is_some_and(|name| {
            name.as_encoded_bytes().get(name.as_encoded_bytes().len().saturating_sub(4)..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b".pem"))
        }) {
            // Walk does not follow directory symlinks. An explicitly selected
            // PEM is still subjected to the existing regular-file read gate.
            self.files.paths.try_reserve(1).map_err(|_| ResourceDenied)?;
            self.files.paths.push(path);
        }
        Ok(())
    }
}

pub(super) fn list(raw: &str, cwd: &Path, cancel: &CancellationToken) -> Result<Files> {
    let expanded = crate::tls_app_config::leaf_values::expand(raw, cwd, cancel)?;
    let path = crate::tls_app_config::leaf_values::absolute(expanded.as_bytes(), cwd)?;
    let mut walk = Walk {
        files: Files { paths: Vec::new(), _credit: cert_transient::reserve(1024)? },
        entries: 0, charged: 1024,
    };
    walk.admit(path.as_os_str().as_encoded_bytes().len())?;
    walk.visit(path, 0, cancel)?;
    Ok(walk.files)
}
