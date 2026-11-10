//! An external request may revoke the process's existing file source. It can
//! never adopt a path received over HTTP or resolve it on the filesystem.
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
pub(super) enum Action {
    #[default]
    None,
    ProcessFile,
    Load {
        file: OsString,
        adapter: String,
    },
}

pub(super) struct Tracked {
    absolute: PathBuf,
    adapter: String,
    active: AtomicBool,
}
impl Tracked {
    pub(super) fn new(cwd: PathBuf, path: PathBuf, adapter: Option<String>) -> Self {
        let absolute = cwd.join(path);
        Self {
            absolute,
            adapter: adapter.unwrap_or_default(),
            active: AtomicBool::new(true),
        }
    }
    pub(super) fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    pub(super) fn accepted(&self, action: &Action) {
        let Action::Load { file, adapter } = action else {
            return;
        };
        let incoming = Path::new(file);
        // Relative paths belong to the client's cwd, and equal basenames do
        // not establish provenance. Preserve only the exact lexical source.
        let same = incoming.is_absolute() && adapter == &self.adapter && incoming == self.absolute;
        if !same {
            self.active.store(false, Ordering::Release);
        }
    }
}
