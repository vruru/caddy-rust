//! Caddy's platform/environment application directories captured at startup.
use super::*;
fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}
fn absolute(cwd: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}
pub fn data(cwd: &Path) -> PathBuf {
    if let Some(base) = env_path("XDG_DATA_HOME") {
        return absolute(cwd, base.join("caddy"));
    }
    if let Some(home) = env_path("HOME") {
        let path = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/Caddy")
        } else if cfg!(target_os = "android") {
            home.join("caddy")
        } else {
            home.join(".local/share/caddy")
        };
        return absolute(cwd, path);
    }
    cwd.join("caddy")
}
pub fn config(cwd: &Path) -> PathBuf {
    if let Some(base) = env_path("XDG_CONFIG_HOME") {
        return absolute(cwd, base.join("caddy"));
    }
    if let Some(home) = env_path("HOME") {
        return absolute(
            cwd,
            if cfg!(target_os = "macos") {
                home.join("Library/Application Support/Caddy")
            } else {
                home.join(".config/caddy")
            },
        );
    }
    cwd.join("caddy")
}
