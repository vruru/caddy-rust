use super::{Engine, Error, Result};
pub(super) use crate::http_runtime::path_glob;
use crate::caddyfile_adapter::pdqsort;
const SUFFIXES: [&str; 13] = [
    "~",
    ".bak",
    ".old",
    ".orig",
    ".dpkg-dist",
    ".dpkg-old",
    ".ucf-dist",
    ".ucf-new",
    ".ucf-old",
    ".rpmnew",
    ".rpmorig",
    ".rpmsave",
    ".in",
];
impl Engine<'_> {
    pub fn lookup(&mut self, name: &[u8]) -> Result<Option<usize>> {
        self.tick((name.len() / 16 + 1) as u64, 0)?;
        let registry = self.registry;
        if let Ok(text) = std::str::from_utf8(name)
            && let Some(&id) = registry
                .db
                .registry_names
                .get(text)
                .or_else(|| registry.db.registry_aliases.get(text))
        {
            return Ok(Some(id));
        }
        let text = super::super::vm::decode_input(name, &mut self.budget)?;
        self.tick(
            text.len() as u64,
            text.len().checked_mul(4).ok_or(Error::TotalLimit)?,
        )?;
        let lower: Vec<i32> = text
            .iter()
            .map(|&ch| {
                registry
                    .db
                    .lower
                    .binary_search_by_key(&ch, |&(key, _)| key)
                    .map_or(ch, |i| registry.db.lower[i].1)
            })
            .collect();
        let lower = self.bytes(&lower)?;
        let lower = std::str::from_utf8(&lower).map_err(|_| "invalid registry lower")?;
        if let Some(&id) = registry
            .db
            .registry_names
            .get(lower)
            .or_else(|| registry.db.registry_aliases.get(lower))
        {
            return Ok(Some(id));
        }
        let name = self.bytes(&text)?;
        let name = std::str::from_utf8(&name).map_err(|_| "invalid registry filename")?;
        let mut ext = Vec::new();
        self.append_bytes(&mut ext, b"filename.")?;
        self.append_bytes(&mut ext, name.as_bytes())?;
        let ext = std::str::from_utf8(&ext).map_err(|_| "invalid extension")?;
        let a = self.filename(ext)?;
        let b = self.filename(name)?;
        Ok(match (a, b) {
            (Some(a), Some(b)) => {
                if self.priority(b) > self.priority(a) {
                    Some(b)
                } else {
                    Some(a)
                }
            }
            (a, b) => a.or(b),
        })
    }
    pub(super) fn priority(&self, id: usize) -> f32 {
        let p = self.registry.db.lexers[id].config.priority;
        if p == 0.0 { 1.0 } else { p }
    }
    fn filename(&mut self, name: &str) -> Result<Option<usize>> {
        let original = name;
        let name = name.trim_end_matches('/');
        let name = if name.is_empty() {
            if original.is_empty() { "." } else { "/" }
        } else {
            name.rsplit('/').next().ok_or("filename")?
        };
        let registry = self.registry;
        for alias in [false, true] {
            let mut candidates = Vec::new();
            for &id in &registry.db.registry_order {
                let patterns = if alias {
                    &registry.globs[id].1
                } else {
                    &registry.globs[id].0
                };
                for pattern in patterns {
                    self.tick(1 + (name.len() / 16) as u64, 0)?;
                    let mut matched = pattern.is_match(name);
                    if !matched {
                        for suffix in &SUFFIXES {
                            self.tick(1, 0)?;
                            if let Some(stem) = name.strip_suffix(suffix)
                                && pattern.is_match(stem)
                            {
                                matched = true;
                                break;
                            }
                        }
                    }
                    if matched {
                        self.tick(1, std::mem::size_of::<usize>())?;
                        candidates
                            .try_reserve_exact(1)
                            .map_err(|_| Error::TotalLimit)?;
                        candidates.push(id);
                    }
                }
            }
            self.tick(
                (candidates.len().saturating_mul(
                    candidates
                        .len()
                        .checked_ilog2()
                        .unwrap_or(0)
                        .saturating_add(1) as usize,
                )) as u64,
                0,
            )?;
            pdqsort::sort_by(&mut candidates, |a, b| {
                self.priority(*a) > self.priority(*b)
            });
            if let Some(id) = candidates.first() {
                return Ok(Some(*id));
            }
        }
        Ok(None)
    }
}
