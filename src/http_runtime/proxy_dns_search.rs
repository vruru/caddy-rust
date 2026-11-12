// Copyright 2015 The Go Authors. All rights reserved.
// Behavior port of net/dnsclient_unix.go nameList; BSD-3-Clause (see notices).
//! Sequential bounded DNS candidates. Each yielded name owns at most 254 bytes;
//! the configured search list remains shared instead of expanding per request.
pub(super) struct Names<'a> {
    base: String,
    search: &'a [String],
    cursor: usize,
    stage: u8,
    rooted: bool,
    first: bool,
}
fn avoid(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    name.as_bytes()
        .get(name.len().saturating_sub(6)..)
        .is_some_and(|s| s.eq_ignore_ascii_case(b".onion"))
}
impl<'a> Names<'a> {
    pub(super) fn new(name: &str, search: &'a [String], ndots: usize) -> Self {
        let rooted = name.ends_with('.');
        let invalid = name.is_empty() || name.len() > 254 || (name.len() == 254 && !rooted);
        let mut base = if invalid {
            String::new()
        } else {
            name.to_owned()
        };
        if !invalid && !rooted {
            base.push('.');
        }
        Self {
            base,
            search,
            cursor: 0,
            stage: if invalid { 3 } else { 0 },
            rooted,
            first: name.bytes().filter(|b| *b == b'.').count() >= ndots,
        }
    }
}
impl Iterator for Names<'_> {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        loop {
            match self.stage {
                0 => {
                    self.stage = if self.rooted { 3 } else { 1 };
                    if (self.rooted || self.first) && !avoid(&self.base) {
                        return Some(self.base.clone());
                    }
                }
                1 => {
                    if self.cursor == self.search.len() {
                        self.stage = 2;
                        continue;
                    }
                    let suffix = &self.search[self.cursor];
                    self.cursor += 1;
                    if self.base.len().saturating_add(suffix.len()) > 254 {
                        continue;
                    }
                    let mut out = String::with_capacity(self.base.len() + suffix.len());
                    out.push_str(&self.base);
                    out.push_str(suffix);
                    if !avoid(&out) {
                        return Some(out);
                    }
                }
                2 => {
                    self.stage = 3;
                    if !self.first && !avoid(&self.base) {
                        return Some(self.base.clone());
                    }
                }
                _ => return None,
            }
        }
    }
}
pub(super) fn rooted(name: &str) -> String {
    if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}
/// Search/domain are interpreted separately; malformed/overlong suffixes must
/// not prevent reading unrelated resolver options or valid absolute candidates.
pub(super) fn without_search(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for line in data.split_inclusive(|b| *b == b'\n') {
        let first = line
            .split(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .find(|f| !f.is_empty());
        if !matches!(first, Some(b"search" | b"domain")) {
            out.extend_from_slice(line);
        }
    }
    out
}
