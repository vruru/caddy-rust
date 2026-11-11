// Copyright 2015 Matthew Holt and The Caddy Authors.
// SPDX-License-Identifier: Apache-2.0
//! Refuse ambiguous external header spellings before running business handlers.
use anyhow::{Result, ensure};
use http::{HeaderMap, HeaderName};
use std::collections::HashSet;

const MAX_EXPECTED_NAMES: usize = 1024;

#[derive(Clone, Default)]
struct Aliases {
    exact_allow: HashSet<HeaderName>,
    exact_drop: HashSet<HeaderName>,
    prefix: Vec<(String, String)>,
}
impl Aliases {
    fn provision(entries: Vec<String>, separator: char) -> Result<Self> {
        ensure!(
            entries.len() <= MAX_EXPECTED_NAMES,
            "too many expected header spellings"
        );
        let mut out = Self::default();
        for entry in entries {
            let prefix = entry.strip_suffix('*');
            let name = prefix.unwrap_or(&entry);
            ensure!(
                name.is_ascii() && name.contains(separator) && !name.contains('*'),
                "invalid expected header spelling"
            );
            // A configured literal/prefix must be a possible header token.
            let allowed = HeaderName::from_bytes(name.as_bytes())?;
            let drop = HeaderName::from_bytes(name.replace(separator, "-").as_bytes())?;
            if prefix.is_some() {
                out.prefix
                    .push((allowed.as_str().into(), drop.as_str().into()));
            } else {
                out.exact_allow.insert(allowed);
                out.exact_drop.insert(drop);
            }
        }
        Ok(out)
    }
    fn allowed(&self, name: &HeaderName) -> bool {
        self.exact_allow.contains(name)
            || self
                .prefix
                .iter()
                .any(|(allow, _)| name.as_str().starts_with(allow))
    }
    fn conflicts(&self, name: &HeaderName) -> bool {
        self.exact_drop.contains(name)
            || self
                .prefix
                .iter()
                .any(|(_, drop)| name.as_str().starts_with(drop))
    }
}

#[derive(Clone, Default)]
pub(crate) struct HeaderAliases {
    underscore: Aliases,
    dot: Aliases,
    configured: bool,
}
impl HeaderAliases {
    pub(super) fn provision(underscore: Vec<String>, dot: Vec<String>) -> Result<Self> {
        let configured = !underscore.is_empty() || !dot.is_empty();
        Ok(Self {
            underscore: Aliases::provision(underscore, '_')?,
            dot: Aliases::provision(dot, '.')?,
            configured,
        })
    }
    pub(crate) fn sanitize(&self, headers: &mut HeaderMap) {
        let mut remove = Vec::new();
        for name in headers.keys() {
            let raw = name.as_str().as_bytes();
            let underscore = raw.contains(&b'_');
            let dot = raw.contains(&b'.');
            let drop = match (underscore, dot) {
                (false, false) => {
                    self.configured && (self.underscore.conflicts(name) || self.dot.conflicts(name))
                }
                _ => {
                    let allowed = match (underscore, dot) {
                        // Prefixes cannot allow a mixed-form suffix.
                        (true, true) => {
                            self.underscore.exact_allow.contains(name)
                                || self.dot.exact_allow.contains(name)
                        }
                        (true, false) => self.underscore.allowed(name),
                        (false, true) => self.dot.allowed(name),
                        (false, false) => unreachable!(),
                    };
                    !allowed || headers.get_all(name).iter().nth(1).is_some()
                }
            };
            if drop {
                remove.push(name.clone());
            }
        }
        for name in remove {
            headers.remove(name);
        }
    }
}
