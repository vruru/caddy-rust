use super::{CandidateResolver, CertificateOrigin};
use crate::{
    challenge::ACME_ALPN,
    tls_policy::ConnectionPolicy,
    tls_resolver::{CertificateSelection, PolicyInventory, PolicyMatch, PolicyQuery},
};
use rustls::{ProtocolVersion, SignatureScheme};
use std::net::IpAddr;

pub(super) enum Choice {
    Missing,
    Unusable { managed: bool, global: bool },
    // The last field marks a whole-inventory lookup rather than this SNI's
    // named lookup. Generic ensure(SNI) cannot maintain an unrelated alias.
    Selected(CertificateSelection, CertificateOrigin, bool),
}

impl Choice {
    pub(super) fn selected(self) -> Option<(CertificateSelection, CertificateOrigin)> {
        match self {
            Self::Selected(cert, origin, _) => Some((cert, origin)),
            Self::Missing | Self::Unusable { .. } => None,
        }
    }
}

pub(super) fn eligible_names<'a>(
    policy: &'a ConnectionPolicy,
    sni: &'a str,
    local_ip: &'a str,
    primary_only: bool,
) -> [Option<&'a str>; 3] {
    let mut names = policy.certificate_names(sni, local_ip);
    for name in &mut names {
        if name.is_some_and(str::is_empty) {
            *name = None;
        }
    }
    if primary_only {
        names[1..].fill(None);
    }
    names
}

fn combine(manual: PolicyMatch, managed: impl FnOnce() -> PolicyMatch) -> Choice {
    let (manual, manual_unusable) = match manual {
        PolicyMatch::Selected(cert, true) => {
            return Choice::Selected(cert, CertificateOrigin::Manual, false);
        }
        PolicyMatch::Selected(cert, false) => (Some(cert), false),
        PolicyMatch::Unusable => (None, true),
        PolicyMatch::NoViable => (None, false),
    };
    match managed() {
        PolicyMatch::Selected(cert, true) => {
            Choice::Selected(cert, CertificateOrigin::Managed, false)
        }
        PolicyMatch::Selected(cert, false) => manual.map_or(
            Choice::Selected(cert, CertificateOrigin::Managed, false),
            |cert| Choice::Selected(cert, CertificateOrigin::Manual, false),
        ),
        other => {
            if let Some(cert) = manual {
                return Choice::Selected(cert, CertificateOrigin::Manual, false);
            }
            if manual_unusable || matches!(other, PolicyMatch::Unusable) {
                Choice::Unusable {
                    managed: matches!(other, PolicyMatch::Unusable),
                    global: false,
                }
            } else {
                Choice::Missing
            }
        }
    }
}

impl CandidateResolver {
    pub(super) fn choose_pinned(
        &self,
        instance: crate::tls_resolver::CertificateInstance,
        origin: CertificateOrigin,
        offered_name: Option<&str>,
        schemes: &[SignatureScheme],
        version: ProtocolVersion,
    ) -> Choice {
        let Some(query) = PolicyQuery::new(self.certificate_selection.as_deref(),
            offered_name, schemes, Some(version)) else {
            return Choice::Unusable { managed: false, global: false };
        };
        let resolver = match origin {
            CertificateOrigin::Manual => &self.static_certificates,
            CertificateOrigin::Managed => &self.managed,
            CertificateOrigin::Proof => return Choice::Missing,
        };
        let Some(inventory) = resolver.policy_inventory() else { return Choice::Missing; };
        match inventory.select_pinned(instance, origin == CertificateOrigin::Manual, &query, |identity, names| match origin {
            CertificateOrigin::Manual => self.allowed_static.contains(identity),
            CertificateOrigin::Managed => names.iter().any(|name| self.managed_name_allowed(name)),
            CertificateOrigin::Proof => false,
        }) {
            PolicyMatch::Selected(certificate, _) => Choice::Selected(certificate, origin, false),
            PolicyMatch::Unusable => Choice::Unusable { managed: origin == CertificateOrigin::Managed, global: false },
            PolicyMatch::NoViable => Choice::Missing,
        }
    }

    pub(super) fn select_for_version(
        &self,
        sni: Option<&str>,
        alpn: &[&[u8]],
        schemes: &[SignatureScheme],
        version: ProtocolVersion,
    ) -> Option<CertificateSelection> {
        self.select_for_version_with_origin(sni, alpn, schemes, version)
            .map(|(cert, _)| cert)
    }

    pub(super) fn select_for_version_with_origin(
        &self,
        sni: Option<&str>,
        alpn: &[&[u8]],
        schemes: &[SignatureScheme],
        version: ProtocolVersion,
    ) -> Option<(CertificateSelection, CertificateOrigin)> {
        self.choose([sni, None, None], sni, alpn, schemes, Some(version))
            .selected()
    }

    pub(super) fn choose(
        &self,
        names: [Option<&str>; 3],
        offered_name: Option<&str>,
        alpn: &[&[u8]],
        schemes: &[SignatureScheme],
        version: Option<ProtocolVersion>,
    ) -> Choice {
        if alpn.contains(&ACME_ALPN) {
            let selection = if let Some(version) = version {
                self.challenges
                    .select_for_version(names[0], alpn, schemes, version)
            } else {
                self.challenges.select_candidate(names[0], alpn, schemes)
            };
            return selection.map_or(Choice::Missing, |cert| {
                Choice::Selected(cert, CertificateOrigin::Proof, false)
            });
        }
        if self.certificate_selection.is_some() {
            return self.choose_explicit(names, offered_name, schemes, version);
        }
        for (index, name) in names.into_iter().enumerate() {
            let Some(name) = name else { continue };
            if index > 0 {
                let (Some(query), Some(manual), Some(managed)) = (
                    PolicyQuery::new(None, offered_name, schemes, version),
                    self.static_certificates.policy_inventory(),
                    self.managed.policy_inventory(),
                ) else {
                    return Choice::Unusable {
                        managed: false,
                        global: false,
                    };
                };
                let result = self.select_exact(
                    name,
                    &query,
                    &manual,
                    &managed,
                    self.managed_name_allowed(name),
                );
                if !matches!(result, Choice::Missing) {
                    return result;
                }
                continue;
            }
            let manual = match version {
                Some(version) => self.static_certificates.select_for_version_filtered(
                    Some(name),
                    alpn,
                    schemes,
                    version,
                    &self.allowed_static,
                ),
                None => self.static_certificates.select_candidate_filtered(
                    Some(name),
                    alpn,
                    schemes,
                    &self.allowed_static,
                ),
            };
            if let Some(cert) = manual {
                return Choice::Selected(cert, CertificateOrigin::Manual, false);
            }
            if !self.managed_name_allowed(name) {
                continue;
            }
            let managed = match version {
                Some(version) => {
                    self.managed
                        .select_for_version(Some(name), alpn, schemes, version)
                }
                None => self.managed.select_candidate(Some(name), alpn, schemes),
            };
            if let Some(cert) = managed {
                return Choice::Selected(cert, CertificateOrigin::Managed, false);
            }
        }
        Choice::Missing
    }

    pub(super) fn managed_name_allowed(&self, name: &str) -> bool {
        if self.certificate_selection.as_ref().is_some_and(|filter| filter.requires_tags()) {
            return false;
        }
        self.allowed_managed.contains(name)
            || (name.parse::<IpAddr>().is_err()
                && name.split_once('.').is_some_and(|(_, suffix)| {
                    self.allowed_managed.contains(&format!("*.{suffix}"))
                }))
            || self
                .provider
                .as_ref()
                .is_some_and(|provider| provider.cached_name(name))
    }

    fn choose_explicit(
        &self,
        names: [Option<&str>; 3],
        offered_name: Option<&str>,
        schemes: &[SignatureScheme],
        version: Option<ProtocolVersion>,
    ) -> Choice {
        let Some(query) = PolicyQuery::new(
            self.certificate_selection.as_deref(),
            offered_name,
            schemes,
            version,
        ) else {
            return Choice::Unusable {
                managed: false,
                global: false,
            };
        };
        let (Some(manual), Some(managed)) = (
            self.static_certificates.policy_inventory(),
            self.managed.policy_inventory(),
        ) else {
            return Choice::Unusable {
                managed: false,
                global: false,
            };
        };
        let mut searched_global = false;
        for (index, name) in names.into_iter().enumerate() {
            let Some(name) = name else { continue };
            let managed_allowed = self.managed_name_allowed(name);
            let mut choose = |name: &str| {
                if manual.has_name(name) || managed.has_name(name) {
                    return self.select_exact(name, &query, &manual, &managed, managed_allowed);
                }
                if searched_global {
                    return Choice::Missing;
                }
                searched_global = true;
                self.select_global(&query, &manual, &managed)
            };
            let first = choose(name);
            if !matches!(first, Choice::Missing) {
                return first;
            }
            // Only the original offered DNS name has cumulative wildcard
            // lookups. Explicit default/fallback names are exact cache keys.
            if index == 0 && name.parse::<IpAddr>().is_err() && !name.starts_with("*.") {
                let mut labels = name.split('.').collect::<Vec<_>>();
                for index in 0..labels.len() {
                    labels[index] = "*";
                    let wildcard = labels.join(".");
                    let result = choose(&wildcard);
                    if !matches!(result, Choice::Missing) {
                        return result;
                    }
                }
            }
        }
        Choice::Missing
    }

    fn select_exact(
        &self,
        name: &str,
        query: &PolicyQuery<'_>,
        manual: &PolicyInventory,
        managed: &PolicyInventory,
        managed_allowed: bool,
    ) -> Choice {
        combine(
            manual.select_named(name, query, |identity, _| {
                self.allowed_static.contains(identity)
            }),
            || {
                if managed_allowed {
                    managed.select_named(name, query, |_, _| true)
                } else {
                    PolicyMatch::NoViable
                }
            },
        )
    }

    fn select_global(
        &self,
        query: &PolicyQuery<'_>,
        manual: &PolicyInventory,
        managed: &PolicyInventory,
    ) -> Choice {
        let choice = combine(
            manual.select_global(query, |identity, _| self.allowed_static.contains(identity)),
            || {
                if self.allowed_managed.is_empty() && self.provider.is_none() {
                    return PolicyMatch::NoViable;
                }
                managed.select_global(query, |_, aliases| {
                    aliases.iter().any(|alias| self.managed_name_allowed(alias))
                })
            },
        );
        match choice {
            Choice::Selected(cert, origin, _) => Choice::Selected(cert, origin, true),
            Choice::Unusable { managed, .. } => Choice::Unusable {
                managed,
                global: true,
            },
            Choice::Missing => Choice::Missing,
        }
    }
}
