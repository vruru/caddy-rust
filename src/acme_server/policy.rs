//! ACME's DNS/IP name-policy subset. Denials take precedence; an explicit
//! allow set does not implicitly authorize a different identifier family.
use super::{
    bolt::Budget,
    config::{Policy, Rules},
    records::Identifier,
};
use anyhow::{Result, ensure};
use std::net::IpAddr;
fn has_names(rules: &Rules) -> bool {
    !rules.domains.is_empty() || !rules.ip_ranges.is_empty()
}
fn domain(raw: &str) -> Result<String> {
    let lower = raw.trim().to_lowercase();
    ensure!(
        !lower.is_empty()
            && !lower.starts_with('.')
            && !lower.ends_with('.')
            && !lower.contains(".."),
        "invalid ACME policy DNS constraint"
    );
    let ascii = crate::local_pki::canonical_acme_dns(&lower)?;
    Ok(ascii.strip_prefix('*').unwrap_or(&ascii).to_owned())
}
fn network(raw: &str) -> Result<ipnet::IpNet> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(ipnet::IpNet::from(ip.to_canonical()));
    }
    let net = raw.parse::<ipnet::IpNet>()?;
    if let ipnet::IpNet::V6(net6) = net {
        if let Some(ip) = net6.addr().to_ipv4_mapped() {
            if net6.prefix_len() >= 96 {
                return Ok(ipnet::IpNet::V4(ipnet::Ipv4Net::new(
                    ip,
                    net6.prefix_len() - 96,
                )?));
            }
        }
    }
    Ok(net)
}
pub(super) fn validate(policy: Option<&Policy>) -> Result<()> {
    if let Some(policy) = policy {
        for rules in [policy.allow.as_ref(), policy.deny.as_ref()]
            .into_iter()
            .flatten()
        {
            for constraint in &rules.domains {
                domain(constraint)?;
            }
            for constraint in &rules.ip_ranges {
                network(constraint)?;
            }
        }
    }
    Ok(())
}
fn matches_dns(value: &str, constraint: &str) -> bool {
    if let Some(suffix) = constraint.strip_prefix('.') {
        let Some(prefix) = value.strip_suffix(suffix).and_then(|s| s.strip_suffix('.')) else {
            return false;
        };
        !prefix.is_empty() && !prefix.contains('.')
    } else {
        value.eq_ignore_ascii_case(constraint)
    }
}
pub(super) fn allows(
    policy: Option<&Policy>,
    identifier: &Identifier,
    budget: &mut impl Budget,
) -> Result<bool> {
    let Some(policy) = policy else {
        return Ok(true);
    };
    let allow = policy.allow.as_ref().filter(|r| has_names(r));
    let deny = policy.deny.as_ref().filter(|r| has_names(r));
    if allow.is_none() && deny.is_none() {
        return Ok(true);
    }
    let dns = identifier.kind == "dns";
    let ip = if dns {
        None
    } else {
        Some(identifier.value.parse::<IpAddr>()?.to_canonical())
    };
    budget.charge(identifier.value.len() * 8 + 1024)?;
    let name = if dns {
        // The pinned policy engine requires relative DNS labels, even when
        // new-order syntax accepts an absolute name with its root label.
        if identifier.value.ends_with('.') {
            return Ok(false);
        }
        if identifier.value.starts_with("*.") && !policy.allow_wildcard_names {
            return Ok(false);
        }
        crate::local_pki::canonical_acme_dns(&identifier.value)?
    } else {
        String::new()
    };
    for (rules, excluded) in [(deny, true), (allow, false)] {
        let Some(rules) = rules else { continue };
        let constraints = if dns {
            &rules.domains
        } else {
            &rules.ip_ranges
        };
        let mut matched = false;
        for constraint in constraints {
            budget.work(constraint.len().div_ceil(16).max(1))?;
            budget.charge(constraint.len() * 8 + 1024)?;
            let applies = if dns {
                matches_dns(&name, &domain(constraint)?)
            } else {
                network(constraint)?.contains(&ip.expect("IP identifier"))
            };
            if applies {
                matched = true;
                break;
            }
        }
        if excluded && matched {
            return Ok(false);
        }
        if !excluded && !matched {
            return Ok(false);
        }
    }
    Ok(true)
}
