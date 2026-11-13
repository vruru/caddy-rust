//! One pass over the query, retaining only expanded configuration keys.
use anyhow::Result;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

fn decoded(raw: &[u8]) -> Option<Cow<'_, [u8]>> {
    if !raw.iter().any(|b| matches!(*b, b'+' | b'%')) {
        return Some(Cow::Borrowed(raw));
    }
    let mut output = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        match byte {
            b'+' => output.push(b' '),
            b'%' => {
                let high = char::from(*rest.first()?).to_digit(16)?;
                let low = char::from(*rest.get(1)?).to_digit(16)?;
                output.push(((high << 4) | low) as u8);
                rest = &rest[2..];
            }
            byte => output.push(byte),
        }
    }
    Some(Cow::Owned(output))
}

type QueryPair<'a> = (Cow<'a, [u8]>, Cow<'a, [u8]>);

pub(super) fn query_pair(segment: &[u8]) -> Option<QueryPair<'_>> {
    if segment.contains(&b';') {
        return None;
    }
    let (key, value) = segment
        .iter()
        .position(|&byte| byte == b'=')
        .map_or((segment, &[][..]), |i| (&segment[..i], &segment[i + 1..]));
    Some((decoded(key)?, decoded(value)?))
}

struct Rule {
    index: usize,
    any: bool,
    values: HashSet<String>,
}

pub(super) async fn matches(
    raw: &str,
    rules: &[(String, Vec<String>)],
    view:super::request::ReplacerView<'_>,
) -> Result<bool> {
    let segments = raw
        .as_bytes()
        .split(|&byte| byte == b'&')
        .filter(|s| !s.is_empty());
    if rules.is_empty() {
        // URL.Query retains valid pairs even when other pairs are invalid.
        return Ok(!segments.into_iter().any(|s| query_pair(s).is_some()));
    }
    let mut candidates: HashMap<Vec<u8>, Vec<Rule>> = HashMap::with_capacity(rules.len());
    let mut expanded_bytes = 0usize;
    for (index, (key, values)) in rules.iter().enumerate() {
        if values.is_empty() {
            return Ok(false);
        }
        let key = view.expand_text_resolved(key,true).await?.into_bytes();
        expanded_bytes = expanded_bytes.saturating_add(key.len());
        let mut accepted = HashSet::new();
        let mut any = false;
        for value in values {
            let value = view.expand_text_resolved(value,true).await?;
            expanded_bytes = expanded_bytes.saturating_add(value.len());
            anyhow::ensure!(
                expanded_bytes <= 1 << 20,
                "expanded query rules exceed byte limit"
            );
            any |= value == "*";
            accepted.insert(value);
        }
        candidates.entry(key).or_default().push(Rule {
            index,
            any,
            values: accepted,
        });
    }
    let mut matches = vec![false; rules.len()];
    for segment in segments {
        let Some((key, value)) = query_pair(segment) else {
            // Even after all requested keys match, Caddy rejects malformed
            // unrelated query parameters in a nonempty matcher.
            return Ok(false);
        };
        if let Some(rules) = candidates.get(key.as_ref()) {
            let value = std::str::from_utf8(value.as_ref()).ok();
            for rule in rules {
                if !matches[rule.index] {
                    matches[rule.index] =
                        rule.any || value.is_some_and(|v| rule.values.contains(v));
                }
            }
        }
    }
    Ok(matches.into_iter().all(|found| found))
}
