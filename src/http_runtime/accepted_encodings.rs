//! Shared Accept-Encoding negotiation for dynamic and precompressed responses.
//! Behavior follows Caddy v2.11.7 modules/caddyhttp/encode/encode.go.
use crate::caddyfile_adapter::stable_sort::stable_sort;
use crate::caddyfile_parser::scalar::parse_float32;
use http::{HeaderMap, header};

const QUALITY_EPSILON: f64 = 0.00001;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Coding {
    Gzip,
    Zstd,
    Brotli,
}

impl Coding {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "gzip" => Some(Self::Gzip),
            "zstd" => Some(Self::Zstd),
            "br" => Some(Self::Brotli),
            _ => None,
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
            Self::Brotli => "br",
        }
    }
}

struct Preference {
    coding: Option<Coding>,
    quality: f64,
    rank: usize,
}

fn parse_preference(accepted: &str, preferred: &[Coding]) -> Option<Preference> {
    let (name, parameters) = accepted.split_once(';').unwrap_or((accepted, ""));
    let name = name.trim();
    let q = parameters.split(';').next().unwrap_or_default().trim();
    let quality = if matches!(q.as_bytes(), [b'q' | b'Q', b'=', ..]) {
        parse_float32(&q[2..])
            .filter(|n| (0.0..=1.0).contains(n))
            .map(f64::from)
            .unwrap_or(1.0)
    } else {
        1.0
    };
    if quality < QUALITY_EPSILON {
        return None;
    }
    let coding = [Coding::Gzip, Coding::Zstd, Coding::Brotli]
        .into_iter()
        .find(|coding| name.eq_ignore_ascii_case(coding.as_str()));
    let rank = coding
        .and_then(|coding| preferred.iter().position(|preferred| *preferred == coding))
        .map_or(0, |at| preferred.len() - at);
    Some(Preference {
        coding,
        quality,
        rank,
    })
}

fn header_text(headers: &HeaderMap) -> Option<std::borrow::Cow<'_, str>> {
    if headers
        .get("sec-websocket-key")
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }
    let value = headers.get(header::ACCEPT_ENCODING)?;
    (!value.is_empty()).then(|| String::from_utf8_lossy(value.as_bytes()))
}

fn ranked(text: &str, preferred: &[Coding]) -> Vec<Preference> {
    // Keep unknown encodings in the sort: the epsilon comparator is not
    // transitive, so even a skipped token can affect the stable ordering.
    let mut choices: Vec<_> = text
        .split(',')
        .filter_map(|accepted| parse_preference(accepted, preferred))
        .collect();
    stable_sort(&mut choices, |a, b| {
        if (a.quality - b.quality).abs() < QUALITY_EPSILON {
            a.rank > b.rank
        } else {
            a.quality > b.quality
        }
    });
    choices
}

pub(super) fn choose(
    headers: &HeaderMap,
    preferred: &[Coding],
    enabled: impl Fn(Coding) -> bool,
) -> Option<Coding> {
    let text = header_text(headers)?;
    if !text.contains(',') {
        return parse_preference(&text, preferred)?.coding.filter(|c| enabled(*c));
    }
    ranked(&text, preferred)
        .into_iter()
        .filter_map(|value| value.coding)
        .find(|coding| enabled(*coding))
}
