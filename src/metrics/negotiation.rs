#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Format {
    Text,
    OpenMetrics,
    OpenMetricsOld,
    ProtoDelimited,
    ProtoText,
    ProtoCompact,
}
impl Format {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            Self::OpenMetricsOld => {
                "application/openmetrics-text; version=0.0.1; charset=utf-8; escaping=underscores"
            }
            Self::OpenMetrics => {
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=underscores"
            }
            Self::ProtoDelimited => {
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited; escaping=underscores"
            }
            Self::ProtoText => {
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=text; escaping=underscores"
            }
            Self::ProtoCompact => {
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=underscores"
            }
        }
    }
}
fn quality(s: &str) -> Option<u16> {
    let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
    if !matches!(whole, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let mut result = whole.parse::<u16>().ok()? * 1000;
    let mut place = 100;
    for b in fraction.bytes() {
        result += (b - b'0') as u16 * place;
        place /= 10;
    }
    (result <= 1000).then_some(result)
}
fn part(s: &str) -> Option<(&str, u16)> {
    let mut parts = s.split(';');
    let token = parts.next()?.trim();
    let mut q = 1000;
    for p in parts {
        let (name, value) = p.trim().split_once('=')?;
        if name.trim().eq_ignore_ascii_case("q") {
            q = quality(value.trim())?;
        }
    }
    Some((token, q))
}
fn parameter<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    s.split(';').skip(1).find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then_some(v.trim().trim_matches('"'))
    })
}
pub(super) fn choose(accept: &str, openmetrics: bool) -> Format {
    if accept.len() > 16384 {
        return Format::Text;
    }
    let mut exact = [None::<(u16, usize)>; 6];
    let mut wildcard = None;
    for (index, range) in accept.split(',').enumerate() {
        let Some((name, q)) = part(range) else {
            continue;
        };
        let v = parameter(range, "version");
        let format = if name.eq_ignore_ascii_case("text/plain") && v.is_none_or(|v| v == "0.0.4") {
            Some(0)
        } else if name.eq_ignore_ascii_case("application/openmetrics-text")
            && openmetrics
            && v.is_none_or(|v| matches!(v, "0.0.1" | "1.0.0"))
        {
            Some(if v == Some("0.0.1") { 5 } else { 1 })
        } else if name.eq_ignore_ascii_case("application/vnd.google.protobuf")
            && parameter(range, "proto") == Some("io.prometheus.client.MetricFamily")
        {
            match parameter(range, "encoding") {
                Some("delimited") => Some(2),
                Some("text") => Some(3),
                Some("compact-text") => Some(4),
                _ => None,
            }
        } else {
            None
        };
        if let Some(f) = format {
            if exact[f].is_none_or(|(old, _)| q > old) {
                exact[f] = Some((q, index));
            }
        } else if matches!(name, "*/*" | "text/*") && wildcard.is_none_or(|(old, _)| q > old) {
            wildcard = Some((q, index));
        }
    }
    if exact[0].is_none() {
        exact[0] = wildcard;
    }
    let mut best = None::<(u16, usize, usize)>;
    for (format, entry) in exact.into_iter().enumerate() {
        if let Some((q, index)) = entry
            && q > 0
            && best.is_none_or(|(old, order, _)| q > old || q == old && index < order)
        {
            best = Some((q, index, format));
        }
    }
    match best.map(|(_, _, f)| f) {
        Some(1) => Format::OpenMetrics,
        Some(2) => Format::ProtoDelimited,
        Some(3) => Format::ProtoText,
        Some(4) => Format::ProtoCompact,
        Some(5) => Format::OpenMetricsOld,
        _ => Format::Text,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Compression {
    Identity,
    Gzip,
    Zstd,
}
pub(super) fn compression(header: &str) -> Compression {
    if header.len() > 16384 {
        return Compression::Identity;
    }
    let mut values = [None::<u16>; 4];
    for range in header.split(',') {
        let Some((name, q)) = part(range) else {
            continue;
        };
        let index = if name.eq_ignore_ascii_case("gzip") {
            0
        } else if name.eq_ignore_ascii_case("zstd") {
            1
        } else if name.eq_ignore_ascii_case("identity") {
            2
        } else if name == "*" {
            3
        } else {
            continue;
        };
        values[index] = Some(values[index].unwrap_or(0).max(q));
    }
    let gzip = values[0].or(values[3]).unwrap_or(0);
    let zstd = values[1].or(values[3]).unwrap_or(0);
    let identity = values[2].unwrap_or(0);
    if identity > gzip.max(zstd) {
        Compression::Identity
    } else if gzip > 0 && gzip >= zstd {
        Compression::Gzip
    } else if zstd > 0 {
        Compression::Zstd
    } else {
        Compression::Identity
    }
}
