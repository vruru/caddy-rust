//! URLPattern request matching with bounded compiled expressions and inputs.
use super::request::{Context, clean_path, decoded_path, failure};
use anyhow::{Result, ensure};
use http::StatusCode;
use std::sync::Arc;
use url::Url;
use urlpattern::regexp::RegExp;
use urlpattern::{
    RegexSyntax, UrlPattern, UrlPatternInit, UrlPatternMatchInput, UrlPatternOptions,
};

const COMPONENT_REGEX_BYTES: usize = 256 << 10;
// Each of eight components may retain a full expression and a matcher
// expression. This allowance bounds compiled programs; the separate per-regex
// DFA cache limit and bounded execution pool are not a total RSS guarantee.
const PROGRAM_ALLOWANCE: usize = 8 * 2 * COMPONENT_REGEX_BYTES;
// Match net/url.URL.EscapedPath before URLPattern's WHATWG input parsing.
// set_path alone uses a less restrictive encoding set for punctuation.
const GO_PATH_ENCODING: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b'/')
    .remove(b':')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');

#[derive(Debug)]
struct BoundedRegex {
    regex: regex::Regex,
    declared_captures: usize,
    pattern: Box<str>,
}
impl RegExp for BoundedRegex {
    fn syntax() -> RegexSyntax {
        RegexSyntax::Rust
    }
    fn parse(pattern: &str, flags: &str, _: bool) -> Result<Self, ()> {
        if flags.chars().any(|flag| !matches!(flag, 'u' | 'i')) {
            return Err(());
        }
        let scoped = if flags.contains('i') {
            format!("(?i){pattern}")
        } else {
            pattern.to_owned()
        };
        let (translated, declared_captures) =
            crate::go_regexp::translate_native_pattern(&scoped, COMPONENT_REGEX_BYTES)
                .map_err(|_| ())?;
        let regex = regex::RegexBuilder::new(&translated)
            .size_limit(COMPONENT_REGEX_BYTES)
            .dfa_size_limit(COMPONENT_REGEX_BYTES)
            .nest_limit(3_100)
            .build()
            .map_err(|_| ())?;
        // As in GoRegexp, native HIR simplification may remove trailing
        // unmatched captures; keep the declared slots and publish them empty.
        if regex.captures_len() > declared_captures {
            return Err(());
        }
        Ok(Self {
            regex,
            declared_captures,
            pattern: pattern.into(),
        })
    }
    fn matches<'a>(&self, text: &'a str) -> Option<Vec<Option<&'a str>>> {
        let captures = self.regex.captures(text)?;
        Some(
            (1..self.declared_captures)
                .map(|index| captures.get(index).map(|value| value.as_str()))
                .collect(),
        )
    }
    fn pattern_string(&self) -> &str {
        &self.pattern
    }
}

#[derive(Clone)]
pub(crate) struct Plan {
    compiled: Arc<UrlPattern<BoundedRegex>>,
    merge_slashes: bool,
}

impl Plan {
    pub(crate) fn prepare(
        pattern: &str,
        base: &str,
        ignore_case: bool,
        remaining: &mut usize,
    ) -> Result<Self> {
        ensure!(
            pattern.len() <= 4096 && base.len() <= 4096,
            "URLPattern configuration length limit exceeded"
        );
        ensure!(
            *remaining >= PROGRAM_ALLOWANCE,
            "HTTP pattern configuration memory limit exceeded"
        );
        let pattern_path = pattern.split_once("://").map_or(pattern, |(_, suffix)| {
            suffix
                .find('/')
                .map(|index| &suffix[index..])
                .unwrap_or_default()
        });
        let merge_slashes = !pattern_path.contains("//");
        let input = if base.is_empty() && !pattern.contains("://") {
            format!("*://*:*{pattern}")
        } else {
            pattern.to_owned()
        };
        let base = (!base.is_empty())
            .then(|| Url::parse(base))
            .transpose()
            .map_err(|_| anyhow::anyhow!("invalid URLPattern base URL"))?;
        let init = UrlPatternInit::parse_constructor_string::<BoundedRegex>(&input, base)
            .map_err(|_| anyhow::anyhow!("invalid URLPattern constructor"))?;
        let compiled = UrlPattern::parse(
            init,
            UrlPatternOptions {
                ignore_case,
                ..Default::default()
            },
        )
        .map_err(|_| anyhow::anyhow!("URLPattern could not be compiled"))?;
        *remaining -= PROGRAM_ALLOWANCE;
        Ok(Self {
            compiled: Arc::new(compiled),
            merge_slashes,
        })
    }

    pub(super) async fn matches(&self, ctx: &mut Context) -> Result<bool> {
        let scheme = if ctx.tls { "https" } else { "http" };
        let path = decoded_path(ctx.req().uri().path())?;
        #[cfg(windows)]
        let path = path
            .replace('\\', "/")
            .split('/')
            .map(|segment| {
                if matches!(segment, "." | "..") {
                    segment
                } else {
                    segment.trim_end_matches(['.', ' '])
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        let path = clean_path(&path, self.merge_slashes);
        let raw_query = ctx.req().uri().query();
        ensure!(
            path.len() + raw_query.map_or(0, str::len) <= 64 << 10,
            "URLPattern request exceeds its byte limit"
        );
        let Ok(mut url) = Url::parse(&format!("{scheme}://{}", ctx.authority)) else {
            return Ok(false);
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Ok(false);
        }
        // Caddy constructs a Go URL from the decoded path, then passes its
        // canonical escaped path to URLPattern. Preserve that exact model.
        url.set_path(&percent_encoding::utf8_percent_encode(&path, GO_PATH_ENCODING).to_string());
        url.set_query(raw_query);
        let compiled = self.compiled.clone();
        let result = ctx
            .resources
            .request_regexp
            .run(move || compiled.exec(UrlPatternMatchInput::Url(url)))
            .await
            .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))?
            .map_err(|_| failure(StatusCode::BAD_REQUEST))?;
        let Some(result) = result else {
            return Ok(false);
        };
        for (name, component) in [
            ("protocol", result.protocol),
            ("username", result.username),
            ("password", result.password),
            ("hostname", result.hostname),
            ("port", result.port),
            ("pathname", result.pathname),
            ("search", result.search),
            ("hash", result.hash),
        ] {
            // Go URLPattern omits a sole empty capture when the component
            // itself is empty; it still publishes empty optional captures in
            // a nonempty component such as /optional/:id?.
            if component.input.is_empty()
                && component.groups.len() == 1
                && component
                    .groups
                    .values()
                    .next()
                    .is_some_and(|value| value.as_deref().is_none_or(str::is_empty))
            {
                continue;
            }
            for (group, value) in component.groups {
                let value = value.unwrap_or_default();
                let key = format!("http.url_pattern.{name}.{group}");
                ctx.regex_capture_budget = ctx
                    .regex_capture_budget
                    .checked_sub(key.len() + value.len())
                    .ok_or_else(|| failure(StatusCode::SERVICE_UNAVAILABLE))?;
                ctx.values.insert(key, value);
            }
        }
        Ok(true)
    }
}
