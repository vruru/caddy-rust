// Behavioral reference: Caddy v2.11.7 modules/caddyhttp/responsematchers.go
// and matchers.go::matchHeaders (Apache-2.0).
use super::request::header_value_bytes_pattern;
use crate::http_config::types::ResponseMatcher;
use http::HeaderMap;

impl ResponseMatcher {
    pub(crate) fn matches(&self, status: u16, headers: &HeaderMap) -> bool {
        // Status check
        if let Some(codes) = &self.status_codes
            && !codes.iter().any(|code| {
                let s = i64::from(status);
                // Go's configured int arithmetic wraps at machine width;
                // retain that behavior even for unusual negative JSON codes.
                *code == s
                    || *code < 100
                        && s >= code.wrapping_mul(100)
                        && s < code.wrapping_add(1).wrapping_mul(100)
            })
        {
            return false;
        }

        // Headers check
        for (name, pattern) in &self.headers {
            // Go supplies a non-nil empty TransferEncoding slice for response
            // matchers, even when the wire header is absent.
            let present = headers.contains_key(name.as_str())
                || name.eq_ignore_ascii_case("Transfer-Encoding");
            let matches = match pattern {
                None => !present,
                Some(vec) => {
                    if vec.is_empty() {
                        present
                    } else {
                        headers.get_all(name.as_str()).iter().any(|value| {
                            vec.iter()
                                .any(|p| header_value_bytes_pattern(p.as_bytes(), value.as_bytes()))
                        })
                    }
                }
            };

            if !matches {
                return false;
            }
        }

        true
    }
}
