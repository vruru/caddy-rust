#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Link {
    pub target: String,
    pub up: bool,
    pub alternate: bool,
}

/// Parse RFC 8288 Link header values.
///
/// - Only accepts `<target>` format for the URI.
/// - Parameters are separated by `;`.
/// - `rel` parameter value can be a token or a quoted-string.
/// - Multiple rel values are separated by whitespace.
/// - Registered rel values `up` and `alternate` are case-insensitive.
/// - Duplicate rel values: only the first occurrence is considered.
/// - Items without `up` or `alternate` rel are ignored.
/// - If raw length > 16384 bytes, returns empty Vec.
/// - Maximum 64 link-values processed.
/// - Target length <= 8192 bytes and no ASCII control characters.
/// - Single malformed item is skipped, no panic, no index out-of-bounds, no infinite loop.
/// - Quoted string in title (and other parameters) handles commas/semicolons correctly.
pub(super) fn parse(raw: &str) -> Vec<Link> {
    if raw.len() > 16384 {
        return Vec::new();
    }

    let mut links = Vec::new();
    let mut seen_count = 0;

    // Split raw into individual link-values on commas that are not inside
    // angle brackets (<...>) or quoted strings ("...").
    let items = split_link_values(raw);

    for item in items {
        if links.len() >= 64 {
            break;
        }
        seen_count += 1;
        if seen_count > 64 {
            break;
        }

        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse the link-item: <URI>;param1=value1;param2="value2"
        if let Some(link) = parse_link_item(trimmed) {
            if link.up || link.alternate {
                links.push(link);
            }
        }
    }

    links
}

/// Split a Link header value string into individual link-values on commas
/// that are not inside angle brackets (<...>) or quoted strings ("...").
fn split_link_values(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let len = bytes.len();

    let mut start = 0;
    let mut in_angle = false;
    let mut in_quote = false;
    let mut escaped = false;

    for i in 0..len {
        let b = bytes[i];

        if escaped {
            escaped = false;
            continue;
        }

        if in_quote {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quote = false;
            }
            continue;
        }

        if in_angle {
            if b == b'>' {
                in_angle = false;
            }
            continue;
        }

        match b {
            b'<' => {
                in_angle = true;
            }
            b'"' => {
                in_quote = true;
            }
            b',' => {
                result.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    // Push the last segment
    if start < len {
        result.push(&s[start..]);
    } else if start == len && len > 0 {
        // Edge case: trailing comma produces empty last element, which we skip
    }

    result
}

/// Parse a single link-item (after trimming) into a Link struct.
/// Returns None if malformed.
fn parse_link_item(s: &str) -> Option<Link> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let bytes = s.as_bytes();
    let len = bytes.len();

    // Must start with '<'
    if bytes[0] != b'<' {
        return None;
    }

    // Find the closing '>'
    let mut close_pos = None;
    let mut in_quote = false;
    let mut escaped = false;

    for i in 1..len {
        let b = bytes[i];

        if escaped {
            escaped = false;
            continue;
        }

        if in_quote {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quote = false;
            }
            continue;
        }

        if b == b'"' {
            in_quote = true;
        } else if b == b'>' {
            close_pos = Some(i);
            break;
        }
    }

    let close = close_pos?;
    let target = &s[1..close];

    // Validate target: no ASCII control characters, length <= 8192
    if target.len() > 8192 {
        return None;
    }
    for &b in target.as_bytes() {
        if b < 0x20 || b == 0x7f {
            return None;
        }
    }

    // The rest after '>' may contain parameters
    let rest = s[close + 1..].trim_start();
    if !rest.is_empty() && !rest.starts_with(';') {
        return None;
    }

    let mut has_up = false;
    let mut has_alternate = false;
    let mut rel_first_seen = false;
    let mut found_up = false;
    let mut found_alternate = false;

    if !rest.is_empty() {
        // Split parameters on ';' that are not inside quoted strings
        let params = split_params(rest)?;

        for param in params {
            let p = param.trim();
            if p.is_empty() {
                continue;
            }

            // Split param on first '='
            if let Some((name, value)) = split_param(p) {
                let name_lower = name.to_ascii_lowercase();

                if name_lower == "rel" {
                    // Parse rel value: may be token(s) separated by whitespace,
                    // or a quoted-string containing whitespace-separated rel values.
                    let rel_values = parse_rel_value(value);

                    // Only first rel parameter matters (per spec interpretation)
                    if rel_first_seen {
                        continue;
                    }
                    rel_first_seen = true;

                    for rv in rel_values {
                        let rv_lower = rv.to_ascii_lowercase();
                        if rv_lower == "up" && !found_up {
                            found_up = true;
                            has_up = true;
                        }
                        if rv_lower == "alternate" && !found_alternate {
                            found_alternate = true;
                            has_alternate = true;
                        }
                    }
                }
                // Other params (title, etc.) are ignored for our purposes
            }
        }
    }

    Some(Link {
        target: target.to_string(),
        up: has_up,
        alternate: has_alternate,
    })
}

/// Split parameter string on ';' that are not inside quoted strings.
fn split_params(s: &str) -> Option<Vec<&str>> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let len = bytes.len();

    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;

    for i in 0..len {
        let b = bytes[i];

        if escaped {
            escaped = false;
            continue;
        }

        if in_quote {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quote = false;
            }
            continue;
        }

        if b == b'"' {
            in_quote = true;
        } else if b == b';' {
            result.push(&s[start..i]);
            start = i + 1;
        }
    }

    if start < len {
        result.push(&s[start..]);
    }

    if in_quote || escaped {
        return None;
    }
    Some(result)
}

/// Split a single parameter "name=value" on the first '='.
/// Returns (name, value). If no '=', value is empty string.
fn split_param(s: &str) -> Option<(&str, &str)> {
    // Find the first '=' that is not inside a quoted string
    let bytes = s.as_bytes();
    let len = bytes.len();

    let mut in_quote = false;
    let mut escaped = false;

    for i in 0..len {
        let b = bytes[i];

        if escaped {
            escaped = false;
            continue;
        }

        if in_quote {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quote = false;
            }
            continue;
        }

        if b == b'"' {
            in_quote = true;
        } else if b == b'=' {
            let name = s[..i].trim_end();
            let value = s[i + 1..].trim_start();
            return Some((name, value));
        }
    }

    // No '=' found
    None
}

/// Parse the value of a rel parameter.
/// rel="up alternate" -> ["up", "alternate"]
/// rel=up -> ["up"]
/// rel="up", "alternate" -> handled at higher level
fn parse_rel_value(value: &str) -> Vec<String> {
    let v = value.trim();
    if v.is_empty() {
        return Vec::new();
    }

    // Check if it's a quoted string
    let bytes = v.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' {
        // Find the closing quote
        if let Some(closed) = find_closing_quote(v, 0) {
            if !v[closed + 1..].trim().is_empty() {
                return Vec::new();
            }
            let inner = &v[1..closed];
            let unescaped = unescape_quoted(inner);
            // Split on whitespace
            return unescaped
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
    }

    // Token(s) separated by whitespace
    v.split_whitespace().map(|s| s.to_string()).collect()
}

/// Find the index of the closing quote (") in s, starting from position `start`
/// which should be at the opening quote.
fn find_closing_quote(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = start + 1;
    let mut escaped = false;

    while i < len {
        let b = bytes[i];

        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }

        if b == b'"' {
            return Some(i);
        }

        i += 1;
    }

    None
}

/// Unescape a quoted string content (handle backslash escapes).
fn unescape_quoted(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let len = bytes.len();

    let mut i = 0;
    while i < len {
        let b = bytes[i];

        if b == b'\\' {
            if i + 1 < len {
                result.push(bytes[i + 1] as char);
                i += 2;
                continue;
            } else {
                // Trailing backslash, treat literally
                result.push('\\');
                i += 1;
                continue;
            }
        }

        result.push(b as char);
        i += 1;
    }

    result
}
