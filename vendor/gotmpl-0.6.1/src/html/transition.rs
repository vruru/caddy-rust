//! The context-transition state machine — port of Go's `transition.go`.
//!
//! One transition function per [`Context`](super::context::Context) state, each
//! scanning a run of template text and returning the updated context plus how
//! far it consumed. Pure `&[u8]` scanning (no HTML parsing over rendered
//! output).
//!
//! # `transition` contract
//!
//! [`transition`] is the equivalent of Go's `transitionFunc[c.state](c, s)`. It
//! scans `s` starting at index `0` while in state `c.state` and returns the
//! updated [`Context`] together with the number of bytes consumed from the
//! front of `s` (always in `0..=s.len()`). A return of `s.len()` means the
//! whole run was consumed and the caller can stop; otherwise the caller must
//! re-invoke `transition` on the remaining suffix, in the loop
//!
//! ```ignore
//! while !s.is_empty() {
//!     let (c2, n) = transition(c, s);
//!     c = c2;
//!     s = &s[n..];
//! }
//! ```
//!
//! A consumed count of `0` is possible (only in [`State::Rcdata`], when a
//! special end tag such as `</script>` sits at index 0): the context flips to
//! [`State::Text`] without consuming input, exactly as Go's
//! `tSpecialTagEnd`/`contextAfterText` do. The driver must therefore rely on
//! the *state change* — not solely on forward progress — to avoid looping, as
//! Go's `escapeText` does.
//!
//! Errors are not carried in the [`Context`]; any Go `stateError` result is
//! represented as [`State::Error`] (see [`Context::error`]).
//!
//! Because `primitives.rs` (phase P2) is not yet populated, the Go `js.go`/
//! `css.go` helpers this machine needs (`nextJSCtx`, `decodeCSS`,
//! `endsWithCSSKeyword`, and their sub-helpers) are ported privately here.

use super::context::{
    Attr, AttrContentType, Context, Delim, Element, JsCtx, State, UrlPart, attr_start_state,
    attr_type,
};
use super::lex::{
    contains_any as contains_any_bytes, decode_css, decode_last_rune, index_any as index_any_bytes,
    index_byte, index_js_line_terminator, index_sub, is_css_nmchar, is_js_ident_part,
    trim_left as trim_left_bytes, trim_right as trim_right_bytes,
};

const COMMENT_START: &[u8] = b"<!--";
const COMMENT_END: &[u8] = b"-->";
const BLOCK_COMMENT_END: &[u8] = b"*/";
const SPECIAL_TAG_END_PREFIX: &[u8] = b"</";
/// Go's `tagEndSeparators` = `"> \t\n\f/"` (note: no `\r`).
const TAG_END_SEPARATORS: &[u8] = b"> \t\n\x0c/";
/// The CSS whitespace set Go trims in `tCSS` (`"\t\n\f\r "`).
const CSS_WS: &[u8] = b"\t\n\x0c\r ";

/// Scan `s` in `c.state`, returning the updated context and bytes consumed.
/// See the module docs for the full contract. Mirrors Go's `transitionFunc`
/// dispatch table exactly.
pub(crate) fn transition(c: Context, s: &[u8]) -> (Context, usize) {
    match c.state {
        State::Text => t_text(c, s),
        State::Tag => t_tag(c, s),
        State::AttrName => t_attr_name(c, s),
        State::AfterName => t_after_name(c, s),
        State::BeforeValue => t_before_value(c, s),
        State::HtmlCmt => t_html_cmt(c, s),
        State::Rcdata => special_tag_end(c, s),
        State::Attr => t_attr(c, s),
        State::Url => t_url(c, s),
        State::Srcset => t_url(c, s),
        State::MetaContent => t_meta_content(c, s),
        State::MetaContentUrl => t_meta_content_url(c, s),
        State::Js => t_js(c, s),
        State::JsDqStr | State::JsSqStr | State::JsRegexp => t_js_delimited(c, s),
        State::JsTmplLit => t_js_tmpl(c, s),
        State::JsBlockCmt => t_block_cmt(c, s),
        State::JsLineCmt | State::JsHtmlOpenCmt | State::JsHtmlCloseCmt => t_line_cmt(c, s),
        State::Css => t_css(c, s),
        State::CssDqStr | State::CssSqStr | State::CssDqUrl | State::CssSqUrl | State::CssUrl => {
            t_css_str(c, s)
        }
        State::CssBlockCmt => t_block_cmt(c, s),
        State::CssLineCmt => t_line_cmt(c, s),
        State::Error => t_error(c, s),
        // Go's transitionFunc has no entry for stateDead; it is never reached
        // because the escaper stops descending at a dead context. Consume the
        // run as a safe no-op default.
        State::Dead => (c, s.len()),
    }
}

// The byte-slice helpers this machine uses (`index_byte`, `index_any_bytes`,
// `contains_any_bytes`, `index_sub`, `trim_*_bytes`) live in `super::lex`, as
// does the one non-ASCII search — the JS line terminators including
// U+2028/U+2029 (`index_js_line_terminator`).

// ---------------------------------------------------------------------------
// Per-state transition functions (Go's tXxx).
// ---------------------------------------------------------------------------

/// Go's `tText`.
fn t_text(c: Context, s: &[u8]) -> (Context, usize) {
    let mut k = 0;
    loop {
        let lt = match index_byte(&s[k..], b'<') {
            Some(rel) => k + rel,
            None => return (c, s.len()),
        };
        if lt + 1 == s.len() {
            return (c, s.len());
        }
        if lt + 4 <= s.len() && &s[lt..lt + 4] == COMMENT_START {
            return (Context::in_state(State::HtmlCmt), lt + 4);
        }
        let mut i = lt + 1;
        let mut end = false;
        if s[i] == b'/' {
            if i + 1 == s.len() {
                return (c, s.len());
            }
            end = true;
            i += 1;
        }
        let (j, e) = eat_tag_name(s, i);
        if j != i {
            // We've found an HTML tag.
            let e = if end { Element::None } else { e };
            return (
                Context {
                    state: State::Tag,
                    element: e,
                    ..Context::default()
                },
                j,
            );
        }
        k = j;
    }
}

/// Go's `elementContentType`: the body state a tag's `>` transitions into.
fn element_content_type(e: Element) -> State {
    match e {
        Element::None => State::Text,
        Element::Script => State::Js,
        Element::Style => State::Css,
        Element::Textarea | Element::Title => State::Rcdata,
        Element::Meta => State::Text,
    }
}

/// Go's `tTag`.
fn t_tag(c: Context, s: &[u8]) -> (Context, usize) {
    // Find the attribute name.
    let i = eat_white_space(s, 0);
    if i == s.len() {
        return (c, s.len());
    }
    if s[i] == b'>' {
        // Treat <meta> specially: it has no end tag, so transition straight
        // back to text.
        if c.element == Element::Meta {
            return (
                Context {
                    state: State::Text,
                    element: Element::None,
                    ..Context::default()
                },
                i + 1,
            );
        }
        return (
            Context {
                state: element_content_type(c.element),
                element: c.element,
                ..Context::default()
            },
            i + 1,
        );
    }
    let j = match eat_attr_name(s, i) {
        None => return (Context::error(), s.len()),
        Some(j) => j,
    };
    if i == j {
        // Go: expected space, attr name, or end of tag.
        return (Context::error(), s.len());
    }

    let attr_name = alloc::string::String::from_utf8_lossy(&s[i..j]).to_ascii_lowercase();
    let attr = if c.element == Element::Script && attr_name == "type" {
        Attr::ScriptType
    } else if c.element == Element::Meta && attr_name == "content" {
        Attr::MetaContent
    } else {
        match attr_type(&attr_name) {
            AttrContentType::Url => Attr::Url,
            AttrContentType::Css => Attr::Style,
            AttrContentType::Js => Attr::Script,
            AttrContentType::Srcset => Attr::Srcset,
            _ => Attr::None,
        }
    };

    let state = if j == s.len() {
        State::AttrName
    } else {
        State::AfterName
    };
    (
        Context {
            state,
            element: c.element,
            attr,
            ..Context::default()
        },
        j,
    )
}

/// Go's `tAttrName`.
fn t_attr_name(mut c: Context, s: &[u8]) -> (Context, usize) {
    match eat_attr_name(s, 0) {
        None => (Context::error(), s.len()),
        Some(i) => {
            if i != s.len() {
                c.state = State::AfterName;
            }
            (c, i)
        }
    }
}

/// Go's `tAfterName`.
fn t_after_name(mut c: Context, s: &[u8]) -> (Context, usize) {
    // Look for the start of the value.
    let i = eat_white_space(s, 0);
    if i == s.len() {
        return (c, s.len());
    }
    if s[i] != b'=' {
        // Occurs due to tag ending '>', and valueless attribute.
        c.state = State::Tag;
        return (c, i);
    }
    c.state = State::BeforeValue;
    // Consume the "=".
    (c, i + 1)
}

/// Go's `tBeforeValue`.
fn t_before_value(mut c: Context, s: &[u8]) -> (Context, usize) {
    let mut i = eat_white_space(s, 0);
    if i == s.len() {
        return (c, s.len());
    }
    // Find the attribute delimiter.
    let mut delim = Delim::SpaceOrTagEnd;
    match s[i] {
        b'\'' => {
            delim = Delim::SingleQuote;
            i += 1;
        }
        b'"' => {
            delim = Delim::DoubleQuote;
            i += 1;
        }
        _ => {}
    }
    c.state = attr_start_state(c.attr);
    c.delim = delim;
    (c, i)
}

/// Go's `tHTMLCmt`.
fn t_html_cmt(c: Context, s: &[u8]) -> (Context, usize) {
    match index_sub(s, COMMENT_END) {
        Some(i) => (Context::default(), i + 3),
        None => (c, s.len()),
    }
}

/// Go's `specialTagEndMarkers`: the case-insensitive sequence that ends the
/// special body of the given element (empty for `<meta>`, which has no body).
fn special_tag_end_marker(e: Element) -> &'static [u8] {
    match e {
        Element::Script => b"script",
        Element::Style => b"style",
        Element::Textarea => b"textarea",
        Element::Title => b"title",
        Element::None | Element::Meta => b"",
    }
}

/// Go's `tSpecialTagEnd` (the transition for raw-text/RCDATA states, and used
/// directly by the escaper's `contextAfterText`).
pub(crate) fn special_tag_end(c: Context, s: &[u8]) -> (Context, usize) {
    if c.element != Element::None {
        // "</script" within script literals/comments is ignored so it can be
        // escaped later rather than closing the element.
        if c.element == Element::Script && (c.state.is_in_script_literal() || c.state.is_comment())
        {
            return (c, s.len());
        }
        if let Some(i) = index_tag_end(s, special_tag_end_marker(c.element)) {
            return (Context::default(), i);
        }
    }
    (c, s.len())
}

/// Go's `indexTagEnd`: the index of a case-insensitive special tag end, or
/// [`None`] for Go's `-1`.
fn index_tag_end(mut s: &[u8], tag: &[u8]) -> Option<usize> {
    let mut res = 0usize;
    let plen = SPECIAL_TAG_END_PREFIX.len();
    while !s.is_empty() {
        // Try to find the tag end prefix first.
        let i = index_sub(s, SPECIAL_TAG_END_PREFIX)?;
        s = &s[i + plen..];
        // Try to match the actual tag if there is still space for it.
        if tag.len() <= s.len() && tag.eq_ignore_ascii_case(&s[..tag.len()]) {
            s = &s[tag.len()..];
            // Check the tag is followed by a proper separator.
            if !s.is_empty() && TAG_END_SEPARATORS.contains(&s[0]) {
                return Some(res + i);
            }
            res += tag.len();
        }
        res += i + plen;
    }
    None
}

/// Go's `tAttr`.
fn t_attr(c: Context, s: &[u8]) -> (Context, usize) {
    (c, s.len())
}

/// Go's `tURL` (also the transition for `stateSrcset`).
fn t_url(mut c: Context, s: &[u8]) -> (Context, usize) {
    if contains_any_bytes(s, b"#?") {
        c.url_part = UrlPart::QueryOrFrag;
    } else if eat_white_space(s, 0) != s.len() && c.url_part == UrlPart::None {
        // HTML5 "Valid URL potentially surrounded by spaces".
        c.url_part = UrlPart::PreQuery;
    }
    (c, s.len())
}

/// Go's `tJS`.
fn t_js(mut c: Context, s: &[u8]) -> (Context, usize) {
    let mut i = match index_any_bytes(s, b"\"`'/{}<-#") {
        None => {
            // Entire input is non string, comment, regexp tokens.
            c.js_ctx = next_js_ctx(s, c.js_ctx);
            return (c, s.len());
        }
        Some(i) => i,
    };
    c.js_ctx = next_js_ctx(&s[..i], c.js_ctx);
    match s[i] {
        b'"' => {
            c.state = State::JsDqStr;
            c.js_ctx = JsCtx::Regexp;
        }
        b'\'' => {
            c.state = State::JsSqStr;
            c.js_ctx = JsCtx::Regexp;
        }
        b'`' => {
            c.state = State::JsTmplLit;
            c.js_ctx = JsCtx::Regexp;
        }
        b'/' => {
            if i + 1 < s.len() && s[i + 1] == b'/' {
                c.state = State::JsLineCmt;
                i += 1;
            } else if i + 1 < s.len() && s[i + 1] == b'*' {
                c.state = State::JsBlockCmt;
                i += 1;
            } else if c.js_ctx == JsCtx::Regexp {
                c.state = State::JsRegexp;
            } else if c.js_ctx == JsCtx::DivOp {
                c.js_ctx = JsCtx::Regexp;
            } else {
                // '/' could start a division or a regexp: ambiguous.
                return (Context::error(), s.len());
            }
        }
        // ECMAScript legacy HTML-like comments (Annex B.1.1): treat a line
        // prefixed with "<!--" or "-->" as if it were "//".
        b'<' if i + 3 < s.len() && &s[i..i + 4] == COMMENT_START => {
            c.state = State::JsHtmlOpenCmt;
            i += 3;
        }
        b'-' if i + 2 < s.len() && &s[i..i + 3] == COMMENT_END => {
            c.state = State::JsHtmlCloseCmt;
            i += 2;
        }
        // Hashbang comment line (section 12.5).
        b'#' if i + 1 < s.len() && s[i + 1] == b'!' => {
            c.state = State::JsLineCmt;
            i += 1;
        }
        b'{' => {
            // Only track brace depth inside a template literal interpolation.
            let Some(last) = c.js_brace_depth.last_mut() else {
                return (c, i + 1);
            };
            *last += 1;
        }
        b'}' => {
            let Some(last) = c.js_brace_depth.last_mut() else {
                return (c, i + 1);
            };
            // A "\}" is not a valid escape in JS; count it as "}" and move on.
            *last -= 1;
            if *last >= 0 {
                return (c, i + 1);
            }
            c.js_brace_depth.pop();
            c.state = State::JsTmplLit;
        }
        // Unreachable: index_any_bytes only returns positions of the bytes in
        // the search set above.
        _ => {}
    }
    (c, i + 1)
}

/// Go's `tJSTmpl`.
fn t_js_tmpl(mut c: Context, s: &[u8]) -> (Context, usize) {
    let mut k = 0;
    loop {
        let mut i = match index_any_bytes(&s[k..], b"`\\$") {
            None => break,
            Some(rel) => k + rel,
        };
        match s[i] {
            b'\\' => {
                i += 1;
                if i == s.len() {
                    // Unfinished escape sequence.
                    return (Context::error(), s.len());
                }
            }
            b'$' if s.len() >= i + 2 && s[i + 1] == b'{' => {
                c.js_brace_depth.push(0);
                c.state = State::Js;
                return (c, i + 2);
            }
            b'`' => {
                // end
                c.state = State::Js;
                return (c, i + 1);
            }
            _ => {}
        }
        k = i + 1;
    }
    (c, s.len())
}

/// Go's `tJSDelimited` (JS string and regexp states).
fn t_js_delimited(mut c: Context, s: &[u8]) -> (Context, usize) {
    let specials: &[u8] = match c.state {
        State::JsSqStr => b"\\'",
        State::JsRegexp => b"\\/[]",
        _ => b"\\\"",
    };

    let mut k = 0;
    let mut in_charset = false;
    loop {
        let mut i = match index_any_bytes(&s[k..], specials) {
            None => break,
            Some(rel) => k + rel,
        };
        match s[i] {
            b'\\' => {
                i += 1;
                if i == s.len() {
                    return (Context::error(), s.len());
                }
            }
            b'[' => in_charset = true,
            b']' => in_charset = false,
            b'/' => {
                // "</script" in a regex literal: the '/' must not close the
                // literal (it is escaped to "\x3C/script" later).
                if i > 0 && i + 7 <= s.len() && s[i - 1..i + 7].eq_ignore_ascii_case(b"</script") {
                    i += 1;
                } else if !in_charset {
                    c.state = State::Js;
                    c.js_ctx = JsCtx::DivOp;
                    return (c, i + 1);
                }
            }
            _ => {
                // end delimiter
                if !in_charset {
                    c.state = State::Js;
                    c.js_ctx = JsCtx::DivOp;
                    return (c, i + 1);
                }
            }
        }
        k = i + 1;
    }

    if in_charset {
        // Interpolation into a charset is not supported.
        return (Context::error(), s.len());
    }
    (c, s.len())
}

/// Go's `tBlockCmt` (`/* comment */` states).
fn t_block_cmt(mut c: Context, s: &[u8]) -> (Context, usize) {
    let i = match index_sub(s, BLOCK_COMMENT_END) {
        None => return (c, s.len()),
        Some(i) => i,
    };
    match c.state {
        State::JsBlockCmt => c.state = State::Js,
        State::CssBlockCmt => c.state = State::Css,
        // Only dispatched for the two block-comment states above.
        _ => return (c, s.len()),
    }
    (c, i + 2)
}

/// Go's `tLineCmt` (`// comment` states and the JS HTML-like comment states).
fn t_line_cmt(mut c: Context, s: &[u8]) -> (Context, usize) {
    let (end_state, found) = match c.state {
        State::JsLineCmt | State::JsHtmlOpenCmt | State::JsHtmlCloseCmt => {
            (State::Js, index_js_line_terminator(s))
        }
        // CSS line terminators: "\n\f\r".
        State::CssLineCmt => (State::Css, index_any_bytes(s, b"\n\x0c\r")),
        _ => return (c, s.len()),
    };
    match found {
        None => (c, s.len()),
        Some(i) => {
            c.state = end_state;
            // The line terminator is not part of the comment.
            (c, i)
        }
    }
}

/// Go's `tCSS`.
fn t_css(mut c: Context, s: &[u8]) -> (Context, usize) {
    let mut k = 0;
    loop {
        let i = match index_any_bytes(&s[k..], b"(\"'/") {
            None => return (c, s.len()),
            Some(rel) => k + rel,
        };
        match s[i] {
            b'(' => {
                // Look for url to the left.
                let p = trim_right_bytes(&s[..i], CSS_WS);
                if ends_with_css_keyword(p, "url") {
                    let trimmed = trim_left_bytes(&s[i + 1..], CSS_WS);
                    let mut j = s.len() - trimmed.len();
                    if j != s.len() && s[j] == b'"' {
                        c.state = State::CssDqUrl;
                        j += 1;
                    } else if j != s.len() && s[j] == b'\'' {
                        c.state = State::CssSqUrl;
                        j += 1;
                    } else {
                        c.state = State::CssUrl;
                    }
                    return (c, j);
                }
            }
            b'/' if i + 1 < s.len() => match s[i + 1] {
                b'/' => {
                    c.state = State::CssLineCmt;
                    return (c, i + 2);
                }
                b'*' => {
                    c.state = State::CssBlockCmt;
                    return (c, i + 2);
                }
                _ => {}
            },
            b'"' => {
                c.state = State::CssDqStr;
                return (c, i + 1);
            }
            b'\'' => {
                c.state = State::CssSqStr;
                return (c, i + 1);
            }
            _ => {}
        }
        k = i + 1;
    }
}

/// Go's `tCSSStr` (CSS string and URL states).
fn t_css_str(mut c: Context, s: &[u8]) -> (Context, usize) {
    let end_and_esc: &[u8] = match c.state {
        State::CssDqStr | State::CssDqUrl => b"\\\"",
        State::CssSqStr | State::CssSqUrl => b"\\'",
        // Unquoted URLs end with a newline or close parenthesis (includes the
        // whitespace chars and nl).
        State::CssUrl => b"\\\t\n\x0c\r )",
        // Only dispatched for the CSS string/URL states above.
        _ => return (c, s.len()),
    };

    let mut k = 0;
    loop {
        let mut i = match index_any_bytes(&s[k..], end_and_esc) {
            None => {
                let decoded = decode_css(&s[k..]);
                let (c1, nread) = t_url(c, &decoded);
                return (c1, k + nread);
            }
            Some(rel) => k + rel,
        };
        if s[i] == b'\\' {
            i += 1;
            if i == s.len() {
                return (Context::error(), s.len());
            }
        } else {
            c.state = State::Css;
            return (c, i + 1);
        }
        let decoded = decode_css(&s[..i + 1]);
        let (c1, _) = t_url(c, &decoded);
        c = c1;
        k = i + 1;
    }
}

/// Go's `tError`.
fn t_error(c: Context, s: &[u8]) -> (Context, usize) {
    (c, s.len())
}

/// Go's `tMetaContent`.
fn t_meta_content(mut c: Context, s: &[u8]) -> (Context, usize) {
    let mut i = 0;
    while i < s.len() {
        // Go: `i+3 <= len(s)-1`, i.e. a "url" with at least one trailing byte.
        if i + 4 <= s.len() && s[i..i + 3].eq_ignore_ascii_case(b"url") {
            let j = eat_white_space(s, i + 3);
            if j < s.len() && s[j] == b'=' {
                c.state = State::MetaContentUrl;
                return (c, j + 1);
            }
        }
        i += 1;
    }
    (c, s.len())
}

/// Go's `tMetaContentURL`.
fn t_meta_content_url(mut c: Context, s: &[u8]) -> (Context, usize) {
    for (i, &b) in s.iter().enumerate() {
        if b == b';' {
            c.state = State::MetaContent;
            return (c, i + 1);
        }
    }
    (c, s.len())
}

// ---------------------------------------------------------------------------
// Tag/attribute name scanners (Go's eat* helpers).
// ---------------------------------------------------------------------------

/// Go's `eatWhiteSpace`.
fn eat_white_space(s: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < s.len() {
        match s[j] {
            b' ' | b'\t' | b'\n' | 0x0c | b'\r' => j += 1,
            _ => return j,
        }
    }
    s.len()
}

/// Go's `eatAttrName`: the largest `j` such that `s[i..j]` is an attribute
/// name, or [`None`] for Go's error result (a quote or `<` in the name).
fn eat_attr_name(s: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    while j < s.len() {
        match s[j] {
            b' ' | b'\t' | b'\n' | 0x0c | b'\r' | b'=' | b'>' => return Some(j),
            // Serious problems if seen in an attr name in a template.
            b'\'' | b'"' | b'<' => return None,
            _ => {}
        }
        j += 1;
    }
    Some(s.len())
}

/// Go's `eatTagName`: the largest `j` such that `s[i..j]` is a tag name, and
/// the element type it denotes.
fn eat_tag_name(s: &[u8], i: usize) -> (usize, Element) {
    if i == s.len() || !s[i].is_ascii_alphabetic() {
        return (i, Element::None);
    }
    let mut j = i + 1;
    while j < s.len() {
        let x = s[j];
        if x.is_ascii_alphanumeric() {
            j += 1;
            continue;
        }
        // Allow "x-y" or "x:y" but not "x-", "-y", or "x--y".
        if (x == b':' || x == b'-') && j + 1 < s.len() && s[j + 1].is_ascii_alphanumeric() {
            j += 2;
            continue;
        }
        break;
    }
    (j, element_name_map(&s[i..j]))
}

/// Go's `elementNameMap`.
fn element_name_map(name: &[u8]) -> Element {
    // Tag names are ASCII (per eat_tag_name), so this lossy match is exact.
    let lower = name.to_ascii_lowercase();
    let Ok(s) = core::str::from_utf8(&lower) else {
        return Element::None;
    };
    match s {
        "script" => Element::Script,
        "style" => Element::Style,
        "textarea" => Element::Textarea,
        "title" => Element::Title,
        "meta" => Element::Meta,
        _ => Element::None,
    }
}

// ---------------------------------------------------------------------------
// JS lexer helper (Go's nextJSCtx from js.go).
// ---------------------------------------------------------------------------

/// The non-ASCII JS whitespace runes Go's `nextJSCtx` trims: only the two
/// line separators U+2028 and U+2029. Go trims exactly the ASCII set
/// `\t \n \f \r <space>` plus these two -- not the full ECMAScript
/// whitespace class -- so we match it byte-for-byte (the ASCII members are
/// handled inline below).
const JS_WS_MB: &[char] = &['\u{2028}', '\u{2029}'];

fn trim_right_js_ws(mut s: &[u8]) -> &[u8] {
    loop {
        match s.last() {
            // Go's set is "\t\n\f\r " — note it excludes the vertical tab (0x0b).
            Some(&(b'\t' | b'\n' | 0x0c | b'\r' | b' ')) => {
                s = &s[..s.len() - 1];
            }
            Some(_) => {
                let mut trimmed = false;
                for &r in JS_WS_MB {
                    let mut buf = [0u8; 4];
                    let enc = r.encode_utf8(&mut buf).as_bytes();
                    if s.ends_with(enc) {
                        s = &s[..s.len() - enc.len()];
                        trimmed = true;
                        break;
                    }
                }
                if !trimmed {
                    return s;
                }
            }
            None => return s,
        }
    }
}

fn is_regexp_preceder_keyword(b: &[u8]) -> bool {
    let Ok(s) = core::str::from_utf8(b) else {
        return false;
    };
    matches!(
        s,
        "break"
            | "case"
            | "continue"
            | "delete"
            | "do"
            | "else"
            | "finally"
            | "in"
            | "instanceof"
            | "return"
            | "throw"
            | "try"
            | "typeof"
            | "void"
    )
}

/// Go's `nextJSCtx`: whether a `/` after this run of tokens starts a regexp or
/// a division operator.
fn next_js_ctx(s: &[u8], preceding: JsCtx) -> JsCtx {
    let s = trim_right_js_ws(s);
    if s.is_empty() {
        return preceding;
    }
    let n = s.len();
    let c = s[n - 1];
    match c {
        b'+' | b'-' => {
            // ++ and -- are not regexp preceders; a single + or - is.
            let mut start = n - 1;
            while start > 0 && s[start - 1] == c {
                start -= 1;
            }
            if (n - start) & 1 == 1 {
                JsCtx::Regexp
            } else {
                JsCtx::DivOp
            }
        }
        b'.' => {
            // Handle "42."
            if n != 1 && s[n - 2].is_ascii_digit() {
                JsCtx::DivOp
            } else {
                JsCtx::Regexp
            }
        }
        b',' | b'<' | b'>' | b'=' | b'*' | b'%' | b'&' | b'|' | b'^' | b'?' => JsCtx::Regexp,
        b'!' | b'~' => JsCtx::Regexp,
        b'(' | b'[' => JsCtx::Regexp,
        b':' | b';' | b'{' => JsCtx::Regexp,
        b'}' => JsCtx::Regexp,
        _ => {
            // Look for an IdentifierName ending the run and see whether it is a
            // regexp-preceding keyword.
            let mut j = n;
            while j > 0 && is_js_ident_part(s[j - 1]) {
                j -= 1;
            }
            if is_regexp_preceder_keyword(&s[j..]) {
                JsCtx::Regexp
            } else {
                JsCtx::DivOp
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CSS lexer helper (Go's endsWithCSSKeyword from css.go). The rune/CSS decode
// helpers it builds on (`decode_last_rune`, `is_css_nmchar`,
// `decode_css`, …) live in `super::lex`.
// ---------------------------------------------------------------------------

/// Go's `endsWithCSSKeyword`: whether `b` ends with an ident that
/// case-insensitively matches the lowercase `kw`.
fn ends_with_css_keyword(b: &[u8], kw: &str) -> bool {
    let kwb = kw.as_bytes();
    if b.len() < kwb.len() {
        // Too short.
        return false;
    }
    let i = b.len() - kwb.len();
    if i != 0 {
        let (r, _) = decode_last_rune(&b[..i]);
        if is_css_nmchar(r) {
            // Too long (the keyword is part of a larger ident).
            return false;
        }
    }
    b[i..].eq_ignore_ascii_case(kwb)
}
