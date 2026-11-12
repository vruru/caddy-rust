//! Byte scanners for Goldmark HTML grammar (MIT, see html_render.rs).
use super::parse_util::blank;
const BLOCK_TAGS: &[&[u8]] = &[
    b"address",
    b"article",
    b"aside",
    b"base",
    b"basefont",
    b"blockquote",
    b"body",
    b"caption",
    b"center",
    b"col",
    b"colgroup",
    b"dd",
    b"details",
    b"dialog",
    b"dir",
    b"div",
    b"dl",
    b"dt",
    b"fieldset",
    b"figcaption",
    b"figure",
    b"footer",
    b"form",
    b"frame",
    b"frameset",
    b"h1",
    b"h2",
    b"h3",
    b"h4",
    b"h5",
    b"h6",
    b"head",
    b"header",
    b"hr",
    b"html",
    b"iframe",
    b"legend",
    b"li",
    b"link",
    b"main",
    b"menu",
    b"menuitem",
    b"meta",
    b"nav",
    b"noframes",
    b"ol",
    b"optgroup",
    b"option",
    b"p",
    b"param",
    b"search",
    b"section",
    b"summary",
    b"table",
    b"tbody",
    b"td",
    b"tfoot",
    b"th",
    b"thead",
    b"title",
    b"tr",
    b"track",
    b"ul",
];
fn white(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}
fn name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || matches!(b, b'_' | b':')
}
fn name_more(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-')
}
/// Match Goldmark's complete inline open/close tag prefix, without UTF8 loss.
pub(super) fn tag_len(s: &[u8]) -> Option<usize> {
    tag(s, false).map(|(n, _)| n)
}
fn end_space(mut s: &[u8], strict: bool) -> bool {
    if strict {
        return s.iter().all(|b| *b == b' ');
    }
    while !s.is_empty() {
        if matches!(s[0], b' ' | b'\t' | b'\n') {
            s = &s[1..];
        } else if s.starts_with(b"\r\n") {
            s = &s[2..];
        } else {
            return false;
        }
    }
    true
}
fn tag(s: &[u8], strict: bool) -> Option<(usize, bool)> {
    if s.first() != Some(&b'<') {
        return None;
    }
    let mut i = 1;
    let close = s.get(i) == Some(&b'/');
    if close {
        i += 1;
        if strict {
            while s.get(i) == Some(&b' ') {
                i += 1;
            }
        }
    }
    if !s.get(i).is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    i += 1;
    while s
        .get(i)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-')
    {
        i += 1;
    }
    let mut attrs = false;
    loop {
        let space = i;
        while s.get(i).is_some_and(|b| white(*b)) {
            i += 1;
        }
        if s.get(i) == Some(&b'>') {
            return end_space(&s[space..i], strict).then_some((i + 1, attrs));
        }
        if (!close || strict) && s.get(i..i + 2) == Some(b"/>") {
            return end_space(&s[space..i], strict).then_some((i + 2, attrs));
        }
        if close && !strict || space == i || !s.get(i).is_some_and(|b| name_start(*b)) {
            return None;
        }
        attrs = true;
        i += 1;
        while s.get(i).is_some_and(|b| name_more(*b)) {
            i += 1;
        }
        let end = i;
        while s.get(i).is_some_and(|b| white(*b)) {
            i += 1;
        }
        if s.get(i) != Some(&b'=') {
            i = end;
            continue;
        }
        i += 1;
        while s.get(i).is_some_and(|b| white(*b)) {
            i += 1;
        }
        let c = *s.get(i)?;
        if matches!(c, b'\'' | b'"') {
            i += 1;
            while *s.get(i)? != c {
                i += 1;
            }
            i += 1;
        } else {
            let start = i;
            while s.get(i).is_some_and(|b| {
                *b > 0x20 && !matches!(b, b'"' | b'\'' | b'=' | b'<' | b'>' | b'`')
            }) {
                i += 1;
            }
            if i == start {
                return None;
            }
        }
    }
}
pub(super) fn block_open(line: &[u8], paragraph: bool) -> Option<u8> {
    let spaces = line.iter().take_while(|b| **b == b' ').count();
    if spaces > 3 {
        return None;
    }
    let s = &line[spaces..];
    if s.first() != Some(&b'<') {
        return None;
    }
    for tag in [b"script".as_slice(), b"pre", b"style", b"textarea"] {
        if s.get(1..1 + tag.len())
            .is_some_and(|v| v.eq_ignore_ascii_case(tag))
        {
            let rest = &s[1 + tag.len()..];
            if rest.is_empty()
                || rest
                    .first()
                    .is_some_and(|b| white(*b) || *b == b'\x0c' || *b == b'>')
                || rest.starts_with(b"/>")
            {
                return Some(1);
            }
        }
    }
    if s.starts_with(b"<!--") {
        return Some(2);
    }
    if s.starts_with(b"<?") {
        return Some(3);
    }
    if s.get(..2) == Some(b"<!") && s.get(2).is_some_and(u8::is_ascii_uppercase) {
        return Some(4);
    }
    if s.starts_with(b"<![CDATA[") {
        return Some(5);
    }
    let mut start = 1;
    if s.get(start) == Some(&b'/') {
        start += 1;
        while s.get(start) == Some(&b' ') {
            start += 1;
        }
    }
    let mut end = start;
    if !s.get(end).is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    end += 1;
    while s
        .get(end)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-')
    {
        end += 1;
    }
    let name = &s[start..end];
    let rest = &s[end..];
    if BLOCK_TAGS.iter().any(|tag| name.eq_ignore_ascii_case(tag))
        && (rest.is_empty()
            || rest.first() == Some(&b' ')
            || rest.first() == Some(&b'>')
            || rest.starts_with(b"/>")
            || matches!(rest, b"\n" | b"\r\n"))
    {
        return Some(6);
    }
    if !paragraph
        && !name.eq_ignore_ascii_case(b"script")
        && !name.eq_ignore_ascii_case(b"style")
        && !name.eq_ignore_ascii_case(b"pre")
    {
        if let Some((n, attrs)) = tag(s, true) {
            let rest = &s[n..];
            let close = s.get(1) == Some(&b'/') && s.get(2) != Some(&b' ');
            if rest.iter().all(|b| matches!(b, b' ' | b'\r' | b'\n')) {
                if BLOCK_TAGS.iter().any(|tag| name.eq_ignore_ascii_case(tag)) {
                    return Some(6);
                }
                if !(close && attrs) {
                    return Some(7);
                }
            }
        }
    }
    None
}
pub(super) fn block_closes(kind: u8, line: &[u8]) -> bool {
    match kind {
        1 => [
            b"</script>".as_slice(),
            b"</pre>",
            b"</style>",
            b"</textarea>",
        ]
        .iter()
        .any(|tag| line.windows(tag.len()).any(|v| v.eq_ignore_ascii_case(tag))),
        2 => line.windows(3).any(|s| s == b"-->"),
        3 => line.windows(2).any(|s| s == b"?>"),
        4 => line.contains(&b'>'),
        5 => line.windows(3).any(|s| s == b"]]>"),
        _ => blank(line),
    }
}
pub(super) fn raw_len(s: &[u8]) -> Option<usize> {
    if s.starts_with(b"<!-->") {
        return Some(5);
    }
    if s.starts_with(b"<!--->") {
        return Some(6);
    }
    let (start, close): (usize, &[u8]) = if s.starts_with(b"<!--") {
        (4, b"-->")
    } else if s.starts_with(b"<?") {
        (0, b"?>")
    } else if s.starts_with(b"<![CDATA[") {
        (0, b"]]>")
    } else if s.starts_with(b"<!") && s.get(2).is_some_and(u8::is_ascii_uppercase) {
        (0, b">")
    } else {
        return tag_len(s);
    };
    s[start..]
        .windows(close.len())
        .position(|v| v == close)
        .map(|n| start + n + close.len())
}
