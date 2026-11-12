//! Byte-preserving HTML renderer for Caddy's Goldmark 1.8.6 configuration:
//! GFM + Footnote, unsafe HTML, default HTML (not XHTML), no hard wrapping.
//!
//! Derived from Goldmark 1.8.6 renderer/html and extension renderers.
//! MIT License
//! Copyright (c) 2019 Yusuke Inuzuka
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.
use super::{
    ast::{Alignment, Arena, CODE, HARD_BREAK, Id, Kind, Node, RAW, SOFT_BREAK, Walk},
    output::Output,
    segment::Bytes,
    text_writer as writer,
};
use gotmpl::{BudgetAccount, BudgetedBytes, Result, TemplateError};
fn invalid() -> TemplateError {
    TemplateError::Exec("invalid Markdown render state".into())
}
const GLOBAL:&[u8]=b"accesskey,autocapitalize,autofocus,class,contenteditable,dir,draggable,enterkeyhint,hidden,id,inert,inputmode,is,itemid,itemprop,itemref,itemscope,itemtype,lang,part,role,slot,spellcheck,style,tabindex,title,translate";
const LINK: &[u8] = b"download,href,lang,media,ping,referrerpolicy,rel,shape,target";
const IMAGE:&[u8]=b"align,border,crossorigin,decoding,height,importance,intrinsicsize,ismap,loading,referrerpolicy,sizes,srcset,usemap,width";
const TABLE: &[u8] = b"align,bgcolor,border,cellpadding,cellspacing,frame,rules,summary,width";
const ROW: &[u8] = b"align,bgcolor,char,charoff,valign";
const CELL: &[u8] =
    b"abbr,align,axis,bgcolor,char,charoff,colspan,headers,height,rowspan,scope,valign,width";
fn number(out: &mut Output, mut value: usize) -> Result<()> {
    let mut digits = [0u8; 40];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.write(&digits[start..])
}
fn attributes(out: &mut Output, node: &Node<'_>, extra: &[u8]) -> Result<()> {
    for attr in &node.attributes {
        let name = &*attr.name;
        if !name.starts_with(b"data-")
            && !GLOBAL
                .split(|b| *b == b',')
                .chain(extra.split(|b| *b == b','))
                .any(|allowed| allowed == name)
        {
            continue;
        }
        out.byte(b' ')?;
        out.write(name)?;
        out.write(b"=\"")?;
        writer::raw_write(out, &attr.value)?;
        out.byte(b'"')?;
    }
    Ok(())
}
fn open(out: &mut Output, node: &Node<'_>, tag: &[u8], extra: &[u8], newline: bool) -> Result<()> {
    out.byte(b'<')?;
    out.write(tag)?;
    attributes(out, node, extra)?;
    out.byte(b'>')?;
    if newline {
        out.byte(b'\n')?;
    }
    Ok(())
}
fn close(out: &mut Output, tag: &[u8], newline: bool) -> Result<()> {
    out.write(b"</")?;
    out.write(tag)?;
    out.byte(b'>')?;
    if newline {
        out.byte(b'\n')?;
    }
    Ok(())
}
fn text(out: &mut Output, value: &[u8], flags: u8, string: bool) -> Result<()> {
    if string && flags & CODE != 0 {
        return out.write(value);
    }
    if flags & RAW != 0 {
        return writer::raw_write(out, value);
    }
    writer::write(out, value, false)?;
    if !string {
        if flags & HARD_BREAK != 0 {
            out.write(b"<br>\n")?;
        } else if flags & SOFT_BREAK != 0 {
            out.byte(b'\n')?;
        }
    }
    Ok(())
}
/// `highlight` owns its returned lease until the full HTML is copied. `Some`
/// is a complete fenced-code rendering; no extra line break is appended.
/// The callback must allocate on the caller's same account. `None` selects
/// Goldmark's ordinary code rendering. Node traversal never recurses.
pub(super) fn render(
    arena: &mut Arena<'_>,
    root: Id,
    source: &[u8],
    limit: usize,
    mut highlight: impl FnMut(&[u8], &[u8]) -> Result<Option<BudgetedBytes>>,
) -> Result<BudgetedBytes> {
    let account = arena.account().clone();
    let mut out = Output::new(&account, limit);
    arena.walk(root, |arena, id, entering| {
        // Goldmark's default table renderer adds/updates style at render time.
        if entering {
            let alignment = match arena.get(id)?.kind {
                Kind::TableCell { alignment } => alignment,
                _ => Alignment::None,
            };
            let align: &[u8] = match alignment {
                Alignment::Left => b"left",
                Alignment::Right => b"right",
                Alignment::Center => b"center",
                Alignment::None => b"",
            };
            if !align.is_empty() {
                let mut style = Output::new(&account, limit);
                if let Some(previous) = arena.attribute(id, b"style")? {
                    style.write(previous)?;
                    style.byte(b';')?;
                }
                style.write(b"text-align:")?;
                style.write(align)?;
                arena.set_attribute(
                    id,
                    Bytes::Borrowed(b"style"),
                    Bytes::Owned(style.into_bytes()?),
                )?;
            }
        }
        let n = arena.get(id)?;
        match &n.kind {
            Kind::Document => {}
            Kind::ReferenceDefinition { .. } => return Ok(Walk::SkipChildren),
            Kind::TextBlock => {
                if !entering && n.next.is_some() && n.first.is_some() {
                    out.byte(b'\n')?;
                }
            }
            Kind::Paragraph => {
                if entering {
                    open(&mut out, n, b"p", b"", false)?;
                } else {
                    close(&mut out, b"p", true)?;
                }
            }
            Kind::Heading { level } => {
                if !(1..=6).contains(level) {
                    return Err(invalid());
                }
                if entering {
                    out.write(b"<h")?;
                    out.byte(b'0' + level)?;
                    attributes(&mut out, n, b"")?;
                    out.byte(b'>')?;
                } else {
                    out.write(b"</h")?;
                    out.byte(b'0' + level)?;
                    out.write(b">\n")?;
                }
            }
            Kind::ThematicBreak => {
                if entering {
                    out.write(b"<hr")?;
                    attributes(&mut out, n, b"align,color,noshade,size,width")?;
                    out.write(b">\n")?;
                }
            }
            Kind::Blockquote => {
                if entering {
                    open(&mut out, n, b"blockquote", b"cite", n.attributes.is_empty())?;
                } else {
                    close(&mut out, b"blockquote", true)?;
                }
            }
            Kind::CodeBlock | Kind::FencedCode { .. } => {
                if !entering {
                    return Ok(Walk::Continue);
                }
                let info = match &n.kind {
                    Kind::FencedCode { info: Some(s) } => Some(s.value(source, &account)?),
                    _ => None,
                };
                if matches!(n.kind, Kind::FencedCode { .. }) {
                    let code = n.lines.value(source)?;
                    if let Some(html) = highlight(info.as_deref().unwrap_or(b""), code.as_bytes())?
                    {
                        out.write(html.as_bytes())?;
                        return Ok(Walk::SkipChildren);
                    }
                }
                out.write(b"<pre><code")?;
                if let Some(info) = info {
                    let end = info.iter().position(|b| *b == b' ').unwrap_or(info.len());
                    out.write(b" class=\"language-")?;
                    writer::write(&mut out, &info[..end], false)?;
                    out.byte(b'"')?;
                }
                out.byte(b'>')?;
                for segment in n.lines.as_slice() {
                    let value = segment.value(source, &account)?;
                    writer::raw_write(&mut out, &value)?;
                }
                out.write(b"</code></pre>\n")?;
                return Ok(Walk::SkipChildren);
            }
            Kind::HtmlBlock { closure, .. } => {
                if entering {
                    for s in n.lines.as_slice() {
                        let value = s.value(source, &account)?;
                        writer::secure_write(&mut out, &value)?;
                    }
                } else if let Some(s) = closure {
                    let value = s.value(source, &account)?;
                    writer::secure_write(&mut out, &value)?;
                }
            }
            Kind::List { marker, start, .. } => {
                let ordered = matches!(marker, b'.' | b')');
                let tag: &[u8] = if ordered { b"ol" } else { b"ul" };
                if entering {
                    out.byte(b'<')?;
                    out.write(tag)?;
                    if ordered && *start != 1 {
                        out.write(b" start=\"")?;
                        number(&mut out, *start)?;
                        out.byte(b'"')?;
                    }
                    attributes(&mut out, n, b"start,reversed,type")?;
                    out.write(b">\n")?;
                } else {
                    close(&mut out, tag, true)?;
                }
            }
            Kind::ListItem { .. } => {
                if entering {
                    open(&mut out, n, b"li", b"value", false)?;
                    if let Some(first) = n.first {
                        if !matches!(arena.get(first)?.kind, Kind::TextBlock) {
                            out.byte(b'\n')?;
                        }
                    }
                } else {
                    close(&mut out, b"li", true)?;
                }
            }
            Kind::Text { segment, flags } => {
                if entering {
                    let value = segment.value(source, &account)?;
                    text(&mut out, &value, *flags, false)?;
                }
            }
            Kind::String { value, flags } => {
                if entering {
                    text(&mut out, value, *flags, true)?;
                }
            }
            Kind::LinkLabel { segment, .. } | Kind::Delimiter { segment, .. } => {
                if entering {
                    let value = segment.value(source, &account)?;
                    writer::write(&mut out, &value, false)?;
                }
            }
            Kind::CodeSpan => {
                if entering {
                    open(&mut out, n, b"code", b"", false)?;
                    let mut child = n.first;
                    while let Some(id) = child {
                        account.charge_work(1)?;
                        let node = arena.get(id)?;
                        let Kind::Text { segment, .. } = node.kind else {
                            return Err(invalid());
                        };
                        let value = segment.value(source, &account)?;
                        if value.last() == Some(&b'\n') {
                            writer::raw_write(&mut out, &value[..value.len() - 1])?;
                            out.byte(b' ')?;
                        } else {
                            writer::raw_write(&mut out, &value)?;
                        }
                        child = node.next;
                    }
                    return Ok(Walk::SkipChildren);
                } else {
                    close(&mut out, b"code", false)?;
                }
            }
            Kind::Emphasis { level } => {
                let tag: &[u8] = if *level == 2 { b"strong" } else { b"em" };
                if entering {
                    open(&mut out, n, tag, b"", false)?;
                } else {
                    close(&mut out, tag, false)?;
                }
            }
            Kind::Strikethrough => {
                if entering {
                    open(&mut out, n, b"del", b"", false)?;
                } else {
                    close(&mut out, b"del", false)?;
                }
            }
            Kind::Link {
                destination, title, ..
            } => {
                if entering {
                    out.write(b"<a href=\"")?;
                    url_write(&mut out, destination, true, &account, limit)?;
                    out.byte(b'"')?;
                    if let Some(title) = title {
                        out.write(b" title=\"")?;
                        writer::write(&mut out, title, false)?;
                        out.byte(b'"')?;
                    }
                    attributes(&mut out, n, LINK)?;
                    out.byte(b'>')?;
                } else {
                    close(&mut out, b"a", false)?;
                }
            }
            Kind::Image {
                destination, title, ..
            } => {
                if entering {
                    out.write(b"<img src=\"")?;
                    url_write(&mut out, destination, true, &account, limit)?;
                    out.write(b"\" alt=\"")?;
                    // Render only text descendants, using parent/sibling links rather
                    // than recursive renderTexts or an unaccounted auxiliary stack.
                    let mut current = n.first;
                    while let Some(cid) = current {
                        account.charge_work(1)?;
                        let c = arena.get(cid)?;
                        match &c.kind {
                            Kind::String { value, flags } => text(&mut out, value, *flags, true)?,
                            Kind::Text { segment, flags } => {
                                let value = segment.value(source, &account)?;
                                text(&mut out, &value, *flags, false)?;
                            }
                            _ => {
                                if c.first.is_some() {
                                    current = c.first;
                                    continue;
                                }
                            }
                        }
                        let mut cursor = cid;
                        loop {
                            let c = arena.get(cursor)?;
                            if c.next.is_some() {
                                current = c.next;
                                break;
                            }
                            let p = c.parent.ok_or_else(invalid)?;
                            if p == id {
                                current = None;
                                break;
                            }
                            cursor = p;
                            account.charge_work(1)?;
                        }
                    }
                    out.byte(b'"')?;
                    if let Some(title) = title {
                        out.write(b" title=\"")?;
                        writer::write(&mut out, title, false)?;
                        out.byte(b'"')?;
                    }
                    attributes(&mut out, n, IMAGE)?;
                    out.byte(b'>')?;
                    return Ok(Walk::SkipChildren);
                }
            }
            Kind::AutoLink {
                email,
                protocol,
                value,
            } => {
                if entering {
                    let label = value.value(source, &account)?;
                    out.write(b"<a href=\"")?;
                    // Email links with explicit Protocol are not produced by the
                    // parser; preserve URL's prefix contract for hand-built ASTs.
                    let mailto = match protocol {
                        None => label
                            .get(..7)
                            .is_some_and(|v| v.eq_ignore_ascii_case(b"mailto:")),
                        Some(p) => {
                            p.eq_ignore_ascii_case(b"mailto")
                                || p.get(..7)
                                    .is_some_and(|v| v.eq_ignore_ascii_case(b"mailto:"))
                        }
                    };
                    if *email && !mailto {
                        out.write(b"mailto:")?;
                    }
                    if let Some(protocol) = protocol {
                        url_write(&mut out, protocol, false, &account, limit)?;
                        out.write(b"://")?;
                    }
                    url_write(&mut out, &label, false, &account, limit)?;
                    out.byte(b'"')?;
                    attributes(&mut out, n, LINK)?;
                    out.byte(b'>')?;
                    writer::raw_write(&mut out, &label)?;
                    out.write(b"</a>")?;
                }
            }
            Kind::RawHtml => {
                if entering {
                    for s in n.lines.as_slice() {
                        let value = s.value(source, &account)?;
                        out.write(&value)?;
                    }
                    return Ok(Walk::SkipChildren);
                }
            }
            Kind::TaskCheckBox { checked } => {
                if entering {
                    out.write(if *checked {
                        b"<input checked=\"\" disabled=\"\" type=\"checkbox\"> "
                    } else {
                        b"<input disabled=\"\" type=\"checkbox\"> "
                    })?;
                }
            }
            Kind::Table { .. } => {
                if entering {
                    open(&mut out, n, b"table", TABLE, true)?;
                } else {
                    close(&mut out, b"table", true)?;
                }
            }
            Kind::TableHeader => {
                if entering {
                    open(&mut out, n, b"thead", ROW, true)?;
                    out.write(b"<tr>\n")?;
                } else {
                    out.write(b"</tr>\n</thead>\n")?;
                    if n.next.is_some() {
                        out.write(b"<tbody>\n")?;
                    }
                }
            }
            Kind::TableRow => {
                if entering {
                    open(&mut out, n, b"tr", ROW, true)?;
                } else {
                    close(&mut out, b"tr", true)?;
                    if n.next.is_none() {
                        out.write(b"</tbody>\n")?;
                    }
                }
            }
            Kind::TableCell { .. } => {
                let header = n
                    .parent
                    .map(|p| arena.get(p).map(|p| matches!(p.kind, Kind::TableHeader)))
                    .transpose()?
                    .unwrap_or(false);
                let tag: &[u8] = if header { b"th" } else { b"td" };
                if entering {
                    open(&mut out, n, tag, CELL, false)?;
                } else {
                    close(&mut out, tag, true)?;
                }
            }
            Kind::Footnote { index, .. } => {
                if entering {
                    out.write(b"<li id=\"fn:")?;
                    number(&mut out, index.ok_or_else(invalid)?)?;
                    out.byte(b'"')?;
                    attributes(&mut out, n, b"value")?;
                    out.write(b">\n")?;
                } else {
                    out.write(b"</li>\n")?;
                }
            }
            Kind::FootnoteList { .. } => {
                if entering {
                    out.write(b"<div class=\"footnotes\" role=\"doc-endnotes\"")?;
                    attributes(&mut out, n, b"")?;
                    out.write(b">\n<hr>\n<ol>\n")?;
                } else {
                    out.write(b"</ol>\n</div>\n")?;
                }
            }
            Kind::FootnoteLink {
                index, ref_index, ..
            } => {
                if entering {
                    out.write(b"<sup id=\"fnref")?;
                    if *ref_index > 0 {
                        number(&mut out, *ref_index)?;
                    }
                    out.byte(b':')?;
                    number(&mut out, *index)?;
                    out.write(b"\"><a href=\"#fn:")?;
                    number(&mut out, *index)?;
                    out.write(b"\" class=\"footnote-ref\" role=\"doc-noteref\">")?;
                    number(&mut out, *index)?;
                    out.write(b"</a></sup>")?;
                }
            }
            Kind::FootnoteBacklink {
                index, ref_index, ..
            } => {
                if entering {
                    out.write(b"&#160;<a href=\"#fnref")?;
                    if *ref_index > 0 {
                        number(&mut out, *ref_index)?;
                    }
                    out.byte(b':')?;
                    number(&mut out, *index)?;
                    out.write(
                        b"\" class=\"footnote-backref\" role=\"doc-backlink\">&#x21a9;&#xfe0e;</a>",
                    )?;
                }
            }
        }
        Ok(Walk::Continue)
    })?;
    out.into_bytes()
}

fn url_write(
    out: &mut Output,
    input: &[u8],
    resolve: bool,
    account: &BudgetAccount,
    limit: usize,
) -> Result<()> {
    if !resolve {
        return url_encode(out, input);
    }
    // Preserve Go's three separate passes: numeric references may produce an
    // ampersand that the subsequent named-entity pass must then recognize.
    let mut unescaped = Output::new(account, limit);
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\\' && input.get(i + 1).is_some_and(u8::is_ascii_punctuation) {
            i += 1;
        }
        unescaped.byte(input[i])?;
        i += 1;
    }
    let unescaped = unescaped.into_bytes()?;
    let numeric = resolve_numeric(unescaped.as_bytes(), account, limit)?;
    drop(unescaped);
    let mut entities = Output::new(account, limit);
    let input = numeric.as_bytes();
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'&' {
            let start = i + 1;
            let mut end = start;
            while end < input.len() && input[end].is_ascii_alphanumeric() {
                account.charge_work(1)?;
                end += 1;
            }
            if end > start && input.get(end) == Some(&b';') {
                if let Some(value) = super::entities::lookup(&input[start..end]) {
                    entities.write(value)?;
                    i = end + 1;
                    continue;
                }
            }
        }
        entities.byte(input[i])?;
        i += 1;
    }
    let entities = entities.into_bytes()?;
    drop(numeric);
    url_encode(out, entities.as_bytes())
}
fn resolve_numeric(input: &[u8], account: &BudgetAccount, limit: usize) -> Result<BudgetedBytes> {
    let mut out = Output::new(account, limit);
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'&' && input.get(i + 1) == Some(&b'#') {
            let mut start = i + 2;
            let hex = input.get(start).is_some_and(|b| matches!(b, b'x' | b'X'));
            if hex {
                start += 1;
            }
            let mut end = start;
            while end < input.len()
                && if hex {
                    input[end].is_ascii_hexdigit()
                } else {
                    input[end].is_ascii_digit()
                }
            {
                account.charge_work(1)?;
                end += 1;
            }
            if end > start && input.get(end) == Some(&b';') && (hex || end - start < 8) {
                let base = if hex {
                    16
                } else if input[start] == b'0' {
                    8
                } else {
                    10
                };
                let mut value = 0u32;
                let mut invalid_digit = false;
                for b in &input[start..end] {
                    let digit = match b {
                        b'0'..=b'9' => (b - b'0') as u32,
                        b'a'..=b'f' => (b - b'a' + 10) as u32,
                        b'A'..=b'F' => (b - b'A' + 10) as u32,
                        _ => unreachable!(),
                    };
                    if digit >= base {
                        invalid_digit = true;
                        break;
                    }
                    value = value.saturating_mul(base).saturating_add(digit);
                }
                if invalid_digit {
                    value = 0;
                }
                let ch = char::from_u32(value)
                    .filter(|c| *c != '\0')
                    .unwrap_or('\u{fffd}');
                let mut buf = [0; 4];
                out.write(ch.encode_utf8(&mut buf).as_bytes())?;
                i = end + 1;
                continue;
            }
        }
        out.byte(input[i])?;
        i += 1;
    }
    out.into_bytes()
}
fn url_encode(out: &mut Output, input: &[u8]) -> Result<()> {
    let mut i = 0;
    const HEX: &[u8] = b"0123456789ABCDEF";
    while i < input.len() {
        let b = input[i];
        if b.is_ascii_alphanumeric() || b"!#$&'()*+,-./:;=?@_~".contains(&b) {
            writer::raw_write(out, &input[i..i + 1])?;
            i += 1;
            continue;
        }
        if b == b'%'
            && input.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && input.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            out.write(&input[i..i + 3])?;
            i += 3;
            continue;
        }
        let (ch, width) = gotmpl::decode_go_rune(&input[i..]).ok_or_else(invalid)?;
        if ch == '\u{fffd}' && width == 1 {
            out.byte(b)?;
            i += 1;
            continue;
        }
        for b in &input[i..i + width] {
            out.write(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]])?;
        }
        i += width;
    }
    Ok(())
}
