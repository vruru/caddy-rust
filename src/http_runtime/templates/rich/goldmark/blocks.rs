//! Goldmark 1.8.6 fixed block parsers (MIT, see html_render.rs).
use super::{
    ast::Kind,
    parse_util::*,
    parser::{Block, BlockKind as B, Fence, Parser},
    reader::Reader,
    segment::{Bytes, Segment, is_space},
};
use gotmpl::Result;
impl<'a> Parser<'a> {
    pub(super) fn open_block(
        &mut self,
        b: B,
        parent: usize,
        r: &mut Reader<'a>,
    ) -> Result<Option<(usize, bool, bool)>> {
        let Some((line, s)) = r.peek_line()? else {
            return Ok(None);
        };
        let offset = r.line_offset()?;
        let pos = self.offset.max(0) as usize;
        let mut children = false;
        let require = false;
        let kind = match b {
            B::Atx => {
                if line.get(pos) != Some(&b'#') {
                    return Ok(None);
                }
                let mut end = pos;
                while line.get(end) == Some(&b'#') {
                    end += 1;
                }
                let level = end - pos;
                if level == 0 || level > 6 {
                    return Ok(None);
                }
                if end < line.len() && !is_space(line[end]) {
                    return Ok(None);
                }
                let n = self.arena.add(Kind::Heading { level: level as u8 })?;
                let start = (end + line[end..].iter().take_while(|b| is_space(**b)).count())
                    .min(line.len().saturating_sub(1));
                let mut content = Segment::new(s.start + start - s.padding, s.stop)
                    .trim_right_space(self.source)?;
                let value = content.value(self.source, &self.account)?;
                let mut stop = value.len();
                if stop > 0 {
                    let mut i = stop - 1;
                    while i > 0 && value[i] == b'#' {
                        i -= 1;
                    }
                    if i == 0 && value[0] == b'#' {
                        stop = 0;
                    } else if i != stop - 1 && is_space(value[i]) {
                        stop = i;
                        while stop > 0 && is_space(value[stop - 1]) {
                            stop -= 1;
                        }
                    }
                }
                drop(value);
                content.stop = content.start + stop;
                if stop > 0 {
                    self.arena.get_mut(n)?.lines.append(content)?;
                }
                r.advance_to_eol()?;
                return Ok(Some((n, false, false)));
            }
            B::Setext => {
                let Some(last) = self.last() else {
                    return Ok(None);
                };
                if !self.paragraph(Some(last)) || self.arena.get(last)?.parent != Some(parent) {
                    return Ok(None);
                }
                let Some(c) = setext(&line) else {
                    return Ok(None);
                };
                self.temporary = Some(last);
                let n = self.arena.add(Kind::Heading {
                    level: if c == b'-' { 2 } else { 1 },
                })?;
                self.arena.get_mut(n)?.lines.append(s)?;
                return Ok(Some((n, false, true)));
            }
            B::Thematic => {
                if !thematic(&line, offset) {
                    return Ok(None);
                }
                r.advance_to_eol()?;
                Kind::ThematicBreak
            }
            B::Quote => {
                drop(line);
                if !self.quote(r)? {
                    return Ok(None);
                }
                children = true;
                Kind::Blockquote
            }
            B::Fence => {
                let Some(ch) = line.get(pos).copied() else {
                    return Ok(None);
                };
                if !matches!(ch, b'`' | b'~') {
                    return Ok(None);
                }
                let length = line[pos..].iter().take_while(|b| **b == ch).count();
                if length < 3 {
                    return Ok(None);
                }
                let rest = &line[pos + length..];
                let value = trim(rest);
                if ch == b'`' && value.contains(&b'`') {
                    return Ok(None);
                }
                let info = if value.is_empty() {
                    None
                } else {
                    let leading = rest
                        .iter()
                        .take_while(|b| super::segment::is_space(**b))
                        .count();
                    Some(Segment::new(
                        s.start - s.padding + pos + length + leading,
                        s.stop
                            - (rest
                                .iter()
                                .rev()
                                .take_while(|b| super::segment::is_space(**b))
                                .count()),
                    ))
                };
                let n = self.arena.add(Kind::FencedCode { info })?;
                self.fence = Some(Fence {
                    ch,
                    indent: pos as isize,
                    length,
                    node: n,
                });
                return Ok(Some((n, false, false)));
            }
            B::Code => {
                let Some((n, padding)) = indent_position(&line, offset, 0, 4) else {
                    return Ok(None);
                };
                if blank(&line) {
                    return Ok(None);
                }
                drop(line);
                r.advance_and_set_padding(n, padding)?;
                let Some((_, mut s)) = r.peek_line()? else {
                    return Err(invalid());
                };
                if s.padding > 0 {
                    self.preserve_tab(&mut s, r, 0)?;
                }
                s.force_newline = true;
                let id = self.arena.add(Kind::CodeBlock)?;
                self.arena.get_mut(id)?.lines.append(s)?;
                r.advance_to_eol()?;
                return Ok(Some((id, false, false)));
            }
            B::Paragraph => {
                if blank(&line) {
                    return Ok(None);
                }
                let id = self.arena.add(Kind::Paragraph)?;
                self.arena.get_mut(id)?.lines.append(s)?;
                r.advance_to_eol()?;
                return Ok(Some((id, false, false)));
            }
            B::List => return self.open_list(parent, r),
            B::Item => return self.open_item(parent, r),
            B::Html => {
                let Some(kind) = super::html_parser::block_open(&line, self.paragraph(self.last()))
                else {
                    return Ok(None);
                };
                let id = self.arena.add(Kind::HtmlBlock {
                    kind,
                    closure: None,
                })?;
                self.arena.get_mut(id)?.lines.append(s)?;
                r.advance_to_eol()?;
                return Ok(Some((id, false, false)));
            }
            B::Footnote => {
                if line.get(pos..pos + 2) != Some(b"[^") {
                    return Ok(None);
                }
                let open = pos + 2;
                let Some(close) = closure(&line[open..], b'[', b']').map(|n| open + n) else {
                    return Ok(None);
                };
                if line.get(close + 1) != Some(&b':') {
                    return Ok(None);
                }
                let label = Segment::new(s.start + open - s.padding, s.start + close - s.padding)
                    .value(self.source, &self.account)?;
                if blank(&label) {
                    return Ok(None);
                }
                let n = close + 2 - s.padding;
                children = n < line.len();
                r.advance_and_set_padding(n, s.padding)?;
                Kind::Footnote {
                    reference: label,
                    index: None,
                }
            }
        };
        let id = self.arena.add(kind)?;
        Ok(Some((id, children, require)))
    }
    pub(super) fn continue_block(&mut self, b: Block, r: &mut Reader<'a>) -> Result<(bool, bool)> {
        let Some((line, s)) = r.peek_line()? else {
            return Ok((false, false));
        };
        let offset = r.line_offset()?;
        match b.parser {
            B::Atx | B::Setext | B::Thematic => Ok((false, false)),
            B::Quote => {
                drop(line);
                Ok((self.quote(r)?, true))
            }
            B::Paragraph => {
                if blank(&line) {
                    return Ok((false, false));
                }
                self.arena.get_mut(b.node)?.lines.append(s)?;
                r.advance_to_eol()?;
                Ok((true, false))
            }
            B::Code => {
                if blank(&line) {
                    self.arena
                        .get_mut(b.node)?
                        .lines
                        .append(s.trim_left_space_width(4, self.source)?)?;
                    return Ok((true, false));
                }
                let Some((n, padding)) = indent_position(&line, offset, 0, 4) else {
                    return Ok((false, false));
                };
                drop(line);
                r.advance_and_set_padding(n, padding)?;
                let Some((_, mut s)) = r.peek_line()? else {
                    return Err(invalid());
                };
                if s.padding > 0 {
                    self.preserve_tab(&mut s, r, 0)?;
                }
                s.force_newline = true;
                self.arena.get_mut(b.node)?.lines.append(s)?;
                r.advance_to_eol()?;
                Ok((true, false))
            }
            B::Fence => {
                let f = self.fence.ok_or_else(invalid)?;
                let (w, pos) = indent_width(&line, offset);
                if w < 4 {
                    let len = line[pos..].iter().take_while(|b| **b == f.ch).count();
                    if len >= f.length && blank(&line[pos + len..]) {
                        r.advance_to_eol()?;
                        return Ok((false, false));
                    }
                }
                let (n, padding) = indent_position(&line, offset, s.padding, f.indent)
                    .unwrap_or_else(|| {
                        (
                            line.iter()
                                .position(|b| !matches!(b, b' ' | b'\t'))
                                .unwrap_or(0)
                                .saturating_sub(s.padding),
                            0,
                        )
                    });
                let mut segment = Segment::new_padding(s.start + n, s.stop, padding);
                drop(line);
                if padding > 0 {
                    self.preserve_tab(&mut segment, r, f.indent)?;
                }
                segment.force_newline = true;
                self.arena.get_mut(b.node)?.lines.append(segment)?;
                r.advance_to_eol()?;
                Ok((true, false))
            }
            B::List => self.continue_list(b.node, r),
            B::Item => self.continue_item(b.node, r),
            B::Footnote => {
                if blank(&line) {
                    return Ok((true, true));
                }
                let Some((n, padding)) = indent_position(&line, offset, 0, 4) else {
                    return Ok((false, false));
                };
                r.advance_and_set_padding(n, padding)?;
                Ok((true, true))
            }
            B::Html => {
                let kind = match self.arena.get(b.node)?.kind {
                    Kind::HtmlBlock { kind, .. } => kind,
                    _ => return Err(invalid()),
                };
                let count = self.arena.get(b.node)?.lines.len();
                let first = if count == 1 {
                    Some(
                        self.arena
                            .get(b.node)?
                            .lines
                            .at(0)?
                            .value(self.source, &self.account)?,
                    )
                } else {
                    None
                };
                if first
                    .as_ref()
                    .is_some_and(|v| super::html_parser::block_closes(kind, v))
                {
                    return Ok((false, false));
                }
                if kind >= 6 && blank(&line) {
                    return Ok((false, false));
                }
                if kind <= 5 && super::html_parser::block_closes(kind, &line) {
                    if let Kind::HtmlBlock { closure, .. } = &mut self.arena.get_mut(b.node)?.kind {
                        *closure = Some(s);
                    }
                    r.advance_to_eol()?;
                    return Ok((false, false));
                }
                self.arena.get_mut(b.node)?.lines.append(s)?;
                r.advance_to_eol()?;
                Ok((true, false))
            }
        }
    }
    pub(super) fn close_block(&mut self, b: Block, r: &mut Reader<'a>) -> Result<()> {
        match b.parser {
            B::Atx | B::Setext => {
                if b.parser == B::Setext {
                    let original = self.temporary.take().ok_or_else(invalid)?;
                    let underline = self.arena.get(b.node)?.lines.at(0)?;
                    self.arena.get_mut(b.node)?.lines.clear()?;
                    if self.arena.get(original)?.lines.len() == 0 {
                        let parent = self.arena.get(b.node)?.parent.ok_or_else(invalid)?;
                        let segment = underline.trim_left_space(self.source)?;
                        let next = self.arena.get(b.node)?.next;
                        if let Some(next) = next.filter(|id| self.paragraph(Some(*id))) {
                            self.arena.get_mut(next)?.lines.unshift(segment)?;
                        } else {
                            let p = self.arena.add(Kind::Paragraph)?;
                            self.arena.get_mut(p)?.lines.append(segment)?;
                            self.arena.insert_after(parent, b.node, p)?;
                        }
                        self.arena.detach(b.node)?;
                    } else {
                        let mut lines = super::segment::Segments::new(&self.account);
                        std::mem::swap(&mut lines, &mut self.arena.get_mut(original)?.lines);
                        self.arena.get_mut(b.node)?.pos = Some(lines.at(0)?.start);
                        self.arena.get_mut(b.node)?.lines = lines;
                        self.arena.get_mut(b.node)?.blank_previous =
                            self.arena.get(original)?.blank_previous;
                        self.arena.detach(original)?;
                    }
                }
                let n = self.arena.get(b.node)?.lines.len();
                let value = if n == 0 {
                    Bytes::Borrowed(b"")
                } else {
                    self.arena
                        .get(b.node)?
                        .lines
                        .at(n - 1)?
                        .value(self.source, &self.account)?
                };
                let id = self.ids.generate(&value, true)?;
                self.arena
                    .set_attribute(b.node, Bytes::Borrowed(b"id"), Bytes::Owned(id))?;
            }
            B::Paragraph => {
                let len = self.arena.get(b.node)?.lines.len();
                if len == 0 {
                    self.arena.detach(b.node)?;
                } else {
                    for i in 0..len {
                        let s = self
                            .arena
                            .get(b.node)?
                            .lines
                            .at(i)?
                            .trim_left_space(self.source)?;
                        self.arena.get_mut(b.node)?.lines.set(i, s)?;
                    }
                    let s = self
                        .arena
                        .get(b.node)?
                        .lines
                        .at(len - 1)?
                        .trim_right_space(self.source)?;
                    self.arena.get_mut(b.node)?.lines.set(len - 1, s)?;
                }
            }
            B::Code => {
                let mut len = self.arena.get(b.node)?.lines.len();
                while len > 0 {
                    let value = self
                        .arena
                        .get(b.node)?
                        .lines
                        .at(len - 1)?
                        .value(self.source, &self.account)?;
                    if !blank(&value) {
                        break;
                    }
                    len -= 1;
                }
                self.arena.get_mut(b.node)?.lines.set_sliced(0, len)?;
            }
            B::Fence => {
                if self.fence.is_some_and(|f| f.node == b.node) {
                    self.fence = None;
                }
            }
            B::List => self.close_list(b.node)?,
            B::Footnote => {
                let list = if let Some(list) = self.footnotes {
                    list
                } else {
                    let list = self.arena.add(Kind::FootnoteList { count: 0 })?;
                    let parent = self.arena.get(b.node)?.parent.ok_or_else(invalid)?;
                    self.arena.insert_before(parent, Some(b.node), list)?;
                    self.footnotes = Some(list);
                    list
                };
                self.arena.append(list, b.node)?;
            }
            _ => {}
        }
        let _ = r;
        Ok(())
    }
    fn quote(&mut self, r: &mut Reader<'a>) -> Result<bool> {
        let Some((line, _)) = r.peek_line()? else {
            return Ok(false);
        };
        let (w, pos) = indent_width(&line, r.line_offset()?);
        if w > 3 || line.get(pos) != Some(&b'>') {
            return Ok(false);
        }
        let pos = pos + 1;
        r.advance(pos)?;
        if line.get(pos).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            let padding = if line[pos] == b'\t' {
                (tab(r.line_offset()?) - 1) as usize
            } else {
                0
            };
            r.advance_and_set_padding(1, padding)?;
        }
        Ok(true)
    }
    fn preserve_tab(&mut self, s: &mut Segment, r: &mut Reader<'a>, indent: isize) -> Result<()> {
        let offset = r.line_offset()? + indent;
        let (line, pos) = r.position();
        if let Some(start) = pos.start.checked_sub(1) {
            r.set_position(line, Segment::new(start, pos.stop));
            if offset == r.line_offset()? {
                s.padding = 0;
                s.start = s.start.checked_sub(1).ok_or_else(invalid)?;
            }
            r.set_position(line, pos);
        }
        Ok(())
    }
}
