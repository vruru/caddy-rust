//! Goldmark inline state machine over the segmented byte reader (MIT).
use super::{
    ast::{HARD_BREAK, Id, Kind, LinkReference, RAW, ReferenceType, SOFT_BREAK, Walk, room},
    block_reader::BlockReader,
    parse_util::*,
    parser::Parser,
    segment::{Bytes, Segment},
};
use gotmpl::Result;
#[derive(Clone, Copy)]
struct Label {
    node: Id,
    segment: Segment,
    image: bool,
    bottom: Option<Id>,
}
impl<'a> Parser<'a> {
    pub(super) fn inlines(&mut self, parent: Id) -> Result<()> {
        if matches!(
            self.arena.get(parent)?.kind,
            Kind::CodeBlock
                | Kind::FencedCode { .. }
                | Kind::HtmlBlock { .. }
                | Kind::ReferenceDefinition { .. }
                | Kind::RawHtml
        ) {
            return Ok(());
        }
        let mut lines = super::segment::Segments::new(&self.account);
        lines.append_all(self.arena.get(parent)?.lines.as_slice())?;
        let mut reader = BlockReader::new(self.source, lines.as_slice(), &self.account)?;
        let mut escaped = false;
        let mut labels = Vec::new();
        let result = (|| {
            'retry: loop {
                let Some((line, _)) = reader.peek_line()? else {
                    break;
                };
                self.account.charge_work(1)?;
                let mut length = line.len();
                let mut flags = 0u8;
                let newline = line.last() == Some(&b'\n');
                let mut visible = false;
                if newline
                    && ((length >= 3 && line[length - 2] == b'\\' && line[length - 3] != b'\\')
                        || (length == 2 && line[0] == b'\\'))
                {
                    length -= 2;
                    flags = HARD_BREAK;
                    visible = true;
                } else if newline
                    && ((length >= 4
                        && line[length - 3] == b'\\'
                        && line[length - 2] == b'\r'
                        && line[length - 4] != b'\\')
                        || (length == 3 && line[0] == b'\\' && line[1] == b'\r'))
                {
                    length -= 3;
                    flags = HARD_BREAK;
                    visible = true;
                } else if newline && length >= 3 && line[length - 3..length - 1] == *b"  " {
                    length -= 3;
                    flags = HARD_BREAK;
                } else if newline && length >= 4 && line[length - 4..length - 1] == *b"  \r" {
                    length -= 4;
                    flags = HARD_BREAK;
                } else if newline {
                    flags = SOFT_BREAK;
                }
                let (line_num, start) = reader.position();
                let mut start = start.ok_or_else(invalid)?;
                let mut n = 0;
                for i in 0..length {
                    self.account.charge_work(1)?;
                    let c = line[i];
                    if c == b'\n' {
                        break;
                    }
                    let space = matches!(c, b' ' | b'\t');
                    let punct = c.is_ascii_punctuation();
                    if punct && !escaped || space || i == 0 {
                        let parser_char = if space || i == 0 && !punct { b' ' } else { c };
                        if matches!(
                            parser_char,
                            b' ' | b'`' | b'!' | b'[' | b']' | b'<' | b'*' | b'_' | b'~' | b'('
                        ) {
                            reader.advance(n)?;
                            n = 0;
                            let saved = reader.position();
                            if i != 0 {
                                let current = reader.position().1.ok_or_else(invalid)?;
                                self.append_inline_text(parent, start.between(current)?, &labels)?;
                                start = current;
                            }
                            let mut found = None;
                            // Task checkbox has extension priority 0, code spans 100, footnotes
                            // 101, links 200, autolinks 300, raw HTML 400, emphasis/strike 500.
                            if c == b'[' {
                                found = self.checkbox(parent, &mut reader)?;
                                if found.is_none() {
                                    reader.set_position(saved.0, saved.1)?;
                                }
                            }
                            if found.is_none() && c == b'`' {
                                found = self.code_span(&mut reader)?;
                            }
                            if found.is_none() && matches!(c, b'!' | b'[') {
                                found = self.footnote_inline(parent, &mut reader)?;
                                if found.is_none() {
                                    reader.set_position(saved.0, saved.1)?;
                                }
                            }
                            if found.is_none() && matches!(c, b'!' | b'[' | b']') {
                                found = self.link(parent, &mut reader, &mut labels)?;
                                if found.is_none() {
                                    reader.set_position(saved.0, saved.1)?;
                                }
                            }
                            if found.is_none() && c == b'<' {
                                found = self.angle_autolink(&mut reader)?;
                                if found.is_none() {
                                    reader.set_position(saved.0, saved.1)?;
                                    found = self.raw_html(&mut reader)?;
                                }
                                if found.is_none() {
                                    reader.set_position(saved.0, saved.1)?;
                                }
                            }
                            if found.is_none() && matches!(c, b'*' | b'_' | b'~') {
                                let Some((value, s)) = reader.peek_line()? else {
                                    return Err(invalid());
                                };
                                let before = reader.preceding_character()?;
                                found = self.scan_delimiter(&value, s, before)?;
                                if let Some(id) = found {
                                    let len = match self.arena.get(id)?.kind {
                                        Kind::Delimiter { length, .. } => length,
                                        _ => return Err(invalid()),
                                    };
                                    drop(value);
                                    reader.advance(len)?;
                                }
                            }
                            if found.is_none()
                                && matches!(parser_char, b' ' | b'*' | b'_' | b'~' | b'(')
                                && labels.is_empty()
                            {
                                reader.set_position(saved.0, saved.1)?;
                                found = self.linkify(parent, &mut reader)?;
                            }
                            if let Some(id) = found {
                                self.arena.append(parent, id)?;
                                continue 'retry;
                            }
                            reader.set_position(saved.0, saved.1)?;
                        }
                    }
                    if escaped {
                        escaped = false;
                        n += 1;
                        continue;
                    }
                    escaped = c == b'\\';
                    n += 1;
                }
                if n != 0 {
                    reader.advance(n)?;
                }
                let (current_line, current) = reader.position();
                if current_line != line_num {
                    continue;
                }
                let mut diff = start.between(current.ok_or_else(invalid)?)?;
                if !visible {
                    diff = diff.trim_right_space(self.source)?;
                }
                let id = self.arena.add(Kind::Text {
                    segment: diff,
                    flags,
                })?;
                self.arena.append(parent, id)?;
                reader.advance_line()?;
            }
            self.process_delimiters(None)?;
            for label in &labels {
                self.arena.get_mut(label.node)?.kind = Kind::Text {
                    segment: label.segment,
                    flags: 0,
                };
            }
            Ok(())
        })();
        let bytes = labels.capacity() * std::mem::size_of::<Label>();
        drop(labels);
        let release = self.account.release(bytes);
        result?;
        release
    }
    fn append_inline_text(
        &mut self,
        parent: Id,
        segment: Segment,
        _labels: &[Label],
    ) -> Result<()> {
        // Pending link labels have their own explicit Kind, so the Arena's
        // Text-only coalescing cannot consume them. No label-stack scan is
        // needed for every ordinary text flush on deeply nested brackets.
        self.arena.append_text_segment(parent, segment)?;
        Ok(())
    }
    fn checkbox(&mut self, parent: Id, r: &mut BlockReader<'a, '_>) -> Result<Option<Id>> {
        let n = self.arena.get(parent)?;
        if n.first.is_some() {
            return Ok(None);
        }
        let Some(item) = n.parent else {
            return Ok(None);
        };
        let p = self.arena.get(item)?;
        if p.first != Some(parent) || !matches!(p.kind, Kind::ListItem { .. }) {
            return Ok(None);
        }
        let Some((line, _)) = r.peek_line()? else {
            return Ok(None);
        };
        if line.get(2) != Some(&b']')
            || !line
                .get(1)
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'x' | b'X'))
        {
            return Ok(None);
        }
        let checked = matches!(line[1], b'x' | b'X');
        let mut end = 3;
        while line
            .get(end)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c'))
        {
            end += 1;
        }
        drop(line);
        r.advance(end)?;
        Ok(Some(self.arena.add(Kind::TaskCheckBox { checked })?))
    }
    fn code_span(&mut self, r: &mut BlockReader<'a, '_>) -> Result<Option<Id>> {
        let Some((line, start)) = r.peek_line()? else {
            return Ok(None);
        };
        let opener = line.iter().take_while(|b| **b == b'`').count();
        drop(line);
        r.advance(opener)?;
        let saved = r.position();
        let code = self.arena.add(Kind::CodeSpan)?;
        loop {
            let Some((line, s)) = r.peek_line()? else {
                r.set_position(saved.0, saved.1)?;
                return Ok(Some(self.arena.add(Kind::Text {
                    segment: start.with_stop(start.start + opener),
                    flags: 0,
                })?));
            };
            let mut i = 0;
            while i < line.len() {
                if line[i] == b'`' {
                    let begin = i;
                    while line.get(i) == Some(&b'`') {
                        i += 1;
                    }
                    if i - begin == opener {
                        let segment = s.with_stop(s.start + begin);
                        if !segment.is_empty() {
                            let child = self.arena.add(Kind::Text {
                                segment,
                                flags: RAW,
                            })?;
                            self.arena.append(code, child)?;
                        }
                        drop(line);
                        r.advance(i)?;
                        let mut all_blank = true;
                        let mut child = self.arena.get(code)?.first;
                        while let Some(id) = child {
                            let n = self.arena.get(id)?;
                            if let Kind::Text { segment, .. } = n.kind {
                                let value = segment.value(self.source, &self.account)?;
                                if !blank(&value) {
                                    all_blank = false;
                                }
                            }
                            child = n.next;
                        }
                        if !all_blank {
                            if let (Some(first), Some(last)) =
                                (self.arena.get(code)?.first, self.arena.get(code)?.last)
                            {
                                let a = match self.arena.get(first)?.kind {
                                    Kind::Text { segment, .. } => segment,
                                    _ => return Err(invalid()),
                                };
                                let b = match self.arena.get(last)?.kind {
                                    Kind::Text { segment, .. } => segment,
                                    _ => return Err(invalid()),
                                };
                                if !a.is_empty()
                                    && !b.is_empty()
                                    && self
                                        .source
                                        .get(a.start)
                                        .is_some_and(|b| matches!(b, b' ' | b'\n'))
                                    && self
                                        .source
                                        .get(b.stop - 1)
                                        .is_some_and(|b| matches!(b, b' ' | b'\n'))
                                {
                                    if let Kind::Text { segment, .. } =
                                        &mut self.arena.get_mut(first)?.kind
                                    {
                                        *segment = segment.with_start(segment.start + 1);
                                    }
                                    if let Kind::Text { segment, .. } =
                                        &mut self.arena.get_mut(last)?.kind
                                    {
                                        *segment = segment.with_stop(segment.stop - 1);
                                    }
                                }
                            }
                        }
                        return Ok(Some(code));
                    }
                    continue;
                }
                i += 1;
            }
            let child = self.arena.add(Kind::Text {
                segment: s,
                flags: RAW,
            })?;
            self.arena.append(code, child)?;
            r.advance_line()?;
        }
    }
    fn raw_html(&mut self, r: &mut BlockReader<'a, '_>) -> Result<Option<Id>> {
        let saved = r.position();
        let Some((line, _)) = r.peek_line()? else {
            return Ok(None);
        };
        let relevant = line.get(1).is_some_and(u8::is_ascii_alphanumeric)
            || line.get(..2) == Some(b"</")
            || line.starts_with(b"<!--")
            || line.starts_with(b"<?")
            || line.starts_with(b"<!");
        if !relevant {
            return Ok(None);
        }
        drop(line);
        let mut combined = super::output::Output::new(&self.account, 1 << 20);
        let mut segments = super::segment::Segments::new(&self.account);
        while let Some((line, s)) = r.peek_line()? {
            combined.write(&line)?;
            segments.append(s)?;
            drop(line);
            if let Some(mut count) = super::html_parser::raw_len(combined.as_bytes()) {
                let bytes = combined.as_bytes();
                let regexp_tag =
                    bytes.get(1).is_some_and(u8::is_ascii_alphanumeric) || bytes.starts_with(b"</");
                if regexp_tag && gotmpl::go_runes(&bytes[..count]).any(|(ch, _)| ch == '\u{fffd}') {
                    r.set_position(saved.0, saved.1)?;
                    return Ok(None);
                }
                let id = self.arena.add(Kind::RawHtml)?;
                r.set_position(saved.0, saved.1)?;
                for segment in segments.as_slice() {
                    let len = segment.len()?;
                    let consumed = count.min(len);
                    self.arena.get_mut(id)?.lines.append(
                        segment.with_stop(segment.start + consumed.saturating_sub(segment.padding)),
                    )?;
                    r.advance(consumed)?;
                    count -= consumed;
                    if count == 0 {
                        break;
                    }
                }
                return Ok(Some(id));
            }
            r.advance_line()?;
        }
        r.set_position(saved.0, saved.1)?;
        Ok(None)
    }
    fn link(
        &mut self,
        parent: Id,
        r: &mut BlockReader<'a, '_>,
        labels: &mut Vec<Label>,
    ) -> Result<Option<Id>> {
        let Some((line, s)) = r.peek_line()? else {
            return Ok(None);
        };
        let image = line.first() == Some(&b'!');
        if line[0] == b'[' || image && line.get(1) == Some(&b'[') {
            let len = if image { 2 } else { 1 };
            let segment = Segment::new(s.start, s.start + len);
            let node = self.arena.add(Kind::LinkLabel {
                segment,
                is_image: image,
            })?;
            room(labels, 1, &self.account)?;
            labels.push(Label {
                node,
                segment,
                image,
                bottom: self.last_delimiter,
            });
            drop(line);
            r.advance(len)?;
            return Ok(Some(node));
        }
        if line[0] != b']' {
            return Ok(None);
        }
        let state_length = labels
            .first()
            .zip(labels.last())
            .map_or(0, |(first, last)| last.segment.stop - first.segment.start);
        let Some(label) = labels.pop() else {
            return Ok(None);
        };
        drop(line);
        r.advance(1)?;
        let mut contained = false;
        if !label.image {
            let mut next = self.arena.get(label.node)?.next;
            while let Some(id) = next {
                next = self.arena.get(id)?.next;
                self.arena.walk(id, |a, id, enter| {
                    if enter && matches!(a.get(id)?.kind, Kind::Link { .. }) {
                        contained = true;
                        return Ok(Walk::Stop);
                    }
                    Ok(Walk::Continue)
                })?;
                if contained {
                    break;
                }
            }
        }
        if state_length > 998 || contained {
            self.arena.get_mut(label.node)?.kind = Kind::Text {
                segment: label.segment,
                flags: 0,
            };
            return Ok(None);
        }
        let saved = r.position();
        let mut destination_title = None;
        let mut reference = None;
        let mut invalid_reference = false;
        if r.peek() == b'(' {
            r.advance(1)?;
            skip_spaces(r)?;
            if r.peek() == b')' {
                r.advance(1)?;
                destination_title = Some((Bytes::Borrowed(b""), None));
            } else if let Some(dest) = destination(r)? {
                skip_spaces(r)?;
                if r.peek() == b')' {
                    r.advance(1)?;
                    destination_title = Some((dest, None));
                } else if let Some(title) = title(r, &self.account)? {
                    skip_spaces(r)?;
                    if r.peek() == b')' {
                        r.advance(1)?;
                        destination_title = Some((dest, Some(title)));
                    }
                }
            }
        } else if r.peek() == b'[' {
            r.advance(1)?;
            if let Some(mut text) = find_closure(r, b'[', b']', &self.account)? {
                let kind = if blank(&text) {
                    let close = s.start;
                    let value = r.value(Segment::new(label.segment.stop, close))?;
                    text = Bytes::Owned(value);
                    ReferenceType::Collapsed
                } else {
                    ReferenceType::Full
                };
                if text.len() <= 999 {
                    if let Some(value) = self.reference_copy(&text)? {
                        destination_title = Some(value);
                        reference = Some(LinkReference { kind, label: text });
                    } else {
                        invalid_reference = true;
                    }
                } else {
                    invalid_reference = true;
                }
            }
        }
        if destination_title.is_none() && !invalid_reference {
            r.set_position(saved.0, saved.1)?;
            let text = Bytes::Owned(r.value(Segment::new(label.segment.stop, s.start))?);
            if text.len() <= 999 {
                if let Some(value) = self.reference_copy(&text)? {
                    destination_title = Some(value);
                    reference = Some(LinkReference {
                        kind: ReferenceType::Shortcut,
                        label: text,
                    });
                }
            }
        }
        let Some((destination, title)) = destination_title else {
            self.arena.get_mut(label.node)?.kind = Kind::Text {
                segment: label.segment,
                flags: 0,
            };
            return Ok(None);
        };
        self.process_delimiters(label.bottom)?;
        let kind = if label.image {
            Kind::Image {
                destination,
                title,
                reference,
            }
        } else {
            Kind::Link {
                destination,
                title,
                reference,
            }
        };
        let id = self.arena.add(kind)?;
        let mut child = self.arena.get(label.node)?.next;
        while let Some(child_id) = child {
            let next = self.arena.get(child_id)?.next;
            self.arena.append(id, child_id)?;
            child = next;
        }
        self.arena.detach(label.node)?;
        self.arena.get_mut(id)?.pos = Some(label.segment.start);
        let _ = parent;
        Ok(Some(id))
    }
}
