//! Goldmark delimiter processing with flat AST indices (MIT).
use super::{
    ast::{DelimiterProcessor, Id, Kind},
    parse_util::invalid,
    parser::Parser,
    punctuation::is_punctuation,
    segment::Segment,
};
use gotmpl::Result;
#[derive(Clone, Copy)]
struct D {
    segment: Segment,
    ch: u8,
    length: usize,
    original: usize,
    open: bool,
    close: bool,
    prev: Option<Id>,
    next: Option<Id>,
    processor: DelimiterProcessor,
}
impl<'a> Parser<'a> {
    fn delimiter_data(&self, id: Id) -> Result<D> {
        match self.arena.get(id)?.kind {
            Kind::Delimiter {
                segment,
                character,
                length,
                original_length,
                can_open,
                can_close,
                previous,
                next,
                processor,
            } => Ok(D {
                segment,
                ch: character,
                length,
                original: original_length,
                open: can_open,
                close: can_close,
                prev: previous,
                next,
                processor,
            }),
            _ => Err(invalid()),
        }
    }
    pub(super) fn scan_delimiter(
        &mut self,
        line: &[u8],
        segment: Segment,
        before: char,
    ) -> Result<Option<Id>> {
        let ch = line[0];
        let length = line.iter().take_while(|b| **b == ch).count();
        if ch == b'~' && (length > 2 || before == '~') {
            return Ok(None);
        }
        let after = gotmpl::decode_go_rune(&line[length..]).map_or(' ', |(ch, _)| ch);
        let before_p = is_punctuation(before);
        let after_p = is_punctuation(after);
        let before_w = before.is_whitespace();
        let after_w = after.is_whitespace();
        let left = !after_w && (!after_p || before_w || before_p);
        let right = !before_w && (!before_p || after_w || after_p);
        let open = if ch == b'_' {
            left && (!right || before_p)
        } else {
            left
        };
        let close = if ch == b'_' {
            right && (!left || after_p)
        } else {
            right
        };
        let id = self.arena.add(Kind::Delimiter {
            segment: segment.with_stop(segment.start + length),
            character: ch,
            length,
            original_length: length,
            can_open: open,
            can_close: close,
            previous: self.last_delimiter,
            next: None,
            processor: if ch == b'~' {
                DelimiterProcessor::Strikethrough
            } else {
                DelimiterProcessor::Emphasis
            },
        })?;
        if let Some(previous) = self.last_delimiter {
            if let Kind::Delimiter { next, .. } = &mut self.arena.get_mut(previous)?.kind {
                *next = Some(id);
            }
        } else {
            self.first_delimiter = Some(id);
        }
        self.last_delimiter = Some(id);
        Ok(Some(id))
    }
    fn remove_delimiter(&mut self, id: Id) -> Result<()> {
        let d = self.delimiter_data(id)?;
        if let Some(prev) = d.prev {
            if let Kind::Delimiter { next, .. } = &mut self.arena.get_mut(prev)?.kind {
                *next = d.next;
            }
        } else {
            self.first_delimiter = d.next;
        }
        if let Some(next) = d.next {
            if let Kind::Delimiter { previous, .. } = &mut self.arena.get_mut(next)?.kind {
                *previous = d.prev;
            }
        } else {
            self.last_delimiter = d.prev;
        }
        if d.length == 0 {
            self.arena.detach(id)?;
        } else {
            self.arena.get_mut(id)?.kind = Kind::Text {
                segment: d.segment,
                flags: 0,
            };
        }
        Ok(())
    }
    fn consume(&mut self, id: Id, count: usize) -> Result<()> {
        if let Kind::Delimiter {
            segment, length, ..
        } = &mut self.arena.get_mut(id)?.kind
        {
            *length -= count;
            *segment = segment.with_stop(segment.start + *length);
            Ok(())
        } else {
            Err(invalid())
        }
    }
    pub(super) fn process_delimiters(&mut self, bottom: Option<Id>) -> Result<()> {
        let Some(last) = self.last_delimiter else {
            return Ok(());
        };
        let mut closer = self.first_delimiter;
        if let Some(bottom) = bottom {
            closer = None;
            if bottom != last {
                let mut c = self.arena.get(last)?.prev;
                while let Some(id) = c {
                    self.account.charge_work(1)?;
                    if id == bottom {
                        break;
                    }
                    if matches!(self.arena.get(id)?.kind, Kind::Delimiter { .. }) {
                        closer = Some(id);
                    }
                    c = self.arena.get(id)?.prev;
                }
            }
        }
        while let Some(cid) = closer {
            self.account.charge_work(1)?;
            let c = self.delimiter_data(cid)?;
            if !c.close {
                closer = c.next;
                continue;
            }
            let mut opener = c.prev;
            let mut found = None;
            let mut maybe = false;
            while let Some(oid) = opener {
                self.account.charge_work(1)?;
                if Some(oid) == bottom {
                    break;
                }
                let o = self.delimiter_data(oid)?;
                if o.open && o.ch == c.ch {
                    maybe = true;
                    let count = if (o.close || c.open)
                        && (o.original + c.original) % 3 == 0
                        && c.original % 3 != 0
                    {
                        0
                    } else if o.length >= 2 && c.length >= 2 {
                        2
                    } else {
                        1
                    };
                    if count > 0 {
                        found = Some((oid, o, count));
                        break;
                    }
                }
                opener = o.prev;
            }
            let Some((oid, o, count)) = found else {
                closer = c.next;
                if !maybe && !c.open {
                    self.remove_delimiter(cid)?;
                }
                continue;
            };
            self.consume(oid, count)?;
            self.consume(cid, count)?;
            let n = self.arena.add(match o.processor {
                DelimiterProcessor::Emphasis => Kind::Emphasis { level: count },
                DelimiterProcessor::Strikethrough => Kind::Strikethrough,
            })?;
            self.arena.get_mut(n)?.pos = Some(o.segment.start);
            let parent = self.arena.get(oid)?.parent.ok_or_else(invalid)?;
            let mut child = self.arena.get(oid)?.next;
            while let Some(id) = child {
                if id == cid {
                    break;
                }
                let next = self.arena.get(id)?.next;
                self.arena.append(n, id)?;
                child = next;
            }
            self.arena.insert_after(parent, oid, n)?;
            let mut d = o.next;
            while let Some(id) = d {
                if id == cid {
                    break;
                }
                let next = self.delimiter_data(id)?.next;
                self.remove_delimiter(id)?;
                d = next;
            }
            if self.delimiter_data(oid)?.length == 0 {
                self.remove_delimiter(oid)?;
            }
            if self.delimiter_data(cid)?.length == 0 {
                let next = self.delimiter_data(cid)?.next;
                self.remove_delimiter(cid)?;
                closer = next;
            }
        }
        // ClearDelimiters follows AST previous-sibling links, not the delimiter chain.
        if let Some(mut id) = self.last_delimiter {
            loop {
                if Some(id) == bottom {
                    break;
                }
                let previous = self.arena.get(id)?.prev;
                if matches!(self.arena.get(id)?.kind, Kind::Delimiter { .. }) {
                    self.remove_delimiter(id)?;
                }
                let Some(previous) = previous else {
                    break;
                };
                id = previous;
            }
        }
        Ok(())
    }
}
