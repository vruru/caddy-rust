//! Goldmark list/list-item parser, MIT (see html_render.rs).
use super::{ast::Kind, parse_util::*, parser::Parser, reader::Reader};
use gotmpl::Result;
#[derive(Copy, Clone, PartialEq, Eq)]
enum ItemType {
    None,
    Bullet,
    Ordered,
}
// Initial mechanical scan drafted by Flash Next; Codex fixed and checked the
// helper contracts against pinned parser/list.go before integration.
fn parse_list_item(line: &[u8]) -> ([isize; 6], ItemType) {
    let mut m = [0; 6];
    let mut i = line.iter().take_while(|b| **b == b' ').count();
    if i > 3 {
        return (m, ItemType::None);
    }
    m[1] = i as isize;
    m[2] = i as isize;
    let typ = if line.get(i).is_some_and(|b| matches!(b, b'-' | b'*' | b'+')) {
        i += 1;
        m[3] = i as isize;
        ItemType::Bullet
    } else {
        let start = i;
        while line.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        m[3] = i as isize;
        if i == start || i - start > 9 || !line.get(i).is_some_and(|b| matches!(b, b'.' | b')')) {
            return (m, ItemType::None);
        }
        i += 1;
        m[3] = i as isize;
        ItemType::Ordered
    };
    if i < line.len() && line[i] != b'\n' && indent_width(&line[i..], 0).0 == 0 {
        return (m, ItemType::None);
    }
    if i >= line.len() {
        m[4] = -1;
        m[5] = -1;
        return (m, typ);
    }
    m[4] = i as isize;
    m[5] = line.len() as isize;
    if line.last() == Some(&b'\n') && line[i] != b'\n' {
        m[5] -= 1;
    }
    (m, typ)
}
fn calc_offset(line: &[u8], m: [isize; 6]) -> isize {
    if m[4] < 0 || blank(&line[m[4] as usize..]) {
        return 1;
    }
    let (w, _) = indent_width(&line[m[4] as usize..], m[4]);
    if w > 4 { 1 } else { w }
}
impl<'a> Parser<'a> {
    fn last_offset(&self, id: usize) -> Result<isize> {
        Ok(match self.arena.get(id)?.last {
            Some(last) => match self.arena.get(last)?.kind {
                Kind::ListItem { offset } => offset,
                _ => return Err(invalid()),
            },
            None => 0,
        })
    }
    pub(super) fn open_list(
        &mut self,
        parent: usize,
        r: &mut Reader<'a>,
    ) -> Result<Option<(usize, bool, bool)>> {
        if self.last().is_some_and(|id| {
            self.arena
                .get(id)
                .is_ok_and(|n| matches!(n.kind, Kind::List { .. }))
        }) || self.skip_list
        {
            self.skip_list = false;
            return Ok(None);
        }
        let Some((line, _)) = r.peek_line()? else {
            return Ok(None);
        };
        let (m, typ) = parse_list_item(&line);
        if typ == ItemType::None {
            return Ok(None);
        }
        let start = if typ == ItemType::Ordered {
            line[m[2] as usize..m[3] as usize - 1]
                .iter()
                .fold(0usize, |n, b| n * 10 + (b - b'0') as usize)
        } else {
            0
        };
        if self.paragraph(self.last())
            && self
                .last()
                .and_then(|id| self.arena.get(id).ok())
                .and_then(|n| n.parent)
                == Some(parent)
        {
            if typ == ItemType::Ordered && start != 1 {
                return Ok(None);
            }
            if m[4] < 0 || blank(&line[m[4] as usize..m[5] as usize]) {
                return Ok(None);
            }
        }
        let marker = line[m[3] as usize - 1];
        self.empty_item = false;
        let id = self.arena.add(Kind::List {
            marker,
            tight: true,
            start,
        })?;
        Ok(Some((id, true, false)))
    }
    pub(super) fn open_item(
        &mut self,
        parent: usize,
        r: &mut Reader<'a>,
    ) -> Result<Option<(usize, bool, bool)>> {
        if !matches!(self.arena.get(parent)?.kind, Kind::List { .. }) {
            return Ok(None);
        }
        let offset = self.last_offset(parent)?;
        let Some((line, _)) = r.peek_line()? else {
            return Ok(None);
        };
        let (m, typ) = parse_list_item(&line);
        if typ == ItemType::None || m[1] - offset > 3 {
            return Ok(None);
        }
        self.empty_item = false;
        let item_offset = calc_offset(&line, m);
        let id = self.arena.add(Kind::ListItem {
            offset: m[3] + item_offset,
        })?;
        if m[4] < 0 || blank(&line[m[4] as usize..m[5] as usize]) {
            return Ok(Some((id, false, false)));
        }
        let (n, padding) =
            indent_position(&line[m[4] as usize..], m[4], 0, item_offset).ok_or_else(invalid)?;
        r.advance_and_set_padding(m[3] as usize + n, padding)?;
        Ok(Some((id, true, false)))
    }
    pub(super) fn continue_list(&mut self, id: usize, r: &mut Reader<'a>) -> Result<(bool, bool)> {
        let Some((line, _)) = r.peek_line()? else {
            return Ok((false, false));
        };
        let last = self.arena.get(id)?.last.ok_or_else(invalid)?;
        let empty = self.arena.get(last)?.child_count == 0;
        if blank(&line) {
            if empty {
                self.empty_item = true;
            }
            return Ok((true, true));
        }
        let offset = self.last_offset(id)?;
        let (indent, _) = indent_width(&line, r.line_offset()?);
        if indent < offset || empty {
            if indent < 4 {
                let (m, typ) = parse_list_item(&line);
                if typ != ItemType::None && m[1] - offset < 4 {
                    let marker = line[m[3] as usize - 1];
                    let previous = match self.arena.get(id)?.kind {
                        Kind::List { marker, .. } => marker,
                        _ => return Err(invalid()),
                    };
                    if previous != marker {
                        return Ok((false, false));
                    }
                    if thematic(&line[m[3] as usize - 1..], 0)
                        && !(self.paragraph(self.last())
                            && setext(&line[m[3] as usize - 1..]) == Some(b'-'))
                    {
                        return Ok((false, false));
                    }
                    return Ok((true, true));
                }
            }
            if !empty {
                return Ok((false, false));
            }
        }
        if empty && indent < offset || self.empty_item {
            return Ok((false, false));
        }
        Ok((true, true))
    }
    pub(super) fn continue_item(&mut self, id: usize, r: &mut Reader<'a>) -> Result<(bool, bool)> {
        let Some((line, _)) = r.peek_line()? else {
            return Ok((false, false));
        };
        if blank(&line) {
            r.advance_to_eol()?;
            return Ok((true, true));
        }
        let parent = self.arena.get(id)?.parent.ok_or_else(invalid)?;
        let offset = self.last_offset(parent)?;
        let empty = self.arena.get(id)?.child_count == 0 && self.empty_item;
        let (indent, _) = indent_width(&line, r.line_offset()?);
        if (empty || indent < offset) && indent < 4 {
            if parse_list_item(&line).1 != ItemType::None {
                self.skip_list = true;
                return Ok((false, false));
            }
            if !empty {
                return Ok((false, false));
            }
        }
        let Some((n, padding)) = indent_position(&line, r.line_offset()?, 0, offset) else {
            return Ok((false, false));
        };
        r.advance_and_set_padding(n, padding)?;
        Ok((true, true))
    }
    pub(super) fn close_list(&mut self, id: usize) -> Result<()> {
        let mut tight = true;
        let first = self.arena.get(id)?.first;
        let mut child = first;
        while let Some(c) = child {
            self.account.charge_work(1)?;
            let n = self.arena.get(c)?;
            if Some(c) != first && n.blank_previous {
                tight = false;
                break;
            }
            let mut gc = n
                .first
                .and_then(|f| self.arena.get(f).ok())
                .and_then(|n| n.next);
            while let Some(g) = gc {
                let n = self.arena.get(g)?;
                if n.blank_previous {
                    tight = false;
                    break;
                }
                gc = n.next;
            }
            if !tight {
                break;
            }
            child = n.next;
        }
        if let Kind::List { tight: value, .. } = &mut self.arena.get_mut(id)?.kind {
            *value = tight;
        }
        if tight {
            let mut child = first;
            while let Some(c) = child {
                let mut gc = self.arena.get(c)?.first;
                while let Some(g) = gc {
                    let n = self.arena.get(g)?;
                    gc = n.next;
                    if matches!(n.kind, Kind::Paragraph) {
                        self.arena.get_mut(g)?.kind = Kind::TextBlock;
                    }
                }
                child = self.arena.get(c)?.next;
            }
        }
        Ok(())
    }
}
