//! Goldmark Footnote numbering and backlinks, MIT.
use super::{
    ast::{Id, Kind, room},
    parse_util::*,
    parser::Parser,
    segment::Segment,
    text::Read,
};
use gotmpl::Result;
impl<'a> Parser<'a> {
    pub(super) fn footnote_inline(
        &mut self,
        parent: Id,
        reader: &mut impl Read<'a>,
    ) -> Result<Option<Id>> {
        let Some((line, s)) = reader.peek_line()? else {
            return Ok(None);
        };
        let image = line.first() == Some(&b'!');
        let open = if image { 3 } else { 2 };
        if line.get(open - 1) != Some(&b'^') || line.get(open).is_none() {
            return Ok(None);
        }
        let Some(close) = closure(&line[open..], b'[', b']').map(|n| open + n) else {
            return Ok(None);
        };
        let value = reader.value(Segment::new(s.start + open, s.start + close))?;
        reader.advance(close + 1)?;
        let Some(list) = self.footnotes else {
            return Ok(None);
        };
        let mut current = self.arena.get(list)?.first;
        let mut index = None;
        while let Some(id) = current {
            self.account.charge_work(1)?;
            let n = self.arena.get(id)?;
            let next = n.next;
            if let Kind::Footnote {
                reference,
                index: i,
            } = &n.kind
            {
                if **reference == *value {
                    let count = match self.arena.get(list)?.kind {
                        Kind::FootnoteList { count } => count,
                        _ => return Err(invalid()),
                    };
                    index = Some(i.unwrap_or(count + 1));
                    if i.is_none() {
                        if let Kind::Footnote { index, .. } = &mut self.arena.get_mut(id)?.kind {
                            *index = Some(count + 1);
                        }
                        if let Kind::FootnoteList { count } = &mut self.arena.get_mut(list)?.kind {
                            *count += 1;
                        }
                    }
                    break;
                }
            }
            current = next;
        }
        let Some(index) = index else {
            return Ok(None);
        };
        let id = self.arena.add(Kind::FootnoteLink {
            index,
            ref_count: 0,
            ref_index: 0,
        })?;
        room(&mut self.footnote_links, 1, &self.account)?;
        self.footnote_links.push(id);
        if image {
            self.arena
                .append_text_segment(parent, Segment::new(s.start, s.start + 1))?;
        }
        Ok(Some(id))
    }
    pub(super) fn finish_footnotes(&mut self, root: Id) -> Result<()> {
        let Some(list) = self.footnotes.take() else {
            return Ok(());
        };
        let count = match self.arena.get(list)?.kind {
            Kind::FootnoteList { count } => count,
            _ => return Err(invalid()),
        };
        let mut counters = Vec::new();
        room(&mut counters, count + 1, &self.account)?;
        counters.resize(count + 1, 0usize);
        for id in &self.footnote_links {
            if let Kind::FootnoteLink { index, .. } = self.arena.get(*id)?.kind {
                counters[index] += 1;
            }
        }
        let mut refs = Vec::new();
        room(&mut refs, count + 1, &self.account)?;
        refs.resize(count + 1, 0usize);
        for id in &self.footnote_links {
            if let Kind::FootnoteLink {
                index,
                ref_count,
                ref_index,
            } = &mut self.arena.get_mut(*id)?.kind
            {
                *ref_count = counters[*index];
                *ref_index = refs[*index];
                refs[*index] += 1;
            }
        }
        let mut ordered = Vec::new();
        let mut node = self.arena.get(list)?.first;
        while let Some(id) = node {
            let n = self.arena.get(id)?;
            node = n.next;
            let index = match n.kind {
                Kind::Footnote { index, .. } => index,
                _ => return Err(invalid()),
            };
            if let Some(index) = index {
                let container = n
                    .last
                    .filter(|last| self.paragraph(Some(*last)))
                    .unwrap_or(id);
                for ref_index in 0..counters[index].max(1) {
                    let backlink = self.arena.add(Kind::FootnoteBacklink {
                        index,
                        ref_count: counters[index],
                        ref_index,
                    })?;
                    self.arena.append(container, backlink)?;
                }
                room(&mut ordered, 1, &self.account)?;
                ordered.push((index, id));
            } else {
                self.arena.detach(id)?;
            }
        }
        ordered.sort_unstable_by_key(|(index, _)| *index);
        for (_, id) in &ordered {
            self.arena.append(list, *id)?;
        }
        if count == 0 {
            self.arena.detach(list)?;
        } else {
            self.arena.append(root, list)?;
        }
        let bytes = counters.capacity() * std::mem::size_of::<usize>()
            + refs.capacity() * std::mem::size_of::<usize>()
            + ordered.capacity() * std::mem::size_of::<(usize, Id)>();
        drop(counters);
        drop(refs);
        drop(ordered);
        self.account.release(bytes)?;
        Ok(())
    }
}
