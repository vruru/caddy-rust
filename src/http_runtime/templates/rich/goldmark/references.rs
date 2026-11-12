//! Goldmark reference-definition paragraph transform (MIT).
use super::{
    ast::{Id, Kind, room},
    block_reader::BlockReader,
    parse_util::*,
    parser::Parser,
    segment::Bytes,
};
use gotmpl::Result;
impl<'a> Parser<'a> {
    fn record_reference(&mut self, id: Id) -> Result<()> {
        let label = match &self.arena.get(id)?.kind {
            Kind::ReferenceDefinition { label, .. } => label,
            _ => return Err(invalid()),
        };
        let normalized = super::normalize::reference(label, &self.account)?;
        if self.refs.contains_key(normalized.as_bytes()) {
            return Ok(());
        }
        super::allocation::btree_insert::<Vec<u8>, Id>(self.refs.is_empty(), &self.account)?;
        let mut key = Vec::new();
        self.account.reserve(normalized.as_bytes().len())?;
        if key.try_reserve_exact(normalized.as_bytes().len()).is_err() {
            self.account.release(normalized.as_bytes().len())?;
            return Err(invalid());
        }
        if key.capacity() != normalized.as_bytes().len() {
            drop(key);
            self.account.release(normalized.as_bytes().len())?;
            return Err(invalid());
        }
        key.extend_from_slice(normalized.as_bytes());
        self.refs.insert(key, id);
        Ok(())
    }
    pub(super) fn reference_copy(
        &self,
        label: &[u8],
    ) -> Result<Option<(Bytes<'a>, Option<Bytes<'a>>)>> {
        let key = super::normalize::reference(label, &self.account)?;
        let Some(id) = self.refs.get(key.as_bytes()) else {
            return Ok(None);
        };
        match &self.arena.get(*id)?.kind {
            Kind::ReferenceDefinition {
                destination, title, ..
            } => Ok(Some((
                destination.copy(&self.account)?,
                title.as_ref().map(|t| t.copy(&self.account)).transpose()?,
            ))),
            _ => Err(invalid()),
        }
    }
    pub(super) fn references(&mut self, node: Id) -> Result<()> {
        let mut lines = super::segment::Segments::new(&self.account);
        lines.append_all(self.arena.get(node)?.lines.as_slice())?;
        let mut block = BlockReader::new(self.source, lines.as_slice(), &self.account)?;
        let mut removes = Vec::new();
        while let Some((id, start, mut end)) = self.definition(&mut block)? {
            if start == 0 {
                self.arena.get_mut(id)?.blank_previous = self.arena.get(node)?.blank_previous;
            }
            let parent = self.arena.get(node)?.parent.ok_or_else(invalid)?;
            self.arena.insert_before(parent, Some(node), id)?;
            for i in start + 1..end {
                self.arena.get_mut(id)?.lines.append(lines.at(i)?)?;
            }
            let n = self.arena.get(id)?.lines.len();
            let last = self
                .arena
                .get(id)?
                .lines
                .at(n - 1)?
                .trim_right_space(self.source)?;
            self.arena.get_mut(id)?.lines.set(n - 1, last)?;
            if start == end {
                end += 1;
            }
            room(&mut removes, 1, &self.account)?;
            removes.push((start, end));
        }
        let mut offset = 0;
        for (start, end) in removes.iter().copied() {
            let n = self.arena.get(node)?.lines.len();
            if n == 0 {
                break;
            }
            let tail_start = end.checked_sub(offset).ok_or_else(invalid)?;
            let prefix = start.checked_sub(offset).ok_or_else(invalid)?;
            let mut tail = super::segment::Segments::new(&self.account);
            tail.append_all(self.arena.get(node)?.lines.sliced(tail_start, n)?)?;
            self.arena.get_mut(node)?.lines.set_sliced(0, prefix)?;
            self.arena
                .get_mut(node)?
                .lines
                .append_all(tail.as_slice())?;
            offset = end;
        }
        let bytes = removes.capacity() * std::mem::size_of::<(usize, usize)>();
        drop(removes);
        self.account.release(bytes)?;
        if self.arena.get(node)?.lines.len() == 0 {
            self.arena.detach(node)?;
        }
        Ok(())
    }
    fn definition(
        &mut self,
        block: &mut BlockReader<'a, '_>,
    ) -> Result<Option<(Id, usize, usize)>> {
        skip_spaces(block)?;
        let Some((line, _)) = block.peek_line()? else {
            return Ok(None);
        };
        let (start_line, start_pos) = block.position();
        let (w, mut pos) = indent_width(&line, 0);
        if w > 3 {
            return Ok(None);
        }
        if w != 0 {
            pos += 1;
        }
        if line.get(pos) != Some(&b'[') {
            return Ok(None);
        }
        drop(line);
        let start_pos = start_pos.ok_or_else(invalid)?;
        block.advance(pos + 1)?;
        let Some(label) = find_closure(block, b'[', b']', &self.account)? else {
            return Ok(None);
        };
        if blank(&label) || block.peek() != b':' {
            return Ok(None);
        }
        block.advance(1)?;
        skip_spaces(block)?;
        let Some(destination) = destination(block)? else {
            return Ok(None);
        };
        let newline = block.peek_line()?.is_none_or(|(line, _)| blank(&line));
        let (end_line, _) = block.position();
        let spaces = skip_spaces(block)?;
        let open = block.peek();
        let (title, end) = if !matches!(open, b'"' | b'\'' | b'(') {
            if !newline {
                return Ok(None);
            }
            (None, end_line + 1)
        } else {
            if spaces == 0 {
                return Ok(None);
            }
            block.advance(1)?;
            let title = find_closure(
                block,
                open,
                if open == b'(' { b')' } else { open },
                &self.account,
            )?;
            if title.is_none() {
                if !newline {
                    return Ok(None);
                }
                block.advance_line()?;
                (None, end_line + 1)
            } else if block.peek_line()?.is_some_and(|(line, _)| !blank(&line)) {
                if !newline {
                    return Ok(None);
                }
                (title, end_line)
            } else {
                (title, block.position().0 + 1)
            }
        };
        let id = self.arena.add(Kind::ReferenceDefinition {
            label,
            destination,
            title,
        })?;
        self.arena.get_mut(id)?.lines.append(start_pos)?;
        self.record_reference(id)?;
        Ok(Some((
            id,
            usize::try_from(start_line).map_err(|_| invalid())?,
            usize::try_from(end).map_err(|_| invalid())?,
        )))
    }
}
