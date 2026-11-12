//! Goldmark 1.8.6 GFM table transforms (MIT, see html_render.rs).
use super::{
    ast::{Alignment, Arena, Id, Kind, RAW, Walk, room},
    parse_util::{blank, indent_width, invalid},
    segment::Segment,
};
use gotmpl::Result;
pub(super) struct EscapedCell {
    cell: Id,
    positions: Vec<usize>,
    transformed: bool,
}
fn delimiter(arena: &Arena<'_>, s: Segment, source: &[u8]) -> Result<Option<Vec<Alignment>>> {
    let account = arena.account();
    let line = s.value(source, account)?;
    if indent_width(&line, 0).0 > 3
        || line.iter().all(|b| *b == b'-')
        || line
            .iter()
            .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'-' | b'|' | b':'))
    {
        return Ok(None);
    }
    let mut cols = line.split(|b| *b == b'|').peekable();
    let mut aligns = Vec::new();
    let mut first = true;
    while let Some(col) = cols.next() {
        if (first || cols.peek().is_none()) && blank(col) {
            first = false;
            continue;
        }
        first = false;
        let col = col.trim_ascii();
        let left = col.first() == Some(&b':');
        let right = col.last() == Some(&b':');
        let start = usize::from(left);
        let end = col.len().saturating_sub(usize::from(right));
        if start >= end || !col[start..end].iter().all(|b| *b == b'-') {
            return Ok(None);
        }
        room(&mut aligns, 1, account)?;
        aligns.push(match (left, right) {
            (true, true) => Alignment::Center,
            (true, false) => Alignment::Left,
            (false, true) => Alignment::Right,
            _ => Alignment::None,
        });
    }
    if aligns.is_empty() {
        Ok(None)
    } else {
        Ok(Some(aligns))
    }
}
fn row(
    arena: &mut Arena<'_>,
    s: Segment,
    aligns: &[Alignment],
    header: bool,
    source: &[u8],
    escaped: &mut Vec<EscapedCell>,
) -> Result<Id> {
    let account = arena.account().clone();
    let segment = s.trim_left_space(source)?.trim_right_space(source)?;
    let line = segment.value(source, &account)?;
    let mut pos = usize::from(line.first() == Some(&b'|'));
    let limit = line
        .len()
        .saturating_sub(usize::from(line.last() == Some(&b'|')));
    let row = arena.add(if header {
        Kind::TableHeader
    } else {
        Kind::TableRow
    })?;
    arena.get_mut(row)?.pos = Some(s.start);
    let mut i = 0;
    while pos < limit {
        account.charge_work(1)?;
        if i >= aligns.len() && !header {
            return Ok(row);
        }
        let cell = arena.add(Kind::TableCell {
            alignment: aligns.get(i).copied().unwrap_or(Alignment::None),
        })?;
        arena.get_mut(cell)?.pos = Some(s.start + pos.saturating_sub(s.padding));
        let mut escaped_index = None;
        let mut backtick = false;
        let mut end = pos;
        while end < limit {
            account.charge_work(1)?;
            if line[end] == b'`' {
                backtick = true;
            }
            if line[end] == b'|' {
                if end == 0 || line[end - 1] != b'\\' {
                    break;
                } else if backtick {
                    let index = if let Some(index) = escaped_index {
                        index
                    } else {
                        room(escaped, 1, &account)?;
                        let index = escaped.len();
                        escaped.push(EscapedCell {
                            cell,
                            positions: Vec::new(),
                            transformed: false,
                        });
                        escaped_index = Some(index);
                        index
                    };
                    room(&mut escaped[index].positions, 1, &account)?;
                    escaped[index].positions.push(segment.start + end - 1);
                }
            }
            end += 1;
        }
        let content = Segment::new(segment.start + pos, segment.start + end)
            .trim_left_space(source)?
            .trim_right_space(source)?;
        arena.get_mut(cell)?.lines.append(content)?;
        arena.append(row, cell)?;
        pos = end + 1;
        i += 1;
    }
    while i < aligns.len() {
        let cell = arena.add(Kind::TableCell {
            alignment: Alignment::None,
        })?;
        arena.append(row, cell)?;
        i += 1;
    }
    Ok(row)
}
pub(super) fn transform(
    arena: &mut Arena<'_>,
    node: Id,
    source: &[u8],
    escaped: &mut Vec<EscapedCell>,
) -> Result<()> {
    let mut i = 1;
    while i < arena.get(node)?.lines.len() {
        let s = arena.get(node)?.lines.at(i)?;
        let Some(aligns) = delimiter(arena, s, source)? else {
            i += 1;
            continue;
        };
        let head = arena.get(node)?.lines.at(i - 1)?;
        let header = row(arena, head, &aligns, true, source, escaped)?;
        if arena.get(header)?.child_count != aligns.len() {
            return Ok(());
        }
        let table = arena.add(Kind::Table { alignments: aligns })?;
        arena.get_mut(table)?.pos = arena.get(node)?.pos;
        arena.append(table, header)?;
        let mut j = i + 1;
        while j < arena.get(node)?.lines.len() {
            let s = arena.get(node)?.lines.at(j)?;
            // Borrowing the stored alignment vector while adding arena nodes is avoided
            // by a separately prepaid copy with an explicit refund after use.
            let account = arena.account().clone();
            let mut aligns = Vec::new();
            if let Kind::Table { alignments } = &arena.get(table)?.kind {
                room(&mut aligns, alignments.len(), &account)?;
                aligns.extend_from_slice(alignments);
            }
            let result = row(arena, s, &aligns, false, source, escaped);
            let size = aligns.capacity() * std::mem::size_of::<Alignment>();
            drop(aligns);
            account.release(size)?;
            let next = result?;
            arena.append(table, next)?;
            j += 1;
        }
        arena.get_mut(node)?.lines.set_sliced(0, i - 1)?;
        let parent = arena.get(node)?.parent.ok_or_else(invalid)?;
        arena.insert_after(parent, node, table)?;
        if arena.get(node)?.lines.len() == 0 {
            arena.detach(node)?;
        } else {
            let s = arena.get(node)?.lines.at(i - 2)?;
            arena
                .get_mut(node)?
                .lines
                .set(i - 2, s.with_stop(s.stop.saturating_sub(1)))?;
        }
        i += 1;
    }
    Ok(())
}
pub(super) fn finish(
    arena: &mut Arena<'_>,
    _root: Id,
    escaped: &mut Vec<EscapedCell>,
) -> Result<()> {
    for cell in escaped.iter_mut() {
        if cell.transformed {
            continue;
        }
        arena.walk(cell.cell, |arena, id, entering| {
            if !entering || !matches!(arena.get(id)?.kind, Kind::CodeSpan) {
                return Ok(Walk::Continue);
            }
            let mut child = arena.get(id)?.first;
            while let Some(cid) = child {
                let next = arena.get(cid)?.next;
                let mut n = cid;
                let original = match arena.get(cid)?.kind {
                    Kind::Text { segment, .. } => Some(segment),
                    _ => None,
                };
                if let Some(original) = original {
                    for position in &cell.positions {
                        if original.start <= *position && *position < original.stop {
                            let segment = match arena.get(n)?.kind {
                                Kind::Text { segment, .. } => segment,
                                _ => return Err(invalid()),
                            };
                            let first = arena.add(Kind::Text {
                                segment: segment.with_stop(*position),
                                flags: RAW,
                            })?;
                            let second = arena.add(Kind::Text {
                                segment: segment.with_start(*position + 1),
                                flags: RAW,
                            })?;
                            arena.insert_after(id, n, first)?;
                            arena.insert_after(id, first, second)?;
                            arena.detach(n)?;
                            n = second;
                            cell.transformed = true;
                        }
                    }
                }
                child = next;
            }
            Ok(Walk::Continue)
        })?;
    }
    Ok(())
}
