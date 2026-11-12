//! Fixed Goldmark 1.8.6 parser configuration for Caddy (MIT).
use super::{
    ast::{Arena, Id, Kind, room},
    ids::Ids,
    parse_util::*,
    reader::Reader,
    segment::Bytes,
    table_parser::EscapedCell,
};
use gotmpl::{BudgetAccount, Result};
use std::collections::BTreeMap;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockKind {
    Atx,
    Setext,
    Thematic,
    Quote,
    List,
    Item,
    Code,
    Fence,
    Html,
    Paragraph,
    Footnote,
}
#[derive(Clone, Copy)]
pub(super) struct Block {
    pub node: Id,
    pub parser: BlockKind,
}
#[derive(Clone, Copy)]
pub(super) struct Fence {
    pub ch: u8,
    pub indent: isize,
    pub length: usize,
    pub node: Id,
}
#[derive(Clone, Copy)]
struct Stat {
    line: isize,
    level: usize,
    blank: bool,
}
pub(super) struct Parser<'a> {
    pub arena: Arena<'a>,
    pub source: &'a [u8],
    pub account: BudgetAccount,
    pub opened: Vec<Block>,
    pub ids: Ids,
    pub refs: BTreeMap<Vec<u8>, Id>,
    pub offset: isize,
    pub indent: isize,
    pub fence: Option<Fence>,
    pub temporary: Option<Id>,
    pub skip_list: bool,
    pub empty_item: bool,
    pub footnotes: Option<Id>,
    pub footnote_links: Vec<Id>,
    pub escaped: Vec<EscapedCell>,
    pub first_delimiter: Option<Id>,
    pub last_delimiter: Option<Id>,
}
impl<'a> Parser<'a> {
    pub fn new(source: &'a [u8], account: &BudgetAccount) -> Self {
        Self {
            arena: Arena::new(account),
            source,
            account: account.clone(),
            opened: Vec::new(),
            ids: Ids::new(account),
            refs: BTreeMap::new(),
            offset: -1,
            indent: -1,
            fence: None,
            temporary: None,
            skip_list: false,
            empty_item: false,
            footnotes: None,
            footnote_links: Vec::new(),
            escaped: Vec::new(),
            first_delimiter: None,
            last_delimiter: None,
        }
    }
    pub fn last(&self) -> Option<Id> {
        self.opened.last().map(|b| b.node)
    }
    pub fn paragraph(&self, id: Option<Id>) -> bool {
        id.and_then(|id| self.arena.get(id).ok())
            .is_some_and(|n| matches!(n.kind, Kind::Paragraph))
    }
    pub fn parse(mut self) -> Result<(Arena<'a>, Id)> {
        let root = self.arena.add(Kind::Document)?;
        let mut reader = Reader::new(self.source, self.account.clone())?;
        self.blocks(root, &mut reader)?;
        // Postorder traversal without recursive stack growth; inline processing only
        // adds inline children after the existing block descendants were visited.
        let mut current = Some(root);
        while let Some(id) = current {
            let mut leaf = id;
            while let Some(first) = self.arena.get(leaf)?.first {
                leaf = first;
                self.account.charge_work(1)?;
            }
            loop {
                let parent = self.arena.get(leaf)?.parent;
                let next = self.arena.get(leaf)?.next;
                self.inlines(leaf)?;
                if let Some(next) = next {
                    current = Some(next);
                    break;
                }
                if let Some(parent) = parent {
                    leaf = parent;
                } else {
                    current = None;
                    break;
                }
            }
        }
        self.finish_footnotes(root)?;
        super::table_parser::finish(&mut self.arena, root, &mut self.escaped)?;
        Ok((self.arena, root))
    }
    fn transform(&mut self, id: Id) -> Result<bool> {
        self.references(id)?;
        if self.arena.get(id)?.parent.is_none() {
            return Ok(true);
        }
        super::table_parser::transform(&mut self.arena, id, self.source, &mut self.escaped)?;
        Ok(self.arena.get(id)?.parent.is_none())
    }
    fn close_blocks(&mut self, from: usize, to: usize, r: &mut Reader<'a>) -> Result<()> {
        if from < to {
            return Ok(());
        }
        for i in (to..=from).rev() {
            self.account.charge_work(1)?;
            let b = self.opened[i];
            if self.paragraph(Some(b.node)) && self.arena.get(b.node)?.parent.is_some() {
                self.transform(b.node)?;
            }
            if self.arena.get(b.node)?.parent.is_some() {
                self.close_block(b, r)?;
            }
        }
        self.opened.drain(to..=from);
        Ok(())
    }
    fn open_blocks(&mut self, mut parent: Id, blank_line: bool, r: &mut Reader<'a>) -> Result<u8> {
        let mut result = 0;
        let mut continuable = self.paragraph(self.last());
        let mut last = self.opened.last().copied();
        'retry: loop {
            self.account.charge_work(1)?;
            let Some((line, _)) = r.peek_line()? else {
                break;
            };
            let (w, pos) = indent_width(&line, r.line_offset()?);
            if w >= line.len() as isize {
                self.offset = -1;
                self.indent = -1;
            } else {
                self.offset = pos as isize;
                self.indent = w;
            }
            if line.first() == Some(&b'\n') {
                break;
            }
            drop(line);
            // Goldmark's priority order, including the no-trigger free parsers.
            for kind in [
                BlockKind::Setext,
                BlockKind::Thematic,
                BlockKind::List,
                BlockKind::Item,
                BlockKind::Code,
                BlockKind::Atx,
                BlockKind::Fence,
                BlockKind::Quote,
                BlockKind::Html,
                BlockKind::Footnote,
                BlockKind::Paragraph,
            ] {
                if continuable
                    && result == 0
                    && matches!(kind, BlockKind::Code | BlockKind::Paragraph)
                {
                    continue;
                }
                if w > 3 && kind != BlockKind::Code {
                    continue;
                }
                last = self.opened.last().copied();
                let previous = last.map(|b| b.node);
                let (_, position) = r.position();
                if let Some((id, children, require)) = self.open_block(kind, parent, r)? {
                    self.arena.get_mut(id)?.pos =
                        Some(position.start + self.offset.max(0) as usize);
                    if require && previous == self.arena.get(parent)?.last {
                        if let Some(last) = last {
                            self.close_block(last, r)?;
                            self.opened.pop();
                            if self.transform(last.node)? {
                                continuable = false;
                                continue 'retry;
                            }
                        }
                    }
                    self.arena.get_mut(id)?.blank_previous = blank_line;
                    if let Some(previous) = previous {
                        if self.arena.get(previous)?.parent.is_none() {
                            if let Some(at) = self.opened.len().checked_sub(1) {
                                self.close_blocks(at, at, r)?;
                            }
                        }
                    }
                    self.arena.append(parent, id)?;
                    result = 2;
                    room(&mut self.opened, 1, &self.account)?;
                    self.opened.push(Block {
                        node: id,
                        parser: kind,
                    });
                    if children {
                        parent = id;
                        continue 'retry;
                    }
                    break;
                }
            }
            break;
        }
        if result == 0 && continuable {
            if let Some(last) = last {
                if self.continue_block(last, r)?.0 {
                    result = 1;
                }
            }
        }
        Ok(result)
    }
    fn blocks(&mut self, root: Id, r: &mut Reader<'a>) -> Result<()> {
        let mut stats = Vec::<Stat>::new();
        let result: Result<()> = (|| {
            loop {
                while let Some((line, _)) = r.peek_line()? {
                    if !blank(&line) {
                        break;
                    }
                    r.advance_line()?;
                }
                if r.peek_line()?.is_none() {
                    return Ok(());
                }
                if self.open_blocks(root, true, r)? != 2 {
                    return Ok(());
                }
                r.advance_line()?;
                stats.clear();
                while !self.opened.is_empty() {
                    let length = self.opened.len();
                    let mut last = length - 1;
                    for i in 0..length {
                        let b = self.opened[i];
                        let Some((line, _)) = r.peek_line()? else {
                            self.close_blocks(last, 0, r)?;
                            r.advance_line()?;
                            return Ok(());
                        };
                        let (line_num, _) = r.position();
                        room(&mut stats, 1, &self.account)?;
                        stats.push(Stat {
                            line: line_num,
                            level: i,
                            blank: blank(&line),
                        });
                        drop(line);
                        if !self.paragraph(Some(b.node)) {
                            let (cont, children) = self.continue_block(b, r)?;
                            if cont {
                                if children && i == last {
                                    let is_blank = stat_blank(line_num - 1, i + 1, &stats);
                                    self.open_blocks(b.node, is_blank, r)?;
                                    break;
                                }
                                continue;
                            }
                        }
                        let is_blank = stat_blank(line_num - 1, i, &stats);
                        let parent = if i == 0 {
                            root
                        } else {
                            self.opened[i - 1].node
                        };
                        let last_node = self.opened[last].node;
                        let result = self.open_blocks(parent, is_blank, r)?;
                        if result != 1 {
                            if self.opened.get(last).is_some_and(|b| b.node != last_node) {
                                if last == 0 {
                                    break;
                                }
                                last -= 1;
                            }
                            self.close_blocks(last, i, r)?;
                        }
                        break;
                    }
                    r.advance_line()?;
                }
            }
        })();
        let bytes = stats.capacity() * std::mem::size_of::<Stat>();
        drop(stats);
        let release = self.account.release(bytes);
        result?;
        release
    }
}
fn stat_blank(line: isize, level: usize, stats: &[Stat]) -> bool {
    if stats.is_empty() {
        return true;
    }
    let Some(start) = stats.len().checked_sub(1 + level) else {
        return false;
    };
    for s in stats[..=start].iter().rev() {
        if s.line == line && s.level <= level {
            return s.blank;
        }
        if s.line < line {
            break;
        }
    }
    false
}
