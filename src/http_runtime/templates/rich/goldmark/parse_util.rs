//! Goldmark 1.8.6 parser byte helpers (MIT, see html_render.rs).
use super::{
    output::Output,
    segment::{Bytes, Segment, is_space},
    text::Read,
};
use gotmpl::{BudgetAccount, Result, TemplateError};
pub(super) fn invalid() -> TemplateError {
    TemplateError::Exec("invalid Markdown parser state".into())
}
pub(super) fn blank(s: &[u8]) -> bool {
    s.iter().all(|b| is_space(*b))
}
pub(super) fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().take_while(|b| is_space(**b)).count();
    let end = s.len()
        - s[start..]
            .iter()
            .rev()
            .take_while(|b| is_space(**b))
            .count();
    &s[start..end]
}
pub(super) fn tab(pos: isize) -> isize {
    4 - pos % 4
}
pub(super) fn indent_width(s: &[u8], current: isize) -> (isize, usize) {
    let mut w = 0;
    let mut pos = 0;
    for b in s {
        match b {
            b' ' => w += 1,
            b'\t' => w += tab(current + w),
            _ => break,
        }
        pos += 1;
    }
    (w, pos)
}
pub(super) fn indent_position(
    s: &[u8],
    current: isize,
    padding: usize,
    width: isize,
) -> Option<(usize, usize)> {
    if width == 0 {
        return Some((0, padding));
    }
    let (mut w, mut i, mut p) = (0, 0, padding);
    while i < s.len() {
        if p > 0 {
            p -= 1;
            w += 1;
            i += 1;
            continue;
        }
        if s[i] == b'\t' && w < width {
            w += tab(current + w);
        } else if s[i] == b' ' && w < width {
            w += 1;
        } else {
            break;
        }
        i += 1;
    }
    if w >= width {
        Some((i.saturating_sub(padding), (w - width) as usize))
    } else {
        None
    }
}
pub(super) fn setext(line: &[u8]) -> Option<u8> {
    let start = line.iter().take_while(|b| **b == b' ').count();
    if start > 3 {
        return None;
    }
    let rest = trim(&line[start..]);
    let c = *rest.first()?;
    if matches!(c, b'=' | b'-') && rest.iter().all(|b| *b == c) {
        Some(c)
    } else {
        None
    }
}
pub(super) fn thematic(line: &[u8], offset: isize) -> bool {
    let (w, pos) = indent_width(line, offset);
    if w > 3 {
        return false;
    }
    let mut mark = 0;
    let mut count = 0;
    for b in &line[pos..] {
        if is_space(*b) {
            continue;
        }
        if mark == 0 {
            if !matches!(b, b'*' | b'-' | b'_') {
                return false;
            }
            mark = *b;
        }
        if *b != mark {
            return false;
        }
        count += 1;
    }
    count > 2
}
pub(super) fn closure(line: &[u8], open: u8, close: u8) -> Option<usize> {
    let mut i = 0;
    while i < line.len() {
        if line[i] == b'\\' && line.get(i + 1).is_some_and(u8::is_ascii_punctuation) {
            i += 2;
            continue;
        }
        if line[i] == close {
            return Some(i);
        }
        if line[i] == open {
            return None;
        }
        i += 1;
    }
    None
}
pub(super) fn skip_spaces<'a>(r: &mut impl Read<'a>) -> Result<usize> {
    let mut count = 0;
    loop {
        let Some((line, _)) = r.peek_line()? else {
            break;
        };
        let n = line.iter().take_while(|b| is_space(**b)).count();
        let length = line.len();
        drop(line);
        if n == 0 {
            break;
        }
        count += n;
        if n == length {
            r.advance_line()?;
        } else {
            r.advance(n)?;
            break;
        }
    }
    Ok(count)
}
pub(super) fn find_closure<'a>(
    r: &mut impl Read<'a>,
    open: u8,
    close: u8,
    account: &BudgetAccount,
) -> Result<Option<Bytes<'a>>> {
    let mut out = Output::new(account, 1 << 20);
    loop {
        let Some((line, _)) = r.peek_line()? else {
            return Ok(None);
        };
        let mut i = 0;
        while i < line.len() {
            account.charge_work(1)?;
            if line[i] == b'\\' && line.get(i + 1).is_some_and(u8::is_ascii_punctuation) {
                i += 2;
                continue;
            }
            if line[i] == close {
                out.write(&line[..i])?;
                drop(line);
                r.advance(i + 1)?;
                return Ok(Some(Bytes::Owned(out.into_bytes()?)));
            }
            if line[i] == open {
                return Ok(None);
            }
            i += 1;
        }
        out.write(&line)?;
        drop(line);
        r.advance_line()?;
    }
}
pub(super) fn destination<'a>(r: &mut impl Read<'a>) -> Result<Option<Bytes<'a>>> {
    skip_spaces(r)?;
    let Some((line, s)) = r.peek_line()? else {
        return Ok(None);
    };
    let mut i = if line.first() == Some(&b'<') { 1 } else { 0 };
    let angle = i == 1;
    let start = i;
    let mut opened = 0;
    while i < line.len() {
        let c = line[i];
        if c == b'\\' && line.get(i + 1).is_some_and(u8::is_ascii_punctuation) {
            i += 2;
            continue;
        }
        if angle {
            if c == b'>' {
                let value = r.value(Segment::new(s.start + start, s.start + i))?;
                drop(line);
                r.advance(i + 1)?;
                return Ok(Some(value));
            }
        } else if c == b'(' {
            opened += 1;
        } else if c == b')' {
            opened -= 1;
            if opened < 0 {
                break;
            }
        } else if is_space(c) {
            break;
        }
        i += 1;
    }
    if angle {
        return Ok(None);
    }
    let value = r.value(Segment::new(s.start, s.start + i))?;
    drop(line);
    r.advance(i)?;
    if i == 0 { Ok(None) } else { Ok(Some(value)) }
}
pub(super) fn title<'a>(
    r: &mut impl Read<'a>,
    account: &BudgetAccount,
) -> Result<Option<Bytes<'a>>> {
    skip_spaces(r)?;
    let open = r.peek();
    if !matches!(open, b'"' | b'\'' | b'(') {
        return Ok(None);
    }
    r.advance(1)?;
    find_closure(r, open, if open == b'(' { b')' } else { open }, account)
}
