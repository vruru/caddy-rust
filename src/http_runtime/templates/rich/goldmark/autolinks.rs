//! Goldmark core autolink and GFM linkify scanners (MIT).
use super::{
    ast::{Id, Kind},
    parse_util::*,
    parser::Parser,
    segment::Segment,
    text::Read,
};
use gotmpl::Result;
fn email(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    while s
        .get(i)
        .is_some_and(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(b))
    {
        i += 1;
    }
    if i == 0 || s.get(i) != Some(&b'@') {
        return None;
    }
    i += 1;
    if !s.get(i).is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }
    loop {
        let start = i;
        let mut end = i;
        while s
            .get(i)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && i - start < 63
        {
            if s[i].is_ascii_alphanumeric() {
                end = i + 1;
            }
            i += 1;
        }
        i = end;
        if s.get(i) == Some(&b'.') && s.get(i + 1).is_some_and(u8::is_ascii_alphanumeric) {
            i += 1;
            continue;
        }
        return Some(i);
    }
}
fn url(s: &[u8]) -> Option<usize> {
    if !s.first().is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut i = 1;
    while s
        .get(i)
        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
    {
        i += 1;
    }
    if i == 1 || i > 33 || s.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while s
        .get(i)
        .is_some_and(|b| *b > 32 && !matches!(b, b'<' | b'>'))
    {
        i += 1;
    }
    Some(i)
}
fn host(s: u8) -> bool {
    s.is_ascii_alphanumeric() || b"-@:%._+~#=".contains(&s)
}
fn gfm_url(s: &[u8], www: bool) -> Option<usize> {
    let start = if www {
        4
    } else if s.starts_with(b"https://") {
        8
    } else if s.starts_with(b"http://") {
        7
    } else if s.starts_with(b"ftp://") {
        6
    } else {
        return None;
    };
    let mut max = start;
    while s.get(max).is_some_and(|b| host(*b)) && max - start < 256 {
        max += 1;
    }
    let mut end = None;
    for i in (start + 1..=max).rev() {
        if s.get(i) != Some(&b'.') {
            continue;
        }
        let mut next = i + 1;
        while s.get(next).is_some_and(u8::is_ascii_lowercase) {
            next += 1;
        }
        if next > i + 1 {
            end = Some(next);
            break;
        }
    }
    let mut end = end?;
    if !www && s.get(end) == Some(&b':') {
        let begin = end + 1;
        let mut next = begin;
        while s.get(next).is_some_and(u8::is_ascii_digit) {
            next += 1;
        }
        if next > begin {
            end = next;
        }
    }
    if s.get(end).is_some_and(|b| matches!(b, b'/' | b'#' | b'?')) {
        end += 1;
        while s.get(end).is_some_and(|b| {
            b.is_ascii_alphanumeric()
                || b"-@:%_+.~#!?&/=();,'\">^{}[]`".contains(b)
                || !www && *b == b'$'
        }) {
            end += 1;
        }
    }
    Some(end)
}
impl<'a> Parser<'a> {
    pub(super) fn angle_autolink(&mut self, r: &mut impl Read<'a>) -> Result<Option<Id>> {
        let Some((line, s)) = r.peek_line()? else {
            return Ok(None);
        };
        if line.len() < 2 {
            return Ok(None);
        }
        let (email_kind, end) = if let Some(end) = email(&line[1..]) {
            (true, end + 1)
        } else if let Some(end) = url(&line[1..]) {
            (false, end + 1)
        } else {
            return Ok(None);
        };
        if line.get(end) != Some(&b'>') {
            return Ok(None);
        }
        let value = Segment::new(s.start + 1, s.start + end);
        drop(line);
        r.advance(end + 1)?;
        Ok(Some(self.arena.add(Kind::AutoLink {
            email: email_kind,
            protocol: None,
            value,
        })?))
    }
    pub(super) fn linkify(&mut self, parent: Id, r: &mut impl Read<'a>) -> Result<Option<Id>> {
        let Some((line, s)) = r.peek_line()? else {
            return Ok(None);
        };
        let consumes = usize::from(
            line.first()
                .is_some_and(|b| matches!(b, b' ' | b'*' | b'_' | b'~' | b'(')),
        );
        let value = &line[consumes..];
        let mut protocol = None;
        let mut is_email = false;
        let mut end = gfm_url(value, false);
        if end.is_none() && value.starts_with(b"www.") {
            end = gfm_url(value, true);
            protocol = Some(b"http".as_slice());
        }
        if end.is_none() {
            if value.first().is_some_and(u8::is_ascii_punctuation) {
                return Ok(None);
            }
            let Some(mut n) = email(value) else {
                return Ok(None);
            };
            let Some(at) = value.iter().position(|b| *b == b'@') else {
                return Ok(None);
            };
            if n <= at + 1 || !value[at..n.saturating_sub(1)].contains(&b'.') {
                return Ok(None);
            }
            if value.get(n - 1) == Some(&b'.') {
                n -= 1;
            }
            if value.get(n).is_some_and(|b| matches!(b, b'-' | b'_')) {
                return Ok(None);
            }
            end = Some(n);
            is_email = true;
        }
        let mut end = end.ok_or_else(invalid)?;
        while end > 1
            && matches!(
                value[end - 1],
                b'?' | b'!' | b'.' | b',' | b':' | b'*' | b'_' | b'~'
            )
        {
            end -= 1;
        }
        if value.get(end - 1) == Some(&b')') {
            let close = value[..end].iter().filter(|b| **b == b')').count();
            let open = value[..end].iter().filter(|b| **b == b'(').count();
            end = end.saturating_sub(close.saturating_sub(open));
        } else if value.get(end - 1) == Some(&b';') {
            let mut j = end - 1;
            while j > 0 && value[j - 1].is_ascii_alphanumeric() {
                j -= 1;
            }
            if j > 0 && j != end - 1 && value[j - 1] == b'&' {
                end = j - 1;
            }
        }
        if consumes != 0 {
            self.arena
                .append_text_segment(parent, s.with_stop(s.start + 1))?;
        }
        let segment = Segment::new(s.start + consumes, s.start + consumes + end);
        drop(line);
        r.advance(consumes + end)?;
        Ok(Some(self.arena.add(Kind::AutoLink {
            email: is_email,
            protocol,
            value: segment,
        })?))
    }
}
