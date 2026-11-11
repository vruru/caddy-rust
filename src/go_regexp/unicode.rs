// Copyright The Go Authors. BSD-3-Clause.
// Range composition follows Go 1.27.3 regexp/syntax/parse.go and perl_groups.go.
use anyhow::{Result, anyhow, bail, ensure};
#[path = "go_unicode.rs"]
mod generated;
use generated::{CLASSES, FOLD_NEXT, RANGES};

pub(super) type Range = (u32, u32);
const MAX_RANGES: usize = 65_536;
const MAX_RUNE: u32 = 0x10ffff;
const DIGIT: &[Range] = &[(b'0' as u32, b'9' as u32)];
const WORD: &[Range] = &[(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)];
const PERL_SPACE: &[Range] = &[(9, 10), (12, 13), (32, 32)];
pub(super) fn push(out: &mut Vec<Range>, range: Range) -> Result<()> {
    ensure!(
        out.len() < MAX_RANGES,
        "regexp character class range limit exceeded"
    );
    out.push(range);
    Ok(())
}
pub(super) fn extend(out: &mut Vec<Range>, from: &mut Vec<Range>) -> Result<()> {
    ensure!(
        out.len()
            .checked_add(from.len())
            .is_some_and(|n| n <= MAX_RANGES),
        "regexp character class range limit exceeded"
    );
    out.append(from);
    Ok(())
}
pub(super) fn clean(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_unstable();
    let mut n = 0;
    for i in 0..ranges.len() {
        let (lo, hi) = ranges[i];
        if n > 0 && ranges[n - 1].1 + 1 >= lo {
            ranges[n - 1].1 = ranges[n - 1].1.max(hi);
        } else {
            ranges[n] = (lo, hi);
            n += 1;
        }
    }
    ranges.truncate(n);
    ranges
}
pub(super) fn negate(ranges: &[Range]) -> Vec<Range> {
    let mut last = 0;
    let mut out = Vec::with_capacity(ranges.len() + 1);
    for &(lo, hi) in ranges {
        if last < lo {
            out.push((last, lo - 1));
        }
        last = hi + 1;
    }
    if last <= MAX_RUNE {
        out.push((last, MAX_RUNE));
    }
    out
}
fn next_fold(cp: u32) -> u32 {
    FOLD_NEXT
        .binary_search_by_key(&cp, |x| x.0)
        .ok()
        .map_or(cp, |i| FOLD_NEXT[i].1)
}
pub(super) fn fold_range(lo: u32, hi: u32) -> Result<Vec<Range>> {
    let mut out = vec![(lo, hi)];
    let start = FOLD_NEXT.partition_point(|x| x.0 < lo);
    let end = FOLD_NEXT.partition_point(|x| x.0 <= hi);
    for &(original, first) in &FOLD_NEXT[start..end] {
        let mut cp = first;
        while cp != original {
            if cp < lo || cp > hi {
                push(&mut out, (cp, cp))?;
            }
            cp = next_fold(cp);
        }
    }
    Ok(clean(out))
}
fn add_table(out: &mut Vec<Range>, table: &[(u32, u32, u32)]) -> Result<()> {
    for &(lo, hi, stride) in table {
        if stride == 1 {
            push(out, (lo, hi))?;
        } else {
            for cp in (lo..=hi).step_by(stride as usize) {
                push(out, (cp, cp))?;
            }
        }
    }
    Ok(())
}
type Table = &'static [(u32, u32, u32)];
fn tables(name: &str) -> Option<(Table, Table)> {
    let i = CLASSES.binary_search_by_key(&name, |c| c.0).ok()?;
    let (_, a, b, c, d) = CLASSES[i];
    Some((&RANGES[a..a + b], &RANGES[c..c + d]))
}
fn contains(table: Table, cp: u32) -> bool {
    let i = table.partition_point(|p| p.1 < cp);
    table
        .get(i)
        .is_some_and(|&(lo, hi, stride)| cp >= lo && cp <= hi && (cp - lo).is_multiple_of(stride))
}
pub(super) fn is_name_character(c: char) -> bool {
    let cp = c as u32;
    c == '_'
        || c.is_ascii_alphanumeric()
        || (!c.is_ascii()
            && (contains(tables("L").unwrap().0, cp) || contains(tables("Nd").unwrap().0, cp)))
}
fn canonical(input: &str) -> Result<String> {
    ensure!(
        input.len() <= 4096,
        "regexp Unicode class name limit exceeded"
    );
    let mut out = String::new();
    for ch in input.chars().filter(|c| !matches!(c, ' ' | '-' | '_')) {
        let c = if out.is_empty() {
            ch.to_ascii_uppercase()
        } else {
            ch.to_ascii_lowercase()
        };
        out.push(c);
    }
    Ok(out)
}
fn from_table(name: &str, fold: bool, negative: bool) -> Result<Vec<Range>> {
    let name = canonical(name)?;
    if name == "Any" {
        return Ok(if negative {
            Vec::new()
        } else {
            vec![(0, MAX_RUNE)]
        });
    }
    if name == "Ascii" {
        let r = if fold {
            vec![(0, 127), (0x17f, 0x17f), (0x212a, 0x212a)]
        } else {
            vec![(0, 127)]
        };
        return Ok(if negative { negate(&r) } else { r });
    }
    let assigned = name == "Assigned";
    let (base, extras) = tables(if assigned { "Cn" } else { &name })
        .ok_or_else(|| anyhow!("unknown regexp Unicode class"))?;
    let mut ranges = Vec::new();
    add_table(&mut ranges, base)?;
    if fold && !assigned {
        add_table(&mut ranges, extras)?;
    }
    let ranges = clean(ranges);
    Ok(if negative != assigned {
        negate(&ranges)
    } else {
        ranges
    })
}
fn from_group(group: &[Range], fold: bool, negative: bool) -> Result<Vec<Range>> {
    let mut ranges = Vec::new();
    for &(lo, hi) in group {
        if fold {
            extend(&mut ranges, &mut fold_range(lo, hi)?)?;
        } else {
            push(&mut ranges, (lo, hi))?;
        }
    }
    let ranges = clean(ranges);
    Ok(if negative { negate(&ranges) } else { ranges })
}
pub(super) fn special(
    input: &str,
    fold: bool,
    in_class: bool,
) -> Result<Option<(Vec<Range>, &str)>> {
    if let Some(rest) = input.strip_prefix('\\')
        && let Some(code) = rest.as_bytes().first().copied()
    {
        if matches!(code, b'p' | b'P') {
            let rest = &rest[1..];
            let (name, after) = if let Some(rest) = rest.strip_prefix('{') {
                rest.split_once('}')
                    .ok_or_else(|| anyhow!("unterminated regexp Unicode class"))?
            } else {
                let c = rest
                    .chars()
                    .next()
                    .ok_or_else(|| anyhow!("missing regexp Unicode class"))?;
                rest.split_at(c.len_utf8())
            };
            let negative = code == b'P';
            let (name, negative) = name
                .strip_prefix('^')
                .map_or((name, negative), |s| (s, !negative));
            return Ok(Some((from_table(name, fold, negative)?, after)));
        }
        let group = match code.to_ascii_lowercase() {
            b'd' => Some(DIGIT),
            b'w' => Some(WORD),
            b's' => Some(PERL_SPACE),
            _ => None,
        };
        if let Some(group) = group {
            return Ok(Some((
                from_group(group, fold, code.is_ascii_uppercase())?,
                &rest[1..],
            )));
        }
    }
    if in_class
        && let Some(rest) = input.strip_prefix("[:")
        && let Some((name, after)) = rest.split_once(":]")
    {
        let (name, negative) = name.strip_prefix('^').map_or((name, false), |s| (s, true));
        let group: &[Range] = match name {
            "alnum" => &[(0x30, 0x39), (0x41, 0x5a), (0x61, 0x7a)],
            "alpha" => &[(0x41, 0x5a), (0x61, 0x7a)],
            "ascii" => &[(0, 0x7f)],
            "blank" => &[(9, 9), (32, 32)],
            "cntrl" => &[(0, 0x1f), (0x7f, 0x7f)],
            "digit" => DIGIT,
            "graph" => &[(0x21, 0x7e)],
            "lower" => &[(0x61, 0x7a)],
            "print" => &[(0x20, 0x7e)],
            "punct" => &[(0x21, 0x2f), (0x3a, 0x40), (0x5b, 0x60), (0x7b, 0x7e)],
            "space" => &[(9, 13), (32, 32)],
            "upper" => &[(0x41, 0x5a)],
            "word" => WORD,
            "xdigit" => &[(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)],
            _ => bail!("unknown regexp POSIX class"),
        };
        return Ok(Some((from_group(group, fold, negative)?, after)));
    }
    Ok(None)
}
