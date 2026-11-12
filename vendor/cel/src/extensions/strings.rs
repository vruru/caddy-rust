//! The strings extension library: member functions on `string` (and
//! `list(string).join`), and `strings.quote`, following cel-go's
//! `ext.Strings()`.
//!
//! Indices are in code points, not bytes, as in the rest of CEL.

mod format;

use super::{arg, iterable};
use crate::common::types::{CelInt, CelList, CelString, LIST_TYPE, STRING_TYPE};
use crate::common::value::{CowVal, Val};
use crate::{DeclarationError, Env, ExecutionError};

/// Registers the strings extension's overloads on `env`.
pub fn extension(env: &mut Env) -> Result<(), DeclarationError> {
    crate::add_member_overload!(env, fn char_at: (CelString, CelInt) -> Result<CelString>)?;
    crate::add_member_overload!(env, fn index_of: (CelString, CelString) -> CelInt)?;
    crate::add_member_overload!(env, fn index_of_offset: (CelString, CelString, CelInt) -> Result<CelInt>,
        name = "indexOf")?;
    crate::add_member_overload!(env, fn last_index_of: (CelString, CelString) -> CelInt)?;
    crate::add_member_overload!(env, fn last_index_of_offset: (CelString, CelString, CelInt) -> Result<CelInt>,
        name = "lastIndexOf")?;
    // Registered by hand, as the macro would downcast the receiver to a
    // `CelList`: `join` takes any `list`, like the stdlib's list overloads.
    env.add_member_overload("join", "list.join()", LIST_TYPE, vec![], join)?;
    env.add_member_overload(
        "join",
        "list.join(string)",
        LIST_TYPE,
        vec![STRING_TYPE],
        join_sep,
    )?;
    crate::add_member_overload!(env, fn lower_ascii: (CelString) -> CelString)?;
    crate::add_member_overload!(env, fn upper_ascii: (CelString) -> CelString)?;
    crate::add_member_overload!(env, fn trim: (CelString) -> CelString)?;
    crate::add_member_overload!(env, fn replace: (CelString, CelString, CelString) -> CelString)?;
    crate::add_member_overload!(env, fn replace_n: (CelString, CelString, CelString, CelInt) -> CelString,
        name = "replace")?;
    crate::add_member_overload!(env, fn split: (CelString, CelString) -> CelList)?;
    crate::add_member_overload!(env, fn split_n: (CelString, CelString, CelInt) -> CelList,
        name = "split")?;
    crate::add_member_overload!(env, fn substring: (CelString, CelInt) -> Result<CelString>)?;
    crate::add_member_overload!(env, fn substring_range: (CelString, CelInt, CelInt) -> Result<CelString>,
        name = "substring")?;
    // By hand, as `join` is: `format` takes any `list`.
    env.add_member_overload(
        "format",
        "string.format(list)",
        STRING_TYPE,
        vec![LIST_TYPE],
        format::format,
    )?;
    crate::add_overload!(env, fn quote: (CelString) -> CelString, name = "strings.quote")?;
    crate::add_member_overload!(env, fn reverse: (CelString) -> CelString)?;
    Ok(())
}

fn out_of_range(function: &str, idx: i64) -> ExecutionError {
    ExecutionError::function_error(function, format!("index out of range: {idx}"))
}

fn char_at(this: &CelString<'_>, idx: &CelInt) -> Result<CelString<'static>, ExecutionError> {
    let idx = *idx.inner();
    let len = this.chars().count() as i64;
    if idx < 0 || idx > len {
        return Err(out_of_range("charAt", idx));
    }
    Ok(this
        .chars()
        .nth(idx as usize)
        .map(|c| c.to_string())
        .unwrap_or_default()
        .into())
}

/// The code-point index of the first occurrence of `needle` in `runes`, at or
/// after `offset`.
fn find_runes(runes: &[char], needle: &[char], offset: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(offset);
    }
    runes[offset..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + offset)
}

/// The code-point index of the last occurrence of `needle` in `runes` that
/// starts at or before `offset`.
fn rfind_runes(runes: &[char], needle: &[char], offset: usize) -> Option<usize> {
    if needle.len() > runes.len() {
        return None;
    }
    let last = offset.min(runes.len() - needle.len());
    (0..=last)
        .rev()
        .find(|&i| runes[i..i + needle.len()] == *needle)
}

fn index_of(this: &CelString<'_>, needle: &CelString<'_>) -> CelInt {
    let runes: Vec<char> = this.chars().collect();
    let needle: Vec<char> = needle.chars().collect();
    find_runes(&runes, &needle, 0)
        .map_or(-1, |i| i as i64)
        .into()
}

fn index_of_offset(
    this: &CelString<'_>,
    needle: &CelString<'_>,
    offset: &CelInt,
) -> Result<CelInt, ExecutionError> {
    let offset = *offset.inner();
    let runes: Vec<char> = this.chars().collect();
    if offset < 0 {
        return Err(out_of_range("indexOf", offset));
    }
    if needle.is_empty() {
        return Ok(offset.min(runes.len() as i64).into());
    }
    if offset >= runes.len() as i64 {
        return Err(out_of_range("indexOf", offset));
    }
    let needle: Vec<char> = needle.chars().collect();
    Ok(find_runes(&runes, &needle, offset as usize)
        .map_or(-1, |i| i as i64)
        .into())
}

fn last_index_of(this: &CelString<'_>, needle: &CelString<'_>) -> CelInt {
    let runes: Vec<char> = this.chars().collect();
    let needle: Vec<char> = needle.chars().collect();
    rfind_runes(&runes, &needle, runes.len())
        .map_or(-1, |i| i as i64)
        .into()
}

fn last_index_of_offset(
    this: &CelString<'_>,
    needle: &CelString<'_>,
    offset: &CelInt,
) -> Result<CelInt, ExecutionError> {
    let offset = *offset.inner();
    let runes: Vec<char> = this.chars().collect();
    if offset < 0 {
        return Err(out_of_range("lastIndexOf", offset));
    }
    if needle.is_empty() {
        return Ok(offset.min(runes.len() as i64).into());
    }
    if offset >= runes.len() as i64 {
        return Err(out_of_range("lastIndexOf", offset));
    }
    let needle: Vec<char> = needle.chars().collect();
    Ok(rfind_runes(&runes, &needle, offset as usize)
        .map_or(-1, |i| i as i64)
        .into())
}

fn join<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    match args.as_slice() {
        [list] => join_with(list.as_ref(), ""),
        _ => Err(ExecutionError::invalid_argument_count(1, args.len())),
    }
}

fn join_sep<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    match args.as_slice() {
        [list, sep] => join_with(list.as_ref(), arg::<CelString>(sep.as_ref())?.inner()),
        _ => Err(ExecutionError::invalid_argument_count(2, args.len())),
    }
}

/// Concatenates the strings of any iterable `list`, `sep` between each.
fn join_with<'b, 'v>(list: &dyn Val, sep: &str) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let mut items = iterable(list)?.iter();
    let mut parts = Vec::new();
    while let Some(item) = items.next() {
        parts.push(arg::<CelString>(item)?.inner());
    }
    Ok(CowVal::owned(CelString::from(parts.join(sep))))
}

fn lower_ascii(this: &CelString<'_>) -> CelString<'static> {
    this.to_ascii_lowercase().into()
}

fn upper_ascii(this: &CelString<'_>) -> CelString<'static> {
    this.to_ascii_uppercase().into()
}

fn trim(this: &CelString<'_>) -> CelString<'static> {
    this.trim().to_owned().into()
}

fn replace(this: &CelString<'_>, from: &CelString<'_>, to: &CelString<'_>) -> CelString<'static> {
    this.replace(from.inner(), to.inner()).into()
}

/// Replaces the first `n` occurrences, or all of them when `n` is negative.
fn replace_n(
    this: &CelString<'_>,
    from: &CelString<'_>,
    to: &CelString<'_>,
    n: &CelInt,
) -> CelString<'static> {
    match usize::try_from(*n.inner()) {
        Ok(n) => this.replacen(from.inner(), to.inner(), n).into(),
        Err(_) => replace(this, from, to),
    }
}

fn split(this: &CelString<'_>, sep: &CelString<'_>) -> CelList<'static> {
    split_n(this, sep, &CelInt::from(-1))
}

/// Splits into at most `n` parts, the last holding the unsplit remainder: none
/// when `n` is zero, all of them when it is negative. An empty separator splits
/// between code points.
fn split_n(this: &CelString<'_>, sep: &CelString<'_>, n: &CelInt) -> CelList<'static> {
    let n = *n.inner();
    let parts: Vec<&str> = match (usize::try_from(n), sep.is_empty()) {
        (Ok(0), _) => Vec::new(),
        (Ok(n), true) => {
            let mut parts: Vec<&str> = Vec::new();
            let mut rest: &str = this;
            while let Some(c) = rest.chars().next() {
                if parts.len() + 1 == n {
                    break;
                }
                let (head, tail) = rest.split_at(c.len_utf8());
                parts.push(head);
                rest = tail;
            }
            if !rest.is_empty() {
                parts.push(rest);
            }
            parts
        }
        (Ok(n), false) => this.splitn(n, sep.inner()).collect(),
        (Err(_), true) => this
            .char_indices()
            .map(|(i, c)| &this[i..i + c.len_utf8()])
            .collect(),
        (Err(_), false) => this.split(sep.inner()).collect(),
    };
    parts
        .into_iter()
        .map(|s| Box::new(CelString::from(s.to_owned())) as Box<dyn Val>)
        .collect::<Vec<_>>()
        .into()
}

fn substring(this: &CelString<'_>, start: &CelInt) -> Result<CelString<'static>, ExecutionError> {
    let len = this.chars().count() as i64;
    if *start.inner() < 0 || *start.inner() > len {
        return Err(out_of_range("substring", *start.inner()));
    }
    substring_range(this, start, &CelInt::from(len))
}

fn substring_range(
    this: &CelString<'_>,
    start: &CelInt,
    end: &CelInt,
) -> Result<CelString<'static>, ExecutionError> {
    let (start, end) = (*start.inner(), *end.inner());
    let len = this.chars().count() as i64;
    if start > end {
        return Err(ExecutionError::function_error(
            "substring",
            format!("invalid substring range. start: {start}, end: {end}"),
        ));
    }
    if start < 0 || start > len {
        return Err(out_of_range("substring", start));
    }
    if end > len {
        return Err(out_of_range("substring", end));
    }
    Ok(this
        .chars()
        .skip(start as usize)
        .take((end - start) as usize)
        .collect::<String>()
        .into())
}

/// `this` as a double-quoted CEL string literal: the characters CEL escapes
/// are escaped.
fn quote(this: &CelString<'_>) -> CelString<'static> {
    let mut quoted = String::with_capacity(this.len() + 2);
    quoted.push('"');
    for c in this.chars() {
        match c {
            '\x07' => quoted.push_str("\\a"),
            '\x08' => quoted.push_str("\\b"),
            '\x0c' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\x0b' => quoted.push_str("\\v"),
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted.into()
}

/// Reverses the code points of `this`.
fn reverse(this: &CelString<'_>) -> CelString<'static> {
    this.chars().rev().collect::<String>().into()
}
