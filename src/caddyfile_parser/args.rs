// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Result, bail};
use std::ops::Range;

pub(crate) fn parse_variadic(
    text: &str,
    arg_count: usize,
    warnings: &mut Vec<String>,
) -> Option<Range<usize>> {
    let rest = text.strip_prefix("{args[")?;
    if !rest.ends_with("]}") {
        return None;
    }

    let arg_range = &rest[..rest.len() - 2];

    if arg_range.is_empty() {
        warnings.push("variadic_empty_index".to_string());
        return None;
    }

    let (start_str, end_str, found_colon) = split_at_first_colon(arg_range);

    if !found_colon {
        return None;
    }

    if start_str.contains('}') || end_str.contains('{') {
        return None;
    }

    let mut start_index: usize = 0;
    let mut end_index: usize = arg_count;

    if !start_str.is_empty() {
        match parse_strict_int(start_str) {
            Ok(val) => {
                if val < 0 {
                    warnings.push("variadic_invalid_start_negative".to_string());
                    return None;
                }
                start_index = usize::try_from(val).ok()?;
            }
            Err(_) => {
                warnings.push("variadic_invalid_start".to_string());
                return None;
            }
        }
    }

    if !end_str.is_empty() {
        match parse_strict_int(end_str) {
            Ok(val) => {
                if val < 0 {
                    warnings.push("variadic_invalid_end_negative".to_string());
                    return None;
                }
                end_index = usize::try_from(val).ok()?;
            }
            Err(_) => {
                warnings.push("variadic_invalid_end".to_string());
                return None;
            }
        }
    }

    if start_index > end_index || end_index > arg_count {
        warnings.push("variadic_out_of_bounds".to_string());
        return None;
    }

    Some(start_index..end_index)
}

pub(crate) fn replace_args(
    input: &str,
    args: &[String],
    warnings: &mut Vec<String>,
    max_bytes: usize,
) -> Result<String> {
    if input.is_empty() {
        return Ok(String::new());
    }

    let mut sb = String::with_capacity(input.len().min(max_bytes));
    let bytes = input.as_bytes();
    let len = bytes.len();

    let mut i = 0;
    let mut last_write_cursor = 0;
    let mut unclosed_count = 0;
    let mut close_cursor = 0;
    let mut newline_cursor = 0;
    let mut colon_cursor = 0;

    const PH_OPEN: u8 = b'{';
    const PH_CLOSE: u8 = b'}';
    const PH_ESCAPE: u8 = b'\\';

    while i < len {
        if warnings.len() > 65_536 {
            bail!("Caddyfile placeholder warning budget exceeded");
        }
        if i > 0 && bytes[i - 1] == PH_ESCAPE && (bytes[i] == PH_CLOSE || bytes[i] == PH_OPEN) {
            push(&mut sb, &input[last_write_cursor..i - 1], max_bytes)?;
            last_write_cursor = i;
            i += 1;
            continue;
        }

        if bytes[i] != PH_OPEN {
            i += 1;
            continue;
        }

        if unclosed_count > 100 {
            warnings.push("too_many_unclosed_placeholders".to_string());
            return Ok(String::new());
        }

        close_cursor = close_cursor.max(i);
        while close_cursor < len
            && !(bytes[close_cursor] == PH_CLOSE
                && (close_cursor == 0
                    || close_cursor + 1 == len
                    || bytes[close_cursor - 1] != PH_ESCAPE))
        {
            close_cursor += 1;
        }
        if close_cursor == len {
            unclosed_count += 1;
            i += 1;
            continue;
        }
        let final_end = close_cursor;

        push(&mut sb, &input[last_write_cursor..i], max_bytes)?;

        let key = &input[i + 1..final_end];
        newline_cursor = newline_cursor.max(i + 1);
        while newline_cursor < len && bytes[newline_cursor] != b'\n' {
            newline_cursor += 1;
        }
        let key_has_newline = newline_cursor < final_end;
        colon_cursor = colon_cursor.max(i + 1);
        while colon_cursor < len && bytes[colon_cursor] != b':' {
            colon_cursor += 1;
        }
        let key_has_colon = colon_cursor < final_end;

        let warning_count = warnings.len();
        let value = get_arg_value(key, key_has_newline, key_has_colon, args, warnings);
        if warnings[warning_count..]
            .iter()
            .any(|s| s == "args_deprecated_negative_index" || s == "args_index_negative")
        {
            bail!("Caddyfile argument index must not be negative");
        }

        let Some(value) = value else {
            last_write_cursor = i;
            i += 1;
            continue;
        };

        push(&mut sb, value, max_bytes)?;

        i = final_end;
        last_write_cursor = i + 1;

        i += 1;
    }

    push(&mut sb, &input[last_write_cursor..], max_bytes)?;

    Ok(sb)
}

fn push(out: &mut String, value: &str, limit: usize) -> Result<()> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|size| size > limit)
    {
        bail!("Caddyfile argument expansion byte limit exceeded");
    }
    out.push_str(value);
    Ok(())
}

fn split_at_first_colon(s: &str) -> (&str, &str, bool) {
    match s.find(':') {
        Some(pos) => (&s[..pos], &s[pos + 1..], true),
        None => (s, "", false),
    }
}

fn parse_strict_int(s: &str) -> std::result::Result<isize, ()> {
    let digits = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    s.parse::<isize>().map_err(|_| ())
}

fn get_arg_value<'a>(
    key: &str,
    key_has_newline: bool,
    key_has_colon: bool,
    args: &'a [String],
    warnings: &mut Vec<String>,
) -> Option<&'a str> {
    if let Some(rest) = key.strip_prefix("args.") {
        if rest.is_empty() || key_has_newline {
            return None;
        }
        let index_str = rest;

        match parse_strict_int(index_str) {
            Ok(val) => {
                if val < 0 {
                    warnings.push("args_deprecated_negative_index".to_string());
                    return None;
                }
                let index = usize::try_from(val).ok()?;
                if index >= args.len() {
                    warnings.push("args_deprecated_index_out_of_bounds".to_string());
                    return None;
                }
                warnings.push("args_deprecated_usage".to_string());
                return Some(&args[index]);
            }
            Err(_) => {
                warnings.push("args_deprecated_invalid_index".to_string());
                return None;
            }
        }
    }

    if key.starts_with("args[") && key.ends_with(']') {
        let inner = &key[5..key.len() - 1];
        if inner.is_empty() || key_has_newline {
            return None;
        }

        if key_has_colon {
            warnings.push("args_variadic_not_standalone".to_string());
            return None;
        }

        match parse_strict_int(inner) {
            Ok(val) => {
                if val < 0 {
                    warnings.push("args_index_negative".to_string());
                    return None;
                }
                let index = usize::try_from(val).ok()?;
                if index >= args.len() {
                    warnings.push("args_index_out_of_bounds".to_string());
                    return None;
                }
                return Some(&args[index]);
            }
            Err(_) => {
                warnings.push("args_index_invalid".to_string());
                return None;
            }
        }
    }

    None
}
