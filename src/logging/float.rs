// Copyright 2016 Uber Technologies, Inc. SPDX-License-Identifier: MIT
//! Zap uses strconv.AppendFloat('f', -1, bitSize), unlike encoding/json's
//! exponent cutoffs. Expand the shortest Ryū significand into fixed notation.
use anyhow::{Result, ensure};
pub(super) fn f64_text(value: f64) -> Result<String> {
    ensure!(
        value.is_finite(),
        "nonfinite log float requires quoted encoding"
    );
    let mut buffer = ryu::Buffer::new();
    fixed(buffer.format_finite(value))
}
pub(super) fn f32_text(value: f32) -> Result<String> {
    ensure!(
        value.is_finite(),
        "nonfinite log float requires quoted encoding"
    );
    let mut buffer = ryu::Buffer::new();
    fixed(buffer.format_finite(value))
}
fn fixed(shortest: &str) -> Result<String> {
    let (negative, text) = shortest
        .strip_prefix('-')
        .map_or((false, shortest), |s| (true, s));
    let (significand, exponent) = match text.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>()?),
        None => (text, 0),
    };
    let dot = significand.find('.').unwrap_or(significand.len()) as i32;
    let mut digits = String::with_capacity(significand.len());
    for b in significand.bytes() {
        if b != b'.' {
            digits.push(char::from(b));
        }
    }
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let position = dot + exponent;
    let mut output = String::with_capacity(328);
    if negative {
        output.push('-');
    }
    if position <= 0 {
        output.push_str("0.");
        for _ in 0..-position {
            output.push('0');
        }
        output.push_str(&digits);
    } else if position as usize >= digits.len() {
        output.push_str(&digits);
        for _ in digits.len()..position as usize {
            output.push('0');
        }
    } else {
        output.push_str(&digits[..position as usize]);
        output.push('.');
        output.push_str(&digits[position as usize..]);
    }
    ensure!(output.len() <= 328, "log float output overflow");
    Ok(output)
}
/// fmt.Fprint's default float formatting is strconv 'g', precision -1.
/// It differs from both Zap JSON ('f') and encoding/json's exponent cutoffs.
pub(super) fn general_f64(value: f64) -> Result<String> {
    if value.is_nan() {
        return Ok("NaN".into());
    }
    if value.is_infinite() {
        return Ok(if value.is_sign_negative() {
            "-Inf"
        } else {
            "+Inf"
        }
        .into());
    }
    let fixed = f64_text(value)?;
    let (negative, text) = fixed
        .strip_prefix('-')
        .map_or((false, fixed.as_str()), |s| (true, s));
    if text == "0" {
        return Ok(fixed);
    }
    let integer = text.find('.').unwrap_or(text.len());
    let first = text
        .bytes()
        .position(|b| b != b'0' && b != b'.')
        .expect("nonzero finite float");
    let exponent = if first < integer {
        integer as i32 - first as i32 - 1
    } else {
        integer as i32 - first as i32
    };
    if (-4..6).contains(&exponent) {
        return Ok(fixed);
    }
    let mut digits: String = text[first..].chars().filter(|c| *c != '.').collect();
    while digits.ends_with('0') {
        digits.pop();
    }
    let mut result = if negative { "-" } else { "" }.to_owned();
    result.push(char::from(digits.as_bytes()[0]));
    if digits.len() > 1 {
        result.push('.');
        result.push_str(&digits[1..]);
    }
    result.push('e');
    result.push(if exponent < 0 { '-' } else { '+' });
    let exponent = exponent.unsigned_abs();
    if exponent < 10 {
        result.push('0');
    }
    result.push_str(&exponent.to_string());
    Ok(result)
}
