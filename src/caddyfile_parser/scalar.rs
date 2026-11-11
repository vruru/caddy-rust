// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Ports readFloat, underscoreOK and atofHex from Go 1.27.3.
// Decimal conversion rounds directly to the requested Rust float width.
use std::borrow::Cow;

struct FloatInfo {
    mantbits: u32,
    expbits: u32,
    bias: i64,
}
const FLOAT64INFO: FloatInfo = FloatInfo {
    mantbits: 52,
    expbits: 11,
    bias: -1023,
};

const FLOAT32INFO: FloatInfo = FloatInfo {
    mantbits: 23,
    expbits: 8,
    bias: -127,
};

enum FloatToken<'a> {
    Nan,
    Infinity {
        negative: bool,
    },
    Hex {
        mantissa: u64,
        exponent: i64,
        negative: bool,
        truncated: bool,
    },
    Decimal(Cow<'a, str>),
}
pub(crate) fn parse_float(s: &str) -> Option<f64> {
    match float_token(s)? {
        FloatToken::Nan => Some(f64::NAN),
        FloatToken::Infinity { negative } => Some(if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        }),
        FloatToken::Hex {
            mantissa,
            exponent,
            negative,
            truncated,
        } => {
            atof_hex_bits(&FLOAT64INFO, mantissa, exponent, negative, truncated).map(f64::from_bits)
        }
        FloatToken::Decimal(clean) => clean.parse::<f64>().ok().filter(|v| v.is_finite()),
    }
}
pub(crate) fn parse_float32(s: &str) -> Option<f32> {
    match float_token(s)? {
        FloatToken::Nan => Some(f32::NAN),
        FloatToken::Infinity { negative } => Some(if negative {
            f32::NEG_INFINITY
        } else {
            f32::INFINITY
        }),
        FloatToken::Hex {
            mantissa,
            exponent,
            negative,
            truncated,
        } => atof_hex_bits(&FLOAT32INFO, mantissa, exponent, negative, truncated)
            .map(|bits| f32::from_bits(bits as u32)),
        FloatToken::Decimal(clean) => clean.parse::<f32>().ok().filter(|v| v.is_finite()),
    }
}
fn float_token(s: &str) -> Option<FloatToken<'_>> {
    if s.len() > 16 << 20 {
        return None;
    }
    if s.eq_ignore_ascii_case("nan") {
        return Some(FloatToken::Nan);
    }
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    if unsigned.eq_ignore_ascii_case("inf") || unsigned.eq_ignore_ascii_case("infinity") {
        return Some(FloatToken::Infinity {
            negative: s.starts_with('-'),
        });
    }
    let b = s.as_bytes();
    let (mantissa, exponent, negative, truncated, hex, n, ok) = read_float(s, b, b.len());
    if !ok || n != b.len() {
        return None;
    }
    if hex {
        return Some(FloatToken::Hex {
            mantissa,
            exponent,
            negative,
            truncated,
        });
    }
    let clean = if s.contains('_') {
        Cow::Owned(s.chars().filter(|c| *c != '_').collect())
    } else {
        Cow::Borrowed(s)
    };
    Some(FloatToken::Decimal(clean))
}

fn read_float(_s: &str, b: &[u8], len: usize) -> (u64, i64, bool, bool, bool, usize, bool) {
    let mut underscores = false;
    let mut i = 0usize;
    let mut neg = false;
    let mut trunc = false;
    let mut mantissa = 0u64;
    let mut hex = false;
    let mut exp = 0i64;

    if i >= len {
        return (0, 0, false, false, false, 0, false);
    }

    if b[i] == b'+' {
        i += 1;
    } else if b[i] == b'-' {
        i += 1;
        neg = true;
    }

    let mut base = 10u64;
    let mut exp_char = b'e';

    if i + 2 < len && b[i] == b'0' && to_ascii_lowercase(b[i + 1]) == b'x' {
        base = 16;
        i += 2;
        exp_char = b'p';
        hex = true;
    }
    let max_mant_digits = if hex { 16 } else { 19 };

    let mut sawdot = false;
    let mut sawdigits = false;
    let mut nd = 0i64;
    let mut ndmant = 0usize;
    let mut dp = 0i64;

    while i < len {
        let c = b[i];
        if c == b'_' {
            underscores = true;
            i += 1;
            continue;
        }

        if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
            i += 1;
            continue;
        }

        if c.is_ascii_digit() {
            sawdigits = true;
            if c == b'0' && nd == 0 {
                dp -= 1;
                i += 1;
                continue;
            }
            nd += 1;
            if ndmant < max_mant_digits {
                mantissa *= base;
                mantissa += (c - b'0') as u64;
                ndmant += 1;
            } else if c != b'0' {
                trunc = true;
            }
            i += 1;
            continue;
        }

        if base == 16 && (b'a'..=b'f').contains(&c) {
            sawdigits = true;
            nd += 1;
            if ndmant < max_mant_digits {
                mantissa *= 16;
                mantissa += (c - b'a' + 10) as u64;
                ndmant += 1;
            } else {
                trunc = true;
            }
            i += 1;
            continue;
        }

        if base == 16 {
            let lc = c.to_ascii_lowercase();
            if (b'a'..=b'f').contains(&lc) {
                sawdigits = true;
                nd += 1;
                if ndmant < max_mant_digits {
                    mantissa *= 16;
                    mantissa += (lc - b'a' + 10) as u64;
                    ndmant += 1;
                } else {
                    trunc = true;
                }
                i += 1;
                continue;
            }
        }

        break;
    }

    if !sawdigits {
        return (0, 0, neg, trunc, hex, i, false);
    }

    if !sawdot {
        dp = nd;
    }

    if base == 16 {
        dp *= 4;
        ndmant *= 4;
    }

    if i < len && to_ascii_lowercase(b[i]) == exp_char {
        i += 1;
        if i >= len {
            return (0, 0, neg, trunc, hex, i, false);
        }
        let mut esign = 1i64;
        if b[i] == b'+' {
            i += 1;
        } else if b[i] == b'-' {
            i += 1;
            esign = -1;
        }

        if i >= len {
            return (0, 0, neg, trunc, hex, i, false);
        }
        let c = b[i];
        if !c.is_ascii_digit() {
            return (0, 0, neg, trunc, hex, i, false);
        }

        let mut e = 0i64;
        while i < len {
            let c = b[i];
            if c == b'_' {
                underscores = true;
                i += 1;
                continue;
            }
            if c.is_ascii_digit() {
                if e < 10000 {
                    e = e * 10 + (c - b'0') as i64;
                }
                i += 1;
                continue;
            }
            break;
        }
        dp += e * esign;
    } else if base == 16 {
        return (0, 0, neg, trunc, hex, i, false);
    }

    if mantissa != 0 {
        exp = dp - (ndmant as i64);
    }

    if underscores && !underscore_ok(b, i) {
        return (0, 0, neg, trunc, hex, i, false);
    }

    (mantissa, exp, neg, trunc, hex, i, true)
}

fn to_ascii_lowercase(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c + 32 } else { c }
}

fn underscore_ok(b: &[u8], n: usize) -> bool {
    let mut saw = b'^';
    let mut i = 0usize;

    let s = if n <= b.len() { &b[..n] } else { b };

    let len = s.len();

    if len >= 1 && (s[0] == b'-' || s[0] == b'+') {
        i = 1;
    }

    let mut hex = false;
    if len - i >= 2
        && s[i] == b'0'
        && (to_ascii_lowercase(s[i + 1]) == b'b'
            || to_ascii_lowercase(s[i + 1]) == b'o'
            || to_ascii_lowercase(s[i + 1]) == b'x')
    {
        i += 2;
        saw = b'0'; // base prefix counts as a digit
        hex = to_ascii_lowercase(s[i - 1]) == b'x';
    }

    while i < len {
        let c = s[i];
        let is_digit = (c.is_ascii_digit())
            || (hex && to_ascii_lowercase(c) >= b'a' && to_ascii_lowercase(c) <= b'f');
        if is_digit {
            saw = b'0';
            i += 1;
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            i += 1;
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
        i += 1;
    }
    saw != b'_'
}

fn atof_hex_bits(
    flt: &FloatInfo,
    mut mantissa: u64,
    mut exp: i64,
    neg: bool,
    trunc: bool,
) -> Option<u64> {
    let mantbits = flt.mantbits;
    let expbits = flt.expbits;
    let bias = flt.bias;

    let max_exp: i64 = (1 << expbits) + bias - 2;
    let min_exp: i64 = bias + 1;

    exp += mantbits as i64; // mantissa now implicitly divided by 2^mantbits.

    while mantissa != 0 && (mantissa >> (mantbits + 2)) == 0 {
        mantissa <<= 1;
        exp -= 1;
    }

    if trunc {
        mantissa |= 1;
    }

    while (mantissa >> (1 + mantbits + 2)) != 0 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exp += 1;
    }

    while mantissa > 1 && exp < min_exp - 2 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exp += 1;
    }

    let mut round = mantissa & 3;
    mantissa >>= 2;
    round |= mantissa & 1; // round to even (round up if mantissa is odd)
    exp += 2;

    if round == 3 {
        mantissa += 1;
        if mantissa == (1 << (1 + mantbits)) {
            mantissa >>= 1;
            exp += 1;
        }
    }

    if (mantissa >> mantbits) == 0 {
        exp = bias;
    }

    let mut overflow = false;
    if exp > max_exp {
        mantissa = 1 << mantbits;
        exp = max_exp + 1;
        overflow = true;
    }

    let mut bits = mantissa & ((1u64 << mantbits) - 1);
    let exp_field = ((exp - bias) as u64) & ((1u64 << expbits) - 1);
    bits |= exp_field << mantbits;

    if neg {
        bits |= 1u64 << mantbits << expbits;
    }

    if overflow {
        return None;
    }

    Some(bits)
}
