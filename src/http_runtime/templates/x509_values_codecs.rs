// Portions derived from Go math/big. Copyright The Go Authors.
// Used under the BSD 3-Clause license in THIRD-PARTY-NOTICES.
//! Byte codecs preserve Go's observable partial scanner updates and Gob sign.
use super::*;
fn commit(data: &Integer, n: BigInt, negative_zero: bool) -> RenderResult<()> {
    let shape = word_commit::Shape::copy(&n)?;
    commit_number(data, n, negative_zero, shape)
}

fn err(text: String) -> Value {
    super::super::error_value("*errors.errorString", text)
}
// Return magnitude, scanner status, consumed-all status, and input sign.
fn scan(bytes: &[u8]) -> RenderResult<Option<(BigInt, bool, bool, bool)>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut at = 0;
    let negative = bytes[0] == b'-';
    if matches!(bytes[0], b'+' | b'-') {
        at += 1
    }
    let mut base = 10;
    let mut prefix = 0u8;
    let mut previous_digit = false;
    let mut count = 0usize;
    if bytes.get(at) == Some(&b'0') {
        at += 1;
        previous_digit = true;
        count = 1;
        if let Some(c) = bytes.get(at) {
            let detected = match c {
                b'b' | b'B' => Some(2),
                b'o' | b'O' => Some(8),
                b'x' | b'X' => Some(16),
                _ => None,
            };
            if let Some(b) = detected {
                base = b;
                prefix = *c;
                at += 1;
                count = 0
            } else {
                base = 8;
                prefix = b'0';
                count = 0
            }
        }
    }
    let mut invalid = false;
    let mut digits = Vec::with_capacity(bytes.len());
    while let Some(c) = bytes.get(at).copied() {
        if c == b'_' {
            if !previous_digit {
                invalid = true
            };
            previous_digit = false;
            at += 1;
            continue;
        }
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'z' => c - b'a' + 10,
            b'A'..=b'Z' => c - b'A' + 10,
            _ => 255,
        };
        if u32::from(d) >= base {
            break;
        }
        digits.push(c);
        count += 1;
        previous_digit = true;
        at += 1;
    }
    let scanner_ok = !invalid && previous_digit && (count > 0 || prefix == b'0');
    let magnitude = if digits.is_empty() {
        BigInt::from(0)
    } else {
        BigInt::parse_bytes(&digits, base)
            .ok_or_else(|| error("validated integer parse rejected"))?
    };
    Ok(Some((magnitude, scanner_ok, at == bytes.len(), negative)))
}
pub(super) fn invoke(o: &Object, name: &str, args: &[Value]) -> RenderResult<Value> {
    let data = o
        .host_data::<Integer>("*big.Int")
        .ok_or_else(|| error("invalid big.Int receiver"))?;
    let f = owner(data)?;
    f.work(1)?;
    arity(
        args,
        if name == "GobEncode" { 0 } else { 1 },
        if name == "GobEncode" { 0 } else { 1 },
    )?;
    if o.is_nil_pointer() {
        return match name {
            "GobEncode" => f.byte_slice(Arc::from([]), true),
            "AppendText" => f.append_bytes(&args[0], b"<nil>"),
            _ => Err(error("nil big.Int receiver")),
        };
    }
    if name == "AppendText" {
        return call(o, "Append", &[args[0].clone(), Value::Int(10)]);
    }
    if name == "GobEncode" {
        let (n, nz) = snapshot_number(data, &f)?;
        let len = usize::try_from(n.bits().div_ceil(8)).map_err(|_| error("Gob size overflow"))?;
        f.reserve(
            len.checked_mul(4)
                .and_then(|n| n.checked_add(1024))
                .ok_or_else(|| error("Gob budget overflow"))?,
        )?;
        f.work(len.div_ceil(8) + 1)?;
        let mut bytes = Vec::with_capacity(len + 1);
        bytes.push(2 | u8::from(n.sign() == Sign::Minus || nz));
        if n.sign() != Sign::NoSign {
            bytes.extend_from_slice(&n.to_bytes_be().1)
        };
        return f.byte_slice(bytes.into(), false);
    }
    let input = byte_argument(&args[0])?;
    let len = input.len();
    f.reserve(
        len.checked_mul(64)
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(|| error("integer codec budget overflow"))?,
    )?;
    let limbs = len.div_ceil(16).max(1);
    f.work(
        limbs
            .checked_mul(limbs)
            .ok_or_else(|| error("integer codec work overflow"))?,
    )?;
    let view = input.visible_bytes();
    let bytes = view.as_deref().unwrap_or_default();
    if name == "GobDecode" {
        if let Some(b) = bytes.first() {
            if b >> 1 != 1 {
                return Ok(err(format!(
                    "Int.GobDecode: encoding version {} not supported",
                    b >> 1
                )));
            }
        }
        let neg = bytes.first().is_some_and(|b| b & 1 != 0);
        let mut n = BigInt::from_bytes_be(Sign::Plus, bytes.get(1..).unwrap_or_default());
        let nz = neg && n.sign() == Sign::NoSign;
        if neg {
            n = -n
        };
        f.work(0)?;
        commit(data, n, nz)?;
        return Ok(Value::NilError);
    }
    if name == "UnmarshalJSON" && bytes == b"null" {
        return Ok(Value::NilError);
    }
    let old_negative = {
        let s = data
            .number
            .lock()
            .map_err(|_| error("big.Int cell poisoned"))?;
        s.number.sign() == Sign::Minus || s.negative_zero
    };
    let parsed = scan(bytes)?;
    let valid = parsed
        .as_ref()
        .is_some_and(|(_, scan, all, _)| *scan && *all);
    let answer = if valid {
        Value::NilError
    } else {
        let quoted =
            gotmpl::go_sprintf_bytes(b"%q", &[Value::from_go_bytes(Arc::<[u8]>::from(bytes))])?;
        let mut message = String::from("math/big: cannot unmarshal ");
        message.push_str(
            std::str::from_utf8(&quoted).map_err(|_| error("invalid Go quoted codec error"))?,
        );
        message.push_str(" into a *big.Int");
        err(message)
    };
    if let Some((mut n, scanner_ok, _, input_negative)) = parsed {
        let neg = if scanner_ok {
            input_negative && n.sign() != Sign::NoSign
        } else {
            old_negative
        };
        let nz = !scanner_ok && neg && n.sign() == Sign::NoSign;
        if neg {
            n = -n
        };
        f.work(0)?;
        commit(data, n, nz)?;
    }
    Ok(answer)
}
