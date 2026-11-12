//! Shared Go encoding/json float64 formatting; integer values stay typed.
pub(crate) fn format(value:f64)->Result<String,&'static str> {
    if !value.is_finite() {
        return Err("invalid_json_number");
    }
    if value == 0.0 {
        return Ok(if value.is_sign_negative() { "-0" } else { "0" }.to_owned());
    }
    let mut buffer = ryu::Buffer::new();
    let text = buffer.format_finite(value);
    let (sign, text) = text.strip_prefix('-').map_or(("", text), |s| ("-", s));
    let (mantissa, exponent) = if let Some((a, b)) = text.split_once('e') {
        (
            a,
            b.parse::<i32>()
                .map_err(|_| "json_number_encoding_failed")?,
        )
    } else {
        (text, 0)
    };
    let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let raw = mantissa.bytes().filter(|b| *b != b'.').collect::<Vec<_>>();
    let start = raw
        .iter()
        .position(|b| *b != b'0')
        .ok_or_else(|| "json_number_encoding_failed")?;
    let end = raw.iter().rposition(|b| *b != b'0').unwrap() + 1;
    let digits = std::str::from_utf8(&raw[start..end])
        .map_err(|_| "json_number_encoding_failed")?;
    let point = point - start as i32;
    let mut result = String::from(sign);
    if value.abs() < 1e-6 || value.abs() >= 1e21 {
        result.push_str(&digits[..1]);
        if digits.len() > 1 {
            result.push('.');
            result.push_str(&digits[1..]);
        }
        result.push('e');
        let exponent = point - 1;
        if exponent >= 0 {
            result.push('+');
        }
        result.push_str(&exponent.to_string());
    } else if point <= 0 {
        result.push_str("0.");
        result.extend(std::iter::repeat_n('0', (-point) as usize));
        result.push_str(digits);
    } else if point as usize >= digits.len() {
        result.push_str(digits);
        result.extend(std::iter::repeat_n('0', point as usize - digits.len()));
    } else {
        let point = point as usize;
        result.push_str(&digits[..point]);
        result.push('.');
        result.push_str(&digits[point..]);
    }
    Ok(result)
}
