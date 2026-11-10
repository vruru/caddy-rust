//! Preserve number lexemes and existing JSON escapes while applying Go's tabs.
use anyhow::{Result, ensure};
fn bytes(out: &mut Vec<u8>, data: &[u8], limit: usize) -> Result<()> {
    ensure!(
        out.len()
            .checked_add(data.len())
            .is_some_and(|n| n <= limit),
        "pretty JSON output limit exceeded"
    );
    out.extend_from_slice(data);
    Ok(())
}
fn newline(out: &mut Vec<u8>, depth: usize, limit: usize) -> Result<()> {
    let end = out
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(depth))
        .filter(|n| *n <= limit)
        .ok_or_else(|| anyhow::anyhow!("pretty JSON output limit exceeded"))?;
    out.push(b'\n');
    out.resize(end, b'\t');
    Ok(())
}
/// Input is the compact output of the validated typed JSON encoder.
pub(super) fn indent(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (i, &byte) in input.iter().enumerate() {
        if quoted {
            bytes(&mut out, &[byte], limit)?;
            if escaped {
                escaped = false
            } else if byte == b'\\' {
                escaped = true
            } else if byte == b'"' {
                quoted = false
            };
            continue;
        }
        match byte {
            b'"' => {
                quoted = true;
                bytes(&mut out, &[byte], limit)?;
            }
            b'{' | b'[' => {
                bytes(&mut out, &[byte], limit)?;
                depth += 1;
                let close = if byte == b'{' { b'}' } else { b']' };
                if input.get(i + 1) != Some(&close) {
                    newline(&mut out, depth, limit)?;
                }
            }
            b'}' | b']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("invalid encoded JSON"))?;
                let open = if byte == b'}' { b'{' } else { b'[' };
                if i == 0 || input[i - 1] != open {
                    newline(&mut out, depth, limit)?;
                }
                bytes(&mut out, &[byte], limit)?;
            }
            b',' => {
                bytes(&mut out, b",", limit)?;
                newline(&mut out, depth, limit)?;
            }
            b':' => bytes(&mut out, b": ", limit)?,
            _ => bytes(&mut out, &[byte], limit)?,
        }
    }
    ensure!(!quoted && depth == 0, "invalid encoded JSON");
    Ok(out)
}
