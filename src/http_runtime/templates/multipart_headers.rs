use http::{HeaderMap, HeaderName, HeaderValue};

// Pending unfolded MIME field.
struct PendingHeader {
    name: HeaderName,
    value: Vec<u8>,
}

/// Parses MIME headers from `body` starting at `cursor`.
///
/// * `body`: The full body slice (caller ensures <= 1MiB).
/// * `cursor`: In/out position. Must point to the first line of headers.
///             Updated to the byte immediately after the terminating blank line.
/// * Returns: `Ok(HeaderMap)` with parsed headers, or `Err(String)` on failure.
///
/// Spec compliance notes:
/// - Max 10000 logical headers.
/// - Max 1MiB total pending value size (per header accumulation).
/// - Handles folded headers (lines starting with SP/TAB).
/// - Strips trailing \r from lines.
/// - Blank line terminates header section (does not consume part body beyond blank line).
pub(super) fn headers(body: &[u8], cursor: &mut usize) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::new();
    let mut header_count: usize = 0;

    // State for handling folded headers
    let mut pending: Option<PendingHeader> = None;

    loop {
        // Check bounds before reading
        if *cursor >= body.len() {
            // EOF reached before finding a blank line
            // If we have a pending header, it's incomplete (no finalizing blank line)
            return Err("unexpected EOF".to_string());
        }

        // Find the next \n
        let newline_pos = body[*cursor..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| *cursor + p);

        let line_end = match newline_pos {
            Some(pos) => pos,
            None => {
                // No \n found in rest of body.
                // The rest of the body is the last line.
                // If we are at EOF, this is the end of input.
                // Since we require a blank line to terminate, and we haven't found it,
                // if we just finished a header line (not blank) and hit EOF, it's unexpected.
                // However, we must check if this "last line" is effectively a blank line?
                // The spec says: "Find next \n, consume including newline".
                // If no \n, we process the rest as a line?
                // Standard MIME: Headers are terminated by a blank line.
                // If we hit EOF without a blank line, it's "unexpected EOF".
                return Err("unexpected EOF".to_string());
            }
        };

        // Extract the line content: from *cursor to line_end (exclusive of \n)
        // We need to strip trailing \r if present.
        let line_bytes = &body[*cursor..line_end];

        // Move cursor past the \n
        *cursor = line_end + 1;

        // Determine effective line content (stripping \r)
        let effective_line: &[u8] = if !line_bytes.is_empty() && line_bytes[line_bytes.len() - 1] == b'\r' {
            &line_bytes[..line_bytes.len() - 1]
        } else {
            line_bytes
        };

        // Check for Blank Line
        if effective_line.is_empty() {
            // Blank line: Terminate header parsing
            if let Some(ph) = pending.take() {
                finalize_pending(&mut map, ph)?;
            }
            break;
        }

        // Check for Continuation (Folded) Header
        // Lines beginning with SP (0x20) or HTAB (0x09)
        if !effective_line.is_empty() && (effective_line[0] == b' ' || effective_line[0] == b'\t') {
            if pending.is_none() {
                return Err(format!(
                    "malformed MIME header initial line: {}",
                    String::from_utf8_lossy(effective_line)
                ));
            }

            // Append continuation to pending header
            // Spec: append a single SP + trimmed continuation to previous pending value
            let ph = pending.as_mut().unwrap();

            // Check size limit for the accumulating value
            // Trim leading SP/TAB from the continuation content
            let mut cont_bytes = &effective_line[1..];
            while let Some(&b) = cont_bytes.first() {
                if b == b' ' || b == b'\t' {
                    cont_bytes = &cont_bytes[1..];
                } else {
                    break;
                }
            }
            // Trim trailing whitespace from continuation
            while let Some(&b) = cont_bytes.last() {
                if b == b' ' || b == b'\t' {
                    cont_bytes = &cont_bytes[..cont_bytes.len() - 1];
                } else {
                    break;
                }
            }

            let add_len = 1 + cont_bytes.len(); // 1 for the inserted single space
            if ph.value.len() + add_len > 1_048_576 {
                return Err("multipart: message too large".to_string());
            }

            ph.value.push(b' ');
            ph.value.extend_from_slice(cont_bytes);

            continue;
        }

        // Normal Header Line
        // If there is a pending header, finalize it before starting a new one
        if let Some(ph) = pending.take() {
            finalize_pending(&mut map, ph)?;
        }

        // Parse Name: Value
        let colon_pos = effective_line.iter().position(|&b| b == b':');

        if colon_pos.is_none() {
            return Err(format!(
                "malformed MIME header initial line: {}",
                String::from_utf8_lossy(effective_line)
            ));
        }

        let colon_idx = colon_pos.unwrap();
        let name_bytes = &effective_line[..colon_idx];

        // Validate Header Name (ASCII Token)
        let header_name = match HeaderName::from_bytes(name_bytes) {
            Ok(n) => n,
            Err(_) => {
                return Err(format!(
                    "malformed MIME header initial line: {}",
                    String::from_utf8_lossy(effective_line)
                ));
            }
        };

        // Increment logical header count
        header_count += 1;
        if header_count > 10_000 {
            return Err("multipart: message too large".to_string());
        }

        // Extract Value
        let mut value_bytes = &effective_line[colon_idx + 1..];

        // Trim leading whitespace (SP/TAB) from value
        while let Some(&b) = value_bytes.first() {
            if b == b' ' || b == b'\t' {
                value_bytes = &value_bytes[1..];
            } else {
                break;
            }
        }

        // Trim trailing whitespace (SP/TAB) from value
        while let Some(&b) = value_bytes.last() {
            if b == b' ' || b == b'\t' {
                value_bytes = &value_bytes[..value_bytes.len() - 1];
            } else {
                break;
            }
        }

        // Check size limit for new pending value
        if value_bytes.len() > 1_048_576 {
            return Err("multipart: message too large".to_string());
        }

        // Set as new pending
        pending = Some(PendingHeader {
            name: header_name,
            value: value_bytes.to_vec(),
        });
    }

    Ok(map)
}

fn finalize_pending(map: &mut HeaderMap, ph: PendingHeader) -> Result<(), String> {
    if ph.value.len() > 1_048_576 {
        return Err("multipart: message too large".to_string());
    }

    let header_value = match HeaderValue::from_bytes(&ph.value) {
        Ok(v) => v,
        Err(_) => {
            // Lossy string for error message
            return Err(format!(
                "malformed MIME header value: {}",
                String::from_utf8_lossy(&ph.value)
            ));
        }
    };

    map.append(ph.name, header_value);
    Ok(())
}
