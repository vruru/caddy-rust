//! Borrowed, allocation-free framing of the certificate and URI SANs.
//! Other certificate semantics remain the original X.509 verifier's job.
type R<T> = Result<T, &'static str>;
struct Item<'a> { tag: u8, body: &'a [u8] }
fn next<'a>(input: &mut &'a [u8]) -> R<Item<'a>> {
    let raw = *input;
    let tag = *raw.first().ok_or("short certificate DER tag")?;
    let mut p = 1usize;
    if tag & 31 == 31 {
        let mut number = 0u32;
        loop {
            let b = *raw.get(p).ok_or("short high DER tag")?;
            if p == 1 && b & 127 == 0 { return Err("noncanonical high DER tag"); }
            number = number.checked_mul(128).and_then(|n| n.checked_add(u32::from(b & 127)))
                .ok_or("DER tag overflow")?;
            p += 1;
            if b & 128 == 0 { break; }
        }
        if number < 31 { return Err("noncanonical high DER tag"); }
    }
    let first = *raw.get(p).ok_or("short certificate DER length")?;
    p += 1;
    let n = if first < 128 { usize::from(first) } else {
        let count = usize::from(first & 127);
        if !(1..=4).contains(&count) { return Err("invalid certificate DER length"); }
        let lengths = raw.get(p..p + count).ok_or("short certificate DER length")?;
        if lengths[0] == 0 { return Err("noncanonical certificate DER length"); }
        let mut n = 0usize;
        for &b in lengths { n = n.checked_mul(256).and_then(|n| n.checked_add(usize::from(b)))
            .ok_or("certificate DER length overflow")?; }
        p += count;
        if n < 128 { return Err("noncanonical certificate DER length"); }
        n
    };
    let end = p.checked_add(n).ok_or("certificate DER size overflow")?;
    let body = raw.get(p..end).ok_or("truncated certificate DER")?;
    *input = &raw[end..];
    Ok(Item { tag, body })
}
fn take<'a>(input: &mut &'a [u8], tag: u8) -> R<&'a [u8]> {
    let item = next(input)?;
    if item.tag != tag { return Err("unexpected certificate DER tag"); }
    Ok(item.body)
}
fn empty(input: &[u8]) -> R<()> {
    if input.is_empty() { Ok(()) } else { Err("trailing certificate DER") }
}
fn uris(der: &[u8], mut visit: impl FnMut(&[u8]) -> R<()>) -> R<()> {
    let mut input = der;
    let mut cert = take(&mut input, 0x30)?;
    empty(input)?;
    let mut tbs = take(&mut cert, 0x30)?;
    take(&mut cert, 0x30)?;
    take(&mut cert, 0x03)?;
    empty(cert)?;
    if tbs.first() == Some(&0xa0) { take(&mut tbs, 0xa0)?; }
    take(&mut tbs, 0x02)?;
    for _ in 0..5 { take(&mut tbs, 0x30)?; }
    // Unique IDs are IMPLICIT BIT STRINGs; the original parser validates them.
    if tbs.first() == Some(&0x81) { take(&mut tbs, 0x81)?; }
    if tbs.first() == Some(&0x82) { take(&mut tbs, 0x82)?; }
    if tbs.is_empty() { return Ok(()); }
    let mut explicit = take(&mut tbs, 0xa3)?;
    empty(tbs)?;
    let mut extensions = take(&mut explicit, 0x30)?;
    empty(explicit)?;
    let mut saw_san = false;
    while !extensions.is_empty() {
        let mut extension = take(&mut extensions, 0x30)?;
        let oid = take(&mut extension, 0x06)?;
        if extension.first() == Some(&0x01) {
            let boolean = take(&mut extension, 0x01)?;
            if boolean != [0] && boolean != [255] { return Err("invalid extension critical flag"); }
        }
        let value = take(&mut extension, 0x04)?;
        empty(extension)?;
        if oid != [0x55, 0x1d, 0x11] { continue; }
        if saw_san { return Err("duplicate subject alternative name extension"); }
        saw_san = true;
        let mut value = value;
        let mut names = take(&mut value, 0x30)?;
        empty(value)?;
        while !names.is_empty() {
            let name = next(&mut names)?;
            if name.tag == 0x86 { visit(name.body)?; }
        }
    }
    Ok(())
}
pub(super) fn uri_max_bytes(der: &[u8]) -> R<usize> {
    let mut maximum = 0;
    uris(der, |raw| { maximum = maximum.max(raw.len()); Ok(()) })?;
    Ok(maximum)
}
pub(super) fn check_der_uris(der: &[u8]) -> R<()> {
    uris(der, |raw| crate::go_url_compat::validate_san_uri(raw)
        .map_err(|_| "invalid certificate URI SAN syntax"))
}
