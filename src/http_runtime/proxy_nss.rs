// Copyright The Go Authors. All rights reserved.
// Behavior port of net/nss.go and net/conf.go; BSD-3-Clause (see notices).
//! Pure-Go Linux hosts lookup order. Criteria are parsed for syntax even on
//! unrelated databases; with cgo unavailable they do not change lookup order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Order {
    #[default]
    FilesDns,
    DnsFiles,
    FilesOnly,
    DnsOnly,
}
impl Order {
    pub(super) fn files_first(self) -> bool {
        matches!(self, Self::FilesDns | Self::FilesOnly)
    }
    pub(super) fn files_last(self) -> bool {
        self == Self::DnsFiles
    }
}
fn space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}
fn trim(mut x: &[u8]) -> &[u8] {
    while x.first().is_some_and(|b| space(*b)) {
        x = &x[1..];
    }
    while x.last().is_some_and(|b| space(*b)) {
        x = &x[..x.len() - 1];
    }
    x
}
/// No allocations and no UTF-8 assumptions. Input must already be bounded by
/// the configuration I/O lane. Missing/unreadable/invalid NSS uses files,dns.
pub(super) fn parse(input: Option<&[u8]>) -> Order {
    let Some(input) = input else {
        return Order::default();
    };
    let (mut files, mut dns, mut unknown) = (None, None, None);
    let mut position = 0usize;
    for line in input.split(|b| *b == b'\n') {
        let line = trim(line.split(|b| *b == b'#').next().unwrap_or_default());
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            return Order::default();
        };
        let hosts = trim(&line[..colon]) == b"hosts";
        let mut rest = &line[colon + 1..];
        loop {
            rest = trim(rest);
            if rest.is_empty() {
                break;
            }
            // Go uses the first literal space, not a generic whitespace split.
            let (source, tail) = match rest.iter().position(|b| *b == b' ') {
                Some(i) => (&rest[..i], trim(&rest[i + 1..])),
                None => (rest, &[][..]),
            };
            rest = tail;
            if rest.first() == Some(&b'[') {
                let Some(close) = rest.iter().position(|b| *b == b']') else {
                    return Order::default();
                };
                for field in rest[1..close]
                    .split(|b| space(*b))
                    .filter(|f| !f.is_empty())
                {
                    let field = field.strip_prefix(b"!").unwrap_or(field);
                    if field.len() < 3 || !field.contains(&b'=') {
                        return Order::default();
                    }
                }
                rest = &rest[close + 1..];
            }
            if hosts {
                let slot = match source {
                    b"files" => &mut files,
                    b"dns" => &mut dns,
                    _ => &mut unknown,
                };
                slot.get_or_insert(position);
                position += 1;
            }
        }
    }
    // Unknown NSS services fall back to DNS only when no explicit dns occurs.
    match (files, dns.or(unknown)) {
        (Some(f), Some(d)) if f < d => Order::FilesDns,
        (Some(_), Some(_)) => Order::DnsFiles,
        (Some(_), None) => Order::FilesOnly,
        (None, Some(_)) => Order::DnsOnly,
        _ => Order::default(),
    }
}
