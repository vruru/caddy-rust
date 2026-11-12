// Copyright 2015 The Go Authors. All rights reserved.
// Derived from Go net/addrselect.go, BSD-3-Clause; see LICENSES/Go-BSD-3-Clause.txt.

use std::net::IpAddr;

pub(super) fn policy(ip: IpAddr) -> (u8, u8) {
    let val = match ip {
        IpAddr::V4(v) => u128::from_be_bytes(v.to_ipv6_mapped().octets()),
        IpAddr::V6(v) => u128::from_be_bytes(v.octets()),
    };

    const TABLE: [(u128, u32, u8, u8); 9] = [
        (0x00000000000000000000000000000001, 128, 50, 0),
        (0x00000000000000000000ffff00000000, 96, 35, 4),
        (0x00000000000000000000000000000000, 96, 1, 3),
        (0x20010000000000000000000000000000, 32, 5, 5),
        (0x20020000000000000000000000000000, 16, 30, 2),
        (0x3ffe0000000000000000000000000000, 16, 1, 12),
        (0xfec00000000000000000000000000000, 10, 1, 11),
        (0xfc000000000000000000000000000000, 7, 3, 13),
        (0, 0, 40, 1),
    ];

    for &(prefix, bits, prec, label) in TABLE.iter() {
        if bits == 0 {
            return (prec, label);
        }
        if (val >> (128 - bits)) == (prefix >> (128 - bits)) {
            return (prec, label);
        }
    }
    (40, 1)
}

pub(super) fn scope(ip: IpAddr) -> u8 {
    let ip = match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    match ip {
        IpAddr::V4(v) => {
            if v.is_loopback() || v.is_link_local() {
                2
            } else {
                14
            }
        }
        IpAddr::V6(v) => {
            if v.is_loopback() || v.is_unicast_link_local() {
                2
            } else if v.is_multicast() {
                v.octets()[1] & 15
            } else {
                let octets = v.octets();
                if octets[0] == 0xfe && (octets[1] & 0xC0) == 0xC0 {
                    5
                } else {
                    14
                }
            }
        }
    }
}
fn native_v6(ip: IpAddr) -> bool {
    matches!(ip,IpAddr::V6(v) if v.to_ipv4_mapped().is_none())
}
fn common_prefix(source: Option<IpAddr>, destination: IpAddr) -> u32 {
    let (Some(IpAddr::V6(source)), IpAddr::V6(destination)) = (source, destination) else {
        return 0;
    };
    if destination.to_ipv4_mapped().is_some() {
        return 0;
    }
    let a = source.octets();
    let b = destination.octets();
    let mut bits = 0;
    for i in 0..8 {
        let different = a[i] ^ b[i];
        if different != 0 {
            return bits + different.leading_zeros();
        }
        bits += 8;
    }
    bits
}
pub(super) fn compare(
    a: &(IpAddr, Option<IpAddr>),
    b: &(IpAddr, Option<IpAddr>),
) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a.1, b.1) {
        (None, None) => return Ordering::Equal,
        (None, Some(_)) => return Ordering::Greater,
        (Some(_), None) => return Ordering::Less,
        _ => {}
    }
    let (ap, al) = policy(a.0);
    let (bp, bl) = policy(b.0);
    let ascope = a.1.map(scope).unwrap_or(0);
    let bscope = b.1.map(scope).unwrap_or(0);
    let dscopea = scope(a.0);
    let dscopeb = scope(b.0);
    let same_scope = (dscopeb == bscope).cmp(&(dscopea == ascope));
    if same_scope != Ordering::Equal {
        return same_scope;
    }
    let aslabel = a.1.map(policy).map(|p| p.1);
    let bslabel = b.1.map(policy).map(|p| p.1);
    let same_label = (bslabel == Some(bl)).cmp(&(aslabel == Some(al)));
    if same_label != Ordering::Equal {
        return same_label;
    }
    let precedence = bp.cmp(&ap);
    if precedence != Ordering::Equal {
        return precedence;
    }
    let smaller_scope = dscopea.cmp(&dscopeb);
    if smaller_scope != Ordering::Equal {
        return smaller_scope;
    }
    if native_v6(a.0) && native_v6(b.0) {
        return common_prefix(b.1, b.0).cmp(&common_prefix(a.1, a.0));
    }
    Ordering::Equal
}
