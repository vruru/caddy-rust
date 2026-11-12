//! Public PKIX/ASN.1/network types used by x509.Certificate. Names reuse the
//! connection metadata implementation's exact Go PKIX representation.
use super::{Factory, RenderResult, arity, error};
use crate::http_runtime::pkix_name::{Attribute, AttributeValue, Name, NativeValue};
use gotmpl::{Object, SliceMethod, SliceType, TypedSlice, Value};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Weak},
};
pub(super) fn bind(factory: &Arc<Factory>, slice: TypedSlice) -> RenderResult<Value> {
    factory.reserve(128)?;
    let control = Arc::downgrade(&factory.owner()?);
    Ok(Value::Slice(slice.with_host_budget(Arc::new(
        move |bytes| {
            control
                .upgrade()
                .ok_or_else(|| error("TLS template owner retired"))?
                .reserve_host_bytes(bytes)
        },
    ))))
}
pub(super) fn list(
    factory: &Arc<Factory>,
    kind: &'static str,
    values: Vec<Value>,
    nil: bool,
) -> RenderResult<Value> {
    bind(
        factory,
        TypedSlice::values(kind, (!nil).then_some(values.into()))?,
    )
}
pub(super) fn strings(factory: &Arc<Factory>, values: &[String]) -> RenderResult<Value> {
    factory.reserve(
        values
            .iter()
            .try_fold(values.len() * 128 + 256, |n, s| n.checked_add(s.len() * 2))
            .ok_or_else(|| error("certificate strings size overflow"))?,
    )?;
    list(
        factory,
        "[]string",
        values
            .iter()
            .map(|s| Value::String(s.as_str().into()))
            .collect(),
        values.is_empty(),
    )
}
fn int_values(slice: &TypedSlice) -> RenderResult<Vec<i64>> {
    if !matches!(slice.go_type(), "asn1.ObjectIdentifier" | "[]int") {
        return Err(error("expected asn1.ObjectIdentifier"));
    }
    slice
        .iter()
        .map(|v| match v {
            Value::Int(n) => Ok(n),
            _ => Err(error("invalid OID component")),
        })
        .collect()
}
fn oid_text(slice: &TypedSlice) -> RenderResult<Value> {
    slice.reserve_host_bytes(
        slice
            .len()
            .checked_mul(48)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(|| error("OID output overflow"))?,
    )?;
    let values = int_values(slice)?;
    Ok(Value::String(
        values
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(".")
            .into(),
    ))
}
static OID_TYPE: SliceType = SliceType {
    name: "asn1.ObjectIdentifier",
    element: "int",
    stringer: Some(oid_text),
    methods: &[
        SliceMethod {
            name: "String",
            invoke: |s, a| {
                arity(a, 0, 0)?;
                oid_text(s)
            },
            signature: None,
        },
        SliceMethod {
            name: "Equal",
            invoke: |s, a| {
                arity(a, 1, 1)?;
                s.reserve_host_bytes((s.len() + a[0].len().unwrap_or(0)) * 32 + 128)?;
                if matches!(a[0], Value::Nil) {
                    return Ok(Value::Bool(s.len() == 0));
                }
                let Value::Slice(other) = &a[0] else {
                    return Err(error("expected asn1.ObjectIdentifier"));
                };
                Ok(Value::Bool(int_values(s)? == int_values(other)?))
            },
            signature: None,
        },
    ],
};
pub(super) fn oid(factory: &Arc<Factory>, text: &str) -> RenderResult<Value> {
    factory.reserve(text.len() * 32 + 256)?;
    let values = text
        .split('.')
        .map(|part| {
            part.parse::<i64>()
                .map(Value::Int)
                .map_err(|_| error("ASN.1 OID arc exceeds Go int"))
        })
        .collect::<RenderResult<Vec<_>>>()?;
    bind(
        factory,
        TypedSlice::named_values(&OID_TYPE, Some(values.into()))?,
    )
}
fn ip_addr(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let a: [u8; 16] = bytes.try_into().ok()?;
            let ip = Ipv6Addr::from(a);
            Some(ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4))
        }
        _ => None,
    }
}
fn ip_text_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "<nil>".into()
    } else if let Some(ip) = ip_addr(bytes) {
        ip.to_string()
    } else {
        let mut result = String::with_capacity(1 + bytes.len() * 2);
        result.push('?');
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(result, "{b:02x}");
        }
        result
    }
}
fn ip_text(s: &TypedSlice) -> RenderResult<Value> {
    s.reserve_host_bytes(s.len() * 2 + 256)?;
    Ok(Value::String(
        ip_text_bytes(s.visible_bytes().as_deref().unwrap_or_default()).into(),
    ))
}
fn ip_method(s: &TypedSlice, name: &str, a: &[Value]) -> RenderResult<Value> {
    arity(
        a,
        usize::from(matches!(name, "Equal" | "Mask")),
        usize::from(matches!(name, "Equal" | "Mask")),
    )?;
    s.reserve_host_bytes(s.len() * 4 + 1024)?;
    let bytes = s.visible_bytes();
    let raw = bytes.as_deref().unwrap_or_default();
    let ip = ip_addr(raw);
    match name {
        "String" => ip_text(s),
        "To4" | "To16" => {
            let slice = match (raw.len(), name) {
                (4, "To4") | (16, "To16") => s.clone(),
                (16, "To4") if matches!(ip, Some(IpAddr::V4(_))) => s.reslice(12, 16)?,
                (4, "To16") => TypedSlice::named_bytes(
                    &IP_TYPE,
                    Some(Arc::from(match ip {
                        Some(IpAddr::V4(v)) => v.to_ipv6_mapped().octets(),
                        _ => return Err(error("invalid IPv4 view")),
                    })),
                )?
                .with_host_budget(budget_from(s)),
                _ => TypedSlice::named_bytes(&IP_TYPE, None)?.with_host_budget(budget_from(s)),
            };
            Ok(Value::Slice(slice))
        }
        "MarshalText" => {
            if !raw.is_empty() && ip.is_none() {
                return Err(error("address is not IPv4 or IPv6"));
            }
            let data = if raw.is_empty() {
                Vec::new()
            } else {
                ip_text_bytes(raw).into_bytes()
            };
            Ok(Value::Slice(
                TypedSlice::bytes(Some(data.into())).with_host_budget(budget_from(s)),
            ))
        }
        "Equal" => {
            let Value::Slice(other) = &a[0] else {
                return Err(error("expected net.IP"));
            };
            if other.go_type() != "net.IP" && !matches!(other.go_type(), "[]uint8" | "[]byte") {
                return Err(error("expected net.IP"));
            }
            let other = other.visible_bytes();
            let other = other.as_deref().unwrap_or_default();
            Ok(Value::Bool(if raw.len() == other.len() {
                raw == other
            } else {
                ip.is_some() && ip == ip_addr(other)
            }))
        }
        "DefaultMask" => {
            let data = match ip {
                Some(IpAddr::V4(v)) => {
                    let first = v.octets()[0];
                    Some(if first < 128 {
                        vec![255, 0, 0, 0]
                    } else if first < 192 {
                        vec![255, 255, 0, 0]
                    } else {
                        vec![255, 255, 255, 0]
                    })
                }
                _ => None,
            };
            Ok(Value::Slice(
                TypedSlice::named_bytes(&MASK_TYPE, data.map(Arc::from))?
                    .with_host_budget(budget_from(s)),
            ))
        }
        "Mask" => {
            let Value::Slice(mask) = &a[0] else {
                return Err(error("expected net.IPMask"));
            };
            if mask.go_type() != "net.IPMask" && !matches!(mask.go_type(), "[]uint8" | "[]byte") {
                return Err(error("expected net.IPMask"));
            }
            let m = mask.visible_bytes();
            let mut m = m.as_deref().unwrap_or_default();
            let mut ip = raw;
            if m.len() == 16 && ip.len() == 4 && m[..12].iter().all(|b| *b == 255) {
                m = &m[12..];
            }
            if m.len() == 4 && ip.len() == 16 {
                if let Some(IpAddr::V4(_)) = ip_addr(ip) {
                    ip = &ip[12..];
                }
            }
            let result = if ip.len() == m.len() {
                Some(
                    ip.iter()
                        .zip(m)
                        .map(|(a, b)| a & b)
                        .collect::<Vec<_>>()
                        .into(),
                )
            } else {
                None
            };
            Ok(Value::Slice(
                TypedSlice::named_bytes(&IP_TYPE, result)?.with_host_budget(budget_from(s)),
            ))
        }
        _ => {
            let value = match ip {
                None => false,
                Some(ip) => match name {
                    "IsUnspecified" => ip.is_unspecified(),
                    "IsLoopback" => ip.is_loopback(),
                    "IsPrivate" => match ip {
                        IpAddr::V4(ip) => ip.is_private(),
                        IpAddr::V6(ip) => (ip.octets()[0] & 0xfe) == 0xfc,
                    },
                    "IsMulticast" => ip.is_multicast(),
                    "IsInterfaceLocalMulticast" => {
                        matches!(ip,IpAddr::V6(ip)if ip.octets()[0]==255&&(ip.octets()[1]&15)==1)
                    }
                    "IsLinkLocalMulticast" => match ip {
                        IpAddr::V4(ip) => ip.octets()[0..3] == [224, 0, 0],
                        IpAddr::V6(ip) => ip.octets()[0] == 255 && (ip.octets()[1] & 15) == 2,
                    },
                    "IsLinkLocalUnicast" => match ip {
                        IpAddr::V4(ip) => ip.is_link_local(),
                        IpAddr::V6(ip) => {
                            (ip.octets()[0] == 0xfe) && (ip.octets()[1] & 0xc0) == 0x80
                        }
                    },
                    "IsGlobalUnicast" => {
                        !ip.is_unspecified()
                            && !ip.is_loopback()
                            && !ip.is_multicast()
                            && match ip {
                                IpAddr::V4(v) => !v.is_broadcast() && !v.is_link_local(),
                                IpAddr::V6(v) => {
                                    !(v.octets()[0] == 0xfe && v.octets()[1] & 0xc0 == 0x80)
                                }
                            }
                    }
                    _ => return Err(error("unknown net.IP method")),
                },
            };
            Ok(Value::Bool(value))
        }
    }
}
// Returned slices keep the same owner callback without capturing mutable cells.
fn budget_from(s: &TypedSlice) -> Arc<dyn Fn(usize) -> RenderResult<()> + Send + Sync> {
    s.host_budget()
        .expect("template named slice factory binds its allocation owner")
}
static IP_TYPE: SliceType = SliceType {
    name: "net.IP",
    element: "uint8",
    stringer: Some(ip_text),
    methods: &[
        SliceMethod {
            name: "String",
            invoke: |s, a| ip_method(s, "String", a),
            signature: None,
        },
        SliceMethod {
            name: "To4",
            invoke: |s, a| ip_method(s, "To4", a),
            signature: None,
        },
        SliceMethod {
            name: "To16",
            invoke: |s, a| ip_method(s, "To16", a),
            signature: None,
        },
        SliceMethod {
            name: "Equal",
            invoke: |s, a| ip_method(s, "Equal", a),
            signature: None,
        },
        SliceMethod {
            name: "DefaultMask",
            invoke: |s, a| ip_method(s, "DefaultMask", a),
            signature: None,
        },
        SliceMethod {
            name: "Mask",
            invoke: |s, a| ip_method(s, "Mask", a),
            signature: None,
        },
        SliceMethod {
            name: "MarshalText",
            invoke: |s, a| ip_method(s, "MarshalText", a),
            signature: None,
        },
        SliceMethod {
            name: "IsUnspecified",
            invoke: |s, a| ip_method(s, "IsUnspecified", a),
            signature: None,
        },
        SliceMethod {
            name: "IsLoopback",
            invoke: |s, a| ip_method(s, "IsLoopback", a),
            signature: None,
        },
        SliceMethod {
            name: "IsPrivate",
            invoke: |s, a| ip_method(s, "IsPrivate", a),
            signature: None,
        },
        SliceMethod {
            name: "IsMulticast",
            invoke: |s, a| ip_method(s, "IsMulticast", a),
            signature: None,
        },
        SliceMethod {
            name: "IsInterfaceLocalMulticast",
            invoke: |s, a| ip_method(s, "IsInterfaceLocalMulticast", a),
            signature: None,
        },
        SliceMethod {
            name: "IsLinkLocalMulticast",
            invoke: |s, a| ip_method(s, "IsLinkLocalMulticast", a),
            signature: None,
        },
        SliceMethod {
            name: "IsLinkLocalUnicast",
            invoke: |s, a| ip_method(s, "IsLinkLocalUnicast", a),
            signature: None,
        },
        SliceMethod {
            name: "IsGlobalUnicast",
            invoke: |s, a| ip_method(s, "IsGlobalUnicast", a),
            signature: None,
        },
    ],
};
fn mask_text(s: &TypedSlice) -> RenderResult<Value> {
    s.reserve_host_bytes(s.len() * 2 + 128)?;
    let mut out = String::with_capacity(s.len() * 2);
    if s.len() == 0 {
        return Ok(Value::String("<nil>".into()));
    }
    if let Some(bytes) = s.visible_bytes() {
        for b in bytes.iter() {
            use std::fmt::Write;
            let _ = write!(out, "{b:02x}");
        }
    }
    Ok(Value::String(out.into()))
}
static MASK_TYPE: SliceType = SliceType {
    name: "net.IPMask",
    element: "uint8",
    stringer: Some(mask_text),
    methods: &[
        SliceMethod {
            name: "String",
            invoke: |s, a| {
                arity(a, 0, 0)?;
                mask_text(s)
            },
            signature: None,
        },
        SliceMethod {
            name: "Size",
            invoke: |_, _| {
                Err(error(
                    "invalid function signature: second return value is not error",
                ))
            },
            signature: None,
        },
    ],
};
pub(super) fn ip_view(factory: &Arc<Factory>, view: TypedSlice) -> RenderResult<Value> {
    bind(factory, view.with_named_bytes(&IP_TYPE)?)
}
pub(super) fn ip_net_view(
    factory: &Arc<Factory>,
    ip: TypedSlice,
    mask: TypedSlice,
) -> RenderResult<Value> {
    factory.reserve(8192)?;
    let ip = ip.with_named_bytes(&IP_TYPE)?;
    let mask = mask.with_named_bytes(&MASK_TYPE)?;
    let Value::Slice(ip) = bind(factory, ip)? else {
        unreachable!()
    };
    let Value::Slice(mask) = bind(factory, mask)? else {
        unreachable!()
    };
    let fields = BTreeMap::from([
        ("IP".into(), Value::Slice(ip.clone())),
        ("Mask".into(), Value::Slice(mask.clone())),
    ]);
    let data = Arc::new(NetData {
        ip,
        mask,
        owner: Arc::downgrade(factory),
    });
    let mut methods = BTreeMap::<Arc<str>, gotmpl::ValueFunc>::new();
    for name in ["String", "Network", "Contains"] {
        let data = data.clone();
        methods.insert(
            name.into(),
            Arc::new(move |args| {
                arity(
                    args,
                    usize::from(name == "Contains"),
                    usize::from(name == "Contains"),
                )?;
                let factory = data
                    .owner
                    .upgrade()
                    .ok_or_else(|| error("certificate owner retired"))?;
                factory.reserve(1024)?;
                if name == "Network" {
                    return Ok(Value::String("ip+net".into()));
                }
                if name == "String" {
                    return Ok(Value::String(net_string(&data).into()));
                }
                let other = match &args[0] {
                    Value::Nil => None,
                    Value::Slice(slice)
                        if matches!(slice.go_type(), "net.IP" | "[]uint8" | "[]byte") =>
                    {
                        slice.visible_bytes()
                    }
                    _ => return Err(error("expected net.IP")),
                };
                let Some(other) = other.as_deref().and_then(ip_addr) else {
                    return Ok(Value::Bool(false));
                };
                let Some((ip, mask)) = net_parts(&data) else {
                    return Ok(Value::Bool(false));
                };
                let other = match other {
                    IpAddr::V4(v) => v.octets().to_vec(),
                    IpAddr::V6(v) => v.octets().to_vec(),
                };
                Ok(Value::Bool(
                    ip.len() == other.len()
                        && ip
                            .iter()
                            .zip(mask.iter().zip(other))
                            .all(|(base, (mask, other))| base & mask == other & mask),
                ))
            }),
        );
    }
    Ok(Value::Object(Arc::new(Object {
        fields,
        methods,
        go_type: Some("*net.IPNet"),
        field_order: Some(["IP", "Mask"].map(Arc::from).into()),
        pointer_identity: Some(Arc::as_ptr(&data) as usize),
        data: Some(data),
        data_bytes: 256,
        formatter: Some(format_net),
        ..Object::default()
    })))
}
struct NetData {
    ip: TypedSlice,
    mask: TypedSlice,
    owner: Weak<Factory>,
}
fn net_parts(data: &NetData) -> Option<(Vec<u8>, Vec<u8>)> {
    let ip = data.ip.visible_bytes()?;
    let ip = match ip_addr(&ip)? {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    let mask = data.mask.visible_bytes()?;
    let mask = match (mask.len(), ip.len()) {
        (4, 4) => mask.to_vec(),
        (16, 4) => mask[12..].to_vec(),
        (16, 16) => mask.to_vec(),
        _ => return None,
    };
    Some((ip, mask))
}
fn net_string(data: &NetData) -> String {
    let Some((ip, mask)) = net_parts(data) else {
        return "<nil>".into();
    };
    let mut bits = 0;
    let mut zero = false;
    let mut canonical = true;
    for b in &mask {
        for bit in (0..8).rev() {
            if b & (1 << bit) != 0 {
                if zero {
                    canonical = false;
                }
                bits += 1;
            } else {
                zero = true;
            }
        }
    }
    let suffix = if canonical {
        bits.to_string()
    } else {
        mask.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    format!("{}/{suffix}", ip_text_bytes(&ip))
}
fn format_net(object: &Object, verb: char, format: &gotmpl::HostFormat) -> RenderResult<Value> {
    let data = object
        .host_data::<NetData>("*net.IPNet")
        .ok_or_else(|| error("invalid IPNet receiver"))?;
    let factory = data
        .owner
        .upgrade()
        .ok_or_else(|| error("certificate owner retired"))?;
    factory.reserve(1024)?;
    super::format_display(&factory, object, verb, format, net_string(data).as_bytes())
}

pub(super) fn time_value(factory: &Arc<Factory>, seconds: i64, nanos: u32) -> RenderResult<Value> {
    factory.reserve(16384)?;
    let stamp = chrono::DateTime::from_timestamp(seconds, nanos)
        .ok_or_else(|| error("X.509 time outside supported range"))?;
    let text = stamp.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string();
    super::super::super::super::sprig::dates::yaml_timestamp(&text)?
        .ok_or_else(|| error("X.509 time conversion failed"))
}
pub(super) fn name(factory: &Arc<Factory>, name: &Name) -> RenderResult<Value> {
    factory.reserve(name.names.len() * 2048 + name.string().len() * 4 + 8192)?;
    let name = Arc::new(name.clone());
    let fields = BTreeMap::from([
        ("Country".into(), strings(factory, &name.country)?),
        ("Organization".into(), strings(factory, &name.organization)?),
        (
            "OrganizationalUnit".into(),
            strings(factory, &name.organizational_unit)?,
        ),
        ("Locality".into(), strings(factory, &name.locality)?),
        ("Province".into(), strings(factory, &name.province)?),
        (
            "StreetAddress".into(),
            strings(factory, &name.street_address)?,
        ),
        ("PostalCode".into(), strings(factory, &name.postal_code)?),
        (
            "SerialNumber".into(),
            Value::String(name.serial_number.as_str().into()),
        ),
        (
            "CommonName".into(),
            Value::String(name.common_name.as_str().into()),
        ),
        ("Names".into(), attributes(factory, &name.names)?),
        (
            "ExtraNames".into(),
            list(factory, "[]pkix.AttributeTypeAndValue", Vec::new(), true)?,
        ),
    ]);
    let weak = Arc::downgrade(factory);
    let display = name.string();
    let n = name.clone();
    let mut methods = BTreeMap::<Arc<str>, gotmpl::ValueFunc>::new();
    methods.insert(
        "String".into(),
        Arc::new(move |a| {
            arity(a, 0, 0)?;
            let f = weak
                .upgrade()
                .ok_or_else(|| error("certificate owner retired"))?;
            f.reserve(display.len() + 64)?;
            Ok(Value::String(display.as_str().into()))
        }),
    );
    let weak = Arc::downgrade(factory);
    methods.insert(
        "ToRDNSequence".into(),
        Arc::new(move |a| {
            arity(a, 0, 0)?;
            let f = weak
                .upgrade()
                .ok_or_else(|| error("certificate owner retired"))?;
            f.reserve(n.names.len() * 4096 + 8192)?;
            let rdns = n.to_rdns();
            let mut result = Vec::with_capacity(rdns.len());
            for set in rdns {
                let vals = attribute_values(&f, &set)?;
                result.push(bind(
                    &f,
                    TypedSlice::named_values(&RDN_SET_TYPE, Some(vals.into()))?,
                )?);
            }
            bind(
                &f,
                TypedSlice::named_values(&RDN_TYPE, Some(result.into()))?,
            )
        }),
    );
    Ok(Value::Object(Arc::new(Object {
        fields,
        methods,
        display: Some(name.string().into()),
        go_type: Some("pkix.Name"),
        field_order: Some(
            [
                "Country",
                "Organization",
                "OrganizationalUnit",
                "Locality",
                "Province",
                "StreetAddress",
                "PostalCode",
                "SerialNumber",
                "CommonName",
                "Names",
                "ExtraNames",
            ]
            .map(Arc::from)
            .into(),
        ),
        ..Object::default()
    })))
}
fn attribute_values(factory: &Arc<Factory>, attrs: &[Attribute]) -> RenderResult<Vec<Value>> {
    attrs
        .iter()
        .map(|a| {
            let value = match &a.value {
                AttributeValue::Text(v) => Value::String(v.as_str().into()),
                AttributeValue::Encoded { native, .. } => native_value(factory, native)?,
            };
            Ok(Value::Object(Arc::new(Object {
                fields: BTreeMap::from([
                    ("Type".into(), oid(factory, &a.oid)?),
                    ("Value".into(), value),
                ]),
                go_type: Some("pkix.AttributeTypeAndValue"),
                data: Some(Arc::new(a.clone())),
                data_bytes: 128,
                field_order: Some([Arc::from("Type"), Arc::from("Value")].into()),
                ..Object::default()
            })))
        })
        .collect()
}
fn attributes(factory: &Arc<Factory>, attrs: &[Attribute]) -> RenderResult<Value> {
    factory.reserve(attrs.len() * 1024 + 256)?;
    list(
        factory,
        "[]pkix.AttributeTypeAndValue",
        attribute_values(factory, attrs)?,
        attrs.is_empty(),
    )
}
fn native_value(factory: &Arc<Factory>, value: &NativeValue) -> RenderResult<Value> {
    Ok(match value {
        NativeValue::Int(n) => Value::Int64(*n),
        NativeValue::Bool(b) => Value::Bool(*b),
        NativeValue::Null => Value::Nil,
        NativeValue::Bytes(bytes) => factory.byte_slice(Arc::from(bytes.as_slice()), false)?,
        NativeValue::Oid(values) => oid(
            factory,
            &values
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join("."),
        )?,
        NativeValue::Time {
            unix_seconds,
            nanoseconds,
        } => time_value(factory, *unix_seconds, *nanoseconds)?,
        NativeValue::BitString { bytes, bit_length } => bit_string(factory, bytes, *bit_length)?,
        NativeValue::Raw {
            class,
            tag,
            constructed,
            bytes,
            full,
        } => Value::Object(Arc::new(Object {
            fields: BTreeMap::from([
                ("Class".into(), Value::Int(i64::from(*class))),
                ("Tag".into(), Value::Int(i64::from(*tag))),
                ("IsCompound".into(), Value::Bool(*constructed)),
                (
                    "Bytes".into(),
                    factory.byte_slice(Arc::from(bytes.as_slice()), false)?,
                ),
                (
                    "FullBytes".into(),
                    factory.byte_slice(Arc::from(full.as_slice()), false)?,
                ),
            ]),
            go_type: Some("asn1.RawValue"),
            field_order: Some(
                ["Class", "Tag", "IsCompound", "Bytes", "FullBytes"]
                    .map(Arc::from)
                    .into(),
            ),
            ..Object::default()
        })),
    })
}
fn bit_string(factory: &Arc<Factory>, bytes: &[u8], bit_length: usize) -> RenderResult<Value> {
    factory.reserve(bytes.len() * 4 + 4096)?;
    let data = Arc::<[u8]>::from(bytes);
    let weak = Arc::downgrade(factory);
    let at = data.clone();
    let right = data.clone();
    Ok(Value::Object(Arc::new(Object {
        fields: BTreeMap::from([
            ("Bytes".into(), factory.byte_slice(data, false)?),
            ("BitLength".into(), Value::Int(bit_length as i64)),
        ]),
        go_type: Some("asn1.BitString"),
        field_order: Some(["Bytes", "BitLength"].map(Arc::from).into()),
        methods: BTreeMap::from([
            (
                "At".into(),
                Arc::new(move |a: &[Value]| {
                    arity(a, 1, 1)?;
                    let i = a[0].as_int().ok_or_else(|| error("expected int"))?;
                    Ok(Value::Int(if i < 0 || i as usize >= bit_length {
                        0
                    } else {
                        i64::from((at[i as usize / 8] >> (7 - i as usize % 8)) & 1)
                    }))
                }) as gotmpl::ValueFunc,
            ),
            (
                "RightAlign".into(),
                Arc::new(move |a: &[Value]| {
                    arity(a, 0, 0)?;
                    let f = weak
                        .upgrade()
                        .ok_or_else(|| error("certificate owner retired"))?;
                    f.reserve(right.len() * 3 + 256)?;
                    let shift = (8 - bit_length % 8) % 8;
                    let mut out = right.to_vec();
                    if shift > 0 {
                        for i in (0..out.len()).rev() {
                            out[i] >>= shift;
                            if i > 0 {
                                out[i] |= right[i - 1] << (8 - shift);
                            }
                        }
                    }
                    f.byte_slice(out.into(), false)
                }) as gotmpl::ValueFunc,
            ),
        ]),
        ..Object::default()
    })))
}
fn rdn_string(s: &TypedSlice) -> RenderResult<Value> {
    let size = Value::Slice(s.clone()).measured_bytes(1 << 20)?;
    s.reserve_host_bytes(
        size.checked_mul(8)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| error("PKIX RDN size overflow"))?,
    )?;
    let mut rows = Vec::with_capacity(s.len());
    for row in s.iter() {
        let Value::Slice(row) = row else {
            return Err(error("invalid pkix.RDNSequence"));
        };
        let mut attrs = Vec::with_capacity(row.len());
        for value in row.iter() {
            let Value::Object(value) = value else {
                return Err(error("invalid PKIX attribute"));
            };
            attrs.push(
                value
                    .host_data::<Attribute>("pkix.AttributeTypeAndValue")
                    .ok_or_else(|| error("missing PKIX attribute identity"))?
                    .clone(),
            );
        }
        rows.push(attrs);
    }
    Ok(Value::String(
        crate::http_runtime::pkix_name::rdns_string(&rows).into(),
    ))
}
static RDN_SET_TYPE: SliceType = SliceType {
    name: "pkix.RelativeDistinguishedNameSET",
    element: "pkix.AttributeTypeAndValue",
    methods: &[],
    stringer: None,
};
static RDN_TYPE: SliceType = SliceType {
    name: "pkix.RDNSequence",
    element: "pkix.RelativeDistinguishedNameSET",
    methods: &[SliceMethod {
        name: "String",
        invoke: |s, a| {
            arity(a, 0, 0)?;
            rdn_string(s)
        },
        signature: None,
    }],
    stringer: Some(rdn_string),
};
