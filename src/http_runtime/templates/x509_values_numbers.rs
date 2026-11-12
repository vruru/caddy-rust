//! Go named X.509 integers and big.Int read views. No key material is derived
//! from a display string; formatting reads the actual arbitrary-precision value.
#[path = "x509_values_advanced.rs"]
mod advanced;
#[path = "x509_values_arithmetic.rs"]
mod arithmetic;
use super::{Factory, RenderResult, arity, error};
use bigdecimal::num_bigint::{BigInt, Sign};
use gotmpl::{ArgKind, HostFormat, HostMethod, HostType, Object, Signature, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock, Mutex, Weak},
};
struct State {
    number: BigInt,
    epoch: u64,
}
pub(super) struct Integer {
    number: Mutex<State>,
    owner: Weak<Factory>,
}
static INT_ARG: Signature = Signature::from_static(&[ArgKind::Int], None);
static BIG_TYPE: HostType = HostType {
    methods: &[
        HostMethod {
            name: "Exp",
            invoke: |o, a| advanced::invoke(o, "Exp", a),
            signature: None,
        },
        HostMethod {
            name: "ModInverse",
            invoke: |o, a| advanced::invoke(o, "ModInverse", a),
            signature: None,
        },
        HostMethod {
            name: "GCD",
            invoke: |o, a| advanced::invoke(o, "GCD", a),
            signature: None,
        },
        HostMethod {
            name: "MulRange",
            invoke: |o, a| advanced::invoke(o, "MulRange", a),
            signature: Some(&RANGE_INT64),
        },
        HostMethod {
            name: "Binomial",
            invoke: |o, a| advanced::invoke(o, "Binomial", a),
            signature: Some(&RANGE_INT64),
        },
        HostMethod {
            name: "Set",
            invoke: |o, a| mutate(o, "Set", a),
            signature: None,
        },
        HostMethod {
            name: "SetInt64",
            invoke: |o, a| mutate(o, "SetInt64", a),
            signature: Some(&SET_INT64),
        },
        HostMethod {
            name: "SetUint64",
            invoke: |o, a| mutate(o, "SetUint64", a),
            signature: Some(&SET_UINT64),
        },
        HostMethod {
            name: "SetBytes",
            invoke: |o, a| mutate(o, "SetBytes", a),
            signature: None,
        },
        HostMethod {
            name: "Abs",
            invoke: |o, a| mutate(o, "Abs", a),
            signature: None,
        },
        HostMethod {
            name: "Neg",
            invoke: |o, a| mutate(o, "Neg", a),
            signature: None,
        },
        HostMethod {
            name: "Add",
            invoke: |o, a| mutate(o, "Add", a),
            signature: None,
        },
        HostMethod {
            name: "Sub",
            invoke: |o, a| mutate(o, "Sub", a),
            signature: None,
        },
        HostMethod {
            name: "Mul",
            invoke: |o, a| mutate(o, "Mul", a),
            signature: None,
        },
        HostMethod {
            name: "Lsh",
            invoke: |o, a| mutate(o, "Lsh", a),
            signature: Some(&SHIFT),
        },
        HostMethod {
            name: "Rsh",
            invoke: |o, a| mutate(o, "Rsh", a),
            signature: Some(&SHIFT),
        },
        HostMethod {
            name: "Quo",
            invoke: |o, a| mutate(o, "Quo", a),
            signature: None,
        },
        HostMethod {
            name: "Rem",
            invoke: |o, a| mutate(o, "Rem", a),
            signature: None,
        },
        HostMethod {
            name: "Div",
            invoke: |o, a| mutate(o, "Div", a),
            signature: None,
        },
        HostMethod {
            name: "Mod",
            invoke: |o, a| mutate(o, "Mod", a),
            signature: None,
        },
        HostMethod {
            name: "And",
            invoke: |o, a| mutate(o, "And", a),
            signature: None,
        },
        HostMethod {
            name: "AndNot",
            invoke: |o, a| mutate(o, "AndNot", a),
            signature: None,
        },
        HostMethod {
            name: "Or",
            invoke: |o, a| mutate(o, "Or", a),
            signature: None,
        },
        HostMethod {
            name: "Xor",
            invoke: |o, a| mutate(o, "Xor", a),
            signature: None,
        },
        HostMethod {
            name: "Not",
            invoke: |o, a| mutate(o, "Not", a),
            signature: None,
        },
        HostMethod {
            name: "SetBit",
            invoke: |o, a| mutate(o, "SetBit", a),
            signature: Some(&SET_BIT),
        },
        HostMethod {
            name: "Sqrt",
            invoke: |o, a| mutate(o, "Sqrt", a),
            signature: None,
        },
        HostMethod {
            name: "TrailingZeroBits",
            invoke: |o, a| {
                arity(a, 0, 0)?;
                let d = payload(o)?;
                let f = owner(d)?;
                let n = read_number(d, &f)?;
                let z = n.trailing_zeros().unwrap_or(0);
                Ok(uint_value(
                    i64::try_from(z).map_err(|_| error("uint size overflow"))?,
                ))
            },
            signature: None,
        },
        HostMethod {
            name: "String",
            invoke: |o, a| call(o, "String", a),
            signature: None,
        },
        HostMethod {
            name: "Text",
            invoke: |o, a| call(o, "Text", a),
            signature: Some(&INT_ARG),
        },
        HostMethod {
            name: "Sign",
            invoke: |o, a| call(o, "Sign", a),
            signature: None,
        },
        HostMethod {
            name: "BitLen",
            invoke: |o, a| call(o, "BitLen", a),
            signature: None,
        },
        HostMethod {
            name: "Bit",
            invoke: |o, a| call(o, "Bit", a),
            signature: Some(&INT_ARG),
        },
        HostMethod {
            name: "Bytes",
            invoke: |o, a| call(o, "Bytes", a),
            signature: None,
        },
        HostMethod {
            name: "Int64",
            invoke: |o, a| call(o, "Int64", a),
            signature: None,
        },
        HostMethod {
            name: "Uint64",
            invoke: |o, a| call(o, "Uint64", a),
            signature: None,
        },
        HostMethod {
            name: "IsInt64",
            invoke: |o, a| call(o, "IsInt64", a),
            signature: None,
        },
        HostMethod {
            name: "IsUint64",
            invoke: |o, a| call(o, "IsUint64", a),
            signature: None,
        },
        HostMethod {
            name: "Cmp",
            invoke: |o, a| call(o, "Cmp", a),
            signature: None,
        },
        HostMethod {
            name: "CmpAbs",
            invoke: |o, a| call(o, "CmpAbs", a),
            signature: None,
        },
        HostMethod {
            name: "MarshalText",
            invoke: |o, a| call(o, "MarshalText", a),
            signature: None,
        },
        HostMethod {
            name: "MarshalJSON",
            invoke: |o, a| call(o, "MarshalJSON", a),
            signature: None,
        },
        HostMethod {
            name: "Append",
            invoke: |o, a| call(o, "Append", a),
            signature: None,
        },
        HostMethod {
            name: "FillBytes",
            invoke: |o, a| call(o, "FillBytes", a),
            signature: None,
        },
    ],
};
fn payload(o: &Object) -> RenderResult<&Integer> {
    if o.is_nil_pointer() {
        return Err(error("nil big.Int receiver"));
    }
    o.host_data::<Integer>("*big.Int")
        .ok_or_else(|| error("invalid big.Int receiver"))
}
fn owner(value: &Integer) -> RenderResult<Arc<Factory>> {
    value
        .owner
        .upgrade()
        .ok_or_else(|| error("certificate owner retired"))
}
fn conversion_work(f: &Factory, bits: u64, base: u32) -> RenderResult<()> {
    let limbs = usize::try_from(bits.div_ceil(64))
        .map_err(|_| error("big.Int conversion work overflow"))?
        .max(1);
    f.work(if base.is_power_of_two() {
        limbs
    } else {
        limbs
            .checked_mul(limbs)
            .ok_or_else(|| error("big.Int conversion work overflow"))?
    })
}
fn radix(n: &BigInt, base: u32) -> String {
    let (sign, digits) = n.to_radix_be(base);
    let mut text = String::with_capacity(digits.len() + usize::from(sign == Sign::Minus));
    if sign == Sign::Minus {
        text.push('-');
    }
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for d in digits {
        text.push(ALPHABET[d as usize] as char);
    }
    if text.is_empty() || text == "-" {
        text.push('0');
    }
    text
}
pub(super) fn integer(factory: &Arc<Factory>, bytes: &[u8], signed: bool) -> RenderResult<Value> {
    factory.reserve(
        bytes
            .len()
            .checked_mul(16)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| error("big.Int size overflow"))?,
    )?;
    let number = if signed {
        BigInt::from_signed_bytes_be(bytes)
    } else {
        BigInt::from_bytes_be(Sign::Plus, bytes)
    };
    let data = Arc::new(Integer {
        number: Mutex::new(State { number, epoch: 0 }),
        owner: Arc::downgrade(factory),
    });
    let id = Arc::as_ptr(&data) as usize;
    Ok(Value::Object(Arc::new(Object {
        go_type: Some("*big.Int"),
        pointer_identity: Some(id),
        data: Some(data),
        data_bytes: bytes.len() * 4 + 128,
        host_type: Some(&BIG_TYPE),
        json_dynamic: Some(json_current),
        formatter: Some(format_integer),
        ..Object::default()
    })))
}
fn call(o: &Object, name: &str, args: &[Value]) -> RenderResult<Value> {
    if o.is_nil_pointer() {
        let d = o
            .host_data::<Integer>("*big.Int")
            .ok_or_else(|| error("invalid nil integer"))?;
        let f = owner(d)?;
        f.reserve(1024)?;
        f.work(1)?;
        match name {
            "String" => {
                arity(args, 0, 0)?;
                return Ok(Value::String("<nil>".into()));
            }
            "Text" => {
                arity(args, 1, 1)?;
                return Ok(Value::String("<nil>".into()));
            }
            "MarshalText" | "MarshalJSON" => {
                arity(args, 0, 0)?;
                return f.byte_slice(
                    Arc::from(if name == "MarshalJSON" {
                        &b"null"[..]
                    } else {
                        &b"<nil>"[..]
                    }),
                    false,
                );
            }
            "Append" => {
                arity(args, 2, 2)?;
                return f.append_bytes(&args[0], b"<nil>");
            }
            _ => return Err(error("nil big.Int receiver")),
        }
    }

    let data = payload(o)?;
    let factory = owner(data)?;
    factory.work(1)?;
    let count = match name {
        "Text" | "Bit" | "Cmp" | "CmpAbs" | "FillBytes" => 1,
        "Append" => 2,
        _ => 0,
    };
    arity(args, count, count)?;
    let current = read_number(data, &factory)?;
    let n = &current;
    let bits = n.bits() as usize;
    factory.reserve(
        bits.checked_mul(4)
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(|| error("big.Int output overflow"))?,
    )?;
    if matches!(name, "String" | "MarshalText" | "MarshalJSON") {
        conversion_work(&factory, n.bits(), 10)?
    }
    match name {
        "String" => Ok(Value::String(n.to_str_radix(10).into())),
        "Text" => {
            let base = args[0]
                .as_int()
                .filter(|base| (2..=62).contains(base))
                .ok_or_else(|| error("invalid big.Int base"))?;
            conversion_work(&factory, n.bits(), base as u32)?;
            Ok(Value::String(radix(&n, base as u32).into()))
        }
        "Sign" => Ok(Value::Int(match n.sign() {
            Sign::Minus => -1,
            Sign::NoSign => 0,
            Sign::Plus => 1,
        })),
        "BitLen" => Ok(Value::Int(bits as i64)),
        "Bit" => {
            let bit = args[0]
                .as_int()
                .filter(|n| *n >= 0)
                .ok_or_else(|| error("negative big.Int bit index"))?;
            {
                static UINT_TYPE: LazyLock<Arc<gotmpl::Int64Type>> = LazyLock::new(|| {
                    Arc::new(gotmpl::Int64Type {
                        name: "uint",
                        kind: "uint",
                        stringer: None,
                        methods: BTreeMap::new(),
                        signatures: BTreeMap::new(),
                    })
                });
                Ok(Value::NamedInt64(
                    i64::from(n.bit(bit as u64)),
                    UINT_TYPE.clone(),
                ))
            }
        }
        "Bytes" => {
            let bytes = if n.sign() == Sign::NoSign {
                Vec::new()
            } else {
                n.to_bytes_be().1
            };
            factory.byte_slice(bytes.into(), false)
        }
        "MarshalText" | "MarshalJSON" => {
            factory.byte_slice(Arc::from(n.to_str_radix(10).into_bytes()), false)
        }
        "Int64" | "Uint64" => {
            let (_, digits) = n.to_u64_digits();
            let value = digits.first().copied().unwrap_or(0);
            Ok(if name == "Int64" {
                Value::Int64(if n.sign() == Sign::Minus {
                    0i64.wrapping_sub(value as i64)
                } else {
                    value as i64
                })
            } else {
                Value::Uint(value)
            })
        }
        "IsInt64" => {
            let min = BigInt::from(i64::MIN);
            let max = BigInt::from(i64::MAX);
            Ok(Value::Bool(*n >= min && *n <= max))
        }
        "IsUint64" => Ok(Value::Bool(n.sign() != Sign::Minus && bits <= 64)),
        "Cmp" | "CmpAbs" => {
            let Value::Object(other) = &args[0] else {
                return Err(error("expected *big.Int"));
            };
            let other = payload(other)?;
            if std::ptr::eq(data, other) {
                return Ok(Value::Int(0));
            }
            let other_value = read_number(other, &factory)?;
            let other = &other_value;
            let order = if name == "CmpAbs" {
                n.magnitude().cmp(other.magnitude())
            } else {
                n.cmp(other)
            };
            Ok(Value::Int(match order {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }))
        }
        "Append" => {
            let base = args[1]
                .as_int()
                .filter(|n| (2..=62).contains(n))
                .ok_or_else(|| error("invalid big.Int base"))?;
            conversion_work(&factory, n.bits(), base as u32)?;
            let text = radix(n, base as u32);
            factory.append_bytes(&args[0], text.as_bytes())
        }
        "FillBytes" => {
            let slice = byte_argument(&args[0])?;
            let backing = slice
                .byte_backing_len()
                .ok_or_else(|| error("invalid byte backing"))?;
            let peak = backing
                .checked_mul(2)
                .and_then(|n| slice.len().checked_mul(2).and_then(|m| n.checked_add(m)))
                .and_then(|n| n.checked_add(1024))
                .ok_or_else(|| error("big.Int FillBytes backing overflow"))?;
            factory.reserve(peak)?;
            factory.work((backing + slice.len()).div_ceil(64) + 1)?;
            let bytes = slice.visible_bytes();
            let bytes = bytes.as_deref().unwrap_or_default();
            let nbytes = if n.sign() == Sign::NoSign {
                Vec::new()
            } else {
                n.to_bytes_be().1
            };
            if nbytes.len() > bytes.len() {
                return Err(error("big.Int buffer too small"));
            }
            let mut output = vec![0; bytes.len()];
            let start = output.len() - nbytes.len();
            output[start..].copy_from_slice(&nbytes);
            slice.write_range(0, &output)?;
            Ok(Value::Slice(slice.clone()))
        }
        _ => Err(error("unknown big.Int method")),
    }
}
fn format_integer(o: &Object, verb: char, f: &HostFormat) -> RenderResult<Value> {
    if o.is_nil_pointer() {
        let d = o
            .host_data::<Integer>("*big.Int")
            .ok_or_else(|| error("invalid nil integer"))?;
        let owner = owner(d)?;
        owner.reserve(1024)?;
        owner.work(1)?;
        return Ok(Value::String(
            if matches!(verb, 'b' | 'o' | 'O' | 'd' | 's' | 'v' | 'x' | 'X') {
                "<nil>".into()
            } else {
                format!("%!{verb}(big.Int=<nil>)").into()
            },
        ));
    }

    let data = payload(o)?;
    let factory = owner(data)?;
    let current = read_number(data, &factory)?;
    let n = &current;
    let bits = n.bits() as usize;
    let maximum = bits.max(f.width.unwrap_or(0)).max(f.precision.unwrap_or(0));
    if maximum > 1 << 20 {
        return Err(error("big.Int formatted output limit"));
    }
    factory.reserve(
        maximum
            .checked_mul(4)
            .and_then(|n| n.checked_add(2048))
            .ok_or_else(|| error("big.Int format overflow"))?,
    )?;
    factory.work(bits.div_ceil(64) + 1)?;
    let base: u32 = match verb {
        'b' => 2,
        'o' | 'O' => 8,
        'd' | 's' | 'v' => 10,
        'x' | 'X' => 16,
        _ => {
            conversion_work(&factory, n.bits(), 10)?;
            return Ok(Value::String(
                format!("%!{verb}(big.Int={})", n.to_str_radix(10)).into(),
            ));
        }
    };
    conversion_work(&factory, n.bits(), base)?;
    let mut digits = n.magnitude().to_str_radix(base);
    if verb == 'X' {
        digits.make_ascii_uppercase();
    }
    if f.precision == Some(0) && n.sign() == Sign::NoSign {
        return Ok(Value::String("".into()));
    }
    let sign = if n.sign() == Sign::Minus {
        "-"
    } else if f.plus {
        "+"
    } else if f.space {
        " "
    } else {
        ""
    };
    let prefix = if verb == 'O' {
        "0o"
    } else if f.hash {
        match verb {
            'b' => "0b",
            'o' => "0",
            'x' => "0x",
            'X' => "0X",
            _ => "",
        }
    } else {
        ""
    };
    let mut zeros = f.precision.unwrap_or(0).saturating_sub(digits.len());
    let length = sign.len() + prefix.len() + zeros + digits.len();
    let padding = f.width.unwrap_or(0).saturating_sub(length);
    let (left, right) = if f.left_align {
        (0, padding)
    } else if f.zero && f.precision.is_none() {
        zeros = padding;
        (0, 0)
    } else {
        (padding, 0)
    };
    let mut text = String::with_capacity(length + padding);
    text.extend(std::iter::repeat_n(' ', left));
    text.push_str(sign);
    text.push_str(prefix);
    text.extend(std::iter::repeat_n('0', zeros));
    text.push_str(&digits);
    text.extend(std::iter::repeat_n(' ', right));
    Ok(Value::String(text.into()))
}

pub(super) fn signature_name(v: i64) -> String {
    match v {
        2 => "MD5-RSA",
        3 => "SHA1-RSA",
        4 => "SHA256-RSA",
        5 => "SHA384-RSA",
        6 => "SHA512-RSA",
        7 => "DSA-SHA1",
        8 => "DSA-SHA256",
        9 => "ECDSA-SHA1",
        10 => "ECDSA-SHA256",
        11 => "ECDSA-SHA384",
        12 => "ECDSA-SHA512",
        13 => "SHA256-RSAPSS",
        14 => "SHA384-RSAPSS",
        15 => "SHA512-RSAPSS",
        16 => "Ed25519",
        17 => "ML-DSA-44",
        18 => "ML-DSA-65",
        19 => "ML-DSA-87",
        _ => return v.to_string(),
    }
    .into()
}
pub(super) fn signature_oid(oid: &str) -> Option<i64> {
    Some(match oid {
        "1.2.840.113549.1.1.4" => 2,
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => 3,
        "1.2.840.113549.1.1.11" => 4,
        "1.2.840.113549.1.1.12" => 5,
        "1.2.840.113549.1.1.13" => 6,
        "1.2.840.10040.4.3" => 7,
        "2.16.840.1.101.3.4.3.2" => 8,
        "1.2.840.10045.4.1" => 9,
        "1.2.840.10045.4.3.2" => 10,
        "1.2.840.10045.4.3.3" => 11,
        "1.2.840.10045.4.3.4" => 12,
        "1.3.101.112" => 16,
        "2.16.840.1.101.3.4.3.17" => 17,
        "2.16.840.1.101.3.4.3.18" => 18,
        "2.16.840.1.101.3.4.3.19" => 19,
        _ => return None,
    })
}
pub(super) fn eku_oid(oid: &str) -> Option<i64> {
    Some(match oid {
        "2.5.29.37.0" => 0,
        "1.3.6.1.5.5.7.3.1" => 1,
        "1.3.6.1.5.5.7.3.2" => 2,
        "1.3.6.1.5.5.7.3.3" => 3,
        "1.3.6.1.5.5.7.3.4" => 4,
        "1.3.6.1.5.5.7.3.5" => 5,
        "1.3.6.1.5.5.7.3.6" => 6,
        "1.3.6.1.5.5.7.3.7" => 7,
        "1.3.6.1.5.5.7.3.8" => 8,
        "1.3.6.1.5.5.7.3.9" => 9,
        "1.3.6.1.4.1.311.10.3.3" => 10,
        "2.16.840.1.113730.4.1" => 11,
        "1.3.6.1.4.1.311.2.1.22" => 12,
        "1.3.6.1.4.1.311.61.1.1" => 13,
        _ => return None,
    })
}
fn public_key_name(v: i64) -> String {
    match v {
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        4 => "Ed25519",
        5 => "ML-DSA",
        _ => return v.to_string(),
    }
    .into()
}
fn usage_name(v: i64) -> String {
    match v {
        1 => "digitalSignature",
        2 => "contentCommitment",
        4 => "keyEncipherment",
        8 => "dataEncipherment",
        16 => "keyAgreement",
        32 => "keyCertSign",
        64 => "cRLSign",
        128 => "encipherOnly",
        256 => "decipherOnly",
        _ => return format!("KeyUsage({v})"),
    }
    .into()
}
fn eku_name(v: i64) -> String {
    match v {
        0 => "anyExtendedKeyUsage",
        1 => "serverAuth",
        2 => "clientAuth",
        3 => "codeSigning",
        4 => "emailProtection",
        5 => "ipsecEndSystem",
        6 => "ipsecTunnel",
        7 => "ipsecUser",
        8 => "timeStamping",
        9 => "OCSPSigning",
        10 => "msSGC",
        11 => "nsSGC",
        12 => "msCodeCom",
        13 => "msKernelCode",
        _ => return format!("ExtKeyUsage({v})"),
    }
    .into()
}
pub(super) fn enumeration(name: &'static str, value: i64) -> Value {
    static TYPES: LazyLock<BTreeMap<&'static str, Arc<gotmpl::Int64Type>>> = LazyLock::new(|| {
        [
            (
                "x509.SignatureAlgorithm",
                signature_name as fn(i64) -> String,
            ),
            ("x509.PublicKeyAlgorithm", public_key_name),
            ("x509.KeyUsage", usage_name),
            ("x509.ExtKeyUsage", eku_name),
        ]
        .into_iter()
        .map(|(name, stringer)| {
            let method = Arc::new(move |value, args: &[Value]| {
                arity(args, 0, 0)?;
                Ok(Value::String(stringer(value).into()))
            }) as gotmpl::Int64Method;
            (
                name,
                Arc::new(gotmpl::Int64Type {
                    name,
                    kind: "int",
                    stringer: Some(stringer),
                    methods: BTreeMap::from([("String".into(), method)]),
                    signatures: BTreeMap::new(),
                }),
            )
        })
        .collect()
    });
    Value::NamedInt64(
        value,
        TYPES
            .get(name)
            .expect("fixed certificate integer type")
            .clone(),
    )
}

fn byte_argument(value: &Value) -> RenderResult<gotmpl::TypedSlice> {
    match value {
        Value::Nil => Ok(gotmpl::TypedSlice::nil("[]uint8")),
        Value::Slice(slice)
            if matches!(slice.go_type(), "[]uint8" | "[]byte")
                || slice
                    .named_type()
                    .is_some_and(|kind| kind.element == "uint8") =>
        {
            slice.clone().into_plain_bytes()
        }
        _ => Err(error("expected []uint8")),
    }
}

pub(super) fn insecure_algorithm(value: i64) -> Value {
    fn text(n: i64) -> String {
        format!(
            "x509: cannot verify signature: insecure algorithm {}",
            signature_name(n)
        )
    }
    static TYPE: LazyLock<Arc<gotmpl::Int64Type>> = LazyLock::new(|| {
        Arc::new(gotmpl::Int64Type {
            name: "x509.InsecureAlgorithmError",
            kind: "int",
            stringer: Some(text),
            methods: BTreeMap::from([(
                "Error".into(),
                Arc::new(|n, a: &[Value]| {
                    arity(a, 0, 0)?;
                    Ok(Value::String(text(n).into()))
                }) as gotmpl::Int64Method,
            )]),
            signatures: BTreeMap::new(),
        })
    });
    Value::NamedInt64(value, TYPE.clone())
}

fn read_number(data: &Integer, factory: &Arc<Factory>) -> RenderResult<BigInt> {
    for _ in 0..8 {
        let (bits, epoch) = {
            let state = data
                .number
                .lock()
                .map_err(|_| error("big.Int cell poisoned"))?;
            (state.number.bits(), state.epoch)
        };
        let bytes =
            usize::try_from(bits.div_ceil(8)).map_err(|_| error("big.Int size overflow"))?;
        factory.reserve(
            bytes
                .checked_mul(4)
                .and_then(|n| n.checked_add(1024))
                .ok_or_else(|| error("big.Int snapshot budget overflow"))?,
        )?;
        factory.work(bytes.div_ceil(8) + 1)?;
        let state = data
            .number
            .lock()
            .map_err(|_| error("big.Int cell poisoned"))?;
        if state.epoch != epoch {
            continue;
        }
        return Ok(state.number.clone());
    }
    Err(error("concurrent big.Int change limit exceeded"))
}
fn json_current(object: &Object) -> RenderResult<Value> {
    let data = payload(object)?;
    let factory = owner(data)?;
    let n = read_number(data, &factory)?;
    factory.reserve(
        (n.bits() as usize)
            .checked_mul(4)
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(|| error("big.Int JSON budget overflow"))?,
    )?;
    conversion_work(&factory, n.bits(), 10)?;
    Ok(Value::String(n.to_str_radix(10).into()))
}
fn shared_payload(object: &Object) -> RenderResult<Arc<Integer>> {
    if object.go_type != Some("*big.Int") || object.is_nil_pointer() {
        return Err(error("expected *big.Int"));
    }
    object
        .data
        .clone()
        .ok_or_else(|| error("nil big.Int receiver"))?
        .downcast::<Integer>()
        .map_err(|_| error("invalid big.Int receiver"))
}
fn rewrap(object: &Object, data: Arc<Integer>, bits: u64) -> RenderResult<Value> {
    let bytes = usize::try_from(bits.div_ceil(8)).map_err(|_| error("big.Int size overflow"))?;
    Ok(Value::Object(Arc::new(Object {
        go_type: Some("*big.Int"),
        pointer_identity: object.pointer_identity,
        data: Some(data),
        data_bytes: bytes * 4 + 128,
        host_type: Some(&BIG_TYPE),
        json_dynamic: Some(json_current),
        formatter: Some(format_integer),
        ..Object::default()
    })))
}
fn native_uint(value: &Value) -> RenderResult<u64> {
    match value {
        Value::NamedInt64(n, kind) if kind.name == "uint" && *n >= 0 => Ok(*n as u64),
        _ => Err(error("expected uint")),
    }
}
fn uint_value(value: i64) -> Value {
    static KIND: LazyLock<Arc<gotmpl::Int64Type>> = LazyLock::new(|| {
        Arc::new(gotmpl::Int64Type {
            name: "uint",
            kind: "uint",
            stringer: None,
            methods: BTreeMap::new(),
            signatures: BTreeMap::new(),
        })
    });
    Value::NamedInt64(value, KIND.clone())
}
static RANGE_INT64: Signature = Signature::from_static(&[ArgKind::Int64, ArgKind::Int64], None);
static SET_INT64: Signature = Signature::from_static(&[ArgKind::Int64], None);
static SET_UINT64: Signature = Signature::from_static(&[ArgKind::Uint64], None);
static SHIFT: Signature = Signature::from_static(
    &[ArgKind::Any, ArgKind::NamedInt64("uint", uint_value)],
    None,
);
static SET_BIT: Signature = Signature::from_static(
    &[
        ArgKind::Any,
        ArgKind::Int,
        ArgKind::NamedInt64("uint", uint_value),
    ],
    None,
);
fn mutate(object: &Object, name: &str, args: &[Value]) -> RenderResult<Value> {
    let data = shared_payload(object)?;
    let factory = owner(&data)?;
    factory.work(1)?;
    let count = match name {
        "SetInt64" | "SetUint64" | "SetBytes" | "Set" | "Abs" | "Neg" | "Not" | "Sqrt" => 1,
        "SetBit" => 3,
        _ => 2,
    };
    arity(args, count, count)?;
    let result = match name {
        "SetInt64" => {
            let Value::Int64(n) = args[0] else {
                return Err(error("expected int64"));
            };
            factory.reserve(2048)?;
            BigInt::from(n)
        }
        "SetUint64" => {
            let Value::Uint(n) = args[0] else {
                return Err(error("expected uint64"));
            };
            factory.reserve(2048)?;
            BigInt::from(n)
        }
        "SetBytes" => {
            let bytes = byte_argument(&args[0])?;
            factory.reserve(
                bytes
                    .len()
                    .checked_mul(8)
                    .and_then(|n| n.checked_add(2048))
                    .ok_or_else(|| error("big.Int SetBytes overflow"))?,
            )?;
            factory.work(bytes.len().div_ceil(8) + 1)?;
            let bytes = bytes.visible_bytes();
            BigInt::from_bytes_be(Sign::Plus, bytes.as_deref().unwrap_or_default())
        }
        _ => {
            let Value::Object(input) = &args[0] else {
                return Err(error("expected *big.Int"));
            };
            let x = read_number(payload(input)?, &factory)?;
            let unary = matches!(name, "Set" | "Abs" | "Neg" | "Not" | "Sqrt");
            let mut scalar = 0u64;
            let y = if unary {
                None
            } else if matches!(name, "Lsh" | "Rsh") {
                scalar = native_uint(&args[1])?;
                None
            } else if name == "SetBit" {
                let Value::Int(index) = args[1] else {
                    return Err(error("expected int bit index"));
                };
                scalar = u64::try_from(index).map_err(|_| error("negative bit index"))?;
                let bit = native_uint(&args[2])?;
                if bit > 1 {
                    return Err(error("set bit is not 0 or 1"));
                }
                Some(BigInt::from(bit))
            } else {
                let Value::Object(input) = &args[1] else {
                    return Err(error("expected *big.Int"));
                };
                Some(read_number(payload(input)?, &factory)?)
            };
            let xb = x.bits();
            let yb = y.as_ref().map_or(0, BigInt::bits);
            let out = match name {
                "Mul" => xb.checked_add(yb),
                "Lsh" => {
                    if x.sign() == Sign::NoSign {
                        Some(0)
                    } else {
                        xb.checked_add(scalar)
                    }
                }
                "SetBit" => {
                    let unchanged = scalar >= xb
                        && ((x.sign() != Sign::Minus
                            && y.as_ref().is_some_and(|y| y.sign() == Sign::NoSign))
                            || (x.sign() == Sign::Minus
                                && y.as_ref().is_some_and(|y| y.sign() == Sign::Plus)));
                    if unchanged {
                        Some(xb)
                    } else {
                        scalar.checked_add(2).map(|n| n.max(xb))
                    }
                }
                _ => xb.max(yb).checked_add(2),
            }
            .ok_or_else(|| error("big.Int result size overflow"))?;
            let bytes = usize::try_from(out.div_ceil(8))
                .map_err(|_| error("big.Int result size overflow"))?;
            factory.reserve(
                bytes
                    .checked_mul(24)
                    .and_then(|n| n.checked_add(4096))
                    .ok_or_else(|| error("big.Int operation budget overflow"))?,
            )?;
            let limbs = usize::try_from(xb.max(yb).div_ceil(64))
                .map_err(|_| error("big.Int work overflow"))?
                .max(1);
            let work = if matches!(name, "Mul" | "Quo" | "Rem" | "Div" | "Mod" | "Sqrt") {
                limbs.checked_mul(limbs).and_then(|n| {
                    if name == "Sqrt" {
                        n.checked_mul((64 - u64::from(xb.max(1)).leading_zeros()) as usize + 1)
                    } else {
                        Some(n)
                    }
                })
            } else {
                Some(limbs)
            }
            .ok_or_else(|| error("big.Int work overflow"))?;
            factory.work(work)?;
            if name == "Set" {
                x
            } else {
                arithmetic::compute(&factory, name, x, y, scalar)?
            }
        }
    };
    factory.reserve(512)?;
    factory.work(0)?;
    let wrapped = rewrap(object, data.clone(), result.bits())?;
    {
        let mut state = data
            .number
            .lock()
            .map_err(|_| error("big.Int cell poisoned"))?;
        let next = state
            .epoch
            .checked_add(1)
            .ok_or_else(|| error("big.Int epoch overflow"))?;
        state.number = result;
        state.epoch = next;
    }
    Ok(wrapped)
}

pub(super) fn singleton_integer(
    factory: &Arc<Factory>,
    bytes: &[u8],
    identity: usize,
) -> RenderResult<Value> {
    if let Some(value) = factory
        .integer_values
        .lock()
        .map_err(|_| error("integer cache poisoned"))?
        .get(&identity)
        .cloned()
    {
        return Ok(value);
    }
    factory.reserve(384)?;
    let mut value = integer(factory, bytes, false)?;
    let Value::Object(object) = &mut value else {
        return Err(error("invalid integer cache value"));
    };
    Arc::get_mut(object)
        .ok_or_else(|| error("new integer unexpectedly shared"))?
        .pointer_identity = Some(identity);
    let mut cache = factory
        .integer_values
        .lock()
        .map_err(|_| error("integer cache poisoned"))?;
    Ok(cache.entry(identity).or_insert(value).clone())
}

pub(super) fn current(value: &Value) -> RenderResult<BigInt> {
    let Value::Object(object) = value else {
        return Err(error("expected *big.Int"));
    };
    let data = payload(object)?;
    let factory = owner(data)?;
    read_number(data, &factory)
}
