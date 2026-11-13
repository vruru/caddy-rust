//! Go named X.509 integers and big.Int read views. No key material is derived
//! from a display string; formatting reads the actual arbitrary-precision value.
#[path = "x509_values_advanced.rs"]
mod advanced;
#[path = "x509_values_arithmetic.rs"]
mod arithmetic;
#[path = "x509_values_codecs.rs"]
mod codecs;
#[path = "x509_values_prime.rs"]
mod prime;
#[path = "x509_values_words.rs"]
mod words;
#[path = "x509_values_word_commit.rs"]
mod word_commit;
use super::{Factory, RenderResult, arity, error};
use bigdecimal::num_bigint::{BigInt, Sign};
use gotmpl::{ArgKind, HostFormat, HostMethod, HostType, Object, Signature, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock, Mutex, Weak},
};
struct State {
    negative_zero: bool,
    number: BigInt,
    words: words::Words,
    epoch: u64,
}
pub(super) struct Integer {
    number: Mutex<State>,
    owner: Weak<Factory>,
}
static INT_ARG: Signature = Signature::from_static(&[ArgKind::Int], None);
static BIG_TYPE: HostType = HostType {
    methods: &[
        HostMethod { name: "Bits", invoke: bits, signature: None },
        HostMethod { name: "SetBits", invoke: set_bits, signature: None },
        HostMethod {
            name: "ProbablyPrime",
            invoke: prime::invoke,
            signature: Some(&INT_ARG),
        },
        HostMethod {
            name: "ModSqrt",
            invoke: |o, a| advanced::invoke(o, "ModSqrt", a),
            signature: None,
        },
        HostMethod {
            name: "GobEncode",
            invoke: |o, a| codecs::invoke(o, "GobEncode", a),
            signature: None,
        },
        HostMethod {
            name: "GobDecode",
            invoke: |o, a| codecs::invoke(o, "GobDecode", a),
            signature: None,
        },
        HostMethod {
            name: "AppendText",
            invoke: |o, a| codecs::invoke(o, "AppendText", a),
            signature: None,
        },
        HostMethod {
            name: "UnmarshalText",
            invoke: |o, a| codecs::invoke(o, "UnmarshalText", a),
            signature: None,
        },
        HostMethod {
            name: "UnmarshalJSON",
            invoke: |o, a| codecs::invoke(o, "UnmarshalJSON", a),
            signature: None,
        },
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
enum Initial { Bytes, Fixed(usize), Decimal, Hex }
pub(super) fn integer(factory: &Arc<Factory>, bytes: &[u8], signed: bool) -> RenderResult<Value> { integer_initial(factory,bytes,signed,Initial::Bytes) }
pub(super) fn coordinate_integer(factory:&Arc<Factory>,bytes:&[u8],width:usize)->RenderResult<Value>{integer_initial(factory,bytes,false,Initial::Fixed(width))}
fn integer_initial(factory: &Arc<Factory>, bytes: &[u8], signed: bool, initial:Initial) -> RenderResult<Value> {
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
    let words = match initial {
        Initial::Bytes=>words::Words::initial(factory,bytes,signed,&number)?,
        Initial::Fixed(width)=>{
            if width<bytes.len() || width>66{return Err(error("invalid elliptic coordinate width"));}
            words::Words::make(factory,&number,width.div_ceil(8))?
        }
        Initial::Decimal=>words::Words::scanned(factory,&number,true)?,
        Initial::Hex=>words::Words::scanned(factory,&number,false)?,
    };
    let data = Arc::new(Integer {
        number: Mutex::new(State {
            number,
            words,
            epoch: 0,
            negative_zero: false,
        }),
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
    let (current, negative_zero) = snapshot_number(data, &factory)?;
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
    let sign = if n.sign() == Sign::Minus || negative_zero {
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
    Ok(snapshot_number(data, factory)?.0)
}
fn snapshot_number(data: &Integer, factory: &Arc<Factory>) -> RenderResult<(BigInt, bool)> {
    let source_owner = owner(data)?;
    source_owner.work(0)?;
    for _ in 0..8 {
        let (length, epoch) = {
            let state = data.number.lock().map_err(|_| error("big.Int cell poisoned"))?;
            (state.words.len(), state.epoch)
        };
        let bytes = length.checked_mul(8).ok_or_else(|| error("big.Int snapshot size overflow"))?;
        factory.reserve(bytes.checked_mul(4).and_then(|n|n.checked_add(1024)).ok_or_else(|| error("big.Int snapshot budget overflow"))?)?;
        factory.work(length.checked_add(1).ok_or_else(|| error("big.Int snapshot work overflow"))?)?;
        let (snapshot, negative, negative_zero) = {
            let state = data.number.lock().map_err(|_| error("big.Int cell poisoned"))?;
            if state.epoch != epoch { continue; }
            (state.words.snapshot(), state.number.sign() == Sign::Minus, state.negative_zero)
        };
        let mut number = match snapshot {
            Some(snapshot) => words::Words::unsigned(factory, &snapshot)?,
            None => BigInt::from(0),
        };
        let zero = number.sign() == Sign::NoSign;
        if negative && !zero { number = -number; }
        return Ok((number, negative_zero || (negative && zero)));
    }
    Err(error("concurrent big.Int change limit exceeded"))
}
fn bits(object: &Object, args: &[Value]) -> RenderResult<Value> {
    arity(args, 0, 0)?;
    let data = payload(object)?;
    let factory = owner(data)?;
    factory.reserve(128)?;
    factory.work(1)?;
    let state = data.number.lock().map_err(|_| error("big.Int cell poisoned"))?;
    Ok(state.words.value())
}
fn set_bits(object: &Object, args: &[Value]) -> RenderResult<Value> {
    arity(args, 1, 1)?;
    let data = shared_payload(object)?;
    let factory = owner(&data)?;
    let words = words::Words::source(&factory, &args[0])?;
    factory.reserve(words.len().checked_mul(32).and_then(|n|n.checked_add(1536)).ok_or_else(||error("big.Int SetBits size overflow"))?)?;
    let number = match words.snapshot() { Some(snapshot) => words::Words::unsigned(&factory, &snapshot)?, None => BigInt::from(0) };
    let wrapped = rewrap(object, data.clone(), number.bits())?;
    factory.work(words.len().checked_add(1).ok_or_else(||error("big.Int SetBits work overflow"))?)?;
    let shape=word_commit::Shape::copy(&number)?;
    word_commit::commit(&factory,&mut [word_commit::Change{data:&data,number,negative_zero:false,shape,adopt:Some(words)}])?;

    Ok(wrapped)
}
fn word_header(data: &Integer) -> RenderResult<(usize, Option<(usize,usize,usize,usize)>)> {
    let state = data.number.lock().map_err(|_|error("big.Int cell poisoned"))?;
    Ok((state.words.len(), state.words.span()))
}
fn aliases(a: Option<(usize,usize,usize,usize)>, b: Option<(usize,usize,usize,usize)>) -> bool {
    match (a,b) { (Some(a),Some(b)) => a.0 == b.0 && a.3 > 0 && b.3 > 0 && a.1 + a.3 == b.1 + b.3, _ => false }
}
fn same_words(a: Option<(usize,usize,usize,usize)>, b: Option<(usize,usize,usize,usize)>) -> bool {
    match (a,b) { (Some(a),Some(b)) => a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.2 > 0, _ => false }
}
fn commit_number(data: &Integer, number: BigInt, negative_zero: bool, shape: word_commit::Shape) -> RenderResult<()> {
    let factory = owner(data)?;
    word_commit::commit(&factory, &mut [word_commit::Change { data, number, negative_zero, shape, adopt:None }])
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
        Value::NamedInt64(n, kind) if kind.name == "uint" => Ok(*n as u64),
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
fn uint_argument(value:u64)->Value{uint_value(value as i64)}
static RANGE_INT64: Signature = Signature::from_static(&[ArgKind::Int64, ArgKind::Int64], None);
static SET_INT64: Signature = Signature::from_static(&[ArgKind::Int64], None);
static SET_UINT64: Signature = Signature::from_static(&[ArgKind::Uint64], None);
static SHIFT: Signature = Signature::from_static(
    &[ArgKind::Any, ArgKind::NamedUint64("uint", uint_argument)],
    None,
);
static SET_BIT: Signature = Signature::from_static(
    &[
        ArgKind::Any,
        ArgKind::Int,
        ArgKind::NamedUint64("uint", uint_argument),
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
    let mut result_negative_zero = false;
    let mut selected_shape = None;
    let mut word_history = Vec::new();
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
            let count = bytes.len().div_ceil(8);
            selected_shape = Some(word_commit::Shape { requested: count, written: count, force_new: false, preserve_header: false });
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
            let input_data = payload(input)?;
            let (x, x_negative_zero) = snapshot_number(input_data, &factory)?;
            let x_header = word_header(input_data)?;
            let target_header = word_header(&data)?;
            let mut y_header = (0usize, None);
            if name == "Set" {
                result_negative_zero = x_negative_zero
            }
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
                let input_data = payload(input)?;
                y_header = word_header(input_data)?;
                Some(read_number(input_data, &factory)?)
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
            let xlen = usize::try_from(xb.div_ceil(64)).map_err(|_|error("big.Int Word size overflow"))?;
            let ylen = usize::try_from(yb.div_ceil(64)).map_err(|_|error("big.Int Word size overflow"))?;
            let mut preserve = false;
            let mut force = false;
            // Go's signed shift/set-bit algorithms write abs(x)-1 and their
            // positive intermediate before adding one. Stage these actual
            // values, so a later allocation leaves genuine old-view history.
            if x.sign() == Sign::Minus && matches!(name,"Rsh"|"SetBit") {
                factory.reserve(bytes.checked_mul(12).and_then(|n|n.checked_add(2048)).ok_or_else(||error("big.Int signed Word staging overflow"))?)?;
                factory.work(xlen.checked_add(1).ok_or_else(||error("big.Int Word work overflow"))?)?;
                let first = -x.clone() - BigInt::from(1);
                let first_len = usize::try_from(first.bits().div_ceil(64)).map_err(|_|error("big.Int Word size overflow"))?;
                let (second, second_request) = if name == "Rsh" {
                    let shift = usize::try_from(scalar).map_err(|_|error("big.Int shift overflow"))?;
                    (if scalar >= first.bits() { BigInt::from(0) } else { &first >> shift },first_len.saturating_sub(shift/64))
                } else {
                    let mut second = first.clone();
                    let bit = !y.as_ref().is_some_and(|n|n.sign()!=Sign::NoSign);
                    second.set_bit(scalar,bit);
                    let request = if bit { first_len.max(usize::try_from(scalar/64).ok().and_then(|n|n.checked_add(1)).ok_or_else(||error("big.Int Word size overflow"))?) } else { first_len };
                    (second,request)
                };
                let second_len = usize::try_from(second.bits().div_ceil(64)).map_err(|_|error("big.Int Word size overflow"))?;
                let final_request = if second_len==0 {1} else {second_len.checked_add(1).ok_or_else(||error("big.Int Word size overflow"))?};
                word_history.try_reserve_exact(2).map_err(|_|error("big.Int Word history allocation failed"))?;
                word_history.push((first,word_commit::Shape{requested:xlen,written:xlen,force_new:false,preserve_header:false}));
                word_history.push((second,word_commit::Shape{requested:second_request,written:second_request,force_new:false,preserve_header:false}));
                selected_shape = Some(word_commit::Shape{requested:final_request,written:final_request,force_new:false,preserve_header:false});
            }
            let negative_x=x.sign()==Sign::Minus;
            let negative_y=y.as_ref().is_some_and(|n|n.sign()==Sign::Minus);
            let xm=minus_one_words(&x)?;
            let ym=match &y{Some(y)=>minus_one_words(y)?,None=>0};
            let mut add_one_request=None;
            let request = match name {
                "Set" | "Abs" | "Neg" => {
                    preserve = std::ptr::eq(input_data, data.as_ref()) && (name == "Set" || x.sign() != Sign::NoSign);
                    Some(if preserve { 0 } else { xlen })
                }
                "Add" | "Sub" => {
                    if xlen == 0 || ylen == 0 { Some(xlen.max(ylen)) }
                    else if ((x.sign() == Sign::Minus) == (y.as_ref().is_some_and(|n|n.sign()==Sign::Minus))) == (name == "Add") {
                        Some(xlen.max(ylen).checked_add(1).ok_or_else(||error("big.Int Word size overflow"))?)
                    } else { Some(xlen.max(ylen)) }
                }
                "Not" => Some(if negative_x { xlen } else if xlen==0 {1} else {xlen.checked_add(1).ok_or_else(||error("big.Int Word size overflow"))?}),
                "And" | "AndNot" | "Or" | "Xor" => {
                    let (requested, add_one) = match (name,negative_x,negative_y) {
                        ("And",false,false)=>(xlen.min(ylen),false),
                        ("And",true,true)=>(xm.max(ym),true),
                        ("And",false,true)=>(xlen,false),
                        ("And",true,false)=>(ylen,false),
                        ("AndNot",false,false)=>(xlen,false),
                        ("AndNot",true,true)=>(ym,false),
                        ("AndNot",true,false)=>(xm.max(ylen),true),
                        ("AndNot",false,true)=>(xlen.min(ym),false),
                        ("Or",false,false)=>(xlen.max(ylen),false),
                        ("Or",true,true)=>(xm.min(ym),true),
                        ("Or",true,false)=>(xm,true),
                        ("Or",false,true)=>(ym,true),
                        ("Xor",false,false)=>(xlen.max(ylen),false),
                        ("Xor",true,true)=>(xm.max(ym),false),
                        ("Xor",true,false)=>(xm.max(ylen),true),
                        ("Xor",false,true)=>(xlen.max(ym),true),
                        _=>return Err(error("invalid big.Int bitwise operation")),
                    };
                    if add_one {add_one_request=Some(requested);None}else{Some(requested)}
                }
                "Quo" if ylen==1 => Some(xlen),
                "Mul" => {
                    if xlen == 0 || ylen == 0 { Some(0) }
                    else if xlen.min(ylen) == 1 { Some(xlen.max(ylen).checked_add(1).ok_or_else(||error("big.Int Word size overflow"))?) }
                    else { force = aliases(target_header.1,x_header.1)||aliases(target_header.1,y_header.1);Some(xlen.checked_add(ylen).ok_or_else(||error("big.Int Word size overflow"))?) }
                }
                "Lsh" => {
                    if xlen == 0 { Some(0) }
                    else if scalar == 0 && same_words(target_header.1,x_header.1) { preserve=true;Some(0) }
                    else if scalar == 0 && !aliases(target_header.1,x_header.1) { Some(xlen) }
                    else { Some(xlen.checked_add(usize::try_from(scalar/64).map_err(|_|error("big.Int Word size overflow"))?).and_then(|n|n.checked_add(1)).ok_or_else(||error("big.Int Word size overflow"))?) }
                }
                "Rsh" if x.sign() != Sign::Minus => {
                    if scalar == 0 && same_words(target_header.1,x_header.1) { preserve=true;Some(0) }
                    else { Some(xlen.saturating_sub(usize::try_from(scalar/64).map_err(|_|error("big.Int Word size overflow"))?)) }
                }
                "SetBit" if x.sign() != Sign::Minus => {
                    if y.as_ref().is_some_and(|n|n.sign()!=Sign::NoSign) {
                        Some(xlen.max(usize::try_from(scalar/64).ok().and_then(|n|n.checked_add(1)).ok_or_else(||error("big.Int Word size overflow"))?))
                    } else { Some(xlen) }
                }
                _ => None,
            };
            if let Some(requested) = request { selected_shape = Some(word_commit::Shape { requested, written: requested, force_new: force, preserve_header: preserve }); }
            let result = if name == "Set" { x } else { arithmetic::compute(&factory, name, x, y, scalar)? };
            if let Some(requested)=add_one_request {
                factory.reserve(bytes.checked_mul(8).and_then(|n|n.checked_add(1024)).ok_or_else(||error("big.Int bitwise Word staging overflow"))?)?;
                factory.work(xlen.max(ylen).checked_add(1).ok_or_else(||error("big.Int Word work overflow"))?)?;
                let prefix = -result.clone() - BigInt::from(1);
                let len = usize::try_from(prefix.bits().div_ceil(64)).map_err(|_|error("big.Int Word size overflow"))?;
                let final_request=if len==0{1}else{len.checked_add(1).ok_or_else(||error("big.Int Word size overflow"))?};
                word_history.try_reserve_exact(1).map_err(|_|error("big.Int Word history allocation failed"))?;
                word_history.push((prefix,word_commit::Shape{requested,written:requested,force_new:false,preserve_header:false}));
                selected_shape=Some(word_commit::Shape{requested:final_request,written:final_request,force_new:false,preserve_header:false});
            }
            result
        }
    };
    factory.reserve(512)?;
    factory.work(0)?;
    let wrapped = rewrap(object, data.clone(), result.bits())?;
    let shape = match selected_shape { Some(shape) => shape, None => word_commit::Shape::copy(&result)? };
    if word_history.is_empty() {
        commit_number(&data, result, result_negative_zero, shape)?;
    } else {
        factory.reserve((word_history.len()+1).checked_mul(std::mem::size_of::<word_commit::Change<'_>>()).and_then(|n|n.checked_add(256)).ok_or_else(||error("big.Int Word history metadata overflow"))?)?;
        let mut changes = Vec::new();
        changes.try_reserve_exact(word_history.len()+1).map_err(|_|error("big.Int Word history allocation failed"))?;
        for (number,shape) in word_history {changes.push(word_commit::Change{data:&data,number,shape,negative_zero:false,adopt:None});}
        changes.push(word_commit::Change{data:&data,number:result,shape,negative_zero:result_negative_zero,adopt:None});
        word_commit::commit(&factory,&mut changes)?;
    }

    Ok(wrapped)
}

pub(super) fn singleton_integer(
    factory: &Arc<Factory>,
    bytes: &[u8],
    identity: usize,
    decimal: bool,
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
    let mut value = integer_initial(factory,bytes,false,if decimal{Initial::Decimal}else{Initial::Hex})?;
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

// Go crypto public-key equality compares unsigned magnitudes in constant time.
pub(super) fn public_magnitude_equal(a: &Value, b: &Value) -> RenderResult<bool> {
    let Value::Object(ao) = a else {
        return Err(error("expected *big.Int"));
    };
    let Value::Object(bo) = b else {
        return Err(error("expected *big.Int"));
    };
    let data = payload(ao)?;
    let factory = owner(data)?;
    let an = read_number(data, &factory)?;
    let bn = read_number(payload(bo)?, &factory)?;
    let n = usize::try_from(an.bits().max(bn.bits()).div_ceil(8))
        .map_err(|_| error("integer equality size overflow"))?;
    factory.reserve(
        n.checked_mul(8)
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(|| error("integer equality budget overflow"))?,
    )?;
    factory.work(n.div_ceil(8) + 1)?;
    if an.bits().div_ceil(8) != bn.bits().div_ceil(8) {
        return Ok(false);
    }
    let a = an.to_bytes_be().1;
    let b = bn.to_bytes_be().1;
    if a.len() != b.len() {
        return Ok(false);
    }
    Ok(openssl::memcmp::eq(&a, &b))
}

pub(super) fn word_reference_factory(value:&Value)->Option<Weak<Factory>> { words::reference_factory(value) }

fn minus_one_words(number:&BigInt)->RenderResult<usize> {
    let bits=number.bits();
    let len=usize::try_from(bits.div_ceil(64)).map_err(|_|error("big.Int Word size overflow"))?;
    Ok(if bits>0 && bits%64==1 && number.trailing_zeros()==Some(bits-1){len-1}else{len})
}
