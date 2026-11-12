//! Reconstruct only template-private public keys. Authenticated snapshot bytes
//! and handshake verification keys are never modified by these operations.
use super::{Factory, PublicKeyData, RenderResult, error, numbers};
use gotmpl::{Object, Value};
use std::{collections::BTreeMap, sync::Arc};
pub(super) fn kind(value: &Value) -> (i64, &'static str) {
    match value {
        Value::Object(o) => match o.host_data::<PublicKeyData>(o.go_type.unwrap_or("")) {
            Some(d) => (
                d.kind,
                match d.kind {
                    1 => "*rsa.PublicKey",
                    2 => "*dsa.PublicKey",
                    3 => "*ecdsa.PublicKey",
                    5 => "*mldsa.PublicKey",
                    _ => "<nil>",
                },
            ),
            None => (0, "<nil>"),
        },
        Value::Slice(s) if s.go_type() == "ed25519.PublicKey" => (4, "ed25519.PublicKey"),
        _ => (0, "<nil>"),
    }
}
fn field<'a>(fields: &'a BTreeMap<Arc<str>, Value>, name: &str) -> RenderResult<&'a Value> {
    fields
        .get(name)
        .ok_or_else(|| error("missing public key field"))
}
pub(super) fn equal(
    factory: &Arc<Factory>,
    which: i64,
    own: &BTreeMap<Arc<str>, Value>,
    original: &PublicKeyData,
    other: &Object,
) -> RenderResult<bool> {
    factory.work(1)?;
    let Some(data) = other
        .data
        .as_ref()
        .and_then(|d| d.downcast_ref::<PublicKeyData>())
    else {
        return Ok(false);
    };
    if data.kind != which {
        return Ok(false);
    }
    match which {
        1 => Ok(
            field(own, "E")?.as_int() == field(&other.fields, "E")?.as_int()
                && numbers::current(field(own, "N")?)?
                    == numbers::current(field(&other.fields, "N")?)?,
        ),
        3 => {
            let curve = |fields: &BTreeMap<Arc<str>, Value>| -> RenderResult<Option<usize>> {
                let Value::Object(curve) = field(fields, "Curve")? else {
                    return Err(error("invalid EC curve"));
                };
                Ok(curve.pointer_identity)
            };
            Ok(curve(own)? == curve(&other.fields)?
                && numbers::current(field(own, "X")?)?
                    == numbers::current(field(&other.fields, "X")?)?
                && numbers::current(field(own, "Y")?)?
                    == numbers::current(field(&other.fields, "Y")?)?)
        }
        _ => Ok(original.der == data.der),
    }
}
pub(super) fn rsa_size(fields: &BTreeMap<Arc<str>, Value>) -> RenderResult<usize> {
    let n = numbers::current(field(fields, "N")?)?;
    usize::try_from(n.bits().div_ceil(8)).map_err(|_| error("RSA size overflow"))
}
pub(super) fn native(
    factory: &Arc<Factory>,
    value: &Value,
) -> RenderResult<Option<openssl::pkey::PKey<openssl::pkey::Public>>> {
    use bigdecimal::num_bigint::Sign;
    use openssl::{
        bn::BigNum,
        ec::EcKey,
        pkey::{Id, PKey},
        rsa::Rsa,
    };
    let (which, _) = kind(value);
    if which == 4 {
        let Value::Slice(slice) = value else {
            unreachable!()
        };
        factory.reserve(slice.len() * 16 + 4096)?;
        let bytes = slice.visible_bytes();
        return Ok(PKey::public_key_from_raw_bytes(
            bytes.as_deref().unwrap_or_default(),
            Id::ED25519,
        )
        .ok());
    }
    let Value::Object(object) = value else {
        return Ok(None);
    };
    let Some(data) = object
        .data
        .as_ref()
        .and_then(|d| d.downcast_ref::<PublicKeyData>())
    else {
        return Ok(None);
    };
    factory.reserve(
        data.der
            .len()
            .checked_mul(32)
            .and_then(|n| n.checked_add(32768))
            .ok_or_else(|| error("public key budget overflow"))?,
    )?;
    match which {
        1 => {
            let n = numbers::current(field(&object.fields, "N")?)?;
            let e = field(&object.fields, "E")?
                .as_int()
                .ok_or_else(|| error("invalid RSA exponent"))?;
            let bytes = usize::try_from(n.bits().div_ceil(8))
                .map_err(|_| error("RSA number size overflow"))?;
            factory.reserve(
                bytes
                    .checked_mul(32)
                    .and_then(|n| n.checked_add(4096))
                    .ok_or_else(|| error("RSA crypto budget overflow"))?,
            )?;
            let limbs = bytes.div_ceil(8).max(1);
            factory.work(
                limbs
                    .checked_mul(limbs)
                    .and_then(|n| n.checked_mul(32))
                    .ok_or_else(|| error("RSA crypto work overflow"))?,
            )?;
            if n.sign() == Sign::NoSign || e <= 0 {
                return Ok(None);
            }
            let (_, magnitude) = n.to_bytes_be();
            let modulus = BigNum::from_slice(&magnitude).map_err(|e| error(e.to_string()))?;
            let exponent =
                BigNum::from_slice(&(e as u64).to_be_bytes()).map_err(|e| error(e.to_string()))?;
            Ok(Rsa::from_public_components(modulus, exponent)
                .ok()
                .and_then(|r| PKey::from_rsa(r).ok()))
        }
        3 => {
            let original = PKey::public_key_from_der(&data.der)
                .map_err(|e| error(e.to_string()))?
                .ec_key()
                .map_err(|e| error(e.to_string()))?;
            let group = original.group();
            let x = numbers::current(field(&object.fields, "X")?)?;
            let y = numbers::current(field(&object.fields, "Y")?)?;
            if x.sign() == Sign::Minus
                || y.sign() == Sign::Minus
                || x.bits() > u64::from(group.degree())
                || y.bits() > u64::from(group.degree())
            {
                return Ok(None);
            }
            factory.work(4096)?;
            let x = BigNum::from_slice(&x.to_bytes_be().1).map_err(|e| error(e.to_string()))?;
            let y = BigNum::from_slice(&y.to_bytes_be().1).map_err(|e| error(e.to_string()))?;
            let Ok(key) = EcKey::from_public_key_affine_coordinates(group, &x, &y) else {
                return Ok(None);
            };
            if key.check_key().is_err() {
                return Ok(None);
            }
            Ok(PKey::from_ec_key(key).ok())
        }
        5 => Ok(PKey::public_key_from_der(&data.der).ok()),
        _ => Ok(None),
    }
}
pub(super) fn ec_bytes(factory: &Arc<Factory>, value: &Value) -> RenderResult<Value> {
    let Some(key) = native(factory, value)? else {
        return Err(error("invalid ECDSA public key"));
    };
    let key = key.ec_key().map_err(|e| error(e.to_string()))?;
    let mut context = openssl::bn::BigNumContext::new().map_err(|e| error(e.to_string()))?;
    let bytes = key
        .public_key()
        .to_bytes(
            key.group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut context,
        )
        .map_err(|e| error(e.to_string()))?;
    factory.byte_slice(bytes.into(), false)
}
