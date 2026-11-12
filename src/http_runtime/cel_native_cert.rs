//! Native Caddy adapter values. A pkix.Name is deliberately not a CEL string;
//! an unsupported URL is an error only when its element is actually observed.
use super::client_cert_facts::Facts;
use crate::cel_engine::eval::{self, EvalError, Host, R, V};
use cel::common::{
    types::{CelBytes, CelList, CelNull, CelString, Type},
    value::{StaticVal, Val},
};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub(super) struct NativeName(Arc<str>);
#[derive(Clone, Debug)]
pub(super) struct NativeError;
static NAME_TYPE: Type = Type::new_struct_type("pkix.Name");
static ERROR_TYPE: Type = Type::new_struct_type("*url.URL");
macro_rules! native_val {
    ($ty:ty,$type:ident,$equal:expr) => {
        impl StaticVal for $ty {}
        impl Val for $ty {
            fn as_any(&self) -> Option<&dyn std::any::Any> {
                Some(self)
            }
            fn get_type(&self) -> &Type {
                &$type
            }
            fn cel_type() -> &'static Type {
                &$type
            }
            fn equals(&self, other: &dyn Val) -> bool {
                ($equal)(self, other)
            }
            fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
            where
                Self: 'v,
            {
                Box::new(self.clone())
            }
        }
    };
}
// Go list/map Equal ignore ordinary element errors (only Bool(false) stops
// comparison). This fallback represents that outcome inside vendor containers;
// direct scalar operations are intercepted by operation() below.
native_val!(
    NativeName,
    NAME_TYPE,
    |name: &NativeName, other: &dyn Val| {
        if let Some(text) = other.downcast_ref::<CelString>() {
            name.0.as_ref() == text.inner()
        } else {
            other.downcast_ref::<CelNull>().is_none()
        }
    }
);
native_val!(
    NativeError,
    ERROR_TYPE,
    |_: &NativeError, other: &dyn Val| other.downcast_ref::<CelNull>().is_none()
);
pub(super) fn observe(value: V) -> R {
    if value.downcast_ref::<NativeError>().is_some() {
        Err(EvalError::new(
            "unsupported conversion to ref.Val: *url.URL",
        ))
    } else {
        Ok(value)
    }
}
pub(super) fn operation(host: &mut impl Host, name: &str, args: &[V]) -> Option<R> {
    if args
        .iter()
        .any(|a| a.downcast_ref::<NativeError>().is_some())
    {
        return Some(Err(EvalError::new(
            "unsupported conversion to ref.Val: *url.URL",
        )));
    }
    if matches!(name, "_==_" | "_!=_")
        && args.len() == 2
        && args[0].downcast_ref::<NativeName>().is_some()
    {
        let is_null = args[1].downcast_ref::<CelNull>().is_some();
        if !is_null && args[1].downcast_ref::<CelString>().is_none() {
            return Some(Err(EvalError::new(
                "pkix.Name is not comparable to this type",
            )));
        }
        let length = comparison_width(args[0].as_ref()).unwrap_or(0);
        let work = args[1].downcast_ref::<CelString>().map_or(1, |v| {
            if length == v.inner().len() {
                v.inner().len() as u64 + 1
            } else {
                1
            }
        });
        if let Err(e) = host.tick(work, 256) {
            return Some(Err(e));
        }
        return Some(Ok(eval::boolean(
            args[0].equals(args[1].as_ref()) == (name == "_==_"),
        )));
    }
    if name == "type"
        && args
            .first()
            .is_some_and(|a| a.downcast_ref::<NativeName>().is_some())
    {
        return Some(Err(EvalError::new(
            "pkix.Name type conversion not implemented",
        )));
    }
    if matches!(name, "@in" | "@caddy_const_in")
        && args.len() == 2
        && args[0].downcast_ref::<NativeName>().is_some()
    {
        if name == "@caddy_const_in" {
            return Some(Ok(eval::boolean(false)));
        }
        let mut matched = false;
        if let Some(list) = args[1].downcast_ref::<CelList>() {
            let length = comparison_width(args[0].as_ref()).unwrap_or(0);
            for value in list.inner() {
                let work = value.downcast_ref::<CelString>().map_or(1, |v| {
                    if length == v.inner().len() {
                        v.inner().len() as u64 + 1
                    } else {
                        1
                    }
                });
                if let Err(e) = host.tick(work, 0) {
                    return Some(Err(e));
                }
                if value.downcast_ref::<CelString>().is_some() && args[0].equals(value.as_ref()) {
                    matched = true;
                    break;
                }
            }
        }
        return Some(Ok(eval::boolean(matched)));
    }
    if name == "@in"
        && args.len() == 2
        && let Some(list) = args[1].downcast_ref::<CelList>()
    {
        let mut native = false;
        for value in list.inner() {
            match contains_native(host, value.as_ref(), 0) {
                Ok(found) => native |= found,
                Err(e) => return Some(Err(e)),
            }
        }
        if !native {
            return None;
        }
        // Go invokes the searched element's Equal, rather than the list item's.
        return Some(Ok(eval::boolean(
            list.inner().iter().any(|v| args[0].equals(v.as_ref())),
        )));
    }
    None
}
fn contains_native(host: &mut impl Host, value: &dyn Val, depth: usize) -> Result<bool, EvalError> {
    host.tick(1, 0)?;
    if depth > 250 {
        return Err(EvalError::fatal("CEL native comparison depth"));
    }
    if value.downcast_ref::<NativeName>().is_some() || value.downcast_ref::<NativeError>().is_some()
    {
        return Ok(true);
    }
    if let Some(list) = value.downcast_ref::<CelList>() {
        for value in list.inner() {
            if contains_native(host, value.as_ref(), depth + 1)? {
                return Ok(true);
            }
        }
    }
    if let Some(map) = value.downcast_ref::<cel::common::types::CelMap>() {
        for value in map.inner().values() {
            if contains_native(host, value.as_ref(), depth + 1)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
pub(super) fn project(host: &mut impl Host, facts: Option<&Arc<Facts>>, field: &str) -> R {
    host.tick(1, 256)?;
    let null = || Ok(Arc::new(CelNull) as V);
    match field {
        "client.serial" => Err(EvalError::new(
            "unsupported conversion to ref.Val: *big.Int",
        )),
        "client.subject" | "client.issuer" => Ok(Arc::new(NativeName(
            facts
                .map(|f| {
                    if field.ends_with("subject") {
                        f.subject_display.clone()
                    } else {
                        f.issuer_display.clone()
                    }
                })
                .unwrap_or_else(|| Arc::from("")),
        ))),
        "client.fingerprint" | "client.public_key_sha256" => {
            use sha2::{Digest, Sha256};
            let bytes = if field == "client.fingerprint" {
                facts.map(|f| f.der.as_ref()).unwrap_or_default()
            } else {
                let Some(key) = facts.and_then(|f| f.public_key.as_deref()) else {
                    return null();
                };
                key
            };
            host.tick(bytes.len() as u64, 256)?;
            string(host, &format!("{:x}", Sha256::digest(bytes)))
        }
        "client.public_key" => {
            let Some(key) = facts.and_then(|f| f.public_key.as_deref()) else {
                return null();
            };
            host.tick(key.len() as u64, key.len() * 3 + 128)?;
            string(
                host,
                &key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            )
        }
        "client.certificate_der_base64" => {
            use base64::Engine;
            let bytes = facts.map(|f| f.der.as_ref()).unwrap_or_default();
            host.tick(bytes.len() as u64, bytes.len() * 2 + 128)?;
            string(
                host,
                &base64::engine::general_purpose::STANDARD.encode(bytes),
            )
        }
        "client.certificate_pem" => {
            use base64::Engine;
            let bytes = facts.map(|f| f.der.as_ref()).unwrap_or_default();
            host.tick(bytes.len() as u64, bytes.len() * 4 + 1024)?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            let mut out = b"-----BEGIN CERTIFICATE-----\n".to_vec();
            for line in encoded.as_bytes().chunks(64) {
                out.extend_from_slice(line);
                out.push(b'\n')
            }
            out.extend_from_slice(b"-----END CERTIFICATE-----\n");
            Ok(Arc::new(CelBytes::from(out)))
        }
        _ => {
            let Some(san) = field.strip_prefix("client.san.") else {
                return null();
            };
            let (kind, index) = san
                .split_once('.')
                .map_or((san, None), |(k, i)| (k, Some(i)));
            let index = if let Some(index) = index {
                match index.trim_start_matches('+').parse::<usize>() {
                    Ok(n) => Some(n),
                    Err(_) => return null(),
                }
            } else {
                None
            };
            let strings = match kind {
                "dns_names" => facts.map(|f| &f.dns),
                "emails" => facts.map(|f| &f.emails),
                _ => None,
            };
            if matches!(kind, "dns_names" | "emails") {
                let values = strings.map(Vec::as_slice).unwrap_or_default();
                if let Some(i) = index {
                    return values.get(i).map_or_else(null, |s| string(host, s));
                }
                host.tick(
                    values.len() as u64,
                    values.len() * 128 + values.iter().map(String::len).sum::<usize>(),
                )?;
                return Ok(Arc::new(CelList::from(
                    values
                        .iter()
                        .map(|v| Box::new(CelString::from(v.clone())) as Box<dyn Val>)
                        .collect::<Vec<_>>(),
                )));
            }
            if kind == "ips" {
                let values = facts.map(|f| f.ips.as_slice()).unwrap_or_default();
                if let Some(i) = index {
                    return match values.get(i) {
                        Some(b) => {
                            host.tick(0, b.len() + 128)?;
                            Ok(Arc::new(CelBytes::from(b.clone())))
                        }
                        None => null(),
                    };
                }
                host.tick(values.len() as u64, values.len() * 160)?;
                return Ok(Arc::new(CelList::from(
                    values
                        .iter()
                        .map(|v| Box::new(CelBytes::from(v.clone())) as Box<dyn Val>)
                        .collect::<Vec<_>>(),
                )));
            }
            if kind == "uris" {
                let count = facts.map_or(0, |f| f.uris.len());
                if let Some(index) = index {
                    return if index < count {
                        Err(EvalError::new(
                            "unsupported conversion to ref.Val: *url.URL",
                        ))
                    } else {
                        null()
                    };
                }
                host.tick(count as u64, count * 128)?;
                return Ok(Arc::new(CelList::from(
                    (0..count)
                        .map(|_| Box::new(NativeError) as Box<dyn Val>)
                        .collect::<Vec<_>>(),
                )));
            }
            null()
        }
    }
}
fn string(host: &mut impl Host, value: &str) -> R {
    host.tick(0, value.len() + 128)?;
    Ok(eval::string(value))
}
pub(super) fn comparison_width(value: &dyn Val) -> Option<usize> {
    if let Some(name) = value.downcast_ref::<NativeName>() {
        Some(name.0.len())
    } else {
        value.downcast_ref::<NativeError>().map(|_| 0)
    }
}
