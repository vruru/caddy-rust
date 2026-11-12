//! Native Sprig functions. Each group performs its own pre-allocation checks;
//! engine crossing checks remain an additional limit, not allocation admission.
#[path = "sprig/strings.rs"]
mod strings;
#[path = "sprig/numeric.rs"]
mod numeric;
#[path = "sprig/collections.rs"]
mod collections;
#[path = "sprig/encoding.rs"]
mod encoding;
#[path = "sprig/entropy.rs"]
mod entropy;
#[path = "sprig/regex.rs"]
mod regex;
#[path = "sprig/signatures.rs"]
mod signatures;
#[path="sprig/dates.rs"]
pub(super) mod dates;
#[path="sprig/paths.rs"]
mod paths;
#[path="sprig/crypto.rs"]
mod crypto;
#[path="sprig/semver.rs"]
mod semver;
#[path="sprig/semver_version.rs"]
mod semver_version;
#[path="sprig/semver_constraints.rs"]
mod semver_constraints;
#[path="sprig/urls.rs"]
mod urls;
#[path="sprig/network.rs"]
mod network;
#[path="sprig/certificates.rs"]
mod certificates;
#[path="sprig/certificate_functions.rs"]
mod certificate_functions;
use gotmpl::{FuncMap, TemplateError, Value};
use std::{collections::BTreeMap, sync::Arc};
type V = Value;
type R = gotmpl::Result<V>;
type M = FuncMap;
const MAX_BYTES: usize = 1 << 20;
const MAX_ITEMS: usize = 16_384;

pub(super) fn functions() -> M { functions_with_maps(&gotmpl::MapContext::new()) }
pub(super) fn functions_with_maps(maps:&gotmpl::MapContext) -> M {
    let mut functions = M::new();
    strings::add(&mut functions);
    numeric::add(&mut functions);
    collections::add(&mut functions,maps);
    encoding::add(&mut functions,maps);
    entropy::add(&mut functions);
    regex::add(&mut functions);
    dates::add_functions(&mut functions);
    paths::add(&mut functions);
    crypto::add(&mut functions);
    semver::add(&mut functions);
    urls::add(&mut functions,maps);
    network::add(&mut functions);
    certificate_functions::add(&mut functions);
    functions
}
fn put(m: &mut M, name: &str, f: impl Fn(&[V]) -> R + Send + Sync + 'static) {
    m.insert(name.to_owned(), Arc::new(f));
}
fn err(message: impl Into<String>) -> TemplateError { TemplateError::Exec(message.into()) }
fn arity(args: &[V], min: usize, max: usize) -> gotmpl::Result<()> {
    if (min..=max).contains(&args.len()) { Ok(()) }
    else { Err(err("wrong number of template function arguments")) }
}
fn arg_text(args: &[V], index: usize) -> gotmpl::Result<&str> {
    args.get(index).and_then(V::as_str).ok_or_else(|| err("expected string argument"))
}
fn arg_int(args: &[V], index: usize) -> gotmpl::Result<i64> {
    match args.get(index) {
        Some(V::Int(n) | V::Int64(n)) => Ok(*n),
        Some(V::Uint8(n))=>Ok(i64::from(*n)),Some(V::Uint16(n))=>Ok(i64::from(*n)),Some(V::Uint32(n))=>Ok(i64::from(*n)),
        Some(V::Uint(n)) if *n <= i64::MAX as u64 => Ok(*n as i64),
        _ => Err(err("expected integer argument")),
    }
}
fn text(value: &V) -> String { value.to_string() }
fn output(value: impl Into<String>) -> R {
    let value = value.into();
    if value.len() > MAX_BYTES { return Err(err("template string exceeds byte limit")); }
    Ok(V::String(value.into()))
}
fn strings_value(values:Option<Vec<V>>,capacity:usize)->R{
    let Some(mut values)=values else{return Ok(V::Slice(gotmpl::TypedSlice::nil("[]string")));};
    if capacity>MAX_ITEMS||capacity.checked_mul(std::mem::size_of::<V>()).is_none_or(|bytes|bytes>MAX_BYTES){return Err(err("string slice exceeds template limit"));}
    let len=values.len();if len>capacity{return Err(err("invalid string slice capacity"));}values.resize_with(capacity,||V::from(""));
    Ok(V::Slice(gotmpl::TypedSlice::values("[]string",Some(values.into()))?.with_len(len)?))
}
fn list(value: Vec<V>) -> R {
    if value.len() > MAX_ITEMS { return Err(err("template list exceeds item limit")); }
    Ok(V::List(value.into()))
}
fn int(value: &V) -> i64 {
    match value {
        V::Int(n) | V::Int64(n) | V::NamedInt64(n,_) => *n, V::Uint(n) => *n as i64, V::Uint8(n)=>i64::from(*n),V::Uint16(n)=>i64::from(*n),V::Uint32(n)=>i64::from(*n), V::Float(n) => gotmpl::float_to_go_i64(*n),
        V::Bool(b) => i64::from(*b),
        V::String(s) => {
            let (negative, unsigned) = s.strip_prefix('-').map_or((false,s.as_ref()), |s| (true,s));
            let unsigned = unsigned.strip_prefix('+').unwrap_or(unsigned);
            let (radix, digits) = if let Some(s) = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")) { (16,s) }
                else if let Some(s) = unsigned.strip_prefix("0b").or_else(|| unsigned.strip_prefix("0B")) { (2,s) }
                else if let Some(s) = unsigned.strip_prefix("0o").or_else(|| unsigned.strip_prefix("0O")) { (8,s) }
                else if unsigned.len() > 1 && unsigned.starts_with('0') { (8,&unsigned[1..]) }
                else { (10,unsigned) };
            i128::from_str_radix(digits,radix).ok().and_then(|n| i64::try_from(if negative {-n} else {n}).ok()).unwrap_or(0)
        }
        _ => 0,
    }
}
fn float(value: &V) -> f64 {
    match value {
        V::Float(n) => *n, V::Int(n) | V::Int64(n) | V::NamedInt64(n,_) => *n as f64, V::Uint(n) => *n as f64,V::Uint8(n)=>f64::from(*n),V::Uint16(n)=>f64::from(*n),V::Uint32(n)=>f64::from(*n),
        V::Bool(b) => u8::from(*b) as f64,
        V::String(s) => s.parse().unwrap_or(0.0), _ => 0.0,
    }
}
fn string_list(value: &V) -> Vec<String> {
    match value {
        V::Nil => Vec::new(),
        V::List(values) => values.iter().filter(|v| !matches!(v,V::Nil)).map(text).collect(),
        value => vec![text(value)],
    }
}
fn checked_length(base: usize, extra: usize) -> gotmpl::Result<usize> {
    base.checked_add(extra).filter(|n| *n <= MAX_BYTES).ok_or_else(|| err("template output exceeds byte limit"))
}

pub(super) fn json_value(value:&serde_json::Value,maps:&gotmpl::MapContext)->R{encoding::from_json(value,maps,0)}

pub(super) fn signatures()->BTreeMap<String,gotmpl::Signature>{signatures::all()}
