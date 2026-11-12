//! The math extension library: functions and macros in the `math` namespace,
//! following cel-go's `ext.Math()`.

use crate::common::ast::{CallExpr, Expr, IdedExpr, ListExpr, LiteralValue};
use crate::common::functions::Function;
use crate::common::types::{
    CelBool, CelDouble, CelInt, CelUInt, Kind, Type, DOUBLE_TYPE, INT_TYPE, LIST_TYPE, UINT_TYPE,
};
use crate::common::value::{CowVal, Val};
use crate::parser::{Macro, MacroExprHelper};
use crate::{DeclarationError, Env, ExecutionError, ParseError};
use std::cmp::Ordering;

/// Registers the math extension's overloads and macros on `env`.
pub fn extension(env: &mut Env) -> Result<(), DeclarationError> {
    crate::add_overload!(env, fn ceil: (CelDouble) -> CelDouble, name = "math.ceil")?;
    crate::add_overload!(env, fn floor: (CelDouble) -> CelDouble, name = "math.floor")?;
    crate::add_overload!(env, fn round: (CelDouble) -> CelDouble, name = "math.round")?;
    crate::add_overload!(env, fn trunc: (CelDouble) -> CelDouble, name = "math.trunc")?;
    crate::add_overload!(env, fn is_inf: (CelDouble) -> CelBool, name = "math.isInf")?;
    crate::add_overload!(env, fn is_nan: (CelDouble) -> CelBool, name = "math.isNaN")?;
    crate::add_overload!(env, fn is_finite: (CelDouble) -> CelBool, name = "math.isFinite")?;
    crate::add_overload!(env, fn abs_double: (CelDouble) -> CelDouble, name = "math.abs")?;
    crate::add_overload!(env, fn abs_int: (CelInt) -> Result<CelInt>, name = "math.abs")?;
    crate::add_overload!(env, fn abs_uint: (CelUInt) -> CelUInt, name = "math.abs")?;
    crate::add_overload!(env, fn sign_double: (CelDouble) -> CelDouble, name = "math.sign")?;
    crate::add_overload!(env, fn sign_int: (CelInt) -> CelInt, name = "math.sign")?;
    crate::add_overload!(env, fn sign_uint: (CelUInt) -> CelUInt, name = "math.sign")?;
    crate::add_overload!(env, fn bit_and_int: (CelInt, CelInt) -> CelInt, name = "math.bitAnd")?;
    crate::add_overload!(env, fn bit_and_uint: (CelUInt, CelUInt) -> CelUInt, name = "math.bitAnd")?;
    crate::add_overload!(env, fn bit_or_int: (CelInt, CelInt) -> CelInt, name = "math.bitOr")?;
    crate::add_overload!(env, fn bit_or_uint: (CelUInt, CelUInt) -> CelUInt, name = "math.bitOr")?;
    crate::add_overload!(env, fn bit_xor_int: (CelInt, CelInt) -> CelInt, name = "math.bitXor")?;
    crate::add_overload!(env, fn bit_xor_uint: (CelUInt, CelUInt) -> CelUInt, name = "math.bitXor")?;
    crate::add_overload!(env, fn bit_not_int: (CelInt) -> CelInt, name = "math.bitNot")?;
    crate::add_overload!(env, fn bit_not_uint: (CelUInt) -> CelUInt, name = "math.bitNot")?;
    crate::add_overload!(env, fn bit_shift_left_int: (CelInt, CelInt) -> Result<CelInt>,
        name = "math.bitShiftLeft")?;
    crate::add_overload!(env, fn bit_shift_left_uint: (CelUInt, CelInt) -> Result<CelUInt>,
        name = "math.bitShiftLeft")?;
    crate::add_overload!(env, fn bit_shift_right_int: (CelInt, CelInt) -> Result<CelInt>,
        name = "math.bitShiftRight")?;
    crate::add_overload!(env, fn bit_shift_right_uint: (CelUInt, CelInt) -> Result<CelUInt>,
        name = "math.bitShiftRight")?;
    crate::add_overload!(env, fn sqrt_double: (CelDouble) -> CelDouble, name = "math.sqrt")?;
    crate::add_overload!(env, fn sqrt_int: (CelInt) -> CelDouble, name = "math.sqrt")?;
    crate::add_overload!(env, fn sqrt_uint: (CelUInt) -> CelDouble, name = "math.sqrt")?;
    extreme_overloads(env, "math.@max", max)?;
    extreme_overloads(env, "math.@min", min)?;
    env.add_macro(Macro::receiver_var_arg(
        "greatest",
        |helper, target, args| extreme(helper, target, args, "greatest", "math.@max"),
    ))?;
    env.add_macro(Macro::receiver_var_arg("least", |helper, target, args| {
        extreme(helper, target, args, "least", "math.@min")
    }))?;
    Ok(())
}

/// `math.greatest(..)` or `math.least(..)`, the `macro_name`: a call of
/// `function` on the one argument, the two arguments, or a list of the
/// arguments when there are more. Declines any target but `math`.
fn extreme(
    helper: &mut MacroExprHelper<'_>,
    target: &mut Option<IdedExpr>,
    args: &mut Vec<IdedExpr>,
    macro_name: &str,
    function: &str,
) -> Result<Option<IdedExpr>, ParseError> {
    let Some(target) = target
        .as_ref()
        .filter(|t| matches!(&t.expr, Expr::Ident(namespace) if namespace == "math"))
    else {
        return Ok(None);
    };
    let invalid = match args.as_slice() {
        [] => Some((target.id, "requires at least one argument")),
        [arg] if !is_numeric_list(arg) && !may_be_numeric(arg) => {
            Some((arg.id, "invalid single argument value"))
        }
        [_] => None,
        args => args
            .iter()
            .find(|arg| !may_be_numeric(arg))
            .map(|arg| (arg.id, "simple literal arguments must be numeric")),
    };
    if let Some((id, message)) = invalid {
        return Err(helper.new_error(id, format!("math.{macro_name}() {message}")));
    }
    let mut args = std::mem::take(args);
    if args.len() > 2 {
        args = vec![helper.next_expr(Expr::List(ListExpr::new(args)))];
    }
    Ok(Some(helper.next_expr(Expr::Call(CallExpr {
        func_name: function.to_owned(),
        target: None,
        args,
    }))))
}

/// Whether `arg` can be a number: a numeric literal, or anything but another
/// literal, a list, a map or a message.
fn may_be_numeric(arg: &IdedExpr) -> bool {
    match &arg.expr {
        Expr::Literal(literal) => matches!(
            literal,
            LiteralValue::Int(_) | LiteralValue::UInt(_) | LiteralValue::Double(_)
        ),
        Expr::List(_) | Expr::Map(_) | Expr::Struct(_) => false,
        _ => true,
    }
}

/// Whether `arg` is a list literal of things that can be numbers, not empty.
fn is_numeric_list(arg: &IdedExpr) -> bool {
    matches!(&arg.expr, Expr::List(list)
        if !list.elements.is_empty() && list.elements.iter().all(may_be_numeric))
}

/// Registers `f` as `name`'s overloads: for a number, two numbers, and a list.
fn extreme_overloads(env: &mut Env, name: &str, f: Function) -> Result<(), DeclarationError> {
    const NUMBERS: [Type; 3] = [INT_TYPE, UINT_TYPE, DOUBLE_TYPE];
    for t in &NUMBERS {
        env.add_overload(
            name,
            &format!("{name}({})", t.name()),
            vec![t.to_owned()],
            f,
        )?;
    }
    for a in &NUMBERS {
        for b in &NUMBERS {
            let id = format!("{name}({},{})", a.name(), b.name());
            env.add_overload(name, &id, vec![a.to_owned(), b.to_owned()], f)?;
        }
    }
    env.add_overload(name, &format!("{name}(list)"), vec![LIST_TYPE], f)
}

fn max<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    extreme_of("math.@max", Ordering::Greater, args)
}

fn min<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    extreme_of("math.@min", Ordering::Less, args)
}

/// The greatest or least of the numbers, as `wanted` says: of the two
/// arguments, or of the elements of the one when it's a list. The first of
/// equal ones wins, keeping its type.
fn extreme_of<'b, 'v>(
    function: &str,
    wanted: Ordering,
    mut args: Vec<CowVal<'b, 'v>>,
) -> Result<CowVal<'b, 'v>, ExecutionError> {
    match (args.pop(), args.pop()) {
        (Some(second), Some(first)) => Ok(
            if compare(first.as_ref(), second.as_ref())? == wanted.reverse() {
                second
            } else {
                first
            },
        ),
        (Some(arg), None) => {
            let Some(list) = arg.as_ref().as_iterable() else {
                return Ok(arg);
            };
            let mut items = list.iter();
            let mut extreme = items.next().ok_or_else(|| {
                ExecutionError::function_error(function, "the list must not be empty")
            })?;
            number(function, extreme)?;
            while let Some(item) = items.next() {
                if compare(extreme, number(function, item)?)? == wanted.reverse() {
                    extreme = item;
                }
            }
            Ok(CowVal::Owned(extreme.clone_as_boxed()))
        }
        _ => Err(ExecutionError::invalid_argument_count(1, 0)),
    }
}

/// `val`, if it's a number: no `function` overload takes anything else.
fn number<'b, 'v>(
    function: &str,
    val: &'b (dyn Val + 'v),
) -> Result<&'b (dyn Val + 'v), ExecutionError> {
    match val.get_type().kind() {
        Kind::Int | Kind::UInt | Kind::Double => Ok(val),
        _ => Err(ExecutionError::overload_for_values(function, [val], false)),
    }
}

fn compare(lhs: &dyn Val, rhs: &dyn Val) -> Result<Ordering, ExecutionError> {
    lhs.as_comparer()
        .ok_or_else(|| ExecutionError::values_not_comparable(lhs, rhs))?
        .compare(rhs)
}

fn ceil(x: &CelDouble) -> CelDouble {
    x.inner().ceil().into()
}

fn floor(x: &CelDouble) -> CelDouble {
    x.inner().floor().into()
}

/// Rounds half away from zero.
fn round(x: &CelDouble) -> CelDouble {
    x.inner().round().into()
}

fn trunc(x: &CelDouble) -> CelDouble {
    x.inner().trunc().into()
}

fn is_inf(x: &CelDouble) -> CelBool {
    x.inner().is_infinite().into()
}

fn is_nan(x: &CelDouble) -> CelBool {
    x.inner().is_nan().into()
}

fn is_finite(x: &CelDouble) -> CelBool {
    x.inner().is_finite().into()
}

fn abs_double(x: &CelDouble) -> CelDouble {
    x.inner().abs().into()
}

/// Fails for `i64::MIN`, whose absolute value is not an `int`.
fn abs_int(x: &CelInt) -> Result<CelInt, ExecutionError> {
    x.inner()
        .checked_abs()
        .map(CelInt::from)
        .ok_or_else(|| ExecutionError::function_error("math.abs", "integer overflow"))
}

fn abs_uint(x: &CelUInt) -> CelUInt {
    *x
}

/// `-1.0`, `0.0` or `1.0`, or NaN for NaN: both zeros are `0.0`, where
/// `f64::signum` would give them a sign.
fn sign_double(x: &CelDouble) -> CelDouble {
    let x = *x.inner();
    if x > 0.0 {
        1.0.into()
    } else if x < 0.0 {
        (-1.0).into()
    } else if x == 0.0 {
        0.0.into()
    } else {
        x.into()
    }
}

fn sign_int(x: &CelInt) -> CelInt {
    x.inner().signum().into()
}

fn sign_uint(x: &CelUInt) -> CelUInt {
    u64::from(*x.inner() != 0).into()
}

fn bit_and_int(l: &CelInt, r: &CelInt) -> CelInt {
    (l.inner() & r.inner()).into()
}

fn bit_and_uint(l: &CelUInt, r: &CelUInt) -> CelUInt {
    (l.inner() & r.inner()).into()
}

fn bit_or_int(l: &CelInt, r: &CelInt) -> CelInt {
    (l.inner() | r.inner()).into()
}

fn bit_or_uint(l: &CelUInt, r: &CelUInt) -> CelUInt {
    (l.inner() | r.inner()).into()
}

fn bit_xor_int(l: &CelInt, r: &CelInt) -> CelInt {
    (l.inner() ^ r.inner()).into()
}

fn bit_xor_uint(l: &CelUInt, r: &CelUInt) -> CelUInt {
    (l.inner() ^ r.inner()).into()
}

fn bit_not_int(x: &CelInt) -> CelInt {
    (!x.inner()).into()
}

fn bit_not_uint(x: &CelUInt) -> CelUInt {
    (!x.inner()).into()
}

/// The bits of a shift by `bits`, `None` when they shift all 64 bits out.
/// Fails when negative.
fn shift(function: &str, bits: &CelInt) -> Result<Option<u32>, ExecutionError> {
    let bits = *bits.inner();
    if bits < 0 {
        return Err(ExecutionError::function_error(
            function,
            format!("negative offset: {bits}"),
        ));
    }
    Ok(u32::try_from(bits).ok().filter(|&bits| bits < u64::BITS))
}

fn bit_shift_left_int(x: &CelInt, bits: &CelInt) -> Result<CelInt, ExecutionError> {
    let shifted = shift("math.bitShiftLeft", bits)?.map_or(0, |bits| x.inner() << bits);
    Ok(shifted.into())
}

fn bit_shift_left_uint(x: &CelUInt, bits: &CelInt) -> Result<CelUInt, ExecutionError> {
    let shifted = shift("math.bitShiftLeft", bits)?.map_or(0, |bits| x.inner() << bits);
    Ok(shifted.into())
}

/// Fills the vacated bits with zeros: the sign is not extended.
fn bit_shift_right_int(x: &CelInt, bits: &CelInt) -> Result<CelInt, ExecutionError> {
    let shifted = shift("math.bitShiftRight", bits)?.map_or(0, |bits| (*x.inner() as u64) >> bits);
    Ok((shifted as i64).into())
}

fn bit_shift_right_uint(x: &CelUInt, bits: &CelInt) -> Result<CelUInt, ExecutionError> {
    let shifted = shift("math.bitShiftRight", bits)?.map_or(0, |bits| x.inner() >> bits);
    Ok(shifted.into())
}

/// NaN for a negative `x`.
fn sqrt_double(x: &CelDouble) -> CelDouble {
    x.inner().sqrt().into()
}

fn sqrt_int(x: &CelInt) -> CelDouble {
    (*x.inner() as f64).sqrt().into()
}

fn sqrt_uint(x: &CelUInt) -> CelDouble {
    (*x.inner() as f64).sqrt().into()
}
