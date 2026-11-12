//! Owned arithmetic only. Receiver mutation and all peak reservations happen
//! in the caller; no number cell lock spans these computations.
use super::{Factory, RenderResult, error};
use bigdecimal::num_bigint::{BigInt, Sign};
pub(super) fn compute(
    factory: &Factory,
    name: &str,
    mut x: BigInt,
    y: Option<BigInt>,
    scalar: u64,
) -> RenderResult<BigInt> {
    factory.work(0)?;
    match name {
        "Abs" => Ok(abs(x)),
        "Neg" => Ok(-x),
        "Not" => Ok(!x),
        "Add" => Ok(x + y.ok_or_else(|| error("missing Add operand"))?),
        "Sub" => Ok(x - y.ok_or_else(|| error("missing Sub operand"))?),
        "Mul" => Ok(x * y.ok_or_else(|| error("missing Mul operand"))?),
        "And" => Ok(x & y.ok_or_else(|| error("missing And operand"))?),
        "AndNot" => Ok(x & !y.ok_or_else(|| error("missing AndNot operand"))?),
        "Or" => Ok(x | y.ok_or_else(|| error("missing Or operand"))?),
        "Xor" => Ok(x ^ y.ok_or_else(|| error("missing Xor operand"))?),
        "Quo" | "Rem" | "Div" | "Mod" => {
            let y = y.ok_or_else(|| error("missing division operand"))?;
            if y.sign() == Sign::NoSign {
                return Err(error("division by zero"));
            }
            if name == "Quo" {
                return Ok(x / y);
            }
            let mut remainder = &x % &y;
            if name == "Rem" {
                return Ok(remainder);
            }
            if name == "Mod" {
                if remainder.sign() == Sign::Minus {
                    remainder += abs(y);
                }
                return Ok(remainder);
            }
            let mut quotient = &x / &y;
            if remainder.sign() == Sign::Minus {
                if y.sign() == Sign::Plus {
                    quotient -= 1;
                } else {
                    quotient += 1;
                }
            }
            Ok(quotient)
        }
        "Lsh" | "Rsh" => {
            if x.sign() == Sign::NoSign {
                return Ok(x);
            }
            let shift =
                usize::try_from(scalar).map_err(|_| error("shift index exceeds native uint"))?;
            Ok(if name == "Lsh" {
                x << shift
            } else {
                x >> shift
            })
        }
        "SetBit" => {
            let y = y.ok_or_else(|| error("missing SetBit value"))?;
            if y != BigInt::from(0) && y != BigInt::from(1) {
                return Err(error("set bit is not 0 or 1"));
            }
            x.set_bit(scalar, y.sign() != Sign::NoSign);
            Ok(x)
        }
        "Sqrt" => {
            if x.sign() == Sign::Minus {
                return Err(error("square root of negative number"));
            }
            if x.sign() == Sign::NoSign {
                return Ok(x);
            }
            let shift =
                usize::try_from(x.bits().div_ceil(2)).map_err(|_| error("sqrt size overflow"))?;
            let mut estimate = BigInt::from(1) << shift;
            loop {
                factory.work(0)?;
                let next = (&estimate + &x / &estimate) >> 1usize;
                if next >= estimate {
                    return Ok(estimate);
                }
                estimate = next;
            }
        }
        _ => Err(error("unsupported big.Int arithmetic operation")),
    }
}
fn abs(value: BigInt) -> BigInt {
    if value.sign() == Sign::Minus {
        -value
    } else {
        value
    }
}
