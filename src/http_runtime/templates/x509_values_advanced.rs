// Portions derived from Go math/big. Copyright The Go Authors.
// Used under the BSD 3-Clause license in THIRD-PARTY-NOTICES.
//! Owned advanced arithmetic. All inputs are staged before any receiver change.
use super::*;
fn abs(x: BigInt) -> BigInt {
    if x.sign() == Sign::Minus { -x } else { x }
}
fn stage(f: &Arc<Factory>, v: &Value) -> RenderResult<BigInt> {
    let Value::Object(o) = v else {
        return Err(error("expected *big.Int"));
    };
    read_number(payload(o)?, f)
}
fn target(v: &Value) -> RenderResult<Option<Arc<Integer>>> {
    if matches!(v, Value::Nil) {
        return Ok(None);
    };
    let Value::Object(o) = v else {
        return Err(error("expected *big.Int"));
    };
    if o.is_nil_pointer() {
        return Ok(None);
    };
    Ok(Some(shared_payload(o)?))
}
fn peak(f: &Factory, bits: u64) -> RenderResult<()> {
    let n = usize::try_from(bits.div_ceil(8)).map_err(|_| error("big.Int size overflow"))?;
    f.reserve(
        n.checked_mul(64)
            .and_then(|n| n.checked_add(16384))
            .ok_or_else(|| error("big.Int peak overflow"))?,
    )
}
fn step(f: &Factory, bits: u64) -> RenderResult<()> {
    let l = usize::try_from(bits.div_ceil(64))
        .map_err(|_| error("big.Int work overflow"))?
        .max(1);
    f.work(
        l.checked_mul(l)
            .and_then(|n| n.checked_mul(8))
            .ok_or_else(|| error("big.Int work overflow"))?,
    )
}
fn write(d: &Integer, n: BigInt) -> RenderResult<()> {
    let mut s = d
        .number
        .lock()
        .map_err(|_| error("big.Int cell poisoned"))?;
    let e = s
        .epoch
        .checked_add(1)
        .ok_or_else(|| error("big.Int epoch overflow"))?;
    s.number = n;
    s.epoch = e;
    Ok(())
}
// Lock all distinct output cells in canonical address order. No budget gate,
// arithmetic, or fallible epoch calculation occurs after the first assignment.
fn write_all(writes: Vec<(Arc<Integer>, BigInt)>) -> RenderResult<()> {
    let mut unique = BTreeMap::new();
    for (cell, value) in writes {
        unique.insert(Arc::as_ptr(&cell) as usize, (cell, value));
    }
    let (cells, values): (Vec<_>, Vec<_>) = unique.into_values().unzip();
    let mut guards = Vec::with_capacity(cells.len());
    for cell in &cells {
        guards.push(
            cell.number
                .lock()
                .map_err(|_| error("big.Int cell poisoned"))?,
        );
    }
    let epochs = guards
        .iter()
        .map(|s| {
            s.epoch
                .checked_add(1)
                .ok_or_else(|| error("big.Int epoch overflow"))
        })
        .collect::<RenderResult<Vec<_>>>()?;
    for ((state, value), epoch) in guards.iter_mut().zip(values).zip(epochs) {
        state.number = value;
        state.epoch = epoch;
    }
    Ok(())
}
fn nil(f: &Arc<Factory>) -> RenderResult<Value> {
    f.reserve(512)?;
    Ok(Value::Object(Arc::new(Object {
        go_type: Some("*big.Int"),
        nil_pointer: Some(Arc::new(|| true)),
        data: Some(Arc::new(Integer {
            number: Mutex::new(State {
                number: BigInt::from(0),
                epoch: 0,
            }),
            owner: Arc::downgrade(f),
        })),
        formatter: Some(format_integer),
        host_type: Some(&BIG_TYPE),
        ..Object::default()
    })))
}
fn extended(f: &Factory, a: BigInt, b: BigInt) -> RenderResult<(BigInt, BigInt, BigInt)> {
    let an = a.sign() == Sign::Minus;
    let bn = b.sign() == Sign::Minus;
    let (mut r, mut next) = (abs(a), abs(b));
    let (mut x, mut nx) = (BigInt::from(1), BigInt::from(0));
    let (mut y, mut ny) = (BigInt::from(0), BigInt::from(1));
    while next.sign() != Sign::NoSign {
        step(f, r.bits().max(next.bits()))?;
        let q = &r / &next;
        let nr = r - &q * &next;
        r = next;
        next = nr;
        let t = x - &q * &nx;
        x = nx;
        nx = t;
        let t = y - &q * &ny;
        y = ny;
        ny = t;
    }
    if an {
        x = -x
    };
    if bn {
        y = -y
    };
    Ok((r, x, y))
}
fn inverse(f: &Factory, g: BigInt, n: BigInt) -> RenderResult<Option<BigInt>> {
    let n = abs(n);
    let g = if g.sign() == Sign::Minus {
        if n.sign() == Sign::NoSign {
            return Err(error("division by zero"));
        };
        let mut r = g % &n;
        if r.sign() == Sign::Minus {
            r += &n
        };
        r
    } else {
        g
    };
    let (d, mut x, _) = extended(f, g, n.clone())?;
    if d != BigInt::from(1) {
        return Ok(None);
    };
    if x.sign() == Sign::Minus {
        x += n
    };
    Ok(Some(x))
}
pub(super) fn invoke(o: &Object, name: &str, args: &[Value]) -> RenderResult<Value> {
    let data = shared_payload(o)?;
    let f = owner(&data)?;
    f.work(1)?;
    arity(
        args,
        match name {
            "Exp" => 3,
            "GCD" => 4,
            _ => 2,
        },
        match name {
            "Exp" => 3,
            "GCD" => 4,
            _ => 2,
        },
    )?;
    let result = match name {
        "MulRange" | "Binomial" => {
            let (Value::Int64(a), Value::Int64(b)) = (&args[0], &args[1]) else {
                return Err(error("expected int64"));
            };
            let (a, b) = (*a, *b);
            if name == "MulRange" {
                if a > b {
                    BigInt::from(1)
                } else if a <= 0 && b >= 0 {
                    BigInt::from(0)
                } else {
                    let count = (b as i128 - a as i128 + 1) as u64;
                    let lo = (a as i128).abs().min((b as i128).abs()) as u64;
                    let hi = (a as i128).abs().max((b as i128).abs()) as u64;
                    peak(
                        &f,
                        count
                            .checked_mul((64 - hi.leading_zeros()) as u64)
                            .ok_or_else(|| error("big.Int range size overflow"))?,
                    )?;
                    f.work(
                        usize::try_from(count).map_err(|_| error("big.Int range work overflow"))?,
                    )?;
                    let mut r = BigInt::from(1);
                    for i in lo..=hi {
                        step(&f, r.bits())?;
                        r *= i
                    }
                    if b < 0 && count % 2 == 1 { -r } else { r }
                }
            } else if b > a || b < 0 {
                BigInt::from(0)
            } else {
                let k = b.min(a - b) as u64;
                peak(
                    &f,
                    k.checked_mul((64 - (a as u64).leading_zeros()) as u64 + 1)
                        .ok_or_else(|| error("big.Int binomial size overflow"))?,
                )?;
                f.work(usize::try_from(k).map_err(|_| error("big.Int binomial work overflow"))?)?;
                let mut r = BigInt::from(1);
                for i in 0..k {
                    step(&f, r.bits())?;
                    r *= a as u64 - i;
                    r /= i + 1
                }
                r
            }
        }
        "ModInverse" => {
            let g = stage(&f, &args[0])?;
            let n = stage(&f, &args[1])?;
            peak(&f, g.bits().max(n.bits()) + 4)?;
            let Some(r) = inverse(&f, g, n)? else {
                return nil(&f);
            };
            r
        }
        "Exp" => {
            let x = stage(&f, &args[0])?;
            let y = stage(&f, &args[1])?;
            let negative_exponent = y.sign() == Sign::Minus;
            let m = if target(&args[2])?.is_none() {
                BigInt::from(0)
            } else {
                abs(stage(&f, &args[2])?)
            };
            if y.sign() == Sign::Minus && m.sign() == Sign::NoSign {
                BigInt::from(1)
            } else {
                let mut base = if y.sign() == Sign::Minus {
                    peak(&f, x.bits().max(m.bits()) + 4)?;
                    let Some(r) = inverse(&f, x.clone(), m.clone())? else {
                        return nil(&f);
                    };
                    abs(r)
                } else {
                    abs(x.clone())
                };
                let modular = m.sign() != Sign::NoSign;
                let exponent = abs(y);
                let bits = if modular {
                    m.bits().checked_mul(2).and_then(|n| n.checked_add(4))
                } else if base == BigInt::from(0) || base == BigInt::from(1) {
                    Some(2)
                } else {
                    let (_, v) = exponent.to_u64_digits();
                    if v.len() > 1 {
                        None
                    } else {
                        base.bits()
                            .checked_mul(v.first().copied().unwrap_or(0))
                            .and_then(|n| n.checked_add(2))
                    }
                }
                .ok_or_else(|| error("big.Int exponent result overflow"))?;
                peak(&f, bits)?;
                f.work(
                    usize::try_from(exponent.bits())
                        .map_err(|_| error("big.Int exponent work overflow"))?,
                )?;
                if modular {
                    base %= &m
                };
                let mut r = BigInt::from(1);
                if modular {
                    r %= &m
                };
                for i in 0..exponent.bits() {
                    step(&f, bits)?;
                    if exponent.bit(i) {
                        r *= &base;
                        if modular {
                            r %= &m
                        }
                    };
                    if i + 1 < exponent.bits() {
                        base = &base * &base;
                        if modular {
                            base %= &m
                        }
                    }
                }
                if !negative_exponent
                    && x.sign() == Sign::Minus
                    && exponent.bit(0)
                    && r.sign() != Sign::NoSign
                {
                    if modular { r = &m - r } else { r = -r }
                };
                r
            }
        }
        "GCD" => {
            let xt = target(&args[0])?;
            let yt = target(&args[1])?;
            for cell in [&xt, &yt].into_iter().flatten() {
                let target_owner = owner(cell)?;
                if !Arc::ptr_eq(&target_owner, &f) {
                    return Err(error("foreign big.Int output owner"));
                }
                target_owner.work(0)?;
            }
            let a = stage(&f, &args[2])?;
            let b = stage(&f, &args[3])?;
            let zero = a.sign() == Sign::NoSign || b.sign() == Sign::NoSign;
            peak(&f, a.bits().max(b.bits()) + 4)?;
            let (g, x, y) = if a.sign() == Sign::NoSign && b.sign() == Sign::NoSign {
                (BigInt::from(0), BigInt::from(0), BigInt::from(0))
            } else {
                extended(&f, a, b)?
            };
            f.reserve(512)?;
            f.work(0)?;
            f.reserve(2048)?;
            let mut writes = Vec::with_capacity(3);
            if zero {
                writes.push((data.clone(), g));
                if let Some(t) = xt {
                    writes.push((t, x));
                }
                if let Some(t) = yt {
                    writes.push((t, y));
                }
            } else {
                if let Some(t) = yt {
                    writes.push((t, y));
                }
                if let Some(t) = xt {
                    writes.push((t, x));
                }
                writes.push((data.clone(), g));
            }
            f.work(0)?;
            let bits = writes
                .iter()
                .rev()
                .find(|(cell, _)| Arc::ptr_eq(cell, &data))
                .ok_or_else(|| error("missing receiver commit"))?
                .1
                .bits();
            let wrapped = rewrap(o, data.clone(), bits)?;
            write_all(writes)?;
            return Ok(wrapped);
        }
        _ => return Err(error("unsupported advanced integer method")),
    };
    f.reserve(512)?;
    f.work(0)?;
    let wrapped = rewrap(o, data.clone(), result.bits())?;
    write(&data, result)?;
    Ok(wrapped)
}
