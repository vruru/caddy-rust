// Portions derived from Go math/big. Copyright The Go Authors.
// Used under the BSD 3-Clause license in THIRD-PARTY-NOTICES.
//! Modular square roots; callers reserve owned limb peaks before entry.
use super::*;
fn modulo(mut x: BigInt, p: &BigInt) -> BigInt {
    x %= p;
    if x.sign() == Sign::Minus {
        x += p
    };
    x
}
pub(in super::super) fn jacobi(f: &Factory, x: BigInt, p: &BigInt) -> RenderResult<i32> {
    let mut a = modulo(x, p);
    let mut b = p.clone();
    let mut sign = 1;
    while a.sign() != Sign::NoSign {
        step(f, a.bits().max(b.bits()))?;
        let shift = a.trailing_zeros().unwrap_or(0);
        a >>= usize::try_from(shift).map_err(|_| error("Jacobi shift overflow"))?;
        if shift % 2 == 1 && b.bit(1) != b.bit(2) {
            sign = -sign
        }
        if a.bit(1) && b.bit(1) {
            sign = -sign
        }
        let next = b % &a;
        b = a;
        a = next;
    }
    Ok(if b == BigInt::from(1) { sign } else { 0 })
}
pub(in super::super) fn power(f: &Factory, mut x: BigInt, e: BigInt, p: &BigInt) -> RenderResult<BigInt> {
    x = modulo(x, p);
    let mut r = BigInt::from(1);
    for i in 0..e.bits() {
        step(f, p.bits() * 2 + 4)?;
        if e.bit(i) {
            r = (r * &x) % p
        };
        if i + 1 < e.bits() {
            x = (&x * &x) % p
        }
    }
    Ok(r)
}
fn square(f: &Factory, x: &BigInt, p: &BigInt) -> RenderResult<BigInt> {
    step(f, p.bits() * 2 + 4)?;
    Ok((x * x) % p)
}
pub(super) fn compute(f: &Factory, x: BigInt, p: BigInt) -> RenderResult<Option<BigInt>> {
    if p <= BigInt::from(1) || !p.bit(0) {
        return Err(error("ModSqrt requires an odd prime modulus"));
    }
    peak(
        f,
        p.bits()
            .checked_mul(2)
            .and_then(|n| n.checked_add(8))
            .ok_or_else(|| error("ModSqrt size overflow"))?,
    )?;
    match jacobi(f, x.clone(), &p)? {
        -1 => return Ok(None),
        0 => return Ok(Some(BigInt::from(0))),
        _ => {}
    }
    let x = modulo(x, &p);
    if p.bit(1) {
        let e = (&p + 1) >> 2usize;
        return Ok(Some(power(f, x, e, &p)?));
    }
    if p.bit(2) {
        let e = &p >> 3usize;
        let tx = &x << 1usize;
        let alpha = power(f, tx.clone(), e, &p)?;
        let mut beta = square(f, &alpha, &p)?;
        step(f, p.bits() * 2 + 4)?;
        beta = (beta * tx) % &p;
        beta -= 1;
        beta = modulo(beta * &x, &p);
        beta = modulo(beta * alpha, &p);
        return Ok(Some(beta));
    }
    let mut s: BigInt = &p - 1;
    let mut r = s.trailing_zeros().unwrap_or(0);
    s >>= usize::try_from(r).map_err(|_| error("ModSqrt shift overflow"))?;
    let mut n = BigInt::from(2);
    while jacobi(f, n.clone(), &p)? != -1 {
        step(f, p.bits())?;
        n += 1
    }
    let mut y = power(f, x.clone(), (&s + 1) >> 1usize, &p)?;
    let mut b = power(f, x, s.clone(), &p)?;
    let mut g = power(f, n, s, &p)?;
    loop {
        let mut m = 0u64;
        let mut t = b.clone();
        while t != BigInt::from(1) {
            if m >= r {
                return Err(error("ModSqrt modulus is not an odd prime"));
            };
            t = square(f, &t, &p)?;
            m += 1
        }
        if m == 0 {
            return Ok(Some(y));
        }
        let shift = r
            .checked_sub(m + 1)
            .ok_or_else(|| error("ModSqrt modulus is not an odd prime"))?;
        t = power(
            f,
            g,
            BigInt::from(1)
                << usize::try_from(shift).map_err(|_| error("ModSqrt shift overflow"))?,
            &p,
        )?;
        g = square(f, &t, &p)?;
        step(f, p.bits() * 2 + 4)?;
        y = (y * t) % &p;
        b = (b * &g) % &p;
        r = m;
    }
}
