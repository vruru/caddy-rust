// Portions derived from Go math/big. Copyright The Go Authors.
// Used under the BSD 3-Clause license in THIRD-PARTY-NOTICES.
//! Deterministic Go Miller–Rabin bases and extra-strong Lucas test.
use super::advanced::peak;
use super::*;
#[path = "x509_values_prime_rng.rs"]
mod random;

pub(super) fn invoke(o: &Object, args: &[Value]) -> RenderResult<Value> {
    arity(args, 1, 1)?;
    let count = args[0].as_int().ok_or_else(|| error("expected int"))?;
    if count < 0 {
        return Err(error("negative n for ProbablyPrime"));
    }
    let d = payload(o)?;
    let f = owner(d)?;
    f.work(1)?;
    let n = read_number(d, &f)?;
    let mut numeric=f.numeric()?;
    let result=compute(&f,n,count as u64);
    // Restore even for arithmetic/resource errors before returning to the
    // ordinary template executor. Panic/cancel instead unwind the guard.
    numeric.resume()?;
    Ok(Value::Bool(result?))
}

fn compute(f: &Factory, n: BigInt, rounds: u64) -> RenderResult<bool> {
    if n.sign() != Sign::Plus {
        return Ok(false);
    }
    if n.bits() <= 6 {
        const MASK: u64 = (1 << 2)
            | (1 << 3)
            | (1 << 5)
            | (1 << 7)
            | (1 << 11)
            | (1 << 13)
            | (1 << 17)
            | (1 << 19)
            | (1 << 23)
            | (1 << 29)
            | (1 << 31)
            | (1 << 37)
            | (1 << 41)
            | (1 << 43)
            | (1 << 47)
            | (1 << 53)
            | (1 << 59)
            | (1 << 61);
        let w = n.iter_u64_digits().next().unwrap_or(0);
        return Ok(MASK & (1 << w) != 0);
    }
    if !n.bit(0) {
        return Ok(false);
    }
    // Bound an individual num_bigint call as well as aggregate work. Its
    // internal multiplication/division cannot observe the cancellation token.
    if n.bits() > 65_536 {
        return Err(error(
            "ProbablyPrime modular operand exceeds 65536-bit resource bound",
        ));
    }
    peak(
        f,
        n.bits()
            .checked_mul(2)
            .and_then(|x| x.checked_add(64))
            .ok_or_else(|| error("ProbablyPrime size overflow"))?,
    )?;
    for p in [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53] {
        linear_fee(f, n.bits())?;
        if (&n % p).sign() == Sign::NoSign {
            return Ok(false);
        }
    }
    let count = rounds
        .checked_add(1)
        .ok_or_else(|| error("ProbablyPrime round overflow"))?;
    // Every round consumes at least one unit. Refuse absurd round counts before
    // constructing the base stream or starting modular exponentiation.
    f.work(usize::try_from(count).map_err(|_| error("ProbablyPrime rounds exceed native size"))?)?;
    f.work(1841)?; //20 warm-up recurrences plus three for each of607 feedback words
    let nm1 = &n - 1u32;
    let k = nm1.trailing_zeros().unwrap_or(0);
    let q = &nm1 >> usize::try_from(k).map_err(|_| error("ProbablyPrime shift overflow"))?;
    let limit = &n - 3u32;
    let words = usize::try_from(limit.bits().div_ceil(64))
        .map_err(|_| error("ProbablyPrime size overflow"))?;
    let mut random_bytes = vec![
        0u8;
        words
            .checked_mul(8)
            .ok_or_else(|| error("ProbablyPrime random size overflow"))?
    ];
    let mut rng = random::Rng::new(n.iter_u64_digits().next().unwrap_or(0) as i64);
    for i in 0..count {
        f.work(0)?;
        let x = if i == rounds {
            BigInt::from(2)
        } else {
            let mask = if limit.bits() % 64 == 0 {
                u64::MAX
            } else {
                (1u64 << (limit.bits() % 64)) - 1
            };
            loop {
                f.work(
                    words
                        .checked_mul(4)
                        .and_then(|x| x.checked_add(1))
                        .ok_or_else(|| error("ProbablyPrime random work overflow"))?,
                )?;
                for j in 0..words {
                    f.work(0)?;
                    let mut word = u64::from(rng.uint32()) | (u64::from(rng.uint32()) << 32);
                    if j + 1 == words {
                        word &= mask;
                    }
                    random_bytes[j * 8..(j + 1) * 8].copy_from_slice(&word.to_le_bytes());
                }
                let x = BigInt::from_bytes_le(Sign::Plus, &random_bytes);
                if x < limit {
                    break x + 2u32;
                }
            }
        };
        let mut y = power(f, x, q.clone(), &n)?;
        if y == BigInt::from(1) || y == nm1 {
            continue;
        }
        let mut accepted = false;
        for _ in 1..k {
            product_fee(f, &y, &y, &n)?;
            y = (&y * &y) % &n;
            if y == nm1 {
                accepted = true;
                break;
            }
            if y == BigInt::from(1) {
                return Ok(false);
            }
        }
        if !accepted {
            return Ok(false);
        }
    }
    lucas(f, &n)
}

fn lucas(f: &Factory, n: &BigInt) -> RenderResult<bool> {
    let mut p = 3u64;
    loop {
        linear_fee(f, n.bits())?;
        if p > 10000 {
            return Err(error("cannot find Lucas parameter"));
        }
        match jacobi(f, BigInt::from(p * p - 4), n)? {
            -1 => break,
            0 => return Ok(n == &BigInt::from(p + 2)),
            _ => {}
        }
        if p == 40 {
            // The library sqrt has no callback. Admit a full quadratic-bit
            // upper estimate first; overlarge operands fail before entry.
            let l = limbs(n.bits())?;
            f.work(
                l.checked_mul(l)
                    .and_then(|v| v.checked_mul(usize::try_from(n.bits()).ok()?))
                    .ok_or_else(|| error("Lucas square work overflow"))?
                    .div_ceil(PRODUCTS_PER_UNIT)
                    .max(1),
            )?;
            let s = n.sqrt();
            if &s * &s == *n {
                return Ok(false);
            }
        }
        p += 1;
    }
    let full = n + 1u32;
    let r = full.trailing_zeros().unwrap_or(0);
    let s = full >> usize::try_from(r).map_err(|_| error("Lucas shift overflow"))?;
    let nm2 = n - 2u32;
    let np = BigInt::from(p);
    let mut v = BigInt::from(2);
    let mut next = np.clone();
    for i in (0..=s.bits()).rev() {
        f.work(1)?;
        product_fee(f, &v, &next, n)?;
        if s.bit(i) {
            v = (&v * &next + n - &np) % n;
            product_fee(f, &next, &next, n)?;
            next = (&next * &next + &nm2) % n;
        } else {
            next = (&v * &next + n - &np) % n;
            product_fee(f, &v, &v, n)?;
            v = (&v * &v + &nm2) % n;
        }
    }
    if v == BigInt::from(2) || v == nm2 {
        product_fee(f, &v, &np, n)?;
        let a = &v * &np;
        let b = &next << 1usize;
        if ((a - b) % n).sign() == Sign::NoSign {
            return Ok(true);
        }
    }
    for _ in 0..r.saturating_sub(1) {
        f.work(1)?;
        if v.sign() == Sign::NoSign {
            return Ok(true);
        }
        if v == BigInt::from(2) {
            return Ok(false);
        }
        product_fee(f, &v, &v, n)?;
        v = (&v * &v - 2u32) % n;
    }
    Ok(false)
}

// A work unit batches 2048 conceptual 64-bit limb products. Modular multiplication
// admits a*b+(a+b)*modulus limbs: schoolbook multiplication plus a conservative
// two-width long-division reduction allowance. Each operation rounds UP (minimum1),
// never down to a free step. Linear scans and RNG operations are separate.
// This local scale is calibrated against 64..4096-bit inputs; it does not alter
// the shared render budget, deadline, or any other mathematical method.
const PRODUCTS_PER_UNIT: usize = 2048;
fn limbs(bits: u64) -> RenderResult<usize> {
    Ok(usize::try_from(bits.div_ceil(64))
        .map_err(|_| error("primality limb count overflow"))?
        .max(1))
}
fn linear_fee(f: &Factory, bits: u64) -> RenderResult<()> {
    f.work(limbs(bits)?.div_ceil(32).max(1))
}
fn division_fee(f: &Factory, numerator: u64, denominator: u64) -> RenderResult<()> {
    let a = limbs(numerator)?;
    let b = limbs(denominator)?;
    let p = a
        .checked_mul(b)
        .ok_or_else(|| error("primality division work overflow"))?;
    f.work(
        p.div_ceil(PRODUCTS_PER_UNIT)
            .max(1)
            .checked_add(a.div_ceil(32))
            .ok_or_else(|| error("primality division work overflow"))?,
    )
}
fn product_fee(f: &Factory, x: &BigInt, y: &BigInt, n: &BigInt) -> RenderResult<()> {
    let a = limbs(x.bits())?;
    let b = limbs(y.bits())?;
    let m = limbs(n.bits())?;
    let products = a
        .checked_mul(b)
        .and_then(|v| a.checked_add(b)?.checked_mul(m)?.checked_add(v))
        .ok_or_else(|| error("primality modular work overflow"))?;
    f.work(products.div_ceil(PRODUCTS_PER_UNIT).max(1))
}
fn power(f: &Factory, mut x: BigInt, e: BigInt, p: &BigInt) -> RenderResult<BigInt> {
    if x >= *p {
        division_fee(f, x.bits(), p.bits())?;
        x %= p;
    }
    let mut r = BigInt::from(1);
    for i in 0..e.bits() {
        f.work(1)?;
        if e.bit(i) {
            product_fee(f, &r, &x, p)?;
            r = (r * &x) % p;
        }
        if i + 1 < e.bits() {
            product_fee(f, &x, &x, p)?;
            x = (&x * &x) % p;
        }
    }
    Ok(r)
}
fn jacobi(f: &Factory, mut a: BigInt, p: &BigInt) -> RenderResult<i32> {
    if a >= *p {
        division_fee(f, a.bits(), p.bits())?;
        a %= p;
    }
    let mut b = p.clone();
    let mut sign = 1;
    while a.sign() != Sign::NoSign {
        linear_fee(f, a.bits().max(b.bits()))?;
        let shift = a.trailing_zeros().unwrap_or(0);
        a >>= usize::try_from(shift).map_err(|_| error("Jacobi shift overflow"))?;
        if shift % 2 == 1 && b.bit(1) != b.bit(2) {
            sign = -sign;
        }
        if a.bit(1) && b.bit(1) {
            sign = -sign;
        }
        division_fee(f, b.bits(), a.bits())?;
        let next = b % &a;
        b = a;
        a = next;
    }
    Ok(if b == BigInt::from(1) { sign } else { 0 })
}
