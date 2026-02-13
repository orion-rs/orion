// MIT License

// Copyright (c) 2025-2026 The orion Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use core::ops::{Add, Mul, Sub};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub(crate) const KYBER_Q: u32 = 3329;

/// Barrett reduction with correctional step.
///
/// Given value < 2q return value mod q (in [0, n]).
///
/// src: https://en.wikipedia.org/wiki/Barrett_reduction
/// src: BoringSSL, https://boringssl.googlesource.com/boringssl/+/refs/heads/main/crypto/fipsmodule/mlkem/mlkem.cc.inc
pub fn barrett_reduce(value: u32) -> u32 {
    debug_assert!(value < KYBER_Q.pow(2));

    const MUL: u64 = 5039;
    const SHIFT: u64 = 24;

    let quo: u32 = ((u64::from(value) * MUL) >> SHIFT) as u32;
    let r = value - (quo * KYBER_Q);
    // NOTE: Guaranteed now 0 <= r < 2q. This is where we add the
    // conditional subtraction.
    debug_assert!((0..KYBER_Q * 2).contains(&r));

    let ret = conditional_sub_u32(r);
    debug_assert!((0..KYBER_Q).contains(&ret));

    ret
}

// Constant-time conditional subtraction
fn conditional_sub_u32(a: u32) -> u32 {
    // Calculate a - mod
    let t: u32 = a.overflowing_sub(KYBER_Q).0;

    // Check if a >= mod (if t is non-negative)
    // If a >= mod, mask will be 0xFFFFFFFF, otherwise 0
    let mask: u32 = 0u32.overflowing_sub(t >> 31).0;

    // If mask is 0, return a (no subtraction), otherwise return t (a - mod)
    (t & !mask) | (a & mask)
}

#[derive(Clone, Copy, PartialEq, Debug)]
/// Element in the field Z_q.
///
/// NOTE(brycx): While for Kyber q = 3329 a field element would fit in u16, but Dilithium q = 8380417 which only fits in u32.
/// Thus, for possible future re-usability, we use 32-bit integer here.
pub struct FieldElement(pub(crate) u32);

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl FieldElement {
    pub fn new(value: u32) -> Self {
        debug_assert!((0..KYBER_Q).contains(&value));

        Self(value)
    }

    pub fn zero() -> Self {
        Self(0)
    }

    /// FIPS-203, def. 4.7.
    /// Mapping of Z_q => Z_{2^{d}}.
    ///
    /// This is a Rust port of:
    /// https://github.com/FiloSottile/mlkem768
    pub fn compress(&self, d: u8) -> u32 {
        debug_assert!((1..=11).contains(&d));

        const MUL: u64 = 5039;
        const SHIFT: u64 = 24;

        let div: u32 = self.0 << d;
        let mut quo: u32 = ((u64::from(div) * MUL) >> SHIFT) as u32;
        let rem: u32 = div - (quo * KYBER_Q);

        quo += ((KYBER_Q / 2).overflowing_sub(rem).0 >> 31) & 1;
        quo += ((KYBER_Q + KYBER_Q / 2 - rem) >> 31) & 1;

        let mask: u32 = (1 << d as u32) - 1;

        ((quo & mask) as u16) as u32
    }

    /// FIPS-203, def. 4.8.
    /// Mapping of Z_{2^{d}} => Z_q.
    ///
    /// This is a Rust port of:
    /// https://github.com/FiloSottile/mlkem768
    pub fn decompress(y: u32, d: u8) -> Self {
        debug_assert!((1..=11).contains(&d));

        let div: u32 = y * KYBER_Q;
        let mut quo: u32 = div >> d as u32;
        quo += (div >> (d as u32 - 1)) & 1;

        debug_assert!(quo < KYBER_Q);

        FieldElement(quo)
    }

    #[cfg(all(test, feature = "safe_api"))]
    pub fn random() -> Self {
        use rand::prelude::*;
        Self(rand::rng().random_range(0..KYBER_Q))
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let x: u32 = self.0 + other.0;
        Self(conditional_sub_u32(x))
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let x: u32 = self.0.overflowing_sub(other.0).0.overflowing_add(KYBER_Q).0;
        Self(conditional_sub_u32(x))
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(barrett_reduce(self.0 * other.0))
    }
}

#[cfg(test)]
mod test_field_modular_arithmetic {
    use super::*;

    #[test]
    fn test_field_ops_add() {
        for x in 0..KYBER_Q {
            for y in 0..KYBER_Q {
                let fe_add_ret = FieldElement(x) + FieldElement(y);
                let num_add_ret = (x + y) % KYBER_Q;

                assert!(fe_add_ret.0 < KYBER_Q);
                assert_eq!(fe_add_ret.0, num_add_ret);
            }
        }
    }

    #[test]
    fn test_field_ops_sub() {
        for x in 0..KYBER_Q {
            for y in 0..KYBER_Q {
                let fe_sub_ret = FieldElement(x) - FieldElement(y);
                let num_sub_ret = (x as i32 - y as i32 + KYBER_Q as i32) % KYBER_Q as i32;

                assert!(fe_sub_ret.0 < KYBER_Q);
                assert_eq!(fe_sub_ret.0, num_sub_ret as u32);
            }
        }
    }

    #[test]
    fn test_field_ops_mul() {
        for x in 0..KYBER_Q {
            for y in 0..KYBER_Q {
                let fe_mul_ret = FieldElement(x) * FieldElement(y);
                let num_mul_ret = (x * y) % KYBER_Q;

                assert_eq!(fe_mul_ret.0, num_mul_ret);
            }
        }
    }

    // Constant-time conditional subtraction
    fn conditional_sub_i16(a: i16, modulo: i16) -> i16 {
        // Calculate a - mod
        let t: i16 = a - modulo;

        // Check if a >= mod (if t is non-negative)
        // If a >= mod, mask will be 0xFFFFFFFF, otherwise 0
        let mask: i16 = t >> 15;

        // If mask is 0, return a (no subtraction), otherwise return t (a - mod)
        (t & !mask) | (a & mask)
    }

    #[test]
    fn test_conditional_sub() {
        for a in 0..KYBER_Q * 2 {
            if a >= KYBER_Q {
                assert_eq!(conditional_sub_u32(a), a - KYBER_Q);
                assert_eq!(
                    conditional_sub_i16(a as i16, KYBER_Q as i16),
                    (a - KYBER_Q) as i16
                );
            } else {
                assert_eq!(conditional_sub_u32(a), a);
                assert_eq!(conditional_sub_i16(a as i16, KYBER_Q as i16), a as i16);
            }
        }
    }

    #[test]
    fn test_field_reduced_state() {
        for a in 0..KYBER_Q.pow(2) {
            let reduced: u32 = barrett_reduce(a);
            assert!((0..KYBER_Q).contains(&reduced));
            assert_eq!(reduced, a % KYBER_Q);
        }
    }
}

#[cfg(test)]
mod test_compression {
    use super::*;
    use num_rational::*;

    // Compress/Decompress is not defined for d = 12.
    const COMPRESSION_D: [u8; 6] = [1, 4, 5, 6, 10, 11];

    // FIPS-203, p. 21, 4.7
    fn ratcompress(x: i32, d: u32) -> i32 {
        let m: i32 = 2i32.pow(d);
        let mut r = Rational32::new(x * m, KYBER_Q as i32);
        r = r.round() % m;

        r.to_integer()
    }

    // FIPS-203, p. 21, 4.8
    fn ratdecompress(y: i32, d: u32) -> i32 {
        let m: i32 = 2i32.pow(d);
        let mut r = Rational32::new(y * KYBER_Q as i32, m);
        r = r.round();

        r.to_integer()
    }

    #[test]
    fn test_compress_with_rational() {
        for d in COMPRESSION_D {
            for x in 0..KYBER_Q {
                let fe = FieldElement::new(x);
                assert_eq!(fe.compress(d) as i32, ratcompress(fe.0 as i32, d.into()));
            }
        }
    }

    #[test]
    fn test_decompress_with_rational() {
        for d in COMPRESSION_D {
            for y in 0..2u32.pow(d as u32) {
                assert_eq!(
                    FieldElement::decompress(y, d).0 as i32,
                    ratdecompress(y as i32, d.into())
                );
            }
        }
    }

    #[test]
    fn test_compress_decompress_roundtrip_d_lt_12() {
        // FIPS-203, p. 21:
        // "That is, Compress_{d}(Decompress_{d}(y)) = y for all y ∈ Z_{2^{d}} and all d < 12."
        for d in COMPRESSION_D {
            for x in 0..2u32.pow(d as u32) {
                assert_eq!(FieldElement::decompress(x, d).compress(d), x);
            }
        }
    }
}
