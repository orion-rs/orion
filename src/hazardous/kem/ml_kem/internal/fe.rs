// MIT License

// Copyright (c) 2025 The orion Developers

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
use zeroize::Zeroize;

pub(crate) const KYBER_Q: i32 = 3329;

/// Barrett reduction with correctional step.
///
/// Given value < 2q return value mod q (in [0, n]).
///
/// src: https://en.wikipedia.org/wiki/Barrett_reduction
pub fn barrett_reduce(value: i32) -> i32 {
    debug_assert!(value < KYBER_Q.pow(2));

    const MUL: i64 = 1290167; // floor((2**32)/q)
    const SHIFT: i64 = 32;

    let quo: i32 = ((i64::from(value) * MUL) >> SHIFT) as i32;
    let r = value - (quo * KYBER_Q);
    // NOTE: Guaranteed now 0 <= r < 2q. This is where we add the
    // conditional subtraction.
    debug_assert!((0..KYBER_Q * 2).contains(&r));

    let ret = conditional_sub_i32(r, KYBER_Q);
    debug_assert!((0..KYBER_Q).contains(&ret));

    ret
}

// Constant-time conditional subtraction
fn conditional_sub_i32(a: i32, modulo: i32) -> i32 {
    // Calculate a - mod
    let t: i32 = a - modulo;

    // Check if a >= mod (if t is non-negative)
    // If a >= mod, mask will be 0xFFFFFFFF, otherwise 0
    let mask: i32 = t >> 31;

    // If mask is 0, return a (no subtraction), otherwise return t (a - mod)
    (t & !mask) | (a & mask)
}

#[derive(Clone, Copy, PartialEq, Debug)]
/// Element in the field Z_q.
///
/// TODO(brycx): While for Kyber q = 3329 a field element would fit in i16, but Dilithium q = 8380417 which only fits in i32.
/// Thus, for possible future re-usability, we use 32-bit integer here. However, we could probably switch to `u32`.
pub struct FieldElement(pub(crate) i32);

impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl FieldElement {
    pub fn new(value: i32) -> Self {
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
    pub fn compress(&self, d: u8) -> i32 {
        debug_assert!((1..=11).contains(&d));

        const MUL: u64 = 1290167; // floor((2**32)/q)
        const SHIFT: u64 = 32;
        const Q: u32 = KYBER_Q as u32;

        let div: u32 = (self.0 as u32) << d;
        let mut quo: u32 = ((u64::from(div) * MUL) >> SHIFT) as u32;
        let rem: u32 = div - (quo * Q);

        quo += (Q / 2).overflowing_sub(rem).0 >> 31 & 1;
        quo += (Q + Q / 2 - rem) >> 31 & 1;

        let mask: u32 = (1 << d as u32) - 1;

        ((quo & mask) as u16) as i32
    }

    /// FIPS-203, def. 4.8.
    /// Mapping of Z_{2^{d}} => Z_q.
    ///
    /// This is a Rust port of:
    /// https://github.com/FiloSottile/mlkem768
    pub fn decompress(y: i32, d: u8) -> Self {
        debug_assert!((1..=11).contains(&d));

        const Q: u32 = KYBER_Q as u32;

        let div: u32 = (y as u32) * Q;
        let mut quo: u32 = div >> d as u32;
        quo += div >> (d as u32 - 1) & 1;

        debug_assert!(quo <= Q);

        FieldElement(quo as i32)
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
        let x: i32 = self.0 + other.0;
        Self(conditional_sub_i32(x, KYBER_Q))
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let x: i32 = self.0 - other.0 + KYBER_Q;
        Self(conditional_sub_i32(x, KYBER_Q))
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

                assert!(0 <= fe_add_ret.0 && fe_add_ret.0 < KYBER_Q);
                assert_eq!(fe_add_ret.0, num_add_ret);
            }
        }
    }

    #[test]
    fn test_field_ops_sub() {
        for x in 0..KYBER_Q {
            for y in 0..KYBER_Q {
                let fe_sub_ret = FieldElement(x) - FieldElement(y);
                let num_sub_ret = (x - y + KYBER_Q) % KYBER_Q;

                assert!(0 <= fe_sub_ret.0 && fe_sub_ret.0 < KYBER_Q);
                assert_eq!(fe_sub_ret.0, num_sub_ret);
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
                assert_eq!(conditional_sub_i32(a, KYBER_Q), (a - KYBER_Q));
                assert_eq!(
                    conditional_sub_i16(a as i16, KYBER_Q as i16),
                    (a - KYBER_Q) as i16
                );
            } else {
                assert_eq!(conditional_sub_i32(a, KYBER_Q), a);
                assert_eq!(conditional_sub_i16(a as i16, KYBER_Q as i16), a as i16);
            }
        }
    }

    #[test]
    fn test_field_reduced_state() {
        for a in 0..(KYBER_Q.pow(2)) {
            let reduced: i32 = barrett_reduce(a);
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
        let mut r = Rational32::new(x * m, KYBER_Q);
        r = r.round() % m;

        r.to_integer()
    }

    // FIPS-203, p. 21, 4.8
    fn ratdecompress(y: i32, d: u32) -> i32 {
        let m: i32 = 2i32.pow(d);
        let mut r = Rational32::new(y * KYBER_Q, m);
        r = r.round();

        r.to_integer()
    }

    #[test]
    fn test_compress_with_rational() {
        for d in COMPRESSION_D {
            for x in 0..KYBER_Q {
                let fe = FieldElement::new(x);
                assert_eq!(fe.compress(d), ratcompress(fe.0, d as u32));
            }
        }
    }

    #[test]
    fn test_decompress_with_rational() {
        for d in COMPRESSION_D {
            for y in 0..2i32.pow(d as u32) {
                assert_eq!(FieldElement::decompress(y, d).0, ratdecompress(y, d as u32));
            }
        }
    }

    #[test]
    fn test_compress_decompress_roundtrip_d_lt_12() {
        // FIPS-203, p. 21:
        // "That is, Compress_{d}(Decompress_{d}(y)) = y for all y ∈ Z_{2^{d}} and all d < 12."
        for d in COMPRESSION_D {
            for x in 0..2i32.pow(d as u32) {
                assert_eq!(FieldElement::decompress(x, d).compress(d), x);
            }
        }
    }
}
