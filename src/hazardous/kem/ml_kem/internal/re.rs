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

use super::fe::FieldElement;
use core::ops::{Add, AddAssign, Mul, Sub};
use core::ops::{Index, IndexMut};
use zeroize::Zeroize;

fn sub_poly(p1: &[FieldElement; 256], p2: &[FieldElement; 256], ret: &mut [FieldElement; 256]) {
    for idx in 0..256 {
        ret[idx] = p1[idx] - p2[idx];
    }
}

fn add_poly(p1: &[FieldElement; 256], p2: &[FieldElement; 256], ret: &mut [FieldElement; 256]) {
    for idx in 0..256 {
        ret[idx] = p1[idx] + p2[idx];
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
/// Element in R_q.
///
/// Ring elements are the same as polynomials, which are the same as vectors
/// of coefficients.
///
/// Adding and subtracting polynomials works the same way in NTT and NTT^{-1},
/// it is however illegal to operate on two polynomials from different domains
/// at the same time.
pub struct RingElement {
    pub coefficients: [FieldElement; 256],
}

impl Zeroize for RingElement {
    fn zeroize(&mut self) {
        self.coefficients.iter_mut().zeroize();
    }
}

impl RingElement {
    pub fn zero() -> Self {
        Self {
            coefficients: [FieldElement::zero(); 256],
        }
    }

    /// NOTE: This should not be accessible by a user.
    pub(crate) fn copy_from_ntt(ntt: &RingElementNTT) -> Self {
        Self {
            coefficients: ntt.coefficients,
        }
    }

    #[cfg(all(test, feature = "safe_api"))]
    pub(crate) fn random_element() -> Self {
        use crate::hazardous::kem::ml_kem::internal::fe::KYBER_Q;
        use rand::{prelude::*, rng};

        let mut rng = rng();
        let mut coefficients = [FieldElement::zero(); 256];

        for rand_coeff in coefficients.iter_mut() {
            let new = rng.random_range(0..KYBER_Q);
            *rand_coeff = FieldElement::new(new);
        }

        Self { coefficients }
    }
}

impl Index<usize> for RingElement {
    type Output = FieldElement;

    fn index(&self, index: usize) -> &Self::Output {
        debug_assert!(index <= 255);

        &self.coefficients[index]
    }
}

impl IndexMut<usize> for RingElement {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        debug_assert!(index <= 255);
        &mut self.coefficients[index]
    }
}

impl Add for RingElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut ret_add = Self::zero();
        add_poly(
            &self.coefficients,
            &other.coefficients,
            &mut ret_add.coefficients,
        );
        ret_add
    }
}

impl Sub for RingElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut ret_sub = Self::zero();
        sub_poly(
            &self.coefficients,
            &other.coefficients,
            &mut ret_sub.coefficients,
        );
        ret_sub
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
/// Element in T_q.
pub struct RingElementNTT {
    pub coefficients: [FieldElement; 256],
}

impl Zeroize for RingElementNTT {
    fn zeroize(&mut self) {
        self.coefficients.iter_mut().zeroize();
    }
}

impl RingElementNTT {
    pub fn zero() -> Self {
        Self {
            coefficients: [FieldElement::zero(); 256],
        }
    }

    /// NOTE: This should not be accessible by a user.
    pub(crate) fn copy_from_non_ntt(not_ntt: &RingElement) -> Self {
        Self {
            coefficients: not_ntt.coefficients,
        }
    }

    /// FIPS-203, Algorithm 12.
    pub fn base_case_multiply(
        a0: FieldElement,
        a1: FieldElement,
        b0: FieldElement,
        b1: FieldElement,
        gamma: FieldElement,
    ) -> (FieldElement, FieldElement) {
        let c0: FieldElement = a0 * b0 + a1 * b1 * gamma;
        let c1: FieldElement = a0 * b1 + a1 * b0;

        (c0, c1)
    }
}

impl Index<usize> for RingElementNTT {
    type Output = FieldElement;

    fn index(&self, index: usize) -> &Self::Output {
        debug_assert!(index <= 255);
        &self.coefficients[index]
    }
}

impl IndexMut<usize> for RingElementNTT {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        debug_assert!(index <= 255);
        &mut self.coefficients[index]
    }
}

impl AddAssign for RingElementNTT {
    fn add_assign(&mut self, other: Self) {
        add_poly(
            &self.coefficients.clone(),
            &other.coefficients,
            &mut self.coefficients,
        );
    }
}

impl Mul for RingElementNTT {
    type Output = Self;

    /// FIPS-203, Algorithm 11.
    ///
    /// self  = f_hat
    /// other = g_hat
    fn mul(self, other: Self) -> Self {
        let mut h_hat = Self::zero();

        for i in 0..128 {
            let a0 = self.coefficients[2 * i];
            let a1 = self.coefficients[2 * i + 1];
            let b0 = other.coefficients[2 * i];
            let b1 = other.coefficients[2 * i + 1];
            let (c0, c1) = Self::base_case_multiply(a0, a1, b0, b1, FieldElement(GAMMA_ALL[i]));

            h_hat[2 * i] = c0;
            h_hat[2 * i + 1] = c1;
        }

        h_hat
    }
}

#[allow(dead_code)]
pub const ZETA_ROOT_OF_UNIT: u16 = 17;

pub const ZETA_ALL: [u32; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// ζ2BitRev7(i)+1
pub const GAMMA_ALL: [u32; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409,
    1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626,
    1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390,
    2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298,
    1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319,
    3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
    403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117,
    1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

// FIPS-203, Algorithm 9.
pub fn to_ntt(f: &RingElement) -> RingElementNTT {
    let mut i = 1;
    let mut len = 128;
    let mut f_hat = RingElementNTT::copy_from_non_ntt(f);

    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = FieldElement::new(ZETA_ALL[i]);
            i += 1;

            for j in start..(start + len) {
                let t: FieldElement = zeta * f_hat[j + len];
                f_hat[j + len] = f_hat[j] - t;
                f_hat[j] = f_hat[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1; // Same as division by 2
    }

    f_hat
}

// FIPS-203, Algorithm 10.
pub fn inverse_ntt(f_hat: &RingElementNTT) -> RingElement {
    let mut f = RingElement::copy_from_ntt(f_hat);

    let mut len = 2;
    let mut i = 127;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = FieldElement::new(ZETA_ALL[i]);
            i -= 1;

            for j in start..(start + len) {
                let t: FieldElement = f[j];
                f[j] = t + f[j + len];
                f[j + len] = zeta * (f[j + len] - t);
            }

            start += 2 * len;
        }
        len *= 2;
    }

    for fe in f.coefficients.iter_mut() {
        *fe = *fe * FieldElement(3303);
    }

    f
}

#[cfg(all(test, feature = "safe_api"))]
mod test_ntt_transform {
    use super::*;

    #[test]
    fn test_to_from_ntt_roundtrips() {
        for _ in 0..100 {
            let f: RingElement = RingElement::random_element();
            let f_hat: RingElementNTT = to_ntt(&RingElement::random_element());

            assert_eq!(f, inverse_ntt(&to_ntt(&f)),);
            assert_eq!(f_hat, to_ntt(&inverse_ntt(&f_hat)),);
        }
    }
}
