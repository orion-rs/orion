// MIT License

// Copyright (c) 2026 The orion Developers

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

use core::fmt::Debug;

use crate::hazardous::dsa::ml_dsa::internal::fe::{FieldElement, RingElement, conditional_sub_u32};

mod fe;
mod sampling;

pub(crate) const fn bitlen(a: u32) -> u32 {
    u32::BITS - a.leading_zeros()
}

#[test]
fn test_bitlen() {
    assert_eq!(bitlen(32), 6);
    assert_eq!(bitlen(31), 5);

    assert_eq!(MlDsa44::GAMMA_1_BITLEN, 17);
    assert_eq!(MlDsa65::GAMMA_1_BITLEN, 19);
    assert_eq!(MlDsa87::GAMMA_1_BITLEN, 19);
}

pub trait MlDsaParameters: Debug {
    const Q: u32 = 8380417;
    const N: usize = 256;

    /// "# of ±1’s in polynomial c"
    const TAU: usize;
    /// "collision strength of c ̃"
    const LAMBDA: usize;
    /// "private key range"
    const ETA: usize;
    /// "dimensions of A"
    const DIM_K: usize;
    const DIM_L: usize;
    /// "coefficient range of y"
    const GAMMA_1: u32;
    /// "low-order rounding range"
    const GAMMA_2: u32;
    /// `bitlen (γ1 − 1)`
    const GAMMA_1_BITLEN: u32 = bitlen(Self::GAMMA_1 - 1);
    /// "# of dropped bits from t"
    const D: u32 = 13;

    const PRIVATE_KEY_SIZE: usize;
    const PUBLIC_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;

    /// FIPS-204, Algorithm 19.
    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement);

    /// FIPS-204, Algorithm 22.
    fn pk_encode<const PK_ENCODED_SIZE: usize>(
        rho: &[u8],
        t1: &[RingElement],
    ) -> [u8; PK_ENCODED_SIZE] {
        debug_assert_eq!(rho.len(), 32);
        debug_assert_eq!(PK_ENCODED_SIZE, Self::PUBLIC_KEY_SIZE);

        let mut pk = [0u8; PK_ENCODED_SIZE];
        pk[..32].copy_from_slice(rho);

        for (idx, encpoly) in (0..Self::DIM_K).zip(pk[32..].chunks_exact_mut(320)) {
            for i in 0..256 / 4 {
                let c = |k: usize| t1[idx].coefficients[4 * i + k].0;
                encpoly[5 * i] = c(0) as u8;
                encpoly[5 * i + 1] = ((c(0) >> 8) | (c(1) << 2)) as u8;
                encpoly[5 * i + 2] = ((c(1) >> 6) | (c(2) << 4)) as u8;
                encpoly[5 * i + 3] = ((c(2) >> 4) | (c(3) << 6)) as u8;
                encpoly[5 * i + 4] = (c(3) >> 2) as u8;
            }
        }

        pk
    }

    /// FIPS-204, Algorithm 23.
    fn pk_decode<const K: usize>(pk: &[u8]) -> ([u8; 32], [RingElement; K]) {
        debug_assert_eq!(pk.len(), Self::PUBLIC_KEY_SIZE);

        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[..32]);

        let mut t1 = [RingElement::zero(); K];

        for (idx, encpoly) in (0..Self::DIM_K).zip(pk[32..].chunks_exact(320)) {
            for (fe, blk) in t1[idx]
                .coefficients
                .chunks_exact_mut(4)
                .zip(encpoly.chunks_exact(5))
            {
                let c = |k: usize| blk[k] as u32;
                fe[0].0 = (c(0) | (c(1) << 8)) & 0x3FF;
                fe[1].0 = ((c(1) >> 2) | (c(2) << 6)) & 0x3FF;
                fe[2].0 = ((c(2) >> 4) | (c(3) << 4)) & 0x3FF;
                fe[3].0 = ((c(3) >> 6) | (c(4) << 2)) & 0x3FF;
            }
        }

        (rho, t1)
    }

    /// FIPS-204, Algorithm 24.
    fn sk_encode<const SK_ENCODED_SIZE: usize, const K: usize, const L: usize>(
        rho: &[u8],
        k: &[u8],
        tr: &[u8],
        s1: &[RingElement],
        s2: &[RingElement],
        t0: &[RingElement],
    ) -> [u8; SK_ENCODED_SIZE] {
        debug_assert_eq!(rho.len(), 32);
        debug_assert_eq!(k.len(), 32);
        debug_assert_eq!(tr.len(), 64);
        debug_assert_eq!(s1.len(), Self::DIM_L);
        debug_assert_eq!(s2.len(), Self::DIM_K);
        debug_assert_eq!(t0.len(), Self::DIM_K);
        debug_assert_eq!(SK_ENCODED_SIZE, Self::PRIVATE_KEY_SIZE);

        let mut sk = [0u8; SK_ENCODED_SIZE];

        sk
    }

    /// FIPS-204, Algorithm 25.
    fn sk_decode<const K: usize>(pk: &[u8]) -> ([u8; 32], [RingElement; K]) {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq, Clone)]
/// ML-DSA-44.
pub struct MlDsa44;

impl MlDsaParameters for MlDsa44 {
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const ETA: usize = 2;
    const DIM_K: usize = 4;
    const DIM_L: usize = 4;
    const GAMMA_1: u32 = 1 << 17;
    const GAMMA_2: u32 = (Self::Q - 1) / 88;

    const PRIVATE_KEY_SIZE: usize = 2560;
    const PUBLIC_KEY_SIZE: usize = 1312;
    const SIGNATURE_SIZE: usize = 2420;

    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(v.len(), 576);
        let fe_gamma1: FieldElement = FieldElement::new(Self::GAMMA_1);

        for (a, blk) in w.coefficients.chunks_exact_mut(4).zip(v.chunks_exact(9)) {
            let b = |k: usize| blk[k] as u32;
            let t = [
                b(0) | (b(1) << 8) | (b(2) << 16),
                (b(2) >> 2) | (b(3) << 6) | (b(4) << 14),
                (b(4) >> 4) | (b(5) << 4) | (b(6) << 12),
                (b(6) >> 6) | (b(7) << 2) | (b(8) << 10),
            ];
            for (dst, &tj) in a.iter_mut().zip(t.iter()) {
                *dst = fe_gamma1 - FieldElement::new(tj & 0x3FFFF);
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
/// ML-DSA-65.
pub struct MlDsa65;

impl MlDsaParameters for MlDsa65 {
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const ETA: usize = 4;
    const DIM_K: usize = 6;
    const DIM_L: usize = 5;
    const GAMMA_1: u32 = 1 << 19;
    const GAMMA_2: u32 = (Self::Q - 1) / 32;

    const PRIVATE_KEY_SIZE: usize = 4032;
    const PUBLIC_KEY_SIZE: usize = 1952;
    const SIGNATURE_SIZE: usize = 3309;

    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(v.len(), 640);
        let fe_gamma1: FieldElement = FieldElement::new(Self::GAMMA_1);

        for (a, blk) in w.coefficients.chunks_exact_mut(2).zip(v.chunks_exact(5)) {
            let b = |k: usize| blk[k] as u32;
            let t0 = b(0) | (b(1) << 8) | (b(2) << 16);
            let t1 = (b(2) >> 4) | (b(3) << 4) | (b(4) << 12);
            a[0] = fe_gamma1 - FieldElement::new(t0 & 0xFFFFF);
            a[1] = fe_gamma1 - FieldElement::new(t1 & 0xFFFFF);
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
/// ML-DSA-87.
pub struct MlDsa87;

impl MlDsaParameters for MlDsa87 {
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const ETA: usize = 2;
    const DIM_K: usize = 8;
    const DIM_L: usize = 7;
    const GAMMA_1: u32 = 1 << 19;
    const GAMMA_2: u32 = (Self::Q - 1) / 32;

    const PRIVATE_KEY_SIZE: usize = 4896;
    const PUBLIC_KEY_SIZE: usize = 2592;
    const SIGNATURE_SIZE: usize = 4627;

    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement) {
        MlDsa65::bitunpack_ring_element_gamma(v, w);
    }
}
