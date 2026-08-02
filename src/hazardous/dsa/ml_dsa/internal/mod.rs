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

use core::{fmt::Debug, marker::PhantomData};

use subtle::Choice;

use crate::{
    errors::UnknownCryptoError,
    hazardous::{
        dsa::ml_dsa::internal::{
            fe::{
                FieldElement, RingElement, RingElementNTT, conditional_sub_u32, inverse_ntt, to_ntt,
            },
            sampling::{MatrixNTT, expand_s},
        },
        hash::sha3::shake256::Shake256,
    },
};

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
    /// bytes used to bitpack a FieldElement for this ETA
    const ETA_BITPACK_SIZE: usize;
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
    /// bytes used to bitpack a FieldElement for this d
    const D_BITPACK_SIZE: usize = 416;

    const PRIVATE_KEY_SIZE: usize;
    const PUBLIC_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;

    /// FIPS-204, Algorithm 17.
    fn bitpack_ring_element_eta(w: &RingElement, out: &mut [u8]);

    /// FIPS-204, Algorithm 19.
    fn bitunpack_ring_element_eta(v: &[u8], w: &mut RingElement);

    /// FIPS-204, Algorithm 19.
    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement);

    /// FIPS-204, Algorithm 17.
    fn bitpack_ring_element_d(w: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(MlDsa44::D, MlDsa65::D);
        debug_assert_eq!(MlDsa65::D, MlDsa87::D);
        debug_assert_eq!(out.len(), Self::D_BITPACK_SIZE);

        let fe_2power12 = FieldElement::new(1 << 12);
        for i in 0..256 / 8 {
            let mut t = [0u32; 8];
            for (j, slot) in t.iter_mut().enumerate() {
                *slot = (fe_2power12 - w.coefficients[8 * i + j]).0;
            }
            out[13 * i] = t[0] as u8;
            out[13 * i + 1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
            out[13 * i + 2] = (t[1] >> 3) as u8;
            out[13 * i + 3] = ((t[1] >> 11) | (t[2] << 2)) as u8;
            out[13 * i + 4] = ((t[2] >> 6) | (t[3] << 7)) as u8;
            out[13 * i + 5] = (t[3] >> 1) as u8;
            out[13 * i + 6] = ((t[3] >> 9) | (t[4] << 4)) as u8;
            out[13 * i + 7] = (t[4] >> 4) as u8;
            out[13 * i + 8] = ((t[4] >> 12) | (t[5] << 1)) as u8;
            out[13 * i + 9] = ((t[5] >> 7) | (t[6] << 6)) as u8;
            out[13 * i + 10] = (t[6] >> 2) as u8;
            out[13 * i + 11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
            out[13 * i + 12] = (t[7] >> 5) as u8;
        }
    }

    /// FIPS-204, Algorithm 19.
    fn bitunpack_ring_element_d(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(MlDsa44::D, MlDsa65::D);
        debug_assert_eq!(MlDsa65::D, MlDsa87::D);
        debug_assert_eq!(v.len(), Self::D_BITPACK_SIZE);

        let fe_2power12 = FieldElement::new(1 << 12);
        for (fe, blk) in w.coefficients.chunks_exact_mut(8).zip(v.chunks_exact(13)) {
            let b = |k: usize| blk[k] as u32;
            let t = [
                b(0) | (b(1) << 8),
                (b(1) >> 5) | (b(2) << 3) | (b(3) << 11),
                (b(3) >> 2) | (b(4) << 6),
                (b(4) >> 7) | (b(5) << 1) | (b(6) << 9),
                (b(6) >> 4) | (b(7) << 4) | (b(8) << 12),
                (b(8) >> 1) | (b(9) << 7),
                (b(9) >> 6) | (b(10) << 2) | (b(11) << 10),
                (b(11) >> 3) | (b(12) << 5),
            ];
            for (dst, &tj) in fe.iter_mut().zip(t.iter()) {
                *dst = fe_2power12 - FieldElement::new(tj & 0x1FFF);
            }
        }
    }

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

        let mut read: usize = 0;
        let mut sk = [0u8; SK_ENCODED_SIZE];

        sk[read..32].copy_from_slice(rho);
        read += 32;
        sk[read..read + 32].copy_from_slice(k);
        read += 32;
        sk[read..read + 64].copy_from_slice(tr);
        read += 64;

        for i in 0..Self::DIM_L {
            Self::bitpack_ring_element_eta(&s1[i], &mut sk[read..read + Self::ETA_BITPACK_SIZE]);
            read += Self::ETA_BITPACK_SIZE;
        }
        for i in 0..Self::DIM_K {
            Self::bitpack_ring_element_eta(&s2[i], &mut sk[read..read + Self::ETA_BITPACK_SIZE]);
            read += Self::ETA_BITPACK_SIZE;
        }
        for i in 0..Self::DIM_K {
            Self::bitpack_ring_element_d(&t0[i], &mut sk[read..read + Self::D_BITPACK_SIZE]);
            read += Self::ETA_BITPACK_SIZE;
        }

        debug_assert_eq!(read, SK_ENCODED_SIZE);

        sk
    }

    /// FIPS-204, Algorithm 25.
    fn sk_decode<const K: usize, const L: usize>(
        sk: &[u8],
    ) -> Result<
        (
            [u8; 32],
            [u8; 32],
            [u8; 64],
            [RingElement; L],
            [RingElement; K],
            [RingElement; K],
        ),
        UnknownCryptoError,
    > {
        let mut rho = [0u8; 32];
        let mut k = [0u8; 32];
        let mut tr = [0u8; 64];
        let mut s1 = [RingElement::zero(); L];
        let mut s2 = [RingElement::zero(); K];
        let mut t0 = [RingElement::zero(); K];

        let mut read: usize = 0;
        rho.copy_from_slice(&sk[read..read + 32]);
        read += 32;
        k.copy_from_slice(&sk[read..read + 32]);
        read += 32;
        tr.copy_from_slice(&sk[read..read + 64]);
        read += 64;

        let mut reject_outside_bound = Choice::from(0u8);

        for s1i in s1.iter_mut() {
            Self::bitunpack_ring_element_eta(&sk[read..read + Self::ETA_BITPACK_SIZE], s1i);
            reject_outside_bound |= s1i.is_outside_bound(Self::ETA as u32);
            read += Self::ETA_BITPACK_SIZE;
        }
        for s2i in s2.iter_mut() {
            Self::bitunpack_ring_element_eta(&sk[read..read + Self::ETA_BITPACK_SIZE], s2i);
            reject_outside_bound |= s2i.is_outside_bound(Self::ETA as u32);
            read += Self::ETA_BITPACK_SIZE;
        }
        for t0i in t0.iter_mut() {
            Self::bitunpack_ring_element_eta(&sk[read..read + Self::D_BITPACK_SIZE], t0i);
            read += Self::D_BITPACK_SIZE;
        }

        if reject_outside_bound.into() {
            return Err(UnknownCryptoError);
        }

        Ok((rho, k, tr, s1, s2, t0))
    }
}

#[derive(Debug, PartialEq, Clone)]
/// ML-DSA-44.
pub struct MlDsa44;

impl MlDsaParameters for MlDsa44 {
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const ETA: usize = 2;
    const ETA_BITPACK_SIZE: usize = 96;
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

    fn bitpack_ring_element_eta(w: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ETA_BITPACK_SIZE);
        let fe_eta = FieldElement::new(Self::ETA as u32);
        for i in 0..256 / 8 {
            let subat = |k: usize| fe_eta - w.coefficients[8 * i + k];
            out[3 * i] = (subat(0).0 | (subat(1).0 << 3) | (subat(2).0 << 6)) as u8;
            out[3 * i + 1] =
                ((subat(2).0 >> 2) | (subat(3).0 << 1) | (subat(4).0 << 4) | (subat(5).0 << 7))
                    as u8;
            out[3 * i + 2] = ((subat(5).0 >> 1) | (subat(6).0 << 2) | (subat(7).0 << 5)) as u8;
        }
    }

    fn bitunpack_ring_element_eta(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(v.len(), Self::ETA_BITPACK_SIZE);
        let fe_eta = FieldElement::new(Self::ETA as u32);
        for (fe, blk) in w.coefficients.chunks_exact_mut(8).zip(v.chunks_exact(3)) {
            let b = |k: usize| blk[k] as u32;
            fe[0] = fe_eta - FieldElement::new(b(0) & 7);
            fe[1] = fe_eta - FieldElement::new((b(0) >> 3) & 7);
            fe[2] = fe_eta - FieldElement::new((b(0) >> 6) | ((b(1) << 2) & 4));
            fe[3] = fe_eta - FieldElement::new((b(1) >> 1) & 7);
            fe[4] = fe_eta - FieldElement::new((b(1) >> 4) & 7);
            fe[5] = fe_eta - FieldElement::new((b(1) >> 7) | ((b(2) << 1) & 6));
            fe[6] = fe_eta - FieldElement::new((b(2) >> 2) & 7);
            fe[7] = fe_eta - FieldElement::new((b(2) >> 5) & 7);
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
    const ETA_BITPACK_SIZE: usize = 128;
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

    fn bitpack_ring_element_eta(w: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ETA_BITPACK_SIZE);
        let fe_eta = FieldElement::new(Self::ETA as u32);

        for i in 0..256 / 2 {
            let t0 = fe_eta - w.coefficients[2 * i];
            let t1 = fe_eta - w.coefficients[2 * i + 1];
            out[i] = (t0.0 | (t1.0 << 4)) as u8;
        }
    }

    fn bitunpack_ring_element_eta(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(v.len(), Self::ETA_BITPACK_SIZE);
        let fe_eta = FieldElement::new(Self::ETA as u32);

        for (fe, &byte) in w.coefficients.chunks_exact_mut(2).zip(v.iter()) {
            fe[0] = fe_eta - FieldElement::new((byte & 0x0F) as u32);
            fe[1] = fe_eta - FieldElement::new((byte >> 4) as u32);
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
    const ETA_BITPACK_SIZE: usize = 96;
    const DIM_K: usize = 8;
    const DIM_L: usize = 7;
    const GAMMA_1: u32 = 1 << 19;
    const GAMMA_2: u32 = (Self::Q - 1) / 32;

    const PRIVATE_KEY_SIZE: usize = 4896;
    const PUBLIC_KEY_SIZE: usize = 2592;
    const SIGNATURE_SIZE: usize = 4627;

    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(Self::GAMMA_1, MlDsa65::GAMMA_1);
        debug_assert_eq!(Self::GAMMA_2, MlDsa65::GAMMA_2);
        MlDsa65::bitunpack_ring_element_gamma(v, w);
    }

    fn bitpack_ring_element_eta(w: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(Self::ETA, MlDsa44::ETA);
        MlDsa44::bitpack_ring_element_eta(w, out);
    }

    fn bitunpack_ring_element_eta(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(Self::ETA, MlDsa44::ETA);
        MlDsa44::bitunpack_ring_element_eta(v, w);
    }
}

pub(crate) struct KeyPair<const K: usize, const L: usize, P: MlDsaParameters> {
    _phantom: PhantomData<P>,
}

impl<const K: usize, const L: usize, P: MlDsaParameters> KeyPair<K, L, P> {
    /// FIPS-204, Algorithm 6.
    pub(crate) fn keygen_internal(seed: &[u8]) -> Result<Self, UnknownCryptoError> {
        debug_assert_eq!(K, P::DIM_K);
        debug_assert_eq!(L, P::DIM_L);
        debug_assert_eq!(seed.len(), 32);

        let mut h = Shake256::new();
        h.absorb(seed)?;
        h.absorb(&[K as u8, L as u8])?;

        let mut expanded_seed = zeroize_wrap!([0u8; 128]);
        h.squeeze(expanded_seed.as_mut())?;

        let mat_a_hat = MatrixNTT::<K, L>::expand_a::<P>(&expanded_seed[..32])?;
        let (s1, s2) = expand_s::<K, L, P>(&expanded_seed[32..32 + 64])?;

        let t = (mat_a_hat * s1.ntt()).inverse_ntt() + s2;
        // Missing component-wise Power2Round

        Ok(Self {
            _phantom: PhantomData,
        })
    }
}
