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

use crate::{
    errors::UnknownCryptoError,
    generics::sealed::{Data, Sealed, TryFromBytes},
    hazardous::{
        dsa::ml_dsa::internal::{
            fe::{FieldElement, Hint, RingElement, Standard, Vector, VectorNTT},
            sampling::{MatrixNTT, expand_mask, expand_s, sample_in_ball},
        },
        hash::sha3::shake256::Shake256,
    },
};
use core::{fmt::Debug, marker::PhantomData};
use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

mod fe;
pub(crate) mod sampling;

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

/// Internal parameters for the three parameter-sets that ML-DSA supports.
pub trait MlDsaParameters: Debug + Sized {
    /// Dilithium constant Q.
    const Q: u32 = 8380417;
    /// Polynomial sizes in T_q/R_q.
    const N: usize = 256;

    /// "# of ±1’s in polynomial c"
    const TAU: usize;
    /// "collision strength of c ̃"
    const LAMBDA: usize;
    /// "private key range"
    const ETA: usize;
    /// bytes used to bitpack a FieldElement for this ETA
    const ETA_BITPACK_SIZE: usize;
    /// "dimensions of A", K
    const DIM_K: usize;
    /// "dimensions of A", L
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
    /// byte used to bitpack w1 during signing
    const W1_BITPACK_SIZE: usize;
    /// maximum w1 value and thus bits needed to repr
    const W1_MAX_VALUE: u32;
    /// "β = τ ⋅ η"
    const BETA: u32;
    /// "max # of 1’s in the hint h"
    const OMEGA: u32;
    /// bytes used to represent the commitment hash during signing.
    const COMMITMENT_HASH_LEN: usize = Self::LAMBDA / 4;
    /// 32 * c, where c = 1 + bitlen (γ1 − 1)
    const CLEN: usize;

    /// Barret M for constant-time Decompose().
    const DECOMPOSE_BARRETT_M: u32;
    /// Barret shift for constant-time Decompose().
    const DECOMPOSE_BARRETT_SHIFT: u32 = 24; // fits all three paramsets
    /// Constant-time Decompose().
    const DECOMPOSE_W1_MAX: u32;

    /// bytes used to encode polynomial as byte signature
    const Z_BITPACK_SIZE: usize;

    /// Size of private signing key in bytes.
    const PRIVATE_KEY_SIZE: usize;
    /// Size of public verification key in bytes.
    const PUBLIC_KEY_SIZE: usize;
    /// Size of public signature in bytes.
    const SIGNATURE_SIZE: usize;

    /// FIPS-204, Algorithm 17.
    fn bitpack_ring_element_eta(w: &RingElement, out: &mut [u8]);

    /// FIPS-204, Algorithm 19.
    fn bitunpack_ring_element_eta(v: &[u8], w: &mut RingElement);

    /// FIPS-204, Algorithm 19.
    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement);

    /// FIPS-204, Algorithm 28.
    fn bitpack_polynomial_vector_w1(w1: &RingElement, out: &mut [u8]);

    /// FIPS-204, Algorithm 28.
    fn bitpack_polynomial_z(z: &RingElement, out: &mut [u8]);

    /// FIPS-204, Algorithm 28.
    fn w1_encode<const K: usize>(w1: &Vector<K>, out: &mut [u8]) {
        debug_assert_eq!(K, Self::DIM_K);
        debug_assert_eq!(out.len(), K * Self::W1_BITPACK_SIZE);

        for (poly, chunk) in w1
            .elems
            .iter()
            .zip(out.chunks_exact_mut(Self::W1_BITPACK_SIZE))
        {
            Self::bitpack_polynomial_vector_w1(poly, chunk);
        }
    }

    /// FIPS-204, Algorithm 17.
    fn bitpack_ring_element_d(w: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(MlDsa44::D, MlDsa65::D);
        debug_assert_eq!(MlDsa65::D, MlDsa87::D);
        debug_assert_eq!(out.len(), Self::D_BITPACK_SIZE);

        let fe_2power12 = FieldElement::new(1 << 12);
        for i in 0..256 / 8 {
            let mut t = [0u32; 8];
            for (j, slot) in t.iter_mut().enumerate() {
                *slot = (fe_2power12 - &w.coefficients[8 * i + j]).0;
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
                *dst = fe_2power12 - &FieldElement::new(tj & 0x1FFF);
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
    fn pk_decode<const K: usize>(pk: &[u8]) -> Result<([u8; 32], Vector<K>), UnknownCryptoError> {
        if pk.len() != Self::PUBLIC_KEY_SIZE {
            return Err(UnknownCryptoError);
        }

        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[..32]);

        let mut t1 = Vector::<K>::zero();

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

        Ok((rho, t1))
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

        for w in s1.iter().take(Self::DIM_L) {
            Self::bitpack_ring_element_eta(w, &mut sk[read..read + Self::ETA_BITPACK_SIZE]);
            read += Self::ETA_BITPACK_SIZE;
        }
        for w in s2.iter().take(Self::DIM_K) {
            Self::bitpack_ring_element_eta(w, &mut sk[read..read + Self::ETA_BITPACK_SIZE]);
            read += Self::ETA_BITPACK_SIZE;
        }
        for w in t0.iter().take(Self::DIM_K) {
            Self::bitpack_ring_element_d(w, &mut sk[read..read + Self::D_BITPACK_SIZE]);
            read += Self::D_BITPACK_SIZE;
        }

        debug_assert_eq!(read, SK_ENCODED_SIZE);

        sk
    }

    #[allow(clippy::type_complexity)]
    /// FIPS-204, Algorithm 25.
    fn sk_decode<const K: usize, const L: usize>(
        sk: &[u8],
    ) -> Result<
        (
            [u8; 32],
            [u8; 32],
            [u8; 64],
            Vector<L>,
            Vector<K>,
            Vector<K>,
        ),
        UnknownCryptoError,
    > {
        if sk.len() != Self::PRIVATE_KEY_SIZE {
            return Err(UnknownCryptoError);
        }

        let mut rho = [0u8; 32];
        let mut k = [0u8; 32];
        let mut tr = [0u8; 64];
        let mut s1 = Vector::<L>::zero();
        let mut s2 = Vector::<K>::zero();
        let mut t0 = Vector::<K>::zero();

        let mut read: usize = 0;
        rho.copy_from_slice(&sk[read..read + 32]);
        read += 32;
        k.copy_from_slice(&sk[read..read + 32]);
        read += 32;
        tr.copy_from_slice(&sk[read..read + 64]);
        read += 64;

        let mut reject_outside_bound = Choice::from(0u8);

        for s1i in s1.elems.iter_mut() {
            Self::bitunpack_ring_element_eta(&sk[read..read + Self::ETA_BITPACK_SIZE], s1i);
            reject_outside_bound |= s1i.is_outside_bound(Self::ETA as u32 + 1);
            read += Self::ETA_BITPACK_SIZE;
        }
        for s2i in s2.elems.iter_mut() {
            Self::bitunpack_ring_element_eta(&sk[read..read + Self::ETA_BITPACK_SIZE], s2i);
            reject_outside_bound |= s2i.is_outside_bound(Self::ETA as u32 + 1);
            read += Self::ETA_BITPACK_SIZE;
        }
        for t0i in t0.elems.iter_mut() {
            Self::bitunpack_ring_element_d(&sk[read..read + Self::D_BITPACK_SIZE], t0i);
            read += Self::D_BITPACK_SIZE;
        }

        if reject_outside_bound.into() {
            return Err(UnknownCryptoError);
        }

        Ok((rho, k, tr, s1, s2, t0))
    }

    /// FIPS-204, Algorithm 26.
    fn sig_encode<const K: usize, const L: usize, const COMMITHASH_LEN: usize>(
        c_tilde: &[u8],
        z: &Vector<L>,
        h: &Hint<K>,
        out: &mut [u8],
    ) {
        debug_assert_eq!(
            Self::SIGNATURE_SIZE,
            (Self::Z_BITPACK_SIZE * L) + COMMITHASH_LEN + Self::OMEGA as usize + K
        );
        debug_assert_eq!(c_tilde.len(), COMMITHASH_LEN);
        debug_assert_eq!(
            out.len(),
            (Self::Z_BITPACK_SIZE * L) + COMMITHASH_LEN + Self::OMEGA as usize + K
        );

        let (cpart, rem) = out.split_at_mut(COMMITHASH_LEN);
        cpart.copy_from_slice(c_tilde);
        let (zpart, hpart) = rem.split_at_mut(Self::Z_BITPACK_SIZE * L);
        for (p, c) in z
            .elems
            .iter()
            .zip(zpart.chunks_exact_mut(Self::Z_BITPACK_SIZE))
        {
            Self::bitpack_polynomial_z(p, c);
        }

        h.hint_bitpack::<Self>(hpart);
    }

    /// FIPS-204, Algorithm 27.
    fn sig_decode<const K: usize, const L: usize, const COMMITHASH_LEN: usize>(
        sigma: &[u8],
    ) -> Result<([u8; COMMITHASH_LEN], Vector<L>, Hint<K>), UnknownCryptoError> {
        debug_assert_eq!(
            Self::SIGNATURE_SIZE,
            (Self::Z_BITPACK_SIZE * L) + COMMITHASH_LEN + Self::OMEGA as usize + K
        );

        if sigma.len() != Self::SIGNATURE_SIZE {
            return Err(UnknownCryptoError);
        }

        let (c_tilde, rem) = sigma.split_at(COMMITHASH_LEN);
        let (polyparts, hintparts) = rem.split_at(Self::Z_BITPACK_SIZE * L);

        let mut z = Vector::<L>::zero();
        for (p, c) in z
            .elems
            .iter_mut()
            .zip(polyparts.chunks_exact(Self::Z_BITPACK_SIZE))
        {
            Self::bitunpack_ring_element_gamma(c, p);
        }

        let h = Hint::<K>::hint_bitunpack::<Self>(hintparts)?;

        let mut c_out = [0u8; COMMITHASH_LEN];
        c_out.copy_from_slice(c_tilde);

        Ok((c_out, z, h))
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
    const CLEN: usize = 576;

    const BETA: u32 = 78;
    const OMEGA: u32 = 80;

    const W1_BITPACK_SIZE: usize = 256 * 6 / 8;
    const W1_MAX_VALUE: u32 = 43;

    const DECOMPOSE_BARRETT_M: u32 = 88;
    const DECOMPOSE_W1_MAX: u32 = 43;

    const Z_BITPACK_SIZE: usize = 576;

    const PRIVATE_KEY_SIZE: usize = 2560;
    const PUBLIC_KEY_SIZE: usize = 1312;
    const SIGNATURE_SIZE: usize = 2420;

    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(v.len(), 576);
        let fe_gamma1 = FieldElement::new(Self::GAMMA_1);

        for (a, blk) in w.coefficients.chunks_exact_mut(4).zip(v.chunks_exact(9)) {
            let b = |k: usize| blk[k] as u32;
            let t = [
                b(0) | (b(1) << 8) | (b(2) << 16),
                (b(2) >> 2) | (b(3) << 6) | (b(4) << 14),
                (b(4) >> 4) | (b(5) << 4) | (b(6) << 12),
                (b(6) >> 6) | (b(7) << 2) | (b(8) << 10),
            ];
            for (dst, &tj) in a.iter_mut().zip(t.iter()) {
                *dst = fe_gamma1 - &FieldElement::new(tj & 0x3FFFF);
            }
        }
    }

    fn bitpack_ring_element_eta(w: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ETA_BITPACK_SIZE);
        let fe_eta = FieldElement::new(Self::ETA as u32);
        for i in 0..256 / 8 {
            let subat = |k: usize| fe_eta - &w.coefficients[8 * i + k];
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
            fe[0] = fe_eta - &FieldElement::new(b(0) & 7);
            fe[1] = fe_eta - &FieldElement::new((b(0) >> 3) & 7);
            fe[2] = fe_eta - &FieldElement::new((b(0) >> 6) | ((b(1) << 2) & 4));
            fe[3] = fe_eta - &FieldElement::new((b(1) >> 1) & 7);
            fe[4] = fe_eta - &FieldElement::new((b(1) >> 4) & 7);
            fe[5] = fe_eta - &FieldElement::new((b(1) >> 7) | ((b(2) << 1) & 6));
            fe[6] = fe_eta - &FieldElement::new((b(2) >> 2) & 7);
            fe[7] = fe_eta - &FieldElement::new((b(2) >> 5) & 7);
        }
    }

    fn bitpack_polynomial_vector_w1(w1: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::W1_BITPACK_SIZE);
        debug_assert!(
            w1.coefficients
                .iter()
                .all(|coeff| coeff.0 <= Self::W1_MAX_VALUE)
        );

        // three bytes will fit 4 coefficients given 6 bits per
        for (i, o) in out.chunks_exact_mut(3).enumerate() {
            let (a, b, c, d) = (
                w1[4 * i].0 as u8,
                w1[4 * i + 1].0 as u8,
                w1[4 * i + 2].0 as u8,
                w1[4 * i + 3].0 as u8,
            );

            o[0] = a | (b << 6);
            o[1] = (b >> 2) | (c << 4);
            o[2] = (c >> 4) | (d << 2);
        }
    }

    fn bitpack_polynomial_z(z: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::Z_BITPACK_SIZE);

        // nine bytes with 4 cofficients given 18 bits per
        for (i, o) in out.chunks_exact_mut(9).enumerate() {
            let a = z[4 * i].bitpack_gamma1_offset::<Self>();
            let b = z[4 * i + 1].bitpack_gamma1_offset::<Self>();
            let c = z[4 * i + 2].bitpack_gamma1_offset::<Self>();
            let d = z[4 * i + 3].bitpack_gamma1_offset::<Self>();

            o[0] = a as u8;
            o[1] = (a >> 8) as u8;
            o[2] = ((a >> 16) | (b << 2)) as u8;
            o[3] = (b >> 6) as u8;
            o[4] = ((b >> 14) | (c << 4)) as u8;
            o[5] = (c >> 4) as u8;
            o[6] = ((c >> 12) | (d << 6)) as u8;
            o[7] = (d >> 2) as u8;
            o[8] = (d >> 10) as u8;
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
    const CLEN: usize = 640;

    const BETA: u32 = 196;
    const OMEGA: u32 = 55;

    const W1_BITPACK_SIZE: usize = 256 * 4 / 8;
    const W1_MAX_VALUE: u32 = 15;

    const DECOMPOSE_BARRETT_M: u32 = 32;
    const DECOMPOSE_W1_MAX: u32 = 15;

    const Z_BITPACK_SIZE: usize = 640;

    const PRIVATE_KEY_SIZE: usize = 4032;
    const PUBLIC_KEY_SIZE: usize = 1952;
    const SIGNATURE_SIZE: usize = 3309;

    fn bitunpack_ring_element_gamma(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(v.len(), 640);
        let fe_gamma1 = FieldElement::new(Self::GAMMA_1);

        for (a, blk) in w.coefficients.chunks_exact_mut(2).zip(v.chunks_exact(5)) {
            let b = |k: usize| blk[k] as u32;
            let t0 = b(0) | (b(1) << 8) | (b(2) << 16);
            let t1 = (b(2) >> 4) | (b(3) << 4) | (b(4) << 12);
            a[0] = fe_gamma1 - &FieldElement::new(t0 & 0xFFFFF);
            a[1] = fe_gamma1 - &FieldElement::new(t1 & 0xFFFFF);
        }
    }

    fn bitpack_ring_element_eta(w: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ETA_BITPACK_SIZE);
        let fe_eta = FieldElement::new(Self::ETA as u32);

        for (i, outelem) in out.iter_mut().enumerate().take(256 / 2) {
            let t0 = fe_eta - &w.coefficients[2 * i];
            let t1 = fe_eta - &w.coefficients[2 * i + 1];
            *outelem = (t0.0 | (t1.0 << 4)) as u8;
        }
    }

    fn bitunpack_ring_element_eta(v: &[u8], w: &mut RingElement) {
        debug_assert_eq!(v.len(), Self::ETA_BITPACK_SIZE);
        let fe_eta = FieldElement::new(Self::ETA as u32);

        for (fe, &byte) in w.coefficients.chunks_exact_mut(2).zip(v.iter()) {
            fe[0] = fe_eta - &FieldElement::new((byte & 0x0F) as u32);
            fe[1] = fe_eta - &FieldElement::new((byte >> 4) as u32);
        }
    }

    fn bitpack_polynomial_vector_w1(w1: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::W1_BITPACK_SIZE);
        debug_assert!(
            w1.coefficients
                .iter()
                .all(|coeff| coeff.0 <= Self::W1_MAX_VALUE)
        );

        for (i, o) in out.iter_mut().enumerate() {
            *o = w1[2 * i].0 as u8 | (w1[2 * i + 1].0 as u8) << 4;
        }
    }

    fn bitpack_polynomial_z(z: &RingElement, out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::Z_BITPACK_SIZE);

        // 5 bytes with 2 cofficients given 20 bits per
        for (i, o) in out.chunks_exact_mut(5).enumerate() {
            let a = z[2 * i].bitpack_gamma1_offset::<Self>();
            let b = z[2 * i + 1].bitpack_gamma1_offset::<Self>();

            o[0] = a as u8;
            o[1] = (a >> 8) as u8;
            o[2] = ((a >> 16) | (b << 4)) as u8;
            o[3] = (b >> 4) as u8;
            o[4] = (b >> 12) as u8;
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
    const GAMMA_2: u32 = MlDsa65::GAMMA_2;
    const CLEN: usize = MlDsa65::CLEN;

    const BETA: u32 = 120;
    const OMEGA: u32 = 75;

    const W1_BITPACK_SIZE: usize = MlDsa65::W1_BITPACK_SIZE;
    const W1_MAX_VALUE: u32 = MlDsa65::W1_MAX_VALUE;

    const DECOMPOSE_BARRETT_M: u32 = MlDsa65::DECOMPOSE_BARRETT_M;
    const DECOMPOSE_W1_MAX: u32 = MlDsa65::DECOMPOSE_W1_MAX;

    const Z_BITPACK_SIZE: usize = MlDsa65::Z_BITPACK_SIZE;

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

    fn bitpack_polynomial_vector_w1(w1: &RingElement, out: &mut [u8]) {
        MlDsa65::bitpack_polynomial_vector_w1(w1, out);
    }

    fn bitpack_polynomial_z(w1: &RingElement, out: &mut [u8]) {
        MlDsa65::bitpack_polynomial_z(w1, out);
    }
}

/// Internal, generic signing key used across the three ML-DSA parametersets.
pub struct KeyPairInternal<
    const SK_ENCODED_SIZE: usize,
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> {
    pub(crate) sk: InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >,
    pub(crate) pk: InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >,
    _phantom: PhantomData<P>,
}

impl<
    const SK_ENCODED_SIZE: usize,
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
>
    KeyPairInternal<
        SK_ENCODED_SIZE,
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    /// FIPS-204, Algorithm 6.
    pub fn keygen_internal(seed: &[u8]) -> Result<Self, UnknownCryptoError> {
        debug_assert_eq!(K, P::DIM_K);
        debug_assert_eq!(L, P::DIM_L);
        debug_assert_eq!(seed.len(), 32);

        let mut h = Shake256::new();
        h.absorb(seed)?;
        h.absorb(&[K as u8, L as u8])?;

        let mut expanded_seed = zeroize_wrap!([0u8; 128]);
        h.squeeze(expanded_seed.as_mut())?;

        // SAFETY: Const-sized on 128.
        let rho: [u8; 32] = expanded_seed[..32].try_into().unwrap();

        let mat_a_hat = MatrixNTT::<K, L>::expand_a::<P>(&rho)?;
        let (s1, s2) = expand_s::<K, L, P>(&expanded_seed[32..32 + 64])?;
        let s1_hat = s1.ntt();
        let t = (&mat_a_hat * &s1_hat).inverse_ntt_mont() + &s2;
        let (t1, t0) = t.power2round::<P>();
        let pk = P::pk_encode::<PK_ENCODED_SIZE>(&rho, &t1.elems);

        let mut tr = [0u8; 64];
        h.reset();
        h.absorb(&pk)?;
        h.squeeze(tr.as_mut())?;

        let sk = P::sk_encode::<SK_ENCODED_SIZE, K, L>(
            &rho,
            &expanded_seed[32 + 64..32 + 64 + 32],
            &tr,
            &s1.elems,
            &s2.elems,
            &t0.elems,
        );

        Ok(Self {
            sk: InternalSigningKey {
                rho,
                sk,
                k: expanded_seed[32 + 64..32 + 64 + 32]
                    .try_into()
                    .expect("const-sized on 128"),
                tr_hash: tr,
                s1_hat,
                s2_hat: s2.ntt(),
                t0_hat: t0.ntt(),
                shake256: Shake256::new(),
                _phantom: PhantomData,
            },
            pk: InternalVerifyingKey {
                pk,
                rho,
                t1,
                mat_a_hat,
                shake256: Shake256::new(),
                _phantom: PhantomData,
            },
            _phantom: PhantomData,
        })
    }
}

/// Internal, generic signing key used across the three ML-DSA parametersets.
pub struct InternalSigningKey<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> {
    rho: [u8; 32],
    pub(crate) sk: [u8; SK_ENCODED_SIZE],
    k: [u8; 32],                    // PRIVATE random seed,
    tr_hash: [u8; 64],              // hash of public key `tr`
    s1_hat: VectorNTT<L, Standard>, // SECRET polyvector
    s2_hat: VectorNTT<K, Standard>, // SECRET polyvector
    t0_hat: VectorNTT<K, Standard>, // uncompressed public key
    shake256: Shake256,             // SHAK256 instance for streaming signing
    _phantom: PhantomData<P>,
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Debug
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {{***OMITTED***}}", stringify!(InternalSigningKey))
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Drop
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.memzero();
        }
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> TryFrom<&[u8]>
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    type Error = UnknownCryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (rho, k, tr, s1, s2, t0) = P::sk_decode(value)?;

        let ret = Self {
            rho,
            sk: value
                .try_into()
                .expect("length check is part of P::sk_decode()"),
            k,
            tr_hash: tr,
            // Precompute and store NTT of s1,s2,t0 and matrix A hat.
            s1_hat: s1.ntt(),
            s2_hat: s2.ntt(),
            t0_hat: t0.ntt(),
            shake256: Shake256::new(),
            _phantom: PhantomData,
        };

        Ok(ret)
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
>
    InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    /// Signing with `mu` precomputed.
    pub fn sign_internal_with_mu(
        &self,
        mu: &[u8],
        rnd: &[u8],
    ) -> Result<InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>, UnknownCryptoError>
    {
        debug_assert_eq!(mu.len(), 64);
        debug_assert_eq!(rnd.len(), 32);

        let mut h = Shake256::new();
        h.absorb(&self.k)?;
        h.absorb(rnd)?;
        h.absorb(mu)?;
        let mut rhoprimeprime = zeroize_wrap!([0u8; 64]);
        h.squeeze(rhoprimeprime.as_mut())?;

        let mut counter = 0u32;
        let mut valid_sample = false;

        let mut w1_bytes = zeroize_wrap!([0u8; W1_ENCODE_SIZE]);

        // Commitment hash
        let mut c_tilde = [0u8; COMMITHASH_LEN];
        let mut hint = Hint::<K>::zero();
        let mut z = Vector::<L>::zero();

        let mat_a_hat = MatrixNTT::<K, L>::expand_a::<P>(&self.rho)?;

        while !valid_sample {
            let y = zeroize_wrap!(expand_mask::<CLEN, K, L, P>(
                rhoprimeprime.as_slice(),
                counter
            )?);
            let w = zeroize_wrap!((&mat_a_hat * &y.ntt()).inverse_ntt_mont());
            let w1 = zeroize_wrap!(w.high_bits::<P>());
            P::w1_encode(&w1, w1_bytes.as_mut());

            // Commitment hash
            h.reset();
            h.absorb(mu)?;
            h.absorb(w1_bytes.as_slice())?;
            h.squeeze(&mut c_tilde)?;

            let c = sample_in_ball::<P>(&c_tilde)?;
            let c_hat = c.into_ntt();
            let c_mul_s1 = zeroize_wrap!((&c_hat * &self.s1_hat).inverse_ntt_mont());
            let c_mul_s2 = zeroize_wrap!((&c_hat * &self.s2_hat).inverse_ntt_mont());

            let w_sub_cs2;
            #[cfg(feature = "zeroize")]
            {
                z = *y + &*c_mul_s1;
                w_sub_cs2 = zeroize_wrap!(*w - &*c_mul_s2);
            }
            #[cfg(not(feature = "zeroize"))]
            {
                z = y + &c_mul_s1;
                w_sub_cs2 = zeroize_wrap!(w - &c_mul_s2);
            }

            let r0 = w_sub_cs2.low_bits::<P>();
            if bool::from(
                z.is_outside_bound(P::GAMMA_1 - P::BETA)
                    | r0.is_outside_bound(P::GAMMA_2 - P::BETA),
            ) {
                // Rejected
                counter += L as u32;
                continue;
            }

            let c_mul_t0 = (&c_hat * &self.t0_hat).inverse_ntt_mont();
            #[cfg(feature = "zeroize")]
            {
                hint = Hint::<K>::make::<P>(&-c_mul_t0, &(*w_sub_cs2 + &c_mul_t0));
            }
            #[cfg(not(feature = "zeroize"))]
            {
                hint = Hint::<K>::make::<P>(&-c_mul_t0, &(w_sub_cs2 + &c_mul_t0));
            }

            if bool::from(c_mul_t0.is_outside_bound(P::GAMMA_2) | hint.weight().ct_gt(&P::OMEGA)) {
                // Rejected
                counter += L as u32;
                continue;
            }

            valid_sample = true;
        }

        let mut sigma = [0u8; SIG_ENCODED_SIZE];
        P::sig_encode::<K, L, COMMITHASH_LEN>(&c_tilde, &z, &hint, &mut sigma);

        Ok(InternalSignature {
            sig: sigma,
            c: c_tilde,
            z,
            h: hint,
            _phantom: PhantomData,
        })
    }

    /// FIPS-204, Algorithm 7.
    pub fn sign_internal(
        &self,
        mprime: &[&[u8]],
        rnd: &[u8],
    ) -> Result<InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>, UnknownCryptoError>
    {
        debug_assert_eq!(rnd.len(), 32);

        let mut h = Shake256::new();
        h.absorb(&self.tr_hash)?;
        for mpart in mprime {
            h.absorb(mpart)?;
        }
        let mut mu = [0u8; 64];
        h.squeeze(&mut mu)?;

        self.sign_internal_with_mu(&mu, rnd)
    }

    /// FIPS-204, Algorithm 2.
    pub fn sign(
        &self,
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8],
    ) -> Result<InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>, UnknownCryptoError>
    {
        debug_assert_eq!(rnd.len(), 32);
        if ctx.len() > 255 {
            return Err(UnknownCryptoError);
        }

        self.sign_internal(&[&[0u8, ctx.len() as u8], ctx, m], rnd)
    }

    /// Initilize this signing keys internal H, to the state up to where an arbitrarly long
    /// message is hashed before signing.
    pub fn init(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError> {
        if ctx.len() > 255 {
            return Err(UnknownCryptoError);
        }

        // The usual streaming is_finalized logic is simply delegated
        // to Shake256. Streaming signing here is basically just a wrapper
        // around this instance. We reset() here everytime beucase init()
        // is the same as new() and a user shouldn't have to call reset()
        // before an init(). reset() direclty isn't provided, as the `ctx`
        // argument is required in terms of mu-input hashing order. So,
        // init() essentially serves as a reset() here as well.

        self.shake256.reset();
        self.shake256.absorb(&self.tr_hash)?;
        self.shake256.absorb(&[0u8, ctx.len() as u8])?;
        self.shake256.absorb(ctx)?;

        Ok(())
    }

    /// Essentially a wrapper over the internal H that hashes a message before signing.
    pub fn update(&mut self, msg: &[u8]) -> Result<(), UnknownCryptoError> {
        self.shake256.absorb(msg)
    }

    /// Finalize by finishing computation of `mu`.
    pub fn finalize(
        &mut self,
        rnd: &[u8],
    ) -> Result<InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>, UnknownCryptoError>
    {
        debug_assert_eq!(rnd.len(), 32);

        self.shake256.absorb(rnd)?;
        let mut mu = [0u8; 64];
        self.shake256.squeeze(&mut mu)?;

        self.sign_internal_with_mu(&mu, rnd)
    }
}

#[derive(Debug, Clone)]
/// Internal, generic verifying key used across the three ML-DSA parametersets.
pub struct InternalVerifyingKey<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> {
    pub(crate) pk: [u8; PK_ENCODED_SIZE],
    rho: [u8; 32],
    t1: Vector<K>,
    mat_a_hat: MatrixNTT<K, L>,
    shake256: Shake256,
    _phantom: PhantomData<P>,
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> PartialEq
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn eq(&self, other: &Self) -> bool {
        // NOTE: Only compare the encoded key type.
        // This is in line with how mldsa44/65/87 Public<VerifyingKey> is built.
        self.pk == other.pk
    }
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> TryFrom<&[u8]>
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    type Error = UnknownCryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (rho, t1) = P::pk_decode::<K>(value)?;

        Ok(Self {
            pk: value
                .try_into()
                .expect("length check is part of P::pk_decode()"),
            rho,
            t1,
            mat_a_hat: MatrixNTT::<K, L>::expand_a::<P>(&rho)?,
            shake256: Shake256::new(),
            _phantom: PhantomData,
        })
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
>
    TryFrom<
        &InternalSigningKey<
            SK_ENCODED_SIZE,
            SIG_ENCODED_SIZE,
            CLEN,
            COMMITHASH_LEN,
            W1_ENCODE_SIZE,
            K,
            L,
            P,
        >,
    >
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    type Error = UnknownCryptoError;

    fn try_from(
        value: &InternalSigningKey<
            SK_ENCODED_SIZE,
            SIG_ENCODED_SIZE,
            CLEN,
            COMMITHASH_LEN,
            W1_ENCODE_SIZE,
            K,
            L,
            P,
        >,
    ) -> Result<Self, Self::Error> {
        #[cfg(feature = "zeroize")]
        let (rho, mut k, _tr, _s1, s2, _t0) = P::sk_decode::<K, L>(&value.sk)?;
        #[cfg(feature = "zeroize")]
        k.zeroize();

        #[cfg(not(feature = "zeroize"))]
        let (rho, _k, _tr, _s1, s2, _t0) = P::sk_decode::<K, L>(&value.sk)?;

        let mat_a_hat = MatrixNTT::<K, L>::expand_a::<P>(&rho)?;
        let t = (&mat_a_hat * &value.s1_hat).inverse_ntt_mont() + &s2;
        let (t1, _t0) = t.power2round::<P>();
        let pk = P::pk_encode::<PK_ENCODED_SIZE>(&rho, &t1.elems);

        Ok(Self {
            pk,
            rho,
            t1,
            mat_a_hat,
            shake256: Shake256::new(),
            _phantom: PhantomData,
        })
    }
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
>
    InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    /// FIPS-204, Algorithm 8.
    pub fn verify_internal_with_mu(
        &self,
        mu: &[u8],
        sigma: &InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>,
    ) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(mu.len(), 64);

        let c = sample_in_ball::<P>(&sigma.c)?;
        // Az − ct1 ⋅ 2d
        let w_approx = ((&self.mat_a_hat * &sigma.z.ntt())
            - &(&c.into_ntt() * &self.t1.shift_left_d::<P>().ntt()))
            .inverse_ntt_mont();

        let w1 = w_approx.use_hint::<P>(&sigma.h);
        let mut c_tilde_prime = [0u8; COMMITHASH_LEN];
        let mut w1encoded = [0u8; W1_ENCODE_SIZE];
        P::w1_encode(&w1, &mut w1encoded);

        let mut h = Shake256::new();
        h.absorb(mu)?;
        h.absorb(&w1encoded)?;
        h.squeeze(&mut c_tilde_prime)?;

        // SECURITY: While this is VerifyingKey and therefor should
        // be no leak of secret data if this were vartime, we keep it
        // because is_outside_bound() return Choice and it is the careful
        // approach.
        if bool::from(
            !sigma.z.is_outside_bound(P::GAMMA_1 - P::BETA)
                & sigma.c.as_slice().ct_eq(&c_tilde_prime),
        ) {
            Ok(())
        } else {
            Err(UnknownCryptoError)
        }
    }

    /// FIPS-204, Algorithm 8.
    pub fn verify_internal(
        &self,
        mprime: &[&[u8]],
        sigma: &InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>,
    ) -> Result<(), UnknownCryptoError> {
        let mut tr = [0u8; 64];
        let mut h = Shake256::new();
        h.absorb(&self.pk)?;
        h.squeeze(&mut tr)?;
        h.reset();

        let mut mu = [0u8; 64];
        h.absorb(&tr)?;
        for mpart in mprime {
            h.absorb(mpart)?;
        }
        h.squeeze(&mut mu)?;

        self.verify_internal_with_mu(&mu, sigma)
    }

    /// FIPS-204, Algorithm 3.
    pub fn verify(
        &self,
        m: &[u8],
        sigma: &InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>,
        ctx: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        if ctx.len() > 255 {
            return Err(UnknownCryptoError);
        }
        self.verify_internal(&[&[0u8, ctx.len() as u8], ctx, m], sigma)
    }

    /// Initilize this signing keys internal H, to the state up to where an arbitrarly long
    /// message is hashed before signing.
    pub fn init(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError> {
        if ctx.len() > 255 {
            return Err(UnknownCryptoError);
        }

        // The usual streaming is_finalized logic is simply delegated
        // to Shake256. Streaming signing here is basically just a wrapper
        // around this instance. We reset() here everytime beucase init()
        // is the same as new() and a user shouldn't have to call reset()
        // before an init(). reset() direclty isn't provided, as the `ctx`
        // argument is required in terms of mu-input hashing order. So,
        // init() essentially serves as a reset() here as well.

        self.shake256.reset();
        let mut tr = [0u8; 64];
        self.shake256.absorb(&self.pk)?;
        self.shake256.squeeze(&mut tr)?;

        self.shake256.reset();
        self.shake256.absorb(&tr)?;
        self.shake256.absorb(&[0u8, ctx.len() as u8])?;
        self.shake256.absorb(ctx)?;

        Ok(())
    }

    /// Essentially a wrapper over the internal H that hashes a message before signing.
    pub fn update(&mut self, msg: &[u8]) -> Result<(), UnknownCryptoError> {
        self.shake256.absorb(msg)
    }

    /// Finalize by finishing computation of `mu`.
    pub fn finalize(
        &mut self,
        sigma: &InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>,
    ) -> Result<(), UnknownCryptoError> {
        let mut mu = [0u8; 64];
        self.shake256.squeeze(&mut mu)?;
        self.verify_internal_with_mu(&mu, sigma)
    }
}

#[derive(Debug, PartialEq, Clone)]
/// Internal, generic signature used across the three ML-DSA parametersets.
pub struct InternalSignature<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> {
    pub sig: [u8; SIGNATURE_SIZE],
    pub c: [u8; COMMITHASH_LEN],
    pub z: Vector<L>,
    pub h: Hint<K>,
    _phantom: PhantomData<P>,
}

impl<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> TryFrom<&[u8]> for InternalSignature<SIGNATURE_SIZE, COMMITHASH_LEN, K, L, P>
{
    type Error = UnknownCryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (c, z, h) = P::sig_decode::<K, L, COMMITHASH_LEN>(value)?;

        Ok(Self {
            sig: value.try_into().expect("sig_decode() checked"),
            c,
            z,
            h,
            _phantom: PhantomData,
        })
    }
}

// TypePrimitive + TypeData + Data impls for InternalSigningKey, InternalVerifyingKey, InternalSignature

impl<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Sealed for InternalSignature<SIGNATURE_SIZE, COMMITHASH_LEN, K, L, P>
{
}

impl<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsRef<[u8]> for InternalSignature<SIGNATURE_SIZE, COMMITHASH_LEN, K, L, P>
{
    fn as_ref(&self) -> &[u8] {
        &self.sig
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Sealed
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsRef<[u8]>
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    // NOTE(brycx): required by `Data`, user-facing API
    // does not expose this directly.
    fn as_ref(&self) -> &[u8] {
        &self.sk
    }
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Sealed
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsRef<[u8]>
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    // NOTE(brycx): required by `Data`, user-facing API
    // does not expose this directly.
    fn as_ref(&self) -> &[u8] {
        &self.pk
    }
}

// NOTE: unimplemented!() for trait-required methods that are not applicable to this
// scenario using SigningKey<> and VerifyingKey<>.

impl<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsMut<[u8]> for InternalSignature<SIGNATURE_SIZE, COMMITHASH_LEN, K, L, P>
{
    fn as_mut(&mut self) -> &mut [u8] {
        unimplemented!("CORRECTNESS: VerifyingKey is not safe to modify only on encoded bytes.")
    }
}

impl<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsMut<[u8; SIGNATURE_SIZE]> for InternalSignature<SIGNATURE_SIZE, COMMITHASH_LEN, K, L, P>
{
    fn as_mut(&mut self) -> &mut [u8; SIGNATURE_SIZE] {
        unimplemented!("CORRECTNESS: VerifyingKey is not safe to modify only on encoded bytes.")
    }
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsMut<[u8]>
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn as_mut(&mut self) -> &mut [u8] {
        unimplemented!("CORRECTNESS: VerifyingKey is not safe to modify only on encoded bytes.")
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsMut<[u8]>
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn as_mut(&mut self) -> &mut [u8] {
        unimplemented!("CORRECTNESS: SigningKey is not safe to modify only on encoded bytes.")
    }
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsMut<[u8; PK_ENCODED_SIZE]>
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn as_mut(&mut self) -> &mut [u8; PK_ENCODED_SIZE] {
        unimplemented!("CORRECTNESS: VerifyingKey is not safe to modify only on encoded bytes.")
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> AsMut<[u8; SK_ENCODED_SIZE]>
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn as_mut(&mut self) -> &mut [u8; SK_ENCODED_SIZE] {
        unimplemented!("CORRECTNESS: SigningKey is not safe to modify only on encoded bytes.")
    }
}

impl<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Data for InternalSignature<SIGNATURE_SIZE, COMMITHASH_LEN, K, L, P>
{
    fn len(&self) -> usize {
        debug_assert_eq!(self.sig.len(), SIGNATURE_SIZE);
        SIGNATURE_SIZE
    }

    fn is_empty(&self) -> bool {
        SIGNATURE_SIZE == 0
    }

    fn new(_size: usize) -> Result<Self, UnknownCryptoError> {
        unimplemented!("CORRECTNESS: Not applicable for this type.")
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        unimplemented!(
            "SECURITY: InternalSignature<> is exposed as Public and should never need memzero as part of Drop."
        );
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Data
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn len(&self) -> usize {
        debug_assert_eq!(self.sk.len(), SK_ENCODED_SIZE);
        SK_ENCODED_SIZE
    }

    fn is_empty(&self) -> bool {
        SK_ENCODED_SIZE == 0
    }

    fn new(_size: usize) -> Result<Self, UnknownCryptoError> {
        unimplemented!("CORRECTNESS: Not applicable for this type.")
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        use zeroize::Zeroize;
        self.sk.iter_mut().zeroize();
        self.k.iter_mut().zeroize();
        self.s1_hat.zeroize();
        self.s2_hat.zeroize();
        self.t0_hat.zeroize();
    }
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> Data
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn len(&self) -> usize {
        debug_assert_eq!(self.pk.len(), PK_ENCODED_SIZE);
        PK_ENCODED_SIZE
    }

    fn is_empty(&self) -> bool {
        PK_ENCODED_SIZE == 0
    }

    fn new(_size: usize) -> Result<Self, UnknownCryptoError> {
        unimplemented!("CORRECTNESS: Not applicable for this type.")
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        unimplemented!(
            "SECURITY: InternalVerifyingKey<> is exposed as Public and should never need memzero as part of Drop."
        );
    }
}

impl<
    const SIGNATURE_SIZE: usize,
    const COMMITHASH_LEN: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> TryFromBytes for InternalSignature<SIGNATURE_SIZE, COMMITHASH_LEN, K, L, P>
{
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        // NOTE: Doesn't need the parse_bytes() because it already uses
        // the TypeData::try_from_bytes(), which we define to be custom here.
        Self::try_from(bytes)
    }
}

impl<
    const SK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> TryFromBytes
    for InternalSigningKey<
        SK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        // NOTE: Doesn't need the parse_bytes() because it already uses
        // the TypeData::try_from_bytes(), which we define to be custom here.
        Self::try_from(bytes)
    }
}

impl<
    const PK_ENCODED_SIZE: usize,
    const SIG_ENCODED_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
> TryFromBytes
    for InternalVerifyingKey<
        PK_ENCODED_SIZE,
        SIG_ENCODED_SIZE,
        CLEN,
        COMMITHASH_LEN,
        W1_ENCODE_SIZE,
        K,
        L,
        P,
    >
{
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        // NOTE: Doesn't need the parse_bytes() because it already uses
        // the TypeData::try_from_bytes(), which we define to be custom here.
        Self::try_from(bytes)
    }
}
