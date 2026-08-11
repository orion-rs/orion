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

pub mod prehash;
use core::{fmt::Debug, marker::PhantomData};

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater};

use crate::{
    errors::UnknownCryptoError,
    generics::sealed::{Data, Sealed, TryFromBytes},
    hazardous::{
        dsa::ml_dsa::internal::{
            fe::{FieldElement, Hint, RingElement, Standard, Vector, VectorNTT},
            prehash::PreHash,
            sampling::{MatrixNTT, expand_mask, expand_s, sample_in_ball},
        },
        hash::{
            sha2::{sha256::Sha256, sha384::Sha384, sha512::Sha512},
            sha3::{
                sha3_224::Sha3_224, sha3_256::Sha3_256, sha3_384::Sha3_384, sha3_512::Sha3_512,
                shake128::Shake128, shake256::Shake256,
            },
        },
    },
};

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

    /// bytes sued to encode polynomial as byte signature
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
            read += Self::D_BITPACK_SIZE;
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

    fn expand_seed<const K: usize, const L: usize>(
        rho: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if rho.len() != 32 || out.len() != 128 {
            return Err(UnknownCryptoError);
        }

        let mut h = Shake256::new();
        h.absorb(rho)?;
        h.absorb(&[K as u8, L as u8])?;
        h.squeeze(out)?;

        Ok(())
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

/// TODO: Safeguard PartialEq, Debug, Drop/Zeroize for all these structs.

#[derive(Debug)]
/// TODO: THIS SHOULD BE INTERNAL
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

        let t = (&mat_a_hat * &s1.ntt()).inverse_ntt_mont() + s2;
        let (t1, t0) = t.power2round::<P>();
        let pk = P::pk_encode::<PK_ENCODED_SIZE>(&rho, &t1.elems);

        let mut tr = [0u8; 64];
        h.reset();
        h.absorb(&pk)?;
        h.squeeze(&mut tr.as_mut())?;

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
                sk,
                k: expanded_seed[32 + 64..32 + 64 + 32]
                    .try_into()
                    .expect("const-sized on 128"),
                tr_hash: tr,
                s1_hat: s1.ntt(),
                s2_hat: s2.ntt(),
                t0_hat: t0.ntt(),
                mat_a_hat: mat_a_hat.clone(),
                _phantom: PhantomData,
            },
            pk: InternalVerifyingKey {
                pk,
                rho,
                t1,
                mat_a_hat,
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
    pub(crate) sk: [u8; SK_ENCODED_SIZE],
    k: [u8; 32],                    // PRIVATE random seed,
    tr_hash: [u8; 64],              // hash of public key `tr`
    s1_hat: VectorNTT<L, Standard>, // SECRET polyvector
    s2_hat: VectorNTT<K, Standard>, // SECRET polyvector
    t0_hat: VectorNTT<K, Standard>, // uncompressed public key
    mat_a_hat: MatrixNTT<K, L>,
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
        write!(f, "{} {{***OMITTED***}}", stringify!($name))
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
            sk: value
                .try_into()
                .expect("length check is part of P::sk_decode()"),
            k,
            tr_hash: tr,
            // Precompute and store NTT of s1,s2,t0 and matrix A hat.
            s1_hat: s1.ntt(),
            s2_hat: s2.ntt(),
            t0_hat: t0.ntt(),
            mat_a_hat: MatrixNTT::<K, L>::expand_a::<P>(&rho)?,
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

        // TODO: does this need zeroize?
        let mut w1_bytes = [0u8; W1_ENCODE_SIZE];

        // Commitment hash
        // TODO: does this need zeroize?
        let mut c_tilde = [0u8; COMMITHASH_LEN];
        let mut hint = Hint::<K>::zero();
        let mut z = Vector::<L>::zero();

        while !valid_sample {
            let y = expand_mask::<CLEN, K, L, P>(rhoprimeprime.as_slice(), counter)?;
            let w = (&self.mat_a_hat * &y.ntt()).inverse_ntt_mont();
            let w1 = w.high_bits::<P>();
            P::w1_encode(&w1, &mut w1_bytes);

            // Commitment hash
            h.reset();
            h.absorb(mu)?;
            h.absorb(&w1_bytes)?;
            h.squeeze(&mut c_tilde)?;

            let c = sample_in_ball::<P>(&c_tilde)?;
            let c_hat = c.into_ntt();
            let c_mul_s1 = (&c_hat * &self.s1_hat).inverse_ntt_mont();
            let c_mul_s2 = (&c_hat * &self.s2_hat).inverse_ntt_mont();
            z = y + c_mul_s1;

            let w_sub_cs2 = w - c_mul_s2;
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
            hint = Hint::<K>::make::<P>(&-c_mul_t0, &(w_sub_cs2 + c_mul_t0));

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

    /// FIPS-204, HashML-DSA.
    pub fn sign_prehash(
        &self,
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8],
        ph: &PreHash,
    ) -> Result<InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>, UnknownCryptoError>
    {
        debug_assert_eq!(rnd.len(), 32);
        if ctx.len() > 255 {
            return Err(UnknownCryptoError);
        }

        match ph {
            // 2.16.840.1.101.3.4.2.1
            PreHash::SHA256 => {
                let hash = Sha256::digest(m)?;
                self.sign_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    rnd,
                )
            }
            // 2.16.840.1.101.3.4.2.2
            PreHash::SHA384 => {
                let hash = Sha384::digest(m)?;
                self.sign_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    rnd,
                )
            }
            // 2.16.840.1.101.3.4.2.3
            PreHash::SHA512 => {
                let hash = Sha512::digest(m)?;
                self.sign_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    rnd,
                )
            }
            PreHash::SHA3_224 => {
                let hash = Sha3_224::digest(m)?;
                self.sign_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    rnd,
                )
            }
            // 2.16.840.1.101.3.4.2.8
            PreHash::SHA3_256 => {
                let hash = Sha3_256::digest(m)?;
                self.sign_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    rnd,
                )
            }
            // 2.16.840.1.101.3.4.2.9
            PreHash::SHA3_384 => {
                let hash = Sha3_384::digest(m)?;
                self.sign_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    rnd,
                )
            }
            // 2.16.840.1.101.3.4.2.10
            PreHash::SHA3_512 => {
                let hash = Sha3_512::digest(m)?;
                self.sign_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    rnd,
                )
            }
            // 2.16.840.1.101.3.4.2.11
            PreHash::SHAKE128 => {
                let mut ph_m = [0u8; 256 / 8];
                let mut shake128 = Shake128::new();
                shake128.absorb(m)?;
                shake128.squeeze(&mut ph_m)?;
                self.sign_internal(&[&[1u8, ctx.len() as u8], ctx, ph.oid(), &ph_m], rnd)
            }
            // 2.16.840.1.101.3.4.2.12
            PreHash::SHAKE256 => {
                let mut ph_m = [0u8; 512 / 8];
                let mut shake256 = Shake256::new();
                shake256.absorb(m)?;
                shake256.squeeze(&mut ph_m)?;
                self.sign_internal(&[&[1u8, ctx.len() as u8], ctx, ph.oid(), &ph_m], rnd)
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
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
            - (&c.into_ntt() * &self.t1.shift_left_d::<P>().ntt()))
            .inverse_ntt_mont();

        let w1 = w_approx.use_hint::<P>(&sigma.h);
        let mut c_tilde_prime = [0u8; COMMITHASH_LEN];
        let mut w1encoded = [0u8; W1_ENCODE_SIZE];
        P::w1_encode(&w1, &mut w1encoded);

        let mut h = Shake256::new();
        h.absorb(mu)?;
        h.absorb(&w1encoded)?;
        h.squeeze(&mut c_tilde_prime)?;

        // TODO: I don't think this requires constant-time?
        // what can be learned of anything? There's no secret data
        // dervied anywhere in this codepath...
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

    /// FIPS-204, HashML-DSA.
    pub fn verify_prehash(
        &self,
        m: &[u8],
        sigma: &InternalSignature<SIG_ENCODED_SIZE, COMMITHASH_LEN, K, L, P>,
        ctx: &[u8],
        ph: &PreHash,
    ) -> Result<(), UnknownCryptoError> {
        if ctx.len() > 255 {
            return Err(UnknownCryptoError);
        }

        match ph {
            // 2.16.840.1.101.3.4.2.1
            PreHash::SHA256 => {
                let hash = Sha256::digest(m)?;
                self.verify_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    sigma,
                )
            }
            // 2.16.840.1.101.3.4.2.2
            PreHash::SHA384 => {
                let hash = Sha384::digest(m)?;
                self.verify_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    sigma,
                )
            }
            // 2.16.840.1.101.3.4.2.3
            PreHash::SHA512 => {
                let hash = Sha512::digest(m)?;
                self.verify_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    sigma,
                )
            }
            PreHash::SHA3_224 => {
                let hash = Sha3_224::digest(m)?;
                self.verify_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    sigma,
                )
            }
            // 2.16.840.1.101.3.4.2.8
            PreHash::SHA3_256 => {
                let hash = Sha3_256::digest(m)?;
                self.verify_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    sigma,
                )
            }
            // 2.16.840.1.101.3.4.2.9
            PreHash::SHA3_384 => {
                let hash = Sha3_384::digest(m)?;
                self.verify_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    sigma,
                )
            }
            // 2.16.840.1.101.3.4.2.10
            PreHash::SHA3_512 => {
                let hash = Sha3_512::digest(m)?;
                self.verify_internal(
                    &[&[1u8, ctx.len() as u8], ctx, ph.oid(), hash.as_ref()],
                    sigma,
                )
            }
            // 2.16.840.1.101.3.4.2.11
            PreHash::SHAKE128 => {
                let mut ph_m = [0u8; 256 / 8];
                let mut shake128 = Shake128::new();
                shake128.absorb(m)?;
                shake128.squeeze(&mut ph_m)?;
                self.verify_internal(&[&[1u8, ctx.len() as u8], ctx, ph.oid(), &ph_m], sigma)
            }
            // 2.16.840.1.101.3.4.2.12
            PreHash::SHAKE256 => {
                let mut ph_m = [0u8; 512 / 8];
                let mut shake256 = Shake256::new();
                shake256.absorb(m)?;
                shake256.squeeze(&mut ph_m)?;
                self.verify_internal(&[&[1u8, ctx.len() as u8], ctx, ph.oid(), &ph_m], sigma)
            }
        }
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

// TODO: either have signature type here or one level up in modules
// for each variant.

// TypePrimitive + TypeData + Data impls for InternalSigningKey and InternalVerifyingKey

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
            "SECURITY: EncapKey<> is exposed as Public and should never need memzero as part of Drop."
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
        self.s1_hat.elems.iter_mut().zeroize();
        self.s2_hat.elems.iter_mut().zeroize();
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
            "SECURITY: EncapKey<> is exposed as Public and should never need memzero as part of Drop."
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
        // NOTE: Doesn't need the parse_bytes() becuase it already uses
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
        // NOTE: Doesn't need the parse_bytes() becuase it already uses
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
        // NOTE: Doesn't need the parse_bytes() becuase it already uses
        // the TypeData::try_from_bytes(), which we define to be custom here.
        Self::try_from(bytes)
    }
}

#[test]
fn test_mldsa_sk_decode() {
    let sk = hex::decode("0B89806F0EEC39F2891116152ED4319D4260DFB8AC0710765BD497E6E1DE17786CDEC899F1C6534284585DDA4DF03E45E4D39B4526015A7B3D65F8BF875452560DB3223594A1FCE8DB48C8F1793611A17FCC0006FFEA26CF7094D8325037288F8AF7D062833B71B8C0F06108442786E3DE59D649162273EF179AEADBBD48CC981CA86463082A0020220CC10003B160C0B82C20A70409C521649820E3A84409C689832621E20832C1B04C1C8911429420193789C12462E4C661643600D8484A0998601902621B104CC2A4495A1600444690A3800CD3889098A49024C3901A344D594052614411248101C416261308881C818083A86142200D23262A1B2501D0422464C4911315094092641B071208956C513830A20831CBB84153240E99C41111A1241A297003A74011B744A2442DDAC0041C21611222684B126821C3104082600A2352C43890CC967063206553486D84124C0239328A0640112689E49841114871D22652E3C2240A98889802891B8031E4089140B404534286411826D102929C946180C84801134118348509B76984180D0A404AE2340E0181809C04662481299AA424A2B8445C38491AC20DD9B045A286491C864011036C13B78044B2618498700A1989A00024E1C2488CB09063B8100A408C18171009B76C1108249136404BC29104A96901B525044802C300319C380E0A26229CC4841A04306184201A1300A1940460982912924D12144AE1068D80B62D1AA5855C240849A20401B56880B449D9B21163240A98424414B40401264282008C0B04651B21409A488494866D18B380C4A801020326CC44491922208A364264048D1205814AB20401426A5886201034110039295A98654138080CC964D3849021A788E0088901386012222859488290C20C538430823626818051A4C871819431E0386ED3A22121186E8B027151240ED13689903408A3480A0B34894C040608314C81280400894503920D010208E0C011D1041288482E01280E08C161C11820C4C84800242A24C545D80020C8368498C885D4B40CC3062942B00D98487002A7899B303152284E10860C23B124901829C2C84462B269431824098621D2062989020A1CA76023C00448426CA4902CE09681C2C66D23286C40206A4404210C3405C980814B0892A0162151B001C1148D413849DC968C212244C4A00D18049240083209126A00177109118114962402C22D109591A1084D0B316C01466ACA8291CA1252D3B23018094D44C4845490411FB45680A1B2685FF6F4075D76E422EE9B1DD39048A2C6B0C1C441689316AEE550C179A8E55B87627071ED299FCBFACFD13CFBE61A9F87BE0579A19357C4E7B0F125D354DCEC0CA0EAEB5E116FBD87EFB3049ADE6F28921D56ED84487CAD51BD84F7C07FF460B09B4201E7B9DF1801DA2771C2DA20D2B687A44D4D1F49DA38BCF9AE30713ACD86E32F52FA8735DCDEDF1CDA4A5C2C8880784A5B7C3AC395FF8C4BD1A0303868CD3E6D1F7EF258F38F5CF560AB9E8357272222123821D25C141258A6B132F9F99D014584BFE23AD4957F6692CD7E8327CF66E581A598C4FF3C7CBF5316B3AB028FF82E8BC3250F250E6A451996BFAA00A1458A86F8304F2A839DD1B929EAE4E53E919AEA13BA09569B14148ECE44CB27650EAE5FB352061C7301D8DD9CB5156BC15DE1F578AD95D6505CCFD485D99867D48BC6910A491856D30B17FD8952B774A70F57A24458CD9B18D0A222BC5B307A34EE347106A9B76609505E7C81495F88D8DA05D742188F01820EBB8AC559FF3417A33E6CD4FDA1D60C1A6D37C3D27F51717645ADEE9020F10748F7CDB0D5B142F465C54FE5D70CB787EB47B8741A162BF373AFA1C8DB3985900C6A8B9035006CEDB7EB9854D3C50E1C30C8A6B34269D85D7C683EDB1BE1455ECE1C9768EA9C9A140036E8EAD9A19D9F167E52CA10DA5FA7FE2BED7C0ADB0A45C642AC02ECB5B1C5199AD5D6227CB4F506A973D696908C15791513783736FFFE5A47395CE2E7CE1C42E7F6541825A2BDE5617F53B5155AC30E3EC43BB4EF5AD727ACE5A5ADCC7F036A1BB606F7C943C112B372DB92832639DB2F488A3ED64E43609DD93B43F38DB939F6BAE61E3E44772929E65F43D739A061AE3272021A220387A43BE3A985AD713999F75E040DF53DA81801BF165052A68179E6BB1FD4F624C31EDAB74F6E2E7EFC31EDA78103BFCB32B837BA07C5D37E922440DE741BE0029BE98DC86739324D73E62B3FD09B9EE00EF8DBCFD0ED687C5269BF3A4F84AFE2B8FB52BBD118E718DF5972038CDAB018CF8AC7D6785C958AC5B9B23785DE1A90B9BE64279015FCE8C36C87453E392DA20CC72C533D115BC0F53A385A0DF6127B3A81592552B7CF0E8AF3797869683FF0C42D2A189C04442966B37CA321A4DBF02067447D50D09F92E4E63A272A97E0460FF1BFBF82F61412BBBDEAE83D0843F5B38E10A53DC5CA86A4C6AEB17601FB560A8852BC60C25767C2489F95143FCF75B648E814374BA98DFA753D08A53F02377F551C9AA374301CE7C84B1A48E6F750794E5386361815155053175DB12E29EF9D49920D7704CC343DA6021249479E5E5405F3BEDE4DBD612009C34E659C3C9D7C59DA97D104F47D4B314D1C0E2414F8746CA658A9731C18A0C89F61E11F617B197093ADDEFA42CA0DF723F93A12ED83C352B05F8F5039B2C8D321C4992D0DF249BC5148E0C27519430A9E70A5CC24B8E0217D6F9BD04737A4FCF7351C7670269DAD9DA97858A1FA9DA23DFAB215172BFF72962F62406D2C5747CA0F273EF8F31761F99CAF2F417685F971C3415FD1C79D7A4E75EC50A6B7B795A35BC45EDAA824EE71E651830C96AC2905C1EAF817B8E833C9BE77242A6B43FFFBC108DAC12631EBC86BC06BD7E506F827B142F03476357C9AE5B98B447DBE0F408C75535FD9341FA3693F2887FACE3B72CECFD62CBF908319A22336AC43E57E2A46C42B28B6E55D7075B5CFED7D8C0A8A1A4ADAAE79B4A09B7CCFC04FD99FEBE3A0DE1F8A9B43F97A2F93CD758AD546C0A1C3801E3BCFE1ADC246E7A34044CF56BFBDF5A5035C2B8D1E19A3A7243C225BE23EBA7FFF8E052C3845310F4B2B7393BDC15B766BA0B3CB45BD0A1CC693C947A5A964DD39287828EE86EB6C2DB9D8967EDF4B75C78EF4B34561EA1A9D93BB8E1209381E9D1F2C0E61EDBAB542E07E2C3C71F4841A3F2117F26B608CA244C46663C3FBD6A6A20F55C8C778C585BAC5DBEFDE74A7EFA8658D95B12EE9412BC8CC24333BB2A3E994E887A8140FE482EDFECA89E887531A536BC13FC44AF7B595B06E6B122E59A324992C553D6278AF277E5C545B126105D1A180D2CF769ABBCD9B8DB72330E6548521FF4569C674E60D35923B86F0166CD24D8AC7FA4F49743E7E2C90BCF3E66955C6F5CA430024902C536D0E0F5D3A637C033A3BA6F9778475C455E440A5E03B485F7C8263F5D007A8A1B3DEF7AE943DD38633715B50A2E76228521EB1D0CAAEAB48951C1E395DF94F9A63313DBCCF1A6BE8C0954388AEBB0AE472E741A8006DC0299F5E4073E89A3D097512321BA8037C391CBEE65977354B3739CB04FAE7663D86E9CE04BEF14D3615B9DF81AEA3E4").unwrap();
    // let sk = testvector...;
    let (rho, k, tr, s1, s2, t0) =
        MlDsa44::sk_decode::<{ MlDsa44::DIM_K }, { MlDsa44::DIM_L }>(&sk).unwrap();

    let sk_rt = MlDsa44::sk_encode::<
        { MlDsa44::PRIVATE_KEY_SIZE },
        { MlDsa44::DIM_K },
        { MlDsa44::DIM_L },
    >(&rho, &k, &tr.as_slice(), &s1.elems, &s2.elems, &t0.elems);

    assert_eq!(sk, sk_rt);
}

#[test]
fn test_mldsa_pk_decode() {
    let pk = hex::decode("0B89806F0EEC39F2891116152ED4319D4260DFB8AC0710765BD497E6E1DE17783CF81E435A412EABEF5DB3AF5D15867BBB4C60F8CF98BA31BAD6D41A5F8EB0C11B632C3F19D844A223C353BD182883DCF13B5C97823D0C0E6902DB25AD8D344A37F59F4AFACA5BC8874792DA1E6A3EAE742AB7034B20A4AB75A93BCA4B68002DD242CED348920B7E5ABF645A0E2E79617BCB3EE7BA972B3E718D3EFFC59B1869814BA3F526927477B12BF25CBAD8B04B09905FDAD3820715A8B9A905DE1CD65EFF6B0B0886305EFB6CFEEC9E90B5EF9A5AAEC45C753298E8DF9B017CE0FEC9B7431B20775CE8CB11F1F42D1D9FE936D0803196E71ADDC26CC430CC3B69760C7CCAFAB7651E21BAA28F92BBFF1C4A6EEF156D6F08F80B5E3B6FC943E6E984378B90888D09A6EA38B0BA86A3446211452E076DC9F65620014205D5271C7A44FEC3CC5375EB246AFFC11B26CAFB8B96CEE3A68E31642E3D69B9130795F25ED818EBB211CD8BE648ADB5C8A120C8186017727FBCAB31C7425C08FE9195DE6BDBADA5778D727EE5CDE0674FACB7AB81786357B529C71DDB24DF770E8E95E5F3112BD297B352CB91B08ED1097A98E87BD7CE4235B8DD42292CD4C59D87C1F0FF00734AA22D7CAE4361ADC47742C897601048526702538828BA3C3A959990C0E99463FD22417E147FF2DAA74C0C8D3A06E9703A2E160590086DB8011A3D9CEC5AE6348706F87CB2379632CE56E660A0BA1B30E3846C5B5C6C0339DD993E543A5322AF5A11FC7040A2DF23A0B43E882D7A0FF4431A723BBB918AFF7F14BC045CBE94BCAB27AE3109147B588665EF486006562B1297016EFDE787B46237060EE431E0F011166F916AA0789A7647103B7400A1CBCF0E22BD7B6DD2BB3EC51EC98F0EC6A5BAA4CDC83F993D302F8FA849F2046B78AA32F0B3751885ECB941799E250E6546DCA5C20C24845190F239EDC20DDA77353D555DE61509CA6D3C6DC3195BBC6F1703CB03EAD5E7FCBCF5D196E9AB71522408E11D6337C74F9A31EB22AD084A19132BF72E7076A9743ED070ABA78789791824E050CD27694C2648263D1200811FA1B81A00B8FC09CB7A338795E54F6598D7753395F05C60E6EBA9630912B7AA8CAAB3017565DEF72C7929F4E7736C2B8043FEB448801E2DED704E834294B69F6A109C0968214FDC5C3FF0D1B1555D617E16DF61829231962C59B22A10FE400F8B8CB2A3F19FB4B2E8D087F22687506E7F0D061857D1C1789C7F55B899FF4B322982D64BD0AA751D5BEE320B135C7F5DDCD5E6245B57DD22F44042F2BA6DE942365A59FD0C6B0F20C07B71277C6EE7DD9D225032605AED1D3CF8242EB85C33A0AFC3AB42764088D8F4A80FAF804CD84360B2055181E58A0B5AD4C367ABC667982045AD0FD7E048AF8C326D5DB60233302B107E515B15B0F90E5F348C54192B559B4C0A86CDF0719387EA3FF6B1D60B324A98963C56927E2B8DD5A39AC792AEB85EBDBD8DC34B395C2B4DEF4D853AC21A7660348EA8C96C943DE0BAFF3AA6849179E5EF2BAA1731C81C605BEC3860FC4A6A08CC9F75BDE9533511780FF1E0B01D34C0DC3EB80A7E2F52A7A4B815DDA98EA775DFE0C5B3D419B05934DDA05A9616C0978CC99CC8D7B68227BD846419D765956C3D7AA811CE60AF22DF322FEF0DCE38C4278E0237F1D29EF139E201C8ECB4D36E79910D06C5CA4CAA8C2886B96DE6EDD40D2499E30EB942F22BEBF6ED5C8E37DF9557E74D67DC467BAAFA68F1CE37C8BD9B3A4F9DE71670128125AA16ACA7232239575E1C6819C820AD16832F23647DD53C5740A8552F86901AA4F883EFD5A3EFD7C3BF458C5122712D44BE43306C9B8264").unwrap();
    let (rho, t1) = MlDsa44::pk_decode::<{ MlDsa44::DIM_K }>(&pk).unwrap();
    let pk_rt = MlDsa44::pk_encode::<{ MlDsa44::PUBLIC_KEY_SIZE }>(&rho, &t1.elems);

    assert_eq!(pk, pk_rt);
}
