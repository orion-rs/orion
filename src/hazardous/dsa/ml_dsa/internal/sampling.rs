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

use crate::errors::UnknownCryptoError;
use crate::hazardous::dsa::ml_dsa::internal::MlDsaParameters;
use crate::hazardous::dsa::ml_dsa::internal::fe::{
    DILITHIUM_Q, FieldElement, RInv, RingElement, RingElementNTT, Standard, Vector, VectorNTT,
    conditional_sub_u32,
};
use crate::hazardous::hash::sha3::shake128::Shake128;
use crate::hazardous::hash::sha3::shake256::Shake256;
use crate::hazardous::kem::ml_kem::internal::serialization::bytes_to_bits;
use core::ops::Mul;

/// FIPS-204, Algorithm 14.
pub(crate) fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<FieldElement<Standard>> {
    // Combine clearing of bits and masking
    let z: u32 = ((b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16)) & 0x7F_FFFF;

    if z < DILITHIUM_Q {
        Some(FieldElement::new(z))
    } else {
        None
    }
}

/// FIPS-204, Algorithm 15.
pub(crate) fn coeff_from_half_byte<P: MlDsaParameters>(b: u32) -> Option<FieldElement<Standard>> {
    // TODO: b range (0..15) len debug_assert

    match P::ETA {
        2 => {
            // (205 * b) >> 10 => floor(b/5)
            // b - 5 * floor(b/5) => b mod 5
            let b_mod_5 = b - 5 * ((205 * b) >> 10);
            (b < 15).then_some(FieldElement::new(conditional_sub_u32(
                2 + DILITHIUM_Q - b_mod_5,
            )))
        }
        4 => (b < 9).then_some(FieldElement::new(conditional_sub_u32(4 + DILITHIUM_Q - b))),
        _ => unreachable!("incorrectly defined ML-DSA MlDsaParameters"),
    }
}

/// FIPS-204, Algorithm 29.
pub(crate) fn sample_in_ball<P: MlDsaParameters>(
    seed: &[u8],
) -> Result<RingElement, UnknownCryptoError> {
    // TODO: len check seed debug_assert

    let mut c = RingElement::zero();
    let mut ctx = Shake256::new();
    ctx.absorb(seed)?;
    let mut s = [0u8; 8];
    ctx.squeeze(&mut s)?;
    let mut signs = u64::from_le_bytes(s);

    let mut h = [0u8; 64];
    bytes_to_bits(&s, &mut h);

    for i in (256 - P::TAU)..256 {
        // reuse s allocation for one-byte squeezes, s[0] = j
        ctx.squeeze(&mut s[..1])?;
        while s[0] > i as u8 {
            ctx.squeeze(&mut s[..1])?;
        }
        let j = s[0] as usize;
        c[i] = c[j];
        c[j] = FieldElement::new(1) - FieldElement::new(2 * (signs & 1) as u32);

        signs >>= 1;
    }

    Ok(c)
}

#[derive(Debug)]
pub(crate) struct MatrixNTT<const K: usize, const L: usize> {
    mat: [VectorNTT<L, Standard>; K],
}

impl<const K: usize, const L: usize> Mul<&VectorNTT<L, Standard>> for &MatrixNTT<K, L> {
    type Output = VectorNTT<K, RInv>;

    /// FIPS-204, Algorithm 45 (product operator).
    fn mul(self, rhs: &VectorNTT<L, Standard>) -> Self::Output {
        let mut w_hat = VectorNTT::<K, RInv>::zero();
        for i in 0..K {
            for j in 0..L {
                let mul_ntt = self.mat[i][j] * rhs[j];
                w_hat[i] = w_hat[i] + mul_ntt;
            }
        }

        w_hat
    }
}

impl<const K: usize, const L: usize> MatrixNTT<K, L> {
    /// FIPS-204, Algorithm 32 and Algorithm 31.
    /// Merged to avoid useless re-instantiations of SHAKE128.
    pub(crate) fn expand_a<P: MlDsaParameters>(seed: &[u8]) -> Result<Self, UnknownCryptoError> {
        debug_assert_eq!(K, P::DIM_K);
        debug_assert_eq!(L, P::DIM_L);
        debug_assert_eq!(seed.len(), 32);

        let mut mat_hat = [VectorNTT::<L, Standard>::zero(); K];
        let mut ctx = Shake128::new();
        ctx.absorb(seed)?;

        for r in 0..K {
            for s in 0..L {
                // FIPS-204, Algorithm 31:

                // rho remains fixed for each of these invocations
                let mut g = ctx.clone();
                g.absorb(&[s as u8, r as u8])?; // rho prime

                let mut a_hat = RingElementNTT::zero();
                let mut j = 0;
                let mut buf = [0u8; 3];
                while j < 256 {
                    g.squeeze(&mut buf)?;
                    if let Some(coeff) = coeff_from_three_bytes(buf[0], buf[1], buf[2]) {
                        a_hat[j] = coeff;
                        j += 1;
                    }
                }

                mat_hat[r][s] = a_hat;
            }
        }

        Ok(Self { mat: mat_hat })
    }
}

/// FIPS-204, Algorithm 33 and Algorithm 30.
/// Merged to avoid useless re-instantiations of SHAKE256.
pub(crate) fn expand_s<const K: usize, const L: usize, P: MlDsaParameters>(
    seed: &[u8],
) -> Result<(Vector<L>, Vector<K>), UnknownCryptoError> {
    debug_assert_eq!(K, P::DIM_K);
    debug_assert_eq!(L, P::DIM_L);
    debug_assert_eq!(seed.len(), 64);

    let mut s1 = Vector::<L>::zero();
    let mut s2 = Vector::<K>::zero();

    let mut ctx = Shake256::new();
    ctx.absorb(seed)?;

    let mut z = [0u8; 1];
    for r in 0..L as u16 {
        let mut h = ctx.clone();
        h.absorb(&r.to_le_bytes())?;

        let mut j = 0;
        while j < 256 {
            h.squeeze(&mut z)?;
            if let Some(z0) = coeff_from_half_byte::<P>((z[0] as u32) & 0x0F) {
                s1[r as usize][j] = z0;
                j += 1;
            }

            if j < 256
                && let Some(z1) = coeff_from_half_byte::<P>((z[0] as u32) >> 4)
            {
                s1[r as usize][j] = z1;
                j += 1;
            }
        }
    }

    for r in 0..K as u16 {
        let mut h = ctx.clone();
        h.absorb(&(r + L as u16).to_le_bytes())?;

        let mut j = 0;
        while j < 256 {
            h.squeeze(&mut z)?;
            if let Some(z0) = coeff_from_half_byte::<P>((z[0] as u32) & 0x0F) {
                s2[r as usize][j] = z0;
                j += 1;
            }

            if j < 256
                && let Some(z1) = coeff_from_half_byte::<P>((z[0] as u32) >> 4)
            {
                s2[r as usize][j] = z1;
                j += 1;
            }
        }
    }

    Ok((s1, s2))
}

/// FIPS-204, Algorithm 34.
///
/// `CLEN`: 32 * c, where c = 1 + bitlen (γ1 − 1)
///
/// - MlDsa44::GAMMA_1_BITLEN = 17 => 576
/// - MlDsa65::GAMMA_1_BITLEN = 19 => 640
/// - MlDsa87::GAMMA_1_BITLEN = 19 => 640
pub(crate) fn expand_mask<const CLEN: usize, const K: usize, const L: usize, P: MlDsaParameters>(
    seed: &[u8],
    mu: u32,
) -> Result<Vector<L>, UnknownCryptoError> {
    // TODO: Is there a range of valid numbers for mu? or does it need checked arithmetic?

    debug_assert_eq!(K, P::DIM_K);
    debug_assert_eq!(L, P::DIM_L);
    debug_assert_eq!(seed.len(), 64);

    let mut y = Vector::<L>::zero();
    let mut v = [0u8; CLEN];

    let mut ctx = Shake256::new();
    ctx.absorb(seed)?;

    for r in 0..L as u16 {
        let mut h = ctx.clone();
        h.absorb(&(mu as u16 + r).to_le_bytes())?;
        h.squeeze(&mut v)?;
        P::bitunpack_ring_element_gamma(&v, &mut y[r as usize]);
    }

    Ok(y)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hazardous::dsa::ml_dsa::internal::{
        MlDsa44, MlDsa65, MlDsa87, MlDsaParameters, fe::DILITHIUM_Q,
        sampling::coeff_from_three_bytes,
    };

    #[test]
    fn test_coeff_from_three_bytes() {
        fn spec(b0: u8, b1: u8, b2: u8) -> Option<u32> {
            let mut b2 = b2;
            if b2 > 127 {
                b2 -= 128;
            }
            let z = 65536 * b2 as u32 + 256 * b1 as u32 + b0 as u32;
            if z < DILITHIUM_Q { Some(z) } else { None }
        }

        // full space for the three bytes is 2.pow(24)
        let mut non_rejected: u64 = 0;
        let mut accepted_z = 0u64;
        for n in 0..(1u32 << 24) {
            let (b0, b1, b2) = (n as u8, (n >> 8) as u8, (n >> 16) as u8);
            if let Some(fe) = coeff_from_three_bytes(b0, b1, b2) {
                assert_eq!(spec(b0, b1, b2).expect("failed"), fe.0);
                non_rejected += 1;
                if b2 < 128 {
                    // b2 bit 7 clearated out
                    accepted_z += 1;
                }
            } else {
                assert!(spec(b0, b1, b2).is_none());
            }
        }

        // if z < DILITHIUM_Q and two byte combinations will hit every z, b2 last bit is cleared.
        assert_eq!(non_rejected, 2 * DILITHIUM_Q as u64);
        assert_eq!(accepted_z, DILITHIUM_Q as u64);
    }

    #[test]
    fn sample_in_ball_has_tau_hammingdistance() {
        let c = sample_in_ball::<MlDsa44>(&[9u8; 64]).unwrap();
        let nonzero = c.coefficients.iter().filter(|&&x| x.0 != 0).count();
        let ones = c
            .coefficients
            .iter()
            .filter(|&&x| x.0 == 1 || x.0 == DILITHIUM_Q - 1)
            .count();

        assert_eq!(nonzero, MlDsa44::TAU);
        assert_eq!(ones, MlDsa44::TAU);

        let c = sample_in_ball::<MlDsa65>(&[9u8; 64]).unwrap();
        let nonzero = c.coefficients.iter().filter(|&&x| x.0 != 0).count();
        let ones = c
            .coefficients
            .iter()
            .filter(|&&x| x.0 == 1 || x.0 == DILITHIUM_Q - 1)
            .count();

        assert_eq!(nonzero, MlDsa65::TAU);
        assert_eq!(ones, MlDsa65::TAU);

        let c = sample_in_ball::<MlDsa87>(&[9u8; 64]).unwrap();
        let nonzero = c.coefficients.iter().filter(|&&x| x.0 != 0).count();
        let ones = c
            .coefficients
            .iter()
            .filter(|&&x| x.0 == 1 || x.0 == DILITHIUM_Q - 1)
            .count();

        assert_eq!(nonzero, MlDsa87::TAU);
        assert_eq!(ones, MlDsa87::TAU);
    }
}
