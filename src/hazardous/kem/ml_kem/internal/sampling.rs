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

use super::fe::*;
use super::re::*;
use super::serialization::bytes_to_bits;

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::sha3::{shake128, shake256};

/// FIPS-203, Algorithm 7.
pub fn sample_ntt(seed: &[u8; 32], ij: &[u8; 2]) -> Result<RingElementNTT, UnknownCryptoError> {
    let mut xof = shake128::Shake128::new();
    xof.absorb(seed)?;
    xof.absorb(ij)?;

    let mut a_hat = RingElementNTT::zero();

    let mut j = 0;
    while j < 256 {
        let mut c = [0u8; 3];
        xof.squeeze(&mut c)?;

        let d1: i16 = (c[0] as i16) + 256 * ((c[1] as i16) & 15);
        debug_assert!(d1 >= 0 || d1 < 2i16.pow(12));

        let d2: i16 = ((c[1] as i16) >> 4u16) + 16i16 * (c[2] as i16);
        debug_assert!(d2 >= 0 || d2 < 2i16.pow(12));

        if d1 < KYBER_Q as i16 {
            a_hat[j] = FieldElement(d1 as i32);
            j += 1;
        }
        if d2 < KYBER_Q as i16 && j < 256 {
            a_hat[j] = FieldElement(d2 as i32);
            j += 1;
        }
    }

    Ok(a_hat)
}

/// FIPS-203, Algorithm 8.
///
/// This is combined iwth PRF_{eta n}.
///
/// See section (4.2) in FIPS 203 on the instiation of B^{65*eta} <=> PRF
pub fn sample_poly_cbd(
    seed: &[u8],
    b: u8,
    prf_out: &mut [u8],
    bits: &mut [u8],
    eta: usize,
) -> Result<RingElement, UnknownCryptoError> {
    debug_assert_eq!(seed.len(), 32);
    debug_assert!(eta == 2 || eta == 3);

    let mut prf = shake256::Shake256::new();
    prf.absorb(seed)?;
    prf.absorb(&[b])?;
    prf.squeeze(prf_out)?;

    bytes_to_bits(prf_out, bits);

    let mut f: RingElement = RingElement::zero();

    for i in 0..256 {
        let mut x: u8 = 0;
        let mut y: u8 = 0;

        for j in 0..eta {
            x += bits[(2 * i * eta) + j];
            y += bits[(2 * i * eta) + eta + j];
        }

        debug_assert!(x <= eta as u8);
        debug_assert!(y <= eta as u8);

        f[i] = FieldElement::new(x as i32) - FieldElement::new(y as i32);

        debug_assert!(
            (0 <= f[i].0 && f[i].0 <= eta as i32)
                || (KYBER_Q - (eta as i32) <= f[i].0 && f[i].0 < KYBER_Q)
        );
    }

    Ok(f)
}
