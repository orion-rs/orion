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

/// Field elements in Z_m where m = q.
pub(crate) mod fe;

/// Ring elements in R_q and T_q (NTT representative).
pub(crate) mod re;

/// Byte/bit serialization routines.
pub(crate) mod serialization;

/// Sampling ring elements from seeds.
pub(crate) mod sampling;

use crate::hazardous::hash::sha3::sha3_256::Sha3_256;
use crate::hazardous::hash::sha3::sha3_512::Sha3_512;
use crate::hazardous::hash::sha3::shake256;
use crate::hazardous::kem::ml_kem::Seed;
use crate::{errors::UnknownCryptoError, hazardous::hash::sha3::sha3_256::SHA3_256_OUTSIZE};
use core::marker::PhantomData;
use fe::*;
use re::*;
use sampling::*;
use serialization::*;

use crate::ZeroizeWrap;
use subtle::{ConditionallySelectable, ConstantTimeEq};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[allow(dead_code)]
/// Degree of polynomials.
pub(crate) const KYBER_POLY_DEG: usize = 256;

/// Size of an encoded polynomial.
pub(crate) const ENCODE_SIZE_POLY: usize = 384;

pub fn mat_mul_vec_transposed<const K: usize>(
    mat: &[[RingElementNTT; K]],
    vec: &[RingElementNTT],
) -> [RingElementNTT; K] {
    let mut ret = [RingElementNTT::zero(); K];

    for (i, r) in ret.iter_mut().enumerate() {
        for j in 0..K {
            let product = mat[j][i] * vec[j];
            *r += product;
        }
    }

    ret
}

/// FIPS-203, Def. 4.5
pub fn g(c: &[&[u8]]) -> ([u8; 32], ZeroizeWrap<[u8; 32]>) {
    let mut state = Sha3_512::new();
    for input in c.iter() {
        state.update(input).unwrap();
    }
    let hash = state.finalize().unwrap();

    let mut rho = [0u8; 32];
    let mut sigma = zeroize_wrap!([0u8; 32]);
    rho.copy_from_slice(&hash.as_ref()[0..32]);
    sigma.copy_from_slice(&hash.as_ref()[32..64]);

    (rho, sigma)
}

/// Internal PKE-related function, for generalizing over the three different PKE parameter-sets.
pub(crate) trait PkeParameters {
    const N: usize = 256;
    const K: usize;
    const ETA_1: usize;
    const ETA_2: usize;
    const D_U: u8;
    const D_V: u8;

    /// Encapsulation key size (bytes).
    const EK_SIZE: usize;
    /// Decapsulation key size (bytes).
    const DK_SIZE: usize;
    /// Ciphertext size (bytes).
    const CIPHERTEXT_SIZE: usize;
    /// Shared Secret size (bytes).
    const SHARED_SECRET_SIZE: usize;

    const ENCODE_SIZE_D_U: usize = Self::N * Self::D_U as usize / 8;
    const ENCODE_SIZE_D_V: usize = Self::N * Self::D_V as usize / 8;

    /// "It is important to note that this checking process does not guarantee
    /// that ek is a properly produced output of ML-KEM.KeyGen.", p.36.
    fn encapsulation_key_check(ek: &[u8]) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(Self::EK_SIZE, (ENCODE_SIZE_POLY * Self::K) + 32);
        // Encapsulation key check, Check 1.
        // This should never actually happen, since the Encapsulation key newtype has already
        // had a check on length.
        if ek.len() != Self::EK_SIZE {
            return Err(UnknownCryptoError);
        }

        // Encapsulation key check, Check 2.
        let mut modulus_check = [FieldElement::zero(); KYBER_POLY_DEG];
        let mut modulus_check_bytes = [0u8; ENCODE_SIZE_POLY];

        for ek_part in ek.chunks_exact(ENCODE_SIZE_POLY).take(Self::K) {
            // Check each of the encoded polynomials (K total). Since this is a public key,
            // it should be fine to abort early if the first parts fail.
            ByteSerialization::decode_12(ek_part, &mut modulus_check);
            ByteSerialization::encode_12(&modulus_check, &mut modulus_check_bytes);

            if modulus_check_bytes != ek_part {
                return Err(UnknownCryptoError);
            }
        }

        Ok(())
    }

    /// NOTE: the Decapsulation input check, Check 1. is not included in this function on purpose.
    /// The Ciphertext newtype is bound by it's length, so that check is
    /// automatically a part of that newtype.
    fn decapsulation_key_check(dk: &[u8]) -> Result<(), UnknownCryptoError> {
        // Decapsulation input check, Check 2.
        // This should never actually happen, since the Decapsulation key newtype has already
        // had a check on length.
        if dk.len() != Self::DK_SIZE {
            return Err(UnknownCryptoError);
        }

        // Decapsulation input check, Check 3.
        let hash_check = Sha3_256::digest(&dk[ENCODE_SIZE_POLY * Self::K..(768 * Self::K) + 32])?;
        if bool::from(
            hash_check
                .as_ref()
                .ct_ne(&dk[(768 * Self::K) + 32..(768 * Self::K) + 64]),
        ) {
            return Err(UnknownCryptoError);
        }

        Ok(())
    }

    fn sample_poly_cbd_eta1(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError>;

    fn sample_poly_cbd_eta2(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError>;

    fn encode_dv(coefficients: &[FieldElement], out: &mut [u8]);

    fn encode_du(coefficients: &[FieldElement], out: &mut [u8]);

    fn decode_dv(inbytes: &[u8], out: &mut [FieldElement]);

    fn decode_du(inbytes: &[u8], out: &mut [FieldElement]);
}

#[derive(Debug, PartialEq, Clone)]
/// ML-KEM-512.
pub struct MlKem512Internal;

impl PkeParameters for MlKem512Internal {
    const K: usize = 2;
    const ETA_1: usize = 3;
    const ETA_2: usize = 2;
    const D_U: u8 = 10;
    const D_V: u8 = 4;

    const EK_SIZE: usize = 800;
    const DK_SIZE: usize = 1632;
    const CIPHERTEXT_SIZE: usize = 768;
    const SHARED_SECRET_SIZE: usize = 32;

    fn sample_poly_cbd_eta1(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError> {
        let mut prf_out = zeroize_wrap!([0u8; 64 * Self::ETA_1]);
        let mut bits = zeroize_wrap!([0u8; (64 * Self::ETA_1) * 8]);
        sample_poly_cbd(seed, b, prf_out.as_mut(), bits.as_mut(), Self::ETA_1)
    }

    fn sample_poly_cbd_eta2(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError> {
        let mut prf_out = zeroize_wrap!([0u8; 64 * Self::ETA_2]);
        let mut bits = zeroize_wrap!([0u8; (64 * Self::ETA_2) * 8]);
        sample_poly_cbd(seed, b, prf_out.as_mut(), bits.as_mut(), Self::ETA_2)
    }

    fn encode_dv(coefficients: &[FieldElement], out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ENCODE_SIZE_D_V);
        ByteSerialization::encode_4(coefficients, out);
    }

    fn encode_du(coefficients: &[FieldElement], out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ENCODE_SIZE_D_U);
        ByteSerialization::encode_10(coefficients, out);
    }

    fn decode_dv(inbytes: &[u8], out: &mut [FieldElement]) {
        debug_assert_eq!(inbytes.len(), Self::ENCODE_SIZE_D_V);
        ByteSerialization::decode_4(inbytes, out);
    }

    fn decode_du(inbytes: &[u8], out: &mut [FieldElement]) {
        debug_assert_eq!(inbytes.len(), Self::ENCODE_SIZE_D_U);
        ByteSerialization::decode_10(inbytes, out);
    }
}

#[derive(Debug, PartialEq, Clone)]
/// ML-KEM-768.
pub struct MlKem768Internal;

impl PkeParameters for MlKem768Internal {
    const K: usize = 3;
    const ETA_1: usize = 2;
    const ETA_2: usize = 2;
    const D_U: u8 = 10;
    const D_V: u8 = 4;

    const EK_SIZE: usize = 1184;
    const DK_SIZE: usize = 2400;
    const CIPHERTEXT_SIZE: usize = 1088;
    const SHARED_SECRET_SIZE: usize = 32;

    fn sample_poly_cbd_eta1(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError> {
        let mut prf_out = zeroize_wrap!([0u8; 64 * Self::ETA_1]);
        let mut bits = zeroize_wrap!([0u8; (64 * Self::ETA_1) * 8]);
        sample_poly_cbd(seed, b, prf_out.as_mut(), bits.as_mut(), Self::ETA_1)
    }

    fn sample_poly_cbd_eta2(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError> {
        let mut prf_out = zeroize_wrap!([0u8; 64 * Self::ETA_2]);
        let mut bits = zeroize_wrap!([0u8; (64 * Self::ETA_2) * 8]);
        sample_poly_cbd(seed, b, prf_out.as_mut(), bits.as_mut(), Self::ETA_2)
    }

    fn encode_dv(coefficients: &[FieldElement], out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ENCODE_SIZE_D_V);
        ByteSerialization::encode_4(coefficients, out);
    }

    fn encode_du(coefficients: &[FieldElement], out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ENCODE_SIZE_D_U);
        ByteSerialization::encode_10(coefficients, out);
    }

    fn decode_dv(inbytes: &[u8], out: &mut [FieldElement]) {
        debug_assert_eq!(inbytes.len(), Self::ENCODE_SIZE_D_V);
        ByteSerialization::decode_4(inbytes, out);
    }

    fn decode_du(inbytes: &[u8], out: &mut [FieldElement]) {
        debug_assert_eq!(inbytes.len(), Self::ENCODE_SIZE_D_U);
        ByteSerialization::decode_10(inbytes, out);
    }
}

#[derive(Debug, PartialEq, Clone)]
/// ML-KEM-1024.
pub struct MlKem1024Internal;

impl PkeParameters for MlKem1024Internal {
    const K: usize = 4;
    const ETA_1: usize = 2;
    const ETA_2: usize = 2;
    const D_U: u8 = 11;
    const D_V: u8 = 5;

    const EK_SIZE: usize = 1568;
    const DK_SIZE: usize = 3168;
    const CIPHERTEXT_SIZE: usize = 1568;
    const SHARED_SECRET_SIZE: usize = 32;

    fn sample_poly_cbd_eta1(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError> {
        let mut prf_out = zeroize_wrap!([0u8; 64 * Self::ETA_1]);
        let mut bits = zeroize_wrap!([0u8; (64 * Self::ETA_1) * 8]);
        sample_poly_cbd(seed, b, prf_out.as_mut(), bits.as_mut(), Self::ETA_1)
    }

    fn sample_poly_cbd_eta2(seed: &[u8], b: u8) -> Result<RingElement, UnknownCryptoError> {
        let mut prf_out = zeroize_wrap!([0u8; 64 * Self::ETA_2]);
        let mut bits = zeroize_wrap!([0u8; (64 * Self::ETA_2) * 8]);
        sample_poly_cbd(seed, b, prf_out.as_mut(), bits.as_mut(), Self::ETA_2)
    }

    fn encode_dv(coefficients: &[FieldElement], out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ENCODE_SIZE_D_V);
        ByteSerialization::encode_5(coefficients, out);
    }

    fn encode_du(coefficients: &[FieldElement], out: &mut [u8]) {
        debug_assert_eq!(out.len(), Self::ENCODE_SIZE_D_U);
        ByteSerialization::encode_11(coefficients, out);
    }

    fn decode_dv(inbytes: &[u8], out: &mut [FieldElement]) {
        debug_assert_eq!(inbytes.len(), Self::ENCODE_SIZE_D_V);
        ByteSerialization::decode_5(inbytes, out);
    }

    fn decode_du(inbytes: &[u8], out: &mut [FieldElement]) {
        debug_assert_eq!(inbytes.len(), Self::ENCODE_SIZE_D_U);
        ByteSerialization::decode_11(inbytes, out);
    }
}

#[derive(Debug, PartialEq, Clone)]
/// ML-KEM encapsulation key.
pub(crate) struct EncapKey<const K: usize, const ENCODED_SIZE: usize, Pke: PkeParameters> {
    pub(crate) bytes: [u8; ENCODED_SIZE],
    h_ek: [u8; SHA3_256_OUTSIZE],
    t_hat: [RingElementNTT; K],
    mat_a: [[RingElementNTT; K]; K],
    _phantom: PhantomData<Pke>,
}

impl<const K: usize, const ENCODED_SIZE: usize, Pke: PkeParameters> AsRef<[u8]>
    for EncapKey<K, ENCODED_SIZE, Pke>
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<const K: usize, const ENCODED_SIZE: usize, Pke: PkeParameters> PartialEq<&[u8]>
    for EncapKey<K, ENCODED_SIZE, Pke>
{
    fn eq(&self, other: &&[u8]) -> bool {
        self.bytes == *other
    }
}

impl<const K: usize, const ENCODED_SIZE: usize, Pke: PkeParameters> EncapKey<K, ENCODED_SIZE, Pke> {
    pub(crate) fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Pke::encapsulation_key_check(slice)?;

        let mut t_hat = [RingElementNTT::zero(); K];

        // Step 3:
        let mut rho = [0u8; 32];
        let ek_len = slice.len() - 32;
        rho.copy_from_slice(&slice[ek_len..]);

        // Step 2:
        for (poly_decoded, ek_part) in t_hat
            .iter_mut()
            .zip(slice[..ek_len].chunks_exact(ENCODE_SIZE_POLY))
        {
            ByteSerialization::decode_12(ek_part, &mut poly_decoded.coefficients);
        }

        // Steps 4..8
        let mut mat_a = [[RingElementNTT::zero(); K]; K];
        for (i, row) in mat_a.iter_mut().enumerate() {
            for (j, re) in row.iter_mut().enumerate() {
                *re = sample_ntt(&rho, &[j as u8, i as u8])?;
            }
        }

        // Cache hash of the bytes so we don't need to re-compute for every encap().
        let h_ek = Sha3_256::digest(slice)?;

        Ok(Self {
            bytes: slice.try_into().unwrap(), // NOTE: Should never panic if encapsulation_key_check() succeeds.
            h_ek: h_ek.value,
            t_hat,
            mat_a,
            _phantom: PhantomData,
        })
    }

    /// FIPS-203, Algorithm 14.
    ///
    /// k \in [2, 3, 4]
    fn encrypt(&self, m: &[u8], r: &[u8], c: &mut [u8]) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(m.len(), 32);
        debug_assert_eq!(r.len(), 32);
        debug_assert_eq!(Pke::K, K);
        debug_assert_eq!(self.bytes.len(), Pke::EK_SIZE);
        debug_assert_eq!(c.len(), Pke::CIPHERTEXT_SIZE);

        let mut n = 0;

        // Steps 9..12
        let mut y = [RingElement::zero(); K];
        for y_re in y.iter_mut().take(Pke::K) {
            *y_re = Pke::sample_poly_cbd_eta1(r, n)?;
            n += 1;
        }

        // Steps 13..16
        let mut e1 = [RingElement::zero(); K];
        for e1_re in e1.iter_mut().take(Pke::K) {
            *e1_re = Pke::sample_poly_cbd_eta2(r, n)?;
            n += 1;
        }

        // Step 17
        #[cfg(feature = "zeroize")]
        let mut e2: RingElement = Pke::sample_poly_cbd_eta2(r, n)?;
        #[cfg(not(feature = "zeroize"))]
        let e2: RingElement = Pke::sample_poly_cbd_eta2(r, n)?;

        // Step 18
        let mut y_hat = [RingElementNTT::zero(); K];
        for i in 0..Pke::K {
            y_hat[i] = to_ntt(&y[i]);
        }
        #[cfg(feature = "zeroize")]
        y.zeroize();

        // Step 19:
        let mut u = [RingElement::zero(); K];

        #[cfg(feature = "zeroize")]
        let mut tmp = mat_mul_vec_transposed::<K>(&self.mat_a, &y_hat);
        #[cfg(not(feature = "zeroize"))]
        let tmp = mat_mul_vec_transposed::<K>(&self.mat_a, &y_hat);

        for (u_poly, tmp_poly) in u.iter_mut().zip(tmp.iter()) {
            *u_poly = inverse_ntt(tmp_poly);
        }
        #[cfg(feature = "zeroize")]
        tmp.zeroize();

        for (uelem, e1elem) in u.iter_mut().zip(e1.iter()) {
            *uelem = *uelem + *e1elem;
        }

        #[cfg(feature = "zeroize")]
        e1.zeroize();

        // Step 20:
        let mut mu = RingElement::zero();
        ByteSerialization::decode_1(m, &mut mu.coefficients);
        for re in mu.coefficients.iter_mut() {
            *re = FieldElement::decompress(re.0, 1);
        }

        // Step 21:
        let mut product = RingElementNTT::zero();
        for (th, yh) in self.t_hat.iter().zip(y_hat.iter()) {
            product += *th * *yh;
        }
        let mut v = inverse_ntt(&product);
        v = v + e2;
        v = v + mu;

        #[cfg(feature = "zeroize")]
        {
            y_hat.zeroize();
            e2.zeroize();
            mu.zeroize();
            product.zeroize();
        }

        // Step 22:
        for re in u.iter_mut() {
            for fe in re.coefficients.iter_mut() {
                *fe = FieldElement::new(fe.compress(Pke::D_U));
            }
        }

        debug_assert_eq!(
            Pke::ENCODE_SIZE_D_U * Pke::K + Pke::ENCODE_SIZE_D_V,
            Pke::CIPHERTEXT_SIZE
        );

        for (c1_part, u_poly) in c
            .chunks_mut(Pke::ENCODE_SIZE_D_U)
            .take(Pke::K)
            .zip(u.iter())
        {
            Pke::encode_du(&u_poly.coefficients, c1_part);
        }

        #[cfg(feature = "zeroize")]
        u.zeroize();

        // Step 23:
        for fe in v.coefficients.iter_mut() {
            *fe = FieldElement::new(fe.compress(Pke::D_V));
        }
        Pke::encode_dv(
            &v.coefficients,
            &mut c[Pke::CIPHERTEXT_SIZE - Pke::ENCODE_SIZE_D_V..Pke::CIPHERTEXT_SIZE],
        );

        #[cfg(feature = "zeroize")]
        v.zeroize();

        Ok(())
    }

    /// FIPS-203, Algorithm 17.
    /// - encapsulation key ek ∈ B^{384k+32}.
    /// - randomness m ∈ B^{32}.
    /// - decapsulation key dk ∈ B^{768k+96}.
    pub(crate) fn mlkem_encap_internal(
        &self,
        m: &[u8],
        c: &mut [u8],
    ) -> Result<[u8; 32], UnknownCryptoError> {
        if m.len() != 32 {
            return Err(UnknownCryptoError);
        }

        // Step 1: (K, r) ← G(m‖H(ek))
        let (k, r) = g(&[m, self.h_ek.as_ref()]);

        // Step 2: c ← K-PKE.Encrypt(ek, m, r)
        self.encrypt(m, r.as_ref(), c)?;

        // Step 3. return (K, c)
        Ok(k)
    }
}

pub(crate) struct DecapKey<
    const K: usize,
    const ENCODED_SIZE_EK: usize,
    const ENCODED_SIZE_DK: usize,
    Pke: PkeParameters,
> {
    pub(crate) bytes: [u8; ENCODED_SIZE_DK],
    s_hat: [RingElementNTT; K],
    _phantom: PhantomData<Pke>,
}

#[cfg(feature = "zeroize")]
impl<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
        Pke: PkeParameters,
    > Drop for DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>
{
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.iter_mut().zeroize();
        self.s_hat.iter_mut().zeroize();
    }
}

impl<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
        Pke: PkeParameters,
    > PartialEq<DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>>
    for DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>
{
    fn eq(&self, other: &DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>) -> bool {
        use subtle::ConstantTimeEq;

        (self
            .unprotected_as_bytes()
            .ct_eq(other.unprotected_as_bytes()))
        .into()
    }
}

impl<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
        Pke: PkeParameters,
    > Eq for DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>
{
}

impl<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
        Pke: PkeParameters,
    > PartialEq<&[u8]> for DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>
{
    fn eq(&self, other: &&[u8]) -> bool {
        use subtle::ConstantTimeEq;

        (self.unprotected_as_bytes().ct_eq(*other)).into()
    }
}

impl<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
        Pke: PkeParameters,
    > core::fmt::Debug for DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {{***OMITTED***}}", stringify!($name))
    }
}

impl<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
        Pke: PkeParameters,
    > DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>
{
    pub(crate) fn get_encapsulation_key_bytes(&self) -> &[u8] {
        &self.bytes[ENCODE_SIZE_POLY * K..(768 * K) + 32]
    }

    pub(crate) fn unchecked_from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Pke::decapsulation_key_check(slice)?;

        let dk_pke = &slice[0..ENCODE_SIZE_POLY * Pke::K];
        let mut s_hat = [RingElementNTT::zero(); K];
        for (dk_part, s_hat_poly) in dk_pke
            .chunks(ENCODE_SIZE_POLY)
            .take(Pke::K)
            .zip(s_hat.iter_mut())
        {
            ByteSerialization::decode_12(dk_part, &mut s_hat_poly.coefficients);
        }

        Ok(Self {
            bytes: slice.try_into().unwrap(), // NOTE: Should never panic if decapsulation_key_check() succeeds.
            s_hat,
            _phantom: PhantomData,
        })
    }

    /// FIPS-203, Algorithm 15.
    ///
    /// k \in [2, 3, 4]
    fn decrypt(&self, c: &[u8]) -> Result<[u8; 32], UnknownCryptoError> {
        debug_assert_eq!(Pke::K, K);
        debug_assert_eq!(c.len(), Pke::CIPHERTEXT_SIZE);

        // Step 1:
        let c1 = &c[..Pke::ENCODE_SIZE_D_U * Pke::K];
        // Step 2:
        let c2 = &c[Pke::ENCODE_SIZE_D_U * Pke::K..Pke::CIPHERTEXT_SIZE];

        // Step 3:
        let mut u = [RingElement::zero(); K];
        for (c1_part, u_poly) in c1
            .chunks(Pke::ENCODE_SIZE_D_U)
            .take(Pke::K)
            .zip(u.iter_mut())
        {
            Pke::decode_du(c1_part, &mut u_poly.coefficients);
            for fe in u_poly.coefficients.iter_mut() {
                *fe = FieldElement::decompress(fe.0, Pke::D_U);
            }
        }

        // Step 4:
        let mut v = RingElement::zero();
        Pke::decode_dv(c2, &mut v.coefficients);
        for fe in v.coefficients.iter_mut() {
            *fe = FieldElement::decompress(fe.0, Pke::D_V);
        }

        // Step 6:
        let mut product = RingElementNTT::zero();
        for (sh, ue) in self.s_hat.iter().zip(u.iter()) {
            product += *sh * to_ntt(ue);
        }

        let mut w = v - inverse_ntt(&product);
        zeroize_call!(product);
        let mut m = [0u8; 32];
        for fe in w.coefficients.iter_mut() {
            *fe = FieldElement::new(fe.compress(1));
        }
        ByteSerialization::encode_1(&w.coefficients, &mut m);

        Ok(m)
    }

    /// FIPS-203, Algorithm 18.
    /// - decapsulation key dk ∈ B^{768k+96}.
    /// - ciphertext c ∈ B^{32*(d_u*k+d_v)}.
    /// - shared secret K ∈ B^{32}.
    pub(crate) fn mlkem_decap_internal_with_ek(
        &self,
        c: &[u8],
        c_prime: &mut [u8],
        ek: &EncapKey<K, ENCODED_SIZE_EK, Pke>,
    ) -> Result<[u8; 32], UnknownCryptoError> {
        debug_assert_eq!(self.get_encapsulation_key_bytes(), ek.as_ref());
        debug_assert_eq!(c.len(), Pke::CIPHERTEXT_SIZE);

        // Step 1:
        let dk_pke = &self.bytes[0..ENCODE_SIZE_POLY * Pke::K];
        // Step 2:
        let ek_pke = &self.bytes[dk_pke.len()..(768 * Pke::K) + 32];
        // Step 3:
        let h = &self.bytes[dk_pke.len() + ek_pke.len()..(768 * Pke::K) + 64];
        // Step 4:
        let z = &self.bytes[dk_pke.len() + ek_pke.len() + h.len()..(768 * Pke::K) + 96];

        // Step 5:
        let m = self.decrypt(c)?;

        // Step 6:
        let (mut k, r) = g(&[&m, h]);

        // Step 7:
        let mut k_bar = zeroize_wrap!([0u8; 32]);
        let mut xof = shake256::Shake256::new();
        xof.absorb(z)?;
        xof.absorb(c)?;
        xof.squeeze(k_bar.as_mut())?;

        // Step 8:
        debug_assert_eq!(self.get_encapsulation_key_bytes(), ek_pke);
        ek.encrypt(&m, r.as_ref(), c_prime)?;

        // Step 9:
        let ct_choice = c.ct_ne(c_prime);
        zeroize_call!(*c_prime); // Discard c_prime, as we only need it as a buffer.

        for (x, y) in k.iter_mut().zip(k_bar.iter()) {
            u8::conditional_assign(x, y, ct_choice);
        }

        Ok(k)
    }

    #[cfg(feature = "safe_api")] // used in from_keys which requires safe_api
    pub(crate) fn mlkem_decap_internal(
        &self,
        c: &[u8],
        c_prime: &mut [u8],
    ) -> Result<[u8; 32], UnknownCryptoError> {
        // In this case we aren't provided a cached encapsulation key.
        let ek =
            EncapKey::<K, ENCODED_SIZE_EK, Pke>::from_slice(self.get_encapsulation_key_bytes())?;

        self.mlkem_decap_internal_with_ek(c, c_prime, &ek)
    }

    pub(crate) fn unprotected_as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) struct KeyPairInternal<Pke: PkeParameters> {
    _phantom: PhantomData<Pke>,
}

impl<Pke: PkeParameters> KeyPairInternal<Pke> {
    /// FIPS-203, Algorithm 13.
    /// ρ => rho
    /// σ => sigma
    ///
    /// ek,dk => ([u8; 384*k+32], [u8;384*k])
    /// k \in [2, 3, 4]
    fn keygen<const K: usize, const ENCODED_SIZE_EK: usize, const ENCODED_SIZE_DK: usize>(
        d: &[u8],
        ek: &mut EncapKey<K, ENCODED_SIZE_EK, Pke>,
        dk: &mut DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>,
    ) -> Result<(), UnknownCryptoError> {
        let (rho, sigma) = g(&[d, &[Pke::K as u8]]);
        let mut n = 0;

        // Steps 3..7
        for i in 0..Pke::K {
            for j in 0..Pke::K {
                ek.mat_a[i][j] = sample_ntt(&rho, &[j as u8, i as u8])?;
            }
        }

        // Steps 8..11
        let mut s = [RingElement::zero(); K];
        for se in s.iter_mut() {
            *se = Pke::sample_poly_cbd_eta1(sigma.as_ref(), n)?;
            n += 1;
        }

        // Steps 12..15
        let mut e = [RingElement::zero(); K];
        for ee in e.iter_mut() {
            *ee = Pke::sample_poly_cbd_eta1(sigma.as_ref(), n)?;
            n += 1;
        }

        for i in 0..Pke::K {
            dk.s_hat[i] = to_ntt(&s[i]);
            ek.t_hat[i] = to_ntt(&e[i]);
        }

        zeroize_call!(s);

        // t ← A ∘ ŝ + ê
        for i in 0..Pke::K {
            for j in 0..Pke::K {
                ek.t_hat[i] += ek.mat_a[i][j] * dk.s_hat[j];
            }
        }

        // Step 19
        for (re, ek_part) in ek
            .t_hat
            .iter()
            .zip(ek.bytes.chunks_exact_mut(ENCODE_SIZE_POLY))
        {
            ByteSerialization::encode_12(&re.coefficients, ek_part);
        }

        let idx = ENCODED_SIZE_EK - rho.len();
        ek.bytes[idx..].copy_from_slice(&rho);

        // Cache hash of ek so we don't need to re-compute for every encap().
        let h_ek = Sha3_256::digest(&ek.bytes)?;
        ek.h_ek = h_ek.value;

        // Step 20
        for (re, dk_part) in dk
            .s_hat
            .iter()
            .zip(dk.bytes.chunks_exact_mut(ENCODE_SIZE_POLY))
        {
            ByteSerialization::encode_12(&re.coefficients, dk_part);
        }

        Ok(())
    }

    pub(crate) fn from_seed<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
    >(
        seed: &Seed,
    ) -> Result<
        (
            EncapKey<K, ENCODED_SIZE_EK, Pke>,
            DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>,
        ),
        UnknownCryptoError,
    > {
        let mut encap_key = EncapKey::<K, ENCODED_SIZE_EK, Pke> {
            bytes: [0u8; ENCODED_SIZE_EK],
            h_ek: [0u8; SHA3_256_OUTSIZE],
            t_hat: [RingElementNTT::zero(); K],
            mat_a: [[RingElementNTT::zero(); K]; K],
            _phantom: PhantomData,
        };
        // Cache the ek separately as well for re-use in MLEKM.decap_internal().
        // `ek` is used directly within dk during keygen.
        let mut decap_key = DecapKey::<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke> {
            bytes: [0u8; ENCODED_SIZE_DK],
            s_hat: [RingElementNTT::zero(); K],
            _phantom: PhantomData,
        };

        // Step 1 + 2. (ekPKE, dkPKE) ← K-PKE.KeyGen(d)
        Self::keygen(
            &seed.unprotected_as_bytes()[..32],
            &mut encap_key,
            &mut decap_key,
        )?;

        // Step 3. dk ← (dkPKE‖ek‖H(ek)‖z)
        decap_key.bytes[(ENCODE_SIZE_POLY * K)..(ENCODE_SIZE_POLY * K) + Pke::EK_SIZE]
            .copy_from_slice(&encap_key.bytes);
        decap_key.bytes
            [(ENCODE_SIZE_POLY * K) + Pke::EK_SIZE..(ENCODE_SIZE_POLY * K) + Pke::EK_SIZE + 32]
            .copy_from_slice(Sha3_256::digest(&encap_key.bytes).unwrap().as_ref());
        decap_key.bytes[(ENCODE_SIZE_POLY * K) + Pke::EK_SIZE + 32
            ..(ENCODE_SIZE_POLY * K) + Pke::EK_SIZE + 32 + 32]
            .copy_from_slice(&seed.unprotected_as_bytes()[32..64]);

        debug_assert_eq!(decap_key.get_encapsulation_key_bytes(), encap_key.as_ref());

        Ok((encap_key, decap_key))
    }

    #[cfg(feature = "safe_api")]
    /// Instantiate a `KeyPair` with all key validation checks, described
    /// in FIPS-203, Section 7.1, 7.2 and 7.3.
    pub(crate) fn from_keys<
        const K: usize,
        const ENCODED_SIZE_EK: usize,
        const ENCODED_SIZE_DK: usize,
        const CIPHERTEXT_SIZE: usize,
    >(
        seed: &Seed,
        ek: &EncapKey<K, ENCODED_SIZE_EK, Pke>,
        dk: &DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>,
    ) -> Result<
        (
            EncapKey<K, ENCODED_SIZE_EK, Pke>,
            DecapKey<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK, Pke>,
        ),
        UnknownCryptoError,
    > {
        // "Key pair check", Check 1
        let (ek_regen, dk_regen) = Self::from_seed::<K, ENCODED_SIZE_EK, ENCODED_SIZE_DK>(seed)?;
        if ek_regen.bytes != ek.bytes {
            return Err(UnknownCryptoError);
        }
        if !bool::from(dk_regen.bytes.ct_eq(&dk.bytes)) {
            return Err(UnknownCryptoError);
        }

        // "Key pair check", Check 2
        Pke::encapsulation_key_check(&ek.bytes)?;

        // "Key pair check", Check 3
        Pke::decapsulation_key_check(&dk.bytes)?;

        // "Key pair check", Check 4
        let mut m = [0u8; 32];
        getrandom::fill(&mut m)?;
        let mut c = [0u8; CIPHERTEXT_SIZE];
        let mut c_prime = [0u8; CIPHERTEXT_SIZE];
        let k = ek.mlkem_encap_internal(&m, &mut c)?;
        let k_prime = dk.mlkem_decap_internal(&c, &mut c_prime)?;

        if bool::from(k.ct_eq(&k_prime)) {
            Ok((ek_regen, dk_regen))
        } else {
            // NOTE(brycx): We do not hit this error in current tests and I'm not sure we can.
            // Given that we re-gen both ek+dk based on the seed and check it reproduces,
            // then that should suffice to "pair-wise consistency" this would normally check.
            // This error should only be reachable if would be possible to create KeyPair
            // without providing a seed. The API is designed to prevent this.
            Err(UnknownCryptoError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hazardous::kem::ml_kem::mlkem1024::KeyPair as MlKem1024KeyPair;
    use crate::hazardous::kem::ml_kem::mlkem512::KeyPair as MlKem512KeyPair;
    use crate::hazardous::kem::ml_kem::mlkem768::KeyPair as MlKem768KeyPair;

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_seed_and_dk_mismatch() {
        let seed = Seed::from_slice(&[128u8; 64]).unwrap();
        let bad_seed = Seed::from_slice(&[1u8; 64]).unwrap();

        // ML-KEM-512.
        let kp = MlKem512KeyPair::try_from(&seed).unwrap();
        let kp_bad = MlKem512KeyPair::try_from(&bad_seed).unwrap();
        assert!(
            KeyPairInternal::<MlKem512Internal>::from_keys::<2, 800, 1632, 768>(
                &seed,
                &kp.public().value,
                &kp.private().value,
            )
            .is_ok()
        );
        assert!(
            KeyPairInternal::<MlKem512Internal>::from_keys::<2, 800, 1632, 768>(
                &seed,
                &kp_bad.public().value,
                &kp.private().value,
            )
            .is_err()
        );
        assert!(
            KeyPairInternal::<MlKem512Internal>::from_keys::<2, 800, 1632, 768>(
                &seed,
                &kp.public().value,
                &kp_bad.private().value,
            )
            .is_err()
        );
        assert!(
            KeyPairInternal::<MlKem512Internal>::from_keys::<2, 800, 1632, 768>(
                &seed,
                &kp_bad.public().value,
                &kp_bad.private().value,
            )
            .is_err()
        );

        // ML-KEM-768.
        let kp = MlKem768KeyPair::try_from(&seed).unwrap();
        let kp_bad = MlKem768KeyPair::try_from(&bad_seed).unwrap();
        assert!(
            KeyPairInternal::<MlKem768Internal>::from_keys::<3, 1184, 2400, 1088>(
                &seed,
                &kp.public().value,
                &kp.private().value,
            )
            .is_ok()
        );
        assert!(
            KeyPairInternal::<MlKem768Internal>::from_keys::<3, 1184, 2400, 1088>(
                &seed,
                &kp_bad.public().value,
                &kp.private().value,
            )
            .is_err()
        );
        assert!(
            KeyPairInternal::<MlKem768Internal>::from_keys::<3, 1184, 2400, 1088>(
                &seed,
                &kp.public().value,
                &kp_bad.private().value,
            )
            .is_err()
        );
        assert!(
            KeyPairInternal::<MlKem768Internal>::from_keys::<3, 1184, 2400, 1088>(
                &seed,
                &kp_bad.public().value,
                &kp_bad.private().value,
            )
            .is_err()
        );

        // ML-KEM-1024.
        let kp = MlKem1024KeyPair::try_from(&seed).unwrap();
        let kp_bad = MlKem1024KeyPair::try_from(&bad_seed).unwrap();
        assert!(
            KeyPairInternal::<MlKem1024Internal>::from_keys::<4, 1568, 3168, 1568>(
                &seed,
                &kp.public().value,
                &kp.private().value,
            )
            .is_ok()
        );
        assert!(
            KeyPairInternal::<MlKem1024Internal>::from_keys::<4, 1568, 3168, 1568>(
                &seed,
                &kp_bad.public().value,
                &kp.private().value,
            )
            .is_err()
        );
        assert!(
            KeyPairInternal::<MlKem1024Internal>::from_keys::<4, 1568, 3168, 1568>(
                &seed,
                &kp.public().value,
                &kp_bad.private().value,
            )
            .is_err()
        );
        assert!(
            KeyPairInternal::<MlKem1024Internal>::from_keys::<4, 1568, 3168, 1568>(
                &seed,
                &kp_bad.public().value,
                &kp_bad.private().value,
            )
            .is_err()
        );
    }

    #[test]
    fn test_encap_internal_check_m() {
        let testing_seed = Seed::from_slice(&[128u8; 64]).unwrap();

        let keypair = MlKem512KeyPair::try_from(&testing_seed).unwrap();
        let mut c = [0u8; MlKem512Internal::CIPHERTEXT_SIZE];
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 32], &mut c)
            .is_ok());
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 31], &mut c)
            .is_err());
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 33], &mut c)
            .is_err());

        let keypair = MlKem768KeyPair::try_from(&testing_seed).unwrap();
        let mut c = [0u8; MlKem768Internal::CIPHERTEXT_SIZE];
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 32], &mut c)
            .is_ok());
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 31], &mut c)
            .is_err());
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 33], &mut c)
            .is_err());

        let keypair = MlKem1024KeyPair::try_from(&testing_seed).unwrap();
        let mut c = [0u8; MlKem1024Internal::CIPHERTEXT_SIZE];
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 32], &mut c)
            .is_ok());
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 31], &mut c)
            .is_err());
        assert!(keypair
            .public()
            .value
            .mlkem_encap_internal(&[0u8; 33], &mut c)
            .is_err());
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_omitted_debug() {
        let testing_seed = Seed::from_slice(&[128u8; 64]).unwrap();

        let keypair = MlKem512KeyPair::try_from(&testing_seed).unwrap();
        let secret = format!("{:?}", keypair.private().value.bytes);
        let test_debug_contents = format!("{:?}", keypair.private());
        assert!(!test_debug_contents.contains(&secret));

        let keypair = MlKem768KeyPair::try_from(&testing_seed).unwrap();
        let secret = format!("{:?}", keypair.private().value.bytes);
        let test_debug_contents = format!("{:?}", keypair.private());
        assert!(!test_debug_contents.contains(&secret));

        let keypair = MlKem1024KeyPair::try_from(&testing_seed).unwrap();
        let secret = format!("{:?}", keypair.private().value.bytes);
        let test_debug_contents = format!("{:?}", keypair.private());
        assert!(!test_debug_contents.contains(&secret));
    }

    macro_rules! test_key_check (($pke:ident, $keypair:ident, $test_mod:ident) => (
        mod $test_mod {
            use super::*;

            #[test]
            #[cfg(feature = "safe_api")]
            fn test_ek_input_check() {
                assert!(
                    $pke::encapsulation_key_check(&[0u8; 0])
                        .is_err()
                );
                assert!(
                    $pke::encapsulation_key_check(
                        &[0u8; $pke::EK_SIZE - 1]
                    )
                    .is_err()
                );
                assert!(
                    $pke::encapsulation_key_check(
                        &[0u8; $pke::EK_SIZE + 1]
                    )
                    .is_err()
                );

                let valid_elements = [FieldElement::random(); 256];
                let mut valid_ek = [0u8; $pke::EK_SIZE];
                ByteSerialization::encode_12(
                    &valid_elements,
                    &mut valid_ek[0..ENCODE_SIZE_POLY * $pke::K],
                );
                assert!(
                    $pke::encapsulation_key_check(&valid_ek)
                        .is_ok()
                );

                // Set the values of fields elements to something above q - 1
                let mut illegal_elements = valid_elements;
                illegal_elements[0].0 = KYBER_Q;
                let mut illegal_ek = [0u8; $pke::EK_SIZE];
                ByteSerialization::encode_12(&illegal_elements, &mut illegal_ek[0..ENCODE_SIZE_POLY * $pke::K]);
                assert!(
                    $pke::encapsulation_key_check(&illegal_ek)
                        .is_err()
                );

                // Set the values of fields elements to something above q - 1
                let mut illegal_elements = valid_elements;
                illegal_elements[128].0 = KYBER_Q + 1;
                let mut illegal_ek = [0u8; $pke::EK_SIZE];
                ByteSerialization::encode_12(&illegal_elements, &mut illegal_ek[0..ENCODE_SIZE_POLY * $pke::K]);
                assert!(
                    $pke::encapsulation_key_check(&illegal_ek)
                        .is_err()
                );

                // Set the values of fields elements to something above q - 1
                let mut illegal_elements = valid_elements;
                illegal_elements[217].0 = 2u32.pow(12) - 1;
                let mut illegal_ek = [0u8; $pke::EK_SIZE];
                ByteSerialization::encode_12(&illegal_elements, &mut illegal_ek[0..ENCODE_SIZE_POLY * $pke::K]);
                assert!(
                    $pke::encapsulation_key_check(&illegal_ek)
                        .is_err()
                );

                // Set the values of fields elements to something above q - 1
                let mut illegal_elements = valid_elements;
                illegal_elements[3].0 = 2u32.pow(16) - 1;
                let mut illegal_ek = [0u8; $pke::EK_SIZE];
                ByteSerialization::encode_12(&illegal_elements, &mut illegal_ek[0..ENCODE_SIZE_POLY * $pke::K]);
                assert!(
                    $pke::encapsulation_key_check(&illegal_ek)
                        .is_err()
                );
                // Reset bad element to ensure that it's now a valid representation.
                illegal_elements[3] = FieldElement::random();


                // All invalid field elements have been reset
                ByteSerialization::encode_12(&illegal_elements, &mut illegal_ek[0..ENCODE_SIZE_POLY * $pke::K]);
                assert!(
                    $pke::encapsulation_key_check(&illegal_ek)
                        .is_ok()
                );
            }

            #[test]
            fn test_dk_input_check() {
                assert!(
                    $pke::decapsulation_key_check(&[0u8; 0])
                        .is_err()
                );
                assert!(
                    $pke::decapsulation_key_check(
                        &[0u8; $pke::DK_SIZE - 1]
                    )
                    .is_err()
                );
                assert!(
                    $pke::decapsulation_key_check(
                        &[0u8; $pke::DK_SIZE + 1]
                    )
                    .is_err()
                );

                let testing_seed = Seed::from_slice(&[128u8; 64]).unwrap();
                let keypair = $keypair::try_from(&testing_seed).unwrap();
                assert!($pke::encapsulation_key_check(&keypair.public().value.as_ref()).is_ok());
                assert!($pke::decapsulation_key_check(&keypair.private().value.unprotected_as_bytes()).is_ok());
                let mut dk = keypair.private().value.unprotected_as_bytes().to_vec();

                // Modify the hash part
                let correct = dk[(768 * $pke::K) + 32];
                dk[(768 * $pke::K) + 32] ^= 1;
                assert!($pke::decapsulation_key_check(&dk).is_err());

                dk[(768 * $pke::K) + 32] = correct;
                assert!($pke::decapsulation_key_check(&dk).is_ok());

                dk[(768 * $pke::K) + 32..(768 * $pke::K) + 64].copy_from_slice(Sha3_256::digest(&[255u8; 16]).unwrap().as_ref());
                assert!($pke::decapsulation_key_check(&dk).is_err());
            }
        }
    ));

    test_key_check!(MlKem512Internal, MlKem512KeyPair, mlkem512);
    test_key_check!(MlKem768Internal, MlKem768KeyPair, mlkem768);
    test_key_check!(MlKem1024Internal, MlKem1024KeyPair, mlkem1024);
}
