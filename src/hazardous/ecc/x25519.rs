// MIT License

// Copyright (c) 2021 The orion Developers

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

use super::fiat_curve25519_u64;
use crate::errors::UnknownCryptoError;
use crate::util::secure_cmp;
use core::convert::{TryFrom, TryInto};
use core::ops::{Add, Mul, Neg, Sub};

/// The size of a public key used in X25519.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// The size of a secret key used in X25519.
pub const SECRET_KEY_SIZE: usize = 32;

/// The size of a shared key used in X25519.
pub const SHARED_KEY_SIZE: usize = 32;

/// TODO: Should probably also be zeroized.
#[derive(Clone, Copy, Debug)]
///
pub struct FieldElement([u64; 5]);

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.as_bytes().ct_eq(&other.as_bytes()).into()
    }
}

// TODO: Seems we don't really use Neg anywhere. Should be used in constant-time swap, but fiat already provides this.
impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // The function fiat_25519_opp negates a field element.
        use fiat_curve25519_u64::{fiat_25519_carry, fiat_25519_opp};

        let mut ret = [0u64; 5];
        fiat_25519_opp(&mut ret, &self.0);
        let tmp = ret;
        fiat_25519_carry(&mut ret, &tmp);

        Self(ret)
    }
}

// The function fiat_25519_carry_mul multiplies two field elements and reduces the result.
impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        use fiat_curve25519_u64::fiat_25519_carry_mul;

        let mut ret = [0u64; 5];
        fiat_25519_carry_mul(&mut ret, &self.0, &rhs.0);

        Self(ret)
    }
}

// The function fiat_25519_add adds two field elements.
impl Add for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        use fiat_curve25519_u64::{fiat_25519_add, fiat_25519_carry};

        let mut ret = [0u64; 5];
        fiat_25519_add(&mut ret, &self.0, &rhs.0);
        let tmp = ret;
        fiat_25519_carry(&mut ret, &tmp);

        Self(ret)
    }
}

// The function fiat_25519_sub subtracts two field elements.
impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        use fiat_curve25519_u64::{fiat_25519_carry, fiat_25519_sub};

        let mut ret = [0u64; 5];
        fiat_25519_sub(&mut ret, &self.0, &rhs.0);
        let tmp = ret;
        fiat_25519_carry(&mut ret, &tmp);

        Self(ret)
    }
}

impl FieldElement {
    ///
    pub fn zero() -> Self {
        Self([0u64, 0u64, 0u64, 0u64, 0u64])
    }

    ///
    pub fn one() -> Self {
        Self([1u64, 0u64, 0u64, 0u64, 0u64])
    }

    /// Serialize the field element as a byte-array.
    pub fn as_bytes(&self) -> [u8; 32] {
        // The function fiat_25519_to_bytes serializes a field element to bytes in little-endian order.
        use fiat_curve25519_u64::fiat_25519_to_bytes;

        let mut ret = [0u8; 32];
        fiat_25519_to_bytes(&mut ret, &self.0);

        // TODO: Should we mask MSB of last byte here as well? (like in `from_bytes()`)
        // Does not seem like it. Only when taking bytes as input. After performing scalarmult this
        // should not apply.

        ret
    }

    /// Deserialize the field element from a byte-array in little-endian.
    ///
    /// Masks the MSB in the final byte of the input bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // The function fiat_25519_from_bytes deserializes a field element from bytes in little-endian order
        use fiat_curve25519_u64::fiat_25519_from_bytes;

        let mut temp = [0u8; 32];
        temp.copy_from_slice(bytes);
        temp[31] &= 127u8; // See RFC: "When receiving such an array, implementations of X25519
                           // (but not X448) MUST mask the most significant bit in the final byte."

        let mut ret = [0u64; 5];
        fiat_25519_from_bytes(&mut ret, &temp);

        Self(ret)
    }

    /// A conditional-swap operation.
    pub fn conditional_swap(swap: u8, a: &mut Self, b: &mut Self) {
        // The function fiat_25519_selectznz is a multi-limb conditional select.
        use fiat_curve25519_u64::fiat_25519_selectznz;

        // SAFETY: This is a part of fiat input bounds.
        debug_assert!(swap == 1 || swap == 0);

        let tmp_a = *a;
        let tmp_b = *b;

        fiat_25519_selectznz(&mut a.0, swap, &tmp_a.0, &tmp_b.0);
        fiat_25519_selectznz(&mut b.0, swap, &tmp_b.0, &tmp_a.0);
    }

    /// Square the field element and reduce the result.
    pub fn square(&self) -> Self {
        use fiat_curve25519_u64::fiat_25519_carry_square;

        let mut ret = [0u64; 5];
        fiat_25519_carry_square(&mut ret, &self.0);

        Self(ret)
    }

    /// Multiply the field element by 121666 and reduce the result.
    pub fn mul_121666(&self) -> Self {
        use fiat_curve25519_u64::fiat_25519_carry_scmul_121666;

        let mut ret = [0u64; 5];
        fiat_25519_carry_scmul_121666(&mut ret, &self.0);

        Self(ret)
    }

    /// Compute the multiplicative inverse of the field element.
    pub fn invert(&mut self) {
        // TODO: Can we find a cleaner approach?
        // Ref: https://github.com/golang/crypto/blob/0c34fe9e7dc2486962ef9867e3edb3503537209f/curve25519/curve25519_generic.go#L718
        let mut t0: FieldElement;
        let mut t1: FieldElement;
        let mut t2: FieldElement;
        let mut t3: FieldElement;

        t0 = self.square();
        t1 = t0.square();
        t1 = t1.square();

        t1 = *self * t1;
        t0 = t0 * t1;
        t2 = t0.square();

        t1 = t1 * t2;
        t2 = t1.square();
        for _ in 1..5 {
            t2 = t2.square();
        }
        t1 = t2 * t1;
        t2 = t1.square();
        for _ in 1..10 {
            t2 = t2.square();
        }
        t2 = t2 * t1;
        t3 = t2.square();
        for _ in 1..20 {
            t3 = t3.square();
        }
        t2 = t3 * t2;
        t2 = t2.square();
        for _ in 1..10 {
            t2 = t2.square();
        }
        t1 = t2 * t1;
        t2 = t1.square();
        for _ in 1..50 {
            t2 = t2.square();
        }
        // TODO: Implement MulAssign for operations such as these?
        t2 = t2 * t1;
        t3 = t2.square();
        for _ in 1..100 {
            t3 = t3.square();
        }
        t2 = t3 * t2;
        t2 = t2.square();
        for _ in 1..50 {
            t2 = t2.square();
        }
        t1 = t2 * t1;
        t1 = t1.square();
        for _ in 1..5 {
            t1 = t1.square();
        }

        *self = t1 * t0;
    }
}

// TODO: Figure out if this is the right type.
// TODO: If it's part of the public, then it should be a mid-level type, and users interact with
// TODO: a `Secret` made form the newtype macros instead, not this one.
#[derive(Clone)]
///
struct Scalar([u8; 32]);

impl Drop for Scalar {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.iter_mut().zeroize();
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Scalar {
    /// Clamp this scalar.
    ///
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-5
    pub fn clamp(&self) -> Self {
        let mut ret = self.0;

        ret[0] &= 248;
        ret[31] &= 127;
        ret[31] |= 64;

        Self(ret)
    }

    /// Create a scalar from some byte-array.
    ///
    /// The scalar is not clamped.
    pub fn from_slice(slice: &[u8]) -> Scalar {
        // TODO: Should be encoded into newtype - returning an error.
        assert_eq!(slice.len(), 32);
        // TODO: Handle this panic
        Self(slice.try_into().expect("SHOULD NOT PANIC"))
    }
}

/// Scalar multiplication using the Montgomery Ladder (a.k.a "scalarmult")
///
/// Refs:
/// - https://eprint.iacr.org/2020/956.pdf
/// - https://eprint.iacr.org/2017/212.pdf
/// - https://github.com/golang/crypto/blob/0c34fe9e7dc2486962ef9867e3edb3503537209f/curve25519/curve25519_generic.go#L779
fn mont_ladder(scalar: &Scalar, point: &[u8; 32]) -> FieldElement {
    let clamped = scalar.clamp();
    let x1 = FieldElement::from_bytes(point);
    let mut x2 = FieldElement::one();
    let mut x3 = x1;
    let mut z3 = FieldElement::one();
    let mut z2 = FieldElement::zero();
    let mut tmp0: FieldElement;
    let mut tmp1: FieldElement;

    let mut swap: u8 = 0;

    for idx in (0..=254).rev() {
        let bit = (clamped.0[idx >> 3] >> (idx & 7)) & 1;
        swap ^= bit;
        FieldElement::conditional_swap(swap, &mut x2, &mut x3);
        FieldElement::conditional_swap(swap, &mut z2, &mut z3);
        swap = bit;

        tmp0 = x3 - z3;
        tmp1 = x2 - z2;
        x2 = x2 + z2;
        z2 = x3 + z3;
        z3 = tmp0 * x2;
        z2 = z2 * tmp1;
        tmp0 = tmp1.square();
        tmp1 = x2.square();
        x3 = z3 + z2;
        z2 = z3 - z2;
        x2 = tmp1 * tmp0;
        tmp1 = tmp1 - tmp0;
        z2 = z2.square();
        z3 = tmp1.mul_121666();
        x3 = x3.square();
        tmp0 = tmp0 + z3;
        z3 = x1 * z2;
        z2 = tmp1 * tmp0;
    }

    FieldElement::conditional_swap(swap, &mut x2, &mut x3);
    FieldElement::conditional_swap(swap, &mut z2, &mut z3);

    z2.invert();
    x2 = x2 * z2;

    x2
}

construct_public! {
    /// A type that represents a `PublicKey` that X25519 uses.
    ///
    /// This type is used internally as a u-coordinate, but hold only raw bytes,
    /// and does not perform any checks (except for lengths) whatsoever.
    /// Non-canonical values are accepted, as dictated in the RFC ([`https://www.ietf.org/rfc/rfc7748.html#section-5`]):
    ///
    /// "Implementations MUST accept non-canonical values and process them as
    ///  if they had been reduced modulo the field prime.  The non-canonical
    ///  values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
    ///  - 1 through 2^448 - 1 for X448."
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (PublicKey, test_public_key, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE)
}

impl_from_trait!(PublicKey, PUBLIC_KEY_SIZE);

construct_secret_key! {
    /// A type to represent the `SecretKey` that X25519 uses.
    ///
    /// This type is used internally as a scalar.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    ///
    /// # Panics:
    /// A panic will occur if:
    /// - Failure to generate random bytes securely.
    (SecretKey, test_secret_key, SECRET_KEY_SIZE, SECRET_KEY_SIZE, SECRET_KEY_SIZE)
}

impl_from_trait!(SecretKey, SECRET_KEY_SIZE);

impl TryFrom<&SecretKey> for PublicKey {
    type Error = UnknownCryptoError;

    fn try_from(secret_key: &SecretKey) -> Result<Self, Self::Error> {
        // NOTE: This implementation should be identical to x25519() except
        // for the check a resulting low order point result.
        let scalar = Scalar::from_slice(secret_key.unprotected_as_bytes());

        Ok(PublicKey::from(mont_ladder(&scalar, &BASEPOINT).as_bytes()))
    }
}

construct_secret_key! {
    /// A type to represent the `SharedKey` that X25519 produces.
    ///
    /// This type simply holds bytes. Creating an instance from slices or similar,
    /// performs no checks whatsoever.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (SharedSecret, test_shared_key, SHARED_KEY_SIZE, SHARED_KEY_SIZE)
}

impl_from_trait!(SharedSecret, SHARED_KEY_SIZE);

/// X25519 (Diffie-Hellman with Montgomery form of Curve25519).
pub fn key_agreement(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<SharedSecret, UnknownCryptoError> {
    let scalar = Scalar::from_slice(secret_key.unprotected_as_bytes());
    let u_coord = &public_key.value;

    let field_element = mont_ladder(&scalar, u_coord).as_bytes();
    // High bit should be zero.
    debug_assert!((field_element[31] & 0b1000_0000u8) == 0u8);
    if secure_cmp(&field_element, &LOW_ORDER_POINT_RESULT).is_ok() {
        return Err(UnknownCryptoError);
    }

    Ok(SharedSecret::from(field_element))
}

/// u-coordinate of the base point.
const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

///
const LOW_ORDER_POINT_RESULT: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod public {
    use crate::hazardous::ecc::x25519::{
        key_agreement, PublicKey, SecretKey, SharedSecret, BASEPOINT,
    };

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_highbit_ignored() {
        // RFC 7748 dictates that the MSB of final byte must be masked when receiving a field element,
        // used for agreement (public key). We check that modifying it does not impact the result of
        // the agreement.
        let k = SecretKey::generate();
        let mut u = PublicKey::from([0u8; 32]);

        crate::util::secure_rand_bytes(&mut u.value).unwrap();
        debug_assert_ne!(u.value[31] & 127u8, (u.value[31] & 127u8) | 128u8);

        // Mask bit to 0 as we do in `FieldElement::from_bytes()`.
        u.value[31] &= 127u8;
        let msb_zero = key_agreement(&k, &u).unwrap();
        u.value[31] |= 128u8;
        let msb_one = key_agreement(&k, &u).unwrap();

        assert_eq!(msb_zero, msb_one);
    }

    #[test]
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-5.2
    fn test_rfc_section_5() {
        let mut scalar = SecretKey::from([0u8; 32]);
        let mut point = PublicKey::from([0u8; 32]);
        let mut expected = SharedSecret::from([0u8; 32]);

        hex::decode_to_slice(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            &mut scalar.value,
        )
        .unwrap();
        hex::decode_to_slice(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            &mut point.value,
        )
        .unwrap();
        hex::decode_to_slice(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            &mut expected.value,
        )
        .unwrap();

        let actual = key_agreement(&scalar, &point).unwrap();
        assert_eq!(actual, expected);

        hex::decode_to_slice(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            &mut scalar.value,
        )
        .unwrap();
        hex::decode_to_slice(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            &mut point.value,
        )
        .unwrap();
        hex::decode_to_slice(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            &mut expected.value,
        )
        .unwrap();

        let actual = key_agreement(&scalar, &point).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-5.2
    fn test_rfc_section_5_iter() {
        let mut k = SecretKey::from(BASEPOINT);
        let mut u = PublicKey::from(BASEPOINT);

        // 1 iter
        let ret = key_agreement(&k, &u).unwrap();
        u.value = k.value;
        k.value = ret.value;

        let mut expected = SharedSecret::from([0u8; 32]);
        hex::decode_to_slice(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            &mut expected.value,
        )
        .unwrap();
        assert_eq!(k.value, expected.value, "Failed after 1 iter");

        for _ in 0..999 {
            let ret = key_agreement(&k, &u).unwrap();
            u.value = k.value;
            k.value = ret.value;
        }

        hex::decode_to_slice(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            &mut expected.value,
        )
        .unwrap();
        assert_eq!(k.value, expected.value, "Failed after 1.000 iter");

        /* Taking a decade...
        for _ in 0..999000 {
            let ret = key_agreement(&k, &u);
            u.value = k.value;
            k.value = ret.value;
        }

        hex::decode_to_slice("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424", &mut expected).unwrap();
        assert_eq!(k.value, expected.value, "Failed after 1.000.000 iter");
         */
    }

    #[test]
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-6.1
    fn test_rfc__section_6_pub_priv_basepoint() {
        let mut alice_pub = PublicKey::from([0u8; 32]);
        let mut alice_priv = SecretKey::from([0u8; 32]);

        let mut bob_pub = PublicKey::from([0u8; 32]);
        let mut bob_priv = SecretKey::from([0u8; 32]);

        let mut shared = SharedSecret::from([0u8; 32]);

        hex::decode_to_slice(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            &mut alice_priv.value,
        )
        .unwrap();
        hex::decode_to_slice(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            &mut alice_pub.value,
        )
        .unwrap();
        assert_eq!(
            key_agreement(&alice_priv, &PublicKey::from(BASEPOINT)).unwrap(),
            alice_pub.value.as_ref()
        );

        hex::decode_to_slice(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            &mut bob_priv.value,
        )
        .unwrap();
        hex::decode_to_slice(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            &mut bob_pub.value,
        )
        .unwrap();
        assert_eq!(
            key_agreement(&bob_priv, &PublicKey::from(BASEPOINT)).unwrap(),
            bob_pub.value.as_ref()
        );

        hex::decode_to_slice(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            &mut shared.value,
        )
        .unwrap();
        assert_eq!(
            key_agreement(&alice_priv, &bob_pub).unwrap(),
            shared.value.as_ref()
        );
        assert_eq!(
            key_agreement(&bob_priv, &alice_pub).unwrap(),
            shared.value.as_ref()
        );
    }
}
