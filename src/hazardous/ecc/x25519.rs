// MIT License

// Copyright (c) 2021-2026 The orion Developers

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

//! # Parameters:
//! - `private_key`: The private key used in key agreement.
//! - `public_key`: The public key used in key agreement.
//!
//! # Errors:
//! An error will be returned if:
//! - The [`key_agreement()`] operation results in an all-zero output.
//!
//! # Security:
//! - Multiple different `private_key`/`public_key` pairs can produce the same shared key. Therefore,
//! using the resulting [`SharedKey`], directly from [`key_agreement()`], is not recommended. This is handled
//! automatically in [`orion::kex`].
//! - To securely generate a strong key, use [`PrivateKey::generate()`].
//!
//! # Recommendation:
//! - It is recommended to use [`orion::kex`] when possible.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::ecc::x25519::{PrivateKey, PublicKey, SharedKey, key_agreement};
//!
//! // Alice generates a private key and computes the corresponding public key
//! let alice_sk = PrivateKey::generate()?;
//! let alice_pk = PublicKey::try_from(&alice_sk)?;
//!
//! // Bob does the same
//! let bob_sk = PrivateKey::generate()?;
//! let bob_pk = PublicKey::try_from(&bob_sk)?;
//!
//! // They both compute a shared key using the others public key
//! let alice_shared = key_agreement(&alice_sk, &bob_pk)?;
//! let bob_shared = key_agreement(&bob_sk, &alice_pk)?;
//!
//! assert_eq!(alice_shared, bob_shared);
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`PrivateKey::generate()`]: crate::hazardous::ecc::x25519::PrivateKey::generate
//! [`orion::kex`]: crate::kex
//! [`key_agreement()`]: crate::hazardous::ecc::x25519::key_agreement
//! [`SharedKey`]: crate::hazardous::ecc::x25519::SharedKey

use crate::errors::UnknownCryptoError;
use crate::generics::GenerateSecret;
use crate::generics::{ByteArrayData, TypeSpec};
use core::ops::{Add, Mul, Sub};

pub use crate::generics::Public;
pub use crate::generics::Secret;

#[cfg(feature = "safe_api")]
use crate::generics::sealed::Data;

use crate::generics::sealed::Sealed;

/// Formally verified Curve25519 field arithmetic from: <https://github.com/mit-plv/fiat-crypto>.
use fiat_crypto::curve25519_64 as fiat_curve25519_u64;
use fiat_curve25519_u64::{
    fiat_25519_add, fiat_25519_carry, fiat_25519_carry_mul, fiat_25519_carry_scmul_121666,
    fiat_25519_carry_square, fiat_25519_loose_field_element, fiat_25519_relax, fiat_25519_sub,
    fiat_25519_tight_field_element,
};

/// The size of a public key used in X25519.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// The size of a private key used in X25519.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// The size of a shared key used in X25519.
pub const SHARED_KEY_SIZE: usize = 32;

/// u-coordinate of the base point.
const BASEPOINT: FieldElement = FieldElement::from_bytes(&[
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/// The result of computing a shared secret with a low order point.
const LOW_ORDER_POINT_RESULT: [u8; 32] = [0u8; 32];

#[derive(Clone, Copy)]
/// Represent an element in the curve field.
struct FieldElement(fiat_25519_tight_field_element);

impl core::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FieldElement({:?})", &self.0.0)
    }
}

/// The function fiat_25519_carry_mul multiplies two field elements and reduces the result.
impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut ret = fiat_25519_tight_field_element([0u64; 5]);
        let mut self_relaxed = fiat_25519_loose_field_element([0u64; 5]);
        let mut rhs_relaxed = fiat_25519_loose_field_element([0u64; 5]);

        fiat_25519_relax(&mut self_relaxed, &self.0);
        fiat_25519_relax(&mut rhs_relaxed, &rhs.0);

        fiat_25519_carry_mul(&mut ret, &self_relaxed, &rhs_relaxed);

        Self(ret)
    }
}

/// The function fiat_25519_add adds two field elements.
impl Add for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = fiat_25519_tight_field_element([0u64; 5]);
        let mut ret_add = fiat_25519_loose_field_element([0u64; 5]);

        fiat_25519_add(&mut ret_add, &self.0, &rhs.0);
        fiat_25519_carry(&mut ret, &ret_add);

        Self(ret)
    }
}

/// The function fiat_25519_sub subtracts two field elements.
impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut ret = fiat_25519_tight_field_element([0u64; 5]);
        let mut ret_sub = fiat_25519_loose_field_element([0u64; 5]);

        fiat_25519_sub(&mut ret_sub, &self.0, &rhs.0);
        fiat_25519_carry(&mut ret, &ret_sub);

        Self(ret)
    }
}

impl FieldElement {
    /// Create a `FieldElement` that is `0`.
    fn zero() -> Self {
        Self(fiat_25519_tight_field_element([
            0u64, 0u64, 0u64, 0u64, 0u64,
        ]))
    }

    /// Create a `FieldElement` that is `1`.
    fn one() -> Self {
        Self(fiat_25519_tight_field_element([
            1u64, 0u64, 0u64, 0u64, 0u64,
        ]))
    }

    /// Serialize the `FieldElement` as a byte-array.
    fn as_bytes(&self) -> [u8; 32] {
        // The function fiat_25519_to_bytes serializes a field element to bytes in little-endian order.
        use fiat_curve25519_u64::fiat_25519_to_bytes;

        let mut ret = [0u8; 32];
        fiat_25519_to_bytes(&mut ret, &self.0);

        ret
    }

    /// Deserialize the `FieldElement` from a byte-array in little-endian.
    ///
    /// Masks the MSB in the final byte of the input bytes.
    const fn from_bytes(bytes: &[u8; 32]) -> Self {
        // The function fiat_25519_from_bytes deserializes a field element from bytes in little-endian order
        use fiat_curve25519_u64::fiat_25519_from_bytes;

        let mut temp = [0u8; 32];
        temp.copy_from_slice(bytes);
        temp[31] &= 127u8; // See RFC: "When receiving such an array, implementations of X25519
        // (but not X448) MUST mask the most significant bit in the final byte."

        let mut ret = fiat_25519_tight_field_element([0u64; 5]);
        fiat_25519_from_bytes(&mut ret, &temp);

        Self(ret)
    }

    /// A conditional-swap operation.
    fn conditional_swap(swap: u8, a: &mut Self, b: &mut Self) {
        // The function fiat_25519_selectznz is a multi-limb conditional select.
        use fiat_curve25519_u64::fiat_25519_selectznz;

        // SAFETY: This is a part of fiat input bounds.
        debug_assert!(swap == 1 || swap == 0);

        let tmp_a = *a;
        let tmp_b = *b;

        fiat_25519_selectznz(&mut a.0.0, swap, &tmp_a.0.0, &tmp_b.0.0);
        fiat_25519_selectznz(&mut b.0.0, swap, &tmp_b.0.0, &tmp_a.0.0);
    }

    /// Square the `FieldElement` and reduce the result.
    fn square(&self) -> Self {
        let mut self_relaxed = fiat_25519_loose_field_element([0u64; 5]);
        let mut ret = fiat_25519_tight_field_element([0u64; 5]);

        fiat_25519_relax(&mut self_relaxed, &self.0);
        fiat_25519_carry_square(&mut ret, &self_relaxed);

        Self(ret)
    }

    /// Multiply the `FieldElement` by 121666 and reduce the result.
    fn mul_121666(&self) -> Self {
        let mut self_relaxed = fiat_25519_loose_field_element([0u64; 5]);
        let mut ret = fiat_25519_tight_field_element([0u64; 5]);

        fiat_25519_relax(&mut self_relaxed, &self.0);
        fiat_25519_carry_scmul_121666(&mut ret, &self_relaxed);

        Self(ret)
    }

    /// Compute the multiplicative inverse of the `FieldElement`.
    ///
    /// Ref: https://github.com/golang/crypto/blob/0c34fe9e7dc2486962ef9867e3edb3503537209f/curve25519/curve25519_generic.go#L718
    fn invert(&mut self) {
        let mut t0 = self.square();
        let mut t1 = t0.square();
        t1 = t1.square();

        t1 = *self * t1;
        t0 = t0 * t1;
        let mut t2 = t0.square();

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
        let mut t3 = t2.square();
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

/// Scalar multiplication using the Montgomery Ladder (a.k.a "scalarmult")
///
/// Refs:
/// - <https://eprint.iacr.org/2020/956.pdf>
/// - <https://eprint.iacr.org/2017/212.pdf>
/// - <https://github.com/golang/crypto/blob/0c34fe9e7dc2486962ef9867e3edb3503537209f/curve25519/curve25519_generic.go#L779>
fn mont_ladder(scalar: &[u8; PRIVATE_KEY_SIZE], point: FieldElement) -> FieldElement {
    debug_assert_eq!(
        point.as_bytes()[31] & 0x80,
        0,
        "FieldElement missing highbit mask!"
    );
    debug_assert!(X25519PrivateKey::is_clamped(scalar));

    let x1 = point;
    let mut x2 = FieldElement::one();
    let mut x3 = x1;
    let mut z3 = FieldElement::one();
    let mut z2 = FieldElement::zero();
    let mut tmp0: FieldElement;
    let mut tmp1: FieldElement;

    let mut swap: u8 = 0;

    for idx in (0..=254).rev() {
        let bit = (scalar[idx >> 3] >> (idx & 7)) & 1;
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

#[derive(Debug)]
/// X25519 private key implementation. See [`PrivateKey`] type for convenience.
pub struct X25519PrivateKey {}
impl Sealed for X25519PrivateKey {}

impl X25519PrivateKey {
    /// Ref: <https://www.ietf.org/rfc/rfc7748.html#section-5>
    const fn clamp(k: &[u8; PRIVATE_KEY_SIZE]) -> [u8; PRIVATE_KEY_SIZE] {
        let mut scalar = *k;
        // Clamp
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        scalar
    }

    fn is_clamped(scalar: &[u8; PRIVATE_KEY_SIZE]) -> bool {
        use subtle::ConstantTimeEq;
        ((scalar[0] & 7).ct_eq(&0) & ((scalar[31] & 0xC0).ct_eq(&0x40))).into()
    }
}

impl TypeSpec for X25519PrivateKey {
    const NAME: &'static str = stringify!(PrivateKey);
    type TypeData = ByteArrayData<PRIVATE_KEY_SIZE>;
}

impl From<[u8; PRIVATE_KEY_SIZE]> for Secret<X25519PrivateKey> {
    fn from(value: [u8; PRIVATE_KEY_SIZE]) -> Self {
        Self::from_data(<X25519PrivateKey as TypeSpec>::TypeData::from(value))
    }
}

impl GenerateSecret for X25519PrivateKey {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<X25519PrivateKey>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(PRIVATE_KEY_SIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;

        Ok(Secret::from_data(data))
    }
}

/// X25519 private key.
pub type PrivateKey = Secret<X25519PrivateKey>;

#[derive(Debug, Clone, Copy)]
/// X25519 public key implementation. See [`PublicKey`] type for convenience.
pub struct X25519PublicKey {}
impl Sealed for X25519PublicKey {}

impl TypeSpec for X25519PublicKey {
    const NAME: &'static str = stringify!(PublicKey);
    type TypeData = ByteArrayData<PUBLIC_KEY_SIZE>;

    /// SECURITY: This overrides the default variable-time [`PartialEq`] with
    /// a variable time one, in order to include high-bit masking.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        debug_assert_eq!(lhs.bytes.len(), PUBLIC_KEY_SIZE);
        if lhs.bytes.len() != rhs.len() {
            return false;
        }

        lhs.bytes[..31] == rhs[..31] && (lhs.bytes[31] & 127u8) == (rhs[31] & 127u8)
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for Public<X25519PublicKey> {
    fn from(value: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self::from_data(<X25519PublicKey as TypeSpec>::TypeData::from(value))
    }
}

impl TryFrom<&PrivateKey> for Public<X25519PublicKey> {
    type Error = UnknownCryptoError;

    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        // NOTE: This implementation should be identical to key_agreement() except
        // for the check of a resulting low order point result.
        Ok(PublicKey::from(
            mont_ladder(&X25519PrivateKey::clamp(&private_key.data.bytes), BASEPOINT).as_bytes(),
        ))
    }
}

impl From<&Public<X25519PublicKey>> for FieldElement {
    fn from(value: &Public<X25519PublicKey>) -> Self {
        FieldElement::from_bytes(&value.data.bytes)
    }
}

impl From<&FieldElement> for Public<X25519PublicKey> {
    fn from(value: &FieldElement) -> Self {
        let bytes = value.as_bytes();
        debug_assert_eq!(
            bytes[31] & 0x80,
            0,
            "parsed FieldElement for PublicKey with missing highbit mask!"
        );

        Self::from(bytes)
    }
}

/// X25519 public key.
///
/// The most significant bit of the last byte is masked when comparing with [`PartialEq`].
/// See [RFC](https://www.ietf.org/rfc/rfc7748.html#section-5).
///
/// This means if two instances differ in the highest bit, then comparing [`PartialEq`]
/// will return true, directly on this type. If comparing with [`Self::as_ref()`]
/// then they will differ.
pub type PublicKey = Public<X25519PublicKey>;

#[derive(Debug)]
/// X25519 shared key implementation. See [`SharedKey`] type for convenience.
pub struct X25519SharedKey {}
impl Sealed for X25519SharedKey {}

impl TypeSpec for X25519SharedKey {
    const NAME: &'static str = stringify!(SharedKey);
    type TypeData = ByteArrayData<SHARED_KEY_SIZE>;

    /// SECURITY: This overrides the default constant-time [`PartialEq`] with
    /// a constant time one, in order to include high-bit masking.
    fn ct_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        debug_assert_eq!(lhs.bytes.len(), SHARED_KEY_SIZE);
        if lhs.bytes.len() != rhs.len() {
            return false;
        }

        (lhs.bytes[..31].ct_eq(&rhs[..31]) & (lhs.bytes[31] & 127u8).ct_eq(&(rhs[31] & 127u8)))
            .into()
    }
}

impl From<[u8; SHARED_KEY_SIZE]> for Secret<X25519SharedKey> {
    fn from(value: [u8; SHARED_KEY_SIZE]) -> Self {
        Self::from_data(<X25519PublicKey as TypeSpec>::TypeData::from(value))
    }
}

impl From<FieldElement> for Secret<X25519SharedKey> {
    fn from(value: FieldElement) -> Self {
        let bytes = value.as_bytes();
        debug_assert_eq!(
            bytes[31] & 0x80,
            0,
            "parsed FieldElement for SharedSecret with missing highbit mask!"
        );

        Self::from(bytes)
    }
}

/// X25519 shared key.
///
/// The most significant bit of the last byte is masked when comparing with [`PartialEq`].
/// See [RFC](https://www.ietf.org/rfc/rfc7748.html#section-5).
///
/// This means if two instances differ in the highest bit, then comparing [`PartialEq`]
/// will return true, directly on this type. If comparing with [`Self::unprotected_as_ref()`]
/// then they will differ.
pub type SharedKey = Secret<X25519SharedKey>;

/// X25519 (Diffie-Hellman with Montgomery form of Curve25519).
pub fn key_agreement(
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<SharedKey, UnknownCryptoError> {
    let u_coord = FieldElement::from(public_key);
    let shared_key = SharedKey::from(mont_ladder(
        &X25519PrivateKey::clamp(&private_key.data.bytes),
        u_coord,
    ));

    // High bit should be zero.
    debug_assert_eq!(shared_key.data.bytes[31] & 0b1000_0000u8, 0u8);
    if shared_key == &LOW_ORDER_POINT_RESULT {
        return Err(UnknownCryptoError);
    }

    Ok(shared_key)
}

#[cfg(test)]
mod public {
    use crate::hazardous::ecc::x25519::{
        BASEPOINT, FieldElement, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, PrivateKey, PublicKey,
        SHARED_KEY_SIZE, SharedKey, X25519PrivateKey, X25519PublicKey, X25519SharedKey,
        key_agreement,
    };

    const BASEPOINT_BYTES: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    #[test]
    fn correctness_clamping() {
        let mut preclamp = [0u8; PRIVATE_KEY_SIZE];

        for b0 in 0u8..=u8::MAX {
            preclamp[0] = b0;

            for b31 in 0u8..=u8::MAX {
                preclamp[31] = b31;
                if X25519PrivateKey::is_clamped(&preclamp) {
                    assert_eq!(&preclamp, &X25519PrivateKey::clamp(&preclamp));
                }
                assert!(X25519PrivateKey::is_clamped(&X25519PrivateKey::clamp(
                    &preclamp
                )));
            }
        }
    }

    #[test]
    fn test_shared_secret() {
        use crate::test_framework::newtypes::secret::SecretNewtype;
        SecretNewtype::test_no_generate::<SHARED_KEY_SIZE, SHARED_KEY_SIZE, X25519SharedKey>();
        // Test of From<[u8; N]>
        assert_ne!(
            SharedKey::from([0u8; SHARED_KEY_SIZE]),
            SharedKey::from([1u8; SHARED_KEY_SIZE])
        );
    }

    #[test]
    fn test_private_key() {
        use crate::test_framework::newtypes::secret::SecretNewtype;
        SecretNewtype::test_with_generate::<
            PRIVATE_KEY_SIZE,
            PRIVATE_KEY_SIZE,
            PRIVATE_KEY_SIZE,
            X25519PrivateKey,
        >();
        // Test of From<[u8; N]>
        assert_ne!(
            PrivateKey::from([0u8; PRIVATE_KEY_SIZE]),
            PrivateKey::from([1u8; PRIVATE_KEY_SIZE])
        );
    }

    #[test]
    fn test_public_key() {
        use crate::test_framework::newtypes::public::PublicNewtype;
        PublicNewtype::test_no_generate::<PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE, X25519PublicKey>();
        // Test of From<[u8; N]>
        assert_ne!(
            PublicKey::from([0u8; PUBLIC_KEY_SIZE]),
            PublicKey::from([1u8; PUBLIC_KEY_SIZE])
        );

        #[cfg(feature = "serde")]
        PublicNewtype::test_serialization::<PUBLIC_KEY_SIZE, X25519PublicKey>();
    }

    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_field_element_debug_impl() {
        let secret = format!("{:?}", [1u8; 32].as_ref());
        let test_debug_contents =
            format!("{:?}", PrivateKey::try_from([1u8; 32].as_slice()).unwrap());
        assert!(!test_debug_contents.contains(&secret));
    }

    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_privatekey_debug_impl() {
        use super::FieldElement;
        let value = format!("{:?}", [1u64, 0u64, 0u64, 0u64, 0u64,].as_ref());
        let test_debug_contents = format!("{:?}", FieldElement::one());
        assert!(test_debug_contents.contains(&value));
    }

    #[test]
    fn test_public_key_ignores_highbit() {
        let u = [0u8; 32];

        let mut msb_zero = u;
        msb_zero[31] &= 127u8;
        let mut msb_one = u;
        msb_one[31] |= 128u8;

        // These should equal each other. The high bits differ, but should be ignored.
        let pk_msb_zero = PublicKey::from(msb_zero);
        assert_eq!(pk_msb_zero, &msb_zero);
        assert_eq!(pk_msb_zero, &msb_one);

        let pk_msb_one = PublicKey::from(msb_one);
        assert_eq!(pk_msb_one, &msb_zero);
        assert_eq!(pk_msb_one, &msb_one);

        assert_eq!(pk_msb_zero, pk_msb_one.as_ref());
        // We do not modify the stored value itself, because any impl MUST accept
        // non-canonical and treat them as if they are. So in stead of modifying,
        // we only handle it internally and on [`PartialEq`]. Preserve still original
        // value.
        assert_ne!(pk_msb_one.as_ref(), pk_msb_zero.as_ref());
    }

    #[test]
    fn test_shared_key_ignores_highbit() {
        let u = [0u8; 32];

        let mut msb_zero = u;
        msb_zero[31] &= 127u8;
        let mut msb_one = u;
        msb_one[31] |= 128u8;

        // These should equal each other. The high bits differ, but should be ignored.
        let pk_msb_zero = SharedKey::from(msb_zero);
        assert_eq!(pk_msb_zero, &msb_zero);
        assert_eq!(pk_msb_zero, &msb_one);

        let pk_msb_one = SharedKey::from(msb_one);
        assert_eq!(pk_msb_one, &msb_zero);
        assert_eq!(pk_msb_one, &msb_one);

        assert_eq!(pk_msb_zero, pk_msb_one.unprotected_as_ref());
        // We do not modify the stored value itself, because any impl MUST accept
        // non-canonical and treat them as if they are. So in stead of modifying,
        // we only handle it internally and on [`PartialEq`]. Preserve still original
        // value.
        assert_ne!(
            pk_msb_one.unprotected_as_ref(),
            pk_msb_zero.unprotected_as_ref()
        );
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_highbit_ignored() {
        // RFC 7748 dictates that the MSB of final byte must be masked when receiving a field element,
        // used for agreement (public key). We check that modifying it does not impact the result of
        // the agreement.
        let k = PrivateKey::generate().unwrap();
        let mut u = [0u8; 32];
        crate::util::secure_rand_bytes(&mut u).unwrap();
        debug_assert_ne!(u[31] & 127u8, (u[31] & 127u8) | 128u8);

        let mut u_msb_zero = u;
        u_msb_zero[31] &= 127u8;
        let mut u_msb_one = u;
        u_msb_one[31] |= 128u8;

        // Mask bit to 0 as we do in `FieldElement::from_bytes()`.
        let msb_zero = key_agreement(&k, &PublicKey::from(u_msb_zero)).unwrap();
        let msb_one = key_agreement(&k, &PublicKey::from(u_msb_one)).unwrap();

        assert_eq!(msb_zero, msb_one);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_scalar_clamp() {
        // We test clamping happens on all three manual impls of parsing bytes

        // GenerateSecret
        let private = PrivateKey::generate().unwrap();
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[0] & !248, 0);
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[31] & !127, 0);
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[31] & 64, 64);

        // TryFrom default impls defined by parse_bytes()
        let private = PrivateKey::try_from(&[0xFFu8; PRIVATE_KEY_SIZE]).unwrap();
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[0] & !248, 0);
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[31] & !127, 0);
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[31] & 64, 64);

        // From<[u8; 32]>
        let private = PrivateKey::from([0xFFu8; PRIVATE_KEY_SIZE]);
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[0] & !248, 0);
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[31] & !127, 0);
        assert_eq!(X25519PrivateKey::clamp(&private.data.bytes)[31] & 64, 64);
    }

    #[test]
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-5.2
    fn test_rfc_section_5() {
        let mut scalar = [0u8; 32];
        let mut point = [0u8; 32];
        let mut expected = SharedKey::from([0u8; 32]);

        hex::decode_to_slice(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            &mut scalar,
        )
        .unwrap();
        hex::decode_to_slice(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            &mut point,
        )
        .unwrap();
        hex::decode_to_slice(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            expected.data.as_mut(),
        )
        .unwrap();

        let actual = key_agreement(&PrivateKey::from(scalar), &PublicKey::from(point)).unwrap();
        assert_eq!(actual, expected);

        hex::decode_to_slice(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            &mut scalar,
        )
        .unwrap();
        hex::decode_to_slice(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            &mut point,
        )
        .unwrap();
        hex::decode_to_slice(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            expected.data.as_mut(),
        )
        .unwrap();

        let actual = key_agreement(&PrivateKey::from(scalar), &PublicKey::from(point)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-5.2
    fn test_rfc_section_5_iter() {
        let mut k = BASEPOINT_BYTES;
        let mut u = BASEPOINT;

        // 1 iter
        let ret = key_agreement(&PrivateKey::from(k), &PublicKey::from(&u)).unwrap();
        u = FieldElement::from_bytes(&k);
        k = ret.data.bytes;

        let mut expected = SharedKey::from([0u8; 32]);
        hex::decode_to_slice(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            expected.data.as_mut(),
        )
        .unwrap();
        assert_eq!(k, expected.unprotected_as_ref(), "Failed after 1 iter");

        for _ in 0..999 {
            let ret = key_agreement(&PrivateKey::from(k), &PublicKey::from(&u)).unwrap();
            u = FieldElement::from_bytes(&k);
            k = ret.data.bytes;
        }

        hex::decode_to_slice(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            expected.data.as_mut(),
        )
        .unwrap();
        assert_eq!(k, expected.unprotected_as_ref(), "Failed after 1.000 iter");

        /* Taking a decade...
        for num in 0..999000 {
            let ret = key_agreement(&PrivateKey::from(k), &PublicKey::from(u)).unwrap();
            u = k;
            k = ret.value;
        }

        hex::decode_to_slice(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            expected.data.as_mut(),
        )
        .unwrap();
        assert_eq!(k, expected.value, "Failed after 1.000.000 iter");
        */
    }

    #[test]
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-6.1
    fn test_rfc_section_6_pub_priv_basepoint() {
        let mut alice_pub = [0u8; 32];
        let mut alice_priv = [0u8; 32];

        let mut bob_pub = [0u8; 32];
        let mut bob_priv = [0u8; 32];

        let mut shared = SharedKey::from([0u8; 32]);

        hex::decode_to_slice(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            &mut alice_priv,
        )
        .unwrap();
        hex::decode_to_slice(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            &mut alice_pub,
        )
        .unwrap();
        assert_eq!(
            PublicKey::from(alice_pub),
            key_agreement(
                &PrivateKey::from(alice_priv),
                &PublicKey::from(BASEPOINT_BYTES)
            )
            .unwrap()
            .unprotected_as_ref()
        );

        hex::decode_to_slice(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            &mut bob_priv,
        )
        .unwrap();
        hex::decode_to_slice(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            &mut bob_pub,
        )
        .unwrap();
        assert_eq!(
            PublicKey::from(bob_pub),
            key_agreement(
                &PrivateKey::from(bob_priv),
                &PublicKey::from(BASEPOINT_BYTES)
            )
            .unwrap()
            .unprotected_as_ref()
        );

        hex::decode_to_slice(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            shared.data.as_mut(),
        )
        .unwrap();
        assert_eq!(
            key_agreement(&PrivateKey::from(alice_priv), &PublicKey::from(bob_pub)).unwrap(),
            shared
        );
        assert_eq!(
            key_agreement(&PrivateKey::from(bob_priv), &PublicKey::from(alice_pub)).unwrap(),
            shared
        );
    }
}
