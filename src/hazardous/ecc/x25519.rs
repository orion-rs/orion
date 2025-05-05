// MIT License

// Copyright (c) 2021-2025 The orion Developers

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
//! - The `key_agreement()` operation results in an all-zero output.
//!
//! # Security:
//! - Multiple different `private_key`/`public_key` pairs can produce the same shared key. Therefore,
//! using the resulting `SharedKey`, directly from `key_agreement()`, is not recommended. This is handled
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
//! use core::convert::TryFrom;
//!
//! // Alice generates a private key and computes the corresponding public key
//! let alice_sk = PrivateKey::generate();
//! let alice_pk = PublicKey::try_from(&alice_sk)?;
//!
//! // Bob does the same
//! let bob_sk = PrivateKey::generate();
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

use crate::errors::UnknownCryptoError;
use crate::util::secure_cmp;
use core::ops::{Add, Mul, Sub};

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
const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// The result of computing a shared secret with a low order point.
const LOW_ORDER_POINT_RESULT: [u8; 32] = [0u8; 32];

#[derive(Clone, Copy)]
/// Represent an element in the curve field.
struct FieldElement(fiat_25519_tight_field_element);

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.as_bytes().ct_eq(&other.as_bytes()).into()
    }
}

impl core::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FieldElement({:?})", &self.0 .0)
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
    fn from_bytes(bytes: &[u8; 32]) -> Self {
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

        fiat_25519_selectznz(&mut a.0 .0, swap, &tmp_a.0 .0, &tmp_b.0 .0);
        fiat_25519_selectznz(&mut b.0 .0, swap, &tmp_b.0 .0, &tmp_a.0 .0);
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

#[derive(Clone)]
/// Represents a Scalar decoded from a byte array.
struct Scalar([u8; PRIVATE_KEY_SIZE]);

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

impl Eq for Scalar {}

impl Scalar {
    /// Create a scalar from some byte-array.
    /// The scalar is clamped according to the RFC.
    ///
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-5
    fn from_slice(slice: &[u8]) -> Result<Scalar, UnknownCryptoError> {
        if slice.len() != PRIVATE_KEY_SIZE {
            return Err(UnknownCryptoError);
        }

        let mut ret = [0u8; PRIVATE_KEY_SIZE];
        ret.copy_from_slice(slice);
        // Clamp
        ret[0] &= 248;
        ret[31] &= 127;
        ret[31] |= 64;

        Ok(Self(ret))
    }
}

/// Scalar multiplication using the Montgomery Ladder (a.k.a "scalarmult")
///
/// Refs:
/// - https://eprint.iacr.org/2020/956.pdf
/// - https://eprint.iacr.org/2017/212.pdf
/// - https://github.com/golang/crypto/blob/0c34fe9e7dc2486962ef9867e3edb3503537209f/curve25519/curve25519_generic.go#L779
fn mont_ladder(scalar: &Scalar, point: FieldElement) -> FieldElement {
    let x1 = point;
    let mut x2 = FieldElement::one();
    let mut x3 = x1;
    let mut z3 = FieldElement::one();
    let mut z2 = FieldElement::zero();
    let mut tmp0: FieldElement;
    let mut tmp1: FieldElement;

    let mut swap: u8 = 0;

    for idx in (0..=254).rev() {
        let bit = (scalar.0[idx >> 3] >> (idx & 7)) & 1;
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

#[allow(clippy::derive_partial_eq_without_eq)]
// NOTE: FieldElement contains a constant-time PartialEq<FieldElement> impl.
/// A type that represents a `PublicKey` that X25519 uses.
///
/// This type holds a field element and is used internally as the u-coordinate.
/// As the RFC mandates, the most significant bit of the last byte is masked.
///
/// # Errors:
/// An error will be returned if:
/// - `slice` is not 32 bytes.
#[derive(PartialEq, Debug, Clone)]
pub struct PublicKey {
    fe: FieldElement,
}

impl PartialEq<&[u8]> for PublicKey {
    fn eq(&self, other: &&[u8]) -> bool {
        if other.len() != PUBLIC_KEY_SIZE {
            return false;
        }
        let other: [u8; 32] = (*other).try_into().unwrap();

        self.fe == FieldElement::from_bytes(&other)
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKey {
    #[inline]
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self {
            fe: FieldElement::from_bytes(&bytes),
        }
    }
}

impl_try_from_trait!(PublicKey);
#[cfg(feature = "serde")]
impl_serde_traits!(PublicKey, to_bytes);

impl TryFrom<&PrivateKey> for PublicKey {
    type Error = UnknownCryptoError;

    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        // NOTE: This implementation should be identical to key_agreement() except
        // for the check of a resulting low order point result.
        let scalar = Scalar::from_slice(private_key.unprotected_as_bytes())?;

        Ok(PublicKey::from(
            mont_ladder(&scalar, FieldElement::from_bytes(&BASEPOINT)).as_bytes(),
        ))
    }
}

impl PublicKey {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Construct from a given byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        let slice_len = slice.len();

        if slice_len != PUBLIC_KEY_SIZE {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            fe: FieldElement::from_bytes(slice.try_into().unwrap()),
        })
    }

    #[inline]
    /// Return the length of the object.
    pub fn len(&self) -> usize {
        PUBLIC_KEY_SIZE
    }

    #[inline]
    /// Return `true` if this object does not hold any data, `false` otherwise.
    ///
    /// __NOTE__: This method should always return `false`, since there shouldn't be a way
    /// to create an empty instance of this object.
    pub fn is_empty(&self) -> bool {
        PUBLIC_KEY_SIZE == 0
    }

    #[inline]
    /// Convert this PublicKey to its byte-representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.fe.as_bytes()
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
// NOTE: Scalar contains a constant-time PartialEq<Scalar> impl.
// NOTE: All newtypes impl Drop by default and Scalar has zeroizing Drop
/// A type to represent the `PrivateKey` that X25519 uses.
///
/// This type holds a scalar and is used internally as such. The scalar held is decoded
/// (a.k.a "clamped") as mandated in the [RFC](https://datatracker.ietf.org/doc/html/rfc7748#section-5).
///
/// # Errors:
/// An error will be returned if:
/// - `slice` is not 32 bytes.
///
/// # Panics:
/// A panic will occur if:
/// - Failure to generate random bytes securely.
///
///
/// # Security:
/// - __**Avoid using**__ `unprotected_as_bytes()` whenever possible, as it breaks all protections
///   that the type implements.
///
/// - The trait `PartialEq<&'_ [u8]>` is implemented for this type so that users are not tempted
///   to call `unprotected_as_bytes` to compare this sensitive value to a byte slice. The trait
///   is implemented in such a way that the comparison happens in constant time. Thus, users should
///   prefer `SecretType == &[u8]` over `SecretType.unprotected_as_bytes() == &[u8]`.
///
/// Examples are shown below. The examples apply to any type that implements `PartialEq<&'_ [u8]>`.
/// ```rust
/// # #[cfg(feature = "safe_api")] {
/// use orion::hazardous::ecc::x25519::PrivateKey;
///
/// // Initialize a secret key with random bytes.
/// let secret_key = PrivateKey::generate();
///
/// // Secure, constant-time comparison with a byte slice
/// assert_ne!(secret_key, &[0; 32][..]);
///
/// // Secure, constant-time comparison with another SecretKey
/// assert_ne!(secret_key, PrivateKey::generate());
/// # }
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
#[derive(PartialEq)]
pub struct PrivateKey {
    scalar: Scalar,
}

impl PartialEq<&[u8]> for PrivateKey {
    fn eq(&self, other: &&[u8]) -> bool {
        match Scalar::from_slice(other) {
            Ok(other_scalar) => self.scalar == other_scalar,
            Err(_) => false,
        }
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {{***OMITTED***}}", stringify!(PrivateKey))
    }
}

impl From<[u8; PRIVATE_KEY_SIZE]> for PrivateKey {
    #[inline]
    fn from(bytes: [u8; PRIVATE_KEY_SIZE]) -> Self {
        PrivateKey {
            // unwrap OK due to valid len
            scalar: Scalar::from_slice(bytes.as_ref()).unwrap(),
        }
    }
}

impl PrivateKey {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Construct from a given byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            scalar: Scalar::from_slice(slice)?,
        })
    }

    #[inline]
    /// Return the length of the object.
    pub fn len(&self) -> usize {
        PRIVATE_KEY_SIZE
    }

    #[inline]
    /// Return `true` if this object does not hold any data, `false` otherwise.
    ///
    /// __NOTE__: This method should always return `false`, since there shouldn't be a way
    /// to create an empty instance of this object.
    pub fn is_empty(&self) -> bool {
        PRIVATE_KEY_SIZE == 0
    }

    #[inline]
    /// Return the object as byte slice. __**Warning**__: Should not be used unless strictly
    /// needed. This __**breaks protections**__ that the type implements.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.scalar.0.as_ref()
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Randomly generate using a CSPRNG. Not available in `no_std` context.
    pub fn generate() -> PrivateKey {
        let mut value = [0u8; PRIVATE_KEY_SIZE];
        crate::util::secure_rand_bytes(&mut value).unwrap();

        Self {
            // unwrap OK due to valid len
            scalar: Scalar::from_slice(&value).unwrap(),
        }
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
    (SharedKey, test_shared_key, SHARED_KEY_SIZE, SHARED_KEY_SIZE)
}

impl_from_trait!(SharedKey, SHARED_KEY_SIZE);

/// X25519 (Diffie-Hellman with Montgomery form of Curve25519).
pub fn key_agreement(
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<SharedKey, UnknownCryptoError> {
    let u_coord = public_key.fe;
    let field_element = mont_ladder(&private_key.scalar, u_coord).as_bytes();
    // High bit should be zero.
    debug_assert_eq!(field_element[31] & 0b1000_0000u8, 0u8);
    if secure_cmp(&field_element, &LOW_ORDER_POINT_RESULT).is_ok() {
        return Err(UnknownCryptoError);
    }

    Ok(SharedKey::from(field_element))
}

#[cfg(test)]
mod public {
    use crate::hazardous::ecc::x25519::{
        key_agreement, PrivateKey, PublicKey, Scalar, SharedKey, BASEPOINT, PRIVATE_KEY_SIZE,
        PUBLIC_KEY_SIZE,
    };

    // NOTE(brycx): PrivateKey/PublicKey in X25519 are manual impls of types that are normally tested as
    // part of typedefs, so we have some extra test code that here, that normally
    // would be part of the macros.

    #[test]
    #[cfg(feature = "safe_api")]
    fn testpublickey_partialeq_bytes() {
        let k = PrivateKey::generate();
        let pk = PublicKey::try_from(&k).unwrap();

        assert_eq!(pk, pk.to_bytes().as_ref());
        assert_ne!(pk, [0u8; PUBLIC_KEY_SIZE].as_ref()); // not zero, because generate()
        assert_ne!(pk, [0u8; PUBLIC_KEY_SIZE - 1].as_ref()); // early abort on length mismatch
        assert_ne!(pk, [0u8; PUBLIC_KEY_SIZE + 1].as_ref());
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn testprivate_partialeq_bytes() {
        let k = PrivateKey::generate();
        assert!(!k.is_empty());
        assert_eq!(k.len(), PRIVATE_KEY_SIZE);

        assert_eq!(k, k.unprotected_as_bytes());
        assert_ne!(k, [0u8; PRIVATE_KEY_SIZE].as_ref()); // not zero, because generate()
        assert_ne!(k, [0u8; PRIVATE_KEY_SIZE - 1].as_ref()); // early abort on length mismatch
        assert_ne!(k, [0u8; PRIVATE_KEY_SIZE + 1].as_ref());
    }

    #[test]
    fn test_scalar_length_from_slice() {
        assert!(Scalar::from_slice(&[0u8; PRIVATE_KEY_SIZE]).is_ok());
        assert!(Scalar::from_slice(&[0u8; PRIVATE_KEY_SIZE - 1]).is_err());
        assert!(Scalar::from_slice(&[0u8; PRIVATE_KEY_SIZE + 1]).is_err());
    }

    #[test]
    fn test_publickey_length_from_slice() {
        assert!(PublicKey::from_slice(&[0u8; PUBLIC_KEY_SIZE]).is_ok());
        assert!(PublicKey::from_slice(&[0u8; PUBLIC_KEY_SIZE - 1]).is_err());
        assert!(PublicKey::from_slice(&[0u8; PUBLIC_KEY_SIZE + 1]).is_err());

        let pk = PublicKey::from_slice(&[0u8; PUBLIC_KEY_SIZE]).unwrap();
        assert!(!pk.is_empty());
        assert_eq!(pk.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_field_element_debug_impl() {
        let secret = format!("{:?}", [1u8; 32].as_ref());
        let test_debug_contents = format!("{:?}", PrivateKey::from_slice(&[1u8; 32]).unwrap());
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

        // These should equal each-other. The high bits differ, but should be ignored.
        assert_eq!(PublicKey::from(msb_zero), msb_one.as_ref());
        assert_eq!(PublicKey::from(msb_zero), PublicKey::from(msb_one));
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_highbit_ignored() {
        // RFC 7748 dictates that the MSB of final byte must be masked when receiving a field element,
        // used for agreement (public key). We check that modifying it does not impact the result of
        // the agreement.
        let k = PrivateKey::generate();
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
            &mut expected.value,
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
            &mut expected.value,
        )
        .unwrap();

        let actual = key_agreement(&PrivateKey::from(scalar), &PublicKey::from(point)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    /// Ref: https://www.ietf.org/rfc/rfc7748.html#section-5.2
    fn test_rfc_section_5_iter() {
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;

        // 1 iter
        let ret = key_agreement(&PrivateKey::from(k), &PublicKey::from(u)).unwrap();
        u = k;
        k = ret.value;

        let mut expected = SharedKey::from([0u8; 32]);
        hex::decode_to_slice(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            &mut expected.value,
        )
        .unwrap();
        assert_eq!(k, expected.value, "Failed after 1 iter");

        for _ in 0..999 {
            let ret = key_agreement(&PrivateKey::from(k), &PublicKey::from(u)).unwrap();
            u = k;
            k = ret.value;
        }

        hex::decode_to_slice(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            &mut expected.value,
        )
        .unwrap();
        assert_eq!(k, expected.value, "Failed after 1.000 iter");

        /* Taking a decade...
        for num in 0..999000 {
            let ret = key_agreement(&PrivateKey::from(k), &PublicKey::from(u)).unwrap();
            u = k;
            k = ret.value;
        }

        hex::decode_to_slice(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            &mut expected.value,
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
            key_agreement(&PrivateKey::from(alice_priv), &PublicKey::from(BASEPOINT)).unwrap(),
            PublicKey::from(alice_pub).to_bytes().as_ref()
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
            key_agreement(&PrivateKey::from(bob_priv), &PublicKey::from(BASEPOINT)).unwrap(),
            PublicKey::from(bob_pub).to_bytes().as_ref()
        );

        hex::decode_to_slice(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            &mut shared.value,
        )
        .unwrap();
        assert_eq!(
            key_agreement(&PrivateKey::from(alice_priv), &PublicKey::from(bob_pub)).unwrap(),
            shared.value.as_ref()
        );
        assert_eq!(
            key_agreement(&PrivateKey::from(bob_priv), &PublicKey::from(alice_pub)).unwrap(),
            shared.value.as_ref()
        );
    }

    #[test]
    fn test_privatekey_edge_cases() {
        // all zeros - clamped in RFC 7748, should be accepted
        assert!(PrivateKey::from_slice(&[0u8; PRIVATE_KEY_SIZE]).is_ok(), "all-zero key");
    
        // all ones - clamped, should be accepted
        assert!(PrivateKey::from_slice(&[0xffu8; PRIVATE_KEY_SIZE]).is_ok(), "all-ones key");
    
        // alternating bits - arbitrary pattern, should be accepted
        assert!(PrivateKey::from_slice(&[0b10101010u8; PRIVATE_KEY_SIZE]).is_ok(), "alternating-bits key");
    
        // only first byte set
        let mut first = [0u8; PRIVATE_KEY_SIZE];
        first[0] = 1;
        assert!(PrivateKey::from_slice(&first).is_ok(), "first-byte-set key");
    
        // only last byte set
        let mut last = [0u8; PRIVATE_KEY_SIZE];
        last[PRIVATE_KEY_SIZE - 1] = 1;
        assert!(PrivateKey::from_slice(&last).is_ok(), "last-byte-set key");
    }

}
