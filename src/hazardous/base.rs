//! ## Parameter: `B` (bytes)
//! `B` parameterizes over the **byte storage**. In practice, this is
//! either an [`ArrayData`][a] or [`VecData`][b]. This allows us
//! to implement methods on any type that can be converted from
//! or interpreted as a `&[u8]`. This also makes it possible to add
//! compatibility with, for example, the [`Bytes`][c] type for
//! zero-copy creation of cryptographic types arriving from the network.
//!
//! TODO: Add example showing how we can use different byte storages.
//!
//! ## Parameter: `C` (context)
//! `C` parameterizes over the **context** of the data. Primarily,
//! this allows us to leverage the type system to protect against
//! misuse of keys (e.g. using one key for two different primitives).
//! In practice, `C` will be a unit struct named after an intended
//! use of the data, such as `chacha::Key`. This will prevent
//! its use in a function that requires instead `aes::Key`.
//!
//! The following example demonstrates how we can leverage the type
//! system and the concept of "contexts" to quickly create types
//! that implement the functionality we want from byte storage objects,
//! but are still logically separate from each other and, in that way,
//! "misuse-resistant".
//! ```rust
//! use orion::hazardous::base::{
//!     Bounded, Generate, NamedContext,
//!     SecretData, VecData
//! };
//!
//! // Let's say you hypothetically had keys of two different types:
//! // AES and Ed25519 secret keys.
//! struct AesContext;
//! struct EdContext;
//!
//! const KEY_SIZE: usize = 32;
//!
//! impl Bounded for AesContext {
//!     const MIN: usize = KEY_SIZE;
//!     const MAX: usize = KEY_SIZE;
//! }
//!
//! impl Bounded for EdContext {
//!     const MIN: usize = KEY_SIZE;
//!     const MAX: usize = KEY_SIZE;
//! }
//!
//! impl Generate for AesContext {
//!     const GEN_SIZE: usize = KEY_SIZE;
//! }
//!
//! impl Generate for EdContext {
//!     const GEN_SIZE: usize = KEY_SIZE;
//! }
//!
//! impl NamedContext for AesContext {
//!     const NAME: &'static str = "AesContext";
//! }
//!
//! impl NamedContext for EdContext {
//!     const NAME: &'static str = "EdContext";
//! }
//!
//! type AesSecretKey = SecretData<VecData, AesContext>;
//! type EdSecretKey = SecretData<VecData, EdContext>;
//!
//! let aes_key0 = AesSecretKey::default();
//! let aes_key1 = AesSecretKey::default();
//!
//! let ed_key0 = EdSecretKey::default();
//! let ed_key1 = EdSecretKey::default();
//!
//! // We can compare two Ed25519 keys.
//! assert_eq!(&ed_key0, &ed_key0);
//! assert_ne!(&ed_key0, &ed_key1);
//!
//! // We can compare two AES keys.
//! assert_eq!(&aes_key0, &aes_key0);
//! assert_ne!(&aes_key0, &aes_key1);
//!
//! // The below code will NOT compile. This is a good thing. Reusing
//! // keys in different contexts is not only incorrect; it can be
//! // disastrous cryptographically, and can even end up revealing
//! // the secret keys themselves.
//! //
//! // Will error:
//! // assert_eq!(&aes_key0, &des_key0);
//! ```
//!
//! [a]: crate::hazardous::base::ArrayData
//! [b]: crate::hazardous::base::VecData
//! [c]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
//!

use crate::errors::UnknownCryptoError;
use core::{convert::TryFrom, marker::PhantomData};

#[cfg(feature = "safe_api")]
use std::fmt;

/// A simple container for bytes that are considered non-sensitive,
/// such as message authentication codes (MACs).
pub struct PublicData<B, C> {
    bytes: B,
    context: PhantomData<C>,
}

/// A simple container for bytes that contain sensitive information,
/// such as secret keys.
pub struct SecretData<B, C> {
    bytes: B,
    context: PhantomData<C>,
}

/// A small trait containing static information about the minimum and
/// maximum size (in bytes) of a type containing data.
pub trait Bounded {
    /// The largest number of bytes this type should be allowed to hold.
    const MIN: usize;

    /// The smallest number of bytes this type should be allowed to hold.
    const MAX: usize;
}

/// A trait to express the fact that a type can be (validly) generated
/// from secure random bytes, and the length of that generated type.
///
/// Note that `PublicData<B, C>` and `PrivateData<B, C>` implement
/// `Default` if and only if `C` implements `Generate`.
pub trait Generate: Bounded {
    /// The size in bytes of the type when generated randomly. Note that
    /// it is a logical error for `SIZE` to be less than
    /// `<Self as Bounded>::MIN` or `<Self as Bounded>::MAX`.
    const GEN_SIZE: usize;
}

/// A trait to give contexts a name. Used in Debug impls.
pub trait NamedContext {
    /// The type name that will appear in Debug impls.
    const NAME: &'static str;
}

/// A stricter version of `TryFrom<&[u8]>`. By implementing this trait for
/// a type `T`, we prove to the compiler that an *owned* `T` can be
/// generated from a byte slice, versus `TryFrom<&[u8]>` which may be
/// implemented even if the type holds a reference to the slice.
pub trait TryFromBytes: Sized {
    /// Convert from a byte slice to an owned `Data`.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError>;
}

impl<B, C> PublicData<B, C>
where
    B: TryFromBytes,
    C: Bounded,
{
    /// Create a `PublicData` from a byte slice. Only available when the context
    /// type parameter is [`Bounded`](crate::hazardous::base::Bounded).
    ///
    /// ## Errors
    /// This function will return an error if:
    ///   - The length of the given `slice` is not contained by the range
    ///     specified by `<C as Bounded>::MIN` and `<C as Bounded>::MAX`).
    ///   - The underlying storage type did not have capacity to hold the
    ///     given slice. In practice, this condition is usually a subset
    ///     of the above and does not need to be considered separately.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        if !(C::MIN..=C::MAX).contains(&slice.len()) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            bytes: B::try_from_bytes(slice)?,
            context: PhantomData,
        })
    }
}

impl<B, C> SecretData<B, C>
where
    B: TryFromBytes,
    C: Bounded,
{
    /// Create a `PrivateData` from a byte slice. Only available when the context
    /// type parameter is [`Bounded`](crate::hazardous::base::Bounded).
    ///
    /// ## Errors
    /// This function will return an error if:
    ///   - The length of the given `slice` is not contained by the range
    ///     specified by `<C as Bounded>::MIN` and `<C as Bounded>::MAX`).
    ///   - The underlying storage type did not have capacity to hold the
    ///     given slice. In practice, this condition is usually a subset
    ///     of the above and does not need to be considered separately.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        if !(C::MIN..=C::MAX).contains(&slice.len()) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            bytes: B::try_from_bytes(slice)?,
            context: PhantomData,
        })
    }
}

impl<B, C> PublicData<B, C>
where
    B: AsRef<[u8]>,
{
    /// Get the length of the contained byte slice.
    pub fn len(&self) -> usize {
        self.bytes.as_ref().len()
    }

    /// Check if the contained byte slice is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.as_ref().is_empty()
    }
}

impl<B, C> SecretData<B, C>
where
    B: AsRef<[u8]>,
{
    /// Get the length of the contained byte slice.
    pub fn len(&self) -> usize {
        self.bytes.as_ref().len()
    }

    /// Check if the contained byte slice is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.as_ref().is_empty()
    }
}

impl<B, K> AsRef<[u8]> for PublicData<B, K>
where
    B: AsRef<[u8]>,
{
    /// Get a reference to the underlying byte slice.
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<B, C> SecretData<B, C>
where
    B: AsRef<[u8]>,
{
    /// TODO: Grab docs for `unprotected_as_bytes` and insert here.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

#[cfg(feature = "safe_api")]
impl<B, C> Default for PublicData<B, C>
where
    B: TryFromBytes,
    C: Bounded + Generate,
{
    /// Use a CSPRNG to fill this type with secure random bytes.
    ///
    /// # Panic
    /// This will panic if the underyling call to
    /// [`secure_rand_bytes`](crate::util::secure_rand_bytes) fails;
    /// see its documentation for more info.
    fn default() -> Self {
        let mut data = vec![0u8; C::GEN_SIZE];
        crate::util::secure_rand_bytes(&mut data).unwrap();
        Self {
            bytes: B::try_from_bytes(data.as_slice()).unwrap(),
            context: PhantomData,
        }
    }
}

#[cfg(feature = "safe_api")]
impl<B, C> Default for SecretData<B, C>
where
    B: TryFromBytes,
    C: Bounded + Generate,
{
    /// Use a CSPRNG to fill this type with secure random bytes.
    ///
    /// # Panic
    /// This will panic if the underyling call to
    /// [`secure_rand_bytes`](crate::util::secure_rand_bytes) fails;
    /// see its documentation for more info.
    fn default() -> Self {
        let mut data = vec![0u8; C::GEN_SIZE];
        crate::util::secure_rand_bytes(&mut data).unwrap();
        Self {
            bytes: B::try_from_bytes(data.as_slice()).unwrap(),
            context: PhantomData,
        }
    }
}

/// Delegates to [`B::from_bytes`](crate::hazardous::base::TryFromBytes) under the hood.
impl<B, C> TryFrom<&[u8]> for PublicData<B, C>
where
    B: TryFromBytes,
{
    type Error = UnknownCryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: B::try_from_bytes(value).unwrap(),
            context: PhantomData,
        })
    }
}

/// Delegates to [`B::from_bytes`](crate::hazardous::base::TryFromBytes) under the hood.
impl<B, C> TryFrom<&[u8]> for SecretData<B, C>
where
    B: TryFromBytes,
{
    type Error = UnknownCryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: B::try_from_bytes(value).unwrap(),
            context: PhantomData,
        })
    }
}

// We implement this manually to skip over the PhantomData.
impl<B, C> PartialEq for PublicData<B, C>
where
    B: PartialEq<B>,
{
    fn eq(&self, other: &Self) -> bool {
        self.bytes.eq(&other.bytes)
    }
}

// We implement this manually to skip over the PhantomData.
// TODO: Should this be less general? Maybe only implement
// PartialEq<&Self> instead of any U: AsRef<u8>.
impl<B, C> PartialEq for SecretData<B, C>
where
    B: AsRef<[u8]>,
{
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.unprotected_as_bytes()
            .ct_eq(other.unprotected_as_bytes())
            .into()
    }
}

impl<B, C> PartialEq<[u8]> for SecretData<B, C>
where
    B: AsRef<[u8]>,
{
    fn eq(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        self.unprotected_as_bytes().ct_eq(other).into()
    }
}

#[cfg(feature = "safe_api")]
impl<B, C> fmt::Debug for PublicData<B, C>
where
    B: fmt::Debug,
    C: NamedContext,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ {}: {:?} }}", C::NAME, self.bytes)
    }
}

// We implement this manually to skip over the PhantomData.
#[cfg(feature = "safe_api")]
impl<B, C> fmt::Debug for SecretData<B, C>
where
    B: fmt::Debug,
    C: NamedContext,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ {}: {:?} }}", C::NAME, self.bytes)
    }
}

/// A convenient type for holding data with a static upper bound on
/// its size. The bytes are held with a static array (`[u8; MAX]`).
#[derive(Clone, Debug)]
pub struct ArrayData<const MAX: usize> {
    bytes: [u8; MAX],
    len: usize,
}

impl<const MAX: usize> TryFromBytes for ArrayData<MAX> {
    fn try_from_bytes(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        if slice.len() > MAX {
            return Err(UnknownCryptoError);
        }

        let mut bytes = [0u8; MAX];

        // PANIC: This is ok because we just checked that the length
        // was less than MAX above. Violating that condition is the
        // only thing that would cause this to panic.
        bytes
            .get_mut(0..slice.len())
            .unwrap()
            .copy_from_slice(slice);

        Ok(Self {
            bytes,
            len: slice.len(),
        })
    }
}

impl<const MAX: usize> AsRef<[u8]> for ArrayData<MAX> {
    fn as_ref(&self) -> &[u8] {
        // PANIC: This unwrap is ok because the type's len is checked at
        // construction time to be less than MAX.
        self.bytes.get(..self.len).unwrap()
    }
}

// NOTE: Using non-constant-time comparison here is okay becuase we don't use
// it for timing-sensitive comparisons. `VecData` is always wrapped in a `Data`
// struct which, when its "context" type parameter is marked as `Private`, will
// implement comparisons using constant-time operations.
impl<const MAX: usize> PartialEq for ArrayData<MAX> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.get(..self.len).eq(&other.bytes.get(..other.len))
    }
}

/// A convenient type for holding data in dynamically allocated buffer.
// TODO: Should we just use a `Vec` here? We could implement all of the
// same traits for a regular old Vec.
//
// NOTE: Deriving PartialEq here is okay becuase we don't use it for
// timing-sensitive comparisons. For sensitive types, `VecData` is always wrapped
// in a `PrivateData` which implements comparisons using constant-time operations.
#[cfg(feature = "safe_api")]
#[derive(Clone, Debug, PartialEq)]
pub struct VecData {
    bytes: Vec<u8>,
}

#[cfg(feature = "safe_api")]
impl TryFromBytes for VecData {
    fn try_from_bytes(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            bytes: slice.into(),
        })
    }
}

#[cfg(feature = "safe_api")]
impl AsRef<[u8]> for VecData {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
