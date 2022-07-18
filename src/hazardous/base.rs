//! # Base
//!
//! This module provides convenient, type-parameterized byte-storage types
//! that can be used to quickly create newtypes for keys, digests, etc.
//! The goal is to support all the various cryptography types that are
//! basically just bags of bytes, but **absolutely cannot** afford to
//! be confused with one another.
//!
//! To that end, we define two structs — `Public` and `Secret` —
//! to act as generic containers for public and secret information, respectively.
//! These containers are each parameterized by the same two type parameters:
//! `B` (for "bytes") and `C` (for "context").
//!
//!
//! ## Parameter: `C` (Context)
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
//!
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::base::{Context, Generate, Secret, VecData};
//!
//! // Let's say you hypothetically had keys of two different types:
//!
//! const KEY_SIZE: usize = 32;
//!
//!
//! // AES 256-bit keys
//! struct AesContext;
//!
//! impl Context for AesContext {
//!     const NAME: &'static str = "Aes256Key";
//!     const MIN: usize = KEY_SIZE;
//!     const MAX: usize = KEY_SIZE;
//! }
//!
//! impl Generate for AesContext {
//!     const GEN_SIZE: usize = KEY_SIZE;
//! }
//!
//!
//! // Ed25519 256-bit keys
//! struct EdContext;
//!
//! impl Context for EdContext {
//!     const NAME: &'static str = "Ed256Key";
//!     const MIN: usize = KEY_SIZE;
//!     const MAX: usize = KEY_SIZE;
//! }
//!
//! impl Generate for EdContext {
//!     const GEN_SIZE: usize = KEY_SIZE;
//! }
//!
//!
//! type AesSecretKey = Secret<AesContext, VecData>;
//! type EdSecretKey = Secret<EdContext, VecData>;
//!
//! let aes_key0 = AesSecretKey::generate();
//! let aes_key1 = AesSecretKey::generate();
//!
//! let ed_key0 = EdSecretKey::generate();
//! let ed_key1 = EdSecretKey::generate();
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
//! # }
//! ```
//!
//! ## Parameter: `D` (Data)
//! `D` parameterizes over the **byte storage**. In practice, this is:
//!
//! - [`ArrayData`][a] for types that hold an amount of data known at
//! compile-time
//! - [`ArrayVecData`][d] for types that hold a compile-time
//! *maximum* amount of data
//! - [`VecData`][b] for types that hold a
//! dynamic amount of data, size known only at runtime.
//!
//! This allows us to implement methods on any type that can be converted
//! from or interpreted as a `&[u8]`. This also makes it possible to add
//! compatibility with, for example, the [`Bytes`][c] type for
//! zero-copy creation of cryptographic types arriving from the network.
//!
//! The following example demonstrates how we can create a type with various
//! types for storage.
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::base::{
//!     Secret, Context, Generate, ArrayData, VecData,
//! };
//!
//! struct Password;
//!
//! impl Context for Password {
//!     const NAME: &'static str = "Password";
//!     const MIN: usize = 8;
//!     const MAX: usize = usize::MAX;
//! }
//!
//! impl Generate for Password {
//!     const GEN_SIZE: usize = 32;
//! }
//!
//! type PasswordVec = Secret<Password, VecData>;
//! type PasswordArray = Secret<Password, ArrayData<32>>;
//! # }
//! ```
//!
//!
//! [a]: crate::hazardous::base::ArrayData
//! [b]: crate::hazardous::base::VecData
//! [c]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
//! [d]: crate::hazardous::base::VecData
//!

use crate::errors::UnknownCryptoError;
use core::{convert::TryFrom, fmt, marker::PhantomData};

pub use self::{array_data::ArrayData, array_vec_data::ArrayVecData, vec_data::VecData};

/// A simple container for bytes that are considered non-sensitive.
pub struct Public<C, D> {
    context: PhantomData<C>,
    data: D,
}

/// A simple container for bytes that contain sensitive information.
pub struct Secret<C, D: Data> {
    context: PhantomData<C>,
    data: D,
}

/// A small trait containing static information about the name, and
/// minimum and maximum size (in bytes) of a type containing data.
pub trait Context {
    /// The type name that will appear in Debug impls.
    const NAME: &'static str;

    /// The smallest number of bytes this type should be allowed to hold.
    const MIN: usize;

    // TODO: Should this be an exclusive bound?
    /// The largest number of bytes this type should be allowed to hold.
    const MAX: usize;
}

/// A trait to express the fact that a type can be (validly) generated
/// from secure random bytes, and the length of that generated type.
///
/// Note that `Public<C, D>` and `Secret<C, D>` implement
/// `Default` if and only if `C` implements `Generate`.
///
/// When a context type `C` implements `Generate`, the following methods
/// are implemented on `Public<B,C>` and `Secret<B,C>`. See those methods'
/// documentation for usage information.
///
/// - [`Public::generate`](Public::generate)
/// - [`Secret::generate`](Secret::generate)
/// - [`Public::generate_with_size`](Public::generate_with_size)
/// - [`Secret::generate_with_size`](Secret::generate_with_size)
pub trait Generate: Context {
    /// The size in bytes of the type when generated randomly. Note that
    /// it is a logical error for `GEN_SIZE` to be less than
    /// `<Self as Context>::MIN` or greater than `<Self as Context>::MAX`.
    const GEN_SIZE: usize;
}

/// A trait indicating that some basic operations on byte-slice-like types
/// are available.
pub trait Data: AsRef<[u8]> + AsMut<[u8]> + TryFromBytes {}

/// A stricter version of `TryFrom<&[u8]>`. By implementing this trait for
/// a type `T`, we prove to the compiler that an *owned* `T` can be
/// generated from a byte slice, versus `TryFrom<&[u8]>` which may be
/// implemented even if the type holds a reference to the slice.
pub trait TryFromBytes: Sized {
    /// Convert from a byte slice to an owned `Data`.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError>;
}

impl<'a, C, D> Drop for Secret<C, D>
where
    D: Data,
{
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.as_mut().iter_mut().zeroize();
    }
}

impl<C, D> Public<C, D>
where
    C: Context,
    D: Data,
{
    /// Create a `Public` from a byte slice.
    ///
    /// ## Errors
    /// This function will return an error if:
    ///   - The length of the given `slice` is not contained by the range
    ///     specified by `<C as Context>::MIN` and `<C as Context>::MAX`).
    ///   - The underlying storage type did not have capacity to hold the
    ///     given slice. In practice, this condition is usually a subset
    ///     of the above and does not need to be considered separately.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        if !(C::MIN..=C::MAX).contains(&slice.len()) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            data: D::try_from_bytes(slice)?,
            context: PhantomData,
        })
    }

    /// Get the length of the contained byte slice.
    pub fn len(&self) -> usize {
        self.data.as_ref().len()
    }

    /// Check if the contained byte slice is empty.
    pub fn is_empty(&self) -> bool {
        self.data.as_ref().is_empty()
    }

    /// Get a reference to the inner byte slice.
    pub fn data(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<C, D> Secret<C, D>
where
    C: Context,
    D: Data,
{
    /// Create a `Secret` from a byte slice. Only available when the context
    /// type parameter is [`Context`](crate::hazardous::base::Context).
    ///
    /// ## Errors
    /// This function will return an error if:
    ///   - The length of the given `slice` is not contained by the range
    ///     specified by `<C as Context>::MIN` and `<C as Context>::MAX`).
    ///   - The underlying storage type did not have capacity to hold the
    ///     given slice. In practice, this condition is usually a subset
    ///     of the above and does not need to be considered separately.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        if !(C::MIN..=C::MAX).contains(&slice.len()) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            context: PhantomData,
            data: D::try_from_bytes(slice)?,
        })
    }

    /// Get the length of the contained byte slice.
    pub fn len(&self) -> usize {
        self.data.as_ref().len()
    }

    /// Check if the contained byte slice is empty.
    pub fn is_empty(&self) -> bool {
        self.data.as_ref().is_empty()
    }

    /// Return the object as byte slice. __**Warning**__: Should not be
    /// used unless strictly needed. This __**breaks protections**__ that
    /// the type implements.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<C, D> AsRef<[u8]> for Public<C, D>
where
    C: Context,
    D: Data,
{
    /// Get a reference to the underlying byte slice.
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

#[cfg(feature = "safe_api")]
impl<C, D> Public<C, D>
where
    C: Context + Generate,
    D: Data,
{
    /// Use a CSPRNG to fill a new instance of this type with secure random bytes.
    ///
    /// # Panic
    /// This will panic if the underyling call to
    /// [`secure_rand_bytes`](crate::util::secure_rand_bytes) fails;
    /// see its documentation for more info.
    pub fn generate() -> Self {
        let mut data = vec![0u8; C::GEN_SIZE];
        crate::util::secure_rand_bytes(&mut data).unwrap();
        Self {
            data: D::try_from_bytes(data.as_slice()).unwrap(),
            context: PhantomData,
        }
    }

    /// Use a CSPRNG to fill a new instance of this type with secure random bytes.
    ///
    /// # Errors
    /// - If the passed `size` is less than `<C as Context>::MIN`.
    /// - If the passed `size` is greater than `<C as Context>::MAX`.
    /// - If the configured data storage parameter cannot hold `size` bytes.
    ///
    /// # Panic
    /// This will panic if the underyling call to
    /// [`secure_rand_bytes`](crate::util::secure_rand_bytes) fails;
    /// see its documentation for more info.
    pub fn generate_with_size(size: usize) -> Result<Self, UnknownCryptoError> {
        if size < <C>::MIN || size > <C as Context>::MAX {
            return Err(UnknownCryptoError);
        }

        let mut data = vec![0u8; size];
        crate::util::secure_rand_bytes(&mut data).unwrap();

        Ok(Self {
            data: D::try_from_bytes(data.as_slice())?,
            context: PhantomData,
        })
    }
}

#[cfg(feature = "safe_api")]
impl<C, D> Secret<C, D>
where
    C: Context + Generate,
    D: Data,
{
    /// Use a CSPRNG to fill a new instance of this type with a given number
    /// of secure random bytes.
    ///
    /// # Panic
    /// This will panic if the underyling call to
    /// [`secure_rand_bytes`](crate::util::secure_rand_bytes) fails;
    /// see its documentation for more info.
    pub fn generate() -> Self {
        let mut data = vec![0u8; C::GEN_SIZE];
        crate::util::secure_rand_bytes(&mut data).unwrap();
        Self {
            data: D::try_from_bytes(data.as_slice()).unwrap(),
            context: PhantomData,
        }
    }

    /// Use a CSPRNG to fill a new instance of this type with a given number
    /// of secure random bytes.
    ///
    /// # Errors
    /// - If the passed `size` is less than `<C as Context>::MIN`.
    /// - If the passed `size` is greater than `<C as Context>::MAX`.
    /// - If the configured data storage parameter cannot hold `size` bytes.
    ///
    /// # Panic
    /// This will panic if the underyling call to
    /// [`secure_rand_bytes`](crate::util::secure_rand_bytes) fails;
    /// see its documentation for more info.
    pub fn generate_with_size(size: usize) -> Result<Self, UnknownCryptoError> {
        if size < <C>::MIN || size > <C as Context>::MAX {
            return Err(UnknownCryptoError);
        }

        let mut data = vec![0u8; size];
        crate::util::secure_rand_bytes(&mut data).unwrap();

        Ok(Self {
            data: D::try_from_bytes(data.as_slice())?,
            context: PhantomData,
        })
    }
}

/// Delegates to [`B::try_from_bytes`](crate::hazardous::base::TryFromBytes) under the hood.
impl<C, D> TryFrom<&[u8]> for Public<C, D>
where
    C: Context,
    D: TryFromBytes,
{
    type Error = UnknownCryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            data: D::try_from_bytes(value).unwrap(),
            context: PhantomData,
        })
    }
}

/// Delegates to [`B::try_from_bytes`](crate::hazardous::base::TryFromBytes) under the hood.
impl<C, D> TryFrom<&[u8]> for Secret<C, D>
where
    C: Context,
    D: Data,
{
    type Error = UnknownCryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            data: D::try_from_bytes(value).unwrap(),
            context: PhantomData,
        })
    }
}

// We define `PartialEq` such that we can compare only with
// other `Public` that have the same "context".
impl<C, D> PartialEq for Public<C, D>
where
    C: Context,
    D: Data,
{
    fn eq(&self, other: &Self) -> bool {
        self.data.as_ref().eq(other.data.as_ref())
    }
}

impl<C, D> PartialEq<[u8]> for Public<C, D>
where
    C: Context,
    D: Data,
{
    fn eq(&self, other: &[u8]) -> bool {
        self.data.as_ref().eq(other)
    }
}

// We define `PartialEq` such that we can compare only with
// other `Public` that have the same "context".
impl<C, D> PartialEq for Secret<C, D>
where
    C: Context,
    D: Data,
{
    fn eq(&self, other: &Secret<C, D>) -> bool {
        use subtle::ConstantTimeEq;
        self.unprotected_as_bytes()
            .ct_eq(other.unprotected_as_bytes())
            .into()
    }
}

impl<C, D> PartialEq<[u8]> for Secret<C, D>
where
    C: Context,
    D: Data,
{
    fn eq(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        self.unprotected_as_bytes().ct_eq(other).into()
    }
}

impl<C, D> fmt::Debug for Public<C, D>
where
    C: Context,
    D: Data,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", C::NAME, self.data.as_ref())
    }
}

impl<C, D> fmt::Debug for Secret<C, D>
where
    C: Context,
    D: Data,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: REDACTED", C::NAME)
    }
}

mod array_data {
    use super::{Data, TryFromBytes};
    use crate::errors::UnknownCryptoError;
    use std::convert::TryFrom;

    /// A convenient type for holding data with a statically known size.
    /// The bytes are held with a static array (`[u8; LEN]`).
    //
    // NOTE: Deriving PartialEq here is okay becuase we don't use it for
    // timing-sensitive comparisons. `ArrayData` is always wrapped in a
    // [`Secret`](crate::hazardous::base::Secret) if it's used for
    // sensitive information, which implements constant-time comparisons.
    //
    // Same thing for Debug: the Secret wrapper will handle it..
    #[derive(Clone, Debug, PartialEq)]
    pub struct ArrayData<const LEN: usize> {
        pub(crate) bytes: [u8; LEN],
    }

    impl<const LEN: usize> Data for ArrayData<LEN> {}

    impl<const LEN: usize> TryFromBytes for ArrayData<LEN> {
        fn try_from_bytes(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
            let bytes = <[u8; LEN]>::try_from(slice).map_err(|_| UnknownCryptoError)?;
            Ok(Self { bytes })
        }
    }

    impl<const LEN: usize> AsRef<[u8]> for ArrayData<LEN> {
        fn as_ref(&self) -> &[u8] {
            self.bytes.as_slice()
        }
    }

    impl<const LEN: usize> AsMut<[u8]> for ArrayData<LEN> {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.bytes
        }
    }
}

mod array_vec_data {
    use super::{Data, TryFromBytes};
    use crate::errors::UnknownCryptoError;

    /// A convenient type for holding data with a static upper bound on
    /// its size. The bytes are held with a static array (`[u8; MAX]`).
    #[derive(Clone, Debug)]
    pub struct ArrayVecData<const MAX: usize> {
        pub(crate) bytes: [u8; MAX],
        pub(crate) len: usize,
    }

    impl<const MAX: usize> Data for ArrayVecData<MAX> {}

    impl<const MAX: usize> TryFromBytes for ArrayVecData<MAX> {
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

    impl<const MAX: usize> AsRef<[u8]> for ArrayVecData<MAX> {
        fn as_ref(&self) -> &[u8] {
            // PANIC: This unwrap is ok because the type's len is checked at
            // construction time to be less than MAX.
            self.bytes.get(..self.len).unwrap()
        }
    }

    impl<const MAX: usize> AsMut<[u8]> for ArrayVecData<MAX> {
        fn as_mut(&mut self) -> &mut [u8] {
            // PANIC: This unwrap is ok because the type's len is checked at
            // construction time to be less than MAX.
            self.bytes.get_mut(..self.len).unwrap()
        }
    }
}

// // NOTE: Using non-constant-time comparison here is okay becuase we don't
// // use it for timing-sensitive comparisons. `ArrayVecData` is always wrapped
// // in a [`Secret`](crate::hazardous::base::Secret) if it's used for
// // sensitive information, which implements constant-time comparisons.
// //
// // Same thing for Debug: the Secret wrapper will handle it.
// impl<const MAX: usize> PartialEq for ArrayVecData<MAX> {
//     fn eq(&self, other: &Self) -> bool {
//         self.bytes.get(..self.len).eq(&other.bytes.get(..other.len))
//     }
// }

mod vec_data {
    use super::{Data, TryFromBytes};
    use crate::errors::UnknownCryptoError;
    use std::convert::TryFrom;

    /// A convenient type for holding data in dynamically allocated buffer.
    // TODO: Should we just use a `Vec` here? We could implement all of the
    // same traits for a regular old Vec.
    //
    // NOTE: Deriving PartialEq here is okay becuase we don't use it for
    // timing-sensitive comparisons. `VecData` is always wrapped in a
    // [`Secret`](crate::hazardous::base::Secret) if it's used for
    // sensitive information, which implements constant-time comparisons.
    //
    // Same thing for Debug: the Secret wrapper will handle it..
    #[cfg(feature = "safe_api")]
    #[derive(Clone, Debug, PartialEq)]
    pub struct VecData {
        pub(crate) bytes: Vec<u8>,
    }

    #[cfg(feature = "safe_api")]
    impl Data for VecData {}

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

    #[cfg(feature = "safe_api")]
    impl AsMut<[u8]> for VecData {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.bytes
        }
    }

    #[cfg(feature = "safe_api")]
    impl<'a> TryFrom<&'a [u8]> for VecData {
        type Error = UnknownCryptoError;

        fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
            let bytes = Vec::from(value);
            Ok(VecData { bytes })
        }
    }
}
