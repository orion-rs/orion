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
use crate::generics::data::sealed::{Data, Sealed, TryFromBytes};
use core::fmt::Debug;
use core::marker::PhantomData;
use subtle::ConstantTimeEq;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// A sealed trait covering a generic newtype backed by a `Data`-impl over some `Primitive`.
pub trait TypeSpec: Sealed + Sized {
    #[doc(hidden)]
    /// Name to use in [`Debug`] impl.
    const NAME: &'static str;

    /// Data-backend, such as statically sized array, MAX-bound allocation with
    /// data on some range up to (incl.), [`Vec`]-based, etc.
    type TypeData: Data + TryFromBytes;

    #[doc(hidden)]
    /// The logic used to create an instance of [`Self::TypeData`]. Default logic
    /// are located within a specific [`Data`]-implementing struct, but can be overridden,
    /// if additional pre-processing is required.
    fn parse_bytes(bytes: &[u8]) -> Result<Self::TypeData, UnknownCryptoError> {
        Self::TypeData::try_from_bytes(bytes)
    }

    #[doc(hidden)]
    /// Default logic to get the amount of data stored. Can be overwritten if
    /// the internal representation does not match [`AsRef<[u8]>`] for example.
    ///
    /// NOTE: If overwritten, make sure it matches with [`Self::is_empty`] behavior.
    fn len(datatype: &Self::TypeData) -> usize {
        datatype.len()
    }

    #[doc(hidden)]
    /// Default logic to get the amount of data stored. Can be overwritten if
    /// the internal representation does not match [`AsRef<[u8]>`] for example.
    ///
    /// NOTE: If overwritten, make sure it matches with [`Self::len`]  behavior.
    fn is_empty(datatype: &Self::TypeData) -> bool {
        datatype.len() == 0
    }

    #[doc(hidden)]
    /// Default constant-time `PartialEq` impl. Can be overwritten if:
    /// - internal representation has additional requirements or
    ///    the bit-for-bit representation does not imply equality.
    ///
    /// [`Secret`] implements this as default internally.
    fn ct_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        lhs.as_ref().ct_eq(rhs).into()
    }

    #[doc(hidden)]
    /// Default variable-time `PartialEq` impl.Can be overwritten if:
    /// - internal representation has additional requirements or
    ///    the bit-for-bit representation does not imply equality.
    ///
    /// [`Public`] implements this as default internally.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        lhs.as_ref() == rhs
    }
}

/// Trait for a [`Secret`] type that may be instantiated using calls to a CSPRNG.
pub trait GenerateSecret: TypeSpec {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Use a CSPRNG to fill a new instance of this type with secure random bytes.
    ///
    /// # Errors:
    /// - Failure during the call to the OS CSPRNG.
    fn generate() -> Result<Secret<Self>, UnknownCryptoError>;
}

impl<T: TypeSpec + GenerateSecret> Secret<T> {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// See [`GenerateSecret::generate`].
    pub fn generate() -> Result<Self, UnknownCryptoError> {
        T::generate()
    }
}

/// Trait for a [`Public`] type that may be instantiated using calls to a CSPRNG.
pub trait GeneratePublic: TypeSpec {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Use a CSPRNG to fill a new instance of this type with secure random bytes.
    ///
    /// # Errors:
    /// - Failure during the call to the OS CSPRNG.
    fn generate() -> Result<Public<Self>, UnknownCryptoError>;
}

impl<T: TypeSpec + GeneratePublic> Public<T> {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// See [`GeneratePublic::generate`].
    pub fn generate() -> Result<Self, UnknownCryptoError> {
        T::generate()
    }
}

/// A key-pair trait, implemented over types holding a [`Secret`] key and its [`Public`] counterpart.
pub trait KP<PrivT: TypeSpec, PubT: TypeSpec>: Debug {
    // NOTE(brycx): This trait is not implemented over a generalized keytype, like [`Secret`] and [`Public`] are.
    // This is intentional, in the way that this should simply provide a basic API contract for a given keypair.
    // The purpose of a keypair, such as ML-KEM, is more specialized operations like key-caching that are not
    // as easily generalized over the two other generic keytypes. As such, keeping this as a trait only
    // is the intended way, to allow more specialized implementations and struct fields where needed.

    /// Return a reference to this key-pairs [`Secret`] key.
    fn private(&self) -> &Secret<PrivT>;

    /// Return a reference to this key-pairs [`Public`] key.
    fn public(&self) -> &Public<PubT>;
}

#[derive(Clone)]
/// A [`Public`] datatype.
///
/// # SECURITY:
/// - Provides a variable-time implementation of [`PartialEq`].
/// - Provides non-omitted implementation of [`Debug`].
pub struct Public<T: TypeSpec> {
    pub(crate) data: T::TypeData,
    _spec: PhantomData<T>,
}

#[derive(Clone)] // SECURITY: Requires T: Clone which should only be enabled selectively.
/// A [`Secret`] datatype.
///
/// # SECURITY:
/// - Provides a constant-time implementation of [`PartialEq`].
/// - Provides omitted implementation of [`Debug`].
/// - Provides a zeroizing [`Drop`] implementation if `"zeroize"` feature is enabled.
pub struct Secret<T: TypeSpec> {
    pub(crate) data: T::TypeData,
    _spec: PhantomData<T>,
}

impl<T: TypeSpec> Public<T> {
    pub(crate) fn from_data(data: T::TypeData) -> Self {
        Public {
            data,
            _spec: PhantomData,
        }
    }

    /// Return the length of the object.
    pub fn len(&self) -> usize {
        T::len(&self.data)
    }

    /// Return true if this object does not hold any data, false otherwise.
    ///
    /// # NOTE:
    /// This method should always return false, since there shouldn't be a way to create
    /// an empty instance of this object.
    pub fn is_empty(&self) -> bool {
        T::is_empty(&self.data)
    }
}

impl<T: TypeSpec> Secret<T> {
    pub(crate) fn from_data(data: T::TypeData) -> Self {
        Secret {
            data,
            _spec: PhantomData,
        }
    }

    /// Return the length of the object.
    pub fn len(&self) -> usize {
        T::len(&self.data)
    }

    /// Return true if this object does not hold any data, false otherwise.
    ///
    /// # NOTE: This method should always return false, since there shouldn't be a way to create
    /// an empty instance of this object.
    pub fn is_empty(&self) -> bool {
        T::is_empty(&self.data)
    }
}

// ------ Public trait impls

impl<T: TypeSpec> PartialEq for Public<T> {
    fn eq(&self, other: &Self) -> bool {
        T::vartime_partial_eq(&self.data, other.data.as_ref())
    }
}

impl<T: TypeSpec> Eq for Public<T> {}

impl<T: TypeSpec> PartialEq<[u8]> for Public<T> {
    fn eq(&self, other: &[u8]) -> bool {
        T::vartime_partial_eq(&self.data, other)
    }
}

impl<T: TypeSpec> PartialEq<&[u8]> for Public<T> {
    fn eq(&self, other: &&[u8]) -> bool {
        T::vartime_partial_eq(&self.data, other)
    }
}

impl<const N: usize, T: TypeSpec> PartialEq<&[u8; N]> for Public<T> {
    fn eq(&self, other: &&[u8; N]) -> bool {
        T::vartime_partial_eq(&self.data, *other)
    }
}

impl<T: TypeSpec> Debug for Public<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {:?}", T::NAME, self.data.as_ref())
    }
}

impl<T: TypeSpec> AsRef<[u8]> for Public<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: TypeSpec> TryFrom<&[u8]> for Public<T> {
    type Error = UnknownCryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Public::from_data(T::parse_bytes(bytes)?))
    }
}

impl<const N: usize, T: TypeSpec> TryFrom<&[u8; N]> for Public<T> {
    type Error = UnknownCryptoError;

    fn try_from(bytes: &[u8; N]) -> Result<Self, Self::Error> {
        Ok(Public::from_data(T::parse_bytes(bytes)?))
    }
}

#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
impl<T: TypeSpec> TryFrom<&Vec<u8>> for Public<T> {
    type Error = UnknownCryptoError;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// This type tries to serialize as a `&[u8]` would. Note that the serialized
/// type likely does not have the same protections that Orion provides, such
/// as constant-time operations. A good rule of thumb is to only serialize
/// these types for storage. Don't operate on the serialized types.
impl<T: TypeSpec> serde::Serialize for Public<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let bytes: &[u8] = self.data.as_ref();
        bytes.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// This type tries to deserialize as a `Vec<u8>` would. If it succeeds, the public data
/// will be built using `Self::try_from`.
///
/// Note that **this allocates** once to store the referenced bytes on the heap.
impl<'de, T: TypeSpec> serde::Deserialize<'de> for Public<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        TryFrom::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

// ------ Secret trait impls

impl<T: TypeSpec> Drop for Secret<T> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.data.memzero();
        }
    }
}

impl<T: TypeSpec> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        T::ct_partial_eq(&self.data, other.data.as_ref())
    }
}

impl<T: TypeSpec> Eq for Secret<T> {}

impl<T: TypeSpec> PartialEq<[u8]> for Secret<T> {
    fn eq(&self, other: &[u8]) -> bool {
        T::ct_partial_eq(&self.data, other)
    }
}

impl<T: TypeSpec> PartialEq<&[u8]> for Secret<T> {
    fn eq(&self, other: &&[u8]) -> bool {
        T::ct_partial_eq(&self.data, other)
    }
}

impl<const N: usize, T: TypeSpec> PartialEq<&[u8; N]> for Secret<T> {
    fn eq(&self, other: &&[u8; N]) -> bool {
        T::ct_partial_eq(&self.data, *other)
    }
}

impl<T: TypeSpec> Debug for Secret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {{***OMITTED***}}", T::NAME)
    }
}

impl<T: TypeSpec> TryFrom<&[u8]> for Secret<T> {
    type Error = UnknownCryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Secret::from_data(T::parse_bytes(bytes)?))
    }
}

impl<const N: usize, T: TypeSpec> TryFrom<&[u8; N]> for Secret<T> {
    type Error = UnknownCryptoError;

    fn try_from(bytes: &[u8; N]) -> Result<Self, Self::Error> {
        Ok(Secret::from_data(T::parse_bytes(bytes)?))
    }
}

#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
impl<T: TypeSpec> TryFrom<&Vec<u8>> for Secret<T> {
    type Error = UnknownCryptoError;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<T: TypeSpec> Secret<T> {
    #[inline]
    /// Return the object as byte slice. **Warning**: Should not be used unless strictly
    /// needed. This **breaks protections** that the type implements.
    pub fn unprotected_as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
