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

use crate::{
    errors::UnknownCryptoError,
    generics::data::sealed::{Data, TryFromBytes},
};

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub(crate) mod sealed {
    use crate::errors::UnknownCryptoError;

    /// Sealing marker trait for any public/private newtypes based on const-generics
    /// such that they cannot be implemented outside the library, given that [`Context`]
    /// requires [`Sealed`].
    pub trait Sealed {}

    pub trait TryFromBytes: Sized {
        fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError>;
    }

    /// A datatype that can be used as the internal backing of a newtype.
    pub trait Data: AsRef<[u8]> + AsMut<[u8]> + TryFromBytes + Sealed {
        /// Return the amount of data stored.
        fn len(&self) -> usize;

        /// Return `true` if no data is stored, `false` otherwise.
        fn is_empty(&self) -> bool;

        /// Create a new instance with `size`.
        fn new(size: usize) -> Result<Self, UnknownCryptoError>;

        #[cfg(feature = "zeroize")]
        /// Zero our the data stored.
        fn memzero(&mut self);
    }
}

#[derive(Debug, Clone)]
/// A newtype data-type that represents static constant size of [`u8`]s.
/// This is for types that only have _one_ valid size.
///
/// SECURITY:
/// While these types do derive non-constant time or plain debug impls, these
/// should *NEVER* be exposed publicly anyway. The implementations of [`crate::generics::Public`]/[`crate::generics::Secret`]
/// will define protections for their type.
pub struct ByteArrayData<const LEN: usize> {
    pub(crate) bytes: [u8; LEN],
}

impl<const LEN: usize> sealed::Sealed for ByteArrayData<LEN> {}

impl<const LEN: usize> AsRef<[u8]> for ByteArrayData<LEN> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const LEN: usize> AsRef<[u8; LEN]> for ByteArrayData<LEN> {
    fn as_ref(&self) -> &[u8; LEN] {
        &self.bytes
    }
}

impl<const LEN: usize> AsMut<[u8]> for ByteArrayData<LEN> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<const LEN: usize> AsMut<[u8; LEN]> for ByteArrayData<LEN> {
    fn as_mut(&mut self) -> &mut [u8; LEN] {
        &mut self.bytes
    }
}

impl<const LEN: usize> From<[u8; LEN]> for ByteArrayData<LEN> {
    fn from(value: [u8; LEN]) -> Self {
        Self { bytes: value }
    }
}

impl<const LEN: usize> TryFromBytes for ByteArrayData<LEN> {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            // NOTE: Length check here is implicit to const-def of LEN.
            bytes: bytes.try_into().map_err(|_| UnknownCryptoError)?,
        })
    }
}

impl<const LEN: usize> Data for ByteArrayData<LEN> {
    fn len(&self) -> usize {
        debug_assert_eq!(self.bytes.len(), LEN);
        LEN
    }

    fn is_empty(&self) -> bool {
        LEN == 0
    }

    fn new(_size: usize) -> Result<Self, UnknownCryptoError> {
        debug_assert_eq!(_size, LEN);
        Ok(Self { bytes: [0u8; LEN] })
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        self.bytes.iter_mut().zeroize();
    }
}

#[derive(Debug, Clone)]
/// A newtype data-type that represents array of bytes within a `MAX` known range.
/// This is for types that have a valid size within a stack-allocatable range, e.g. BLAKE2b secret keys.
///
/// It always allocates `MAX`, but keeps an extra length field to keep track of what the original value was.
/// If the provided byte slice was less than `MAX`, then the required bytes from left to right are returned.
///
/// SECURITY:
/// While these types do derive non-constant time or omitted debug impls, these
/// should *NEVER* be exposed publicly anyway. The implementations of [`crate::generics::Public`]/[`crate::generics::Secret`]
/// will define protections for their type.
pub struct ByteArrayVecData<const MIN: usize, const MAX: usize> {
    pub(crate) bytes: [u8; MAX],
    pub(crate) len: usize,
}

impl<const MIN: usize, const MAX: usize> sealed::Sealed for ByteArrayVecData<MIN, MAX> {}

impl<const MIN: usize, const MAX: usize> AsRef<[u8]> for ByteArrayVecData<MIN, MAX> {
    fn as_ref(&self) -> &[u8] {
        self.bytes[..self.len].as_ref()
    }
}

impl<const MIN: usize, const MAX: usize> AsMut<[u8]> for ByteArrayVecData<MIN, MAX> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

impl<const MIN: usize, const MAX: usize> TryFromBytes for ByteArrayVecData<MIN, MAX> {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        if !(MIN..=MAX).contains(&bytes.len()) {
            return Err(UnknownCryptoError);
        }

        let mut ret = Self {
            bytes: [0u8; MAX],
            len: bytes.len(),
        };

        ret.bytes[..bytes.len()].copy_from_slice(bytes);

        Ok(ret)
    }
}

impl<const MIN: usize, const MAX: usize> Data for ByteArrayVecData<MIN, MAX> {
    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn new(size: usize) -> Result<Self, UnknownCryptoError> {
        if !(MIN..=MAX).contains(&size) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            bytes: [0u8; MAX],
            len: size,
        })
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        self.bytes.iter_mut().zeroize();
    }
}

#[derive(Debug, Clone)]
#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
/// A newtype data-type that represents heap-allocated [`Vec<u8>`].
///
/// The maximum size for [`ByteVecData`] is [`isize::MAX`].
///
/// SECURITY:
/// While these types do derive non-constant time or omitted debug impls, these
/// should *NEVER* be exposed publicly anyway. The implementations of [`crate::generics::Public`]/[`crate::generics::Secret`]
/// will define protections for their type.
pub struct ByteVecData {
    pub(crate) bytes: Vec<u8>,
}

#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
impl sealed::Sealed for ByteVecData {}

#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
impl AsRef<[u8]> for ByteVecData {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
impl AsMut<[u8]> for ByteVecData {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
impl TryFromBytes for ByteVecData {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        // See issue on `isize` limit: https://github.com/orion-rs/orion/issues/130
        if bytes.is_empty() || bytes.len() > (isize::MAX as usize) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            bytes: Vec::from(bytes),
        })
    }
}

#[cfg(any(feature = "safe_api", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "safe_api", feature = "alloc"))))]
impl Data for ByteVecData {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn new(size: usize) -> Result<Self, UnknownCryptoError> {
        // See issue on `isize` limit: https://github.com/orion-rs/orion/issues/130
        if size == 0 || size > (isize::MAX as usize) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            bytes: vec![0u8; size],
        })
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        self.bytes.iter_mut().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)] // panics with debug_assertions.
    fn force_internal_new_size_contract() {
        // ByteArrayData::new() does not use the size argument. It uses LEN
        // directly. But if this should ever change or simply for the reason
        // of keeping things sane, we require the size argument then be LEN.
        assert!(ByteArrayData::<4>::new(3).is_ok());
    }

    #[test]
    fn test_arraydata_u8() {
        assert!(ByteArrayData::<4>::try_from_bytes(&[0u8; 4]).is_ok());
        assert!(ByteArrayData::<4>::try_from_bytes(&[0u8; 3]).is_err());
        assert!(ByteArrayData::<4>::try_from_bytes(&[0u8; 5]).is_err());
        assert!(ByteArrayData::<4>::new(4).is_ok());
        assert_eq!(&ByteArrayData::<4>::new(4).unwrap().as_ref(), &[0u8; 4]);

        let mut data = ByteArrayData::<4>::try_from_bytes(&[1u8; 4]).unwrap();
        assert_eq!(data.bytes, [1u8; 4]);
        assert_eq!(data.as_ref(), [1u8; 4]); // AsRef<[u8]>
        assert_eq!(data.as_mut(), [1u8; 4]); // AsMut<[u8]>
        assert_eq!(
            <ByteArrayData<4> as AsRef<[u8; 4]>>::as_ref(&data),
            &[1u8; 4]
        ); // AsRef<[; N]>
        assert_eq!(
            <ByteArrayData<4> as AsMut<[u8; 4]>>::as_mut(&mut data),
            &[1u8; 4]
        ); // AsRef<[; N]>
        assert_eq!(data.len(), 4);
        assert!(!data.is_empty());

        #[cfg(feature = "zeroize")]
        {
            data.memzero();
            assert_eq!(data.bytes, [0u8; 4]);
        }
    }

    #[test]
    fn test_arrayvecdata_u8() {
        assert!(ByteArrayVecData::<1, 4>::try_from_bytes(&[0u8; 0]).is_err());
        assert!(ByteArrayVecData::<1, 4>::try_from_bytes(&[0u8; 1]).is_ok());
        assert!(ByteArrayVecData::<1, 4>::try_from_bytes(&[0u8; 4]).is_ok());
        assert!(ByteArrayVecData::<1, 4>::try_from_bytes(&[0u8; 3]).is_ok());
        assert!(ByteArrayVecData::<1, 4>::try_from_bytes(&[0u8; 5]).is_err());
        assert!(ByteArrayVecData::<1, 4>::new(0).is_err());
        assert!(ByteArrayVecData::<1, 4>::new(1).is_ok());
        assert!(ByteArrayVecData::<1, 4>::new(4).is_ok());
        assert!(ByteArrayVecData::<1, 4>::new(3).is_ok());
        assert!(ByteArrayVecData::<1, 4>::new(5).is_err());

        assert_eq!(
            ByteArrayVecData::<1, 4>::new(4).unwrap().as_ref(),
            &[0u8; 4]
        );

        let mut data = ByteArrayVecData::<1, 4>::try_from_bytes(&[1u8; 4]).unwrap();
        assert_eq!(data.bytes, [1u8; 4]);
        assert_eq!(data.as_ref(), &[1u8; 4]);
        assert_eq!(data.as_mut(), &mut [1u8; 4]);
        assert_eq!(data.len(), 4);
        assert!(!data.is_empty());

        #[cfg(feature = "zeroize")]
        {
            data.memzero();
            assert_eq!(data.bytes, [0u8; 4]);
        }

        let mut data = ByteArrayVecData::<1, 4>::try_from_bytes(&[1u8; 3]).unwrap();
        assert_eq!(&data.bytes[..3], &[1u8; 3]);
        assert_eq!(&data.bytes[3], &0u8);
        assert_eq!(data.as_ref(), &[1u8; 3]);
        assert_eq!(data.as_mut(), &mut [1u8; 3]);
        assert_eq!(data.len(), 3);
        assert!(!data.is_empty());

        #[cfg(feature = "zeroize")]
        {
            // memzero() zeroes all bytes, even if the full range wasn't used.
            data.memzero();
            assert_eq!(data.bytes, [0u8; 4]);
        }
    }

    #[test]
    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_vecdata_u8() {
        assert!(ByteVecData::try_from_bytes(&[0u8; 0]).is_err());
        assert!(ByteVecData::try_from_bytes(&[0u8; 4]).is_ok());
        assert!(ByteVecData::try_from_bytes(&[0u8; 3]).is_ok());
        assert!(ByteVecData::try_from_bytes(&[0u8; 5]).is_ok());
        assert!(ByteVecData::new(0).is_err());
        assert!(ByteVecData::new(4).is_ok());
        assert!(ByteVecData::new(3).is_ok());
        assert!(ByteVecData::new(5).is_ok());

        assert_eq!(ByteVecData::new(4).unwrap().as_ref(), &[0u8; 4]);

        let mut data = ByteVecData::try_from_bytes(&[1u8; 4]).unwrap();
        assert_eq!(data.bytes, [1u8; 4]);
        assert_eq!(data.as_ref(), &[1u8; 4]);
        assert_eq!(data.as_mut(), &mut [1u8; 4]);
        assert_eq!(data.len(), 4);
        assert!(!data.is_empty());

        #[cfg(feature = "zeroize")]
        {
            data.memzero();
            assert_eq!(data.bytes, [0u8; 4]);
        }

        let mut data = ByteVecData::try_from_bytes(&[1u8; 3]).unwrap();
        assert_eq!(data.bytes, [1u8; 3]);
        assert_eq!(data.as_ref(), &[1u8; 3]);
        assert_eq!(data.as_mut(), &mut [1u8; 3]);
        assert_eq!(data.len(), 3);
        assert!(!data.is_empty());

        #[cfg(feature = "zeroize")]
        {
            // memzero() zeroes all bytes, even if the full range wasn't used.
            data.memzero();
            assert_eq!(data.bytes, [0u8; 3]);
        }
    }
}
