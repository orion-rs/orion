use crate::errors::UnknownCryptoError;
use std::{convert::TryFrom, fmt, marker::PhantomData};

/// Marker trait for when a type contains some sensitive information.
pub trait Secret {}

/// Marker trait for when a type contains only non-sensitive information.
/// Be careful if implementing this trait on your own. It cannot
/// cause memory unsafety, and so is not marked `unsafe`. Implementing
/// it can, however, lead to data types containing sensitive data ending
/// up with APIs meant only for types containing only non-sensitive data.
pub trait Public {}

/// A small trait containing static information about the minimum and
/// maximum size (in bytes) of a type containing data.
pub trait Bounded {
    /// The largest number of bytes this type should be allowed to hold.
    const MIN: Option<usize> = None;

    /// The smallest number of bytes this type should be allowed to hold.
    const MAX: Option<usize> = None;
}

/// A generic holder for types that are basically just a bag of bytes
/// with extra semantic meaning and restriction on top. We parameterize
/// over the byte storage with parameter `B`. We parameterize over the
/// API-level semantics of the type with phantom type `K`.
#[derive(Clone)]
pub struct Data<B, K> {
    bytes: B,
    phantom: PhantomData<K>,
}

impl<'a, B, K> Data<B, K>
where
    B: TryFrom<&'a [u8], Error = UnknownCryptoError>,
    K: Bounded,
{
    /// TODO
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, B::Error> {
        let min = K::MIN.unwrap_or(0);
        let max = K::MAX.unwrap_or(usize::MAX);
        if slice.len() < min || slice.len() > max {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            bytes: B::try_from(slice)?,
            phantom: PhantomData,
        })
    }
}

impl<'a, B, K> Data<B, K>
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

impl<'a, B, K> AsRef<[u8]> for Data<B, K>
where
    B: AsRef<[u8]>,
    K: Public,
{
    /// Get a reference to the underlying byte slice.
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<'a, B, K> Data<B, K>
where
    B: AsRef<[u8]>,
    K: Secret,
{
    /// TODO: Grab docs for `unprotected_as_bytes` and insert here.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

// We implement this manually to skip over the PhantomData.
impl<B, K> PartialEq for Data<B, K>
where
    B: PartialEq<B>,
{
    fn eq(&self, other: &Self) -> bool {
        self.bytes.eq(&other.bytes)
    }
}

// We implement this manually to skip over the PhantomData.
impl<B, K> fmt::Debug for Data<B, K>
where
    B: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes.fmt(f)
    }
}

/// A convenient type for holding data with a static upper bound on
/// its size. The bytes are held with a static array.
#[derive(Clone, Debug)]
pub struct StaticData<const MAX: usize> {
    bytes: [u8; MAX],
    len: usize,
}

impl<const MAX: usize> TryFrom<&[u8]> for StaticData<MAX> {
    type Error = UnknownCryptoError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
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

impl<const MAX: usize> AsRef<[u8]> for StaticData<MAX> {
    fn as_ref(&self) -> &[u8] {
        // PANIC: This unwrap is ok because the type's len is checked at
        // construction time to be less than MAX.
        self.bytes.get(..self.len).unwrap()
    }
}

impl<const MAX: usize> PartialEq for StaticData<MAX> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.get(..self.len).eq(&other.bytes.get(..other.len))
    }
}
