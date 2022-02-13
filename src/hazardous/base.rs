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

/// A trait to express the fact that a type can be (validly) generated
/// from secure random bytes, and the length of that generated type.
///
/// Note that `Data<B, C>` implements `Default` if and only if
/// `C` implements  
pub trait Generate: Bounded {
    /// The size in bytes of the type when generated randomly. Note that
    /// it is a logical error for `SIZE` to be less than
    /// `<Self as Bounded>::MIN` or `<Self as Bounded>::MAX`.
    const SIZE: usize;
}

/// A generic holder for types that are basically just a bag of bytes
/// with extra semantic meaning and restriction on top. There are two
/// important type parameters to consider:
///
/// ## Parameter: `B` (bytes)
/// `B` parameterizes over the **byte storage**. In practice, this is
/// either a [`ArrayData`][a] or [`VecData`][b]. This allows us
/// to implement methods on any type that can be converted from
/// or interpreted as a `&[u8]`. This makes it possible to add
/// compatibility with, for example, the [`Bytes`][c] type for
/// zero-copy creation of cryptographic types arriving from the network.
///
/// TODO: Add example showing how we can use different byte storages.
///
/// ## Parameter: `C` (context)
/// `C` parameterizes over the **context** of the data. Primarily,
/// this allows us to leverage the type system to protect against
/// misuse of keys (e.g. using one key for two different primitives).
/// In practice, `C` will be a unit struct named after an intended
/// use of the data, such as `chacha::KeyContext`. This will prevent
/// its use in a function that requires instead `aes::KeyContext`.
///
/// TODO: Add example showing how we cannnot misuse two Data types
/// with different `C` (context) types.
///
/// ```rust
/// use orion::hazardous::base::{Bounded, Data, Generate};
///
/// // Let's say you hypothetically had keys of two different types:
/// // AES and DES secret keys. (Please don't use DES for anything real.)
/// struct DesContext;
/// struct AesContext;
///
/// impl Bounded for DesContext {
///     const MIN: usize = 32;
///     const MAX: usize = 32;
/// }
///
/// impl Bounded for AesContext {
///     const MIN: usize = 32;
///     const MAX: usize = 32;
/// }
///
/// impl Generate for DesContext {
///     const SIZE: usize = 32;
/// }
///
/// impl Generate for AesContext {
///     const SIZE: usize = 32;
/// }
///
/// let des_key0: Data<Vec<u8>, DesContext> = Data::default();
/// let des_key1: Data<Vec<u8>, DesContext> = Data::default();
///
/// let aes_key0: Data<Vec<u8>, AesContext> = Data::default();
/// let aes_key1: Data<Vec<u8>, AesContext> = Data::default();
///
/// // We can compare two DES keys.
/// assert_eq!(&des_key0, &des_key0);
/// assert_ne!(&des_key0, &des_key1);
///
/// // We can compare two DES keys.
/// assert_eq!(&aes_key0, &aes_key0);
/// assert_ne!(&aes_key0, &aes_key1);
///
/// // The below code will not compile. This is a good thing. Reusing
/// // keys in different contexts is not only incorrect; it can be
/// // disastrous cryptographically, and can even end up revealing
/// // the secret keys themselves.
/// //
/// // Will error:
/// // assert_eq!(&aes_key0, &des_key0);
/// ```
///
/// [a]: crate::hazardous::base::ArrayData
/// [b]: crate::hazardous::base::VecData
/// [c]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
///
pub struct Data<B, C> {
    bytes: B,
    context: PhantomData<C>,
}

impl<'a, B, C> Data<B, C>
where
    B: TryFrom<&'a [u8], Error = UnknownCryptoError>,
    C: Bounded,
{
    /// Create `Data` from a byte slice. Only available when the context
    /// type parameter is [`Bounded`](crate::hazardous::base::Bounded).
    ///
    /// ## Errors
    /// This function will return an error if:
    ///   - The length of the given `slice` is not contained by the range
    ///     specified by `<C as Bounded>::MIN` and `<C as Bounded>::MAX`).
    ///   - The underlying storage type did not have capacity to hold the
    ///     given slice. In practice, this condition is usually a subset
    ///     of the above and does not need to be considered separately.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, B::Error> {
        let min = C::MIN.unwrap_or(0);
        let max = C::MAX.unwrap_or(usize::MAX);
        if !(min..=max).contains(&slice.len()) {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            bytes: B::try_from(slice)?,
            context: PhantomData,
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
/// its size. The bytes are held with a static array (`[u8; MAX]`).
#[derive(Clone, Debug)]
pub struct ArrayData<const MAX: usize> {
    bytes: [u8; MAX],
    len: usize,
}

impl<const MAX: usize> TryFrom<&[u8]> for ArrayData<MAX> {
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

impl<const MAX: usize> AsRef<[u8]> for ArrayData<MAX> {
    fn as_ref(&self) -> &[u8] {
        // PANIC: This unwrap is ok because the type's len is checked at
        // construction time to be less than MAX.
        self.bytes.get(..self.len).unwrap()
    }
}

impl<const MAX: usize> PartialEq for ArrayData<MAX> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.get(..self.len).eq(&other.bytes.get(..other.len))
    }
}

/// A convenient type for holding data with a dynamic upper bound on
/// its size. The bytes are held with a `Vec<u8>`.
#[derive(Clone, Debug)]
pub struct VecData<const MAX: usize> {
    bytes: Vec<u8>,
    len: usize,
}
