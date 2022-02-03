use crate::errors::UnknownCryptoError;

/// This trait holds most of the behavior of types whose data are
/// meant to be public. This is what users are expected to import
/// in order to work with various Orion types that represent
/// non-secret data.
pub trait Public<D>: Sized {
    /// Construct from a given byte slice.
    ///
    /// ## Errors
    /// `UnknownCryptoError` will be returned if:
    ///   - `slice` is empty
    ///   - TODO: figure out how to express max length in the docs
    fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError>;

    /// Return a byte slice representing the underlying data.
    fn as_ref(&self) -> &[u8];

    /// Get the length of the underlying data in bytes.
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Check if the length of the underlying data is 0.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// This is a trait used to express the fact that a type can be interpreted
/// as or converted from another type. It's used primarily to let us
/// reinterpret simple wrappers over [`PublicArray`][0] as the `PublicArray`
/// itself.
///
/// [0]: crate::hazardous::base::PublicArray
pub trait Wrapper<T> {
    /// This allows us to require that `Self` can return a reference to
    /// the underlying `T`. It's functionally equivalent to `AsRef<T>`
    fn data(&self) -> &T;

    /// This allows us to require that `Self` can be constructed from
    /// its underlying type without possibility of failure. It's
    /// functionally equivalent to `From<T>`.
    fn from(data: T) -> Self;
}

// TODO: Do we want to redefine Wrapper<T> as:
// `trait Wrapper<T>: AsRef<T> + From<T> {}` ? It seems equivalent. If
// we're going to use a macro to generate these `Wrapper` impls anyway, we
// might as well just use the standard traits (?).

/// `PublicArray` is a convenient type for storing public bytes in an array.
/// It implements [`Public`](crate::hazardous::base::Public), so creating
/// a newtype around it that also implements `Public` is fairly simple.
///
/// ```rust
/// use orion::hazardous::base::{Public, PublicArray, Wrapper};
///
/// // Create a type that must be exactly 32 bytes long (32..=32).
/// type ShaArray = PublicArray<32, 32>;
/// struct ShaDigest(ShaArray);
///
/// // Implement Wrapper (only has to be imported for newtype creation).
/// // This is the block we may want to have a macro derive for us.
/// impl Wrapper<ShaArray> for ShaDigest {
///     fn data(&self) -> &ShaArray { &self.0 }
///     fn from(data: ShaArray) -> Self { Self(data) }
/// }
///
/// // Thanks to an auto-impl, `ShaDigest` now implements `Public`.
/// let digest = ShaDigest::from_slice(&[42; 32]);
/// assert!(digest.is_ok());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PublicArray<const MIN: usize, const MAX: usize> {
    value: [u8; MAX],
    original_length: usize,
}

impl<const MIN: usize, const MAX: usize> Public<Self> for PublicArray<MIN, MAX> {
    fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        let slice_len = slice.len();

        if !(MIN..=MAX).contains(&slice_len) {
            return Err(UnknownCryptoError);
        }

        let mut value = [0u8; MAX];
        value[..slice_len].copy_from_slice(slice);

        Ok(Self {
            value,
            original_length: slice_len,
        })
    }

    fn as_ref(&self) -> &[u8] {
        self.value.get(..self.original_length).unwrap()
    }
}

/// Anything that can be converted to/from a `PublicArray` will
/// implement `Public` thanks to this auto implementation. The
/// ability to be converted to/from a PublicArray is expressed
/// using the `PublicData<Data = PublicArray<_,_>` trait bound.
impl<T, const MIN: usize, const MAX: usize> Public<PublicArray<MIN, MAX>> for T
where
    T: Wrapper<PublicArray<MIN, MAX>>,
{
    fn from_slice(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        let a = PublicArray::from_slice(bytes)?;
        Ok(Self::from(a))
    }

    fn as_ref(&self) -> &[u8] {
        self.data().as_ref()
    }
}

/// `PublicVec` is a convenient type for storing public bytes in an `Vec`.
/// It implements [`Public`](crate::hazardous::base::Public), so creating
/// a newtype around it that also implements `Public` is fairly simple.
///
/// ```rust
/// use orion::hazardous::base::{Public, PublicVec, Wrapper};
///
/// // Maybe you want your public key to be variable-sized.
/// struct PublicKey(PublicVec);
///
/// // Implement Wrapper (only has to be imported for newtype creation).
/// // This is the block we may want to have a macro derive for us.
/// impl Wrapper<PublicVec> for PublicKey {
///     fn data(&self) -> &PublicVec { &self.0 }
///     fn from(data: PublicVec) -> Self { Self(data) }
/// }
///
/// // Thanks to an auto-impl, `PublicKey` now implements `Public`.
/// let digest = PublicKey::from_slice(&[42; 32]);
/// assert!(digest.is_ok());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PublicVec {
    value: Vec<u8>,
    original_length: usize,
}

/// Anything that can be converted to/from a `PublicVec` will
/// implement `Public` thanks to this auto implementation. The
/// ability to be converted to/from a PublicAVecis expressed
/// using the `PublicDynamic<Data = PublicVec<_,_>` trait bound.
impl Public<Self> for PublicVec {
    fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            value: Vec::from(slice),
            original_length: slice.len(),
        })
    }

    fn as_ref(&self) -> &[u8] {
        self.value.get(..self.original_length).unwrap()
    }
}

/// Anything that can be converted to/from a `PublicVec` will
/// implement `Public` thanks to this auto implementation. The
/// ability to be converted to/from a PublicArray is expressed
/// using the `Wrapper<PublicVec>` trait bound.
impl<T> Public<PublicVec> for T
where
    T: Wrapper<PublicVec>,
{
    fn from_slice(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        let a = PublicVec::from_slice(bytes)?;
        Ok(Self::from(a))
    }

    fn as_ref(&self) -> &[u8] {
        self.data().as_ref()
    }
}
