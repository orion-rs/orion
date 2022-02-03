use crate::errors::UnknownCryptoError;

pub trait Public: Sized {
    fn from_slice(byte: &[u8]) -> Result<Self, UnknownCryptoError>;
    fn as_ref(&self) -> &[u8];

    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait OrionDeref {
    type Target;
    fn deref(&self) -> &Self::Target;
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicArray<const MIN: usize, const MAX: usize> {
    value: [u8; MAX],
    original_length: usize,
}

impl<const MIN: usize, const MAX: usize> Public for PublicArray<MIN, MAX> {
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

impl<T, const MIN: usize, const MAX: usize> Public for T
where
    T: OrionDeref<Target = PublicArray<MIN, MAX>>,
    T: From<PublicArray<MIN, MAX>>,
{
    fn from_slice(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        let pub_array = PublicArray::<MIN, MAX>::from_slice(bytes)?;
        Ok(Self::from(pub_array))
    }

    fn as_ref(&self) -> &[u8] {
        self.deref().as_ref()
    }
}
