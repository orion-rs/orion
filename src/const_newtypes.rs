// MIT License

// Copyright (c) 2022 The orion Developers

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

pub struct Secret<const LB: usize, const UB: usize, const GEN: usize> {
    pub(crate) value: [u8; UB],
    pub(crate) original_length: usize,
}

impl<const LB: usize, const UB: usize, const GEN: usize> Secret<LB, UB, GEN> {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Construct from a given byte slice.
    pub fn from_slice(
        slice: &[u8],
    ) -> Result<Secret<LB, UB, GEN>, crate::errors::UnknownCryptoError> {
        let slice_len = slice.len();

        if !(LB..=UB).contains(&slice_len) {
            return Err(crate::errors::UnknownCryptoError);
        }

        let mut value = [0u8; UB];
        value[..slice_len].copy_from_slice(slice);

        Ok(Self {
            value,
            original_length: slice_len,
        })
    }

    #[inline]
    /// Return the object as byte slice. __**Warning**__: Should not be used unless strictly
    /// needed. This __**breaks protections**__ that the type implements.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.value[..self.original_length].as_ref()
    }

    #[inline]
    /// Return the length of the object.
    pub fn len(&self) -> usize {
        self.original_length
    }

    #[inline]
    /// Return `true` if this object does not hold any data, `false` otherwise.
    ///
    /// __NOTE__: This method should always return `false`, since there shouldn't be a way
    /// to create an empty instance of this object.
    pub fn is_empty(&self) -> bool {
        self.original_length == 0
    }

    #[cfg(feature = "safe_api")]
    /// Randomly generate using a CSPRNG. Not available in `no_std` context.
    pub fn generate() -> Secret<LB, UB, GEN> {
        let mut value = [0u8; UB];
        // This will not panic on size, unless the newtype has been defined with $upper_bound
        // or $gen_length equal to 0.
        crate::util::secure_rand_bytes(&mut value[..GEN]).unwrap();

        Self {
            value,
            original_length: GEN,
        }
    }
}

impl<const LB: usize, const UB: usize, const GEN: usize> core::fmt::Debug for Secret<LB, UB, GEN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} {{***OMITTED***}}", stringify!(Secret<N, GEN>))
    }
}

impl<const LB: usize, const UB: usize, const GEN: usize> Drop for Secret<LB, UB, GEN> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.iter_mut().zeroize();
    }
}

impl<const LB: usize, const UB: usize, const GEN: usize> core::convert::TryFrom<&[u8]>
    for Secret<LB, UB, GEN>
{
    type Error = crate::errors::UnknownCryptoError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(slice)
    }
}

#[cfg(feature = "safe_api")]
impl<const LB: usize, const UB: usize, const GEN: usize> Default for Secret<LB, UB, GEN> {
    /// Randomly generate using a CSPRNG with recommended size. Not available in `no_std` context.
    fn default() -> Secret<LB, UB, GEN> {
        // NOTE: In this case we cannot use GEN, because value is defined over N.
        // So, we'll have to generate N random bytes, even if it is less than N,
        // and then let `original_length` track how many bytes we actually want
        // when we later call unprotected_as_bytes().
        let mut value = [0u8; UB];
        crate::util::secure_rand_bytes(&mut value).unwrap();

        Self {
            value,
            original_length: GEN,
        }
    }
}

impl<const LB: usize, const UB: usize, const GEN: usize> PartialEq<Secret<LB, UB, GEN>>
    for Secret<LB, UB, GEN>
{
    fn eq(&self, other: &Secret<LB, UB, GEN>) -> bool {
        use subtle::ConstantTimeEq;

        (self.value.as_ref().ct_eq(other.value.as_ref())).into()
    }
}

impl<const LB: usize, const UB: usize, const GEN: usize> Eq for Secret<LB, UB, GEN> {}

impl<const LB: usize, const UB: usize, const GEN: usize> PartialEq<&[u8]> for Secret<LB, UB, GEN> {
    fn eq(&self, other: &&[u8]) -> bool {
        use subtle::ConstantTimeEq;

        (self.value.as_ref().ct_eq(other)).into()
    }
}
