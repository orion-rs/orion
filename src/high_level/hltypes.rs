// MIT License

// Copyright (c) 2020-2026 The orion Developers

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

use crate::generics::{ByteVecData, Public, Secret, TypeSpec, sealed::Data, sealed::Sealed};
#[cfg(feature = "safe_api")]
use crate::{
    errors::UnknownCryptoError,
    generics::{GeneratePublic, GenerateSecret},
};

#[derive(Debug)]
/// Marker type for Orion high-level secret key.
pub struct KeyType {}
impl Sealed for KeyType {}

impl TypeSpec for KeyType {
    const NAME: &'static str = stringify!(SecretKey);
    type TypeData = ByteVecData;
}

impl GenerateSecret for KeyType {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<KeyType>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(32)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

/// A type to represent a secret key.
///
/// [`SecretKey::generate()`] will generate a random secret key of 32 bytes.
///
/// # Errors:
/// An error will be returned if:
/// - `slice` is empty.
/// - `length` is 0.
/// - `length` is not less than [`isize::MAX`].
/// - Failure to generate random bytes securely.
pub type SecretKey = Secret<KeyType>;

#[derive(Debug, Clone, Copy)]
/// Marker type for Orion high-level salt for KDF operations.
pub struct SaltType {}
impl Sealed for SaltType {}

impl TypeSpec for SaltType {
    const NAME: &'static str = stringify!(Salt);
    type TypeData = ByteVecData;
}

impl GeneratePublic for SaltType {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Public<SaltType>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(crate::pwhash::SALT_LENGTH)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Public::from_data(data))
    }
}

/// A type to represent the `Salt` that Argon2i uses during key derivation.
///
/// [`Salt::generate()`] will generate a random salt of 16 bytes.
///
/// # Errors:
/// An error will be returned if:
/// - `slice` is empty.
/// - `length` is 0.
/// - `length` is not less than [`isize::MAX`].
/// - Failure to generate random bytes securely.
pub type Salt = Public<SaltType>;

#[derive(Debug)]
/// Marker type for Orion high-level password.
pub struct PasswordType {}
impl Sealed for PasswordType {}

impl TypeSpec for PasswordType {
    const NAME: &'static str = stringify!(Password);
    type TypeData = ByteVecData;
}

/// A type to represent the `Password` that Argon2i hashes and uses for key derivation.
///
/// # Errors:
/// An error will be returned if:
/// - `slice` is empty.
/// - `length` is 0.
/// - `length` is not less than [`isize::MAX`].
pub type Password = Secret<PasswordType>;
