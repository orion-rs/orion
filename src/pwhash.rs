// MIT License

// Copyright (c) 2018-2020 The orion Developers

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

//! Password hashing and verification.
//!
//! # Use case:
//! `orion::pwhash` is suitable for securely storing passwords.
//!
//! An example of this would be needing to store user passwords (from a sign-up
//! at a webstore) in a server database,
//! where a potential disclosure of the data in this database should not result
//! in the user's actual passwords being disclosed as well.
//!
//! # About:
//! - Uses Argon2i.
//! - A salt of 16 bytes is automatically generated.
//! - The password hash length is set to 32.
//!
//! [`PasswordHash`] provides two ways of retrieving the hashed password:
//! - [`unprotected_as_encoded()`] returns the hashed password in an encoded form.
//! The encoding specifies the settings used to hash the password.
//! - [`unprotected_as_bytes()`] returns only the hashed password in raw bytes.
//!
//! The following is an example of how the encoded password hash might look:
//! ```text
//! $argon2i$v=19$m=8192,t=3,p=1$c21hbGxzYWx0$lmO1aPPy3x0CcvrKpFLi1TL/uSVJ/eO5hPHiWZFaWvY
//! ```
//!
//! See a more detailed descrption of the encoding format [here](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md).
//!
//! # Note:
//! This implementation only supports a single thread/lane.
//!
//! # Parameters:
//! - `password`: The password to be hashed.
//! - `expected`: The expected password hash.
//! - `iterations`: Iterations cost parameter for Argon2i.
//! - `memory`: Memory (in kibibytes (KiB)) cost parameter for Argon2i.
//!
//! # Errors:
//! An error will be returned if:
//! - `memory` is less than 8.
//! - `iterations` is less than 3.
//! - The password hash does not match `expected`.
//!
//! # Panics:
//! A panic will occur if:
//! - Failure to generate random bytes securely.
//!
//! # Security:
//! - [`unprotected_as_encoded()`] and [`unprotected_as_bytes()`] should never
//! be used to compare password hashes, as these will not run in constant-time.
//! Either use [`pwhash::hash_password_verify`] or compare two [`PasswordHash`]es.
//! - Choosing the correct cost parameters is important for security. Please refer to
//! [libsodium's docs](https://download.libsodium.org/doc/password_hashing/default_phf#guidelines-for-choosing-the-parameters)
//! for a description on how to do this.
//!
//! # Example:
//! ```rust
//! use orion::pwhash;
//!
//! let password = pwhash::Password::from_slice(b"Secret password")?;
//!
//! let hash = pwhash::hash_password(&password, 3, 1<<16)?;
//! assert!(pwhash::hash_password_verify(&hash, &password, 3, 1<<16).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`PasswordHash`]: struct.PasswordHash.html
//! [`unprotected_as_encoded()`]: struct.PasswordHash.html#method.unprotected_as_encoded
//! [`unprotected_as_bytes()`]: struct.PasswordHash.html#method.unprotected_as_bytes
//! [`pwhash::hash_password`]: fn.hash_password.html
//! [`pwhash::hash_password_verify`]: fn.hash_password_verify.html

pub use crate::hltypes::Password;
use crate::{
    errors::UnknownCryptoError,
    hazardous::kdf::argon2i::{self, LANES, MIN_MEMORY},
    hltypes::Salt,
};
use base64::{decode_config, encode_config, STANDARD_NO_PAD};

/// The length of the salt used for password hashing.
pub const SALT_LENGTH: usize = 16;

/// The length of the hashed password.
pub const PWHASH_LENGTH: usize = 32;

/// Minimum amount of iterations.
pub(crate) const MIN_ITERATIONS: u32 = 3;

/// A type to represent the `PasswordHash` that Argon2i returns when used for password hashing.
///
///  
/// # Errors:
/// An error will be returned if:
/// - The encoded password hash contains whitespaces.
/// - The encoded password hash has a parallelism count other than 1.
/// - The encoded password contains any other fields than: The algorithm name,
/// version, m, t, p and the salt and password hash.
/// - The encoded password hash contains invalid Base64 encoding.
/// - `iterations` is less than 3.
/// - `memory` is less than 8.
/// - `password` is not 32 bytes.
/// - `salt` is not 16 bytes.
/// - The encoded password hash contains numerical values that cannot
/// be represented as a `u32`.
///
/// # Panics:
/// A panic will occur if:
/// - Overflowing calculations happen on `usize` when decoding the password and salt from Base64.
///
/// # Security:
/// - __**Avoid using**__ `unprotected_as_bytes()` whenever possible, as it breaks all protections
/// that the type implements.
/// - Never use `unprotected_as_bytes()` or `unprotected_as_encoded()` to compare password hashes,
/// as that will not run in constant-time. Compare `PasswordHash`es directly using `==` instead.
///
/// - The trait `PartialEq<&'_ [u8]>` is implemented for this type so that users are not tempted
/// to call `unprotected_as_bytes` to compare this sensitive value to a byte slice. The trait
/// is implemented in such a way that the comparison happens in constant time. Thus, users should
/// prefer `SecretType == &[u8]` over `SecretType.unprotected_as_bytes() == &[u8]`.
/// Examples are shown below. The examples apply to any type that implements `PartialEq<&'_ [u8]>`.
/// ```rust
/// use orion::hazardous::mac::hmac::Tag;
/// # use orion::errors::UnknownCryptoError;
///
/// # fn main() -> Result<(), Box<UnknownCryptoError>> {
/// // Initialize an arbitrary, 64-byte tag.
/// let tag = Tag::from_slice(&[1; 64])?;
///
/// // Secure, constant-time comparison with a byte slice
/// assert!(tag == &[1; 64][..]);
///
/// // Secure, constant-time comparison with another Tag
/// assert!(tag == Tag::from_slice(&[1; 64])?);
/// # Ok(())
/// # }
/// ```
pub struct PasswordHash {
    encoded_password_hash: String,
    password_hash: Vec<u8>,
    salt: Salt,
    iterations: u32,
    memory: u32,
}

#[allow(clippy::len_without_is_empty)]
impl PasswordHash {
    /// Encode password hash, salt and parameters for storage.
    fn encode(password_hash: &[u8], salt: &[u8], iterations: u32, memory: u32) -> String {
        format!(
            "$argon2i$v=19$m={},t={},p=1${}${}",
            memory,
            iterations,
            encode_config(&salt, STANDARD_NO_PAD),
            encode_config(&password_hash, STANDARD_NO_PAD)
        )
    }

    /// Construct from given byte slice and parameters.
    pub fn from_slice(
        password_hash: &[u8],
        salt: &[u8],
        iterations: u32,
        memory: u32,
    ) -> Result<Self, UnknownCryptoError> {
        if password_hash.len() != PWHASH_LENGTH {
            return Err(UnknownCryptoError);
        }
        if salt.len() != SALT_LENGTH {
            return Err(UnknownCryptoError);
        }
        if iterations < MIN_ITERATIONS {
            return Err(UnknownCryptoError);
        }
        if memory < MIN_MEMORY {
            return Err(UnknownCryptoError);
        }

        let encoded_password_hash = Self::encode(password_hash, salt, iterations, memory);

        Ok(Self {
            encoded_password_hash,
            password_hash: password_hash.into(),
            salt: Salt::from_slice(salt)?,
            iterations,
            memory,
        })
    }

    /// Construct from encoded password hash.
    pub fn from_encoded(password_hash: &str) -> Result<Self, UnknownCryptoError> {
        if password_hash.contains(' ') {
            return Err(UnknownCryptoError);
        }

        let parts_split = password_hash.split('$').collect::<Vec<&str>>();
        if parts_split.len() != 6 {
            return Err(UnknownCryptoError);
        }
        let mut parts = parts_split.into_iter();
        if parts.next() != Some("") {
            return Err(UnknownCryptoError);
        }
        if parts.next() != Some("argon2i") {
            return Err(UnknownCryptoError);
        }
        if parts.next() != Some("v=19") {
            return Err(UnknownCryptoError);
        }

        // Splits as ["m", "X", "t", "Y", "p", "Z"] where m=X, t=Y and p=Z.
        let param_parts_split = parts
            .next()
            .unwrap()
            .split(|v| v == '=' || v == ',')
            .collect::<Vec<&str>>();
        if param_parts_split.len() != 6 {
            return Err(UnknownCryptoError);
        }
        let mut param_parts = param_parts_split.into_iter();

        if param_parts.next() != Some("m") {
            return Err(UnknownCryptoError);
        }
        // .parse::<u32>() automatically checks for overflow.
        // Both in debug and release builds.
        let memory = param_parts.next().unwrap().parse::<u32>()?;
        if memory < MIN_MEMORY {
            return Err(UnknownCryptoError);
        }

        if param_parts.next() != Some("t") {
            return Err(UnknownCryptoError);
        }
        let iterations = param_parts.next().unwrap().parse::<u32>()?;
        if iterations < MIN_ITERATIONS {
            return Err(UnknownCryptoError);
        }

        if param_parts.next() != Some("p") {
            return Err(UnknownCryptoError);
        }
        let lanes = param_parts.next().unwrap().parse::<u32>()?;
        if lanes != LANES {
            return Err(UnknownCryptoError);
        }

        let salt = decode_config(parts.next().unwrap(), STANDARD_NO_PAD)?;
        if salt.len() != SALT_LENGTH {
            return Err(UnknownCryptoError);
        }
        let password_hash_raw = decode_config(&parts.next().unwrap(), STANDARD_NO_PAD)?;
        if password_hash_raw.len() != PWHASH_LENGTH {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            encoded_password_hash: password_hash.into(),
            password_hash: password_hash_raw,
            salt: Salt::from_slice(&salt)?,
            iterations,
            memory,
        })
    }

    /// Return encoded password hash. __**Warning**__: Should not be used to verify
    /// password hashes. This __**breaks protections**__ that the type implements.
    pub fn unprotected_as_encoded(&self) -> &str {
        self.encoded_password_hash.as_ref()
    }

    /// Return the password hash as byte slice. __**Warning**__: Should not be used unless strictly
    /// needed. This __**breaks protections**__ that the type implements.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.password_hash.as_ref()
    }

    #[inline]
    /// Return the length of the password hash.
    pub fn len(&self) -> usize {
        self.password_hash.len()
    }
}

impl core::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PasswordHash {{ encoded_password_hash: [***OMITTED***], password_hash: [***OMITTED***], iterations: \
             {:?}, memory: {:?} }}",
            self.iterations, self.memory
        )
    }
}

impl PartialEq<PasswordHash> for PasswordHash {
    fn eq(&self, other: &PasswordHash) -> bool {
        use subtle::ConstantTimeEq;

        (self
            .unprotected_as_bytes()
            .ct_eq(other.unprotected_as_bytes()))
        .into()
    }
}

impl Eq for PasswordHash {}

impl PartialEq<&[u8]> for PasswordHash {
    fn eq(&self, other: &&[u8]) -> bool {
        use subtle::ConstantTimeEq;

        (self.unprotected_as_bytes().ct_eq(*other)).into()
    }
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Hash a password using Argon2i.
pub fn hash_password(
    password: &Password,
    iterations: u32,
    memory: u32,
) -> Result<PasswordHash, UnknownCryptoError> {
    if iterations < MIN_ITERATIONS {
        return Err(UnknownCryptoError);
    }

    // Cannot panic as this is a valid size.
    let salt = Salt::generate(SALT_LENGTH).unwrap();
    let mut buffer = vec![0u8; PWHASH_LENGTH];

    argon2i::derive_key(
        password.unprotected_as_bytes(),
        salt.as_ref(),
        iterations,
        memory,
        None,
        None,
        &mut buffer,
    )?;

    Ok(PasswordHash::from_slice(
        &buffer,
        salt.as_ref(),
        iterations,
        memory,
    )?)
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Hash and verify a password using Argon2i.
pub fn hash_password_verify(
    expected: &PasswordHash,
    password: &Password,
    iterations: u32,
    memory: u32,
) -> Result<(), UnknownCryptoError> {
    if iterations < MIN_ITERATIONS {
        return Err(UnknownCryptoError);
    }

    let mut buffer = vec![0u8; PWHASH_LENGTH];

    argon2i::verify(
        expected.unprotected_as_bytes(),
        password.unprotected_as_bytes(),
        expected.salt.as_ref(),
        iterations,
        memory,
        None,
        None,
        &mut buffer,
    )?;

    Ok(())
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    mod test_password_hash {
        use super::*;

        #[test]
        fn test_password_hash_eq() {
            let password_hash =
                PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 1 << 16).unwrap();
            assert_eq!(password_hash.len(), 32);
            assert_eq!(password_hash.unprotected_as_bytes(), &[0u8; 32]);

            let password_hash_again =
                PasswordHash::from_encoded(password_hash.unprotected_as_encoded()).unwrap();
            assert_eq!(password_hash, password_hash_again);
        }

        #[test]
        fn test_password_hash_ne() {
            let password_hash =
                PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 1 << 16).unwrap();
            assert_eq!(password_hash.len(), 32);
            assert_eq!(password_hash.unprotected_as_bytes(), &[0u8; 32]);

            let password_hash_again =
                PasswordHash::from_slice(&[1u8; 32], &[0u8; 16], 3, 1 << 16).unwrap();

            assert_ne!(password_hash, password_hash_again);
        }

        #[test]
        fn test_valid_encoded_password() {
            let valid = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            assert!(PasswordHash::from_encoded(valid).is_ok());
        }

        #[test]
        fn test_bad_encoding_missing_dollar() {
            let first_missing = "argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let second_missing = "$argon2iv=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let third_missing = "$argon2i$v=19m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let fourth_missing = "$argon2i$v=19$m=65536,t=3,p=1cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let fifth_missing = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(first_missing).is_err());
            assert!(PasswordHash::from_encoded(second_missing).is_err());
            assert!(PasswordHash::from_encoded(third_missing).is_err());
            assert!(PasswordHash::from_encoded(fourth_missing).is_err());
            assert!(PasswordHash::from_encoded(fifth_missing).is_err());
        }

        #[test]
        fn test_bad_encoding_missing_comma() {
            let first_missing = "$argon2i$v=19$m=65536t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let second_missing = "$argon2i$v=19$m=65536,t=3p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(first_missing).is_err());
            assert!(PasswordHash::from_encoded(second_missing).is_err());
        }

        #[test]
        fn test_bad_encoding_missing_equals() {
            let first_missing = "$argon2i$v19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let second_missing = "$argon2$iv=19$m65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let third_missing = "$argon2i$v=19$m=65536,t3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let fourth_missing = "$argon2i$v=19$m=65536,t=3,p1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(first_missing).is_err());
            assert!(PasswordHash::from_encoded(second_missing).is_err());
            assert!(PasswordHash::from_encoded(third_missing).is_err());
            assert!(PasswordHash::from_encoded(fourth_missing).is_err());
        }

        #[test]
        fn test_bad_encoding_whitespace() {
            let first = "$argon2i$v=19$m=65536,t=3, p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let second = " $argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let third = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA ";

            assert!(PasswordHash::from_encoded(first).is_err());
            assert!(PasswordHash::from_encoded(second).is_err());
            assert!(PasswordHash::from_encoded(third).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_threads() {
            let one = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let zero = "$argon2i$v=19$m=65536,t=3,p=0$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let two = "$argon2i$v=19$m=65536,t=3,p=2$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(one).is_ok());
            assert!(PasswordHash::from_encoded(zero).is_err());
            assert!(PasswordHash::from_encoded(two).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_memory() {
            let exact_min = "$argon2i$v=19$m=8,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let less = "$argon2i$v=19$m=7,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            // Throws error during parsing as u32
            let u32_overflow = format!("$argon2i$v=19$m={},t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA", u64::max_value());

            assert!(PasswordHash::from_encoded(exact_min).is_ok());
            assert!(PasswordHash::from_encoded(less).is_err());
            assert!(PasswordHash::from_encoded(&u32_overflow).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_iterations() {
            let exact_min = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let less = "$argon2i$v=19$m=65536,t=2,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            // Throws error during parsing as u32
            let u32_overflow = format!("$argon2i$v=19$m=65536,t={},p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA", u64::max_value());

            assert!(PasswordHash::from_encoded(exact_min).is_ok());
            assert!(PasswordHash::from_encoded(less).is_err());
            assert!(PasswordHash::from_encoded(&u32_overflow).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_algo() {
            let argon2id = "$argon2id$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let argon2d = "$argon2d$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let nothing = "$$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(argon2d).is_err());
            assert!(PasswordHash::from_encoded(argon2id).is_err());
            assert!(PasswordHash::from_encoded(nothing).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_version() {
            let v13 = "$argon2i$v=13$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let v0 = "$argon2i$v=0$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let nothing = "$argon2i$v=$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(v13).is_err());
            assert!(PasswordHash::from_encoded(v0).is_err());
            assert!(PasswordHash::from_encoded(nothing).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_order() {
            let version_first = "$v=19$argon2i$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let t_beofre_m = "$argon2i$v=19$t=3,m=65536,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let p_before_t = "$argon2i$v=19$m=65536,p=1,t=3$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let p_before_m = "$argon2i$v=19$p=1,m=65536,t=3$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let pass_before_salt = "$argon2i$v=19$m=65536,t=3,p=1$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA$cHBwcHBwcHBwcHBwcHBwcA";
            let salt_first = "$cHBwcHBwcHBwcHBwcHBwcA$argon2i$v=19$m=65536,t=3,p=1$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let pass_first = "$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA";

            assert!(PasswordHash::from_encoded(version_first).is_err());
            assert!(PasswordHash::from_encoded(t_beofre_m).is_err());
            assert!(PasswordHash::from_encoded(p_before_t).is_err());
            assert!(PasswordHash::from_encoded(p_before_m).is_err());
            assert!(PasswordHash::from_encoded(pass_before_salt).is_err());
            assert!(PasswordHash::from_encoded(salt_first).is_err());
            assert!(PasswordHash::from_encoded(pass_first).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_salt() {
            let exact = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let nothing =
                "$argon2i$v=19$m=65536,t=3,p=1$$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let above = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcAA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(exact).is_ok());
            assert!(PasswordHash::from_encoded(nothing).is_err());
            assert!(PasswordHash::from_encoded(above).is_err());
        }

        #[test]
        fn test_bad_encoding_invalid_password() {
            let exact = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let nothing = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$";
            let above = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAA";

            assert!(PasswordHash::from_encoded(exact).is_ok());
            assert!(PasswordHash::from_encoded(nothing).is_err());
            assert!(PasswordHash::from_encoded(above).is_err());
        }

        #[test]
        fn test_bad_encoding_bad_parsing_integers() {
            let j_instead_of_mem = "$argon2i$v=19$m=j,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            assert!(PasswordHash::from_encoded(j_instead_of_mem).is_err());
        }

        #[test]
        fn test_from_slice_password() {
            assert!(PasswordHash::from_slice(&[0u8; 31], &[0u8; 16], 3, 1 << 16).is_err());
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 1 << 16).is_ok());
            assert!(PasswordHash::from_slice(&[0u8; 33], &[0u8; 16], 3, 1 << 16).is_err());
        }

        #[test]
        fn test_from_slice_salt() {
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 15], 3, 1 << 16).is_err());
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 1 << 16).is_ok());
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 17], 3, 1 << 16).is_err());
        }

        #[test]
        fn test_from_slice_mem() {
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 7).is_err());
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 8).is_ok());
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 9).is_ok());
        }

        #[test]
        fn test_from_slice_bad_iter() {
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 2, 1 << 16).is_err());
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 3, 1 << 16).is_ok());
            assert!(PasswordHash::from_slice(&[0u8; 32], &[0u8; 16], 4, 1 << 16).is_ok());
        }

        // Proptests. Only executed when NOT testing no_std.
        #[cfg(feature = "safe_api")]
        mod proptest {
            use super::*;

            quickcheck! {
                /// If valid params then it's always valid to encode/decode.
                fn prop_always_produce_valid_encoding(password: Vec<u8>, salt: Vec<u8>, iterations: u32, memory: u32) -> bool {
                    let res = PasswordHash::from_slice(&password[..], &salt[..], iterations, memory);
                    if res.is_ok() {
                        assert!(PasswordHash::from_encoded(res.unwrap().unprotected_as_encoded()).is_ok());
                    }

                    true
                }
            }
        }
    }

    mod test_pwhash_and_verify {
        use super::*;

        #[test]
        fn test_argon2i_verify() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let dk = hash_password(&password, 3, 4096).unwrap();

            assert!(hash_password_verify(&dk, &password, 3, 4096).is_ok());
        }

        #[test]
        fn test_argon2i_verify_err_modified_password() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let mut pwd_mod = dk.unprotected_as_bytes().to_vec();
            pwd_mod[0..32].copy_from_slice(&[0u8; 32]);
            let modified = PasswordHash::from_slice(&pwd_mod, dk.salt.as_ref(), 3, 4096).unwrap();

            assert!(hash_password_verify(&modified, &password, 3, 4096).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_salt() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let mut salt_mod = dk.salt.as_ref().to_vec();
            salt_mod[0..16].copy_from_slice(&[0u8; 16]);
            let modified =
                PasswordHash::from_slice(&dk.unprotected_as_bytes(), &salt_mod, 3, 4096).unwrap();

            assert!(hash_password_verify(&modified, &password, 3, 4096).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_salt_and_password() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let mut pwd_mod = dk.unprotected_as_bytes().to_vec();
            let mut salt_mod = dk.salt.as_ref().to_vec();
            pwd_mod[0..32].copy_from_slice(&[0u8; 32]);
            salt_mod[0..16].copy_from_slice(&[0u8; 16]);
            let modified = PasswordHash::from_slice(&pwd_mod, &salt_mod, 3, 4096).unwrap();

            assert!(hash_password_verify(&modified, &password, 3, 4096).is_err());
        }

        #[test]
        fn test_argon2i_invalid_iterations() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();

            assert!(hash_password(&password, MIN_ITERATIONS - 1, 4096).is_err());
        }

        #[test]
        fn test_argon2i_invalid_memory() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();

            assert!(hash_password(&password, 3, MIN_MEMORY - 1).is_err());
        }
    }
}
