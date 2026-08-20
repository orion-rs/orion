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
//! - Uses Argon2id.
//! - A salt of 16 bytes is automatically generated.
//! - The password hash length is set to 32.
//!
//! [`PasswordHash`] provides two ways of retrieving the hashed password:
//! - [`PasswordHash::unprotected_as_str()`] returns the hashed password in an encoded form.
//!   The encoding specifies the settings used to hash the password.
//! - [`PasswordHash::unprotected_as_ref()`] returns only the hashed password in raw bytes.
//!
//! The following is an example of how the encoded password hash might look:
//! ```text
//! $argon2id$v=19$m=32,t=3,p=1$AgICAgICAgICAgICAgICAg$MOC0S34jQjtygoWeo28CgltYKN3jwl8STVnULXI14TI
//! ```
//!
//! See a more detailed description of the [encoding format here].
//!
//! # Note:
//! This implementation only supports a single thread/lane.
//!
//! # Parameters:
//! - `password`: The password to be hashed.
//! - `expected`: The expected password hash.
//! - `iterations`: Iterations cost parameter for Argon2id.
//! - `memory`: Memory (in kibibytes (KiB)) cost parameter for Argon2id.
//! - `parallelism`: Degree of parallelism/lanes cost parameter for Argon2id.
//!
//! # Errors:
//! An error will be returned if:
//! - `memory` is less than 8.
//! - `iterations` is less than 3.
//! - `password` is not 32 bytes.
//! - `salt` is not 16 bytes.
//! - The length of the `password` is greater than [`isize::MAX`].
//! - The password hash does not match `expected`.
//! - Failure to generate random bytes securely during [`Salt::generate()`].
//!
//! # Security:
//! - [`PasswordHash::unprotected_as_str()`] and [`PasswordHash::unprotected_as_ref()`] should never
//!   be used to compare password hashes, as these will not run in constant-time.
//!   Either use [`hash_password_verify()`] or compare two [`PasswordHash`]es directly.
//! - Choosing the correct cost parameters is important for security. Please refer to [libsodium's docs]
//!   for a description of how to do this.
//!
//! If the concrete cost parameters needed are unclear, please refer to [OWASP] for recommended minimum values.
//!
//! # Example:
//! ```rust
//! use orion::pwhash;
//!
//! let password = pwhash::Password::try_from(b"Secret password")?;
//!
//! let hash = pwhash::hash_password(&password, 3, 1<<16)?;
//! assert!(pwhash::hash_password_verify(&hash, &password).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [encoding format here]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
//! [libsodium's docs]: https://download.libsodium.org/doc/password_hashing/default_phf#guidelines-for-choosing-the-parameters
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use super::hltypes::Password;
pub use crate::hazardous::kdf::argon2::PasswordHash;

use super::hltypes::Salt;
use crate::{errors::UnknownCryptoError, hazardous::kdf::argon2};

/// The length of the salt used for password hashing.
pub const SALT_LENGTH: usize = 16;

/// The length of the hashed password.
pub const PWHASH_LENGTH: usize = 32;

/// Minimum amount of iterations.
pub(crate) const MIN_ITERATIONS: u32 = 3;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct CostParams {
    pub iterations: u32,
    pub memory: u32,
    pub parallelism: u32,
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Hash a password using Argon2id.
pub fn hash_password(
    password: &Password,
    iterations: u32,
    memory: u32,
    parallelism: u32,
) -> Result<PasswordHash, UnknownCryptoError> {
    if iterations < MIN_ITERATIONS {
        return Err(UnknownCryptoError);
    }

    let salt = Salt::generate()?;
    argon2::Argon2::<argon2::ID, argon2::Sequential>::derive_key_encoded(
        password.unprotected_as_ref(),
        salt.as_ref(),
        iterations,
        memory,
        parallelism,
        None,
        None,
        PWHASH_LENGTH,
    )
}

/// Hash and verify a password using Argon2id. The Argon2id parameters `iterations`,
/// `parallelism` and `memory` will be pulled from the `expected: &PasswordHash` argument. If
/// you want to manually specify the iterations and memory for Argon2id to use in
/// hashing the `password` argument, see the
/// [`hazardous::kdf`](crate::hazardous::kdf::argon2) module.
///
/// # Example:
/// ```rust
/// use orion::pwhash;
///
/// let password = pwhash::Password::try_from(b"Secret password")?;
/// let wrong_password = pwhash::Password::try_from(b"hunter2")?;
///
/// // Pretend these are stored somewhere and out-of-mind, e.g. in a database.
/// let hash1 = pwhash::hash_password(&password, 3, 1<<15)?;
/// let hash2 = pwhash::hash_password(&password, 4, 2<<15)?;
///
/// // We don't have to remember which password used what parameters when it's
/// // time to verify them. Both will correctly return `Ok(())`.
/// assert!(pwhash::hash_password_verify(&hash1, &password).is_ok());
/// assert!(pwhash::hash_password_verify(&hash2, &password).is_ok());
///
/// // The only way to get a failing result is to use the wrong password.
/// assert!(pwhash::hash_password_verify(&hash1, &wrong_password).is_err());
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
pub fn hash_password_verify(
    expected: &PasswordHash,
    password: &Password,
) -> Result<(), UnknownCryptoError> {
    argon2::Argon2::<argon2::ID, argon2::Sequential>::verify_encoded(
        expected,
        password.unprotected_as_ref(),
        None,
        None,
    )
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    mod test_password_hash {
        use super::*;

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// If valid params then it's always valid to encode/decode.
        fn prop_always_produce_valid_encoding(hash: String) -> bool {
            if let Ok(res) = PasswordHash::try_from(hash.as_str()) {
                assert!(PasswordHash::try_from(res.unprotected_as_ref()).is_ok());
            }

            true
        }
    }

    mod test_pwhash_and_verify {
        use super::*;

        #[test]
        fn test_argon2i_verify() {
            let password = Password::try_from(&[0u8; 64]).unwrap();
            let dk = hash_password(&password, 3, 4096).unwrap();

            assert!(hash_password_verify(&dk, &password).is_ok());
            assert!(!dk.is_empty());
        }

        #[test]
        fn test_argon2i_verify_err_modified_password() {
            let password = Password::try_from(&[0u8; 64]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let mut pwd_mod = dk.unprotected_as_ref().to_vec();
            pwd_mod[0..32].copy_from_slice(&[0u8; 32]);
            let modified = PasswordHash::from_slice(&pwd_mod, dk.salt.as_ref(), 3, 4096).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_memory() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let encoded = dk.unprotected_as_encoded();

            let mut modified = encoded.to_string();
            let memory_offset = modified.find("$m=4096").unwrap();
            modified.replace_range(memory_offset..memory_offset + 7, "$m=2048");

            let modified = PasswordHash::from_encoded(&modified).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_iterations() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let encoded = dk.unprotected_as_encoded();

            let mut modified = encoded.to_string();
            let iterations_offset = modified.find(",t=3").unwrap();
            modified.replace_range(iterations_offset..iterations_offset + 4, ",t=4");

            let modified = PasswordHash::from_encoded(&modified).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_memory_and_iterations() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let encoded = dk.unprotected_as_encoded();

            let mut modified = encoded.to_string();
            let memory_offset = modified.find("$m=4096").unwrap();
            let iterations_offset = modified.find(",t=3").unwrap();
            modified.replace_range(memory_offset..memory_offset + 7, "$m=2048");
            modified.replace_range(iterations_offset..iterations_offset + 4, ",t=4");

            let modified = PasswordHash::from_encoded(&modified).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_salt() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let mut salt_mod = dk.salt.as_ref().to_vec();
            salt_mod[0..16].copy_from_slice(&[0u8; 16]);
            let modified =
                PasswordHash::from_slice(dk.unprotected_as_ref(), &salt_mod, 3, 4096).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_salt_and_password() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();

            let dk = hash_password(&password, 3, 4096).unwrap();
            let mut pwd_mod = dk.unprotected_as_ref().to_vec();
            let mut salt_mod = dk.salt.as_ref().to_vec();
            pwd_mod[0..32].copy_from_slice(&[0u8; 32]);
            salt_mod[0..16].copy_from_slice(&[0u8; 16]);
            let modified = PasswordHash::from_slice(&pwd_mod, &salt_mod, 3, 4096).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_invalid_iterations() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();
            assert!(hash_password(&password, MIN_ITERATIONS - 1, 4096).is_err());
        }

        #[test]
        fn test_argon2i_invalid_memory() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();
            assert!(hash_password(&password, MIN_ITERATIONS, 8 - 1).is_err());
        }
    }
}
