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
//! - [`PasswordHash::unprotected_as_ref::<str>()`] returns the hashed password in an encoded form.
//!   The encoding specifies the settings used to hash the password.
//! - [`PasswordHash::unprotected_as_ref::<[u8]>()`] returns only the hashed password in raw bytes.
//!
//! The following is an example of how the encoded password hash might look:
//! ```text
//! $argon2id$v=19$m=32,t=3,p=1$AgICAgICAgICAgICAgICAg$MOC0S34jQjtygoWeo28CgltYKN3jwl8STVnULXI14TI
//! ```
//!
//! See a more detailed description of the [encoding format here].
//!
//! # Note:
//! This implementation only supports a single thread, so modifying the parallelism degree beyond `1`
//! will simply make them run sequentially.
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
//! - `memory` is less than `8 * parallelism`.
//! - The length of the `password` is greater than [`isize::MAX`].
//! - The password hash does not match `expected`.
//! - Failure to generate random bytes securely during [`Salt::generate()`].
//!
//! # Security:
//! - [`PasswordHash::unprotected_as_ref()`] should never
//!   be used to compare password hashes, as these will not run in constant-time.
//!   Either use [`hash_password_verify()`] or compare two [`PasswordHash`]es directly.
//! - Choosing the correct cost parameters is important for security. Please refer to [libsodium's docs]
//!   for a description of how to do this.
//! - The cost parameter presets provided as convenience may be outdated. Be sure to check [OWASP] to ensure
//!   they are still adequate.
//! - The cost parameters are **__not__** suitable for _i_-variant.
//!
//! # Example:
//! ```rust
//! use orion::pwhash;
//!
//! let password = pwhash::Password::try_from(b"Secret password")?;
//! let cost = pwhash::OWASP_ARGON2ID_1ST;
//! let hash = pwhash::hash_password(&password, &cost)?;
//! assert!(pwhash::hash_password_verify(&hash, &password).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [encoding format here]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
//! [libsodium's docs]: https://download.libsodium.org/doc/password_hashing/default_phf#guidelines-for-choosing-the-parameters
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use super::hltypes::Password;
pub use crate::hazardous::kdf::argon2::CostParams;
pub use crate::hazardous::kdf::argon2::PasswordHash;

use super::hltypes::Salt;
use crate::{errors::UnknownCryptoError, hazardous::kdf::argon2};

/// The length of the salt used for password hashing.
pub const SALT_LENGTH: usize = 16;

/// The length of the hashed password.
pub const PWHASH_LENGTH: usize = 32;

/// m=47104 (46 MiB), t=1, p=1 (Do not use with Argon2i).
pub const OWASP_ARGON2ID_1ST: CostParams = CostParams {
    iterations: 1,
    memory: 47104,
    parallelism: 1,
};

/// m=19456 (19 MiB), t=2, p=1 (Do not use with Argon2i)
pub const OWASP_ARGON2ID_2ND: CostParams = CostParams {
    iterations: 2,
    memory: 19456,
    parallelism: 1,
};

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Hash a password using Argon2id.
pub fn hash_password(
    password: &Password,
    cost: &CostParams,
) -> Result<PasswordHash, UnknownCryptoError> {
    let salt = Salt::generate()?;
    argon2::Argon2::<argon2::ID, argon2::Sequential>::derive_key_encoded(
        password.unprotected_as_ref(),
        salt.as_ref(),
        cost,
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
/// let cost = pwhash::OWASP_ARGON2ID_1ST;
/// // Pretend these are stored somewhere and out-of-mind, e.g. in a database.
/// let hash1 = pwhash::hash_password(&password, &cost)?;
/// let hash2 = pwhash::hash_password(&password, &cost)?;
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
                assert!(PasswordHash::try_from(res.unprotected_as_ref::<str>()).is_ok());
            }

            true
        }
    }

    mod test_pwhash_and_verify {
        use super::*;

        #[test]
        fn test_argon2i_verify() {
            let password = Password::try_from(&[0u8; 64]).unwrap();
            let cost = CostParams::new(1, 4096, 1).unwrap();
            let dk = hash_password(&password, &cost).unwrap();

            assert!(hash_password_verify(&dk, &password).is_ok());
            assert!(!dk.is_empty());
        }

        #[test]
        fn test_argon2i_verify_err_modified_passwordhash() {
            let password = Password::try_from(&[0u8; 64]).unwrap();
            let cost = CostParams::new(1, 4096, 1).unwrap();
            let dk = hash_password(&password, &cost).unwrap();
            let mut pwd_mod = dk.unprotected_as_ref::<[u8]>().to_vec();
            pwd_mod[0..32].copy_from_slice(&[0u8; 32]);

            assert!(PasswordHash::try_from(&pwd_mod).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_memory() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();
            let cost = CostParams::new(1, 4096, 1).unwrap();
            let dk = hash_password(&password, &cost).unwrap();
            let encoded = dk.unprotected_as_ref::<str>();

            let mut modified = encoded.to_string();
            let memory_offset = modified.find("$m=4096").unwrap();
            modified.replace_range(memory_offset..memory_offset + 7, "$m=2048");

            let modified = PasswordHash::try_from(modified.as_str()).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_iterations() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();
            let cost = CostParams::new(1, 4096, 1).unwrap();
            let dk = hash_password(&password, &cost).unwrap();
            let encoded = dk.unprotected_as_ref::<str>();

            let mut modified = encoded.to_string();
            let iterations_offset = modified.find(",t=1").unwrap();
            modified.replace_range(iterations_offset..iterations_offset + 4, ",t=2");

            let modified = PasswordHash::try_from(modified.as_str()).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_memory_and_iterations() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();
            let cost = CostParams::new(1, 4096, 1).unwrap();
            let dk = hash_password(&password, &cost).unwrap();
            let encoded = dk.unprotected_as_ref::<str>();

            let mut modified = encoded.to_string();
            let memory_offset = modified.find("$m=4096").unwrap();
            let iterations_offset = modified.find(",t=1").unwrap();
            modified.replace_range(memory_offset..memory_offset + 7, "$m=2048");
            modified.replace_range(iterations_offset..iterations_offset + 4, ",t=2");

            let modified = PasswordHash::try_from(modified.as_str()).unwrap();

            assert!(hash_password_verify(&modified, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_salt() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();
            let cost = CostParams::new(1, 4096, 1).unwrap();
            let mut dk = hash_password(&password, &cost).unwrap();
            dk.data.salt[0..16].copy_from_slice(&[0u8; 16]);
            dk.data.encode_to_phc().unwrap();

            assert!(hash_password_verify(&dk, &password).is_err());
        }

        #[test]
        fn test_argon2i_verify_err_modified_salt_and_password() {
            let password = Password::try_from(&[0u8; 64][..]).unwrap();

            let cost = CostParams::new(1, 4096, 1).unwrap();
            let mut dk = hash_password(&password, &cost).unwrap();
            dk.data.salt[0..16].copy_from_slice(&[0u8; 16]);
            dk.data.hash[0..16].copy_from_slice(&[0u8; 16]);
            dk.data.encode_to_phc().unwrap();

            assert!(hash_password_verify(&dk, &password).is_err());
        }
    }
}
