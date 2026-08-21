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

//! Key derivation.
//!
//! # Use case:
//! `orion::kdf` can be used to derive higher-entropy keys from low-entropy
//! keys. Also known as key stretching.
//!
//! An example of this could be deriving a key from a user-submitted password
//! and using this derived key in disk encryption.
//!
//! # About:
//! - Uses Argon2id.
//!
//! # Note:
//! This implementation only supports a single thread, so modifying the parallelism degree beyond `1`
//! will simply make them run sequentially.
//!
//! # Parameters:
//! - `password`: The low-entropy input key to be used in key derivation.
//! - `salt`: The salt used for the key derivation.
//! - `iterations`: Iterations cost parameter for Argon2i.
//! - `memory`: Memory (in kibibytes (KiB)) cost parameter for Argon2i.
//! - `length`: The desired length of the derived key.
//! - `parallelism`: Degree of parallelism/lanes cost parameter for Argon2id.
//!
//! # Errors:
//! An error will be returned if:
//! - `length` is less than 4.
//! - `memory` is less than `8 * parallelism`.
//! - The length of the `password` is greater than [`isize::MAX`].
//! - The length of the `salt` is greater than [`isize::MAX`] or less than `8`.
//!
//! # Security:
//! - Choosing the correct cost parameters is important for security. Please refer to
//!   [libsodium's docs] for a description of how to do this.
//! - The salt should always be generated using a CSPRNG. [`Salt::generate()`]
//!   can be used for this, it will generate a [`Salt`] of 16 bytes.
//! - The recommended minimum size for a salt is 16 bytes.
//! - The recommended minimum size for a derived key is 16 bytes.
//! - The cost parameter presets provided as convenience may be outdated. Be sure to check [OWASP] to ensure
//!   they are still adequate.
//!
//! # Example:
//! ```rust
//! use orion::kdf;
//!
//! let user_password = kdf::Password::try_from(b"User password")?;
//! let salt = kdf::Salt::generate()?;
//! let cost = kdf::OWASP_ARGON2ID_1ST;
//! let derived_key = kdf::derive_key(&user_password, &salt, &cost, 32)?;
//!
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [libsodium's docs]: https://download.libsodium.org/doc/password_hashing/default_phf#guidelines-for-choosing-the-parameters
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use super::hltypes::{Password, Salt, SecretKey};
pub use crate::hazardous::kdf::argon2::CostParams;
pub use crate::pwhash::OWASP_ARGON2ID_1ST;
pub use crate::pwhash::OWASP_ARGON2ID_2ND;
use crate::{errors::UnknownCryptoError, hazardous::kdf::argon2};

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Derive a key using Argon2id.
pub fn derive_key(
    password: &Password,
    salt: &Salt,
    cost: &CostParams,
    length: u32,
) -> Result<SecretKey, UnknownCryptoError> {
    if salt.len() < 8 {
        return Err(UnknownCryptoError);
    }

    let mut dk = SecretKey::try_from(&vec![0u8; length as usize])?;
    argon2::Argon2::<argon2::ID, argon2::Sequential>::derive_key(
        password.unprotected_as_ref(),
        salt.as_ref(),
        cost,
        None,
        None,
        dk.data.as_mut(),
    )?;

    Ok(dk)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    mod test_derive_key_and_verify {
        use super::*;

        #[test]
        fn test_derive_key() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let salt = Salt::try_from([0u8; 16].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();
            let dk_first = derive_key(&password, &salt, &cost, 32).unwrap();
            let dk_second = derive_key(&password, &salt, &cost, 32).unwrap();

            assert_eq!(dk_first, dk_second);
        }

        #[test]
        fn test_derive_key_err_diff_iter() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let salt = Salt::try_from([0u8; 64].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();

            let dk = derive_key(&password, &salt, &cost, 32).unwrap();
            let dk_diff_iter =
                derive_key(&password, &salt, &CostParams::new(4, 1024, 1).unwrap(), 32).unwrap();

            assert_ne!(dk, dk_diff_iter);
        }

        #[test]
        fn test_derive_key_err_diff_mem() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let salt = Salt::try_from([0u8; 64].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();

            let dk = derive_key(&password, &salt, &cost, 32).unwrap();
            let dk_diff_mem =
                derive_key(&password, &salt, &CostParams::new(4, 512, 1).unwrap(), 32).unwrap();

            assert_ne!(dk, dk_diff_mem);
        }

        #[test]
        fn test_derive_key_err_diff_salt() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let salt = Salt::try_from([0u8; 64].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();

            let dk = derive_key(&password, &salt, &cost, 32).unwrap();
            let dk_diff_salt = derive_key(
                &password,
                &Salt::try_from([1u8; 64].as_slice()).unwrap(),
                &cost,
                32,
            )
            .unwrap();

            assert_ne!(dk, dk_diff_salt);
        }

        #[test]
        fn test_derive_key_err_diff_len() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let salt = Salt::try_from([0u8; 64].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();

            let dk = derive_key(&password, &salt, &cost, 32).unwrap();
            let dk_diff_len = derive_key(&password, &salt, &cost, 64).unwrap();

            assert_ne!(dk, dk_diff_len);
        }

        #[test]
        fn test_derive_key_err_diff_pass() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let salt = Salt::try_from([0u8; 64].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();

            let dk = derive_key(&password, &salt, &cost, 32).unwrap();
            let dk_diff_pass = derive_key(
                &Password::try_from([1u8; 64].as_slice()).unwrap(),
                &salt,
                &cost,
                32,
            )
            .unwrap();

            assert_ne!(dk, dk_diff_pass);
        }

        #[test]
        fn test_derive_key_bad_length() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let salt = Salt::try_from([0u8; 64].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();

            assert!(derive_key(&password, &salt, &cost, 3).is_err());
            assert!(derive_key(&password, &salt, &cost, 4).is_ok());
            assert!(derive_key(&password, &salt, &cost, 5).is_ok());
        }

        #[test]
        fn test_derive_salt_bad_length() {
            let password = Password::try_from([0u8; 64].as_slice()).unwrap();
            let cost: CostParams = CostParams::new(3, 1024, 1).unwrap();

            assert!(
                derive_key(
                    &password,
                    &Salt::try_from([0].as_slice()).unwrap(),
                    &cost,
                    3
                )
                .is_err()
            );
            assert!(
                derive_key(
                    &password,
                    &Salt::try_from([0u8; 1].as_slice()).unwrap(),
                    &cost,
                    4
                )
                .is_err()
            );
            assert!(
                derive_key(
                    &password,
                    &Salt::try_from([0u8; 8].as_slice()).unwrap(),
                    &cost,
                    5
                )
                .is_ok()
            );
        }
    }
}
