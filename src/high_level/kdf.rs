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
//! - Uses Argon2i.
//!
//! # Note:
//! This implementation only supports a single thread/lane.
//!
//! # Parameters:
//! - `password`: The low-entropy input key to be used in key derivation.
//! - `salt`: The salt used for the key derivation.
//! - `iterations`: Iterations cost parameter for Argon2i.
//! - `memory`: Memory (in kibibytes (KiB)) cost parameter for Argon2i.
//! - `length`: The desired length of the derived key.
//!
//! # Errors:
//! An error will be returned if:
//! - `iterations` is less than 3.
//! - `length` is less than 4.
//! - `memory` is less than 8.
//! - The length of the `password` is greater than [`isize::MAX`].
//! - The length of the `salt` is greater than [`isize::MAX`] or less than `8`.
//!
//! # Security:
//! - Choosing the correct cost parameters is important for security. Please refer to
//!   [libsodium's docs] for a description of how to do this.
//! - The salt should always be generated using a CSPRNG. [`Salt::default()`]
//!   can be used for this, it will generate a [`Salt`] of 16 bytes.
//! - The recommended minimum size for a salt is 16 bytes.
//! - The recommended minimum size for a derived key is 16 bytes.
//!
//! If the concrete cost parameters needed are unclear, please refer to [OWASP] for recommended minimum values.
//!
//! # Example:
//! ```rust
//! use orion::kdf;
//!
//! let user_password = kdf::Password::from_slice(b"User password")?;
//! let salt = kdf::Salt::default();
//!
//! let derived_key = kdf::derive_key(&user_password, &salt, 3, 1<<16, 32)?;
//!
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [libsodium's docs]: https://download.libsodium.org/doc/password_hashing/default_phf#guidelines-for-choosing-the-parameters
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use super::hltypes::{Password, Salt, SecretKey};
use crate::{errors::UnknownCryptoError, hazardous::kdf::argon2i, pwhash::MIN_ITERATIONS};

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Derive a key using Argon2i.
pub fn derive_key(
    password: &Password,
    salt: &Salt,
    iterations: u32,
    memory: u32,
    length: u32,
) -> Result<SecretKey, UnknownCryptoError> {
    if iterations < MIN_ITERATIONS {
        return Err(UnknownCryptoError);
    }

    let mut dk = SecretKey::from_slice(&vec![0u8; length as usize])?;

    argon2i::derive_key(
        password.unprotected_as_bytes(),
        salt.as_ref(),
        iterations,
        memory,
        None,
        None,
        &mut dk.value,
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
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 16]).unwrap();
            let dk_first = derive_key(&password, &salt, 3, 1024, 32).unwrap();
            let dk_second = derive_key(&password, &salt, 3, 1024, 32).unwrap();

            assert_eq!(dk_first, dk_second);
        }

        #[test]
        fn test_derive_key_err_diff_iter() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 64]).unwrap();
            let dk = derive_key(&password, &salt, 3, 1024, 32).unwrap();
            let dk_diff_iter = derive_key(&password, &salt, 4, 1024, 32).unwrap();

            assert_ne!(dk, dk_diff_iter);
        }

        #[test]
        fn test_derive_key_err_diff_mem() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 64]).unwrap();
            let dk = derive_key(&password, &salt, 3, 1024, 32).unwrap();
            let dk_diff_mem = derive_key(&password, &salt, 3, 512, 32).unwrap();

            assert_ne!(dk, dk_diff_mem);
        }

        #[test]
        fn test_derive_key_err_diff_salt() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 64]).unwrap();
            let dk = derive_key(&password, &salt, 3, 1024, 32).unwrap();
            let dk_diff_salt = derive_key(
                &password,
                &Salt::from_slice(&[1u8; 64]).unwrap(),
                3,
                1024,
                32,
            )
            .unwrap();

            assert_ne!(dk, dk_diff_salt);
        }

        #[test]
        fn test_derive_key_err_diff_len() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 64]).unwrap();
            let dk = derive_key(&password, &salt, 3, 1024, 32).unwrap();
            let dk_diff_len = derive_key(&password, &salt, 3, 1024, 64).unwrap();

            assert_ne!(dk, dk_diff_len);
        }

        #[test]
        fn test_derive_key_err_diff_pass() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 64]).unwrap();
            let dk = derive_key(&password, &salt, 3, 1024, 32).unwrap();
            let dk_diff_pass = derive_key(
                &Password::from_slice(&[1u8; 64]).unwrap(),
                &salt,
                3,
                1024,
                32,
            )
            .unwrap();

            assert_ne!(dk, dk_diff_pass);
        }

        #[test]
        fn test_derive_key_bad_length() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 64]).unwrap();

            assert!(derive_key(&password, &salt, 3, 1024, 3).is_err());
            assert!(derive_key(&password, &salt, 3, 1024, 4).is_ok());
            assert!(derive_key(&password, &salt, 3, 1024, 5).is_ok());
        }

        #[test]
        fn test_derive_key_bad_iter() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 16]).unwrap();

            assert!(derive_key(&password, &salt, 2, 1024, 32).is_err());
            assert!(derive_key(&password, &salt, 3, 1024, 32).is_ok());
            assert!(derive_key(&password, &salt, 4, 1024, 32).is_ok());
        }

        #[test]
        fn test_derive_key_bad_mem() {
            let password = Password::from_slice(&[0u8; 64]).unwrap();
            let salt = Salt::from_slice(&[0u8; 16]).unwrap();

            assert!(derive_key(&password, &salt, 3, 7, 32).is_err());
            assert!(derive_key(&password, &salt, 3, 8, 32).is_ok());
            assert!(derive_key(&password, &salt, 3, 9, 32).is_ok());
        }
    }
}
