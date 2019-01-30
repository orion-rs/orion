// MIT License

// Copyright (c) 2018-2019 The orion Developers

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
//! - Uses PBKDF2-HMAC-SHA512.
//! - A salt of 64 bytes is automatically generated.
//! - The password hash length is set to 64.
//!
//! The first 64 bytes of the `PasswordHash` returned by `pwhash::hash_password`
//! is the salt used to hash the password and the last 64 bytes is the actual
//! hashed password. When using this function with
//! `pwhash::hash_password_verify()`, then the separation of the salt and the
//! password hash is automatically handled.
//!
//! # Parameters:
//! - `password`: The password to be hashed.
//! - `expected_with_salt`: The expected password hash with the corresponding
//!   salt prepended.
//! - `iterations`: The number of iterations performed by PBKDF2, i.e. the cost
//!   parameter.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `iterations` is 0.
//! - The `OsRng` fails to initialize or read from its source.
//! - The `expected_with_salt` is not constructed exactly as in
//!   `pwhash::hash_password`.
//! - The password hash does not match `expected_with_salt`.
//!
//! # Security:
//! - The iteration count should be set as high as feasible. The recommended
//!   minimum is 100000.
//!
//! # Example:
//! ```
//! use orion::pwhash;
//!
//! let password = pwhash::Password::from_slice(b"Secret password").unwrap();
//!
//! let hash = pwhash::hash_password(&password, 100000).unwrap();
//! assert!(pwhash::hash_password_verify(&hash, &password, 100000).unwrap());
//! ```

pub use crate::hltypes::{Password, PasswordHash};
use crate::{
	errors::{UnknownCryptoError, ValidationCryptoError},
	hazardous::kdf::pbkdf2,
	util,
};
use clear_on_drop::clear::Clear;

#[must_use]
/// Hash a password using PBKDF2-HMAC-SHA512.
pub fn hash_password(
	password: &Password,
	iterations: usize,
) -> Result<PasswordHash, UnknownCryptoError> {
	let mut buffer = [0u8; 128];
	let mut salt = [0u8; 64];
	util::secure_rand_bytes(&mut salt)?;

	buffer[..64].copy_from_slice(&salt);
	pbkdf2::derive_key(
		&pbkdf2::Password::from_slice(password.unprotected_as_bytes())?,
		&salt,
		iterations,
		&mut buffer[64..],
	)?;

	let dk = PasswordHash::from_slice(&buffer)?;
	buffer.clear();

	Ok(dk)
}

#[must_use]
/// Hash and verify a password using PBKDF2-HMAC-SHA512.
pub fn hash_password_verify(
	expected_with_salt: &PasswordHash,
	password: &Password,
	iterations: usize,
) -> Result<bool, ValidationCryptoError> {
	let mut dk = [0u8; 64];

	let is_good = pbkdf2::verify(
		&expected_with_salt.unprotected_as_bytes()[64..],
		&pbkdf2::Password::from_slice(password.unprotected_as_bytes())?,
		&expected_with_salt.unprotected_as_bytes()[..64],
		iterations,
		&mut dk,
	)?;

	dk.clear();

	Ok(is_good)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	mod test_pwhash_and_verify {
		use super::*;

		#[test]
		fn test_pbkdf2_verify() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();

			let pbkdf2_dk = hash_password(&password, 100).unwrap();

			assert_eq!(
				hash_password_verify(&pbkdf2_dk, &password, 100).unwrap(),
				true
			);
		}

		#[test]
		fn test_pbkdf2_verify_err_modified_salt() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();

			let pbkdf2_dk = hash_password(&password, 100).unwrap();
			let mut pwd_mod = pbkdf2_dk.unprotected_as_bytes().to_vec();
			pwd_mod[0..32].copy_from_slice(&[0u8; 32]);
			let modified = PasswordHash::from_slice(&pwd_mod).unwrap();

			assert!(hash_password_verify(&modified, &password, 100).is_err());
		}

		#[test]
		fn test_pbkdf2_verify_err_modified_password() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();

			let pbkdf2_dk = hash_password(&password, 100).unwrap();
			let mut pwd_mod = pbkdf2_dk.unprotected_as_bytes().to_vec();
			pwd_mod[120..128].copy_from_slice(&[0u8; 8]);
			let modified = PasswordHash::from_slice(&pwd_mod).unwrap();

			assert!(hash_password_verify(&modified, &password, 100).is_err());
		}

		#[test]
		fn test_pbkdf2_verify_err_modified_salt_and_password() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();

			let pbkdf2_dk = hash_password(&password, 100).unwrap();
			let mut pwd_mod = pbkdf2_dk.unprotected_as_bytes().to_vec();
			pwd_mod[64..96].copy_from_slice(&[0u8; 32]);
			let modified = PasswordHash::from_slice(&pwd_mod).unwrap();

			assert!(hash_password_verify(&modified, &password, 100).is_err());
		}

		#[test]
		fn test_pbkdf2_zero_iterations() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();

			assert!(hash_password(&password, 0).is_err());
		}
	}

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(not(feature = "no_std"))]
	mod proptest {
		use super::*;

		quickcheck! {
			/// Hashing and verifying the same password should always be true.
			fn prop_pwhash_verify(input: Vec<u8>) -> bool {
				let passin = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let pass = Password::from_slice(&passin[..]).unwrap();
				let pass_hash = hash_password(&pass, 100).unwrap();

				if hash_password_verify(&pass_hash, &pass, 100).is_ok() {
					true
				} else {
					false
				}
			}
		}

		quickcheck! {
			/// Hashing and verifying different passwords should always be false.
			fn prop_pwhash_verify_false(input: Vec<u8>) -> bool {
				let passin = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let pass = Password::from_slice(&passin[..]).unwrap();
				let pass_hash = hash_password(&pass, 100).unwrap();
				let bad_pass = Password::generate(32).unwrap();

				if hash_password_verify(&pass_hash, &bad_pass, 100).is_err() {
					true
				} else {
					false
				}
			}
		}
	}
}
