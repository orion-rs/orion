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

//! Key derivation.
//!
//! # Use case:
//! `orion::kdf` can be used to derive higher-entropy keys from low-entropy
//! keys. Also known as key stretching.
//!
//! An example of this could be deriving a key from a user-submitted password
//! and using this derived key in disk encryption. The disk encryption software VeraCrypt [uses](https://www.veracrypt.fr/en/Header%20Key%20Derivation.html)
//! PBKDF2-HMAC-SHA512 to derive header keys, which in turn are used to
//! encrypt/decrypt the master keys responsible for encrypting the data in a
//! VeraCrypt volume.
//!
//!
//! # About:
//! - Uses PBKDF2-HMAC-SHA512.
//!
//! # Parameters:
//! - `password`: The low-entropy input key to be used in key derivation.
//! - `expected`: The expected derived key.
//! - `salt`: The salt used for the key derivation.
//! - `iterations`: The number of iterations performed by PBKDF2, i.e. the cost
//!   parameter.
//! - `length`: The desired length of the derived key.
//!
//! # Errors:
//! An error will be returned if:
//! - `iterations` is 0.
//! - `length` is 0.
//! - `length` is not less than `u32::max_value()`.
//! - The `expected` does not match the derived key.
//!
//!
//! # Security:
//! - The iteration count should be set as high as feasible. The recommended
//!   minimum is 100000.
//! - The salt should always be generated using a CSPRNG. `Salt::default()` can
//!   be used for
//! this, it will generate a `Salt` of 64 bytes.
//!
//! # Example:
//! ```
//! use orion::kdf;
//!
//! let user_password = kdf::Password::from_slice(b"User password").unwrap();
//! let salt = kdf::Salt::default();
//!
//! let derived_key = kdf::derive_key(&user_password, &salt, 100000, 64).unwrap();
//!
//! assert!(kdf::derive_key_verify(&derived_key, &user_password, &salt, 100000).unwrap());
//! ```

pub use crate::hltypes::{Password, Salt, SecretKey};
use crate::{errors::UnknownCryptoError, hazardous::kdf::pbkdf2};
use zeroize::Zeroize;

#[must_use]
/// Derive a key using PBKDF2-HMAC-SHA512.
pub fn derive_key(
	password: &Password,
	salt: &Salt,
	iterations: usize,
	length: usize,
) -> Result<SecretKey, UnknownCryptoError> {
	if length < 1 || length >= (u32::max_value() as usize) {
		return Err(UnknownCryptoError);
	}

	let mut buffer = vec![0u8; length];

	pbkdf2::derive_key(
		&pbkdf2::Password::from_slice(password.unprotected_as_bytes())?,
		salt.as_ref(),
		iterations,
		&mut buffer,
	)?;

	let dk = SecretKey::from_slice(&buffer)?;
	buffer.zeroize();

	Ok(dk)
}

#[must_use]
/// Derive and verify a key using PBKDF2-HMAC-SHA512.
pub fn derive_key_verify(
	expected: &SecretKey,
	password: &Password,
	salt: &Salt,
	iterations: usize,
) -> Result<bool, UnknownCryptoError> {
	let mut buffer = vec![0u8; expected.get_length()];

	let is_good = pbkdf2::verify(
		expected.unprotected_as_bytes(),
		&pbkdf2::Password::from_slice(password.unprotected_as_bytes())?,
		salt.as_ref(),
		iterations,
		&mut buffer,
	)?;

	buffer.zeroize();

	Ok(is_good)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	mod test_derive_key_and_verify {
		use super::*;
		#[test]
		fn test_derive_key_and_verify() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();
			let salt = Salt::from_slice(&[0u8; 64]).unwrap();

			let dk = derive_key(&password, &salt, 100, 64).unwrap();

			assert!(derive_key_verify(&dk, &password, &salt, 100).unwrap());
		}

		#[test]
		fn test_derive_key_and_verify_err() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();
			let salt = Salt::from_slice(&[0u8; 64]).unwrap();

			let dk = derive_key(&password, &salt, 100, 64).unwrap();

			assert!(derive_key_verify(&dk, &password, &salt, 50).is_err());
		}

		#[test]
		fn test_derive_key_bad_length() {
			let password = Password::from_slice(&[0u8; 64]).unwrap();
			let salt = Salt::from_slice(&[0u8; 64]).unwrap();

			assert!(derive_key(&password, &salt, 100, 0).is_err());
			assert!(derive_key(&password, &salt, 100, 1).is_ok());
			assert!(derive_key(&password, &salt, 100, usize::max_value()).is_err());
		}
	}

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use super::*;

		quickcheck! {
			/// Deriving a key and verifying with the same parameters should always be true.
			fn prop_derive_key_verify(input: Vec<u8>, size: usize) -> bool {
				let passin = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let size_checked = if size < 5 {
					32
				} else {
					size
				};

				let pass = Password::from_slice(&passin[..]).unwrap();
				let salt = Salt::from_slice(&[192, 251, 70, 48, 200, 151, 170, 100, 177, 86, 7, 16, 143, 23, 38, 197, 108,
					242, 204, 54, 98, 204, 77, 28, 249, 83, 164, 183, 255, 33, 151, 109, 103, 17, 226, 74, 163, 26, 120, 151,
					103, 53, 255, 135, 17, 7, 62, 11, 12, 190, 214, 194, 57, 27, 168, 82, 50, 23, 49, 80, 80, 84, 212, 191]).unwrap();
				let derived_key = derive_key(&pass, &salt, 100, size_checked).unwrap();

				if derive_key_verify(&derived_key, &pass, &salt, 100).is_ok() {
					true
				} else {
					false
				}
			}
		}

		quickcheck! {
			/// Deriving a key and verifying with a different password should always be false.
			fn prop_derive_key_verify_false_bad_password(input: Vec<u8>, size: usize) -> bool {
				let passin = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let size_checked = if size < 5 {
					32
				} else {
					size
				};

				let pass = Password::from_slice(&passin[..]).unwrap();
				let salt = Salt::from_slice(&[192, 251, 70, 48, 200, 151, 170, 100, 177, 86, 7, 16, 143, 23, 38, 197, 108,
					242, 204, 54, 98, 204, 77, 28, 249, 83, 164, 183, 255, 33, 151, 109, 103, 17, 226, 74, 163, 26, 120, 151,
					103, 53, 255, 135, 17, 7, 62, 11, 12, 190, 214, 194, 57, 27, 168, 82, 50, 23, 49, 80, 80, 84, 212, 191]).unwrap();
				let derived_key = derive_key(&pass, &salt, 100, size_checked).unwrap();
				let bad_pass = Password::from_slice(&[119, 56, 92, 141, 149, 150, 233, 171, 16, 88, 129, 93, 114, 154, 91,
					118, 227, 98, 170, 53, 229, 140, 132, 83, 80, 192, 71, 208, 186, 34, 87, 112]).unwrap();

				if derive_key_verify(&derived_key, &bad_pass, &salt, 100).is_err() {
					true
				} else {
					false
				}
			}
		}

		quickcheck! {
			/// Deriving a key and verifying with a different salt should always be false.
			fn prop_derive_key_verify_false_bad_salt(input: Vec<u8>, size: usize) -> bool {
				let passin = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let size_checked = if size < 5 {
					32
				} else {
					size
				};

				let pass = Password::from_slice(&passin[..]).unwrap();
				let salt = Salt::from_slice(&[192, 251, 70, 48, 200, 151, 170, 100, 177, 86, 7, 16, 143, 23, 38, 197, 108, 242,
					204, 54, 98, 204, 77, 28, 249, 83, 164, 183, 255, 33, 151, 109, 103, 17, 226, 74, 163, 26, 120, 151, 103, 53,
					255, 135, 17, 7, 62, 11, 12, 190, 214, 194, 57, 27, 168, 82, 50, 23, 49, 80, 80, 84, 212, 191]).unwrap();
				let derived_key = derive_key(&pass, &salt, 100, size_checked).unwrap();
				let bad_salt = Salt::from_slice(&[169, 110, 7, 6, 17, 74, 70, 22, 26, 1, 37, 22, 44, 7, 141, 67, 246, 208, 151,
					232, 6, 105, 153, 83, 191, 31, 65, 164, 237, 40, 114, 70, 210, 20, 168, 59, 151, 101, 245, 141, 144, 49, 126,
					68, 157, 82, 149, 142, 126, 48, 238, 36, 178, 172, 108, 75, 114, 215, 242, 107, 231, 115, 193, 51]).unwrap();

				if derive_key_verify(&derived_key, &pass, &bad_salt, 100).is_err() {
					true
				} else {
					false
				}
			}
		}
	}
}
