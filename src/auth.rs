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

//! Message authentication.
//!
//! # Use case:
//! `orion::auth` can be used to ensure message integrity and authenticity by
//! using a secret key.
//!
//! An example of this could be securing API's by having a user of a given API
//! sign their API request and having the API server verify these signed API
//! requests.
//!
//! # About:
//! - Uses HMAC-SHA512.
//!
//! # Parameters:
//! - `secret_key`: Secret key used to authenticate `data`.
//! - `data`: Data to be authenticated.
//! - `expected`: The expected authentication tag.
//!
//! # Errors:
//! An error will be returned if:
//! - The calculated [`Tag`] does not match the expected.
//!
//! # Security:
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::default()`] can be used for
//! this, it will generate a [`SecretKey`] of 32 bytes.
//! - The recommended minimum length for a [`SecretKey`] is 32.
//!
//! # Example:
//! ```rust
//! use orion::auth;
//!
//! let key = auth::SecretKey::default();
//! let msg = "Some message.".as_bytes();
//!
//! let expected_tag = auth::authenticate(&key, msg)?;
//! assert!(auth::authenticate_verify(&expected_tag, &key, &msg).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey`]: struct.SecretKey.html
//! [`SecretKey::default()`]: struct.SecretKey.html
//! [`Tag`]: ../hazardous/mac/hmac/struct.Tag.html

use crate::{errors::UnknownCryptoError, hazardous::mac::hmac};
pub use crate::{hazardous::mac::hmac::Tag, hltypes::SecretKey};

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Authenticate a message using HMAC-SHA512.
pub fn authenticate(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
	let mut state = hmac::Hmac::new(&hmac::SecretKey::from_slice(
		secret_key.unprotected_as_bytes(),
	)?);
	state.update(data)?;
	state.finalize()
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Authenticate and verify a message using HMAC-SHA512.
pub fn authenticate_verify(
	expected: &Tag,
	secret_key: &SecretKey,
	data: &[u8],
) -> Result<(), UnknownCryptoError> {
	let key = hmac::SecretKey::from_slice(secret_key.unprotected_as_bytes())?;
	hmac::verify(expected, &key, data)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	mod test_auth_and_verify {
		use super::*;
		#[test]
		fn test_authenticate_verify_bad_key() {
			let sec_key_correct = SecretKey::generate(64).unwrap();
			let sec_key_false = SecretKey::default();
			let msg = "what do ya want for nothing?".as_bytes().to_vec();

			let hmac_bob = authenticate(&sec_key_correct, &msg).unwrap();

			assert!(authenticate_verify(&hmac_bob, &sec_key_correct, &msg).is_ok());
			assert!(authenticate_verify(&hmac_bob, &sec_key_false, &msg).is_err());
		}

		#[test]
		fn test_authenticate_verify_bad_msg() {
			let sec_key = SecretKey::generate(64).unwrap();
			let msg = "what do ya want for nothing?".as_bytes().to_vec();

			let hmac_bob = authenticate(&sec_key, &msg).unwrap();

			assert!(authenticate_verify(&hmac_bob, &sec_key, &msg).is_ok());
			assert!(authenticate_verify(&hmac_bob, &sec_key, b"bad msg").is_err());
		}
	}

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use super::*;

		quickcheck! {
			/// Authentication and verifing that authentication with the same parameters
			/// should always be true.
			fn prop_authenticate_verify(input: Vec<u8>) -> bool {
				let sk = SecretKey::default();

				let tag = authenticate(&sk, &input[..]).unwrap();
				authenticate_verify(&tag, &sk, &input[..]).is_ok()
			}
		}

		quickcheck! {
			/// Authentication and verifing that authentication with a different key should
			/// never be true.
			fn prop_verify_fail_diff_key(input: Vec<u8>) -> bool {
				let sk = SecretKey::default();
				let sk2 = SecretKey::default();

				let tag = authenticate(&sk, &input[..]).unwrap();
				if authenticate_verify(&tag, &sk2, &input[..]).is_err() {
					true
				} else {
					false
				}
			}
		}

		quickcheck! {
			/// Authentication and verifing that authentication with different input should
			/// never be true.
			fn prop_verify_fail_diff_input(input: Vec<u8>) -> bool {
				let sk = SecretKey::default();

				let tag = authenticate(&sk, &input[..]).unwrap();
				if authenticate_verify(&tag, &sk, b"Completely wrong input").is_err() {
					true
				} else {
					false
				}
			}
		}
	}
}
