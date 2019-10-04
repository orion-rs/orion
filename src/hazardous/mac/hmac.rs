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

//! # Parameters:
//! - `secret_key`:  The authentication key.
//! - `data`: Data to be authenticated.
//! - `expected`: The expected authentication tag.
//!
//! # Errors:
//! An error will be returned if:
//! - [`finalize()`] is called twice without a [`reset()`] in between.
//! - [`update()`] is called after [`finalize()`] without a [`reset()`] in
//!   between.
//! - The HMAC does not match the expected when verifying.
//!
//! # Security:
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::generate()`] can be used
//! for this. It generates a secret key of 128 bytes.
//! - The minimum recommended size for a secret key is 64 bytes.
//!
//! # Recommendation:
//! - If you are unsure of whether to use HMAC or Poly1305, it is most often
//!   easier to just
//! use HMAC. See also [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html).
//!
//! # Example:
//! ```rust
//! use orion::hazardous::mac::hmac;
//!
//! let key = hmac::SecretKey::generate();
//!
//! let mut state = hmac::Hmac::new(&key);
//! state.update(b"Some message.")?;
//! let tag = state.finalize()?;
//!
//! assert!(hmac::verify(&tag, &key, b"Some message.")?);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: struct.Hmac.html
//! [`reset()`]: struct.Hmac.html
//! [`finalize()`]: struct.Hmac.html
//! [`SecretKey::generate()`]: struct.SecretKey.html

use crate::{
	errors::UnknownCryptoError,
	hazardous::hash::sha512::{self, SHA512_BLOCKSIZE, SHA512_OUTSIZE},
};
use zeroize::Zeroize;

construct_hmac_key! {
	/// A type to represent the `SecretKey` that HMAC uses for authentication.
	///
	/// # Note:
	/// `SecretKey` pads the secret key for use with HMAC to a length of 128, when initialized.
	///
	/// Using `unprotected_as_bytes()` will return the secret key with padding.
	///
	/// Using `get_length()` will return the length with padding (always 128).
	///
	/// # Panics:
	/// A panic will occur if:
	/// - Failure to generate random bytes securely.
	(SecretKey, SHA512_BLOCKSIZE)
}

construct_tag! {
	/// A type to represent the `Tag` that HMAC returns.
	///
	/// # Errors:
	/// An error will be returned if:
	/// - `slice` is not 64 bytes.
	(Tag, test_tag, SHA512_OUTSIZE, SHA512_OUTSIZE)
}

impl_from_trait!(Tag, SHA512_OUTSIZE);

#[derive(Clone)]
/// HMAC-SHA512 streaming state.
pub struct Hmac {
	working_hasher: sha512::Sha512,
	opad_hasher: sha512::Sha512,
	ipad_hasher: sha512::Sha512,
	is_finalized: bool,
}

impl core::fmt::Debug for Hmac {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(
			f,
			"Hmac {{ working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***],
            ipad_hasher: [***OMITTED***], is_finalized: {:?} }}",
			self.is_finalized
		)
	}
}

impl Hmac {
	#[inline]
	/// Pad `key` with `ipad` and `opad`.
	fn pad_key_io(&mut self, key: &SecretKey) {
		let mut ipad = [0x36; SHA512_BLOCKSIZE];
		let mut opad = [0x5C; SHA512_BLOCKSIZE];
		// `key` has already been padded with zeroes to a length of SHA512_BLOCKSIZE
		// in SecretKey::from_slice
		for (idx, itm) in key.unprotected_as_bytes().iter().enumerate() {
			opad[idx] ^= itm;
			ipad[idx] ^= itm;
		}

		// Due to opad_hasher and ipad_hasher being initialized in new()
		// and the size of input to update() is known to be acceptable size,
		// .unwrap() here should not be able to panic
		self.ipad_hasher.update(ipad.as_ref()).unwrap();
		self.opad_hasher.update(opad.as_ref()).unwrap();
		self.working_hasher = self.ipad_hasher.clone();
		ipad.zeroize();
		opad.zeroize();
	}

	/// Initialize `Hmac` struct with a given key.
	pub fn new(secret_key: &SecretKey) -> Self {
		let mut state = Self {
			working_hasher: sha512::Sha512::new(),
			opad_hasher: sha512::Sha512::new(),
			ipad_hasher: sha512::Sha512::new(),
			is_finalized: false,
		};

		state.pad_key_io(secret_key);
		state
	}

	/// Reset to `new()` state.
	pub fn reset(&mut self) {
		self.working_hasher = self.ipad_hasher.clone();
		self.is_finalized = false;
	}

	#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
	/// Update state with a `data`. This can be called multiple times.
	pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
		if self.is_finalized {
			Err(UnknownCryptoError)
		} else {
			self.working_hasher.update(data)
		}
	}

	#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
	/// Return a `Tag`.
	pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
		if self.is_finalized {
			return Err(UnknownCryptoError);
		}

		self.is_finalized = true;
		let mut outer_hasher = self.opad_hasher.clone();
		outer_hasher.update(self.working_hasher.finalize()?.as_ref())?;
		let tag = Tag::from_slice(outer_hasher.finalize()?.as_ref())?;

		Ok(tag)
	}
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// One-shot function for generating an HMAC-SHA512 tag of `data`.
pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
	let mut hmac_state = Hmac::new(secret_key);
	hmac_state.update(data)?;
	hmac_state.finalize()
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Verify a HMAC-SHA512 Tag in constant time.
pub fn verify(
	expected: &Tag,
	secret_key: &SecretKey,
	data: &[u8],
) -> Result<bool, UnknownCryptoError> {
	let mut hmac_state = Hmac::new(secret_key);
	hmac_state.update(data)?;

	if expected == &hmac_state.finalize()? {
		Ok(true)
	} else {
		Err(UnknownCryptoError)
	}
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	#[cfg(feature = "safe_api")]
	mod test_verify {
		use super::*;

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// When using the same parameters verify() should always yeild true.
				fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate();
					let mut state = Hmac::new(&sk);
					state.update(&data[..]).unwrap();
					let tag = state.finalize().unwrap();

					let bad_sk = SecretKey::generate();

					let res = if verify(&tag, &bad_sk, &data[..]).is_err() {
						true
					} else {
						false
					};

					res
				}
			}
		}
	}

	mod test_streaming_interface {
		use super::*;
		use crate::hazardous::hash::sha512::compare_sha512_states;
		use crate::test_framework::incremental_interface::*;

		const KEY: [u8; 32] = [0u8; 32];

		impl TestableStreamingContext<Tag> for Hmac {
			fn reset(&mut self) -> Result<(), UnknownCryptoError> {
				Ok(self.reset())
			}

			fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
				self.update(input)
			}

			fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
				self.finalize()
			}

			fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
				hmac(&SecretKey::from_slice(&KEY).unwrap(), input)
			}

			fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
				// This will only run verifcation tests on differing input. They do not
				// include tests for different secret keys.
				if verify(expected, &SecretKey::from_slice(&KEY).unwrap(), input).is_ok() {
					Ok(())
				} else {
					Err(UnknownCryptoError)
				}
			}

			fn compare_states(state_1: &Hmac, state_2: &Hmac) {
				compare_sha512_states(&state_1.opad_hasher, &state_2.opad_hasher);
				compare_sha512_states(&state_1.ipad_hasher, &state_2.ipad_hasher);
				compare_sha512_states(&state_1.working_hasher, &state_2.working_hasher);
				assert_eq!(state_1.is_finalized, state_2.is_finalized);
			}
		}

		#[test]
		fn default_consistency_tests() {
			let initial_state: Hmac = Hmac::new(&SecretKey::from_slice(&KEY).unwrap());

			let test_runner = StreamingContextConsistencyTester::<Tag, Hmac>::new(
				initial_state,
				SHA512_BLOCKSIZE,
			);
			test_runner.run_all_tests();
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// Related bug: https://github.com/brycx/orion/issues/46
				/// Test different streaming state usage patterns.
				fn prop_input_to_consistency(data: Vec<u8>) -> bool {
					let initial_state: Hmac = Hmac::new(&SecretKey::from_slice(&KEY).unwrap());

					let test_runner = StreamingContextConsistencyTester::<Tag, Hmac>::new(
						initial_state,
						SHA512_BLOCKSIZE,
					);
					test_runner.run_all_tests_property(&data);
					true
				}
			}
		}
	}
}
