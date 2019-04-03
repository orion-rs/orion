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
//! - `finalize()` is called twice without a `reset()` in between.
//! - `update()` is called after `finalize()` without a `reset()` in between.
//! - The HMAC does not match the expected when verifying.
//!
//! # Security:
//! - The secret key should always be generated using a CSPRNG.
//!   `SecretKey::generate()` can be used
//! for this. It generates a secret key of 128 bytes.
//! - The minimum recommended size for a secret key is 64 bytes.
//!
//! # Recommendation:
//! - If you are unsure of whether to use HMAC or Poly1305, it is most often
//!   easier to just
//! use HMAC. See also [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html).
//!
//! # Example:
//! ```
//! use orion::hazardous::mac::hmac;
//!
//! let key = hmac::SecretKey::generate().unwrap();
//!
//! let mut state = hmac::init(&key);
//! state.update(b"Some message.").unwrap();
//! let tag = state.finalize().unwrap();
//!
//! assert!(hmac::verify(&tag, &key, b"Some message.").unwrap());
//! ```

use crate::{
	errors::UnknownCryptoError,
	hazardous::{
		constants::{BlocksizeArray, SHA512_BLOCKSIZE, SHA512_OUTSIZE},
		hash::sha512,
	},
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
	/// # Errors:
	/// An error will be returned if:
	/// - The `OsRng` fails to initialize or read from its source.
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

#[must_use]
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
		let mut ipad: BlocksizeArray = [0x36; SHA512_BLOCKSIZE];
		let mut opad: BlocksizeArray = [0x5C; SHA512_BLOCKSIZE];
		// `key` has already been padded with zeroes to a length of SHA512_BLOCKSIZE
		// in SecretKey::from_slice
		assert_eq!(key.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
		for (idx, itm) in key.unprotected_as_bytes().iter().enumerate() {
			opad[idx] ^= itm;
			ipad[idx] ^= itm;
		}

		// Due to opad_hasher and ipad_hasher being initialized in init()
		// and the size of input to update() is known to be acceptable size,
		// .unwrap() here should not be able to panic
		self.ipad_hasher.update(ipad.as_ref()).unwrap();
		self.opad_hasher.update(opad.as_ref()).unwrap();
		self.working_hasher = self.ipad_hasher.clone();
		ipad.zeroize();
		opad.zeroize();
	}

	/// Reset to `init()` state.
	pub fn reset(&mut self) {
		self.working_hasher = self.ipad_hasher.clone();
		self.is_finalized = false;
	}

	#[must_use]
	/// Update state with a `data`. This can be called multiple times.
	pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
		if self.is_finalized {
			Err(UnknownCryptoError)
		} else {
			self.working_hasher.update(data)?;
			Ok(())
		}
	}

	#[must_use]
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

#[must_use]
/// Initialize `Hmac` struct with a given key.
pub fn init(secret_key: &SecretKey) -> Hmac {
	let mut state = Hmac {
		working_hasher: sha512::init(),
		opad_hasher: sha512::init(),
		ipad_hasher: sha512::init(),
		is_finalized: false,
	};

	state.pad_key_io(secret_key);
	state
}

#[must_use]
/// One-shot function for generating an HMAC-SHA512 tag of `data`.
pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
	let mut hmac_state = init(secret_key);
	hmac_state.update(data)?;

	Ok(hmac_state.finalize()?)
}

#[must_use]
/// Verify a HMAC-SHA512 Tag in constant time.
pub fn verify(
	expected: &Tag,
	secret_key: &SecretKey,
	data: &[u8],
) -> Result<bool, UnknownCryptoError> {
	let mut hmac_state = init(secret_key);
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

	use crate::hazardous::hash::sha512::compare_sha512_states;

	// One function tested per submodule.

	/// Compare two HMAC state objects to check if their fields
	/// are the same.
	fn compare_hmac_states(state_1: &Hmac, state_2: &Hmac) {
		compare_sha512_states(&state_1.opad_hasher, &state_2.opad_hasher);
		compare_sha512_states(&state_1.ipad_hasher, &state_2.ipad_hasher);
		compare_sha512_states(&state_1.working_hasher, &state_2.working_hasher);

		assert_eq!(state_1.is_finalized, state_2.is_finalized);
	}

	mod test_verify {
		use super::*;

		#[test]
		fn finalize_and_verify_true() {
			let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut tag = init(&secret_key);
			tag.update(data).unwrap();

			assert_eq!(
				verify(
					&tag.finalize().unwrap(),
					&SecretKey::from_slice("Jefe".as_bytes()).unwrap(),
					data
				)
				.unwrap(),
				true
			);
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// When using the same parameters verify() should always yeild true.
				fn prop_verify_same_params_true(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate().unwrap();

					let mut state = init(&sk);
					state.update(&data[..]).unwrap();
					let tag = state.finalize().unwrap();
					// Failed verification on Err so res is not needed.
					let _res = verify(&tag, &sk, &data[..]).unwrap();

					true
				}
			}

			quickcheck! {
				/// When using the same parameters verify() should always yeild true.
				fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate().unwrap();
					let mut state = init(&sk);
					state.update(&data[..]).unwrap();
					let tag = state.finalize().unwrap();

					let bad_sk = SecretKey::generate().unwrap();

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

	mod test_reset {
		use super::*;

		#[test]
		fn test_double_reset_ok() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init(&sk);
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			state.reset();
			state.reset();
		}
	}

	mod test_update {
		use super::*;

		#[test]
		fn test_update_after_finalize_with_reset_ok() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init(&sk);
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			state.reset();
			state.update(data).unwrap();
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/28
		fn test_update_after_finalize_err() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init(&sk);
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			assert!(state.update(data).is_err());
		}
	}

	mod test_finalize {
		use super::*;

		#[test]
		fn test_double_finalize_with_reset_no_update_ok() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init(&sk);
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			state.reset();
			let _ = state.finalize().unwrap();
		}

		#[test]
		fn test_double_finalize_with_reset_ok() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init(&sk);
			state.update(data).unwrap();
			let one = state.finalize().unwrap();
			state.reset();
			state.update(data).unwrap();
			let two = state.finalize().unwrap();
			assert_eq!(one, two);
		}

		#[test]
		fn test_double_finalize_err() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init(&sk);
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			assert!(state.finalize().is_err());
		}

	}

	mod test_streaming_interface {
		use super::*;

		/// Related bug: https://github.com/brycx/orion/issues/46
		/// Testing different usage combinations of init(), update(),
		/// finalize() and reset() produce the same Digest.
		fn produces_same_hash(sk: &SecretKey, data: &[u8]) {
			// init(), update(), finalize()
			let mut state_1 = init(&sk);
			state_1.update(data).unwrap();
			let res_1 = state_1.finalize().unwrap();

			// init(), reset(), update(), finalize()
			let mut state_2 = init(&sk);
			state_2.reset();
			state_2.update(data).unwrap();
			let res_2 = state_2.finalize().unwrap();

			// init(), update(), reset(), update(), finalize()
			let mut state_3 = init(&sk);
			state_3.update(data).unwrap();
			state_3.reset();
			state_3.update(data).unwrap();
			let res_3 = state_3.finalize().unwrap();

			// init(), update(), finalize(), reset(), update(), finalize()
			let mut state_4 = init(&sk);
			state_4.update(data).unwrap();
			let _ = state_4.finalize().unwrap();
			state_4.reset();
			state_4.update(data).unwrap();
			let res_4 = state_4.finalize().unwrap();

			assert_eq!(res_1, res_2);
			assert_eq!(res_2, res_3);
			assert_eq!(res_3, res_4);

			// Tests for the assumption that returning Ok() on empty update() calls
			// with streaming API's, gives the correct result. This is done by testing
			// the reasoning that if update() is empty, returns Ok(), it is the same as
			// calling init() -> finalize(). i.e not calling update() at all.
			if data.is_empty() {
				// init(), finalize()
				let mut state_5 = init(&sk);
				let res_5 = state_5.finalize().unwrap();

				// init(), reset(), finalize()
				let mut state_6 = init(&sk);
				state_6.reset();
				let res_6 = state_6.finalize().unwrap();

				// init(), update(), reset(), finalize()
				let mut state_7 = init(&sk);
				state_7.update(b"Wrong data").unwrap();
				state_7.reset();
				let res_7 = state_7.finalize().unwrap();

				assert_eq!(res_4, res_5);
				assert_eq!(res_5, res_6);
				assert_eq!(res_6, res_7);
			}
		}

		/// Related bug: https://github.com/brycx/orion/issues/46
		/// Testing different usage combinations of init(), update(),
		/// finalize() and reset() produce the same Digest.
		fn produces_same_state(sk: &SecretKey, data: &[u8]) {
			// init()
			let state_1 = init(&sk);

			// init(), reset()
			let mut state_2 = init(&sk);
			state_2.reset();

			// init(), update(), reset()
			let mut state_3 = init(&sk);
			state_3.update(data).unwrap();
			state_3.reset();

			// init(), update(), finalize(), reset()
			let mut state_4 = init(&sk);
			state_4.update(data).unwrap();
			let _ = state_4.finalize().unwrap();
			state_4.reset();

			compare_hmac_states(&state_1, &state_2);
			compare_hmac_states(&state_2, &state_3);
			compare_hmac_states(&state_3, &state_4);
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/46
		fn test_produce_same_state() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			produces_same_state(&sk, b"Tests");
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/46
		fn test_produce_same_hash() {
			let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			produces_same_hash(&sk, b"Tests");
			produces_same_hash(&sk, b"");
		}

		#[test]
		#[cfg(feature = "safe_api")]
		// Test for issues when incrementally processing data.
		fn test_streaming_consistency() {
			for len in 0..SHA512_BLOCKSIZE * 4 {
				let sk = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
				let data = vec![0u8; len];
				let mut state = init(&sk);
				let mut other_data: Vec<u8> = Vec::new();

				other_data.extend_from_slice(&data);
				state.update(&data).unwrap();

				if data.len() > SHA512_BLOCKSIZE {
					other_data.extend_from_slice(b"");
					state.update(b"").unwrap();
				}
				if data.len() > SHA512_BLOCKSIZE * 2 {
					other_data.extend_from_slice(b"Extra");
					state.update(b"Extra").unwrap();
				}
				if data.len() > SHA512_BLOCKSIZE * 3 {
					other_data.extend_from_slice(&[0u8; 256]);
					state.update(&[0u8; 256]).unwrap();
				}

				let digest_one_shot = hmac(&sk, &other_data).unwrap();

				assert!(state.finalize().unwrap() == digest_one_shot);
			}
		}
		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// Related bug: https://github.com/brycx/orion/issues/46
				/// Test different streaming state usage patterns.
				fn prop_same_hash_different_usage(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate().unwrap();
					// Will panic on incorrect results.
					produces_same_hash(&sk, &data[..]);

					true
				}
			}

			quickcheck! {
				/// Related bug: https://github.com/brycx/orion/issues/46
				/// Test different streaming state usage patterns.
				fn prop_same_state_different_usage(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate().unwrap();
					// Will panic on incorrect results.
					produces_same_state(&sk, &data[..]);

					true
				}
			}

			quickcheck! {
				/// Using the one-shot function should always produce the
				/// same result as when using the streaming interface.
				fn prop_hmac_same_as_streaming(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate().unwrap();
					let mut state = init(&sk);
					state.update(&data[..]).unwrap();
					let stream = state.finalize().unwrap();
					let one_shot = hmac(&sk, &data[..]).unwrap();

					(one_shot == stream)
				}
			}
		}
	}
}
