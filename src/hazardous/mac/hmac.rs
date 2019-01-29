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
//! # Exceptions:
//! An exception will be thrown if:
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
//! ### Generating HMAC:
//! ```
//! use orion::hazardous::mac::hmac;
//!
//! let key = hmac::SecretKey::generate().unwrap();
//! let msg = "Some message.";
//!
//! let mut tag = hmac::init(&key);
//! tag.update(msg.as_bytes()).unwrap();
//! tag.finalize().unwrap();
//! ```
//! ### Verifying HMAC:
//! ```
//! use orion::hazardous::mac::hmac;
//!
//! let key = hmac::SecretKey::generate().unwrap();
//! let msg = "Some message.";
//!
//! let mut tag = hmac::init(&key);
//! tag.update(msg.as_bytes()).unwrap();
//!
//! assert!(hmac::verify(&tag.finalize().unwrap(), &key, msg.as_bytes()).unwrap());
//! ```

extern crate core;

use self::core::mem;
use crate::{
	errors::{FinalizationCryptoError, UnknownCryptoError, ValidationCryptoError},
	hazardous::{
		constants::{BlocksizeArray, HLEN, SHA2_BLOCKSIZE},
		hash::sha512,
	},
};
use clear_on_drop::clear::Clear;

construct_hmac_key! {
	/// A type to represent the `SecretKey` that HMAC uses for authentication.
	///
	/// # Note:
	/// `SecretKey` pads the secret key for use with HMAC, when initialized.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - The `OsRng` fails to initialize or read from its source.
	(SecretKey, SHA2_BLOCKSIZE)
}

construct_tag! {
	/// A type to represent the `Tag` that HMAC returns.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `slice` is not 64 bytes.
	(Tag, HLEN)
}

#[must_use]
#[derive(Clone)]
/// HMAC-SHA512 (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub struct Hmac {
	ipad: BlocksizeArray,
	opad_hasher: sha512::Sha512,
	ipad_hasher: sha512::Sha512,
	is_finalized: bool,
}

impl Drop for Hmac {
	fn drop(&mut self) {
		use clear_on_drop::clear::Clear;
		self.ipad.clear();
	}
}

impl core::fmt::Debug for Hmac {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(
			f,
			"Hmac {{ ipad: [***OMITTED***], opad_hasher: [***OMITTED***],
            ipad_hasher: [***OMITTED***], is_finalized: {:?} }}",
			self.is_finalized
		)
	}
}

impl Hmac {
	#[inline]
	/// Pad `key` with `ipad` and `opad`.
	fn pad_key_io(&mut self, key: &SecretKey) {
		let mut opad: BlocksizeArray = [0x5C; SHA2_BLOCKSIZE];
		// `key` has already been padded with zeroes to a length of SHA2_BLOCKSIZE
		// in SecretKey::from_slice
		for (idx, itm) in key.unprotected_as_bytes().iter().enumerate() {
			self.ipad[idx] ^= itm;
			opad[idx] ^= itm;
		}
		// Due to opad_hasher and ipad_hasher being initialized in init()
		// using .unwrap() here should not be able to panic
		self.ipad_hasher.update(self.ipad.as_ref()).unwrap();
		self.opad_hasher.update(opad.as_ref()).unwrap();
		opad.clear();
	}

	/// Reset to `init()` state.
	pub fn reset(&mut self) {
		self.ipad_hasher = sha512::init();
		// Using unwrap() as this should not panic,
		// since the state has just been initialized and therefore
		// cannot already be finalized.
		self.ipad_hasher.update(self.ipad.as_ref()).unwrap();
		self.is_finalized = false;
	}

	#[must_use]
	/// Update state with a `data`. This can be called multiple times.
	pub fn update(&mut self, data: &[u8]) -> Result<(), FinalizationCryptoError> {
		if self.is_finalized {
			Err(FinalizationCryptoError)
		} else {
			self.ipad_hasher.update(data)?;
			Ok(())
		}
	}

	#[must_use]
	/// Return a `Tag`.
	pub fn finalize(&mut self) -> Result<Tag, FinalizationCryptoError> {
		if self.is_finalized {
			return Err(FinalizationCryptoError);
		}

		self.is_finalized = true;

		let mut hash_ires = sha512::init();
		mem::swap(&mut self.ipad_hasher, &mut hash_ires);

		let mut o_hash = self.opad_hasher.clone();
		o_hash.update(&hash_ires.finalize()?.as_bytes())?;
		let tag = Tag::from_slice(&o_hash.finalize()?.as_bytes())?;

		Ok(tag)
	}
}

#[must_use]
/// Initialize `Hmac` struct with a given key.
pub fn init(secret_key: &SecretKey) -> Hmac {
	let mut state = Hmac {
		ipad: [0x36; SHA2_BLOCKSIZE],
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
) -> Result<bool, ValidationCryptoError> {
	let mut hmac_state = init(secret_key);
	hmac_state.update(data)?;

	if expected == &hmac_state.finalize()? {
		Ok(true)
	} else {
		Err(ValidationCryptoError)
	}
}

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

#[test]
fn veriy_false_wrong_data() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();

	assert!(verify(
		&tag.finalize().unwrap(),
		&SecretKey::from_slice("Jefe".as_bytes()).unwrap(),
		"what do ya want for something?".as_bytes()
	)
	.is_err());
}

#[test]
fn veriy_false_wrong_secret_key() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();

	assert!(verify(
		&tag.finalize().unwrap(),
		&SecretKey::from_slice("Jose".as_bytes()).unwrap(),
		data
	)
	.is_err());
}

#[test]
fn double_finalize_err() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();
	let _ = tag.finalize().unwrap();
	assert!(tag.finalize().is_err());
}

#[test]
fn double_finalize_with_reset_ok() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();
	let one = tag.finalize().unwrap();
	tag.reset();
	tag.update(data).unwrap();
	let two = tag.finalize().unwrap();
	assert_eq!(one.unprotected_as_bytes(), two.unprotected_as_bytes());
}

#[test]
fn double_finalize_with_reset_no_update_ok() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();
	let _ = tag.finalize().unwrap();
	tag.reset();
	let _ = tag.finalize().unwrap();
}

#[test]
fn update_after_finalize_err() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();
	let _ = tag.finalize().unwrap();
	assert!(tag.update(data).is_err());
}

#[test]
fn update_after_finalize_with_reset_ok() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();
	let _ = tag.finalize().unwrap();
	tag.reset();
	tag.update(data).unwrap();
}

#[test]
fn double_reset_ok() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut tag = init(&secret_key);
	tag.update(data).unwrap();
	let _ = tag.finalize().unwrap();
	tag.reset();
	tag.reset();
}

#[test]
fn reset_after_update_correct_resets() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();

	let state_1 = init(&secret_key);

	let mut state_2 = init(&secret_key);
	state_2.update(b"Tests").unwrap();
	state_2.reset();

	assert_eq!(state_1.ipad[..], state_2.ipad[..]);
	assert_eq!(state_1.is_finalized, state_2.is_finalized);
}

#[test]
fn reset_after_update_correct_resets_and_verify() {
	let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();

	let mut state_1 = init(&secret_key);
	state_1.update(b"Tests").unwrap();
	let d1 = state_1.finalize().unwrap();

	let mut state_2 = init(&secret_key);
	state_2.update(b"Tests").unwrap();
	state_2.reset();
	state_2.update(b"Tests").unwrap();
	let d2 = state_2.finalize().unwrap();

	assert_eq!(d1, d2);
}
