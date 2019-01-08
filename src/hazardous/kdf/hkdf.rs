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
//! - `salt`: Salt value.
//! - `ikm`: Input keying material.
//! - `info`: Optional context and application-specific information.  If `None`
//!   then it's an empty string.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `okm_out`.
//! - `expected`: The expected derived key.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of `dst_out` is less than 1.
//! - The length of `dst_out` is greater than 255 * hash_output_size_in_bytes.
//! - The derived key does not match the expected when verifying.
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG.
//!   `util::secure_rand_bytes()` can be used for this.
//! - The recommended length for a salt is 64 bytes.
//! - Even though a salt value is optional, it is strongly recommended to use
//!   one.
//! - HKDF is not suitable for password storage.
//!
//! # Example:
//! ```
//! use orion::{hazardous::kdf::hkdf, util};
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt).unwrap();
//! let mut okm_out = [0u8; 32];
//!
//! hkdf::derive_key(&salt, "IKM".as_bytes(), None, &mut okm_out).unwrap();
//!
//! let exp_okm = okm_out;
//!
//! assert!(hkdf::verify(&exp_okm, &salt, "IKM".as_bytes(), None, &mut okm_out).unwrap());
//! ```

use crate::{
	errors::{UnknownCryptoError, ValidationCryptoError},
	hazardous::{
		constants::HLEN,
		mac::hmac::{self, SecretKey},
	},
	util,
};

#[must_use]
#[inline(always)]
/// The HKDF extract step.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<hmac::Tag, UnknownCryptoError> {
	let mut prk = hmac::init(&SecretKey::from_slice(salt)?);
	prk.update(ikm)?;

	Ok(prk.finalize()?)
}

#[must_use]
#[inline(always)]
/// The HKDF expand step.
pub fn expand(
	prk: &hmac::Tag,
	info: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	if dst_out.len() > 16320 {
		return Err(UnknownCryptoError);
	}
	if dst_out.is_empty() {
		return Err(UnknownCryptoError);
	}

	let optional_info = match info {
		Some(ref n_val) => *n_val,
		None => &[0u8; 0],
	};

	let mut hmac = hmac::init(&hmac::SecretKey::from_slice(&prk.unprotected_as_bytes())?);
	let okm_len = dst_out.len();

	for (idx, hlen_block) in dst_out.chunks_mut(HLEN).enumerate() {
		let block_len = hlen_block.len();

		hmac.update(optional_info)?;
		hmac.update(&[idx as u8 + 1_u8])?;
		hlen_block.copy_from_slice(&hmac.finalize()?.unprotected_as_bytes()[..block_len]);

		// Check if it's the last iteration, if yes don't process anything
		if block_len < HLEN || (block_len * (idx + 1) == okm_len) {
			break;
		} else {
			hmac.reset();
			hmac.update(&hlen_block)?;
		}
	}

	Ok(())
}

#[must_use]
/// Combine `extract` and `expand` to return a derived key.
pub fn derive_key(
	salt: &[u8],
	ikm: &[u8],
	info: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	expand(&extract(salt, ikm)?, info, dst_out)?;

	Ok(())
}

#[must_use]
/// Verify a derived key in constant time.
pub fn verify(
	expected: &[u8],
	salt: &[u8],
	ikm: &[u8],
	info: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<bool, ValidationCryptoError> {
	expand(&extract(salt, ikm)?, info, dst_out)?;

	if util::secure_cmp(&dst_out, expected).is_err() {
		Err(ValidationCryptoError)
	} else {
		Ok(true)
	}
}

#[cfg(test)]
mod test {
	extern crate hex;
	use self::hex::decode;
	use crate::hazardous::kdf::hkdf::*;

	#[test]
	fn hkdf_maximum_length_512() {
		// Max allowed length here is 16320
		let mut okm_out = [0u8; 17000];
		let prk = extract("".as_bytes(), "".as_bytes()).unwrap();

		assert!(expand(&prk, Some(b""), &mut okm_out).is_err());
	}

	#[test]
	fn hkdf_zero_length() {
		let mut okm_out = [0u8; 0];
		let prk = extract("".as_bytes(), "".as_bytes()).unwrap();

		assert!(expand(&prk, Some(b""), &mut okm_out).is_err());
	}

	#[test]
	fn hkdf_verify_true() {
		let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let salt = decode("000102030405060708090a0b0c").unwrap();
		let info = decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
		let mut okm_out = [0u8; 42];

		let expected_okm = decode(
			"832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
		)
		.unwrap();

		assert_eq!(
			verify(&expected_okm, &salt, &ikm, Some(&info), &mut okm_out).unwrap(),
			true
		);
	}

	#[test]
	fn hkdf_verify_wrong_salt() {
		let salt = "salt".as_bytes();
		let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let info = "".as_bytes();
		let mut okm_out = [0u8; 42];

		let expected_okm = decode(
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		)
		.unwrap();

		assert!(verify(&expected_okm, &salt, &ikm, Some(info), &mut okm_out).is_err());
	}

	#[test]
	fn hkdf_verify_wrong_ikm() {
		let salt = "".as_bytes();
		let ikm = decode("0b").unwrap();
		let info = "".as_bytes();
		let mut okm_out = [0u8; 42];

		let expected_okm = decode(
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		)
		.unwrap();

		assert!(verify(&expected_okm, &salt, &ikm, Some(info), &mut okm_out).is_err());
	}

	#[test]
	fn verify_diff_length() {
		let salt = "".as_bytes();
		let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let info = "".as_bytes();
		let mut okm_out = [0u8; 72];

		let expected_okm = decode(
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		)
		.unwrap();

		assert!(verify(&expected_okm, &salt, &ikm, Some(info), &mut okm_out).is_err());
	}
}
