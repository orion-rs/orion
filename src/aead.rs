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

//! Authenticated secret-key encryption.
//!
//! # Use case:
//! `orion::aead` can be used to encrypt data in a way that detects if the
//! encrypted data has been tampered with before decrypting it.
//!
//! An example of this could be sending messages across networks, where
//! confidentiality and authenticity of these messages is required.
//!
//! # About:
//! - The nonce is automatically generated.
//! - Returns a vector where the first 24 bytes are the nonce and the rest is
//!   the authenticated
//! ciphertext with the last 16 bytes being the corresponding Poly1305 tag.
//! - Uses XChaCha20Poly1305 with no additional data.
//! - When using [`seal`] and [`open`] then the separation of tags, nonces and
//!   ciphertext are automatically handled.
//!
//! # Parameters:
//! - `plaintext`:  The data to be encrypted.
//! - `secret_key`: The secret key used to encrypt the `plaintext`.
//! - `ciphertext_with_tag_and_nonce`:  The data to be decrypted with the first
//!   24 bytes being the nonce and the last
//! 16 bytes being the corresponding Poly1305 tag.
//!
//! # Errors:
//! An error will be returned if:
//! - `secret_key` is not 32 bytes.
//! - `plaintext` is empty.
//! - `ciphertext_with_tag_and_nonce` is less than 41 bytes
//!   ([`XCHACHA_NONCESIZE`] + [`POLY1305_OUTSIZE`] + 1).
//! - The received tag does not match the calculated tag when calling [`open`].
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^32-1 * 64 bytes of data are processed.
//! - Failure to generate random bytes securely.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - To securely generate a strong key, use [`SecretKey::default()`].
//!
//! # Example:
//! ```rust
//! use orion::aead;
//!
//! let secret_key = aead::SecretKey::default();
//! let ciphertext = aead::seal(&secret_key, "Secret message".as_bytes())?;
//! let decrypted_data = aead::open(&secret_key, &ciphertext)?;
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`seal`]: https://docs.rs/orion/latest/orion/aead/fn.seal.html
//! [`open`]: https://docs.rs/orion/latest/orion/aead/fn.open.html
//! [`POLY1305_OUTSIZE`]: https://docs.rs/orion/latest/orion/hazardous/mac/poly1305/constant.POLY1305_OUTSIZE.html
//! [`XCHACHA_NONCESIZE`]: https://docs.rs/orion/latest/orion/hazardous/stream/xchacha20/constant.XCHACHA_NONCESIZE.html
//! [`SecretKey::default()`]: https://docs.rs/orion/latest/orion/aead/struct.SecretKey.html

pub use crate::hltypes::SecretKey;
use crate::{
	errors::UnknownCryptoError,
	hazardous::{
		aead,
		mac::poly1305::POLY1305_OUTSIZE,
		stream::{
			chacha20,
			xchacha20::{Nonce, XCHACHA_NONCESIZE},
		},
	},
};

#[must_use]
/// Authenticated encryption using XChaCha20Poly1305.
pub fn seal(secret_key: &SecretKey, plaintext: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
	if plaintext.is_empty() {
		return Err(UnknownCryptoError);
	}

	let nonce = Nonce::generate();

	let mut dst_out = vec![0u8; plaintext.len() + (XCHACHA_NONCESIZE + POLY1305_OUTSIZE)];
	dst_out[..XCHACHA_NONCESIZE].copy_from_slice(nonce.as_ref());

	aead::xchacha20poly1305::seal(
		&chacha20::SecretKey::from_slice(secret_key.unprotected_as_bytes())?,
		&nonce,
		plaintext,
		None,
		&mut dst_out[XCHACHA_NONCESIZE..],
	)?;

	Ok(dst_out)
}

#[must_use]
/// Authenticated decryption using XChaCha20Poly1305.
pub fn open(
	secret_key: &SecretKey,
	ciphertext_with_tag_and_nonce: &[u8],
) -> Result<Vec<u8>, UnknownCryptoError> {
	// `+ 1` to avoid empty ciphertexts
	if ciphertext_with_tag_and_nonce.len() < (XCHACHA_NONCESIZE + POLY1305_OUTSIZE + 1) {
		return Err(UnknownCryptoError);
	}

	let mut dst_out =
		vec![0u8; ciphertext_with_tag_and_nonce.len() - (XCHACHA_NONCESIZE + POLY1305_OUTSIZE)];

	aead::xchacha20poly1305::open(
		&chacha20::SecretKey::from_slice(secret_key.unprotected_as_bytes())?,
		&Nonce::from_slice(&ciphertext_with_tag_and_nonce[..XCHACHA_NONCESIZE])?,
		&ciphertext_with_tag_and_nonce[XCHACHA_NONCESIZE..],
		None,
		&mut dst_out,
	)?;

	Ok(dst_out)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	mod test_seal_open {
		use super::*;
		#[test]
		fn test_auth_enc_encryption_decryption() {
			let key = SecretKey::default();
			let plaintext = "Secret message".as_bytes().to_vec();

			let dst_ciphertext = seal(&key, &plaintext).unwrap();
			assert!(dst_ciphertext.len() == plaintext.len() + (24 + 16));
			let dst_plaintext = open(&key, &dst_ciphertext).unwrap();
			assert!(dst_plaintext.len() == plaintext.len());
			assert_eq!(plaintext, dst_plaintext);
		}

		#[test]
		fn test_auth_enc_plaintext_empty_err() {
			let key = SecretKey::default();
			let plaintext = "".as_bytes().to_vec();

			assert!(seal(&key, &plaintext).is_err());
		}

		#[test]
		fn test_auth_enc_ciphertext_less_than_41_err() {
			let key = SecretKey::default();
			let ciphertext = [0u8; 40];

			assert!(open(&key, &ciphertext).is_err());
		}

		#[test]
		fn test_modified_nonce_err() {
			let key = SecretKey::default();
			let plaintext = "Secret message".as_bytes().to_vec();

			let mut dst_ciphertext = seal(&key, &plaintext).unwrap();
			// Modify nonce
			dst_ciphertext[10] ^= 1;
			assert!(open(&key, &dst_ciphertext).is_err());
		}

		#[test]
		fn test_modified_ciphertext_err() {
			let key = SecretKey::default();
			let plaintext = "Secret message".as_bytes().to_vec();

			let mut dst_ciphertext = seal(&key, &plaintext).unwrap();
			// Modify ciphertext
			dst_ciphertext[25] ^= 1;
			assert!(open(&key, &dst_ciphertext).is_err());
		}

		#[test]
		fn test_modified_tag_err() {
			let key = SecretKey::default();
			let plaintext = "Secret message".as_bytes().to_vec();

			let mut dst_ciphertext = seal(&key, &plaintext).unwrap();
			let dst_ciphertext_len = dst_ciphertext.len();
			// Modify tag
			dst_ciphertext[dst_ciphertext_len - 6] ^= 1;
			assert!(open(&key, &dst_ciphertext).is_err());
		}

		#[test]
		fn test_diff_secret_key_err() {
			let key = SecretKey::default();
			let plaintext = "Secret message".as_bytes().to_vec();

			let dst_ciphertext = seal(&key, &plaintext).unwrap();
			let bad_key = SecretKey::default();
			assert!(open(&bad_key, &dst_ciphertext).is_err());
		}

		#[test]
		fn test_secret_length_err() {
			let key = SecretKey::generate(31).unwrap();
			let plaintext = "Secret message Secret message Secret message Secret message "
				.as_bytes()
				.to_vec();

			assert!(seal(&key, &plaintext).is_err());
			assert!(open(&key, &plaintext).is_err());
		}
	}

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use super::*;

		quickcheck! {
			// Sealing input, and then opening should always yield the same input.
			fn prop_seal_open_same_input(input: Vec<u8>) -> bool {
				let pt = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let sk = SecretKey::default();

				let ct = seal(&sk, &pt).unwrap();
				let pt_decrypted = open(&sk, &ct).unwrap();

				(pt == pt_decrypted)
			}
		}

		quickcheck! {
			// Sealing input, modifying the tag and then opening should
			// always fail due to authentication.
			fn prop_fail_on_diff_key(input: Vec<u8>) -> bool {
				let pt = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let sk = SecretKey::default();
				let sk2 = SecretKey::default();

				let ct = seal(&sk, &pt).unwrap();
				if open(&sk2, &ct).is_err() {
					true
				} else {
					false
				}
			}
		}
	}
}
