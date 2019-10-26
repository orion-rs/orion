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
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `ad`: Additional data to authenticate (this is not encrypted and can be
//!   `None`.  This data is also not a part of `dst_out`).
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 16 byte
//!   Poly1305 tag appended to it.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the
//!   `ciphertext_with_tag`/`plaintext` after encryption/decryption.
//!
//! `ad`: "A typical use for these data is to authenticate version numbers,
//! timestamps or monotonically increasing counters in order to discard previous
//! messages and prevent replay attacks." See [libsodium docs](https://download.libsodium.org/doc/secret-key_cryptography/aead#additional-data) for more information.
//!
//! `nonce`: "Counters and LFSRs are both acceptable ways of generating unique
//! nonces, as is encrypting a counter using a block cipher with a 64-bit block
//! size such as DES.  Note that it is not acceptable to use a truncation of a
//! counter encrypted with block ciphers with 128-bit or 256-bit blocks,
//! because such a truncation may repeat after a short time." See [RFC](https://tools.ietf.org/html/rfc8439#section-3)
//! for more information.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext + 16` when encrypting.
//! - The length of `dst_out` is less than `ciphertext_with_tag - 16` when
//!   decrypting.
//! - The length of `ciphertext_with_tag` is not greater than `16`.
//! - `plaintext` or `ciphertext_with_tag` are empty.
//! - The received tag does not match the calculated tag when decrypting.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^32-1 * 64 bytes of data are processed.
//! - `plaintext.len()` + [`POLY1305_OUTSIZE`] overflows when encrypting.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - Only a nonce for XChaCha20Poly1305 is big enough to be randomly generated
//!   using a CSPRNG.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//!
//! # Recommendation:
//! - It is recommended to use [XChaCha20Poly1305] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::aead;
//!
//! let secret_key = aead::chacha20poly1305::SecretKey::generate();
//!
//! let nonce = aead::chacha20poly1305::Nonce::from_slice(&[
//! 	0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
//! ])?;
//! let ad = "Additional data".as_bytes();
//! let message = "Data to protect".as_bytes();
//!
//! // Length of the above message is 15 and then we accommodate 16 for the Poly1305
//! // tag.
//!
//! let mut dst_out_ct = [0u8; 15 + 16];
//! let mut dst_out_pt = [0u8; 15];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! aead::chacha20poly1305::seal(&secret_key, &nonce, message, Some(&ad), &mut dst_out_ct)?;
//! // Verify tag, if correct then decrypt and place message in dst_out_pt
//! aead::chacha20poly1305::open(&secret_key, &nonce, &dst_out_ct, Some(&ad), &mut dst_out_pt)?;
//!
//! assert_eq!(dst_out_pt.as_ref(), message.as_ref());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: ../../stream/chacha20/struct.SecretKey.html
//! [XChaCha20Poly1305]: ../xchacha20poly1305/index.html
//! [`POLY1305_OUTSIZE`]: ../../mac/poly1305/constant.POLY1305_OUTSIZE.html
pub use crate::hazardous::stream::chacha20::{Nonce, SecretKey};
use crate::{
	errors::UnknownCryptoError,
	hazardous::{
		mac::poly1305::{self, OneTimeKey, POLY1305_KEYSIZE, POLY1305_OUTSIZE},
		stream::chacha20,
	},
	util,
};

#[inline]
/// Poly1305 key generation using IETF ChaCha20.
pub(crate) fn poly1305_key_gen(
	key: &SecretKey,
	nonce: &Nonce,
) -> Result<OneTimeKey, UnknownCryptoError> {
	OneTimeKey::from_slice(&chacha20::keystream_block(key, nonce, 0)?[..POLY1305_KEYSIZE])
}

#[inline]
/// Padding size that gives the needed bytes to pad `input` to an integral
/// multiple of 16.
pub(crate) fn padding(input: usize) -> usize {
	if input == 0 {
		return 0;
	}

	let rem = input % 16;

	if rem != 0 {
		16 - rem
	} else {
		0
	}
}

#[inline]
/// Process data to be authenticated using a `Poly1305` struct initialized with
/// a one-time-key. Up to `buf_in_len` data in `buf` get's authenticated. The
/// indexing is needed because authentication happens on different input lenghts
/// in seal()/open().
fn process_authentication(
	poly1305_state: &mut poly1305::Poly1305,
	ad: &[u8],
	buf: &[u8],
	buf_in_len: usize,
) -> Result<(), UnknownCryptoError> {
	// If buf_in_len is 0, then NO ciphertext gets authenticated.
	// Because of this, buf may never be empty either.
	debug_assert!(!buf.is_empty());
	debug_assert!(buf_in_len <= buf.len());
	assert!(buf_in_len > 0);

	let mut padding_max = [0u8; 16];

	if !ad.is_empty() {
		poly1305_state.update(ad)?;
		poly1305_state.update(&padding_max[..padding(ad.len())])?;
	}

	poly1305_state.update(&buf[..buf_in_len])?;
	poly1305_state.update(&padding_max[..padding(buf[..buf_in_len].len())])?;

	// Using the 16 bytes from padding template to store length information
	if !ad.is_empty() {
		// If ad is empty then padding_max[..8] already reflects its 0-length
		// since it was initialized with 0's.
		padding_max[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
	}

	padding_max[8..16].copy_from_slice(&(buf_in_len as u64).to_le_bytes());
	poly1305_state.update(padding_max.as_ref())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// AEAD ChaCha20Poly1305 encryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn seal(
	secret_key: &SecretKey,
	nonce: &Nonce,
	plaintext: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	if dst_out.len() < plaintext.len().checked_add(POLY1305_OUTSIZE).unwrap() {
		return Err(UnknownCryptoError);
	}
	if plaintext.is_empty() {
		return Err(UnknownCryptoError);
	}

	let optional_ad = match ad {
		Some(n_val) => n_val,
		None => &[0u8; 0],
	};

	chacha20::encrypt(
		secret_key,
		nonce,
		1,
		plaintext,
		&mut dst_out[..plaintext.len()],
	)?;

	let poly1305_key = poly1305_key_gen(secret_key, nonce)?;
	let mut poly1305_state = poly1305::Poly1305::new(&poly1305_key);

	process_authentication(&mut poly1305_state, optional_ad, &dst_out, plaintext.len())?;
	dst_out[plaintext.len()..(plaintext.len() + POLY1305_OUTSIZE)]
		.copy_from_slice(poly1305_state.finalize()?.unprotected_as_bytes());

	Ok(())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// AEAD ChaCha20Poly1305 decryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn open(
	secret_key: &SecretKey,
	nonce: &Nonce,
	ciphertext_with_tag: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	if ciphertext_with_tag.len() <= POLY1305_OUTSIZE {
		return Err(UnknownCryptoError);
	}
	if dst_out.len() < ciphertext_with_tag.len() - POLY1305_OUTSIZE {
		return Err(UnknownCryptoError);
	}

	let optional_ad = match ad {
		Some(n_val) => n_val,
		None => &[0u8; 0],
	};

	let ciphertext_len = ciphertext_with_tag.len() - POLY1305_OUTSIZE;

	let poly1305_key = poly1305_key_gen(secret_key, nonce)?;
	let mut poly1305_state = poly1305::Poly1305::new(&poly1305_key);
	process_authentication(
		&mut poly1305_state,
		optional_ad,
		ciphertext_with_tag,
		ciphertext_len,
	)?;

	util::secure_cmp(
		poly1305_state.finalize()?.unprotected_as_bytes(),
		&ciphertext_with_tag[ciphertext_len..],
	)?;

	chacha20::decrypt(
		secret_key,
		nonce,
		1,
		&ciphertext_with_tag[..ciphertext_len],
		dst_out,
	)
}

// Testing public functions in the module.
#[cfg(test)]
#[cfg(feature = "safe_api")]
mod public {
	use super::*;

	// Proptests. Only executed when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use super::*;
		use crate::test_framework::aead_interface::*;

		quickcheck! {
			fn prop_aead_interface(input: Vec<u8>, ad: Vec<u8>) -> bool {
				let secret_key = SecretKey::generate();
				let nonce = Nonce::from_slice(&[0u8; chacha20::IETF_CHACHA_NONCESIZE]).unwrap();
				AeadTestRunner(seal, open, secret_key, nonce, &input, None, POLY1305_OUTSIZE, &ad);

				true
			}
		}
	}
}

// Testing private functions in the module.
#[cfg(test)]
mod private {
	use super::*;

	mod test_padding {
		use super::*;
		#[test]
		fn test_length_padding() {
			assert_eq!(padding(0), 0);
			assert_eq!(padding(1), 15);
			assert_eq!(padding(2), 14);
			assert_eq!(padding(3), 13);
			assert_eq!(padding(4), 12);
			assert_eq!(padding(5), 11);
			assert_eq!(padding(6), 10);
			assert_eq!(padding(7), 9);
			assert_eq!(padding(8), 8);
			assert_eq!(padding(9), 7);
			assert_eq!(padding(10), 6);
			assert_eq!(padding(11), 5);
			assert_eq!(padding(12), 4);
			assert_eq!(padding(13), 3);
			assert_eq!(padding(14), 2);
			assert_eq!(padding(15), 1);
			assert_eq!(padding(16), 0);
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				// The usize that padding() returns should always
				// be what remains to make input a multiple of 16 in length.
				fn prop_padding_result(input: usize) -> bool {
					let rem = padding(input);

					(((input + rem) % 16) == 0)
				}
			}

			quickcheck! {
				// padding() should never return a usize above 15.
				// The usize must always be in range of 0..=15.
				fn prop_result_never_above_15(input: usize) -> bool {
					padding(input) < 16
				}
			}
		}
	}

	mod test_process_authentication {
		use super::*;

		#[test]
		#[should_panic]
		fn test_panic_index_0() {
			let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();
			let n = Nonce::from_slice(&[0u8; 12]).unwrap();

			let poly1305_key = poly1305_key_gen(&sk, &n).unwrap();
			let mut poly1305_state = poly1305::Poly1305::new(&poly1305_key);

			process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 0).unwrap();
		}

		#[test]
		#[should_panic]
		fn test_panic_empty_buf() {
			let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();
			let n = Nonce::from_slice(&[0u8; 12]).unwrap();

			let poly1305_key = poly1305_key_gen(&sk, &n).unwrap();
			let mut poly1305_state = poly1305::Poly1305::new(&poly1305_key);

			process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 0], 64).unwrap();
		}

		#[test]
		#[should_panic]
		fn test_panic_above_length_index() {
			let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();
			let n = Nonce::from_slice(&[0u8; 12]).unwrap();

			let poly1305_key = poly1305_key_gen(&sk, &n).unwrap();
			let mut poly1305_state = poly1305::Poly1305::new(&poly1305_key);

			process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 65).unwrap();
		}

		#[test]
		fn test_length_index() {
			let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();
			let n = Nonce::from_slice(&[0u8; 12]).unwrap();

			let poly1305_key = poly1305_key_gen(&sk, &n).unwrap();
			let mut poly1305_state = poly1305::Poly1305::new(&poly1305_key);

			assert!(process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 64).is_ok());
			assert!(process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 63).is_ok());
			assert!(process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 1).is_ok());
			assert!(process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 1], 1).is_ok());
		}
	}
}

// Testing any test vectors that aren't put into library's /tests folder.
#[cfg(test)]
mod test_vectors {
	use super::*;

	#[test]
	fn rfc8439_poly1305_key_gen_1() {
		let key = SecretKey::from_slice(&[0u8; 32]).unwrap();
		let nonce = Nonce::from_slice(&[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		])
		.unwrap();
		let expected = [
			0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
			0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
			0x8b, 0x77, 0x0d, 0xc7,
		];

		assert_eq!(
			poly1305_key_gen(&key, &nonce)
				.unwrap()
				.unprotected_as_bytes(),
			expected.as_ref()
		);
	}

	#[test]
	fn rfc8439_poly1305_key_gen_2() {
		let key = SecretKey::from_slice(&[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
		])
		.unwrap();
		let nonce = Nonce::from_slice(&[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		])
		.unwrap();
		let expected = [
			0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74, 0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9,
			0xe8, 0x76, 0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87, 0xbc, 0x26, 0x66, 0xdd,
			0xe3, 0xfb, 0xb7, 0x39,
		];

		assert_eq!(
			poly1305_key_gen(&key, &nonce)
				.unwrap()
				.unprotected_as_bytes(),
			expected.as_ref()
		);
	}

	#[test]
	fn rfc8439_poly1305_key_gen_3() {
		let key = SecretKey::from_slice(&[
			0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
			0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc,
			0x20, 0x70, 0x75, 0xc0,
		])
		.unwrap();
		let nonce = Nonce::from_slice(&[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		])
		.unwrap();
		let expected = [
			0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9, 0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29,
			0xf9, 0x4b, 0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb, 0xdd, 0x59, 0xde, 0xaa,
			0xd2, 0x33, 0x10, 0xae,
		];

		assert_eq!(
			poly1305_key_gen(&key, &nonce)
				.unwrap()
				.unprotected_as_bytes(),
			expected.as_ref()
		);
	}
}
