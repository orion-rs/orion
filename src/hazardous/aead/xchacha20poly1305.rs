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
//!   `None`).
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 16 byte
//!   Poly1305 tag
//! appended to it.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the
//!   `ciphertext_with_tag`/`plaintext` after encryption/decryption.
//!
//! `ad`: "A typical use for these data is to authenticate version numbers,
//! timestamps or monotonically increasing counters in order to discard previous
//! messages and prevent replay attacks." See [libsodium docs](https://download.libsodium.org/doc/secret-key_cryptography/aead#additional-data) for more information.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext + 16` when encrypting.
//! - The length of `dst_out` is less than `ciphertext_with_tag - 16` when
//!   decrypting.
//! - The length of `ciphertext_with_tag` is not greater than `16`.
//! - `plaintext` or `ciphertext_with_tag` are empty.
//! - `plaintext` or `ciphertext_with_tag - 16` are longer than (2^32)-2.
//! - The received tag does not match the calculated tag when decrypting.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - Only a nonce for XChaCha20Poly1305 is big enough to be randomly generated
//!   using a CSPRNG.
//! `Nonce::generate()` can be used for this.
//! - To securely generate a strong key, use `SecretKey::generate()`.
//!
//! # Recommendation:
//! - It is recommended to use XChaCha20Poly1305 when possible.
//!
//! # Example:
//! ```
//! use orion::hazardous::aead;
//!
//! let secret_key = aead::xchacha20poly1305::SecretKey::generate().unwrap();
//! let nonce = aead::xchacha20poly1305::Nonce::generate().unwrap();
//!
//! let ad = [
//! 	0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
//! 	];
//! let plaintext = b"\
//! Ladies and Gentlemen of the class of '99: If I could offer you o\
//! nly one tip for the future, sunscreen would be it.";
//!
//! // Length of above plaintext is 114 and then we accomodate 16 for the Poly1305
//! // tag.
//!
//! let mut dst_out_ct = [0u8; 114 + 16];
//! let mut dst_out_pt = [0u8; 114];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! aead::xchacha20poly1305::seal(&secret_key, &nonce, plaintext, Some(&ad), &mut dst_out_ct)
//! 	.unwrap();
//! // Verify tag, if correct then decrypt and place plaintext in dst_out_pt
//! aead::xchacha20poly1305::open(&secret_key, &nonce, &dst_out_ct, Some(&ad), &mut dst_out_pt)
//! 	.unwrap();
//!
//! assert_eq!(dst_out_pt.as_ref(), plaintext.as_ref());
//! ```
pub use crate::hazardous::stream::{chacha20::SecretKey, xchacha20::Nonce};
use crate::{
	errors::UnknownCryptoError,
	hazardous::{
		aead::chacha20poly1305,
		constants::IETF_CHACHA_NONCESIZE,
		stream::chacha20::{self, Nonce as IETFNonce},
	},
};

#[must_use]
/// AEAD XChaCha20Poly1305 encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn seal(
	secret_key: &SecretKey,
	nonce: &Nonce,
	plaintext: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	let subkey: SecretKey =
		SecretKey::from_slice(&chacha20::hchacha20(secret_key, &nonce.as_bytes()[0..16])?)?;
	let mut prefixed_nonce = [0u8; IETF_CHACHA_NONCESIZE];
	prefixed_nonce[4..IETF_CHACHA_NONCESIZE].copy_from_slice(&nonce.as_bytes()[16..24]);

	chacha20poly1305::seal(
		&subkey,
		&IETFNonce::from_slice(&prefixed_nonce)?,
		plaintext,
		ad,
		dst_out,
	)?;

	Ok(())
}

#[must_use]
/// AEAD XChaCha20Poly1305 decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn open(
	secret_key: &SecretKey,
	nonce: &Nonce,
	ciphertext_with_tag: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	let subkey: SecretKey =
		SecretKey::from_slice(&chacha20::hchacha20(secret_key, &nonce.as_bytes()[0..16])?)?;
	let mut prefixed_nonce = [0u8; 12];
	prefixed_nonce[4..12].copy_from_slice(&nonce.as_bytes()[16..24]);

	chacha20poly1305::open(
		&subkey,
		&IETFNonce::from_slice(&prefixed_nonce)?,
		ciphertext_with_tag,
		ad,
		dst_out,
	)?;

	Ok(())
}

//
// The tests below are the same tests as the ones in `chacha20poly1305`
// but with a bigger nonce. It's debatable whether this is needed, but right
// now I'm keeping them as they don't seem to bring any disadvantages.
//

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;
	use crate::hazardous::constants::POLY1305_OUTSIZE;
	// One function tested per submodule.

	mod test_seal {
		use super::*;

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/52
		fn test_dst_out_length() {
			let mut dst_out_ct = [0u8; 80]; // 64 + Poly1305TagLen
			let mut dst_out_ct_less = [0u8; 79]; // 64 + Poly1305TagLen - 1
			let mut dst_out_ct_more = [0u8; 81]; // 64 + Poly1305TagLen + 1
			let mut dst_out_ct_more_2 = [0u8; 64 + (POLY1305_OUTSIZE * 2)];

			assert!(seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 64],
				None,
				&mut dst_out_ct,
			)
			.is_ok());

			// Related bug: #52
			assert!(seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 64],
				None,
				&mut dst_out_ct_more,
			)
			.is_ok());

			// Related bug: #52
			assert!(seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 64],
				None,
				&mut dst_out_ct_more_2,
			)
			.is_ok());

			assert!(seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 64],
				None,
				&mut dst_out_ct_less,
			)
			.is_err());
		}

		#[test]
		fn test_plaintext_length() {
			let mut dst_out_ct_0 = [0u8; 16]; // 0 + Poly1305TagLen
			let mut dst_out_ct_1 = [0u8; 17]; // 1 + Poly1305TagLen
			let mut dst_out_ct_128 = [0u8; 144]; // 128 + Poly1305TagLen

			assert!(seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 0],
				None,
				&mut dst_out_ct_0,
			)
			.is_err());

			assert!(seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 1],
				None,
				&mut dst_out_ct_1,
			)
			.is_ok());

			assert!(seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 128],
				None,
				&mut dst_out_ct_128,
			)
			.is_ok());
		}
	}

	mod test_open {
		use super::*;

		#[test]
		fn test_ciphertext_with_tag_length() {
			let mut dst_out_pt = [0u8; 64];

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 0],
				None,
				&mut dst_out_pt,
			)
			.is_err());

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; POLY1305_OUTSIZE],
				None,
				&mut dst_out_pt,
			)
			.is_err());

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; POLY1305_OUTSIZE - 1],
				None,
				&mut dst_out_pt,
			)
			.is_err());

			let mut dst_out_ct = [0u8; 64 + 16];
			seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; POLY1305_OUTSIZE + 1],
				None,
				&mut dst_out_ct,
			)
			.unwrap();

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&dst_out_ct[..(POLY1305_OUTSIZE + 1) + 16],
				None,
				&mut dst_out_pt,
			)
			.is_ok());
		}

		#[test]
		fn test_dst_out_length() {
			let mut dst_out_ct = [0u8; 64 + 16];
			seal(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&[0u8; 64],
				None,
				&mut dst_out_ct,
			)
			.unwrap();

			let mut dst_out_pt = [0u8; 64];
			let mut dst_out_pt_0 = [0u8; 0];
			let mut dst_out_pt_less = [0u8; 63];
			let mut dst_out_pt_more = [0u8; 65];

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&dst_out_ct,
				None,
				&mut dst_out_pt,
			)
			.is_ok());

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&dst_out_ct,
				None,
				&mut dst_out_pt_0,
			)
			.is_err());

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&dst_out_ct,
				None,
				&mut dst_out_pt_less,
			)
			.is_err());

			assert!(open(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				&dst_out_ct,
				None,
				&mut dst_out_pt_more,
			)
			.is_ok());
		}
	}

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use super::*;

		// Only return true if both a and b are true.
		fn check_all_true(a: bool, b: bool) -> bool { (a == true) && (b == true) }

		quickcheck! {
			// Sealing input, and then opening should always yield the same input.
			fn prop_seal_open_same_input(input: Vec<u8>, ad: Vec<u8>) -> bool {
				let pt = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let mut dst_out_ct_no_ad = vec![0u8; pt.len() + POLY1305_OUTSIZE];
				let mut dst_out_pt_no_ad = vec![0u8; pt.len()];

				let mut dst_out_ct_with_ad = vec![0u8; pt.len() + POLY1305_OUTSIZE];
				let mut dst_out_pt_with_ad = vec![0u8; pt.len()];

				seal(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&pt[..],
					None,
					&mut dst_out_ct_no_ad,
				).unwrap();

				open(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&dst_out_ct_no_ad[..],
					None,
					&mut dst_out_pt_no_ad,
				).unwrap();

				seal(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&pt[..],
					Some(&ad[..]),
					&mut dst_out_ct_with_ad,
				).unwrap();

				open(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&dst_out_ct_with_ad[..],
					Some(&ad[..]),
					&mut dst_out_pt_with_ad,
				).unwrap();

				check_all_true(dst_out_pt_no_ad == pt, dst_out_pt_with_ad == pt)
			}
		}

		quickcheck! {
			// Sealing input, modifying the tag and then opening should
			// always fail due to authentication.
			fn prop_fail_on_bad_auth_tag(input: Vec<u8>, ad: Vec<u8>) -> bool {
				let pt = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let mut dst_out_ct_no_ad = vec![0u8; pt.len() + POLY1305_OUTSIZE];
				let mut dst_out_pt_no_ad = vec![0u8; pt.len()];

				let mut dst_out_ct_with_ad = vec![0u8; pt.len() + POLY1305_OUTSIZE];
				let mut dst_out_pt_with_ad = vec![0u8; pt.len()];

				seal(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&pt[..],
					None,
					&mut dst_out_ct_no_ad,
				).unwrap();

				// Modify tags first byte
				dst_out_ct_no_ad[pt.len() + 1] ^= 1;

				let res0 = if open(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&dst_out_ct_no_ad[..],
					None,
					&mut dst_out_pt_no_ad,
				).is_err() {
					true
				} else {
					false
				};

				seal(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&pt[..],
					Some(&ad[..]),
					&mut dst_out_ct_with_ad,
				).unwrap();

				// Modify tags first byte
				dst_out_ct_with_ad[pt.len() + 1] ^= 1;

				let res1 = if open(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&dst_out_ct_with_ad[..],
					Some(&ad[..]),
					&mut dst_out_pt_with_ad,
				).is_err() {
					true
				} else {
					false
				};

				check_all_true(res0, res1)
			}
		}

		quickcheck! {
			// Sealing input, modifying the ciphertext and then opening should
			// always fail due to authentication.
			fn prop_fail_on_bad_ciphertext(input: Vec<u8>, ad: Vec<u8>) -> bool {
				let pt = if input.is_empty() {
					vec![1u8; 10]
				} else {
					input
				};

				let mut dst_out_ct_no_ad = vec![0u8; pt.len() + POLY1305_OUTSIZE];
				let mut dst_out_pt_no_ad = vec![0u8; pt.len()];

				let mut dst_out_ct_with_ad = vec![0u8; pt.len() + POLY1305_OUTSIZE];
				let mut dst_out_pt_with_ad = vec![0u8; pt.len()];

				seal(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&pt[..],
					None,
					&mut dst_out_ct_no_ad,
				).unwrap();

				// Modify ciphertexts first byte
				dst_out_ct_no_ad[0] ^= 1;

				let res0 = if open(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&dst_out_ct_no_ad[..],
					None,
					&mut dst_out_pt_no_ad,
				).is_err() {
					true
				} else {
					false
				};

				seal(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&pt[..],
					Some(&ad[..]),
					&mut dst_out_ct_with_ad,
				).unwrap();

				// Modify tags first byte
				dst_out_ct_with_ad[0] ^= 1;

				let res1 = if open(
					&SecretKey::from_slice(&[0u8; 32]).unwrap(),
					&Nonce::from_slice(&[0u8; 24]).unwrap(),
					&dst_out_ct_with_ad[..],
					Some(&ad[..]),
					&mut dst_out_pt_with_ad,
				).is_err() {
					true
				} else {
					false
				};

				check_all_true(res0, res1)
			}
		}
	}
}
