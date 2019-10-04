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
//! - `initial_counter`: The initial counter value. In most cases, this is `0`.
//! - `ciphertext`: The encrypted data.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the ciphertext/plaintext after
//!   encryption/decryption.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext` or `ciphertext`.
//! - `plaintext` or `ciphertext` is empty.
//! - The `initial_counter` is high enough to cause a potential overflow.
//!
//! Even though `dst_out` is allowed to be of greater length than `plaintext`,
//! the `ciphertext` produced by `chacha20`/`xchacha20` will always be of the
//! same length as the `plaintext`.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^32-1 * 64 bytes of data are processed.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - Functions herein do not provide any data integrity. If you need
//! data integrity, which is nearly ***always the case***, you should use an
//! AEAD construction instead. See orions `aead` module for this.
//! - Only a nonce for XChaCha20 is big enough to be randomly generated using a
//!   CSPRNG.
//! [`Nonce::generate()`] can be used for this.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//!
//! # Recommendation:
//! - It is recommended to use [XChaCha20Poly1305] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::stream::xchacha20;
//!
//! let secret_key = xchacha20::SecretKey::generate();
//! let nonce = xchacha20::Nonce::generate();
//!
//! // Length of this message is 15
//! let message = "Data to protect".as_bytes();
//!
//! let mut dst_out_pt = [0u8; 15];
//! let mut dst_out_ct = [0u8; 15];
//!
//! xchacha20::encrypt(&secret_key, &nonce, 0, message, &mut dst_out_ct)?;
//!
//! xchacha20::decrypt(&secret_key, &nonce, 0, &dst_out_ct, &mut dst_out_pt)?;
//!
//! assert_eq!(dst_out_pt, message);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`Nonce::generate()`]: struct.Nonce.html
//! [`SecretKey::generate()`]: ../chacha20/struct.SecretKey.html
//! [XChaCha20Poly1305]: ../../aead/xchacha20poly1305/index.html
pub use crate::hazardous::stream::chacha20::SecretKey;
use crate::{
	errors::UnknownCryptoError,
	hazardous::stream::chacha20::{self, Nonce as IETFNonce, IETF_CHACHA_NONCESIZE},
};

/// The nonce size for XChaCha20.
pub const XCHACHA_NONCESIZE: usize = 24;

construct_public! {
	/// A type that represents a `Nonce` that XChaCha20 and XChaCha20Poly1305 use.
	///
	/// # Errors:
	/// An error will be returned if:
	/// - `slice` is not 24 bytes.
	///
	/// # Panics:
	/// A panic will occur if:
	/// - Failure to generate random bytes securely.
	(Nonce, test_nonce, XCHACHA_NONCESIZE, XCHACHA_NONCESIZE, XCHACHA_NONCESIZE)
}

impl_from_trait!(Nonce, XCHACHA_NONCESIZE);

/// Generate a subkey using HChaCha20 for XChaCha20 and corresponding nonce.
pub(crate) fn subkey_and_nonce(secret_key: &SecretKey, nonce: &Nonce) -> (SecretKey, IETFNonce) {
	// .unwrap() should not be able to panic because we pass a 16-byte nonce.
	let subkey: SecretKey =
		SecretKey::from(chacha20::hchacha20(secret_key, &nonce.as_ref()[0..16]).unwrap());
	let mut prefixed_nonce = [0u8; IETF_CHACHA_NONCESIZE];
	prefixed_nonce[4..IETF_CHACHA_NONCESIZE].copy_from_slice(&nonce.as_ref()[16..24]);

	(subkey, IETFNonce::from(prefixed_nonce))
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// XChaCha20 encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn encrypt(
	secret_key: &SecretKey,
	nonce: &Nonce,
	initial_counter: u32,
	plaintext: &[u8],
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	let (subkey, ietf_nonce) = subkey_and_nonce(secret_key, nonce);

	chacha20::encrypt(&subkey, &ietf_nonce, initial_counter, plaintext, dst_out)
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// XChaCha20 decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn decrypt(
	secret_key: &SecretKey,
	nonce: &Nonce,
	initial_counter: u32,
	ciphertext: &[u8],
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	encrypt(secret_key, nonce, initial_counter, ciphertext, dst_out)
}

//
// The tests below are the same tests as the ones in `chacha20`
// but with a bigger nonce. It's debatable whether this is needed, but right
// now I'm keeping them as they don't seem to bring any disadvantages.
//

// Testing public functions in the module.
#[cfg(test)]
#[cfg(feature = "safe_api")]
mod public {
	use super::*;

	mod test_encrypt_decrypt {
		use super::*;
		use crate::test_framework::streamcipher_interface::*;

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				fn prop_streamcipher_interface(input: Vec<u8>, counter: u32) -> bool {
					let secret_key = SecretKey::generate();
					let nonce = Nonce::generate();
					StreamCipherTestRunner(encrypt, decrypt, secret_key, nonce, counter, &input, None);

					true
				}
			}

			quickcheck! {
				// Encrypting and decrypting using two different secret keys and the same nonce
				// should never yield the same input.
				fn prop_encrypt_decrypt_diff_keys_diff_input(input: Vec<u8>) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let sk1 = SecretKey::from_slice(&[0u8; 32]).unwrap();
					let sk2 = SecretKey::from_slice(&[1u8; 32]).unwrap();

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					encrypt(
						&sk1,
						&Nonce::from_slice(&[0u8; 24]).unwrap(),
						0,
						&pt[..],
						&mut dst_out_ct,
					).unwrap();

					decrypt(
						&sk2,
						&Nonce::from_slice(&[0u8; 24]).unwrap(),
						0,
						&dst_out_ct[..],
						&mut dst_out_pt,
					).unwrap();

					(dst_out_pt != pt)
				}
			}

			quickcheck! {
				// Encrypting and decrypting using two different nonces and the same secret key
				// should never yield the same input.
				fn prop_encrypt_decrypt_diff_nonces_diff_input(input: Vec<u8>) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let n1 = Nonce::from_slice(&[0u8; 24]).unwrap();
					let n2 = Nonce::from_slice(&[1u8; 24]).unwrap();

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					encrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&n1,
						0,
						&pt[..],
						&mut dst_out_ct,
					).unwrap();

					decrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&n2,
						0,
						&dst_out_ct[..],
						&mut dst_out_pt,
					).unwrap();

					(dst_out_pt != pt)
				}
			}

			quickcheck! {
				// Encrypting and decrypting using two different initial counters
				// should never yield the same input.
				fn prop_encrypt_decrypt_diff_init_counter_diff_input(input: Vec<u8>) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let init_counter1 = 32;
					let init_counter2 = 64;

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					encrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&Nonce::from_slice(&[0u8; 24]).unwrap(),
						init_counter1,
						&pt[..],
						&mut dst_out_ct,
					).unwrap();

					decrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&Nonce::from_slice(&[0u8; 24]).unwrap(),
						init_counter2,
						&dst_out_ct[..],
						&mut dst_out_pt,
					).unwrap();

					(dst_out_pt != pt)
				}
			}
		}
	}
}
