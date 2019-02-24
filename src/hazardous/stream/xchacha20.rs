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
//! `Nonce::generate()` can be used for this.
//! - To securely generate a strong key, use `SecretKey::generate()`.
//!
//! # Recommendation:
//! - It is recommended to use XChaCha20Poly1305 when possible.
//!
//! # Example:
//! ```
//! use orion::hazardous::stream::xchacha20;
//!
//! let secret_key = xchacha20::SecretKey::generate().unwrap();
//! let nonce = xchacha20::Nonce::generate().unwrap();
//!
//! // Length of this message is 15
//! let message = "Data to protect".as_bytes();
//!
//! let mut dst_out_pt = [0u8; 15];
//! let mut dst_out_ct = [0u8; 15];
//!
//! xchacha20::encrypt(&secret_key, &nonce, 0, message, &mut dst_out_ct);
//!
//! xchacha20::decrypt(&secret_key, &nonce, 0, &dst_out_ct, &mut dst_out_pt);
//!
//! assert_eq!(dst_out_pt, message);
//! ```
pub use crate::hazardous::stream::chacha20::SecretKey;
use crate::{
	errors::UnknownCryptoError,
	hazardous::{
		constants::{IETF_CHACHA_NONCESIZE, XCHACHA_NONCESIZE},
		stream::chacha20::{self, Nonce as IETFNonce},
	},
};

construct_nonce_with_generator! {
	/// A type that represents a `Nonce` that XChaCha20 and XChaCha20Poly1305 use.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `slice` is not 24 bytes.
	/// - The `OsRng` fails to initialize or read from its source.
	(Nonce, XCHACHA_NONCESIZE)
}

#[must_use]
/// XChaCha20 encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub fn encrypt(
	secret_key: &SecretKey,
	nonce: &Nonce,
	initial_counter: u32,
	plaintext: &[u8],
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	let subkey: SecretKey =
		SecretKey::from_slice(&chacha20::hchacha20(secret_key, &nonce.as_bytes()[0..16])?)?;
	let mut prefixed_nonce = [0u8; IETF_CHACHA_NONCESIZE];
	prefixed_nonce[4..IETF_CHACHA_NONCESIZE].copy_from_slice(&nonce.as_bytes()[16..24]);

	chacha20::encrypt(
		&subkey,
		&IETFNonce::from_slice(&prefixed_nonce)?,
		initial_counter,
		plaintext,
		dst_out,
	)?;

	Ok(())
}

#[must_use]
/// XChaCha20 decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub fn decrypt(
	secret_key: &SecretKey,
	nonce: &Nonce,
	initial_counter: u32,
	ciphertext: &[u8],
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	encrypt(secret_key, nonce, initial_counter, ciphertext, dst_out)?;

	Ok(())
}

#[test]
fn test_nonce_sizes() {
	assert!(Nonce::from_slice(&[0u8; 23]).is_err());
	assert!(Nonce::from_slice(&[0u8; 25]).is_err());
	assert!(Nonce::from_slice(&[0u8; 24]).is_ok());
}

#[test]
fn test_err_on_empty_pt_xchacha() {
	let mut dst = [0u8; 64];

	assert!(encrypt(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 24]).unwrap(),
		0,
		&[0u8; 0],
		&mut dst
	)
	.is_err());
}

#[test]
fn test_err_on_initial_counter_overflow_xchacha() {
	let mut dst = [0u8; 65];

	assert!(encrypt(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 24]).unwrap(),
		4294967295,
		&[0u8; 65],
		&mut dst,
	)
	.is_err());
}

#[test]
fn test_pass_on_one_iter_max_initial_counter() {
	let mut dst = [0u8; 64];
	// Should pass because only one iteration is completed, so block_counter will
	// not increase
	encrypt(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 24]).unwrap(),
		4294967295,
		&[0u8; 64],
		&mut dst,
	)
	.unwrap();
}

//
// The tests below are the same tests as the ones in `chacha20`
// but with a bigger nonce. It's debatable whether this is needed, but right
// now I'm keeping them as they don't seem to bring any disadvantages.
//

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;
	// One function tested per submodule.

	// encrypt()/decrypt() are tested together here
	// since decrypt() is just a wrapper around encrypt()
	// and so only the decrypt() function is called
	mod test_encrypt_decrypt {
		use super::*;
		#[test]
		fn test_fail_on_initial_counter_overflow() {
			let mut dst = [0u8; 65];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				u32::max_value(),
				&[0u8; 65],
				&mut dst,
			)
			.is_err());
		}

		#[test]
		fn test_pass_on_one_iter_max_initial_counter() {
			let mut dst = [0u8; 64];
			// Should pass because only one iteration is completed, so block_counter will
			// not increase
			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				u32::max_value(),
				&[0u8; 64],
				&mut dst,
			)
			.is_ok());
		}

		#[test]
		fn test_fail_on_empty_plaintext() {
			let mut dst = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				0,
				&[0u8; 0],
				&mut dst,
			)
			.is_err());
		}

		#[test]
		fn test_dst_out_length() {
			let mut dst_small = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				0,
				&[0u8; 128],
				&mut dst_small,
			)
			.is_err());

			let mut dst = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				0,
				&[0u8; 64],
				&mut dst,
			)
			.is_ok());

			let mut dst_big = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 24]).unwrap(),
				0,
				&[0u8; 32],
				&mut dst_big,
			)
			.is_ok());
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			/// Given a input length `a` find out how many times
			/// the initial counter on encrypt()/decrypt() would
			/// increase.
			fn counter_increase_times(a: f32) -> u32 {
				// Otherwise a overvlowing subtration would happen
				if a <= 64f32 {
					return 0;
				}

				let check_with_floor = (a / 64f32).floor();
				let actual = a / 64f32;

				assert!(actual >= check_with_floor);
				// Subtract one because the first 64 in length
				// the counter does not increase
				if actual > check_with_floor {
					(actual.ceil() as u32) - 1
				} else {
					(actual as u32) - 1
				}
			}

			quickcheck! {
				// Encrypting input, and then decrypting should always yield the same input.
				fn prop_encrypt_decrypt_same_input(input: Vec<u8>, block_counter: u32) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					// If `block_counter` is high enough check if it would overflow
					if counter_increase_times(pt.len() as f32).checked_add(block_counter).is_none() {
						// Overflow will occur and the operation should fail
						let res = if encrypt(
							&SecretKey::from_slice(&[0u8; 32]).unwrap(),
							&Nonce::from_slice(&[0u8; 24]).unwrap(),
							block_counter,
							&pt[..],
							&mut dst_out_ct,
						).is_err() { true } else { false };

						return res;
					} else {

						encrypt(
							&SecretKey::from_slice(&[0u8; 32]).unwrap(),
							&Nonce::from_slice(&[0u8; 24]).unwrap(),
							block_counter,
							&pt[..],
							&mut dst_out_ct,
						).unwrap();

						decrypt(
							&SecretKey::from_slice(&[0u8; 32]).unwrap(),
							&Nonce::from_slice(&[0u8; 24]).unwrap(),
							block_counter,
							&dst_out_ct[..],
							&mut dst_out_pt,
						).unwrap();

						return dst_out_pt == pt;
					}
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
