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
//! - `password`: Password.
//! - `salt`: Salt value.
//! - `iterations`: Iteration count.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `dk_out`.
//! - `expected`: The expected derived key.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than 1.
//! - The specified iteration count is less than 1.
//! - The hashed password does not match the expected when verifying.
//!
//! # Panics:
//! A panic will occur if:
//! - The length of `dst_out` is greater than (2^32 - 1) * 64.
//!
//! # Security:
//! - Use [`Password::generate()`] to randomly generate a password of 128 bytes.
//! - Salts should always be generated using a CSPRNG.
//!   [`util::secure_rand_bytes()`] can be used for this.
//! - The recommended length for a salt is 64 bytes.
//! - The iteration count should be set as high as feasible. The recommended
//!   minimum is 100000.
//!
//! # Example:
//! ```rust
//! use orion::{hazardous::kdf::pbkdf2, util};
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt)?;
//! let password = pbkdf2::Password::from_slice("Secret password".as_bytes())?;
//! let mut dk_out = [0u8; 64];
//!
//! pbkdf2::derive_key(&password, &salt, 10000, &mut dk_out)?;
//!
//! let exp_dk = dk_out;
//!
//! assert!(pbkdf2::verify(
//! 	&exp_dk,
//! 	&password,
//! 	&salt,
//! 	10000,
//! 	&mut dk_out
//! )?);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`Password::generate()`]: https://docs.rs/orion/latest/orion/hazardous/kdf/pbkdf2/struct.Password.html
//! [`util::secure_rand_bytes()`]: https://docs.rs/orion/latest/orion/util/fn.secure_rand_bytes.html

use crate::{
	errors::UnknownCryptoError,
	hazardous::{
		hash::sha512::{SHA512_BLOCKSIZE, SHA512_OUTSIZE},
		mac::hmac,
	},
	util,
};

construct_hmac_key! {
	/// A type to represent the `Password` that PBKDF2 hashes.
	///
	/// # Note:
	/// Because `Password` is used as a `SecretKey` for HMAC during hashing, `Password` already
	/// pads the given password to a length of 128, for use in HMAC, when initialized.
	///
	/// Using `unprotected_as_bytes()` will return the password with padding.
	///
	/// Using `get_length()` will return the length with padding (always 128).
	///
	/// # Panics:
	/// A panic will occur if:
	/// - Failure to generate random bytes securely.
	(Password, SHA512_BLOCKSIZE)
}

#[inline]
/// The F function as described in the RFC.
fn function_f(
	salt: &[u8],
	iterations: usize,
	index: u32,
	dk_block: &mut [u8],
	block_len: usize,
	hmac: &mut hmac::Hmac,
) -> Result<(), UnknownCryptoError> {
	let mut u_step: [u8; SHA512_OUTSIZE] = [0u8; 64];
	hmac.update(salt)?;
	hmac.update(&index.to_be_bytes())?;

	u_step.copy_from_slice(&hmac.finalize()?.unprotected_as_bytes());
	dk_block.copy_from_slice(&u_step[..block_len]);

	if iterations > 1 {
		for _ in 1..iterations {
			hmac.reset();
			hmac.update(&u_step)?;
			u_step.copy_from_slice(&hmac.finalize()?.unprotected_as_bytes());
			dk_block
				.iter_mut()
				.zip(u_step.iter())
				.for_each(|(a, b)| *a ^= b);
		}
	}

	Ok(())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// PBKDF2-SHA512 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub fn derive_key(
	password: &Password,
	salt: &[u8],
	iterations: usize,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	if iterations < 1 {
		return Err(UnknownCryptoError);
	}
	if dst_out.is_empty() {
		return Err(UnknownCryptoError);
	}

	let mut hmac = hmac::Hmac::new(&hmac::SecretKey::from_slice(
		&password.unprotected_as_bytes(),
	)?);

	for (idx, dk_block) in dst_out.chunks_mut(SHA512_OUTSIZE).enumerate() {
		// If this panics, then the size limit for PBKDF2 is reached.
		let block_idx = (1u32).checked_add(idx as u32).unwrap();

		function_f(
			salt,
			iterations,
			block_idx,
			dk_block,
			dk_block.len(),
			&mut hmac,
		)?;
		hmac.reset();
	}

	Ok(())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Verify PBKDF2-HMAC-SHA512 derived key in constant time.
pub fn verify(
	expected: &[u8],
	password: &Password,
	salt: &[u8],
	iterations: usize,
	dst_out: &mut [u8],
) -> Result<bool, UnknownCryptoError> {
	derive_key(password, salt, iterations, dst_out)?;
	util::secure_cmp(&dst_out, expected)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	// One function tested per submodule.

	mod test_verify {
		use super::*;

		#[test]
		fn verify_true() {
			let password = Password::from_slice("pass\0word".as_bytes()).unwrap();
			let salt = "sa\0lt".as_bytes();
			let iterations: usize = 4096;
			let mut okm_out = [0u8; 16];
			let mut okm_out_verify = [0u8; 16];

			derive_key(&password, &salt, iterations, &mut okm_out).unwrap();

			assert!(verify(&okm_out, &password, salt, iterations, &mut okm_out_verify).is_ok());
		}

		#[test]
		fn verify_false_wrong_salt() {
			let password = Password::from_slice("pass\0word".as_bytes()).unwrap();
			let salt = "sa\0lt".as_bytes();
			let iterations: usize = 4096;
			let mut okm_out = [0u8; 16];
			let mut okm_out_verify = [0u8; 16];

			derive_key(&password, &salt, iterations, &mut okm_out).unwrap();

			assert!(verify(&okm_out, &password, b"", iterations, &mut okm_out_verify).is_err());
		}
		#[test]
		fn verify_false_wrong_password() {
			let password = Password::from_slice("pass\0word".as_bytes()).unwrap();
			let salt = "sa\0lt".as_bytes();
			let iterations: usize = 4096;
			let mut okm_out = [0u8; 16];
			let mut okm_out_verify = [0u8; 16];

			derive_key(&password, &salt, iterations, &mut okm_out).unwrap();

			assert!(verify(
				&okm_out,
				&Password::from_slice(b"").unwrap(),
				salt,
				iterations,
				&mut okm_out_verify
			)
			.is_err());
		}

		#[test]
		fn verify_diff_dklen_error() {
			let password = Password::from_slice("pass\0word".as_bytes()).unwrap();
			let salt = "sa\0lt".as_bytes();
			let iterations: usize = 4096;
			let mut okm_out = [0u8; 16];
			let mut okm_out_verify = [0u8; 32];

			derive_key(&password, &salt, iterations, &mut okm_out).unwrap();

			assert!(verify(&okm_out, &password, salt, iterations, &mut okm_out_verify).is_err());
		}

		#[test]
		fn verify_diff_iter_error() {
			let password = Password::from_slice("pass\0word".as_bytes()).unwrap();
			let salt = "sa\0lt".as_bytes();
			let iterations: usize = 4096;
			let mut okm_out = [0u8; 16];
			let mut okm_out_verify = [0u8; 16];

			derive_key(&password, &salt, iterations, &mut okm_out).unwrap();

			assert!(verify(&okm_out, &password, salt, 1024, &mut okm_out_verify).is_err());
		}
	}

	mod test_derive_key {
		use super::*;

		#[test]
		fn zero_iterations_err() {
			let password = Password::from_slice("password".as_bytes()).unwrap();
			let salt = "salt".as_bytes();
			let iterations: usize = 0;
			let mut okm_out = [0u8; 15];

			assert!(derive_key(&password, salt, iterations, &mut okm_out).is_err());
		}

		#[test]
		fn zero_dklen_err() {
			let password = Password::from_slice("password".as_bytes()).unwrap();
			let salt = "salt".as_bytes();
			let iterations: usize = 1;
			let mut okm_out = [0u8; 0];

			assert!(derive_key(&password, salt, iterations, &mut okm_out).is_err());
		}
	}
}
