// MIT License

// Copyright (c) 2018 brycx

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

//! Key derivation.
//!
//! # Use case:
//! `orion::kdf` can be used to derive higher-entropy keys from low-entropy
//! keys. Also known as key stretching.
//!
//! An example of this could be deriving a key from a user-submitted password
//! and using this derived key in disk encryption. The disk encryption software VeraCrypt, [uses](https://www.veracrypt.fr/en/Header%20Key%20Derivation.html)
//! PBKDF2-HMAC-SHA512 to derive header keys, which in turn are used to
//! encrypt/decrypt the master keys responsible for encrypting the data in a
//! VeraCrypt volume.
//!
//!
//! # About:
//! - Uses PBKDF2-HMAC-SHA512.
//!
//! # Parameters:
//! - `password`: The low-entropy input key to be used in key derivation.
//! - `expected`: The expected derived key.
//! - `salt`: The salt used for the key derivation.
//! - `iterations`: The number of iterations performed by PBKDF2, i.e. the cost
//!   parameter.
//! - `length`: The desired length of the derived key.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `iterations` is 0.
//! - `length` is 0.
//! - `length` is not less than `u32::max_value()`.
//! - The `OsRng` fails to initialize or read from its source.
//! - The `expected` does not match the derived key.
//!
//!
//! # Security:
//! - The iteration count should be set as high as feasible. The recommended
//!   minimum is 100000.
//! - The salt should always be generated using a CSPRNG. `Salt::default()` can
//!   be used for
//! this, it will generate a `Salt` of 64 bytes.
//!
//! # Example:
//! ```
//! use orion::kdf;
//!
//! let user_password = kdf::Password::from_slice(b"User password").unwrap();
//! let salt = kdf::Salt::default();
//!
//! let derived_key = kdf::derive_key(&user_password, &salt, 100000, 64).unwrap();
//!
//! assert!(kdf::derive_key_verify(&derived_key, &user_password, &salt, 100000).unwrap());
//! ```

pub use crate::hltypes::{Password, Salt, SecretKey};
use crate::{
	errors::{UnknownCryptoError, ValidationCryptoError},
	hazardous::kdf::pbkdf2,
};
use clear_on_drop::clear::Clear;

#[must_use]
/// Derive a key using PBKDF2-HMAC-SHA512.
pub fn derive_key(
	password: &Password,
	salt: &Salt,
	iterations: usize,
	length: usize,
) -> Result<SecretKey, UnknownCryptoError> {
	if length < 1 || length >= (u32::max_value() as usize) {
		return Err(UnknownCryptoError);
	}

	let mut buffer = vec![0u8; length];

	pbkdf2::derive_key(
		&pbkdf2::Password::from_slice(password.unprotected_as_bytes())?,
		&salt.as_bytes(),
		iterations,
		&mut buffer,
	)?;

	let dk = SecretKey::from_slice(&buffer)?;
	Clear::clear(&mut buffer);

	Ok(dk)
}

#[must_use]
/// Derive and verify a key using PBKDF2-HMAC-SHA512.
pub fn derive_key_verify(
	expected: &SecretKey,
	password: &Password,
	salt: &Salt,
	iterations: usize,
) -> Result<bool, ValidationCryptoError> {
	let mut buffer = vec![0u8; expected.get_length()];

	let is_good = pbkdf2::verify(
		&expected.unprotected_as_bytes(),
		&pbkdf2::Password::from_slice(password.unprotected_as_bytes())?,
		&salt.as_bytes(),
		iterations,
		&mut buffer,
	)?;

	Clear::clear(&mut buffer);

	Ok(is_good)
}

#[test]
fn derive_key_and_verify() {
	let password = Password::from_slice(&[0u8; 64]).unwrap();
	let salt = Salt::from_slice(&[0u8; 64]).unwrap();

	let dk = derive_key(&password, &salt, 100, 64).unwrap();

	assert!(derive_key_verify(&dk, &password, &salt, 100).unwrap());
}

#[test]
fn derive_key_and_verify_err() {
	let password = Password::from_slice(&[0u8; 64]).unwrap();
	let salt = Salt::from_slice(&[0u8; 64]).unwrap();

	let dk = derive_key(&password, &salt, 100, 64).unwrap();

	assert!(derive_key_verify(&dk, &password, &salt, 50).is_err());
}

#[test]
fn derive_key_bad_length() {
	let password = Password::from_slice(&[0u8; 64]).unwrap();
	let salt = Salt::from_slice(&[0u8; 64]).unwrap();

	assert!(derive_key(&password, &salt, 100, 0).is_err());
	assert!(derive_key(&password, &salt, 100, 1).is_ok());
	assert!(derive_key(&password, &salt, 100, usize::max_value()).is_err());
}
