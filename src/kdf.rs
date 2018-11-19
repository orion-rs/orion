// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Key derivation.
//!
//! # About:
//! - Uses HKDF-HMAC-SHA512.
//! - A salt of `64` bytes is automatically generated.
//! - Returns both the salt used and the derived key as: `(salt, okm)`.
//!
//! # Parameters:
//! - `ikm`: Input keying material.
//! - `info`: Optional context and application specific information. If `None` then it's an empty string.
//! - `length`: The desired length of the derived key.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `length` is greater than 16320.
//! - The `OsRng` fails to initialize or read from its source.
//! - The derived key does not match `expected`.
//!
//!
//! # Security:
//! - `derive_key` is not suitable for password storage. See `orion::pwhash`.
//!
//! # Example:
//! ```
//! use orion::kdf;
//!
//! let secret_key = "Secret key that needs strethcing".as_bytes();
//!
//! let info = "Session key".as_bytes();
//!
//! let (salt, derived_key) = kdf::derive_key(secret_key, Some(info), 32).unwrap();
//!
//! // `derived_key` could now be used as encryption key with `orion::aead`
//!
//! assert!(kdf::derive_key_verify(&derived_key, &salt, secret_key, Some(info)).unwrap());
//! ```

use errors::{UnknownCryptoError, ValidationCryptoError};
use hazardous::kdf::hkdf;
use util;

#[must_use]
/// Derive a key using HKDF-HMAC-SHA512.
pub fn derive_key(
    ikm: &[u8],
    info: Option<&[u8]>,
    length: usize,
) -> Result<([u8; 64], Vec<u8>), UnknownCryptoError> {
    if length > 16320 {
        return Err(UnknownCryptoError);
    }

    let mut okm = vec![0u8; length];
    let mut salt = [0u8; 64];
    util::secure_rand_bytes(&mut salt).unwrap();

    hkdf::derive_key(&salt, ikm, info, &mut okm).unwrap();

    Ok((salt, okm))
}

#[must_use]
/// Derive and verify a key using HKDF-HMAC-SHA512.
pub fn derive_key_verify(
    expected: &[u8],
    salt: &[u8],
    ikm: &[u8],
    info: Option<&[u8]>,
) -> Result<bool, ValidationCryptoError> {
    let mut okm = vec![0u8; expected.len()];

    hkdf::verify(expected, salt, ikm, info, &mut okm)
}

#[test]
fn derive_key_ok() {
    let data = "Some data.".as_bytes();
    let info = "Some info.".as_bytes();

    assert!(derive_key(data, Some(info), 32).is_ok());
    assert!(derive_key(data, None, 32).is_ok());
}

#[test]
fn derive_key_okm_length() {
    let data = "Some data.".as_bytes();
    let info = "Some info.".as_bytes();

    assert!(derive_key(data, Some(info), 16321).is_err());
    assert!(derive_key(data, Some(info), 16320).is_ok());
}

#[test]
fn test_derive_key_verify_bad_params() {
    let data = "Some data.".as_bytes();
    let info = "Some info.".as_bytes();
    let (mut salt1, mut dk1) = derive_key(data, Some(info), 32).unwrap();
    assert!(derive_key_verify(&dk1, &salt1, data, Some(info)).is_ok());
    // Test diff salt
    assert!(derive_key_verify(&dk1, &salt1[..32], data, Some(info)).is_err());
    // Test wrong info
    assert!(derive_key_verify(&dk1, &salt1, data, None).is_err());
    // Test mod dk
    let dk_orig = dk1.clone();
    dk1[1] ^= 1;
    assert!(derive_key_verify(&dk1, &salt1, data, Some(info)).is_err());
    salt1[1] ^= 1;
    assert!(derive_key_verify(&dk_orig, &salt1, data, Some(info)).is_err());
}
