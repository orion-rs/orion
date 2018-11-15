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

//! Derive multiple keys from a single key using HKDF-HMAC-SHA512.
//!
//! # About:
//! - A salt of `64` bytes is automatically generated
//! - Returns both the salt used and the derived key as: `(salt, okm)`
//!
//! # Parameters:
//! - `ikm`: Input keying material
//! - `info`: Optional context and application specific information. If `None` then it's an empty string.
//! - `length`: The desired length of the derived key
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `length` is greater than `16320`
//! - The `OsRng` fails to initialize or read from its source
//!
//! # Security:
//! HKDF is not suitable for password storage.
//!
//! # Example:
//! ```
//! use orion::default::kdf;
//!
//! let secret_key = "Secret key that needs strethcing".as_bytes();
//!
//! let info = "Session key".as_bytes();
//!
//! let (salt, derived_key) = kdf::hkdf(secret_key, Some(info), 32).unwrap();
//!
//! // `derived_key` could now be used as encryption key with `seal`/`open`
//! ```

use errors::UnknownCryptoError;
use hazardous::kdf::hkdf;
pub use hazardous::kdf::hkdf::Salt;

#[must_use]
/// Key derivation with HKDF-HMAC-SHA512.
pub fn hkdf(
    ikm: &[u8],
    info: Option<&[u8]>,
    length: usize,
) -> Result<(Salt, Vec<u8>), UnknownCryptoError> {
    if length > 16320 {
        return Err(UnknownCryptoError);
    }

    let mut okm = vec![0u8; length];
    let salt = Salt::generate();

    hkdf::derive_key(&salt, ikm, info, &mut okm).unwrap();

    Ok((salt, okm))
}

#[test]
fn hkdf_ok() {
    let data = "Some data.".as_bytes();
    let info = "Some info.".as_bytes();

    assert!(hkdf(data, Some(info), 32).is_ok());
    assert!(hkdf(data, None, 32).is_ok());
}

#[test]
fn hkdf_okm_length() {
    let data = "Some data.".as_bytes();
    let info = "Some info.".as_bytes();

    assert!(hkdf(data, Some(info), 16321).is_err());
    assert!(hkdf(data, Some(info), 16320).is_ok());
}
