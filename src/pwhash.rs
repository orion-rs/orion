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

//! Password hashing and verification.
//!
//! # Use case:
//! `orion::pwhash` is suitable for securely storing passwords.
//!
//! An example of this would be needing to store user passwords (from a sign-up at a webstore) in a server database,
//! where a potential disclosure of the data in this database should not result in the user's actual passwords being
//! disclosed as well.
//!
//! # About:
//! - Uses PBKDF2-HMAC-SHA512
//! - A salt of 64 bytes is automatically generated.
//! - The password hash length is set to 64.
//! - 512.000 iterations are used.
//! - An array of 128 bytes is returned.
//!
//! The first 64 bytes of the array returned by `pwhash::hash_password` is the salt used to hash the password
//! and the last 64 bytes is the actual hashed password. When using this function with
//! `pwhash::hash_password_verify()`, then the seperation of the salt and the password hash are automatically handeled.
//!
//! # Parameters:
//! - `password`: The password to be hashed.
//! - `expected_with_salt`: The expected password hash with a salt prepended.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The `OsRng` fails to initialize or read from its source.
//! - The `expected_with_salt` is not constructed exactly as in `pwhash::hash_password`.
//! - The password hash does not match `expected_with_salt`.
//!
//! # Example:
//! ```
//! use orion::pwhash;
//!
//! let password = pwhash::Password::from_slice("Secret password".as_bytes());
//!
//! let hash = pwhash::hash_password(&password).unwrap();
//! assert!(pwhash::hash_password_verify(&hash, &password).unwrap());
//! ```

use errors::{UnknownCryptoError, ValidationCryptoError};
use hazardous::kdf::pbkdf2;
pub use hazardous::kdf::pbkdf2::Password;
use util;

#[must_use]
/// Hash a password using PBKDF2-HMAC-SHA512.
pub fn hash_password(password: &Password) -> Result<[u8; 128], UnknownCryptoError> {
    let mut dk = [0u8; 128];
    let mut salt = [0u8; 64];
    util::secure_rand_bytes(&mut salt).unwrap();

    dk[..64].copy_from_slice(&salt);
    pbkdf2::derive_key(password, &salt, 512_000, &mut dk[64..]).unwrap();

    Ok(dk)
}

#[must_use]
/// Hash and verify a password using PBKDF2-HMAC-SHA512.
pub fn hash_password_verify(
    expected_with_salt: &[u8],
    password: &Password,
) -> Result<bool, ValidationCryptoError> {
    let mut dk = [0u8; 64];

    pbkdf2::verify(
        &expected_with_salt[64..],
        password,
        &expected_with_salt[..64],
        512_000,
        &mut dk,
    )
}

#[test]
fn pbkdf2_verify() {
    let password = Password::from_slice(&[0u8; 64]);

    let pbkdf2_dk: [u8; 128] = hash_password(&password).unwrap();

    assert_eq!(hash_password_verify(&pbkdf2_dk, &password).unwrap(), true);
}

#[test]
#[should_panic]
fn pbkdf2_verify_err_modified_salt() {
    let password = Password::from_slice(&[0u8; 64]);

    let mut pbkdf2_dk = hash_password(&password).unwrap();
    pbkdf2_dk[..10].copy_from_slice(&[0x61; 10]);

    hash_password_verify(&pbkdf2_dk, &password).unwrap();
}

#[test]
#[should_panic]
fn pbkdf2_verify_err_modified_password() {
    let password = Password::from_slice(&[0u8; 64]);

    let mut pbkdf2_dk = hash_password(&password).unwrap();
    pbkdf2_dk[70..80].copy_from_slice(&[0x61; 10]);

    hash_password_verify(&pbkdf2_dk, &password).unwrap();
}

#[test]
#[should_panic]
fn pbkdf2_verify_err_modified_salt_and_password() {
    let password = Password::from_slice(&[0u8; 64]);

    let mut pbkdf2_dk = hash_password(&password).unwrap();
    pbkdf2_dk[63..73].copy_from_slice(&[0x61; 10]);

    hash_password_verify(&pbkdf2_dk, &password).unwrap();
}

#[test]
fn pbkdf2_verify_expected_dk_too_long() {
    let password = Password::from_slice(&[0u8; 64]);

    let mut pbkdf2_dk = [0u8; 129];
    pbkdf2_dk[..128].copy_from_slice(&hash_password(&password).unwrap());

    assert!(hash_password_verify(&pbkdf2_dk, &password).is_err());
}

#[test]
fn pbkdf2_verify_expected_dk_too_short() {
    let password = Password::from_slice(&[0u8; 127]);

    let pbkdf2_dk = hash_password(&password).unwrap();

    assert!(hash_password_verify(&pbkdf2_dk[..127], &password).is_err());
}
