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

use errors::{UnknownCryptoError, ValidationCryptoError};
use hazardous::kdf::pbkdf2;
pub use hazardous::kdf::pbkdf2::Salt;

#[must_use]
/// Hash a password using PBKDF2-HMAC-SHA512.
/// # About:
/// This is meant to be used for password storage.
/// - A salt of 64 bytes is automatically generated.
/// - The derived key length is set to 64.
/// - 512.000 iterations are used.
/// - An array of 128 bytes is returned.
///
/// The first 64 bytes of this array is the salt used to derive the key and the last 64 bytes
/// is the actual derived key. When using this function with `default::password_hash_verify()`,
/// then the seperation of the salt and the derived key are automatically handeled.
///
/// # Parameters:
/// - `password` : The password to be hashed
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the password is less than 14 bytes
/// - The `OsRng` fails to initialize or read from its source
///
/// # Example:
///
/// ```
/// use orion::default::pwhash;
///
/// let password = "Secret password".as_bytes();
///
/// let derived_password = pwhash::password_hash(password);
/// ```
pub fn password_hash(password: &[u8]) -> Result<[u8; 128], UnknownCryptoError> {
    if password.len() < 14 {
        return Err(UnknownCryptoError);
    }

    let mut dk = [0u8; 128];
    let salt = Salt::generate();

    dk[..64].copy_from_slice(&salt.as_bytes());
    pbkdf2::derive_key(password, &salt, 512_000, &mut dk[64..]).unwrap();

    Ok(dk)
}

#[must_use]
/// Verify a hashed password using PBKDF2-HMAC-SHA512.
/// # About:
/// This function is meant to be used with the `default::password_hash()` function in orion's default API. It can be
/// used without it, but then the `expected_dk` passed to the function must be constructed just as in
/// `default::password_hash()`. See documention on `default::password_hash()` for details on this.
///
/// # Parameters:
/// - `expected_dk`: The expected password hash
/// - `password` : The password to be hashed
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of `expected_dk` is not 128 bytes
/// - The password hash does not match the expected
///
/// # Example:
///
/// ```
/// use orion::default::pwhash;
///
/// let password = "Secret password".as_bytes();
///
/// let derived_password = pwhash::password_hash(password).unwrap();
/// assert!(pwhash::password_hash_verify(&derived_password, password).unwrap());
/// ```
pub fn password_hash_verify(
    expected_dk: &[u8],
    password: &[u8],
) -> Result<bool, ValidationCryptoError> {
    if expected_dk.len() != 128 {
        return Err(ValidationCryptoError);
    }

    let mut dk = [0u8; 64];

    pbkdf2::verify(
        &expected_dk[64..],
        password,
        &Salt::from_slice(&expected_dk[..64]).unwrap(),
        512_000,
        &mut dk,
    )
}

#[test]
fn pbkdf2_verify() {
    let password = [0u8; 64];

    let pbkdf2_dk: [u8; 128] = password_hash(&password).unwrap();

    assert_eq!(password_hash_verify(&pbkdf2_dk, &password).unwrap(), true);
}

#[test]
#[should_panic]
fn pbkdf2_verify_err_modified_salt() {
    let password = [0u8; 64];

    let mut pbkdf2_dk = password_hash(&password).unwrap();
    pbkdf2_dk[..10].copy_from_slice(&[0x61; 10]);

    password_hash_verify(&pbkdf2_dk, &password).unwrap();
}

#[test]
#[should_panic]
fn pbkdf2_verify_err_modified_password() {
    let password = [0u8; 64];

    let mut pbkdf2_dk = password_hash(&password).unwrap();
    pbkdf2_dk[70..80].copy_from_slice(&[0x61; 10]);

    password_hash_verify(&pbkdf2_dk, &password).unwrap();
}

#[test]
#[should_panic]
fn pbkdf2_verify_err_modified_salt_and_password() {
    let password = [0u8; 64];

    let mut pbkdf2_dk = password_hash(&password).unwrap();
    pbkdf2_dk[63..73].copy_from_slice(&[0x61; 10]);

    password_hash_verify(&pbkdf2_dk, &password).unwrap();
}

#[test]
fn pbkdf2_verify_expected_dk_too_long() {
    let password = [0u8; 64];

    let mut pbkdf2_dk = [0u8; 129];
    pbkdf2_dk[..128].copy_from_slice(&password_hash(&password).unwrap());

    assert!(password_hash_verify(&pbkdf2_dk, &password).is_err());
}

#[test]
fn pbkdf2_verify_expected_dk_too_short() {
    let password = [0u8; 127];

    let pbkdf2_dk = password_hash(&password).unwrap();

    assert!(password_hash_verify(&pbkdf2_dk[..127], &password).is_err());
}

#[test]
fn pbkdf2_password_too_short() {
    let password = [0u8; 13];

    assert!(password_hash(&password).is_err());
}
