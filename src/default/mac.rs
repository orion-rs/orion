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

use errors::ValidationCryptoError;
use hazardous::mac::hmac;
pub use hazardous::mac::hmac::{SecretKey, Tag};

#[must_use]
/// Authenticate a message using HMAC-SHA512.
/// # Parameters:
/// - `secret_key`:  The authentication key
/// - `data`: Data to be authenticated
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the secret key is less than 64 bytes
///
/// # Security:
/// The secret key should always be generated using a CSPRNG. `SecretKey::generate()` can be used for
/// this.
///
/// # Example:
/// ```
/// use orion::default::mac;
///
/// let key = mac::SecretKey::generate();
/// let msg = "Some message.".as_bytes();
///
/// let hmac = mac::hmac(&key, msg);
/// ```
pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Tag {
    let mut tag = hmac::init(secret_key);
    tag.update(data).unwrap();

    tag.finalize().unwrap()
}

#[must_use]
/// Verify a HMAC-SHA512 MAC in constant time and with Double-HMAC Verification.
///
/// # Parameters:
/// - `expected_hmac`: The expected HMAC
/// - `secret_key`: The authentication key
/// - `data`: Data to be authenticated
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The calculated HMAC does not match the expected
/// - The `OsRng` fails to initialize or read from its source
///
/// # Example:
///
/// ```
/// use orion::default::mac;
///
/// let key = mac::SecretKey::generate();
/// let msg = "Some message.".as_bytes();
///
/// let expected_hmac = mac::hmac(&key, msg);
/// assert!(mac::hmac_verify(&expected_hmac, &key, &msg).unwrap());
/// ```
pub fn hmac_verify(
    expected_hmac: &Tag,
    secret_key: &SecretKey,
    data: &[u8],
) -> Result<bool, ValidationCryptoError> {
    let mut tag = hmac::init(secret_key);
    tag.update(data).unwrap();

    let rand_key = hmac::SecretKey::generate();
    let mut nd_round_expected = hmac::init(&rand_key);

    nd_round_expected
        .update(&expected_hmac.unprotected_as_bytes())
        .unwrap();

    hmac::verify(
        &nd_round_expected.finalize().unwrap(),
        &rand_key,
        &tag.finalize().unwrap().unprotected_as_bytes(),
    )
}

#[test]
fn test_hmac_verify() {
    let sec_key_correct = SecretKey::generate();
    let sec_key_false = SecretKey::generate();
    let msg = "what do ya want for nothing?".as_bytes().to_vec();

    let hmac_bob = hmac(&sec_key_correct, &msg);

    assert_eq!(
        hmac_verify(&hmac_bob, &sec_key_correct, &msg).unwrap(),
        true
    );
    assert!(hmac_verify(&hmac_bob, &sec_key_false, &msg).is_err());
}
