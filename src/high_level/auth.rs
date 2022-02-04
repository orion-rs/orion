// MIT License

// Copyright (c) 2020-2022 The orion Developers

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

//! Message authentication.
//!
//! # Use case:
//! `orion::auth` can be used to ensure message integrity and authenticity by
//! using a secret key.
//!
//! An example of this could be securing APIs by having a user of a given API
//! sign their API request and having the API server verify these signed API
//! requests.
//!
//! # About:
//! - Uses BLAKE2b-256 in keyed mode.
//!
//! # Parameters:
//! - `secret_key`: Secret key used to authenticate `data`.
//! - `data`: Data to be authenticated.
//! - `expected`: The expected authentication [`Tag`].
//!
//! # Errors:
//! An error will be returned if:
//! - The calculated [`Tag`] does not match the expected.
//! - The [`SecretKey`] supplied is less than 32 bytes or greater than 64 bytes.
//! - The expected [`Tag`] is not 32 bytes when verifying.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2*(2^64-1) bytes of data are authenticated.
//!
//! # Security:
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::default()`] can be used for
//! this; it will generate a [`SecretKey`] of 32 bytes.
//! - The required minimum length for a [`SecretKey`] is 32 bytes.
//!
//! # Example:
//! ```rust
//! use orion::auth;
//!
//! // There exists a shared key between the user and API server
//! let key = auth::SecretKey::default();
//!
//! // User generates message and authentication tag
//! let msg = "Some message.".as_bytes();
//! let expected_tag = auth::authenticate(&key, msg)?;
//!
//! // API server verifies the authenticity of the message with the tag
//! assert!(auth::authenticate_verify(&expected_tag, &key, &msg).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use super::hltypes::SecretKey;
pub use crate::hazardous::mac::blake2b::Tag;
use crate::{
    errors::UnknownCryptoError,
    hazardous::mac::blake2b::{self, Blake2b},
};

/// The Tag size (bytes) to be output by BLAKE2b in keyed mode.
const BLAKE2B_TAG_SIZE: usize = 32;
/// The minimum `SecretKey` size (bytes) to be used by BLAKE2b in keyed mode.
const BLAKE2B_MIN_KEY_SIZE: usize = 32;

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Authenticate a message using BLAKE2b-256 in keyed mode.
pub fn authenticate(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
    if secret_key.len() < BLAKE2B_MIN_KEY_SIZE {
        return Err(UnknownCryptoError);
    }
    let blake2b_secret_key = blake2b::SecretKey::from_slice(secret_key.unprotected_as_bytes())?;
    let mut state = Blake2b::new(&blake2b_secret_key, BLAKE2B_TAG_SIZE)?;
    state.update(data)?;
    state.finalize()
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Authenticate and verify a message using BLAKE2b-256 in keyed mode.
pub fn authenticate_verify(
    expected: &Tag,
    secret_key: &SecretKey,
    data: &[u8],
) -> Result<(), UnknownCryptoError> {
    if secret_key.len() < BLAKE2B_MIN_KEY_SIZE || expected.len() != BLAKE2B_TAG_SIZE {
        return Err(UnknownCryptoError);
    }
    let key = blake2b::SecretKey::from_slice(secret_key.unprotected_as_bytes())?;
    Blake2b::verify(expected, &key, BLAKE2B_TAG_SIZE, data)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    mod test_auth_and_verify {
        use super::*;
        #[test]
        fn test_authenticate_verify_bad_key() {
            let sec_key_correct = SecretKey::generate(64).unwrap();
            let sec_key_false = SecretKey::default();
            let msg = "what do ya want for nothing?".as_bytes().to_vec();
            let mac_bob = authenticate(&sec_key_correct, &msg).unwrap();

            assert!(authenticate_verify(&mac_bob, &sec_key_correct, &msg).is_ok());
            assert!(authenticate_verify(&mac_bob, &sec_key_false, &msg).is_err());
        }

        #[test]
        fn test_authenticate_verify_bad_msg() {
            let sec_key = SecretKey::generate(64).unwrap();
            let msg = "what do ya want for nothing?".as_bytes().to_vec();
            let mac_bob = authenticate(&sec_key, &msg).unwrap();

            assert!(authenticate_verify(&mac_bob, &sec_key, &msg).is_ok());
            assert!(authenticate_verify(&mac_bob, &sec_key, b"bad msg").is_err());
        }

        #[test]
        fn test_authenticate_key_too_small() {
            let sec_key = SecretKey::generate(31).unwrap();
            let msg = "what do ya want for nothing?".as_bytes().to_vec();

            assert!(authenticate(&sec_key, &msg).is_err());
        }

        #[test]
        fn test_authenticate_verify_key_too_small() {
            let sec_key = SecretKey::generate(31).unwrap();
            let msg = "what do ya want for nothing?".as_bytes().to_vec();
            let mac = Tag::from_slice(&[0u8; 32][..]).unwrap();

            assert!(authenticate_verify(&mac, &sec_key, &msg).is_err());
        }
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Authentication and verifying that tag with the same parameters
    /// should always be true.
    fn prop_authenticate_verify(input: Vec<u8>) -> bool {
        let sk = SecretKey::default();
        let tag = authenticate(&sk, &input[..]).unwrap();
        authenticate_verify(&tag, &sk, &input[..]).is_ok()
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Authentication and verifying that tag with a different key should
    /// never be true.
    fn prop_verify_fail_diff_key(input: Vec<u8>) -> bool {
        let sk = SecretKey::default();
        let sk2 = SecretKey::default();
        let tag = authenticate(&sk, &input[..]).unwrap();

        authenticate_verify(&tag, &sk2, &input[..]).is_err()
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Authentication and verifying that tag with different input should
    /// never be true.
    fn prop_verify_fail_diff_input(input: Vec<u8>) -> bool {
        let sk = SecretKey::default();
        let tag = authenticate(&sk, &input[..]).unwrap();

        authenticate_verify(&tag, &sk, b"Completely wrong input").is_err()
    }

    use crate::hazardous::hash::blake2::blake2b_core::BLAKE2B_KEYSIZE;

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Verify the bounds of 32..=64 (inclusive) for the `SecretKey` used
    /// in `authenticate/authenticate_verify`.
    fn prop_authenticate_key_size(input: Vec<u8>) -> bool {
        let sec_key_res = SecretKey::from_slice(&input);
        if input.is_empty() || input.len() >= u32::MAX as usize {
            return sec_key_res.is_err();
        }
        let sec_key = sec_key_res.unwrap();
        let msg = "what do ya want for nothing?".as_bytes().to_vec();
        let auth_res = authenticate(&sec_key, &msg);
        if input.len() >= BLAKE2B_MIN_KEY_SIZE && input.len() <= BLAKE2B_KEYSIZE {
            auth_res.is_ok()
        } else {
            auth_res.is_err()
        }
    }
}
