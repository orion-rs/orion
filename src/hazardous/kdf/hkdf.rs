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

//! # Parameters:
//! - `salt`:  Optional salt value
//! - `ikm`: Input keying material
//! - `info`: Optional context and application specific information.  If `None` then it's an empty string.
//! - `okm_out`: Destination buffer for the derived key. The length of the derived key is implied by the length of `okm_out`
//!
//! See [RFC](https://tools.ietf.org/html/rfc5869#section-2.2) for more information.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of `okm_out` is less than 1
//! - The length of `okm_out` is greater than 255 * hash_output_size_in_bytes
//! - The derived key does not match the expected when verifying
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG. `Salt::generate()` can be used for this.
//! It generates a salt of 128 bytes.
//! - The recommended minimum length for a salt is 64 bytes.
//! - Even though a salt value is optional, it is strongly recommended to use one.
//! - HKDF is not suitable for password storage.
//!
//! # Example:
//! ```
//! use orion::hazardous::kdf::hkdf;
//!
//! let salt = hkdf::Salt::generate();
//! let mut okm_out = [0u8; 32];
//!
//! hkdf::derive_key(&salt, "IKM".as_bytes(), None, &mut okm_out).unwrap();
//!
//! let exp_okm = okm_out;
//!
//! assert!(hkdf::verify(&exp_okm, &salt, "IKM".as_bytes(), None, &mut okm_out).unwrap());
//! ```

use errors::*;
use hazardous::constants::HLEN;
use hazardous::mac::hmac;
use hazardous::mac::hmac::SecretKey;
use util;

construct_salt!(Salt, 128, 64);

#[must_use]
#[inline(always)]
/// The HKDF extract step.
pub fn extract(salt: &Salt, ikm: &[u8]) -> hmac::Tag {
    let mut prk = hmac::init(&SecretKey::from_slice(salt.as_bytes()));
    prk.update(ikm).unwrap();

    prk.finalize().unwrap()
}

#[must_use]
#[inline(always)]
/// The HKDF expand step.
pub fn expand(
    prk: &hmac::Tag,
    info: Option<&[u8]>,
    okm_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if okm_out.len() > 16320 {
        return Err(UnknownCryptoError);
    }
    if okm_out.is_empty() {
        return Err(UnknownCryptoError);
    }

    let optional_info = match info {
        Some(ref n_val) => *n_val,
        None => &[0u8; 0],
    };

    let mut hmac = hmac::init(&hmac::SecretKey::from_slice(&prk.unprotected_as_bytes()));
    let okm_len = okm_out.len();

    for (idx, hlen_block) in okm_out.chunks_mut(HLEN).enumerate() {
        let block_len = hlen_block.len();
        assert!(block_len <= okm_len);

        hmac.update(optional_info).unwrap();
        hmac.update(&[idx as u8 + 1_u8]).unwrap();
        hlen_block.copy_from_slice(&hmac.finalize().unwrap().unprotected_as_bytes()[..block_len]);

        // Check if it's the last iteration, if yes don't process anything
        if block_len < HLEN || (block_len * (idx + 1) == okm_len) {
            break;
        } else {
            hmac.reset();
            hmac.update(&hlen_block).unwrap();
        }
    }

    Ok(())
}

#[must_use]
/// Combine `extract` and `expand` to return a derived key.
pub fn derive_key(
    salt: &Salt,
    ikm: &[u8],
    info: Option<&[u8]>,
    okm_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    expand(&extract(salt, ikm), info, okm_out)
}

#[must_use]
/// Verify a derived key in constant time.
pub fn verify(
    expected_dk: &[u8],
    salt: &Salt,
    ikm: &[u8],
    info: Option<&[u8]>,
    okm_out: &mut [u8],
) -> Result<bool, ValidationCryptoError> {
    expand(&extract(salt, ikm), info, okm_out).unwrap();

    if util::compare_ct(&okm_out, expected_dk).is_err() {
        Err(ValidationCryptoError)
    } else {
        Ok(true)
    }
}

#[cfg(test)]
mod test {
    extern crate hex;
    use self::hex::decode;
    use hazardous::kdf::hkdf::*;

    #[test]
    fn hkdf_maximum_length_512() {
        // Max allowed length here is 16320
        let mut okm_out = [0u8; 17000];
        let prk = extract(&Salt::from_slice("".as_bytes()).unwrap(), "".as_bytes());

        assert!(expand(&prk, Some(b""), &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_zero_length() {
        let mut okm_out = [0u8; 0];
        let prk = extract(&Salt::from_slice("".as_bytes()).unwrap(), "".as_bytes());

        assert!(expand(&prk, Some(b""), &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_verify_true() {
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = Salt::from_slice(&decode("000102030405060708090a0b0c").unwrap()).unwrap();
        let info = decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm_out = [0u8; 42];

        let expected_okm = decode(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        ).unwrap();

        assert_eq!(
            verify(&expected_okm, &salt, &ikm, Some(&info), &mut okm_out).unwrap(),
            true
        );
    }

    #[test]
    fn hkdf_verify_wrong_salt() {
        let salt = Salt::from_slice("salt".as_bytes()).unwrap();
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = "".as_bytes();
        let mut okm_out = [0u8; 42];

        let expected_okm = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ).unwrap();

        assert!(verify(&expected_okm, &salt, &ikm, Some(info), &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_verify_wrong_ikm() {
        let salt = Salt::from_slice("".as_bytes()).unwrap();
        let ikm = decode("0b").unwrap();
        let info = "".as_bytes();
        let mut okm_out = [0u8; 42];

        let expected_okm = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ).unwrap();

        assert!(verify(&expected_okm, &salt, &ikm, Some(info), &mut okm_out).is_err());
    }

    #[test]
    fn verify_diff_length() {
        let salt = Salt::from_slice("".as_bytes()).unwrap();
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = "".as_bytes();
        let mut okm_out = [0u8; 72];

        let expected_okm = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ).unwrap();

        assert!(verify(&expected_okm, &salt, &ikm, Some(info), &mut okm_out).is_err());
    }
}
