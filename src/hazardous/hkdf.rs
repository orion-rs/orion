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
//! - `info`: Optional context and application specific information (can be a zero-length string)
//! - `okm_out`: Destination buffer for the derived key. The length of the derived key is implied by the length of `okm_out`
//!
//! See [RFC](https://tools.ietf.org/html/rfc5869#section-2.2) for more information.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of `okm_out` is less than 1
//! - The length of `okm_out` is greater than 255 * hash_output_size_in_bytes
//!
//! # Security:
//! Salts should always be generated using a CSPRNG. The `gen_rand_key` function
//! in `util` can be used for this. The recommended length for a salt is 16 bytes as a minimum.
//! HKDF is not suitable for password storage. Even though a salt value is optional, it is strongly
//! recommended to use one.
//!
//! # Example:
//! ### Generating derived key:
//! ```
//! use orion::hazardous::hkdf;
//! use orion::utilities::util;
//!
//! let mut salt = [0u8; 32];
//! util::gen_rand_key(&mut salt).unwrap();
//! let mut okm_out = [0u8; 32];
//!
//! hkdf::derive_key(&salt, "IKM".as_bytes(), "Info".as_bytes(), &mut okm_out).unwrap();
//! ```
//! ### Verifying derived key:
//! ```
//! use orion::hazardous::hkdf;
//! use orion::utilities::util;
//!
//! let mut salt = [0u8; 32];
//! util::gen_rand_key(&mut salt).unwrap();
//! let mut okm_out = [0u8; 32];
//!
//! hkdf::derive_key(&salt, "IKM".as_bytes(), "Info".as_bytes(), &mut okm_out).unwrap();
//! let exp_okm = okm_out;
//! assert!(hkdf::verify(&exp_okm, &salt, "IKM".as_bytes(), "Info".as_bytes(), &mut okm_out).unwrap());
//! ```

use hazardous::constants::HLEN;
use hazardous::hmac;
use utilities::{errors::*, util};

#[inline(always)]
/// The HKDF extract step.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    let mut prk = hmac::init(salt);
    prk.update(ikm).unwrap();

    prk.finalize().unwrap()
}

#[inline(always)]
/// The HKDF expand step.
pub fn expand(prk: &[u8], info: &[u8], okm_out: &mut [u8]) -> Result<(), UnknownCryptoError> {
    if okm_out.len() > 16320 {
        return Err(UnknownCryptoError);
    }
    if okm_out.is_empty() {
        return Err(UnknownCryptoError);
    }

    let mut hmac = hmac::init(prk);
    let okm_len = okm_out.len();

    for (idx, hlen_block) in okm_out.chunks_mut(HLEN).enumerate() {
        let block_len = hlen_block.len();
        assert!(block_len <= okm_len);

        hmac.update(info).unwrap();
        hmac.update(&[idx as u8 + 1_u8]).unwrap();
        hmac.finalize_with_dst(&mut hlen_block[..block_len])
            .unwrap();

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

/// Combine `extract` and `expand` to return a derived key.
pub fn derive_key(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    expand(&extract(salt, ikm), info, okm_out)
}

/// Verify a derived key in constant time.
pub fn verify(
    expected_dk: &[u8],
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
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
    use hazardous::hkdf::*;

    #[test]
    fn hkdf_maximum_length_512() {
        // Max allowed length here is 16320
        let mut okm_out = [0u8; 17000];
        let prk = extract("".as_bytes(), "".as_bytes());

        assert!(expand(&prk, "".as_bytes(), &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_zero_length() {
        let mut okm_out = [0u8; 0];
        let prk = extract("".as_bytes(), "".as_bytes());

        assert!(expand(&prk, "".as_bytes(), &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_verify_true() {
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = decode("000102030405060708090a0b0c").unwrap();
        let info = decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm_out = [0u8; 42];

        let expected_okm = decode(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        ).unwrap();

        assert_eq!(
            verify(&expected_okm, &salt, &ikm, &info, &mut okm_out).unwrap(),
            true
        );
    }

    #[test]
    fn hkdf_verify_wrong_salt() {
        let salt = "salt".as_bytes();
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = "".as_bytes();
        let mut okm_out = [0u8; 42];

        let expected_okm = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ).unwrap();

        assert!(verify(&expected_okm, salt, &ikm, info, &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_verify_wrong_ikm() {
        let salt = "".as_bytes();
        let ikm = decode("0b").unwrap();
        let info = "".as_bytes();
        let mut okm_out = [0u8; 42];

        let expected_okm = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ).unwrap();

        assert!(verify(&expected_okm, salt, &ikm, info, &mut okm_out).is_err());
    }

    #[test]
    fn verify_diff_length() {
        let salt = "".as_bytes();
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = "".as_bytes();
        let mut okm_out = [0u8; 72];

        let expected_okm = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ).unwrap();

        assert!(verify(&expected_okm, salt, &ikm, info, &mut okm_out).is_err());
    }
}
