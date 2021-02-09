// MIT License

// Copyright (c) 2018-2021 The orion Developers

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
//! - `salt`: Salt value.
//! - `ikm`: Input keying material.
//! - `info`: Optional context and application-specific information.  If `None`
//!   then it's an empty string.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `okm_out`.
//! - `expected`: The expected derived key.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than 1.
//! - The length of `dst_out` is greater than 255 * SHA(256/384/512)_OUTSIZE.
//! - The derived key does not match the expected when verifying.
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG.
//!   [`util::secure_rand_bytes()`] can be used for this.
//! - The recommended length for a salt is 64 bytes.
//! - Even though a salt value is optional, it is strongly recommended to use
//!   one.
//! - HKDF is not suitable for password storage.
//!
//! # Example:
//! ```rust
//! use orion::{hazardous::kdf::hkdf, util};
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt)?;
//! let mut okm_out = [0u8; 32];
//!
//! hkdf::sha512::derive_key(&salt, "IKM".as_bytes(), None, &mut okm_out)?;
//!
//! let exp_okm = okm_out;
//!
//! assert!(hkdf::sha512::verify(&exp_okm, &salt, "IKM".as_bytes(), None, &mut okm_out).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`util::secure_rand_bytes()`]: ../../../util/fn.secure_rand_bytes.html

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::{self, sha2};
use crate::hazardous::mac::hmac;
use crate::util;

/// The HKDF extract step.
fn _extract<T, const SHA2_BLOCKSIZE: usize, const SHA2_OUTSIZE: usize>(
    salt: &[u8],
    ikm: &[u8],
) -> Result<[u8; SHA2_OUTSIZE], UnknownCryptoError>
where
    T: hash::ShaHash,
{
    let mut prk =
        hmac::HmacGeneric::<T, { SHA2_BLOCKSIZE }, { SHA2_OUTSIZE }>::new_with_padding(salt)?;
    prk.update(ikm)?;
    prk.finalize()?;

    Ok(prk.buffer)
}

/// The HKDF expand step.
fn _expand<T, const SHA2_BLOCKSIZE: usize, const SHA2_OUTSIZE: usize>(
    prk: &[u8],
    info: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError>
where
    T: hash::ShaHash,
{
    if dst_out.len() > 255 * SHA2_OUTSIZE {
        return Err(UnknownCryptoError);
    }
    if dst_out.is_empty() {
        return Err(UnknownCryptoError);
    }

    let optional_info = info.unwrap_or(&[0u8; 0]);

    let mut hmac =
        hmac::HmacGeneric::<T, { SHA2_BLOCKSIZE }, { SHA2_OUTSIZE }>::new_with_padding(prk)?;
    let okm_len = dst_out.len();

    for (idx, hlen_block) in dst_out.chunks_mut(SHA2_OUTSIZE).enumerate() {
        let block_len = hlen_block.len();

        hmac.update(optional_info)?;
        hmac.update(&[idx as u8 + 1_u8])?;
        hmac.finalize()?;
        hlen_block.copy_from_slice(&hmac.buffer[..block_len]);

        // Check if it's the last iteration, if yes don't process anything
        if block_len < SHA2_OUTSIZE || (block_len * (idx + 1) == okm_len) {
            break;
        } else {
            hmac.reset();
            hmac.update(&hlen_block)?;
        }
    }

    Ok(())
}

/// HKDF-HMAC-SHA256 (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod sha256 {
    use super::*;

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF extract step.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<hmac::sha256::Tag, UnknownCryptoError> {
        let mut prk = hmac::sha256::HmacSha256::new(&hmac::sha256::SecretKey::from_slice(salt)?);
        prk.update(ikm)?;
        prk.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF expand step.
    pub fn expand(
        prk: &hmac::sha256::Tag,
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert!(prk.len() == sha2::sha256::SHA256_OUTSIZE);

        _expand::<
            sha2::sha256::Sha256,
            { sha2::sha256::SHA256_BLOCKSIZE },
            { sha2::sha256::SHA256_OUTSIZE },
        >(prk.unprotected_as_bytes(), info, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Combine `extract` and `expand` to return a derived key.
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        expand(&extract(salt, ikm)?, info, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify a derived key in constant time.
    pub fn verify(
        expected: &[u8],
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        derive_key(salt, ikm, info, dst_out)?;
        util::secure_cmp(&dst_out, expected)
    }

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    // Mark safe_api because currently it only contains proptests.
    mod test_derive_key {
        use super::*;

        // Proptests. Only executed when NOT testing no_std.
        #[cfg(feature = "safe_api")]
        mod proptest {

            use sha2::sha256::SHA256_OUTSIZE;

            use super::*;

            quickcheck! {
                /// Using derive_key() should always yield the same result
                /// as using extract and expand separately.
                fn prop_test_derive_key_same_separate(salt: Vec<u8>, ikm: Vec<u8>, info: Vec<u8>, outsize: usize) -> bool {

                    let outsize_checked = if outsize == 0 || outsize > 255 * SHA256_OUTSIZE {
                        64
                    } else {
                        outsize
                    };

                    let prk = extract(&salt[..], &ikm[..]).unwrap();
                    let mut out = vec![0u8; outsize_checked];
                    expand(&prk, Some(&info[..]), &mut out).unwrap();

                    let mut out_one_shot = vec![0u8; outsize_checked];
                    derive_key(&salt[..], &ikm[..], Some(&info[..]), &mut out_one_shot).unwrap();

                    out == out_one_shot
                }
            }
        }
    }
}

/// HKDF-HMAC-SHA384 (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod sha384 {
    use super::*;

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF extract step.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<hmac::sha384::Tag, UnknownCryptoError> {
        let mut prk = hmac::sha384::HmacSha384::new(&hmac::sha384::SecretKey::from_slice(salt)?);
        prk.update(ikm)?;
        prk.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF expand step.
    pub fn expand(
        prk: &hmac::sha384::Tag,
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert!(prk.len() == sha2::sha384::SHA384_OUTSIZE);

        _expand::<
            sha2::sha384::Sha384,
            { sha2::sha384::SHA384_BLOCKSIZE },
            { sha2::sha384::SHA384_OUTSIZE },
        >(prk.unprotected_as_bytes(), info, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Combine `extract` and `expand` to return a derived key.
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        expand(&extract(salt, ikm)?, info, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify a derived key in constant time.
    pub fn verify(
        expected: &[u8],
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        derive_key(salt, ikm, info, dst_out)?;
        util::secure_cmp(&dst_out, expected)
    }

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    // Mark safe_api because currently it only contains proptests.
    mod test_derive_key {
        use super::*;

        // Proptests. Only executed when NOT testing no_std.
        #[cfg(feature = "safe_api")]
        mod proptest {

            use sha2::sha384::SHA384_OUTSIZE;

            use super::*;

            quickcheck! {
                /// Using derive_key() should always yield the same result
                /// as using extract and expand separately.
                fn prop_test_derive_key_same_separate(salt: Vec<u8>, ikm: Vec<u8>, info: Vec<u8>, outsize: usize) -> bool {

                    let outsize_checked = if outsize == 0 || outsize > 255 * SHA384_OUTSIZE {
                        64
                    } else {
                        outsize
                    };

                    let prk = extract(&salt[..], &ikm[..]).unwrap();
                    let mut out = vec![0u8; outsize_checked];
                    expand(&prk, Some(&info[..]), &mut out).unwrap();

                    let mut out_one_shot = vec![0u8; outsize_checked];
                    derive_key(&salt[..], &ikm[..], Some(&info[..]), &mut out_one_shot).unwrap();

                    out == out_one_shot
                }
            }
        }
    }
}

/// HKDF-HMAC-SHA512 (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod sha512 {
    use super::*;

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF extract step.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<hmac::sha512::Tag, UnknownCryptoError> {
        let mut prk = hmac::sha512::HmacSha512::new(&hmac::sha512::SecretKey::from_slice(salt)?);
        prk.update(ikm)?;
        prk.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF expand step.
    pub fn expand(
        prk: &hmac::sha512::Tag,
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert!(prk.len() == sha2::sha512::SHA512_OUTSIZE);

        _expand::<
            sha2::sha512::Sha512,
            { sha2::sha512::SHA512_BLOCKSIZE },
            { sha2::sha512::SHA512_OUTSIZE },
        >(prk.unprotected_as_bytes(), info, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Combine `extract` and `expand` to return a derived key.
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        expand(&extract(salt, ikm)?, info, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify a derived key in constant time.
    pub fn verify(
        expected: &[u8],
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        derive_key(salt, ikm, info, dst_out)?;
        util::secure_cmp(&dst_out, expected)
    }

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    // Mark safe_api because currently it only contains proptests.
    mod test_derive_key {
        use super::*;

        // Proptests. Only executed when NOT testing no_std.
        #[cfg(feature = "safe_api")]
        mod proptest {
            use sha2::sha512::SHA512_OUTSIZE;

            use super::*;

            quickcheck! {
                /// Using derive_key() should always yield the same result
                /// as using extract and expand separately.
                fn prop_test_derive_key_same_separate(salt: Vec<u8>, ikm: Vec<u8>, info: Vec<u8>, outsize: usize) -> bool {

                    let outsize_checked = if outsize == 0 || outsize > 255 * SHA512_OUTSIZE {
                        64
                    } else {
                        outsize
                    };

                    let prk = extract(&salt[..], &ikm[..]).unwrap();
                    let mut out = vec![0u8; outsize_checked];
                    expand(&prk, Some(&info[..]), &mut out).unwrap();

                    let mut out_one_shot = vec![0u8; outsize_checked];
                    derive_key(&salt[..], &ikm[..], Some(&info[..]), &mut out_one_shot).unwrap();

                    out == out_one_shot
                }
            }
        }
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    mod test_expand {
        use super::*;
        use sha2::sha256::SHA256_OUTSIZE;
        use sha2::sha384::SHA384_OUTSIZE;
        use sha2::sha512::SHA512_OUTSIZE;

        #[test]
        fn hkdf_above_maximum_length_err() {
            let mut okm_out = [0u8; 255 * SHA256_OUTSIZE + 1];
            let prk = sha256::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_err());

            let mut okm_out = [0u8; 255 * SHA384_OUTSIZE + 1];
            let prk = sha384::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_err());

            let mut okm_out = [0u8; 255 * SHA512_OUTSIZE + 1];
            let prk = sha512::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_err());
        }

        #[test]
        fn hkdf_exact_maximum_length_ok() {
            let mut okm_out = [0u8; 255 * SHA256_OUTSIZE];
            let prk = sha256::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_ok());

            let mut okm_out = [0u8; 255 * SHA384_OUTSIZE];
            let prk = sha384::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_ok());

            let mut okm_out = [0u8; 255 * SHA512_OUTSIZE];
            let prk = sha512::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_ok());
        }

        #[test]
        fn hkdf_zero_length_err() {
            let mut okm_out = [0u8; 0];

            let prk = sha256::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_err());

            let prk = sha384::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_err());

            let prk = sha512::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_err());
        }

        #[test]
        fn hkdf_info_param() {
            // Test that using None or empty array as info is the same.
            let mut okm_out = [0u8; 32];
            let mut okm_out_verify = [0u8; 32];

            let prk = sha256::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_ok()); // Use info Some
            assert!(sha256::verify(&okm_out, b"", b"", None, &mut okm_out_verify).is_ok());

            let prk = sha384::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_ok()); // Use info Some
            assert!(sha384::verify(&okm_out, b"", b"", None, &mut okm_out_verify).is_ok());

            let prk = sha512::extract("".as_bytes(), "".as_bytes()).unwrap();
            assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_ok()); // Use info Some
            assert!(sha512::verify(&okm_out, b"", b"", None, &mut okm_out_verify).is_ok());
        }
    }

    mod test_verify {
        use super::*;

        #[test]
        fn hkdf_verify_true() {
            let ikm = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
            let salt = b"000102030405060708090a0b0c";
            let info = b"f0f1f2f3f4f5f6f7f8f9";
            let mut okm_out = [0u8; 42];
            let mut okm_out_verify = [0u8; 42];

            sha256::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha256::verify(&okm_out, salt, ikm, Some(info), &mut okm_out_verify).is_ok());

            sha384::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha384::verify(&okm_out, salt, ikm, Some(info), &mut okm_out_verify).is_ok());

            sha512::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha512::verify(&okm_out, salt, ikm, Some(info), &mut okm_out_verify).is_ok());
        }

        #[test]
        fn hkdf_verify_wrong_salt() {
            let ikm = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
            let salt = b"000102030405060708090a0b0c";
            let info = b"f0f1f2f3f4f5f6f7f8f9";
            let mut okm_out = [0u8; 42];
            let mut okm_out_verify = [0u8; 42];

            sha256::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha256::verify(&okm_out, b"", ikm, Some(info), &mut okm_out_verify).is_err());

            sha384::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha384::verify(&okm_out, b"", ikm, Some(info), &mut okm_out_verify).is_err());

            sha512::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha512::verify(&okm_out, b"", ikm, Some(info), &mut okm_out_verify).is_err());
        }

        #[test]
        fn hkdf_verify_wrong_ikm() {
            let ikm = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
            let salt = b"000102030405060708090a0b0c";
            let info = b"f0f1f2f3f4f5f6f7f8f9";
            let mut okm_out = [0u8; 42];
            let mut okm_out_verify = [0u8; 42];

            sha256::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha256::verify(&okm_out, salt, b"", Some(info), &mut okm_out_verify).is_err());

            sha384::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha384::verify(&okm_out, salt, b"", Some(info), &mut okm_out_verify).is_err());

            sha512::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha512::verify(&okm_out, salt, b"", Some(info), &mut okm_out_verify).is_err());
        }

        #[test]
        fn verify_diff_length() {
            let ikm = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
            let salt = b"000102030405060708090a0b0c";
            let info = b"f0f1f2f3f4f5f6f7f8f9";
            let mut okm_out = [0u8; 42];
            let mut okm_out_verify = [0u8; 43];

            sha256::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha256::verify(&okm_out, salt, ikm, Some(info), &mut okm_out_verify).is_err());

            sha384::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha384::verify(&okm_out, salt, ikm, Some(info), &mut okm_out_verify).is_err());

            sha512::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
            assert!(sha512::verify(&okm_out, salt, ikm, Some(info), &mut okm_out_verify).is_err());
        }
    }
}
