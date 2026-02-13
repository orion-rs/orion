// MIT License

// Copyright (c) 2018-2026 The orion Developers

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
//! - `info`: Optional context and application-specific information.  If [`None`]
//!   then it's an empty string.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `okm_out`.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than 1.
//! - The length of `dst_out` is greater than 255 * SHA(256/384/512)_OUTSIZE.
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG.
//!   [`secure_rand_bytes()`] can be used for this.
//! - The recommended length for a salt is 64 bytes.
//! - Even though a salt value is optional, it is strongly recommended to use one.
//! - HKDF is not suitable for password storage.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::{hazardous::kdf::hkdf, util};
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt)?;
//! let mut okm_out = [0u8; 32];
//!
//! hkdf::sha512::derive_key(&salt, "IKM".as_bytes(), None, &mut okm_out)?;
//!
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`secure_rand_bytes()`]: crate::util::secure_rand_bytes

use crate::errors::UnknownCryptoError;
use crate::hazardous::mac::hmac;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// The HKDF extract step.
///
/// NOTE: Hmac has the output size of the hash function defined,
/// but the array initialization with the size cannot depend on a generic parameter,
/// because we don't have full support for const generics yet.
fn _extract<Hmac, const OUTSIZE: usize>(
    salt: &[u8],
    ikm: &[u8],
) -> Result<[u8; OUTSIZE], UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    debug_assert_eq!(OUTSIZE, Hmac::HASH_FUNC_OUTSIZE);
    let mut dest = [0u8; OUTSIZE];

    let mut ctx = Hmac::_new(salt)?;
    ctx._update(ikm)?;
    ctx._finalize(&mut dest)?;

    Ok(dest)
}

fn _extract_with_parts<Hmac, const OUTSIZE: usize>(
    salt: &[u8],
    ikm: &[&[u8]],
) -> Result<[u8; OUTSIZE], UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    debug_assert_eq!(OUTSIZE, Hmac::HASH_FUNC_OUTSIZE);
    let mut dest = [0u8; OUTSIZE];

    let mut ctx = Hmac::_new(salt)?;
    for ikm_part in ikm.iter() {
        ctx._update(ikm_part)?;
    }
    ctx._finalize(&mut dest)?;

    Ok(dest)
}

/// The HKDF expand step.
fn _expand<Hmac, const OUTSIZE: usize>(
    prk: &[u8],
    info: Option<&[u8]>,
    dest: &mut [u8],
) -> Result<(), UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    debug_assert_eq!(OUTSIZE, Hmac::HASH_FUNC_OUTSIZE);
    debug_assert_eq!(prk.len(), Hmac::HASH_FUNC_OUTSIZE);
    if dest.is_empty() || dest.len() > 255 * Hmac::HASH_FUNC_OUTSIZE {
        return Err(UnknownCryptoError);
    }

    let optional_info = info.unwrap_or(&[0u8; 0]);
    let mut ctx = Hmac::_new(prk)?;

    // We require a temporary buffer in case the requested bytes
    // to derive are lower than the HMAC functions output size.
    let mut tmp = [0u8; OUTSIZE];
    let mut idx: u8 = 1;
    for hlen_block in dest.chunks_mut(Hmac::HASH_FUNC_OUTSIZE) {
        ctx._update(optional_info)?;
        ctx._update(&[idx])?;
        debug_assert!(!hlen_block.is_empty() && hlen_block.len() <= Hmac::HASH_FUNC_OUTSIZE);
        ctx._finalize(&mut tmp)?;
        hlen_block.copy_from_slice(&tmp[..hlen_block.len()]);

        if hlen_block.len() < Hmac::HASH_FUNC_OUTSIZE {
            break;
        }
        match idx.checked_add(1) {
            Some(next) => {
                idx = next;
                ctx._reset();
                ctx._update(hlen_block)?;
            }
            // If `idx` reaches 255, the maximum (255 * Hmac::HASH_FUNC_OUTSIZE)
            // amount of blocks have been processed.
            None => break,
        };
    }

    #[cfg(feature = "zeroize")]
    tmp.iter_mut().zeroize();

    Ok(())
}

fn _expand_with_parts<Hmac, const OUTSIZE: usize>(
    prk: &[u8],
    info: Option<&[&[u8]]>,
    dest: &mut [u8],
) -> Result<(), UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    debug_assert_eq!(OUTSIZE, Hmac::HASH_FUNC_OUTSIZE);
    debug_assert_eq!(prk.len(), Hmac::HASH_FUNC_OUTSIZE);
    if dest.is_empty() || dest.len() > 255 * Hmac::HASH_FUNC_OUTSIZE {
        return Err(UnknownCryptoError);
    }

    let optional_info = info.unwrap_or(&[]);
    let mut ctx = Hmac::_new(prk)?;

    // We require a temporary buffer in case the requested bytes
    // to derive are lower than the HMAC functions output size.
    let mut tmp = [0u8; OUTSIZE];
    let mut idx: u8 = 1;
    for hlen_block in dest.chunks_mut(Hmac::HASH_FUNC_OUTSIZE) {
        for info_part in optional_info.iter() {
            ctx._update(info_part)?;
        }
        ctx._update(&[idx])?;
        debug_assert!(!hlen_block.is_empty() && hlen_block.len() <= Hmac::HASH_FUNC_OUTSIZE);
        ctx._finalize(&mut tmp)?;
        hlen_block.copy_from_slice(&tmp[..hlen_block.len()]);

        if hlen_block.len() < Hmac::HASH_FUNC_OUTSIZE {
            break;
        }
        match idx.checked_add(1) {
            Some(next) => {
                idx = next;
                ctx._reset();
                ctx._update(hlen_block)?;
            }
            // If `idx` reaches 255, the maximum (255 * Hmac::HASH_FUNC_OUTSIZE)
            // amount of blocks have been processed.
            None => break,
        };
    }

    tmp.iter_mut().zeroize();

    Ok(())
}

/// Combine `extract` and `expand` to return a derived key.
///
/// NOTE: See comment about const param at _extract function.
fn _derive_key<Hmac, const OUTSIZE: usize>(
    salt: &[u8],
    ikm: &[u8],
    info: Option<&[u8]>,
    dest: &mut [u8],
) -> Result<(), UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    _expand::<Hmac, { OUTSIZE }>(&_extract::<Hmac, { OUTSIZE }>(salt, ikm)?, info, dest)
}

/// HKDF-HMAC-SHA256 (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod sha256 {
    use super::*;
    use crate::hazardous::hash::sha2::sha256::SHA256_OUTSIZE;
    pub use crate::hazardous::mac::hmac::sha256::Tag;

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF extract step.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<Tag, UnknownCryptoError> {
        Ok(Tag::from(_extract::<
            hmac::sha256::HmacSha256,
            { SHA256_OUTSIZE },
        >(salt, ikm)?))
    }

    pub(crate) fn extract_with_parts(
        salt: &[u8],
        ikm: &[&[u8]],
    ) -> Result<Tag, UnknownCryptoError> {
        Ok(Tag::from(_extract_with_parts::<
            hmac::sha256::HmacSha256,
            { SHA256_OUTSIZE },
        >(salt, ikm)?))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF expand step.
    pub fn expand(
        prk: &Tag,
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _expand::<hmac::sha256::HmacSha256, { SHA256_OUTSIZE }>(
            prk.unprotected_as_bytes(),
            info,
            dst_out,
        )
    }

    pub(crate) fn expand_with_parts(
        prk: &[u8],
        info: Option<&[&[u8]]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _expand_with_parts::<hmac::sha256::HmacSha256, { SHA256_OUTSIZE }>(prk, info, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Combine `extract` and `expand` to return a derived key.
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _derive_key::<hmac::sha256::HmacSha256, { SHA256_OUTSIZE }>(salt, ikm, info, dst_out)
    }

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    // Mark safe_api because currently it only contains proptests.
    mod test_derive_key {
        use crate::hazardous::hash::sha2::sha256::SHA256_OUTSIZE;

        use super::*;

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Using derive_key() should always yield the same result
        /// as using extract and expand separately.
        fn prop_test_derive_key_same_separate(
            salt: Vec<u8>,
            ikm: Vec<u8>,
            info: Vec<u8>,
            outsize: usize,
        ) -> bool {
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

/// HKDF-HMAC-SHA384 (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod sha384 {
    use super::*;
    use crate::hazardous::hash::sha2::sha384::SHA384_OUTSIZE;
    pub use crate::hazardous::mac::hmac::sha384::Tag;

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF extract step.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<Tag, UnknownCryptoError> {
        Ok(Tag::from(_extract::<
            hmac::sha384::HmacSha384,
            { SHA384_OUTSIZE },
        >(salt, ikm)?))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF expand step.
    pub fn expand(
        prk: &Tag,
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _expand::<hmac::sha384::HmacSha384, { SHA384_OUTSIZE }>(
            prk.unprotected_as_bytes(),
            info,
            dst_out,
        )
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Combine `extract` and `expand` to return a derived key.
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _derive_key::<hmac::sha384::HmacSha384, { SHA384_OUTSIZE }>(salt, ikm, info, dst_out)
    }

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    // Mark safe_api because currently it only contains proptests.
    mod test_derive_key {
        use crate::hazardous::hash::sha2::sha384::SHA384_OUTSIZE;

        use super::*;

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Using derive_key() should always yield the same result
        /// as using extract and expand separately.
        fn prop_test_derive_key_same_separate(
            salt: Vec<u8>,
            ikm: Vec<u8>,
            info: Vec<u8>,
            outsize: usize,
        ) -> bool {
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

/// HKDF-HMAC-SHA512 (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod sha512 {
    use super::*;
    use crate::hazardous::hash::sha2::sha512::SHA512_OUTSIZE;
    pub use crate::hazardous::mac::hmac::sha512::Tag;

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF extract step.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<Tag, UnknownCryptoError> {
        Ok(Tag::from(_extract::<
            hmac::sha512::HmacSha512,
            { SHA512_OUTSIZE },
        >(salt, ikm)?))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// The HKDF expand step.
    pub fn expand(
        prk: &Tag,
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _expand::<hmac::sha512::HmacSha512, { SHA512_OUTSIZE }>(
            prk.unprotected_as_bytes(),
            info,
            dst_out,
        )
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Combine `extract` and `expand` to return a derived key.
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _derive_key::<hmac::sha512::HmacSha512, { SHA512_OUTSIZE }>(salt, ikm, info, dst_out)
    }

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    // Mark safe_api because currently it only contains proptests.
    mod test_derive_key {
        use crate::hazardous::hash::sha2::sha512::SHA512_OUTSIZE;

        use super::*;

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Using derive_key() should always yield the same result
        /// as using extract and expand separately.
        fn prop_test_derive_key_same_separate(
            salt: Vec<u8>,
            ikm: Vec<u8>,
            info: Vec<u8>,
            outsize: usize,
        ) -> bool {
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

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;
    use crate::hazardous::hash::sha2::{
        sha256::SHA256_OUTSIZE, sha384::SHA384_OUTSIZE, sha512::SHA512_OUTSIZE,
    };

    #[test]
    fn hkdf_above_maximum_length_err() {
        let mut okm_out = [0u8; 255 * SHA256_OUTSIZE + 1];
        let prk = sha256::extract(b"", b"").unwrap();
        assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_err());
        assert!(sha256::derive_key(b"", b"", Some(b""), &mut okm_out).is_err());

        let mut okm_out = [0u8; 255 * SHA384_OUTSIZE + 1];
        let prk = sha384::extract(b"", b"").unwrap();
        assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_err());
        assert!(sha384::derive_key(b"", b"", Some(b""), &mut okm_out).is_err());

        let mut okm_out = [0u8; 255 * SHA512_OUTSIZE + 1];
        let prk = sha512::extract(b"", b"").unwrap();
        assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_err());
        assert!(sha512::derive_key(b"", b"", Some(b""), &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_exact_maximum_length_ok() {
        let mut okm_out = [0u8; 255 * SHA256_OUTSIZE];
        let prk = sha256::extract(b"", b"").unwrap();
        assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_ok());
        assert!(sha256::derive_key(b"", b"", Some(b""), &mut okm_out).is_ok());

        let mut okm_out = [0u8; 255 * SHA384_OUTSIZE];
        let prk = sha384::extract(b"", b"").unwrap();
        assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_ok());
        assert!(sha384::derive_key(b"", b"", Some(b""), &mut okm_out).is_ok());

        let mut okm_out = [0u8; 255 * SHA512_OUTSIZE];
        let prk = sha512::extract(b"", b"").unwrap();
        assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_ok());
        assert!(sha512::derive_key(b"", b"", Some(b""), &mut okm_out).is_ok());
    }

    #[test]
    fn hkdf_zero_length_err() {
        let mut okm_out = [0u8; 0];

        let prk = sha256::extract(b"", b"").unwrap();
        assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_err());
        assert!(sha256::derive_key(b"", b"", Some(b""), &mut okm_out).is_err());

        let prk = sha384::extract(b"", b"").unwrap();
        assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_err());
        assert!(sha384::derive_key(b"", b"", Some(b""), &mut okm_out).is_err());

        let prk = sha512::extract(b"", b"").unwrap();
        assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_err());
        assert!(sha512::derive_key(b"", b"", Some(b""), &mut okm_out).is_err());
    }

    #[test]
    fn hkdf_info_param() {
        // Test that using None or empty array as info is the same.
        let mut okm_out = [0u8; 32];
        let mut okm_out_verify = [0u8; 32];

        let prk = sha256::extract(b"", b"").unwrap();
        assert!(sha256::expand(&prk, Some(b""), &mut okm_out).is_ok()); // Use info Some
        assert!(sha256::derive_key(b"", b"", None, &mut okm_out_verify).is_ok());
        assert_eq!(okm_out, okm_out_verify);

        let prk = sha384::extract(b"", b"").unwrap();
        assert!(sha384::expand(&prk, Some(b""), &mut okm_out).is_ok()); // Use info Some
        assert!(sha384::derive_key(b"", b"", None, &mut okm_out_verify).is_ok());
        assert_eq!(okm_out, okm_out_verify);

        let prk = sha512::extract(b"", b"").unwrap();
        assert!(sha512::expand(&prk, Some(b""), &mut okm_out).is_ok()); // Use info Some
        assert!(sha512::derive_key(b"", b"", None, &mut okm_out_verify).is_ok());
        assert_eq!(okm_out, okm_out_verify);
    }

    #[test]
    fn hkdf_wrong_salt() {
        let ikm = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let salt = b"000102030405060708090a0b0c";
        let info = b"f0f1f2f3f4f5f6f7f8f9";
        let mut okm_out = [0u8; 42];
        let mut okm_out_verify = [0u8; 42];

        sha256::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha256::derive_key(b"", ikm, Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out, okm_out_verify);

        sha384::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha384::derive_key(b"", ikm, Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out, okm_out_verify);

        sha512::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha512::derive_key(b"", ikm, Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out, okm_out_verify);
    }

    #[test]
    fn hkdf_verify_wrong_ikm() {
        let ikm = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let salt = b"000102030405060708090a0b0c";
        let info = b"f0f1f2f3f4f5f6f7f8f9";
        let mut okm_out = [0u8; 42];
        let mut okm_out_verify = [0u8; 42];

        sha256::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha256::derive_key(salt, b"", Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out, okm_out_verify);

        sha384::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha384::derive_key(salt, b"", Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out, okm_out_verify);

        sha512::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha512::derive_key(salt, b"", Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out, okm_out_verify);
    }

    #[test]
    fn verify_diff_length() {
        let ikm = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let salt = b"000102030405060708090a0b0c";
        let info = b"f0f1f2f3f4f5f6f7f8f9";
        let mut okm_out = [0u8; 42];
        let mut okm_out_verify = [0u8; 43];

        sha256::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha256::derive_key(salt, ikm, Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out[..], okm_out_verify[..]);

        sha384::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha384::derive_key(salt, ikm, Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out[..], okm_out_verify[..]);

        sha512::derive_key(salt, ikm, Some(info), &mut okm_out).unwrap();
        sha512::derive_key(salt, ikm, Some(info), &mut okm_out_verify).unwrap();
        assert_ne!(okm_out[..], okm_out_verify[..]);
    }
}
