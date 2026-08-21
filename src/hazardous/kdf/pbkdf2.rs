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
//! - `password`: Password.
//! - `salt`: Salt value.
//! - `iterations`: Iteration count.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `dst_out`.
//! - `expected`: The expected derived key.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than 1.
//! - The specified iteration count is less than 1.
//! - The hashed password does not match the expected when verifying.
//!
//! # Panics:
//! A panic will occur if:
//! - The length of `dst_out` is greater than (2^32 - 1) * SHA(256/384/512)_OUTSIZE.
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG.
//!   [`secure_rand_bytes()`] can be used for this.
//! - The recommended length for a salt is 64 bytes.
//! - The iteration count should be set as high as feasible. Please check [OWASP] for
//! the recommended minimum amount (600000 at the time of writing).
//! - Please note that when verifying, a copy of the computed password hash is placed into
//! `dst_out`. If the derived hash is considered sensitive and you want to provide defense
//! in depth against an attacker reading your application's private memory, then you as
//! the user are responsible for zeroing out this buffer (see the [`zeroize` crate]).
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::{hazardous::kdf::pbkdf2::*, util};
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt)?;
//! let mut dst_out = [0u8; 64];
//!
//! Pbkdf2::<SHA512>::derive_key(b"Secret password", &salt, 10000, &mut dst_out)?;
//!
//! let expected_dk = dst_out;
//!
//! assert!(Pbkdf2::<SHA512>::verify(&expected_dk, b"Secret password", &salt, 10000, &mut dst_out).is_ok());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`Password::generate()`]: pbkdf2::sha512::Password::generate
//! [`secure_rand_bytes()`]: crate::util::secure_rand_bytes
//! [`zeroize` crate]: https://crates.io/crates/zeroize
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

use crate::{errors::UnknownCryptoError, hazardous::mac::hmac};
use core::marker::PhantomData;

/// The F function as described in the RFC.
fn _function_f<Hmac>(
    salt: &[u8],
    iterations: usize,
    index: u32,
    dk_block: &mut [u8],
    block_len: usize,
    u_step: &mut [u8],
    hmac: &mut Hmac,
) -> Result<(), UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    debug_assert_eq!(u_step.len(), Hmac::HASH_FUNC_OUTSIZE);
    hmac._update(salt)?;
    hmac._update(&index.to_be_bytes())?;
    hmac._finalize(u_step)?;
    debug_assert!(block_len <= u_step.len());
    dk_block.copy_from_slice(&u_step[..block_len]);

    if iterations > 1 {
        for _ in 1..iterations {
            hmac._reset();
            hmac._update(u_step)?;
            hmac._finalize(u_step)?;
            xor_slices!(u_step, dk_block);
        }
    }

    Ok(())
}

///
///
/// NOTE: Hmac has the output size of the hash function defined,
/// but the array initialization with the size cannot depend on a generic parameter,
/// because we don't have full support for const generics yet.
fn _derive_key<Hmac, const OUTSIZE: usize>(
    padded_password: &[u8],
    salt: &[u8],
    iterations: usize,
    dest: &mut [u8],
) -> Result<(), UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    debug_assert_eq!(OUTSIZE, Hmac::HASH_FUNC_OUTSIZE);
    if dest.is_empty() || iterations < 1 {
        return Err(UnknownCryptoError);
    }

    let mut u_step = [0u8; OUTSIZE];
    let mut hmac = Hmac::_new(padded_password)?;
    for (idx, dk_block) in dest.chunks_mut(Hmac::HASH_FUNC_OUTSIZE).enumerate() {
        // If this panics, then the size limit for PBKDF2 is reached.
        let block_idx: u32 = 1u32.checked_add(idx as u32).unwrap();

        _function_f(
            salt,
            iterations,
            block_idx,
            dk_block,
            dk_block.len(),
            &mut u_step,
            &mut hmac,
        )?;

        hmac._reset();
    }

    Ok(())
}

///
///
/// NOTE: Hmac has the output size of the hash function defined,
/// but the array initialization with the size cannot depend on a generic parameter,
/// because we don't have full support for const generics yet.
fn _verify<Hmac, const OUTSIZE: usize>(
    expected: &[u8],
    padded_password: &[u8],
    salt: &[u8],
    iterations: usize,
    dest: &mut [u8],
) -> Result<(), UnknownCryptoError>
where
    Hmac: hmac::HmacFunction,
{
    debug_assert_eq!(OUTSIZE, Hmac::HASH_FUNC_OUTSIZE);
    _derive_key::<Hmac, { OUTSIZE }>(padded_password, salt, iterations, dest)?;
    crate::util::secure_cmp(expected, dest)
}

// NOTE(brycx): Has to be a different Sealed, otherwise you could
// plug these into Argon2.
pub(crate) mod sealed {
    pub trait Sealed {}
    pub trait Variant: Sealed {}
}

#[derive(Debug, PartialEq)]
/// PBKDF2-HMAC-SHA256 (Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub struct SHA256;
impl sealed::Sealed for SHA256 {}
impl sealed::Variant for SHA256 {}

#[derive(Debug, PartialEq)]
/// PBKDF2-HMAC-SHA384 (Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub struct SHA384;
impl sealed::Sealed for SHA384 {}
impl sealed::Variant for SHA384 {}

#[derive(Debug, PartialEq)]
/// PBKDF2-HMAC-SHA512 (Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub struct SHA512;
impl sealed::Sealed for SHA512 {}
impl sealed::Variant for SHA512 {}

#[derive(Debug)]
///Password-Based Key Derivation Function as specified in the [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914.html).
pub struct Pbkdf2<V: sealed::Variant> {
    _variant: PhantomData<V>,
}

impl Pbkdf2<SHA256> {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Derive a key using PBKDF2-HMAC-SHA256.
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let padded = hmac::sha256::SecretKey::try_from(password)?;
        _derive_key::<
            hmac::sha256::HmacSha256,
            { crate::hazardous::hash::sha2::sha256::SHA256_OUTSIZE },
        >(padded.unprotected_as_ref(), salt, iterations, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify PBKDF2-HMAC-SHA256 derived key in constant time.
    pub fn verify(
        expected: &[u8],
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let padded = hmac::sha256::SecretKey::try_from(password)?;
        _verify::<hmac::sha256::HmacSha256, { crate::hazardous::hash::sha2::sha256::SHA256_OUTSIZE }>(
            expected,
            padded.unprotected_as_ref(),
            salt,
            iterations,
            dst_out,
        )
    }
}

impl Pbkdf2<SHA384> {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Derive a key using PBKDF2-HMAC-SHA384.
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let padded = hmac::sha384::SecretKey::try_from(password)?;
        _derive_key::<
            hmac::sha384::HmacSha384,
            { crate::hazardous::hash::sha2::sha384::SHA384_OUTSIZE },
        >(padded.unprotected_as_ref(), salt, iterations, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify PBKDF2-HMAC-SHA384 derived key in constant time.
    pub fn verify(
        expected: &[u8],
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let padded = hmac::sha384::SecretKey::try_from(password)?;
        _verify::<hmac::sha384::HmacSha384, { crate::hazardous::hash::sha2::sha384::SHA384_OUTSIZE }>(
            expected,
            padded.unprotected_as_ref(),
            salt,
            iterations,
            dst_out,
        )
    }
}

impl Pbkdf2<SHA512> {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Derive a key using PBKDF2-HMAC-SHA512.
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let padded = hmac::sha512::SecretKey::try_from(password)?;
        _derive_key::<
            hmac::sha512::HmacSha512,
            { crate::hazardous::hash::sha2::sha512::SHA512_OUTSIZE },
        >(padded.unprotected_as_ref(), salt, iterations, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify PBKDF2-HMAC-SHA512 derived key in constant time.
    pub fn verify(
        expected: &[u8],
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let padded = hmac::sha512::SecretKey::try_from(password)?;
        _verify::<hmac::sha512::HmacSha512, { crate::hazardous::hash::sha2::sha512::SHA512_OUTSIZE }>(
            expected,
            padded.unprotected_as_ref(),
            salt,
            iterations,
            dst_out,
        )
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    mod test_verify {
        use super::*;

        #[test]
        fn verify_true() {
            let password = b"pass\0word";
            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            Pbkdf2::<SHA256>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA256>::verify(&okm_out, password, salt, iterations, &mut okm_out_verify)
                    .is_ok()
            );

            Pbkdf2::<SHA384>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA384>::verify(&okm_out, password, salt, iterations, &mut okm_out_verify)
                    .is_ok()
            );

            Pbkdf2::<SHA512>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA512>::verify(&okm_out, password, salt, iterations, &mut okm_out_verify)
                    .is_ok()
            );
        }

        #[test]
        fn verify_false_wrong_salt() {
            let password = b"pass\0word";
            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            Pbkdf2::<SHA256>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA256>::verify(&okm_out, password, b"", iterations, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA384>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA384>::verify(&okm_out, password, b"", iterations, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA512>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA512>::verify(&okm_out, password, b"", iterations, &mut okm_out_verify)
                    .is_err()
            );
        }
        #[test]
        fn verify_false_wrong_password() {
            let password = b"pass\0word";
            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            Pbkdf2::<SHA256>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA256>::verify(&okm_out, b"pass", salt, iterations, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA384>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA384>::verify(&okm_out, b"pass", salt, iterations, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA512>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA512>::verify(&okm_out, b"pass", salt, iterations, &mut okm_out_verify)
                    .is_err()
            );
        }

        #[test]
        fn verify_diff_dklen_error() {
            let password = b"pass\0word";

            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 32];

            Pbkdf2::<SHA256>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA256>::verify(&okm_out, password, salt, iterations, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA384>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA384>::verify(&okm_out, password, salt, iterations, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA512>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA512>::verify(&okm_out, password, salt, iterations, &mut okm_out_verify)
                    .is_err()
            );
        }

        #[test]
        fn verify_diff_iter_error() {
            let password = b"pass\0word";
            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            Pbkdf2::<SHA256>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA256>::verify(&okm_out, password, salt, 127, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA384>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA384>::verify(&okm_out, password, salt, 127, &mut okm_out_verify)
                    .is_err()
            );

            Pbkdf2::<SHA512>::derive_key(password, salt, iterations, &mut okm_out).unwrap();
            assert!(
                Pbkdf2::<SHA512>::verify(&okm_out, password, salt, 127, &mut okm_out_verify)
                    .is_err()
            );
        }
    }

    mod test_derive_key {
        use super::*;

        #[test]
        fn zero_iterations_err() {
            let password = b"pass\0word";

            let salt = "salt".as_bytes();
            let iterations: usize = 0;
            let mut okm_out = [0u8; 15];

            assert!(
                Pbkdf2::<SHA256>::derive_key(password, salt, iterations, &mut okm_out).is_err()
            );
            assert!(
                Pbkdf2::<SHA384>::derive_key(password, salt, iterations, &mut okm_out).is_err()
            );
            assert!(
                Pbkdf2::<SHA512>::derive_key(password, salt, iterations, &mut okm_out).is_err()
            );
        }

        #[test]
        fn zero_dklen_err() {
            let password = b"pass\0word";

            let salt = "salt".as_bytes();
            let iterations: usize = 1;
            let mut okm_out = [0u8; 0];

            assert!(
                Pbkdf2::<SHA256>::derive_key(password, salt, iterations, &mut okm_out).is_err()
            );
            assert!(
                Pbkdf2::<SHA384>::derive_key(password, salt, iterations, &mut okm_out).is_err()
            );
            assert!(
                Pbkdf2::<SHA512>::derive_key(password, salt, iterations, &mut okm_out).is_err()
            );
        }
    }
}
