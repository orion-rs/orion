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
//! - Use [`Password::generate()`] to randomly generate a password of the same length as
//! the underlying SHA2 hash functions blocksize.
//! - Salts should always be generated using a CSPRNG.
//!   [`util::secure_rand_bytes()`] can be used for this.
//! - The recommended length for a salt is 64 bytes.
//! - The iteration count should be set as high as feasible. The recommended
//!   minimum is 100000.
//!
//! # Example:
//! ```rust
//! use orion::{hazardous::kdf::pbkdf2, util};
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt)?;
//! let password = pbkdf2::sha512::Password::from_slice("Secret password".as_bytes())?;
//! let mut dst_out = [0u8; 64];
//!
//! pbkdf2::sha512::derive_key(&password, &salt, 10000, &mut dst_out)?;
//!
//! let expected_dk = dst_out;
//!
//! assert!(pbkdf2::sha512::verify(&expected_dk, &password, &salt, 10000, &mut dst_out).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`Password::generate()`]: struct.Password.html#method.generate
//! [`util::secure_rand_bytes()`]: ../../../util/fn.secure_rand_bytes.html

use crate::{errors::UnknownCryptoError, hazardous::mac::hmac};

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
    debug_assert!(u_step.len() == Hmac::HASH_FUNC_OUTSIZE);
    hmac._update(salt)?;
    hmac._update(&index.to_be_bytes())?;
    hmac._finalize(u_step)?;
    debug_assert!(block_len <= u_step.len());
    dk_block.copy_from_slice(&u_step[..block_len]);

    if iterations > 1 {
        for _ in 1..iterations {
            hmac._reset();
            hmac._update(&u_step)?;
            hmac._finalize(u_step)?;
            xor_slices!(&u_step, dk_block);
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
    debug_assert!(OUTSIZE == Hmac::HASH_FUNC_OUTSIZE);
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
    debug_assert!(OUTSIZE == Hmac::HASH_FUNC_OUTSIZE);
    _derive_key::<Hmac, { OUTSIZE }>(padded_password, salt, iterations, dest)?;
    crate::util::secure_cmp(expected, dest)
}

/// PBKDF2-HMAC-SHA256 (Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub mod sha256 {
    use super::*;
    use crate::hazardous::hash::sha2::sha256::{self, Sha256};

    construct_hmac_key! {
        /// A type to represent the `Password` that PBKDF2 hashes.
        ///
        /// # Note:
        /// Because `Password` is used as a `SecretKey` for HMAC during hashing, `Password` already
        /// pads the given password to a length of 64, for use in HMAC, when initialized.
        ///
        /// Using `unprotected_as_bytes()` will return the password with padding.
        ///
        /// Using `get_length()` will return the length with padding (always 64).
        ///
        /// # Panics:
        /// A panic will occur if:
        /// - Failure to generate random bytes securely.
        (Password, Sha256, sha256::SHA256_OUTSIZE, test_pbkdf2_password, sha256::SHA256_BLOCKSIZE)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Derive a key using PBKDF2-HMAC-SHA256.
    pub fn derive_key(
        password: &Password,
        salt: &[u8],
        iterations: usize,
        dest: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _derive_key::<hmac::sha256::HmacSha256, { sha256::SHA256_OUTSIZE }>(
            password.unprotected_as_bytes(),
            salt,
            iterations,
            dest,
        )
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify PBKDF2-HMAC-SHA256 derived key in constant time.
    pub fn verify(
        expected: &[u8],
        password: &Password,
        salt: &[u8],
        iterations: usize,
        dest: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _verify::<hmac::sha256::HmacSha256, { sha256::SHA256_OUTSIZE }>(
            expected,
            password.unprotected_as_bytes(),
            salt,
            iterations,
            dest,
        )
    }
}

/// PBKDF2-HMAC-SHA384 (Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub mod sha384 {
    use super::*;
    use crate::hazardous::hash::sha2::sha384::{self, Sha384};

    construct_hmac_key! {
        /// A type to represent the `Password` that PBKDF2 hashes.
        ///
        /// # Note:
        /// Because `Password` is used as a `SecretKey` for HMAC during hashing, `Password` already
        /// pads the given password to a length of 128, for use in HMAC, when initialized.
        ///
        /// Using `unprotected_as_bytes()` will return the password with padding.
        ///
        /// Using `get_length()` will return the length with padding (always 128).
        ///
        /// # Panics:
        /// A panic will occur if:
        /// - Failure to generate random bytes securely.
        (Password, Sha384, sha384::SHA384_OUTSIZE, test_pbkdf2_password, sha384::SHA384_BLOCKSIZE)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Derive a key using PBKDF2-HMAC-SHA384.
    pub fn derive_key(
        password: &Password,
        salt: &[u8],
        iterations: usize,
        dest: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _derive_key::<hmac::sha384::HmacSha384, { sha384::SHA384_OUTSIZE }>(
            password.unprotected_as_bytes(),
            salt,
            iterations,
            dest,
        )
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify PBKDF2-HMAC-SHA384 derived key in constant time.
    pub fn verify(
        expected: &[u8],
        password: &Password,
        salt: &[u8],
        iterations: usize,
        dest: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _verify::<hmac::sha384::HmacSha384, { sha384::SHA384_OUTSIZE }>(
            expected,
            password.unprotected_as_bytes(),
            salt,
            iterations,
            dest,
        )
    }
}

/// PBKDF2-HMAC-SHA512 (Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub mod sha512 {
    use super::*;
    use crate::hazardous::hash::sha2::sha512::{self, Sha512};

    construct_hmac_key! {
        /// A type to represent the `Password` that PBKDF2 hashes.
        ///
        /// # Note:
        /// Because `Password` is used as a `SecretKey` for HMAC during hashing, `Password` already
        /// pads the given password to a length of 128, for use in HMAC, when initialized.
        ///
        /// Using `unprotected_as_bytes()` will return the password with padding.
        ///
        /// Using `get_length()` will return the length with padding (always 128).
        ///
        /// # Panics:
        /// A panic will occur if:
        /// - Failure to generate random bytes securely.
        (Password, Sha512, sha512::SHA512_OUTSIZE, test_pbkdf2_password, sha512::SHA512_BLOCKSIZE)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Derive a key using PBKDF2-HMAC-SHA512.
    pub fn derive_key(
        password: &Password,
        salt: &[u8],
        iterations: usize,
        dest: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _derive_key::<hmac::sha512::HmacSha512, { sha512::SHA512_OUTSIZE }>(
            password.unprotected_as_bytes(),
            salt,
            iterations,
            dest,
        )
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify PBKDF2-HMAC-SHA512 derived key in constant time.
    pub fn verify(
        expected: &[u8],
        password: &Password,
        salt: &[u8],
        iterations: usize,
        dest: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        _verify::<hmac::sha512::HmacSha512, { sha512::SHA512_OUTSIZE }>(
            expected,
            password.unprotected_as_bytes(),
            salt,
            iterations,
            dest,
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
            let password_256 = sha256::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_384 = sha384::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_512 = sha512::Password::from_slice("pass\0word".as_bytes()).unwrap();

            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            sha256::derive_key(&password_256, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha256::verify(
                &okm_out,
                &password_256,
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_ok());

            sha384::derive_key(&password_384, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha384::verify(
                &okm_out,
                &password_384,
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_ok());

            sha512::derive_key(&password_512, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha512::verify(
                &okm_out,
                &password_512,
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_ok());
        }

        #[test]
        fn verify_false_wrong_salt() {
            let password_256 = sha256::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_384 = sha384::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_512 = sha512::Password::from_slice("pass\0word".as_bytes()).unwrap();

            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            sha256::derive_key(&password_256, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha256::verify(
                &okm_out,
                &password_256,
                b"",
                iterations,
                &mut okm_out_verify
            )
            .is_err());

            sha384::derive_key(&password_384, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha384::verify(
                &okm_out,
                &password_384,
                b"",
                iterations,
                &mut okm_out_verify
            )
            .is_err());

            sha512::derive_key(&password_512, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha512::verify(
                &okm_out,
                &password_512,
                b"",
                iterations,
                &mut okm_out_verify
            )
            .is_err());
        }
        #[test]
        fn verify_false_wrong_password() {
            let password_256 = sha256::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_384 = sha384::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_512 = sha512::Password::from_slice("pass\0word".as_bytes()).unwrap();

            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            sha256::derive_key(&password_256, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha256::verify(
                &okm_out,
                &sha256::Password::from_slice(b"pass").unwrap(),
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_err());

            sha384::derive_key(&password_384, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha384::verify(
                &okm_out,
                &sha384::Password::from_slice(b"pass").unwrap(),
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_err());

            sha512::derive_key(&password_512, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha512::verify(
                &okm_out,
                &sha512::Password::from_slice(b"pass").unwrap(),
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_err());
        }

        #[test]
        fn verify_diff_dklen_error() {
            let password_256 = sha256::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_384 = sha384::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_512 = sha512::Password::from_slice("pass\0word".as_bytes()).unwrap();

            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 32];

            sha256::derive_key(&password_256, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha256::verify(
                &okm_out,
                &password_256,
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_err());

            sha384::derive_key(&password_384, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha384::verify(
                &okm_out,
                &password_384,
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_err());

            sha512::derive_key(&password_512, &salt, iterations, &mut okm_out).unwrap();
            assert!(sha512::verify(
                &okm_out,
                &password_512,
                salt,
                iterations,
                &mut okm_out_verify
            )
            .is_err());
        }

        #[test]
        fn verify_diff_iter_error() {
            let password_256 = sha256::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_384 = sha384::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_512 = sha512::Password::from_slice("pass\0word".as_bytes()).unwrap();

            let salt = "sa\0lt".as_bytes();
            let iterations: usize = 128;
            let mut okm_out = [0u8; 16];
            let mut okm_out_verify = [0u8; 16];

            sha256::derive_key(&password_256, &salt, iterations, &mut okm_out).unwrap();
            assert!(
                sha256::verify(&okm_out, &password_256, salt, 127, &mut okm_out_verify).is_err()
            );

            sha384::derive_key(&password_384, &salt, iterations, &mut okm_out).unwrap();
            assert!(
                sha384::verify(&okm_out, &password_384, salt, 127, &mut okm_out_verify).is_err()
            );

            sha512::derive_key(&password_512, &salt, iterations, &mut okm_out).unwrap();
            assert!(
                sha512::verify(&okm_out, &password_512, salt, 127, &mut okm_out_verify).is_err()
            );
        }
    }

    mod test_derive_key {
        use super::*;

        #[test]
        fn zero_iterations_err() {
            let password_256 = sha256::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_384 = sha384::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_512 = sha512::Password::from_slice("pass\0word".as_bytes()).unwrap();

            let salt = "salt".as_bytes();
            let iterations: usize = 0;
            let mut okm_out = [0u8; 15];

            assert!(sha256::derive_key(&password_256, salt, iterations, &mut okm_out).is_err());
            assert!(sha384::derive_key(&password_384, salt, iterations, &mut okm_out).is_err());
            assert!(sha512::derive_key(&password_512, salt, iterations, &mut okm_out).is_err());
        }

        #[test]
        fn zero_dklen_err() {
            let password_256 = sha256::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_384 = sha384::Password::from_slice("pass\0word".as_bytes()).unwrap();
            let password_512 = sha512::Password::from_slice("pass\0word".as_bytes()).unwrap();

            let salt = "salt".as_bytes();
            let iterations: usize = 1;
            let mut okm_out = [0u8; 0];

            assert!(sha256::derive_key(&password_256, salt, iterations, &mut okm_out).is_err());
            assert!(sha384::derive_key(&password_384, salt, iterations, &mut okm_out).is_err());
            assert!(sha512::derive_key(&password_512, salt, iterations, &mut okm_out).is_err());
        }
    }
}
