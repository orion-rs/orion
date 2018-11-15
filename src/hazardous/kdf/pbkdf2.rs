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
//! - `password`: Password
//! - `salt`: Salt value
//! - `iterations`: Iteration count
//! - `dk_out`: Destination buffer for the derived key. The length of the derived key is implied by the length of `dk_out`
//!
//! See [RFC](https://tools.ietf.org/html/rfc8018#section-5.2) for more information.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of `dk_out` is less than 1
//! - The length of `dk_out` is greater than (2^32 - 1) * hLen
//! - The specified iteration count is less than 1
//! - The hashed password does not match the expected when verifying
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG. The `gen_rand_key` function
//! in `util` can be used for this.
//! - The recommended length for a salt is 64 bytes.
//! - The iteration count should be set as high as feasible. The recommended minimum is 10000.
//!
//! # Example:
//! ```
//! use orion::hazardous::kdf::pbkdf2;
//! use orion::util;
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt).unwrap();
//! let password = pbkdf2::Password::from_slice("Secret password".as_bytes());
//! let mut dk_out = [0u8; 64];
//!
//! pbkdf2::derive_key(&password, &salt, 10000, &mut dk_out).unwrap();
//!
//! let exp_dk = dk_out;
//!
//! assert!(pbkdf2::verify(&exp_dk, &password, &salt, 10000, &mut dk_out).unwrap());
//! ```

use byteorder::{BigEndian, ByteOrder};
use errors::*;
use hazardous::constants::{HLenArray, HLEN, SHA2_BLOCKSIZE};
use hazardous::mac::hmac;
use util;

// We use an HMAC key as password type because the password
// is used as HMAC `SecretKey` in `derive_key` so no further padding is needed.
// The types a explicitly seperated.
construct_hmac_key!(Password, SHA2_BLOCKSIZE);

#[inline(always)]
/// The F function as described in the RFC.
fn function_f(
    salt: &[u8],
    iterations: usize,
    index: u32,
    dk_block: &mut [u8],
    block_len: usize,
    hmac: &mut hmac::Hmac,
) {
    let mut u_step: HLenArray = [0u8; 64];
    // First 4 bytes used for index BE conversion
    BigEndian::write_u32(&mut u_step[..4], index);
    hmac.update(salt).unwrap();
    hmac.update(&u_step[..4]).unwrap();

    u_step.copy_from_slice(&hmac.finalize().unwrap().unprotected_as_bytes());
    dk_block.copy_from_slice(&u_step[..block_len]);

    if iterations > 1 {
        for _ in 1..iterations {
            hmac.reset();
            hmac.update(&u_step).unwrap();
            u_step.copy_from_slice(&hmac.finalize().unwrap().unprotected_as_bytes());

            for (idx, val) in u_step[..block_len].iter().enumerate() {
                dk_block[idx] ^= val;
            }
        }
    }
}

#[must_use]
#[inline(always)]
/// PBKDF2-SHA512 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub fn derive_key(
    password: &Password,
    salt: &[u8],
    iterations: usize,
    dk_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if iterations < 1 {
        return Err(UnknownCryptoError);
    }
    if dk_out.is_empty() {
        return Err(UnknownCryptoError);
    }

    let mut hmac = hmac::init(&hmac::SecretKey::from_slice(
        &password.unprotected_as_bytes(),
    ));

    for (idx, dk_block) in dk_out.chunks_mut(HLEN).enumerate() {
        let block_len = dk_block.len();
        let block_idx = (1_u32).checked_add(idx as u32);

        if block_idx.is_some() {
            function_f(
                salt,
                iterations,
                block_idx.unwrap(),
                dk_block,
                block_len,
                &mut hmac,
            );
            hmac.reset();
        } else {
            return Err(UnknownCryptoError);
        }
    }

    Ok(())
}

#[must_use]
/// Verify PBKDF2-HMAC-SHA512 derived key in constant time.
pub fn verify(
    expected_dk: &[u8],
    password: &Password,
    salt: &[u8],
    iterations: usize,
    dk_out: &mut [u8],
) -> Result<bool, ValidationCryptoError> {
    derive_key(password, salt, iterations, dk_out).unwrap();

    if util::secure_cmp(&dk_out, expected_dk).is_err() {
        Err(ValidationCryptoError)
    } else {
        Ok(true)
    }
}

#[cfg(test)]
mod test {

    extern crate hex;
    use self::hex::decode;
    use hazardous::kdf::pbkdf2::*;

    #[test]
    fn zero_iterations_err() {
        let password = Password::from_slice("password".as_bytes());
        let salt = "salt".as_bytes();
        let iterations: usize = 0;
        let mut okm_out = [0u8; 15];

        assert!(derive_key(&password, salt, iterations, &mut okm_out).is_err());
    }

    #[test]
    fn zero_dklen_err() {
        let password = Password::from_slice("password".as_bytes());
        let salt = "salt".as_bytes();
        let iterations: usize = 1;
        let mut okm_out = [0u8; 0];

        assert!(derive_key(&password, salt, iterations, &mut okm_out).is_err());
    }

    #[test]
    fn verify_true() {
        let password = Password::from_slice("pass\0word".as_bytes());
        let salt = "sa\0lt".as_bytes();
        let iterations: usize = 4096;
        let mut okm_out = [0u8; 16];

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert_eq!(
            verify(&expected_dk, &password, salt, iterations, &mut okm_out).unwrap(),
            true
        );
    }

    #[test]
    fn verify_false_wrong_salt() {
        let password = Password::from_slice("pass\0word".as_bytes());
        let salt = "".as_bytes();
        let iterations: usize = 4096;
        let mut okm_out = [0u8; 16];

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(verify(&expected_dk, &password, salt, iterations, &mut okm_out).is_err());
    }
    #[test]
    fn verify_false_wrong_password() {
        let password = Password::from_slice("".as_bytes());
        let salt = "sa\0lt".as_bytes();
        let iterations: usize = 4096;
        let mut okm_out = [0u8; 16];

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(verify(&expected_dk, &password, salt, iterations, &mut okm_out).is_err());
    }

    #[test]
    fn verify_diff_dklen_error() {
        let password = Password::from_slice("pass\0word".as_bytes());
        let salt = "sa\0lt".as_bytes();
        let iterations: usize = 4096;
        let mut okm_out = [0u8; 32];

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(verify(&expected_dk, &password, salt, iterations, &mut okm_out).is_err());
    }

    #[test]
    fn verify_diff_iter_error() {
        let password = Password::from_slice("pass\0word".as_bytes());
        let salt = "sa\0lt".as_bytes();
        let iterations: usize = 512;
        let mut okm_out = [0u8; 16];

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(verify(&expected_dk, &password, salt, iterations, &mut okm_out).is_err());
    }
}
