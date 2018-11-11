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
//! - `secret_key`: The secret key
//! - `nonce`: The nonce value
//! - `initial_counter`: The initial counter value. In most cases this is `0`
//! - `ciphertext`: The encrypted data
//! - `plaintext`: The data to be encrypted
//! - `dst_out`: Destination array that will hold the ciphertext/plaintext after encryption/decryption
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of the `secret_key` is not `32` bytes
//! - The length of the `nonce` is not `24` bytes
//! - The length of `dst_out` is less than `plaintext` or `ciphertext`
//! - `plaintext` or `ciphertext` are empty
//! - `plaintext` or `ciphertext` are longer than (2^32)-2
//! - The `initial_counter` is high enough to cause a potential overflow
//!
//! Even though `dst_out` is allowed to be of greater length than `plaintext`, the `ciphertext`
//! produced by `chacha20`/`xchacha20` will always be of the same length as the `plaintext`.
//!
//! # Security:
//! It is critical for security that a given nonce is not re-used with a given key. Should this happen,
//! the security of all data that has been encrypted with that given key is compromised.
//!
//! Functions herein do not provide any data integrity. If you need
//! data integrity, which is nearly ***always the case***, you should use an AEAD construction instead.
//! See orions `aead` module for this.
//!
//! Only a `nonce` for XChaCha20 is big enough to be randomly generated using a CSPRNG. The `gen_rand_key` function
//! in `util` can be used for this.
//!
//! # Example:
//! ```
//! use orion::hazardous::stream::xchacha20;
//!
//! let secret_key = xchacha20::SecretKey::generate();
//! let nonce = xchacha20::Nonce::generate();
//!
//! // Length of this message is 15
//! let message = "Data to protect".as_bytes();
//!
//! let mut dst_out_pt = [0u8; 15];
//! let mut dst_out_ct = [0u8; 15];
//!
//! xchacha20::encrypt(&secret_key, &nonce, 0, message, &mut dst_out_ct);
//!
//! xchacha20::decrypt(&secret_key, &nonce, 0, &dst_out_ct, &mut dst_out_pt);
//!
//! assert_eq!(dst_out_pt, message);
//! ```
use errors::UnknownCryptoError;
use hazardous::constants::XCHACHA_NONCESIZE;
use hazardous::stream::chacha20;
use hazardous::stream::chacha20::Nonce as IETFNonce;
pub use hazardous::stream::chacha20::SecretKey;
use zeroize::Zeroize;
#[cfg(feature = "safe_api")]
use util;

/// A nonce for XChaCha20.
pub struct Nonce {
    value: [u8; XCHACHA_NONCESIZE],
}

impl Drop for Nonce {
    fn drop(&mut self) {
        self.value.as_mut().zeroize();
    }
}

impl Nonce {
    /// Make Nonce from a byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        if slice.len() != XCHACHA_NONCESIZE {
            return Err(UnknownCryptoError);
        }

        let mut xchacha_nonce = [0u8; XCHACHA_NONCESIZE];
        xchacha_nonce.copy_from_slice(slice);

        Ok(Self {
            value: xchacha_nonce,
        })
    }
    /// Return Nonce as bytes.
    pub fn as_bytes(&self) -> [u8; XCHACHA_NONCESIZE] {
        self.value
    }
    #[cfg(feature = "safe_api")]
    /// Randomly generate a SecretKey using a CSPRNG of length 32. Not available in `no_std` context.
    pub fn generate() -> Self {
        let mut nonce = [0u8; XCHACHA_NONCESIZE];
        util::gen_rand_key(&mut nonce).unwrap();

        Self { value: nonce }
    }
}

/// XChaCha20 encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub fn encrypt(
    secret_key: &SecretKey,
    nonce: &Nonce,
    initial_counter: u32,
    plaintext: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    let subkey: SecretKey =
        SecretKey::from_slice(&chacha20::hchacha20(secret_key, &nonce.as_bytes()[0..16]).unwrap())
            .unwrap();
    let mut prefixed_nonce = [0u8; 12];
    prefixed_nonce[4..12].copy_from_slice(&nonce.as_bytes()[16..24]);

    chacha20::encrypt(
        &subkey,
        &IETFNonce::from_slice(&prefixed_nonce).unwrap(),
        initial_counter,
        plaintext,
        dst_out,
    ).unwrap();

    Ok(())
}

/// XChaCha20 decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub fn decrypt(
    secret_key: &SecretKey,
    nonce: &Nonce,
    initial_counter: u32,
    ciphertext: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    encrypt(secret_key, nonce, initial_counter, ciphertext, dst_out)
}

#[test]
fn test_nonce_sizes() {
    assert!(Nonce::from_slice(&[0u8; 23]).is_err());
    assert!(Nonce::from_slice(&[0u8; 25]).is_err());
    assert!(Nonce::from_slice(&[0u8; 24]).is_ok());
}

#[test]
#[should_panic]
fn test_err_on_empty_pt_xchacha() {
    let mut dst = [0u8; 64];

    assert!(
        encrypt(
            &SecretKey::from_slice(&[0u8; 32]).unwrap(),
            &Nonce::from_slice(&[0u8; 24]).unwrap(),
            0,
            &[0u8; 0],
            &mut dst
        ).is_err()
    );
}

#[test]
#[should_panic]
fn test_err_on_initial_counter_overflow_xchacha() {
    let mut dst = [0u8; 65];

    encrypt(
        &SecretKey::from_slice(&[0u8; 32]).unwrap(),
        &Nonce::from_slice(&[0u8; 24]).unwrap(),
        4294967295,
        &[0u8; 65],
        &mut dst,
    ).unwrap();
}

#[test]
fn test_pass_on_one_iter_max_initial_counter() {
    let mut dst = [0u8; 64];
    // Should pass because only one iteration is completed, so block_counter will not increase
    encrypt(
        &SecretKey::from_slice(&[0u8; 32]).unwrap(),
        &Nonce::from_slice(&[0u8; 24]).unwrap(),
        4294967295,
        &[0u8; 64],
        &mut dst,
    ).unwrap();
}
