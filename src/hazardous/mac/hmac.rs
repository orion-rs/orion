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
//! - `secret_key`:  The authentication key
//! - `data`: Data to be authenticated
//!
//! See [RFC](https://tools.ietf.org/html/rfc2104#section-2) for more information.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - Either `finalize()` or `finalize_with_dst()` is called twice without a `reset()` in between
//! - `update()` is called after `finalize()` without a `reset()` in between
//! - The HMAC does not match the expected when verifying
//!
//! # Security:
//! The secret key should always be generated using a CSPRNG. The `gen_rand_key` function
//! in `util` can be used for this. The recommended length for a secret key is 64.
//!
//! # Example:
//! ### Generating HMAC:
//! ```
//! use orion::hazardous::hmac;
//! use orion::util;
//!
//! let mut key = [0u8; 64];
//! util::gen_rand_key(&mut key).unwrap();
//! let msg = "Some message.";
//!
//! let mut mac = hmac::init(&key);
//! mac.update(msg.as_bytes()).unwrap();
//! mac.finalize().unwrap();
//! ```
//! ### Verifying HMAC:
//! ```
//! use orion::hazardous::mac::hmac;
//! use orion::util;
//!
//! let mut key = [0u8; 64];
//! util::gen_rand_key(&mut key).unwrap();
//! let msg = "Some message.";
//!
//! let mut mac = hmac::init(&key);
//! mac.update(msg.as_bytes()).unwrap();
//!
//! assert!(hmac::verify(&mac.finalize().unwrap(), &key, msg.as_bytes()).unwrap());
//! ```

extern crate core;

use self::core::mem;
use errors::*;
use hazardous::constants::{BlocksizeArray, HLenArray, HLEN, SHA2_BLOCKSIZE};
use seckey::zero;
use sha2::{Digest, Sha512};
use util;

/// HMAC-SHA512 (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub struct Hmac {
    ipad: BlocksizeArray,
    opad_hasher: Sha512,
    ipad_hasher: Sha512,
    is_finalized: bool,
}

impl Drop for Hmac {
    fn drop(&mut self) {
        zero(&mut self.ipad)
    }
}

impl Hmac {
    #[inline(always)]
    /// Pad `key` with `ipad` and `opad`.
    fn pad_key_io(&mut self, key: &[u8]) {
        let mut opad: BlocksizeArray = [0x5C; SHA2_BLOCKSIZE];

        if key.len() > SHA2_BLOCKSIZE {
            self.ipad[..HLEN].copy_from_slice(&Sha512::digest(&key));

            for (idx, itm) in self.ipad.iter_mut().take(HLEN).enumerate() {
                *itm ^= 0x36;
                opad[idx] = *itm ^ 0x6A; // XOR with result of (0x5C ^ 0x36) to inverse
            }
        } else {
            for (idx, itm) in key.iter().enumerate() {
                self.ipad[idx] ^= itm;
                opad[idx] ^= itm;
            }
        }

        self.ipad_hasher.input(self.ipad.as_ref());
        self.opad_hasher.input(opad.as_ref());
        zero(&mut opad);
    }

    /// Reset to `init()` state.
    pub fn reset(&mut self) {
        if self.is_finalized {
            self.ipad_hasher.input(self.ipad.as_ref());
            self.is_finalized = false;
        } else {
        }
    }

    /// This can be called multiple times.
    pub fn update(&mut self, message: &[u8]) -> Result<(), FinalizationCryptoError> {
        if self.is_finalized {
            Err(FinalizationCryptoError)
        } else {
            self.ipad_hasher.input(message);
            Ok(())
        }
    }

    #[inline(always)]
    /// Return MAC.
    pub fn finalize(&mut self) -> Result<[u8; 64], FinalizationCryptoError> {
        if self.is_finalized {
            return Err(FinalizationCryptoError);
        }

        self.is_finalized = true;

        let mut hash_ires = Sha512::default();
        mem::swap(&mut self.ipad_hasher, &mut hash_ires);

        let mut o_hash = self.opad_hasher.clone();
        o_hash.input(&hash_ires.result());

        let mut mac: HLenArray = [0u8; HLEN];
        mac.copy_from_slice(&o_hash.result());

        Ok(mac)
    }

    #[inline(always)]
    /// Retrieve MAC and copy to `dst`.
    pub fn finalize_with_dst(&mut self, dst: &mut [u8]) -> Result<(), FinalizationCryptoError> {
        if self.is_finalized {
            return Err(FinalizationCryptoError);
        }

        self.is_finalized = true;

        let mut hash_ires = Sha512::default();
        mem::swap(&mut self.ipad_hasher, &mut hash_ires);

        let mut o_hash = self.opad_hasher.clone();
        o_hash.input(&hash_ires.result());
        let dst_len = dst.len();

        dst.copy_from_slice(&o_hash.result()[..dst_len]);

        Ok(())
    }
}

/// Verify a HMAC-SHA512 MAC in constant time.
pub fn verify(
    expected: &[u8],
    secret_key: &[u8],
    message: &[u8],
) -> Result<bool, ValidationCryptoError> {
    let mut mac = init(secret_key);
    mac.update(message).unwrap();

    if util::compare_ct(&mac.finalize().unwrap(), expected).is_err() {
        Err(ValidationCryptoError)
    } else {
        Ok(true)
    }
}

#[inline(always)]
/// Initialize `Hmac` struct with a given key.
pub fn init(secret_key: &[u8]) -> Hmac {
    let mut mac = Hmac {
        ipad: [0x36; SHA2_BLOCKSIZE],
        opad_hasher: Sha512::default(),
        ipad_hasher: Sha512::default(),
        is_finalized: false,
    };

    mac.pad_key_io(secret_key);
    mac
}

#[test]
fn finalize_and_verify_true() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();

    assert_eq!(
        verify(&mac.finalize().unwrap(), secret_key, data).unwrap(),
        true
    );
}

#[test]
fn veriy_false_wrong_data() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();

    assert!(
        verify(
            &mac.finalize().unwrap(),
            secret_key,
            "what do ya want for something?".as_bytes()
        ).is_err()
    );
}

#[test]
fn veriy_false_wrong_secret_key() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();

    assert!(verify(&mac.finalize().unwrap(), "Jose".as_bytes(), data).is_err());
}

#[test]
#[should_panic]
fn double_finalize_err() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();
    mac.finalize().unwrap();
    mac.finalize().unwrap();
}

#[test]
fn double_finalize_with_reset_ok() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();
    mac.finalize().unwrap();
    mac.reset();
    mac.update("Test".as_bytes()).unwrap();
    mac.finalize().unwrap();
}

#[test]
fn double_finalize_with_reset_no_update_ok() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();
    mac.finalize().unwrap();
    mac.reset();
    mac.finalize().unwrap();
}

#[test]
#[should_panic]
fn update_after_finalize_err() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();
    mac.finalize().unwrap();
    mac.update(data).unwrap();
}

#[test]
fn update_after_finalize_with_reset_ok() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data).unwrap();
    mac.finalize().unwrap();
    mac.reset();
    mac.update(data).unwrap();
}
