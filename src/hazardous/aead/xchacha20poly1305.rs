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
//! - `key`: The secret key
//! - `nonce`: The nonce value
//! - `aad`: The additional authenticated data
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 128-bit Poly1305 tag
//! appended to it
//! - `plaintext`: The data to be encrypted
//! - `dst_out`: Destination array that will hold the `ciphertext_with_tag`/`plaintext` after encryption/decryption
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of the `key` is not `32` bytes
//! - The length of the `nonce` is not `24` bytes
//! - The length of `dst_out` is less than `plaintext + 16` when encrypting
//! - The length of `dst_out` is less than `ciphertext_with_tag - 16` when decrypting
//! - The length of `ciphertext_with_tag` is not greater than `16`
//! - `plaintext` or `ciphertext_with_tag` are empty
//! - `plaintext` or `ciphertext_with_tag - 16` are longer than (2^32)-2
//! - The received tag does not match the calculated tag when decrypting
//!
//! # Security:
//! It is critical for security that a given nonce is not re-used with a given key. Should this happen,
//! the security of all data that has been encrypted with that given key is compromised.
//!
//! Only a `nonce` for `xchacha20poly1305` is big enough to be randomly generated using a CSPRNG. The `gen_rand_key` function
//! in `util` can be used for this.
//!
//! # Example:
//! ```
//! use orion::hazardous::aead;
//! use orion::util;
//!
//! let mut key = [0u8; 32];
//! let mut nonce = [0u8; 24];
//! util::gen_rand_key(&mut key).unwrap();
//! util::gen_rand_key(&mut nonce).unwrap();
//!
//! let aad = [ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 ];
//! let plaintext = b"\
//! Ladies and Gentlemen of the class of '99: If I could offer you o\
//! nly one tip for the future, sunscreen would be it.";
//!
//! // Length of above plaintext is 114 and then we accomodate 16 for the Poly1305 tag.
//!
//! let mut dst_out_ct = [0u8; 114 + 16];
//! let mut dst_out_pt = [0u8; 114];
//!
//! aead::xchacha20poly1305::encrypt(&key, &nonce, plaintext, &aad, &mut dst_out_ct).unwrap();
//!
//! aead::xchacha20poly1305::decrypt(&key, &nonce, &dst_out_ct, &aad, &mut dst_out_pt).unwrap();
//!
//! assert_eq!(dst_out_pt.as_ref(), plaintext.as_ref());
//! ```
use errors::UnknownCryptoError;
use hazardous::aead::chacha20poly1305;
use hazardous::constants::{IETF_CHACHA_NONCESIZE, XCHACHA_NONCESIZE};
use hazardous::stream::chacha20;
use seckey::zero;

/// AEAD XChaCha20Poly1305 encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if nonce.len() != XCHACHA_NONCESIZE {
        return Err(UnknownCryptoError);
    }

    let mut subkey = chacha20::hchacha20(key, &nonce[0..16]).unwrap();
    let mut prefixed_nonce: [u8; IETF_CHACHA_NONCESIZE] = [0u8; IETF_CHACHA_NONCESIZE];
    prefixed_nonce[4..12].copy_from_slice(&nonce[16..24]);

    chacha20poly1305::encrypt(&subkey, &prefixed_nonce, plaintext, aad, dst_out).unwrap();

    zero(&mut subkey);

    Ok(())
}

/// AEAD XChaCha20Poly1305 decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if nonce.len() != XCHACHA_NONCESIZE {
        return Err(UnknownCryptoError);
    }

    let mut subkey = chacha20::hchacha20(key, &nonce[0..16]).unwrap();
    let mut prefixed_nonce: [u8; IETF_CHACHA_NONCESIZE] = [0u8; IETF_CHACHA_NONCESIZE];
    prefixed_nonce[4..12].copy_from_slice(&nonce[16..24]);

    chacha20poly1305::decrypt(&subkey, &prefixed_nonce, ciphertext_with_tag, aad, dst_out).unwrap();

    zero(&mut subkey);

    Ok(())
}

#[test]
fn test_err_on_bad_nonce_xchacha() {
    let mut dst_out_ct = [0u8; 80]; // 64 + Poly1305TagLen
    let mut dst_out_pt = [0u8; 64];

    assert!(
        encrypt(
            &[0u8; 32],
            &[0u8; 23],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );

    assert!(
        decrypt(
            &[0u8; 32],
            &[0u8; 23],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        encrypt(
            &[0u8; 32],
            &[0u8; 25],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );

    assert!(
        decrypt(
            &[0u8; 32],
            &[0u8; 25],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        encrypt(
            &[0u8; 32],
            &[0u8; 24],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_ok()
    );

    assert!(
        decrypt(
            &[0u8; 32],
            &[0u8; 24],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_ok()
    );
}

#[test]
#[should_panic]
fn test_modified_tag_error() {
    let mut dst_out_ct = [0u8; 80]; // 64 + Poly1305TagLen
    let mut dst_out_pt = [0u8; 64];

    encrypt(
        &[0u8; 32],
        &[0u8; 24],
        &[0u8; 64],
        &[0u8; 0],
        &mut dst_out_ct,
    ).unwrap();
    // Modify the tags first byte
    dst_out_ct[65] ^= 1;
    decrypt(
        &[0u8; 32],
        &[0u8; 24],
        &dst_out_ct,
        &[0u8; 0],
        &mut dst_out_pt,
    ).unwrap();
}
