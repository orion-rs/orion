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
//! - `dst_out`: Destination array that will hold the ciphertext_with_tag/plaintext after encryption/decryption
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of the `key` is not `32` bytes
//! - The length of the `nonce` is not an acceptable length (`12` with ChaCha20, `16` with HChaCha20 and
//! `24` with XChaCha20).
//! - The length of `dst_out` is less than `plaintext + 16` when encrypting
//! - The length of `dst_out` is less than `ciphertext_with_tag - 16` when decrypting
//! - The length of `ciphertext_with_tag` is not greater than 16
//! - `plaintext` or `ciphertext_with_tag` are empty
//! - `plaintext` or `ciphertext_with_tag - 16` are longer than (2^32)-2
//! - The received tag does not match the calculated tag when decrypting
//!
//! # Security:
//! It is critical for security that a given nonce is not re-used with a given key. Should this happen,
//! the security of all data that has been encrypted with that given key is compromised.
//!
//! # Example:
//! ```
//! use orion::hazardous::aead;
//!
//! let key = [
//!     0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
//!     0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
//!     0x9c, 0x9d, 0x9e, 0x9f,
//! ];
//! let nonce = [
//!     0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
//! ];
//! let aad = [
//!     0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
//! ];
//! let plaintext = b"\
//! Ladies and Gentlemen of the class of '99: If I could offer you o\
//! nly one tip for the future, sunscreen would be it.";
//!
//! // Length of above plaintext is 114 and then we accomodate 16 for the Poly1305 tag.
//!
//! let mut dst_out_ct = [0u8; 114 + 16];
//! aead::ietf_chacha20_poly1305_encrypt(&key, &nonce, plaintext, &aad, &mut dst_out_ct).unwrap();
//!
//! let mut dst_out_pt = [0u8; 114];
//! aead::ietf_chacha20_poly1305_decrypt(&key, &nonce, &dst_out_ct, &aad, &mut dst_out_pt).unwrap();
//!
//! assert_eq!(dst_out_pt.as_ref(), plaintext.as_ref());
//! ```
use byteorder::{ByteOrder, LittleEndian};
use errors::UnknownCryptoError;
use hazardous::chacha20;
use hazardous::constants::{
    CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE, POLY1305_BLOCKSIZE, POLY1305_KEYSIZE, XCHACHA_NONCESIZE,
};
use hazardous::poly1305;
use seckey::zero;
use util;

/// Poly1305 key generation using IETF ChaCha20.
fn poly1305_key_gen(key: &[u8], nonce: &[u8]) -> [u8; POLY1305_KEYSIZE] {
    let mut poly1305_key = [0u8; POLY1305_KEYSIZE];
    poly1305_key.copy_from_slice(
        &chacha20::chacha20_keystream_block(key, nonce, 0).unwrap()[..POLY1305_KEYSIZE],
    );

    poly1305_key
}

/// Padding size that gives the needed bytes to pad `input` to an integral multiple of 16.
fn padding(input: &[u8]) -> usize {
    if input.len() % 16 != 0 {
        16 - (input.len() % 16)
    } else {
        0
    }
}

/// Process data to be authenticated using a `Poly1305` struct initialized with a one-time-key.
fn process_authentication(
    poly1305_state: &mut poly1305::Poly1305,
    aad: &[u8],
    buf: &[u8],
    buf_in_len: usize,
) -> Result<(), UnknownCryptoError> {
    if buf_in_len > buf.len() {
        return Err(UnknownCryptoError);
    }

    let mut padding_max = [0u8; 16];

    poly1305_state.update(aad).unwrap();
    poly1305_state
        .update(&padding_max[..padding(aad)])
        .unwrap();
    poly1305_state.update(&buf[..buf_in_len]).unwrap();
    poly1305_state
        .update(&padding_max[..padding(&buf[..buf_in_len])])
        .unwrap();

    // Using the 16 bytes from padding template to store length information
    LittleEndian::write_u64(&mut padding_max[..8], aad.len() as u64);
    LittleEndian::write_u64(&mut padding_max[8..16], buf_in_len as u64);

    poly1305_state.update(&padding_max[..8]).unwrap();
    poly1305_state.update(&padding_max[8..16]).unwrap();

    Ok(())
}

/// `AEAD_ChaCha20_Poly1305` encryption as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn ietf_chacha20_poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if key.len() != CHACHA_KEYSIZE {
        return Err(UnknownCryptoError);
    }
    if nonce.len() != IETF_CHACHA_NONCESIZE {
        return Err(UnknownCryptoError);
    }
    if dst_out.len() < plaintext.len() + POLY1305_BLOCKSIZE {
        return Err(UnknownCryptoError);
    }
    if plaintext.is_empty() {
        return Err(UnknownCryptoError);
    }

    let mut poly1305_key = poly1305_key_gen(key, nonce);
    chacha20::chacha20_encrypt(key, nonce, 1, plaintext, &mut dst_out[..plaintext.len()]).unwrap();
    let mut poly1305_state = poly1305::init(&poly1305_key).unwrap();

    process_authentication(&mut poly1305_state, aad, &dst_out, plaintext.len()).unwrap();
    dst_out[plaintext.len()..].copy_from_slice(&poly1305_state.finalize().unwrap());

    zero(&mut poly1305_key);

    Ok(())
}

/// `AEAD_ChaCha20_Poly1305` decryption as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn ietf_chacha20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if key.len() != CHACHA_KEYSIZE {
        return Err(UnknownCryptoError);
    }
    if nonce.len() != IETF_CHACHA_NONCESIZE {
        return Err(UnknownCryptoError);
    }
    if ciphertext_with_tag.len() <= POLY1305_BLOCKSIZE {
        return Err(UnknownCryptoError);
    }
    if dst_out.len() < ciphertext_with_tag.len() - POLY1305_BLOCKSIZE {
        return Err(UnknownCryptoError);
    }

    let ciphertext_len = ciphertext_with_tag.len() - POLY1305_BLOCKSIZE;

    let mut poly1305_key = poly1305_key_gen(key, nonce);
    let mut poly1305_state = poly1305::init(&poly1305_key).unwrap();
    process_authentication(
        &mut poly1305_state,
        aad,
        ciphertext_with_tag,
        ciphertext_len,
    ).unwrap();

    util::compare_ct(
        &poly1305_state.finalize().unwrap(),
        &ciphertext_with_tag[ciphertext_len..],
    ).unwrap();

    chacha20::chacha20_decrypt(
        key,
        nonce,
        1,
        &ciphertext_with_tag[..ciphertext_len],
        dst_out,
    ).unwrap();

    zero(&mut poly1305_key);

    Ok(())
}

/// `AEAD_XChaCha20_Poly1305` encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub fn xchacha20_poly1305_encrypt(
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

    ietf_chacha20_poly1305_encrypt(&subkey, &prefixed_nonce, plaintext, aad, dst_out).unwrap();

    zero(&mut subkey);

    Ok(())
}

/// `AEAD_XChaCha20_Poly1305` decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub fn xchacha20_poly1305_decrypt(
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

    ietf_chacha20_poly1305_decrypt(&subkey, &prefixed_nonce, ciphertext_with_tag, aad, dst_out)
        .unwrap();

    zero(&mut subkey);

    Ok(())
}


#[test]
fn length_padding_tests() {
    // Integral multiple of 16
    assert_eq!(padding(&[0u8; 16]), 0);
    assert_eq!(padding(&[0u8; 15]), 1);
    assert_eq!(padding(&[0u8; 32]), 0);
    assert_eq!(padding(&[0u8; 30]), 2);
}

#[test]
#[should_panic]
fn test_auth_process_with_above_length_index() {
    let poly1305_key = poly1305_key_gen(&[0u8; 32], &[0u8; 12]);
    let mut poly1305_state = poly1305::init(&poly1305_key).unwrap();

    process_authentication(
        &mut poly1305_state,
        &[0u8; 0],
        &[0u8; 64],
        65,
    ).unwrap();
}

#[test]
fn test_auth_process_ok_index_length() {
    let poly1305_key = poly1305_key_gen(&[0u8; 32], &[0u8; 12]);
    let mut poly1305_state = poly1305::init(&poly1305_key).unwrap();

    process_authentication(
        &mut poly1305_state,
        &[0u8; 0],
        &[0u8; 64],
        64,
    ).unwrap();

    process_authentication(
        &mut poly1305_state,
        &[0u8; 0],
        &[0u8; 64],
        0,
    ).unwrap();
}

#[test]
fn test_err_on_bad_nonce_xchacha() {
    let mut dst_out_ct = [0u8; 80]; // 64 + Poly1305TagLen
    let mut dst_out_pt = [0u8; 64];

    assert!(
        xchacha20_poly1305_encrypt(
            &[0u8; 32],
            &[0u8; 23],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );

    assert!(
        xchacha20_poly1305_decrypt(
            &[0u8; 32],
            &[0u8; 23],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        xchacha20_poly1305_encrypt(
            &[0u8; 32],
            &[0u8; 25],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );

    assert!(
        xchacha20_poly1305_decrypt(
            &[0u8; 32],
            &[0u8; 25],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        xchacha20_poly1305_encrypt(
            &[0u8; 32],
            &[0u8; 24],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_ok()
    );

    assert!(
        xchacha20_poly1305_decrypt(
            &[0u8; 32],
            &[0u8; 24],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_ok()
    );
}

#[test]
fn test_err_bad_key_nonce_sizes_ietf() {
    let mut dst_out_ct = [0u8; 80]; // 64 + Poly1305TagLen
    let mut dst_out_pt = [0u8; 64];

    assert!(
        ietf_chacha20_poly1305_encrypt(
            &[0u8; 30],
            &[0u8; 10],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );
    assert!(
        ietf_chacha20_poly1305_decrypt(
            &[0u8; 30],
            &[0u8; 10],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        ietf_chacha20_poly1305_encrypt(
            &[0u8; 30],
            &[0u8; 12],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );
    assert!(
        ietf_chacha20_poly1305_decrypt(
            &[0u8; 30],
            &[0u8; 12],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        ietf_chacha20_poly1305_encrypt(
            &[0u8; 32],
            &[0u8; 10],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );
    assert!(
        ietf_chacha20_poly1305_decrypt(
            &[0u8; 32],
            &[0u8; 10],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        ietf_chacha20_poly1305_encrypt(
            &[0u8; 33],
            &[0u8; 13],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_err()
    );
    assert!(
        ietf_chacha20_poly1305_decrypt(
            &[0u8; 33],
            &[0u8; 13],
            &dst_out_ct,
            &[0u8; 0],
            &mut dst_out_pt
        ).is_err()
    );

    assert!(
        ietf_chacha20_poly1305_encrypt(
            &[0u8; 32],
            &[0u8; 12],
            &[0u8; 64],
            &[0u8; 0],
            &mut dst_out_ct
        ).is_ok()
    );
    assert!(
        ietf_chacha20_poly1305_decrypt(
            &[0u8; 32],
            &[0u8; 12],
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

    ietf_chacha20_poly1305_encrypt(
        &[0u8; 32],
        &[0u8; 12],
        &[0u8; 64],
        &[0u8; 0],
        &mut dst_out_ct,
    ).unwrap();
    // Modify the tags first byte
    dst_out_ct[65] ^= 1;
    ietf_chacha20_poly1305_decrypt(
        &[0u8; 32],
        &[0u8; 12],
        &dst_out_ct,
        &[0u8; 0],
        &mut dst_out_pt,
    ).unwrap();
}

#[test]
fn rfc_8439_test_poly1305_key_gen_1() {
    let key = [0u8; 32];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let expected = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
        0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
        0x0d, 0xc7,
    ];

    assert_eq!(poly1305_key_gen(&key, &nonce).as_ref(), expected.as_ref());
}

#[test]
fn rfc_8439_test_poly1305_key_gen_2() {
    let key = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];
    let expected = [
        0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74, 0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9, 0xe8,
        0x76, 0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87, 0xbc, 0x26, 0x66, 0xdd, 0xe3, 0xfb,
        0xb7, 0x39,
    ];

    assert_eq!(poly1305_key_gen(&key, &nonce).as_ref(), expected.as_ref());
}

#[test]
fn rfc_8439_test_poly1305_key_gen_3() {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5,
        0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70,
        0x75, 0xc0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];
    let expected = [
        0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9, 0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29, 0xf9,
        0x4b, 0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb, 0xdd, 0x59, 0xde, 0xaa, 0xd2, 0x33,
        0x10, 0xae,
    ];

    assert_eq!(poly1305_key_gen(&key, &nonce).as_ref(), expected.as_ref());
}
