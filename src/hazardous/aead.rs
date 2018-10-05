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

use byteorder::{ByteOrder, LittleEndian};
use hazardous::chacha20;
use hazardous::constants::{
    CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE, POLY1305_BLOCKSIZE, POLY1305_KEYSIZE,
};
use hazardous::poly1305;
use utilities::errors::UnknownCryptoError;
use utilities::util;

/// AEAD_Chacha20_Poly1305 as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).

fn poly1305_key_gen(key: &[u8], nonce: &[u8]) -> [u8; POLY1305_KEYSIZE] {
    let mut poly1305_key = [0u8; POLY1305_KEYSIZE];
    poly1305_key
        .copy_from_slice(&chacha20::keystream_block(key, nonce, 0).unwrap()[..POLY1305_KEYSIZE]);

    poly1305_key
}

fn padding(input: &[u8], pad_len: usize) -> usize {
    if input.len() % pad_len != 0 {
        pad_len - (input.len() % pad_len)
    } else {
        0
    }
}

pub fn aead_ietf_chacha20_poly1305_encrypt(
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
    if aad.is_empty() {
        return Err(UnknownCryptoError);
    }
    if plaintext.is_empty() {
        return Err(UnknownCryptoError);
    }

    let poly1305_key = poly1305_key_gen(key, nonce);
    chacha20::encrypt(key, nonce, 1, plaintext, &mut dst_out[..plaintext.len()]).unwrap();
    let mut poly1305_state = poly1305::init(&poly1305_key).unwrap();

    let mut padding_max = [0u8; 16];

    poly1305_state.update(aad).unwrap();
    poly1305_state
        .update(&padding_max[..padding(aad, 16)])
        .unwrap();
    poly1305_state.update(&dst_out[..plaintext.len()]).unwrap();
    poly1305_state
        .update(&padding_max[..padding(&dst_out[..plaintext.len()], 16)])
        .unwrap();

    // Using the 16 bytes from padding template to store length information
    LittleEndian::write_u64(&mut padding_max[..8], aad.len() as u64);
    // Plaintext length == ciphertext length with ChaCha20
    LittleEndian::write_u64(&mut padding_max[8..16], plaintext.len() as u64);

    poly1305_state.update(&padding_max[..8]).unwrap();
    poly1305_state.update(&padding_max[8..16]).unwrap();

    dst_out[plaintext.len()..].copy_from_slice(&poly1305_state.finalize().unwrap());

    Ok(())
}

pub fn aead_ietf_chacha20_poly1305_decrypt(
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
    if dst_out.len() < ciphertext_with_tag.len() - POLY1305_BLOCKSIZE {
        return Err(UnknownCryptoError);
    }
    if aad.is_empty() {
        return Err(UnknownCryptoError);
    }

    let ciphertext_len = ciphertext_with_tag.len() - POLY1305_BLOCKSIZE;

    let poly1305_key = poly1305_key_gen(key, nonce);
    let mut padding_max = [0u8; 16];

    let mut poly1305_state = poly1305::init(&poly1305_key).unwrap();
    poly1305_state.update(aad).unwrap();
    poly1305_state
        .update(&padding_max[..padding(aad, 16)])
        .unwrap();
    poly1305_state
        .update(&ciphertext_with_tag[..ciphertext_len])
        .unwrap();
    poly1305_state
        .update(&padding_max[..padding(&ciphertext_with_tag[..ciphertext_len], 16)])
        .unwrap();

    // Using the 16 bytes from padding template to store length information
    LittleEndian::write_u64(&mut padding_max[..8], aad.len() as u64);
    // Plaintext length == ciphertext length with ChaCha20
    LittleEndian::write_u64(&mut padding_max[8..16], ciphertext_len as u64);

    poly1305_state.update(&padding_max[..8]).unwrap();
    poly1305_state.update(&padding_max[8..16]).unwrap();

    util::compare_ct(
        &poly1305_state.finalize().unwrap(),
        &ciphertext_with_tag[ciphertext_len..],
    ).unwrap();

    chacha20::decrypt(
        key,
        nonce,
        1,
        &ciphertext_with_tag[..ciphertext_len],
        dst_out,
    ).unwrap();

    Ok(())
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
