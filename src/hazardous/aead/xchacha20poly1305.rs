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
//! - `ad`: Additional data to authenticate (this is not encrypted and can be an empty slice)
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 128-bit Poly1305 tag
//! appended to it
//! - `plaintext`: The data to be encrypted
//! - `dst_out`: Destination array that will hold the `ciphertext_with_tag`/`plaintext` after encryption/decryption
//!
//! `ad`: "A typical use for these data is to authenticate version numbers, timestamps or
//! monotonically increasing counters in order to discard previous messages and prevent
//! replay attacks." See [libsodium docs](https://download.libsodium.org/doc/secret-key_cryptography/aead#additional-data) for more information.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of the `secret_key` is not `32` bytes
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
//! Only a nonce for XChaCha20Poly1305 is big enough to be randomly generated using a CSPRNG. The `gen_rand_key` function
//! in `util` can be used for this.
//!
//! It is recommended to use XChaCha20Poly1305 when possible.
//!
//! # Example:
//! ```
//! use orion::hazardous::aead;
//! use orion::util;
//!
//! let mut secret_key = [0u8; 32];
//! let mut nonce = [0u8; 24];
//! util::gen_rand_key(&mut secret_key).unwrap();
//! util::gen_rand_key(&mut nonce).unwrap();
//!
//! let ad = [ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 ];
//! let plaintext = b"\
//! Ladies and Gentlemen of the class of '99: If I could offer you o\
//! nly one tip for the future, sunscreen would be it.";
//!
//! // Length of above plaintext is 114 and then we accomodate 16 for the Poly1305 tag.
//!
//! let mut dst_out_ct = [0u8; 114 + 16];
//! let mut dst_out_pt = [0u8; 114];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! aead::xchacha20poly1305::encrypt(&secret_key, &nonce, plaintext, &ad, &mut dst_out_ct).unwrap();
//! // Verify tag, if correct then decrypt and place plaintext in dst_out_pt
//! aead::xchacha20poly1305::decrypt(&secret_key, &nonce, &dst_out_ct, &ad, &mut dst_out_pt).unwrap();
//!
//! assert_eq!(dst_out_pt.as_ref(), plaintext.as_ref());
//! ```
use errors::UnknownCryptoError;
use hazardous::aead::chacha20poly1305;
use hazardous::stream::chacha20;
pub use hazardous::stream::chacha20::SecretKey;
pub use hazardous::stream::xchacha20::Nonce;
use hazardous::stream::chacha20::Nonce as IETFNonce;

/// AEAD XChaCha20Poly1305 encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn encrypt(
    secret_key: SecretKey,
    nonce: Nonce,
    plaintext: &[u8],
    ad: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    let subkey: SecretKey =
        SecretKey::from_slice(&chacha20::hchacha20(secret_key, &nonce.as_bytes()[0..16]).unwrap()).unwrap();
    let mut prefixed_nonce = [0u8; 12];
    prefixed_nonce[4..12].copy_from_slice(&nonce.as_bytes()[16..24]);

    chacha20poly1305::encrypt(subkey, IETFNonce::from_slice(&prefixed_nonce).unwrap(), plaintext, ad, dst_out).unwrap();

    Ok(())
}

/// AEAD XChaCha20Poly1305 decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn decrypt(
    secret_key: SecretKey,
    nonce: Nonce,
    ciphertext_with_tag: &[u8],
    ad: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    let subkey: SecretKey =
        SecretKey::from_slice(&chacha20::hchacha20(secret_key, &nonce.as_bytes()[0..16]).unwrap()).unwrap();
    let mut prefixed_nonce = [0u8; 12];
    prefixed_nonce[4..12].copy_from_slice(&nonce.as_bytes()[16..24]);

    chacha20poly1305::decrypt(subkey, IETFNonce::from_slice(&prefixed_nonce).unwrap(), ciphertext_with_tag, ad, dst_out).unwrap();

    Ok(())
}

#[test]
#[should_panic]
fn test_modified_tag_error() {
    let mut dst_out_ct = [0u8; 80]; // 64 + Poly1305TagLen
    let mut dst_out_pt = [0u8; 64];

    encrypt(
        SecretKey::from_slice(&[0u8; 32]).unwrap(),
        Nonce::from_slice(&[0u8; 24]).unwrap(),
        &[0u8; 64],
        &[0u8; 0],
        &mut dst_out_ct,
    ).unwrap();
    // Modify the tags first byte
    dst_out_ct[65] ^= 1;
    decrypt(
        SecretKey::from_slice(&[0u8; 32]).unwrap(),
        Nonce::from_slice(&[0u8; 24]).unwrap(),
        &dst_out_ct,
        &[0u8; 0],
        &mut dst_out_pt,
    ).unwrap();
}
