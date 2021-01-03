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
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `ad`: Additional data to authenticate (this is not encrypted and can be `None`).
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 16 byte
//!   Poly1305 tag appended to it.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the
//!   `ciphertext_with_tag`/`plaintext` after encryption/decryption.
//!
//! `ad`: "A typical use for these data is to authenticate version numbers,
//! timestamps or monotonically increasing counters in order to discard previous
//! messages and prevent replay attacks." See [libsodium docs](https://download.libsodium.org/doc/secret-key_cryptography/aead#additional-data) for more information.
//!
//! `nonce`: "Counters and LFSRs are both acceptable ways of generating unique
//! nonces, as is encrypting a counter using a block cipher with a 64-bit block
//! size such as DES.  Note that it is not acceptable to use a truncation of a
//! counter encrypted with block ciphers with 128-bit or 256-bit blocks,
//! because such a truncation may repeat after a short time." See [RFC](https://tools.ietf.org/html/rfc8439#section-3)
//! for more information.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext` + [`POLY1305_OUTSIZE`] when calling [`seal()`].
//! - The length of `dst_out` is less than `ciphertext_with_tag` - [`POLY1305_OUTSIZE`] when
//!   calling [`open()`].
//! - The length of `ciphertext_with_tag` is not at least [`POLY1305_OUTSIZE`].
//! - The received tag does not match the calculated tag when  calling [`open()`].
//! - `plaintext.len()` + [`POLY1305_OUTSIZE`] overflows when  calling [`seal()`].
//! - Converting `usize` to `u64` would be a lossy conversion.
//!
//! # Panics:
//! A panic will occur if:
//! - More than `2^32-1 * 64` bytes of data are processed.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen, the security of all data that has been encrypted
//!   with that given key is compromised.
//! - Only a nonce for XChaCha20Poly1305 is big enough to be randomly generated
//!   using a CSPRNG.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//! - The length of the `plaintext` is not hidden, only its contents.
//!
//! # Recommendation:
//! - It is recommended to use [`XChaCha20Poly1305`] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::aead;
//!
//! let secret_key = aead::chacha20poly1305::SecretKey::generate();
//!
//! // WARNING: This nonce is only meant for demonstration and should not
//! // be repeated. Please read the security section.
//! let nonce = aead::chacha20poly1305::Nonce::from([0u8; 12]);
//! let ad = "Additional data".as_bytes();
//! let message = "Data to protect".as_bytes();
//!
//! // Length of the above message is 15 and then we accommodate 16 for the Poly1305
//! // tag.
//!
//! let mut dst_out_ct = [0u8; 15 + 16];
//! let mut dst_out_pt = [0u8; 15];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! aead::chacha20poly1305::seal(&secret_key, &nonce, message, Some(&ad), &mut dst_out_ct)?;
//! // Verify tag, if correct then decrypt and place message in dst_out_pt
//! aead::chacha20poly1305::open(&secret_key, &nonce, &dst_out_ct, Some(&ad), &mut dst_out_pt)?;
//!
//! assert_eq!(dst_out_pt.as_ref(), message.as_ref());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: ../../stream/chacha20/struct.SecretKey.html
//! [`XChaCha20Poly1305`]: ../xchacha20poly1305/index.html
//! [`POLY1305_OUTSIZE`]: ../../mac/poly1305/constant.POLY1305_OUTSIZE.html
//! [`seal()`]: fn.seal.html
//! [`open()`]: fn.open.html
pub use crate::hazardous::stream::chacha20::{Nonce, SecretKey};
use crate::{
    errors::UnknownCryptoError,
    hazardous::{
        mac::poly1305::{OneTimeKey, Poly1305, POLY1305_KEYSIZE, POLY1305_OUTSIZE},
        stream::chacha20::{self, ChaCha20, CHACHA_BLOCKSIZE},
    },
    util,
};
use core::convert::TryInto;
use zeroize::Zeroizing;

/// The initial counter used for encryption and decryption.
const ENC_CTR: u32 = 1;

/// The initial counter used for Poly1305 key generation.
const AUTH_CTR: u32 = 0;

/// Poly1305 key generation using IETF ChaCha20.
pub(crate) fn poly1305_key_gen(
    ctx: &mut ChaCha20,
    tmp_buffer: &mut Zeroizing<[u8; CHACHA_BLOCKSIZE]>,
) -> OneTimeKey {
    ctx.keystream_block(AUTH_CTR, tmp_buffer.as_mut());
    OneTimeKey::from_slice(&tmp_buffer[..POLY1305_KEYSIZE]).unwrap()
}

/// Authenticates the ciphertext, ad and their lengths.
fn process_authentication(
    auth_ctx: &mut Poly1305,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<(), UnknownCryptoError> {
    auth_ctx.process_pad_to_blocksize(ad)?;
    auth_ctx.process_pad_to_blocksize(ciphertext)?;

    let (ad_len, ct_len): (u64, u64) = match (ad.len().try_into(), ciphertext.len().try_into()) {
        (Ok(alen), Ok(clen)) => (alen, clen),
        _ => return Err(UnknownCryptoError),
    };

    let mut tmp_pad = [0u8; 16];
    tmp_pad[0..8].copy_from_slice(&ad_len.to_le_bytes());
    tmp_pad[8..16].copy_from_slice(&ct_len.to_le_bytes());
    auth_ctx.update(tmp_pad.as_ref())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// AEAD ChaCha20Poly1305 encryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn seal(
    secret_key: &SecretKey,
    nonce: &Nonce,
    plaintext: &[u8],
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    match plaintext.len().checked_add(POLY1305_OUTSIZE) {
        Some(out_min_len) => {
            if dst_out.len() < out_min_len {
                return Err(UnknownCryptoError);
            }
        }
        None => return Err(UnknownCryptoError),
    };

    let mut enc_ctx =
        ChaCha20::new(secret_key.unprotected_as_bytes(), nonce.as_ref(), true).unwrap();
    let mut tmp = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);

    let pt_len = plaintext.len();
    if pt_len != 0 {
        dst_out[..pt_len].copy_from_slice(plaintext);
        chacha20::xor_keystream(&mut enc_ctx, ENC_CTR, tmp.as_mut(), &mut dst_out[..pt_len])?;
    }

    let mut auth_ctx = Poly1305::new(&poly1305_key_gen(&mut enc_ctx, &mut tmp));
    let ad = ad.unwrap_or(&[0u8; 0]);
    process_authentication(&mut auth_ctx, ad, &dst_out[..pt_len])?;
    dst_out[pt_len..(pt_len + POLY1305_OUTSIZE)]
        .copy_from_slice(auth_ctx.finalize()?.unprotected_as_bytes());

    Ok(())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// AEAD ChaCha20Poly1305 decryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn open(
    secret_key: &SecretKey,
    nonce: &Nonce,
    ciphertext_with_tag: &[u8],
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if ciphertext_with_tag.len() < POLY1305_OUTSIZE {
        return Err(UnknownCryptoError);
    }
    if dst_out.len() < ciphertext_with_tag.len() - POLY1305_OUTSIZE {
        return Err(UnknownCryptoError);
    }

    let mut dec_ctx =
        ChaCha20::new(secret_key.unprotected_as_bytes(), nonce.as_ref(), true).unwrap();
    let mut tmp = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);
    let mut auth_ctx = Poly1305::new(&poly1305_key_gen(&mut dec_ctx, &mut tmp));

    let ciphertext_len = ciphertext_with_tag.len() - POLY1305_OUTSIZE;
    let ad = ad.unwrap_or(&[0u8; 0]);
    process_authentication(&mut auth_ctx, ad, &ciphertext_with_tag[..ciphertext_len])?;
    util::secure_cmp(
        auth_ctx.finalize()?.unprotected_as_bytes(),
        &ciphertext_with_tag[ciphertext_len..],
    )?;

    if ciphertext_len != 0 {
        dst_out[..ciphertext_len].copy_from_slice(&ciphertext_with_tag[..ciphertext_len]);
        chacha20::xor_keystream(
            &mut dec_ctx,
            ENC_CTR,
            tmp.as_mut(),
            &mut dst_out[..ciphertext_len],
        )?;
    }

    Ok(())
}

// Testing public functions in the module.
#[cfg(test)]
#[cfg(feature = "safe_api")]
mod public {
    use super::*;

    // Proptests. Only executed when NOT testing no_std.
    #[cfg(feature = "safe_api")]
    mod proptest {
        use super::*;
        use crate::test_framework::aead_interface::*;

        quickcheck! {
            fn prop_aead_interface(input: Vec<u8>, ad: Vec<u8>) -> bool {
                let secret_key = SecretKey::generate();
                let nonce = Nonce::from_slice(&[0u8; chacha20::IETF_CHACHA_NONCESIZE]).unwrap();
                AeadTestRunner(seal, open, secret_key, nonce, &input, None, POLY1305_OUTSIZE, &ad);
                test_diff_params_err(&seal, &open, &input, POLY1305_OUTSIZE);
                true
            }
        }
    }
}

// Testing any test vectors that aren't put into library's /tests folder.
#[cfg(test)]
mod test_vectors {
    use super::*;

    #[test]
    fn rfc8439_poly1305_key_gen_1() {
        let key = SecretKey::from_slice(&[0u8; 32]).unwrap();
        let nonce = Nonce::from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7,
        ];

        let mut chacha20_ctx =
            ChaCha20::new(key.unprotected_as_bytes(), nonce.as_ref(), true).unwrap();
        let mut tmp_block = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);

        assert_eq!(
            poly1305_key_gen(&mut chacha20_ctx, &mut tmp_block).unprotected_as_bytes(),
            expected.as_ref()
        );
    }

    #[test]
    fn rfc8439_poly1305_key_gen_2() {
        let key = SecretKey::from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ])
        .unwrap();
        let nonce = Nonce::from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ])
        .unwrap();
        let expected = [
            0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74, 0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9,
            0xe8, 0x76, 0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87, 0xbc, 0x26, 0x66, 0xdd,
            0xe3, 0xfb, 0xb7, 0x39,
        ];

        let mut chacha20_ctx =
            ChaCha20::new(key.unprotected_as_bytes(), nonce.as_ref(), true).unwrap();
        let mut tmp_block = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);

        assert_eq!(
            poly1305_key_gen(&mut chacha20_ctx, &mut tmp_block).unprotected_as_bytes(),
            expected.as_ref()
        );
    }

    #[test]
    fn rfc8439_poly1305_key_gen_3() {
        let key = SecretKey::from_slice(&[
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc,
            0x20, 0x70, 0x75, 0xc0,
        ])
        .unwrap();
        let nonce = Nonce::from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ])
        .unwrap();
        let expected = [
            0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9, 0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29,
            0xf9, 0x4b, 0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb, 0xdd, 0x59, 0xde, 0xaa,
            0xd2, 0x33, 0x10, 0xae,
        ];

        let mut chacha20_ctx =
            ChaCha20::new(key.unprotected_as_bytes(), nonce.as_ref(), true).unwrap();
        let mut tmp_block = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);

        assert_eq!(
            poly1305_key_gen(&mut chacha20_ctx, &mut tmp_block).unprotected_as_bytes(),
            expected.as_ref()
        );
    }
}
