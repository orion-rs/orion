// MIT License

// Copyright (c) 2023 The orion Developers

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

use crate::errors::UnknownCryptoError;
use crate::hazardous::aead;
pub use crate::hazardous::aead::chacha20poly1305::A_MAX;
pub use crate::hazardous::aead::chacha20poly1305::P_MAX;
use crate::hazardous::aead::chacha20poly1305::{poly1305_key_gen, process_authentication, ENC_CTR};
pub use crate::hazardous::cae::chacha20poly1305blake2b::{C_MAX, TAG_SIZE};
use crate::hazardous::hash::blake2::blake2b::Blake2b;
use crate::hazardous::mac::poly1305::{Poly1305, POLY1305_OUTSIZE};
use crate::hazardous::stream::chacha20::{self, ChaCha20, CHACHA_BLOCKSIZE};
use crate::hazardous::stream::xchacha20::subkey_and_nonce;
pub use crate::hazardous::stream::{chacha20::SecretKey, xchacha20::Nonce};
use crate::util;
use zeroize::Zeroizing;

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// CTX XChaCha20Poly1305 with BLAKE2b-256.
pub fn seal(
    secret_key: &SecretKey,
    nonce: &Nonce,
    plaintext: &[u8],
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if u64::try_from(plaintext.len()).map_err(|_| UnknownCryptoError)? > P_MAX {
        return Err(UnknownCryptoError);
    }

    let ad = ad.unwrap_or(&[0u8; 0]);
    #[allow(clippy::absurd_extreme_comparisons)]
    if u64::try_from(ad.len()).map_err(|_| UnknownCryptoError)? > A_MAX {
        return Err(UnknownCryptoError);
    }

    match plaintext.len().checked_add(TAG_SIZE) {
        Some(out_min_len) => {
            if dst_out.len() < out_min_len {
                return Err(UnknownCryptoError);
            }
        }
        None => return Err(UnknownCryptoError),
    };

    let (subkey, ietf_nonce) = subkey_and_nonce(secret_key, nonce);
    aead::chacha20poly1305::seal(
        &subkey,
        &ietf_nonce,
        plaintext,
        Some(ad),
        &mut dst_out[..plaintext.len() + POLY1305_OUTSIZE],
    )?;

    let mut blake2b = Blake2b::new(32)?;
    blake2b.update(secret_key.unprotected_as_bytes())?;
    blake2b.update(nonce.as_ref())?;
    blake2b.update(ad)?;
    blake2b.update(&dst_out[plaintext.len()..plaintext.len() + POLY1305_OUTSIZE])?;
    let tag = blake2b.finalize()?;

    dst_out[plaintext.len()..plaintext.len() + TAG_SIZE].copy_from_slice(tag.as_ref());

    Ok(())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// CTX XChaCha20Poly1305 with BLAKE2b-256.
pub fn open(
    secret_key: &SecretKey,
    nonce: &Nonce,
    ciphertext_with_tag: &[u8],
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if u64::try_from(ciphertext_with_tag.len()).map_err(|_| UnknownCryptoError)? > C_MAX {
        return Err(UnknownCryptoError);
    }
    let ad = ad.unwrap_or(&[0u8; 0]);
    #[allow(clippy::absurd_extreme_comparisons)]
    if u64::try_from(ad.len()).map_err(|_| UnknownCryptoError)? > A_MAX {
        return Err(UnknownCryptoError);
    }
    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(UnknownCryptoError);
    }
    if dst_out.len() < ciphertext_with_tag.len() - TAG_SIZE {
        return Err(UnknownCryptoError);
    }

    let mut blake2b = Blake2b::new(32)?;
    blake2b.update(secret_key.unprotected_as_bytes())?;
    blake2b.update(nonce.as_ref())?;
    blake2b.update(ad)?;

    let (subkey, ietf_nonce) = subkey_and_nonce(secret_key, nonce);
    let mut dec_ctx =
        ChaCha20::new(subkey.unprotected_as_bytes(), ietf_nonce.as_ref(), true).unwrap();
    let mut tmp = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);
    let mut auth_ctx = Poly1305::new(&poly1305_key_gen(&mut dec_ctx, &mut tmp));

    let ciphertext_len = ciphertext_with_tag.len() - TAG_SIZE;
    process_authentication(&mut auth_ctx, ad, &ciphertext_with_tag[..ciphertext_len])?;

    blake2b.update(auth_ctx.finalize()?.unprotected_as_bytes())?;

    util::secure_cmp(
        blake2b.finalize()?.as_ref(),
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
    use crate::test_framework::aead_interface::{test_diff_params_err, AeadTestRunner};

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    fn prop_aead_interface(input: Vec<u8>, ad: Vec<u8>) -> bool {
        let secret_key = SecretKey::generate();
        let nonce = Nonce::generate();
        AeadTestRunner(seal, open, secret_key, nonce, &input, None, TAG_SIZE, &ad);
        test_diff_params_err(&seal, &open, &input, TAG_SIZE);
        true
    }
}
