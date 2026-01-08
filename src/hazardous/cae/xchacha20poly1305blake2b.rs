// MIT License

// Copyright (c) 2023-2026 The orion Developers

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

//! # About
//! This provides a fully committing AEAD, using the CTX construction proposed by Chan and Rogaway,
//! in the ["On Committing Authenticated Encryption"] paper. Specifically, CTX is instantiated with BLAKE2b-256.
//!
//! A fully committing AEAD is important if attacks like the [partitioning oracle attack] are a part of the threat model.
//!
//! # Parameters:
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `ad`: Additional data to authenticate (this is not encrypted and can be [`None`]).
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 32 byte
//!   BLAKE2b tag appended to it.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the
//!   `ciphertext_with_tag`/`plaintext` after encryption/decryption.
//!
//! `ad`: "A typical use for these data is to authenticate version numbers,
//! timestamps or monotonically increasing counters in order to discard previous
//! messages and prevent replay attacks." See [libsodium docs] for more information.
//!
//! `dst_out`: The output buffer may have a capacity greater than the input. If this is the case,
//! only the first input length amount of bytes in `dst_out` are modified, while the rest remain untouched.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext` + [`TAG_SIZE`] when calling [`seal()`].
//! - The length of `dst_out` is less than `ciphertext_with_tag` - [`TAG_SIZE`] when
//!   calling [`open()`].
//! - The length of `ciphertext_with_tag` is not at least [`TAG_SIZE`].
//! - The received tag does not match the calculated tag when  calling [`open()`].
//! - `plaintext.len()` + [`TAG_SIZE`] overflows when  calling [`seal()`].
//! - Converting `usize` to `u64` would be a lossy conversion.
//! - `plaintext.len() >` [`P_MAX`]
//! - `ad.len() >` [`A_MAX`]
//! - `ciphertext_with_tag.len() >` [`C_MAX`]
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
//!   using a CSPRNG. [`Nonce::generate()`] can be used for this.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//! - The length of the `plaintext` is not hidden, only its contents.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::cae;
//!
//! let secret_key = cae::xchacha20poly1305blake2b::SecretKey::generate();
//! let nonce = cae::xchacha20poly1305blake2b::Nonce::generate();
//! let ad = "Additional data".as_bytes();
//! let message = "Data to protect".as_bytes();
//!
//! // Length of the above message is 15 and then we accommodate 32 for the BLAKE2b
//! // tag.
//!
//! let mut dst_out_ct = [0u8; 15 + 32];
//! let mut dst_out_pt = [0u8; 15];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! cae::xchacha20poly1305blake2b::seal(&secret_key, &nonce, message, Some(&ad), &mut dst_out_ct)?;
//! // Verify tag, if correct then decrypt and place message in dst_out_pt
//! cae::xchacha20poly1305blake2b::open(&secret_key, &nonce, &dst_out_ct, Some(&ad), &mut dst_out_pt)?;
//!
//! assert_eq!(dst_out_pt.as_ref(), message.as_ref());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: super::stream::chacha20::SecretKey::generate
//! [`Nonce::generate()`]: super::stream::xchacha20::Nonce::generate
//! [`TAG_SIZE`]: xchacha20poly1305blake2b::TAG_SIZE
//! [`seal()`]: xchacha20poly1305blake2b::seal
//! [`open()`]: xchacha20poly1305blake2b::open
//! [RFC]: https://tools.ietf.org/html/rfc8439#section-3
//! [libsodium docs]: https://download.libsodium.org/doc/secret-key_cryptography/aead#additional-data
//! [`P_MAX`]: xchacha20poly1305blake2b::P_MAX
//! [`A_MAX`]: xchacha20poly1305blake2b::A_MAX
//! [`C_MAX`]: xchacha20poly1305blake2b::C_MAX
//! ["On Committing Authenticated Encryption"]: https://eprint.iacr.org/2022/1260
//! [partitioning oracle attack]: https://www.usenix.org/conference/usenixsecurity21/presentation/len

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
