// MIT License

// Copyright (c) 2018-2026 The orion Developers

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
//! - `sk`: The secret key.
//! - `n`: The nonce value.
//! - `ad`: Additional data to authenticate (this is not encrypted and can be [`None`]).
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 16 byte
//!   Poly1305 tag appended to it.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the
//!   `ciphertext_with_tag`/`plaintext` after encryption/decryption.
//! - `bytes`: Bytes that are either encrypted or decrypted.
//! - `tag`: The Poly1305 tag used for authenticity verification when using [`ChaCha20Poly1305::open_inplace()`].
//!
//! `ad`: "A typical use for these data is to authenticate version numbers,
//! timestamps or monotonically increasing counters in order to discard previous
//! messages and prevent replay attacks." See [libsodium docs] for more information.
//!
//! `nonce`: "Counters and LFSRs are both acceptable ways of generating unique
//! nonces, as is encrypting a counter using a block cipher with a 64-bit block
//! size such as DES.  Note that it is not acceptable to use a truncation of a
//! counter encrypted with block ciphers with 128-bit or 256-bit blocks,
//! because such a truncation may repeat after a short time." See [RFC] for more information.
//!
//! `dst_out`: The output buffer may have a capacity greater than the input. If this is the case,
//! only the first input length amount of bytes in `dst_out` are modified, while the rest remain untouched.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext` + [`POLY1305_OUTSIZE`] when calling [`ChaCha20Poly1305::seal()`].
//! - The length of `dst_out` is less than `ciphertext_with_tag` - [`POLY1305_OUTSIZE`] when
//!   calling [`ChaCha20Poly1305::open()`].
//! - The length of `ciphertext_with_tag` is not at least [`POLY1305_OUTSIZE`].
//! - The received tag does not match the calculated tag when  calling [`ChaCha20Poly1305::open()`]/[`ChaCha20Poly1305::open_inplace()`].
//! - `plaintext.len()` + [`POLY1305_OUTSIZE`] overflows when  calling [`ChaCha20Poly1305::seal()`].
//! - Converting [`usize`] to [`u64`] would be a lossy conversion.
//! - `plaintext.len() >` [`P_MAX`]
//! - `ad.len() >` [`A_MAX`]
//! - `ciphertext_with_tag.len() >` [`C_MAX`]
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
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::aead::chacha20poly1305::{SecretKey, Nonce, ChaCha20Poly1305};
//!
//! let sk = SecretKey::generate()?;
//! // WARNING: This nonce is only meant for demonstration and should not
//! // be repeated. Please read the security section.
//! let n = Nonce::from([0u8; 12]);
//! let ad = "Additional data".as_bytes();
//! let message = "Data to protect".as_bytes();
//!
//! // With output buffer:
//!
//! // Length of the above message is 15 and then we accommodate 16 for the Poly1305
//! // tag.
//! let mut dst_out_ct = [0u8; 15 + 16];
//! let mut dst_out_pt = [0u8; 15];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! ChaCha20Poly1305::seal(&sk, &n, message, Some(&ad), &mut dst_out_ct)?;
//! // Verify tag, if correct then decrypt and place message in dst_out_pt
//! ChaCha20Poly1305::open(&sk, &n, &dst_out_ct, Some(&ad), &mut dst_out_pt)?;
//! assert_eq!(dst_out_pt.as_ref(), message.as_ref());
//!
//! // In-place:
//! let mut message: [u8; 15] = *b"Data to protect";
//! let tag = ChaCha20Poly1305::seal_inplace(&sk, &n, Some(&ad), &mut message)?;
//! assert_eq!(&dst_out_ct[..15], &message);
//! ChaCha20Poly1305::open_inplace(&sk, &n, &tag, Some(&ad), &mut message)?;
//! assert_eq!(b"Data to protect", &message);
//!
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: super::stream::chacha20::SecretKey::generate
//! [`XChaCha20Poly1305`]: xchacha20poly1305
//! [`POLY1305_OUTSIZE`]: super::mac::poly1305::POLY1305_OUTSIZE
//! [RFC]: https://tools.ietf.org/html/rfc8439#section-3
//! [libsodium docs]: https://download.libsodium.org/doc/secret-key_cryptography/aead#additional-data
//! [`P_MAX`]: chacha20poly1305::P_MAX
//! [`A_MAX`]: chacha20poly1305::A_MAX
//! [`C_MAX`]: chacha20poly1305::C_MAX
//! [`ChaCha20Poly1305::open()`]: chacha20poly1305::ChaCha20Poly1305::open()
//! [`ChaCha20Poly1305::open_inplace()`]: chacha20poly1305::ChaCha20Poly1305::open_inplace()
//! [`ChaCha20Poly1305::seal()`]: chacha20poly1305::ChaCha20Poly1305::seal()

use crate::hazardous::mac::poly1305::POLY1305_BLOCKSIZE;
pub use crate::hazardous::mac::poly1305::Tag;
pub use crate::hazardous::stream::chacha20::{Nonce, SecretKey};
use crate::util::xor_slices;
use crate::{
    errors::UnknownCryptoError,
    hazardous::{
        mac::poly1305::{OneTimeKey, POLY1305_KEYSIZE, POLY1305_OUTSIZE, Poly1305},
        stream::chacha20::{CHACHA_BLOCKSIZE, ChaCha20},
    },
};
use core::convert::TryInto;

/// The initial counter used for encryption and decryption.
pub(crate) const ENC_CTR: u32 = 1;

/// The initial counter used for Poly1305 key generation.
pub(crate) const AUTH_CTR: u32 = 0;

/// The maximum size of the plaintext (see [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439#section-2.8)).
pub const P_MAX: u64 = (u32::MAX as u64) * 64;

/// The maximum size of the ciphertext (see [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439#section-2.8)).
pub const C_MAX: u64 = P_MAX + (POLY1305_OUTSIZE as u64);

/// The maximum size of the associated data (see [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439#section-2.8)).
pub const A_MAX: u64 = u64::MAX;

#[derive(Debug)]
/// ChaCha20Poly1305 encryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub struct ChaCha20Poly1305 {}

impl ChaCha20Poly1305 {
    fn poly1305_key_gen(ctx: &mut ChaCha20) -> OneTimeKey {
        ctx.set_position(AUTH_CTR);
        ctx.keystream_block();
        debug_assert_eq!(
            ctx.position(),
            ENC_CTR,
            "ctx.keystream_block() did not advance internal counter"
        );

        let mut authsk = OneTimeKey::from([0u8; POLY1305_KEYSIZE]);
        authsk
            .data
            .bytes
            .copy_from_slice(&ctx.keystreamblock[..POLY1305_KEYSIZE]);

        authsk
    }

    /// Poly1305 key generation using IETF ChaCha20.
    pub(crate) fn poly1305_init(ctx: &mut ChaCha20) -> Poly1305 {
        Poly1305::new(&Self::poly1305_key_gen(ctx))
    }

    /// Authenticates the ciphertext, ad and their lengths.
    pub(crate) fn process_authentication(
        auth_ctx: &mut Poly1305,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        let (ad_len, ct_len): (u64, u64) = match (ad.len().try_into(), ciphertext.len().try_into())
        {
            (Ok(alen), Ok(clen)) => (alen, clen),
            _ => return Err(UnknownCryptoError),
        };

        auth_ctx.process_pad_to_blocksize(ad)?;
        auth_ctx.process_pad_to_blocksize(ciphertext)?;

        debug_assert_eq!(size_of::<u64>() * 2, POLY1305_BLOCKSIZE);
        let mut tmp_pad = [0u8; POLY1305_BLOCKSIZE];
        tmp_pad[0..8].copy_from_slice(&ad_len.to_le_bytes());
        tmp_pad[8..16].copy_from_slice(&ct_len.to_le_bytes());
        auth_ctx.update(tmp_pad.as_ref())?;

        Ok(())
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD ChaCha20Poly1305 encryption and authentication. Encrypt `bytes` in-place and return the authentication [`Tag`].
    ///
    /// # SECURITY:
    /// If this returns [`UnknownCryptoError`], then not all `bytes` have been processed.
    /// Take care to zero out the bytes if this contains sensitive information.
    ///
    /// This equates to enryption if `bytes` is the plaintext and decryption if `bytes`
    /// is the ciphertext.
    pub fn seal_inplace(
        sk: &SecretKey,
        n: &Nonce,
        ad: Option<&[u8]>,
        bytes: &mut [u8],
    ) -> Result<Tag, UnknownCryptoError> {
        if u64::try_from(bytes.len()).map_err(|_| UnknownCryptoError)? > P_MAX {
            return Err(UnknownCryptoError);
        }
        let ad = ad.unwrap_or(&[0u8; 0]);
        #[allow(clippy::absurd_extreme_comparisons)]
        if u64::try_from(ad.len()).map_err(|_| UnknownCryptoError)? > A_MAX {
            return Err(UnknownCryptoError);
        }
        let (ad_len, ct_len): (u64, u64) = match (ad.len().try_into(), bytes.len().try_into()) {
            (Ok(alen), Ok(clen)) => (alen, clen),
            _ => return Err(UnknownCryptoError),
        };

        let mut streamctx = ChaCha20::new(sk, n);
        let mut auth_ctx = Self::poly1305_init(&mut streamctx);

        auth_ctx.process_pad_to_blocksize(ad)?;
        debug_assert_eq!(streamctx.position(), ENC_CTR);
        debug_assert_eq!(streamctx.keystream_remaining(), P_MAX);

        let mut parts = bytes.chunks_mut(CHACHA_BLOCKSIZE).peekable();
        while let Some(block) = parts.next() {
            streamctx.keystream_block();
            xor_slices(&streamctx.keystreamblock, block);

            debug_assert!(
                block.len() <= CHACHA_BLOCKSIZE,
                "chunks_mut() violated contract"
            );
            if block.len() == CHACHA_BLOCKSIZE {
                // Given CHACHA_BLOCKSIZE evenly divides POLY1305_BLOCKSIZE
                // we can skip padding-checks here.
                auth_ctx.update(block)?;
            } else {
                auth_ctx.process_pad_to_blocksize(block)?;
                debug_assert!(parts.peek().is_none());
            }

            // The only time we don't want to error on this check
            // is when we have self.streampos == u32::MAX and there's
            // at most CHACHA_BLOCKSIZE amount of bytes to process.
            if parts.peek().is_some() {
                streamctx.next_producible()?;
            }
        }

        debug_assert_eq!(size_of::<u64>() * 2, POLY1305_BLOCKSIZE);
        let mut tmp_pad = [0u8; POLY1305_BLOCKSIZE];
        tmp_pad[0..8].copy_from_slice(&ad_len.to_le_bytes());
        tmp_pad[8..16].copy_from_slice(&ct_len.to_le_bytes());
        auth_ctx.update(tmp_pad.as_ref())?;

        auth_ctx.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD ChaCha20Poly1305 encryption and authentication. Verify authenticity of `tag` and decrypt `bytes` in-place if
    /// successful.
    pub fn open_inplace(
        sk: &SecretKey,
        n: &Nonce,
        tag: &Tag,
        ad: Option<&[u8]>,
        bytes: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if u64::try_from(bytes.len()).map_err(|_| UnknownCryptoError)? > P_MAX {
            return Err(UnknownCryptoError);
        }
        let ad = ad.unwrap_or(&[0u8; 0]);
        #[allow(clippy::absurd_extreme_comparisons)]
        if u64::try_from(ad.len()).map_err(|_| UnknownCryptoError)? > A_MAX {
            return Err(UnknownCryptoError);
        }

        let mut streamctx = ChaCha20::new(sk, n);
        let mut auth_ctx = Self::poly1305_init(&mut streamctx);

        Self::process_authentication(&mut auth_ctx, ad, bytes)?;
        if auth_ctx.finalize()? != *tag {
            return Err(UnknownCryptoError);
        }

        debug_assert_eq!(streamctx.position(), ENC_CTR);
        debug_assert_eq!(streamctx.keystream_remaining(), P_MAX);
        streamctx.xor_keystream_into(bytes)?;

        Ok(())
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD ChaCha20Poly1305 encryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
    pub fn seal(
        sk: &SecretKey,
        n: &Nonce,
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
        match plaintext.len().checked_add(POLY1305_OUTSIZE) {
            Some(out_min_len) => {
                if dst_out.len() < out_min_len {
                    return Err(UnknownCryptoError);
                }
            }
            None => return Err(UnknownCryptoError),
        };
        let (ad_len, ct_len): (u64, u64) = match (ad.len().try_into(), plaintext.len().try_into()) {
            (Ok(alen), Ok(clen)) => (alen, clen),
            _ => return Err(UnknownCryptoError),
        };

        let mut streamctx = ChaCha20::new(sk, n);
        let mut auth_ctx = Self::poly1305_init(&mut streamctx);

        auth_ctx.process_pad_to_blocksize(ad)?;
        debug_assert_eq!(streamctx.position(), ENC_CTR);
        debug_assert_eq!(streamctx.keystream_remaining(), P_MAX);

        let mut p_iter = plaintext.chunks(CHACHA_BLOCKSIZE).peekable();
        let mut c_iter = dst_out[..plaintext.len()]
            .chunks_mut(CHACHA_BLOCKSIZE)
            .peekable();
        while let (Some(p_block), Some(c_block)) = (p_iter.next(), c_iter.next()) {
            debug_assert_eq!(p_block.len(), c_block.len());
            debug_assert_eq!(p_iter.peek().is_some(), c_iter.peek().is_some());
            streamctx.keystream_block();

            c_block.copy_from_slice(p_block);
            xor_slices(&streamctx.keystreamblock, c_block);

            if c_block.len() == CHACHA_BLOCKSIZE {
                auth_ctx.update(c_block)?;
            } else {
                auth_ctx.process_pad_to_blocksize(c_block)?;

                debug_assert!(p_iter.peek().is_none());
                debug_assert!(c_iter.peek().is_none());
            }

            // The only time we don't want to error on this check
            // is when we have self.streampos == u32::MAX and there's
            // at most CHACHA_BLOCKSIZE amount of bytes to process.
            if c_iter.peek().is_some() {
                streamctx.next_producible()?;
            }
        }

        debug_assert_eq!(size_of::<u64>() * 2, POLY1305_BLOCKSIZE);
        let mut tmp_pad = [0u8; POLY1305_BLOCKSIZE];
        tmp_pad[0..8].copy_from_slice(&ad_len.to_le_bytes());
        tmp_pad[8..16].copy_from_slice(&ct_len.to_le_bytes());
        auth_ctx.update(tmp_pad.as_ref())?;

        dst_out[plaintext.len()..(plaintext.len() + POLY1305_OUTSIZE)]
            .copy_from_slice(auth_ctx.finalize()?.unprotected_as_ref());

        Ok(())
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD ChaCha20Poly1305 decryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
    pub fn open(
        sk: &SecretKey,
        n: &Nonce,
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
        if ciphertext_with_tag.len() < POLY1305_OUTSIZE {
            return Err(UnknownCryptoError);
        }
        if dst_out.len() < ciphertext_with_tag.len() - POLY1305_OUTSIZE {
            return Err(UnknownCryptoError);
        }

        let mut streamctx = ChaCha20::new(sk, n);
        let mut auth_ctx = Self::poly1305_init(&mut streamctx);

        let ctlen = ciphertext_with_tag.len() - POLY1305_OUTSIZE;
        Self::process_authentication(&mut auth_ctx, ad, &ciphertext_with_tag[..ctlen])?;
        let tag = Tag::try_from(&ciphertext_with_tag[ctlen..ctlen + POLY1305_OUTSIZE])?;
        if auth_ctx.finalize()? != tag {
            return Err(UnknownCryptoError);
        }

        // NOTE: We could easily use Self::open_inplace() but that would require
        // us to copy entire ciphertext over to dst _BEFORE_ authenticity checks,
        // thus it seems more reliable to keep it equivalent in behavior to open()
        // which doesn't touch the ret-buffer before auth check has passed.
        dst_out[..ctlen].copy_from_slice(&ciphertext_with_tag[..ctlen]);

        debug_assert_eq!(streamctx.position(), ENC_CTR);
        debug_assert_eq!(streamctx.keystream_remaining(), P_MAX);
        streamctx.xor_keystream_into(&mut dst_out[..ctlen])?;

        Ok(())
    }
}

// Testing public functions in the module.
#[cfg(test)]
#[cfg(feature = "safe_api")]
mod public {
    use super::*;
    use crate::{
        hazardous::{
            mac::poly1305::Poly1305Tag,
            stream::chacha20::{CHACHA_KEYSIZE, ChaCha20Key, ChaCha20Nonce, IETF_CHACHA_NONCESIZE},
        },
        test_framework::aead_interface::{AeadTestRunner, TestableAead},
    };

    const ZERO_KEY: [u8; CHACHA_KEYSIZE] = [0u8; CHACHA_KEYSIZE];
    const ZERO_IETF_NONCE: [u8; IETF_CHACHA_NONCESIZE] = [0u8; IETF_CHACHA_NONCESIZE];

    impl TestableAead for ChaCha20Poly1305 {
        type Key = ChaCha20Key;
        type Nonce = ChaCha20Nonce;
        type Tag = Poly1305Tag;

        fn _seal_inplace(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            ad: Option<&[u8]>,
            bytes: &mut [u8],
        ) -> Result<crate::Secret<Self::Tag>, UnknownCryptoError> {
            ChaCha20Poly1305::seal_inplace(sk, n, ad, bytes)
        }

        fn _open_inplace(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            tag: &crate::Secret<Self::Tag>,
            ad: Option<&[u8]>,
            bytes: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            ChaCha20Poly1305::open_inplace(sk, n, tag, ad, bytes)
        }

        fn _seal(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            plaintext: &[u8],
            ad: Option<&[u8]>,
            dst_out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            ChaCha20Poly1305::seal(sk, n, plaintext, ad, dst_out)
        }

        fn _open(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            ciphertext_with_tag: &[u8],
            ad: Option<&[u8]>,
            dst_out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            ChaCha20Poly1305::open(sk, n, ciphertext_with_tag, ad, dst_out)
        }
    }

    #[test]
    fn test_aead_interface() {
        AeadTestRunner::<ChaCha20Poly1305, CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE, POLY1305_OUTSIZE>::run_all_tests(&[213u8; 512]);
    }

    #[test]
    fn test_max_values() {
        let sk = SecretKey::from(ZERO_KEY);
        let nonce = Nonce::from(ZERO_IETF_NONCE);
        let mut ctx = ChaCha20::new(&sk, &nonce);
        ctx.set_position(ENC_CTR);

        assert_eq!(ctx.keystream_remaining(), P_MAX);
        assert_eq!(ctx.keystream_remaining() + POLY1305_OUTSIZE as u64, C_MAX);
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    fn prop_aead_interface(input: Vec<u8>) -> bool {
        AeadTestRunner::<ChaCha20Poly1305, CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE, POLY1305_OUTSIZE>::run_all_tests(&input);
        true
    }
}

// Testing any test vectors that aren't put into library's /tests folder.
#[cfg(test)]
mod test_vectors {
    use super::*;

    #[test]
    fn rfc8439_poly1305_key_gen_1() {
        let key = SecretKey::from([0u8; 32]);
        let nonce = Nonce::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7,
        ];

        let mut chacha20_ctx = ChaCha20::new(&key, &nonce);
        assert_eq!(
            ChaCha20Poly1305::poly1305_key_gen(&mut chacha20_ctx).unprotected_as_ref(),
            expected.as_ref()
        );
    }

    #[test]
    fn rfc8439_poly1305_key_gen_2() {
        let key = SecretKey::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ]);
        let nonce = Nonce::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ]);
        let expected = [
            0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74, 0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9,
            0xe8, 0x76, 0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87, 0xbc, 0x26, 0x66, 0xdd,
            0xe3, 0xfb, 0xb7, 0x39,
        ];

        let mut chacha20_ctx = ChaCha20::new(&key, &nonce);
        assert_eq!(
            ChaCha20Poly1305::poly1305_key_gen(&mut chacha20_ctx).unprotected_as_ref(),
            expected.as_ref()
        );
    }

    #[test]
    fn rfc8439_poly1305_key_gen_3() {
        let key = SecretKey::from([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc,
            0x20, 0x70, 0x75, 0xc0,
        ]);
        let nonce = Nonce::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ]);
        let expected = [
            0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9, 0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29,
            0xf9, 0x4b, 0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb, 0xdd, 0x59, 0xde, 0xaa,
            0xd2, 0x33, 0x10, 0xae,
        ];

        let mut chacha20_ctx = ChaCha20::new(&key, &nonce);
        assert_eq!(
            ChaCha20Poly1305::poly1305_key_gen(&mut chacha20_ctx).unprotected_as_ref(),
            expected.as_ref()
        );
    }
}
