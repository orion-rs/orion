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
//! - `tag`: The Poly1305 tag used for authenticity verification when using [`XChaCha20Poly1305::open_inplace()`].
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
//! - The length of `dst_out` is less than `plaintext` + [`POLY1305_OUTSIZE`] when calling [`XChaCha20Poly1305::seal()`].
//! - The length of `dst_out` is less than `ciphertext_with_tag` - [`POLY1305_OUTSIZE`] when
//!   calling [`XChaCha20Poly1305::open()`].
//! - The length of `ciphertext_with_tag` is not at least [`POLY1305_OUTSIZE`].
//! - The received tag does not match the calculated tag when  calling [`XChaCha20Poly1305::open()`]/[`XChaCha20Poly1305::open_inplace()`].
//! - `plaintext.len()` + [`POLY1305_OUTSIZE`] overflows when  calling [`XChaCha20Poly1305::seal()`].
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
//!   using a CSPRNG. [`Nonce::generate()`] can be used for this.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//! - The length of the `plaintext` is not hidden, only its contents.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::aead::xchacha20poly1305::{SecretKey, Nonce, XChaCha20Poly1305};
//!
//! let sk = SecretKey::generate()?;
//! let n = Nonce::generate()?;
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
//! XChaCha20Poly1305::seal(&sk, &n, message, Some(&ad), &mut dst_out_ct)?;
//! // Verify tag, if correct then decrypt and place message in dst_out_pt
//! XChaCha20Poly1305::open(&sk, &n, &dst_out_ct, Some(&ad), &mut dst_out_pt)?;
//! assert_eq!(dst_out_pt.as_ref(), message.as_ref());
//!
//! // In-place:
//! let mut message: [u8; 15] = *b"Data to protect";
//! let tag = XChaCha20Poly1305::seal_inplace(&sk, &n, Some(&ad), &mut message)?;
//! assert_eq!(&dst_out_ct[..15], &message);
//! XChaCha20Poly1305::open_inplace(&sk, &n, &tag, Some(&ad), &mut message)?;
//! assert_eq!(b"Data to protect", &message);
//!
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: super::stream::chacha20::SecretKey::generate
//! [`Nonce::generate()`]: super::stream::xchacha20::Nonce::generate
//! [`POLY1305_OUTSIZE`]: super::mac::poly1305::POLY1305_OUTSIZE
//! [libsodium docs]: https://download.libsodium.org/doc/secret-key_cryptography/aead#additional-data
//! [`P_MAX`]: chacha20poly1305::P_MAX
//! [`A_MAX`]: chacha20poly1305::A_MAX
//! [`C_MAX`]: chacha20poly1305::C_MAX
//! [`XChaCha20Poly1305::open()`]: xchacha20poly1305::XChaCha20Poly1305::open()
//! [`XChaCha20Poly1305::open_inplace()`]: xchacha20poly1305::XChaCha20Poly1305::open_inplace()
//! [`XChaCha20Poly1305::seal()`]: xchacha20poly1305::XChaCha20Poly1305::seal()

use crate::errors::UnknownCryptoError;
pub use crate::hazardous::mac::poly1305::Tag;
pub use crate::hazardous::stream::{chacha20::SecretKey, xchacha20::Nonce};
use crate::hazardous::{aead::chacha20poly1305::ChaCha20Poly1305, stream::xchacha20::XChaCha20};

#[derive(Debug)]
/// XChaCha20Poly1305 encryption and authentication as specified in the [draft RFC](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03).
pub struct XChaCha20Poly1305 {}

impl XChaCha20Poly1305 {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD XChaCha20Poly1305 encryption and authentication. Encrypt `bytes` in-place and return the authentication [`Tag`].
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
        let (subkey, ietf_nonce) = XChaCha20::subkey_and_ietf_nonce(sk, n);
        ChaCha20Poly1305::seal_inplace(&subkey, &ietf_nonce, ad, bytes)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD XChaCha20Poly1305 encryption and authentication. Verify authenticity of `tag` and decrypt `bytes` in-place if
    /// successful.
    pub fn open_inplace(
        sk: &SecretKey,
        n: &Nonce,
        tag: &Tag,
        ad: Option<&[u8]>,
        bytes: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let (subkey, ietf_nonce) = XChaCha20::subkey_and_ietf_nonce(sk, n);
        ChaCha20Poly1305::open_inplace(&subkey, &ietf_nonce, tag, ad, bytes)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD XChaCha20Poly1305 encryption and authentication as specified in the [draft RFC](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03).
    pub fn seal(
        sk: &SecretKey,
        n: &Nonce,
        plaintext: &[u8],
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let (subkey, ietf_nonce) = XChaCha20::subkey_and_ietf_nonce(sk, n);
        ChaCha20Poly1305::seal(&subkey, &ietf_nonce, plaintext, ad, dst_out)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// AEAD XChaCha20Poly1305 decryption and authentication as specified in the [draft RFC](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03).
    pub fn open(
        sk: &SecretKey,
        n: &Nonce,
        ciphertext_with_tag: &[u8],
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let (subkey, ietf_nonce) = XChaCha20::subkey_and_ietf_nonce(sk, n);
        ChaCha20Poly1305::open(&subkey, &ietf_nonce, ciphertext_with_tag, ad, dst_out)
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;
    use crate::hazardous::mac::poly1305::{POLY1305_OUTSIZE, Poly1305Tag};
    use crate::hazardous::stream::chacha20::{CHACHA_KEYSIZE, ChaCha20Key};
    use crate::hazardous::stream::xchacha20::{XCHACHA_NONCESIZE, XChaCha20Nonce};
    use crate::test_framework::aead_interface::{AeadTestRunner, TestableAead};

    impl TestableAead for XChaCha20Poly1305 {
        type Key = ChaCha20Key;
        type Nonce = XChaCha20Nonce;
        type Tag = Poly1305Tag;

        fn _seal_inplace(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            ad: Option<&[u8]>,
            bytes: &mut [u8],
        ) -> Result<crate::Secret<Self::Tag>, UnknownCryptoError> {
            XChaCha20Poly1305::seal_inplace(sk, n, ad, bytes)
        }

        fn _open_inplace(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            tag: &crate::Secret<Self::Tag>,
            ad: Option<&[u8]>,
            bytes: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            XChaCha20Poly1305::open_inplace(sk, n, tag, ad, bytes)
        }

        fn _seal(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            plaintext: &[u8],
            ad: Option<&[u8]>,
            dst_out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            XChaCha20Poly1305::seal(sk, n, plaintext, ad, dst_out)
        }

        fn _open(
            sk: &crate::Secret<Self::Key>,
            n: &crate::Public<Self::Nonce>,
            ciphertext_with_tag: &[u8],
            ad: Option<&[u8]>,
            dst_out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            XChaCha20Poly1305::open(sk, n, ciphertext_with_tag, ad, dst_out)
        }
    }

    #[test]
    fn test_aead_interface() {
        AeadTestRunner::<XChaCha20Poly1305, CHACHA_KEYSIZE, XCHACHA_NONCESIZE, POLY1305_OUTSIZE>::run_all_tests(&[213u8; 512]);
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    fn prop_aead_interface(input: Vec<u8>) -> bool {
        AeadTestRunner::<XChaCha20Poly1305, CHACHA_KEYSIZE, XCHACHA_NONCESIZE, POLY1305_OUTSIZE>::run_all_tests(&input);
        true
    }
}
