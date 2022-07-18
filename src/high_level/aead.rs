// MIT License

// Copyright (c) 2020-2022 The orion Developers

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

//! Authenticated secret-key encryption.
//!
//! # Use case:
//! `orion::aead` can be used to encrypt data in a way that detects if the
//! encrypted data has been tampered with before decrypting it.
//!
//! An example of this could be sending messages across networks, where
//! confidentiality and authenticity of these messages is required.
//!
//! # About:
//! - Both one-shot functions and a [`streaming`] API are provided.
//! - The nonce is automatically generated.
//! - Returns a vector where the first 24 bytes are the nonce and the rest is
//!   the authenticated ciphertext with the last 16 bytes being the corresponding Poly1305 tag.
//! - Uses XChaCha20Poly1305 with no additional data.
//! - When using [`seal`] and [`open`] then the separation of tags, nonces and
//!   ciphertext are automatically handled.
//!
//! # Parameters:
//! - `plaintext`:  The data to be encrypted.
//! - `secret_key`: The secret key used to encrypt the `plaintext`.
//! - `ciphertext_with_tag_and_nonce`:  The data to be decrypted with the first
//!   24 bytes being the nonce and the last 16 bytes being the corresponding Poly1305 tag.
//!
//! # Errors:
//! An error will be returned if:
//! - `secret_key` is not 32 bytes.
//! - The `plaintext` is empty.
//! - `ciphertext_with_tag_and_nonce` is less than 41 bytes
//!   ([`XCHACHA_NONCESIZE`] + [`POLY1305_OUTSIZE`] + 1).
//! - The received tag does not match the calculated tag when calling [`open`].
//! - `plaintext.len()` + [`XCHACHA_NONCESIZE`] + [`POLY1305_OUTSIZE`] overflows when calling [`seal`].
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^32-1 * 64 bytes of data are processed.
//! - Failure to generate random bytes securely.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - To securely generate a strong key, use [`SecretKey::default()`].
//! - The length of the `plaintext` is not hidden, only its contents.
//!
//! # Example:
//! ```rust
//! use orion::aead;
//!
//! let secret_key = aead::SecretKey::default();
//! let ciphertext = aead::seal(&secret_key, b"Secret message")?;
//! let decrypted_data = aead::open(&secret_key, &ciphertext)?;
//!
//! assert_eq!(decrypted_data, b"Secret message");
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

use crate::{
    errors::UnknownCryptoError,
    hazardous::{
        aead,
        base::{Context, Generate, Secret, VecData},
        mac::poly1305::POLY1305_OUTSIZE,
        stream::{
            chacha20,
            xchacha20::{Nonce, XCHACHA_NONCESIZE},
        },
    },
};

/// A type to represent the `SecretKey` used in AEAD.
pub type SecretKey = Secret<AeadKey, VecData>;

/// A marker type to declare that this data represents an AEAD secret key.
// TODO: Should this be named something more specific? Like `ChaChaKey`?
pub struct AeadKey;

impl Context for AeadKey {
    const NAME: &'static str = "AeadKey";
    const MIN: usize = 32; // TODO: Is this the right min size?
    const MAX: usize = 1024 * 1024; // TODO: Is there a less arbitrary upper bound than a MB?
}

impl Generate for AeadKey {
    const GEN_SIZE: usize = 32;
}

impl Default for SecretKey {
    fn default() -> Self {
        Self::generate()
    }
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Authenticated encryption using XChaCha20Poly1305.
pub fn seal(secret_key: &SecretKey, plaintext: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
    if plaintext.is_empty() {
        return Err(UnknownCryptoError);
    }

    let out_len = match plaintext
        .len()
        .checked_add(XCHACHA_NONCESIZE + POLY1305_OUTSIZE)
    {
        Some(min_out_len) => min_out_len,
        None => return Err(UnknownCryptoError),
    };

    let mut dst_out = vec![0u8; out_len];
    let nonce = Nonce::generate();
    dst_out[..XCHACHA_NONCESIZE].copy_from_slice(nonce.as_ref());

    aead::xchacha20poly1305::seal(
        &chacha20::SecretKey::from_slice(secret_key.unprotected_as_bytes())?,
        &nonce,
        plaintext,
        None,
        &mut dst_out[XCHACHA_NONCESIZE..],
    )?;

    Ok(dst_out)
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Authenticated decryption using XChaCha20Poly1305.
pub fn open(
    secret_key: &SecretKey,
    ciphertext_with_tag_and_nonce: &[u8],
) -> Result<Vec<u8>, UnknownCryptoError> {
    // Avoid empty ciphertexts
    if ciphertext_with_tag_and_nonce.len() <= (XCHACHA_NONCESIZE + POLY1305_OUTSIZE) {
        return Err(UnknownCryptoError);
    }

    let mut dst_out =
        vec![0u8; ciphertext_with_tag_and_nonce.len() - (XCHACHA_NONCESIZE + POLY1305_OUTSIZE)];

    aead::xchacha20poly1305::open(
        &chacha20::SecretKey::from_slice(secret_key.unprotected_as_bytes())?,
        &Nonce::from_slice(&ciphertext_with_tag_and_nonce[..XCHACHA_NONCESIZE])?,
        &ciphertext_with_tag_and_nonce[XCHACHA_NONCESIZE..],
        None,
        &mut dst_out,
    )?;

    Ok(dst_out)
}

pub mod streaming {
    //! Streaming AEAD based on XChaCha20Poly1305.
    //!
    //! # Use case:
    //!  This can be used to encrypt and authenticate a stream of data. It prevents the
    //!  modification, reordering, dropping or duplication of messages. Nonce management is handled automatically.
    //!
    //!  An example of this could be the encryption of files that are too large to encrypt in one piece.
    //!
    //! # About:
    //! This implementation is based on and compatible with the ["secretstream" API] of libsodium.
    //!
    //! # Parameters:
    //! - `secret_key`: The secret key.
    //! - `nonce`: The nonce value.
    //! - `plaintext`: The data to be encrypted.
    //! - `ciphertext`: The encrypted data with a Poly1305 tag and a [`StreamTag`] indicating its function.
    //! - `tag`: Indicates the type of message. The `tag` is a part of the output when encrypting. It
    //! is encrypted and authenticated.
    //!
    //! # Errors:
    //! An error will be returned if:
    //! - `secret_key` is not 32 bytes.
    //! - The length of `ciphertext` is not at least [`ABYTES`].
    //! - The received mac does not match the calculated mac when decrypting. This can indicate
    //!   a dropped or reordered message within the stream.
    //! - More than 2^32-3 * 64 bytes of data are processed when encrypting/decrypting a single chunk.
    //! - [`ABYTES`] + `plaintext.len()` overflows when encrypting.
    //!
    //! # Panics:
    //! A panic will occur if:
    //! - 64 + (`ciphertext.len()` - [`ABYTES`]) overflows when decrypting.
    //! - Failure to generate random bytes securely.
    //!
    //! # Security:
    //! - It is critical for security that a given nonce is not re-used with a given
    //!   key.
    //! - To securely generate a strong key, use [`SecretKey::generate()`].
    //! - The length of the messages is leaked.
    //! - It is recommended to use `StreamTag::Finish` as tag for the last message. This allows the
    //!   decrypting side to detect if messages at the end of the stream are lost.
    //!
    //! # Example:
    //! ```rust
    //! use orion::aead::streaming::*;
    //! use orion::aead::SecretKey;
    //!
    //! let chunk_size: usize = 128; // The size of the chunks you wish to split the stream into.
    //! let src = [255u8; 4096]; // Some example input stream.
    //! let mut out: Vec<Vec<u8>> = Vec::with_capacity(4096 / 128);
    //!
    //! let secret_key = SecretKey::default();
    //!
    //! // Encryption:
    //! let (mut sealer, nonce) = StreamSealer::new(&secret_key)?;
    //!
    //! for (n_chunk, src_chunk) in src.chunks(chunk_size).enumerate() {
    //!     let encrypted_chunk =
    //!         if src_chunk.len() != chunk_size || n_chunk + 1 == src.len() / chunk_size {
    //!             // We've reached the end of the input source,
    //!             // so we mark it with the Finish tag.
    //!             sealer.seal_chunk(src_chunk, &StreamTag::Finish)?
    //!         } else {
    //!             // Just a normal chunk
    //!             sealer.seal_chunk(src_chunk, &StreamTag::Message)?
    //!         };
    //!     // Save the encrypted chunk somewhere
    //!     out.push(encrypted_chunk);
    //! }
    //!
    //! // Decryption:
    //! let mut opener = StreamOpener::new(&secret_key, &nonce)?;
    //!
    //! for (n_chunk, src_chunk) in out.iter().enumerate() {
    //!     let (_decrypted_chunk, tag) = opener.open_chunk(src_chunk)?;
    //!
    //!     if src_chunk.len() != chunk_size + ABYTES || n_chunk + 1 == out.len() {
    //!         // We've reached the end of the input source,
    //!         // so we check if the last chunk is also set as Finish.
    //!         assert_eq!(tag, StreamTag::Finish, "Stream has been truncated!");
    //!     }
    //! }
    //!
    //! # Ok::<(), orion::errors::UnknownCryptoError>(())
    //! ```
    //! [`ABYTES`]: crate::hazardous::aead::streaming::ABYTES
    //! [`StreamTag`]: crate::hazardous::aead::streaming::StreamTag
    //! [`SecretKey::generate()`]: super::SecretKey::generate
    //! ["secretstream" API]: https://download.libsodium.org/doc/secret-key_cryptography/secretstream

    use super::*;
    pub use crate::hazardous::aead::streaming::Nonce;
    pub use crate::hazardous::aead::streaming::StreamTag;
    pub use crate::hazardous::aead::streaming::ABYTES;

    #[derive(Debug)]
    /// Streaming authenticated encryption.
    pub struct StreamSealer {
        internal_sealer: aead::streaming::StreamXChaCha20Poly1305,
    }

    impl StreamSealer {
        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Initialize a `StreamSealer` struct with a given key.
        pub fn new(secret_key: &SecretKey) -> Result<(Self, Nonce), UnknownCryptoError> {
            let nonce = Nonce::generate();
            let sk = &aead::streaming::SecretKey::from_slice(secret_key.unprotected_as_bytes())?;

            let sealer = Self {
                internal_sealer: aead::streaming::StreamXChaCha20Poly1305::new(sk, &nonce),
            };
            Ok((sealer, nonce))
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Encrypts `plaintext`. The `StreamTag` indicates the type of message.
        pub fn seal_chunk(
            &mut self,
            plaintext: &[u8],
            tag: &StreamTag,
        ) -> Result<Vec<u8>, UnknownCryptoError> {
            let sealed_chunk_len = plaintext.len().checked_add(ABYTES);
            if sealed_chunk_len.is_none() {
                return Err(UnknownCryptoError);
            }

            let mut sealed_chunk = vec![0u8; sealed_chunk_len.unwrap()];
            self.internal_sealer
                .seal_chunk(plaintext, None, &mut sealed_chunk, tag)?;

            Ok(sealed_chunk)
        }
    }

    #[derive(Debug)]
    /// Streaming authenticated decryption.
    pub struct StreamOpener {
        internal_sealer: aead::streaming::StreamXChaCha20Poly1305,
    }

    impl StreamOpener {
        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Initialize a `StreamOpener` struct with a given key and nonce.
        pub fn new(secret_key: &SecretKey, nonce: &Nonce) -> Result<Self, UnknownCryptoError> {
            let sk = &chacha20::SecretKey::from_slice(secret_key.unprotected_as_bytes())?;

            Ok(Self {
                internal_sealer: aead::streaming::StreamXChaCha20Poly1305::new(sk, nonce),
            })
        }
        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Decrypts `ciphertext`. Returns the decrypted data and the `StreamTag` indicating the type of message.
        pub fn open_chunk(
            &mut self,
            ciphertext: &[u8],
        ) -> Result<(Vec<u8>, StreamTag), UnknownCryptoError> {
            if ciphertext.len() < ABYTES {
                return Err(UnknownCryptoError);
            }

            let mut opened_chunk = vec![0u8; ciphertext.len() - ABYTES];
            let tag = self
                .internal_sealer
                .open_chunk(ciphertext, None, &mut opened_chunk)?;

            Ok((opened_chunk, tag))
        }
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    mod test_seal_open {
        use super::*;

        #[test]
        fn test_auth_enc_encryption_decryption() {
            let key = SecretKey::default();
            let plaintext = "Secret message".as_bytes();

            let dst_ciphertext = seal(&key, plaintext).unwrap();
            assert_eq!(dst_ciphertext.len(), plaintext.len() + (24 + 16));
            let dst_plaintext = open(&key, &dst_ciphertext).unwrap();
            assert_eq!(plaintext, &dst_plaintext[..]);
        }

        #[test]
        fn test_auth_enc_plaintext_empty_err() {
            let key = SecretKey::default();
            let plaintext = "".as_bytes();

            assert!(seal(&key, plaintext).is_err());
        }

        #[test]
        fn test_auth_enc_ciphertext_less_than_41_err() {
            let key = SecretKey::default();
            let ciphertext = [0u8; XCHACHA_NONCESIZE + POLY1305_OUTSIZE];

            assert!(open(&key, &ciphertext).is_err());
        }

        #[test]
        fn test_modified_nonce_err() {
            let key = SecretKey::default();
            let plaintext = "Secret message".as_bytes();

            let mut dst_ciphertext = seal(&key, plaintext).unwrap();
            // Modify nonce
            dst_ciphertext[10] ^= 1;
            assert!(open(&key, &dst_ciphertext).is_err());
        }

        #[test]
        fn test_modified_ciphertext_err() {
            let key = SecretKey::default();
            let plaintext = "Secret message".as_bytes();

            let mut dst_ciphertext = seal(&key, plaintext).unwrap();
            // Modify ciphertext
            dst_ciphertext[25] ^= 1;
            assert!(open(&key, &dst_ciphertext).is_err());
        }

        #[test]
        fn test_modified_tag_err() {
            let key = SecretKey::default();
            let plaintext = "Secret message".as_bytes();

            let mut dst_ciphertext = seal(&key, plaintext).unwrap();
            let dst_ciphertext_len = dst_ciphertext.len();
            // Modify tag
            dst_ciphertext[dst_ciphertext_len - 6] ^= 1;
            assert!(open(&key, &dst_ciphertext).is_err());
        }

        #[test]
        fn test_diff_secret_key_err() {
            let key = SecretKey::default();
            let plaintext = "Secret message".as_bytes();

            let dst_ciphertext = seal(&key, plaintext).unwrap();
            let bad_key = SecretKey::default();
            assert!(open(&bad_key, &dst_ciphertext).is_err());
        }

        #[test]
        fn test_secret_length_err() {
            let key = SecretKey::generate_with_size(31).unwrap();
            let plaintext = "Secret message".as_bytes();

            assert!(seal(&key, plaintext).is_err());
            assert!(open(&key, plaintext).is_err());
        }
    }

    mod test_stream_seal_open {
        use super::streaming::*;
        use super::*;

        #[test]
        fn test_auth_enc_encryption_decryption() {
            let key = SecretKey::default();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let plaintext = "Secret message".as_bytes();

            let dst_ciphertext = sealer.seal_chunk(plaintext, &StreamTag::Message).unwrap();
            assert_eq!(dst_ciphertext.len(), plaintext.len() + 17);
            let (dst_plaintext, tag) = opener.open_chunk(&dst_ciphertext).unwrap();
            assert_eq!(plaintext, &dst_plaintext[..]);
            assert_eq!(tag, StreamTag::Message);
        }

        #[test]
        fn test_seal_chunk_plaintext_empty_ok() {
            let key = SecretKey::default();
            let (mut sealer, _) = StreamSealer::new(&key).unwrap();
            let plaintext = "".as_bytes();

            assert!(sealer.seal_chunk(plaintext, &StreamTag::Message).is_ok());
        }

        #[test]
        fn test_open_chunk_less_than_abytes_err() {
            let key = SecretKey::default();
            let ciphertext = [0u8; ABYTES - 1];
            let (_, nonce) = StreamSealer::new(&key).unwrap();
            let mut opener = StreamOpener::new(&key, &nonce).unwrap();

            assert!(opener.open_chunk(&ciphertext).is_err());
        }

        #[test]
        fn test_open_chunk_abytes_exact_ok() {
            let key = SecretKey::default();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let ciphertext = sealer
                .seal_chunk("".as_bytes(), &StreamTag::Message)
                .unwrap();
            let (pt, tag) = opener.open_chunk(&ciphertext).unwrap();

            assert!(pt.is_empty());
            assert_eq!(tag.as_byte(), 0u8);
        }

        #[test]
        fn test_modified_tag_err() {
            let key = SecretKey::default();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let plaintext = "Secret message".as_bytes();

            let mut dst_ciphertext = sealer.seal_chunk(plaintext, &StreamTag::Message).unwrap();
            // Modify tag
            dst_ciphertext[0] ^= 1;
            assert!(opener.open_chunk(&dst_ciphertext).is_err());
        }

        #[test]
        fn test_modified_ciphertext_err() {
            let key = SecretKey::default();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let plaintext = "Secret message".as_bytes();

            let mut dst_ciphertext = sealer.seal_chunk(plaintext, &StreamTag::Message).unwrap();
            // Modify ciphertext
            dst_ciphertext[1] ^= 1;
            assert!(opener.open_chunk(&dst_ciphertext).is_err());
        }

        #[test]
        fn test_modified_mac_err() {
            let key = SecretKey::default();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let plaintext = "Secret message".as_bytes();

            let mut dst_ciphertext = sealer.seal_chunk(plaintext, &StreamTag::Message).unwrap();
            // Modify mac
            let macpos = dst_ciphertext.len() - 1;
            dst_ciphertext[macpos] ^= 1;
            assert!(opener.open_chunk(&dst_ciphertext).is_err());
        }

        #[test]
        fn test_diff_secret_key_err() {
            let key = SecretKey::default();
            let plaintext = "Secret message".as_bytes();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let bad_key = SecretKey::default();
            let mut opener = StreamOpener::new(&bad_key, &nonce).unwrap();

            let dst_ciphertext = sealer.seal_chunk(plaintext, &StreamTag::Message).unwrap();

            assert!(opener.open_chunk(&dst_ciphertext).is_err());
        }

        #[test]
        fn test_secret_length_err() {
            let key = SecretKey::generate_with_size(31).unwrap();
            assert!(StreamSealer::new(&key).is_err());
            assert!(StreamOpener::new(&key, &Nonce::generate()).is_err());
        }

        #[test]
        fn same_input_generates_different_ciphertext() {
            let key = SecretKey::default();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let plaintext = "Secret message 1".as_bytes();
            let cipher1 = sealer.seal_chunk(plaintext, &StreamTag::Message).unwrap();
            let cipher2 = sealer.seal_chunk(plaintext, &StreamTag::Message).unwrap();
            assert_ne!(cipher1, cipher2);

            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let (dec1, tag1) = opener.open_chunk(&cipher1).unwrap();
            let (dec2, tag2) = opener.open_chunk(&cipher2).unwrap();
            assert_eq!(plaintext, &dec1[..]);
            assert_eq!(plaintext, &dec2[..]);
            assert_eq!(tag1, StreamTag::Message);
            assert_eq!(tag2, StreamTag::Message);
        }

        #[test]
        fn same_input_on_same_init_different_ct() {
            // Two sealers initialized that encrypt the same plaintext
            // should produce different ciphertexts because the nonce
            // is randomly generated.
            let key = SecretKey::default();
            let (mut sealer_first, _) = StreamSealer::new(&key).unwrap();
            let (mut sealer_second, _) = StreamSealer::new(&key).unwrap();
            let plaintext = "Secret message 1".as_bytes();

            let cipher1 = sealer_first
                .seal_chunk(plaintext, &StreamTag::Message)
                .unwrap();
            let cipher2 = sealer_second
                .seal_chunk(plaintext, &StreamTag::Message)
                .unwrap();
            assert_ne!(cipher1, cipher2);
        }

        #[test]
        fn test_stream_seal_and_open() {
            let key = SecretKey::default();
            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let plaintext1 = "Secret message 1".as_bytes();
            let plaintext2 = "Secret message 2".as_bytes();
            let plaintext3 = "Secret message 3".as_bytes();
            let cipher1 = sealer.seal_chunk(plaintext1, &StreamTag::Message).unwrap();
            let cipher2 = sealer.seal_chunk(plaintext2, &StreamTag::Finish).unwrap();
            let cipher3 = sealer.seal_chunk(plaintext3, &StreamTag::Message).unwrap();

            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let (dec1, tag1) = opener.open_chunk(&cipher1).unwrap();
            let (dec2, tag2) = opener.open_chunk(&cipher2).unwrap();
            let (dec3, tag3) = opener.open_chunk(&cipher3).unwrap();
            assert_eq!(plaintext1, &dec1[..]);
            assert_eq!(plaintext2, &dec2[..]);
            assert_eq!(plaintext3, &dec3[..]);
            assert_eq!(tag1, StreamTag::Message);
            assert_eq!(tag2, StreamTag::Finish);
            assert_eq!(tag3, StreamTag::Message);
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_stream_seal_open_same_input(input: Vec<u8>) -> bool {
            let key = SecretKey::default();

            let (mut sealer, nonce) = StreamSealer::new(&key).unwrap();
            let ct = sealer.seal_chunk(&input[..], &StreamTag::Message).unwrap();

            let mut opener = StreamOpener::new(&key, &nonce).unwrap();
            let (pt_decrypted, tag) = opener.open_chunk(&ct).unwrap();

            input == pt_decrypted && tag == StreamTag::Message
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        // Sealing input, and then opening should always yield the same input.
        fn prop_seal_open_same_input(input: Vec<u8>) -> bool {
            let pt = if input.is_empty() {
                vec![1u8; 10]
            } else {
                input
            };

            let sk = SecretKey::default();

            let ct = seal(&sk, &pt).unwrap();
            let pt_decrypted = open(&sk, &ct).unwrap();

            pt == pt_decrypted
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        // Sealing input, modifying the tag and then opening should
        // always fail due to authentication.
        fn prop_fail_on_diff_key(input: Vec<u8>) -> bool {
            let pt = if input.is_empty() {
                vec![1u8; 10]
            } else {
                input
            };

            let sk = SecretKey::default();
            let sk2 = SecretKey::default();
            let ct = seal(&sk, &pt).unwrap();

            open(&sk2, &ct).is_err()
        }
    }

    mod test_base {
        use crate::{
            hazardous::base::VecData,
            high_level::aead::{AeadKey, SecretKey},
        };

        fn gen_test_data() -> SecretKey {
            SecretKey::generate_with_size(64).unwrap()
        }

        crate::test_base!(SecretKey, gen_test_data, secret);
        crate::test_generate!(AeadKey, VecData, secret);
    }
}
