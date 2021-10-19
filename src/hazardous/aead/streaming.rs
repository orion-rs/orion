// MIT License

// Copyright (c) 2019-2021 The orion Developers

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

//! # About:
//!
//! This implementation is based on and compatible with the ["secretstream" API] of libsodium.
//!
//! # Parameters:
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `ad`: Additional data to authenticate (this is not encrypted and can be `None`).
//! - `plaintext`: The data to be encrypted.
//! - `ciphertext`: The encrypted data with, a Poly1305 tag and a [`StreamTag`] indicating its function.
//! - `dst_out`: Destination array that will hold the `ciphertext`/`plaintext` after encryption/decryption.
//! - `tag`: Indicates the type of message. The `tag` is a part of the output when encrypting. It
//!   is encrypted and authenticated.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext` + [`ABYTES`] when calling [`seal_chunk()`].
//! - The length of `dst_out` is less than `ciphertext` - [`ABYTES`] when calling [`open_chunk()`].
//! - The length of the `ciphertext` is less than [`ABYTES`].
//! - The received mac does not match the calculated mac when calling [`open_chunk()`]. This can
//!   indicate a dropped or reordered message within the stream.
//! - More than `2^32-3 * 64` bytes of data are processed when sealing/opening a single chunk.
//! - [`ABYTES`] + `plaintext.len()` overflows when encrypting.
//!
//! # Panics:
//! A panic will occur if:
//! - 64 + (`ciphertext.len()` - [`ABYTES`]) overflows [`u64::MAX`] when decrypting.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given key.
//! - The nonce can be randomly generated using a CSPRNG. [`Nonce::generate()`] can be used for this.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//! - The lengths of the messages are not hidden, only their contents.
//! - It is recommended to use [`StreamTag::Finish`] as the tag for the last message. This allows the
//!   decrypting side to detect if messages at the end of the stream are lost.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::aead::streaming::*;
//!
//! let secret_key = SecretKey::generate();
//! let nonce = Nonce::generate();
//! let ad = "Additional data".as_bytes();
//! let message = "Data to protect".as_bytes();
//!
//! // Length of the above message is 15 and then we accommodate 17
//! // for the mac and tag.
//! let mut dst_out_ct = [0u8; 15 + ABYTES];
//! let mut dst_out_pt = [0u8; 15];
//!
//! let mut ctx_enc = StreamXChaCha20Poly1305::new(&secret_key, &nonce);
//!
//! // Encrypt and place tag + ciphertext + mac in dst_out_ct
//! ctx_enc.seal_chunk(message, Some(ad), &mut dst_out_ct, StreamTag::Message)?;
//!
//! let mut ctx_dec = StreamXChaCha20Poly1305::new(&secret_key, &nonce);
//!
//! // Decrypt and save the tag the message was encrypted with.
//! let tag = ctx_dec.open_chunk(&dst_out_ct, Some(ad), &mut dst_out_pt)?;
//!
//! assert_eq!(tag, StreamTag::Message);
//! assert_eq!(dst_out_pt.as_ref(), message);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: super::stream::chacha20::SecretKey::generate
//! [`Nonce::generate()`]: super::stream::xchacha20::Nonce::generate
//! [`StreamTag`]: streaming::StreamTag
//! [`StreamTag::Finish`]: streaming::StreamTag::Finish
//! [`ABYTES`]: streaming::ABYTES
//! [`seal_chunk()`]: streaming::StreamXChaCha20Poly1305::seal_chunk
//! [`open_chunk()`]: streaming::StreamXChaCha20Poly1305::open_chunk
//! ["secretstream" API]: https://download.libsodium.org/doc/secret-key_cryptography/secretstream

use crate::errors::UnknownCryptoError;
use crate::hazardous::aead::chacha20poly1305::poly1305_key_gen;
use crate::hazardous::mac::poly1305::{Poly1305, Tag as Poly1305Tag, POLY1305_OUTSIZE};
pub use crate::hazardous::stream::chacha20::SecretKey;
use crate::hazardous::stream::chacha20::{
    encrypt as chacha20_enc, encrypt_in_place as chacha20_xor_stream, ChaCha20, Nonce as IETFNonce,
    CHACHA_BLOCKSIZE, CHACHA_KEYSIZE, HCHACHA_NONCESIZE, IETF_CHACHA_NONCESIZE,
};
use crate::hazardous::stream::xchacha20::subkey_and_nonce;
pub use crate::hazardous::stream::xchacha20::Nonce;
use core::convert::TryFrom;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy)]
/// Tag that indicates the type of message.
pub enum StreamTag {
    /// A message with no special meaning.
    Message,
    /// Marks that the message is the end of a set of messages. Allows the decrypting site to
    /// start working with this data.
    Push,
    /// Derives a new secret key and forgets the one used for earlier encryption/decryption
    /// operations.
    Rekey,
    /// Indicates the end of a stream. Also does a rekey.
    Finish,
}

impl StreamTag {
    #[inline]
    /// Return the tag as a byte.
    pub fn as_byte(&self) -> u8 {
        match *self {
            StreamTag::Message => 0b0000_0000,
            StreamTag::Push => 0b0000_0001,
            StreamTag::Rekey => 0b0000_0010,
            StreamTag::Finish => 0b0000_0011, /* StreamTag::Push.as_byte() | StreamTag::Rekey.as_bytes() */
        }
    }
}

impl TryFrom<u8> for StreamTag {
    type Error = UnknownCryptoError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0b0000_0000 => Ok(Self::Message),
            0b0000_0001 => Ok(Self::Push),
            0b0000_0010 => Ok(Self::Rekey),
            0b0000_0011 => Ok(Self::Finish),
            _ => Err(UnknownCryptoError),
        }
    }
}

impl PartialEq<StreamTag> for StreamTag {
    fn eq(&self, other: &StreamTag) -> bool {
        (self.as_byte().ct_eq(&other.as_byte())).into()
    }
}

/// The size of the internal counter.
const COUNTERBYTES: usize = 4;
/// The size of the internal nonce.
const INONCEBYTES: usize = 8;
/// The size of a StreamTag.
pub const TAG_SIZE: usize = 1;
/// Size of additional data appended to each message.
pub const ABYTES: usize = POLY1305_OUTSIZE + TAG_SIZE;

/// Padding size that gives the needed bytes to pad `input` to an integral
/// multiple of 16.
fn padding(input: usize) -> usize {
    if input == 0 {
        return 0;
    }

    let rem = input % 16;

    if rem != 0 {
        16 - rem
    } else {
        0
    }
}

/// Streaming XChaCha20Poly1305 state.
pub struct StreamXChaCha20Poly1305 {
    key: SecretKey,
    counter: u32,
    inonce: [u8; INONCEBYTES],
}

impl core::fmt::Debug for StreamXChaCha20Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "StreamXChaCha20Poly1305  {{ key: [***OMITTED***], counter: [***OMITTED***], inonce: [***OMITTED***]",
        )
    }
}

impl StreamXChaCha20Poly1305 {
    /// Return a nonce used with ChaCha20Poly1305 based on the internal counter
    /// and inonce.
    fn get_nonce(&self) -> IETFNonce {
        let mut nonce = [0u8; IETF_CHACHA_NONCESIZE];
        nonce[..COUNTERBYTES].copy_from_slice(&self.counter.to_le_bytes());
        nonce[COUNTERBYTES..].copy_from_slice(&self.inonce);

        IETFNonce::from(nonce)
    }

    /// Generates a Poly1305 tag for a message.
    fn generate_auth_tag(
        &mut self,
        text: &[u8],
        ad: &[u8],
        msglen: usize,
        block: &[u8],
        textpos: usize,
    ) -> Result<Poly1305Tag, UnknownCryptoError> {
        debug_assert!(text.len() >= textpos + msglen);

        let mut chacha20_ctx = ChaCha20::new(
            self.key.unprotected_as_bytes(),
            self.get_nonce().as_ref(),
            true,
        )
        .unwrap();
        let mut tmp_block = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);

        let mut pad = [0u8; 16];
        let mut poly = Poly1305::new(&poly1305_key_gen(&mut chacha20_ctx, &mut tmp_block));

        poly.process_pad_to_blocksize(ad)?;
        poly.update(block)?;
        poly.update(&text[textpos..(textpos + msglen)])?;
        poly.update(&pad[..padding(CHACHA_BLOCKSIZE.wrapping_sub(msglen))])?;
        pad[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
        pad[8..16].copy_from_slice(
            &((CHACHA_BLOCKSIZE as u64)
                .checked_add(msglen as u64)
                .unwrap())
            .to_le_bytes(),
        );
        poly.update(&pad)?;

        poly.finalize()
    }

    /// Update internal inonce and counter. Performs rekey on overflowing counter and
    /// designated tags.
    fn advance_state(
        &mut self,
        mac: &Poly1305Tag,
        tag: &StreamTag,
    ) -> Result<(), UnknownCryptoError> {
        xor_slices!(mac.unprotected_as_bytes()[..INONCEBYTES], self.inonce);
        self.counter = self.counter.wrapping_add(1);
        if bool::from(
            !(tag.as_byte() & StreamTag::Rekey.as_byte()).ct_eq(&0u8) | self.counter.ct_eq(&0u32),
        ) {
            self.rekey()?;
        };

        Ok(())
    }

    /// Initialize a `StreamXChaCha20Poly1305` struct with a given secret key and nonce.
    pub fn new(secret_key: &SecretKey, nonce: &Nonce) -> Self {
        let mut inonce = [0u8; INONCEBYTES];
        inonce.copy_from_slice(&nonce.as_ref()[HCHACHA_NONCESIZE..]);

        Self {
            key: subkey_and_nonce(secret_key, nonce).0,
            counter: 1,
            inonce,
        }
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Derives a new secret key used for encryption and decryption.
    pub fn rekey(&mut self) -> Result<(), UnknownCryptoError> {
        let mut new_key_and_inonce = [0u8; CHACHA_KEYSIZE + INONCEBYTES];
        new_key_and_inonce[..CHACHA_KEYSIZE].copy_from_slice(self.key.unprotected_as_bytes());
        new_key_and_inonce[CHACHA_KEYSIZE..].copy_from_slice(&self.inonce);

        chacha20_xor_stream(&self.key, &self.get_nonce(), 0, &mut new_key_and_inonce)?;

        self.key = SecretKey::from_slice(&new_key_and_inonce[..CHACHA_KEYSIZE]).unwrap();
        self.inonce
            .copy_from_slice(&new_key_and_inonce[CHACHA_KEYSIZE..]);
        self.counter = 1;
        new_key_and_inonce.zeroize();

        Ok(())
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Encrypt and authenticate a single message and tag.
    pub fn seal_chunk(
        &mut self,
        plaintext: &[u8],
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
        tag: StreamTag,
    ) -> Result<(), UnknownCryptoError> {
        let msglen = plaintext.len();
        match ABYTES.checked_add(msglen) {
            Some(out_min_len) => {
                if dst_out.len() < out_min_len {
                    return Err(UnknownCryptoError);
                }
            }
            None => return Err(UnknownCryptoError),
        };

        let mut block = [0u8; CHACHA_BLOCKSIZE];
        let ad = ad.unwrap_or(&[0u8; 0]);

        let macpos = TAG_SIZE + msglen;
        let nonce = self.get_nonce();

        block[0] = tag.as_byte();
        chacha20_xor_stream(&self.key, &nonce, 1, &mut block)?;
        dst_out[0] = block[0];

        if msglen != 0 {
            chacha20_enc(&self.key, &nonce, 2, plaintext, &mut dst_out[TAG_SIZE..])?;
        }

        let mac = self.generate_auth_tag(dst_out, ad, msglen, &block, TAG_SIZE)?;
        dst_out[macpos..(macpos + POLY1305_OUTSIZE)].copy_from_slice(mac.unprotected_as_bytes());

        self.advance_state(&mac, &tag)
    }

    #[allow(clippy::range_plus_one)]
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Authenticate and decrypt a single message and tag.
    pub fn open_chunk(
        &mut self,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<StreamTag, UnknownCryptoError> {
        if ciphertext.len() < ABYTES {
            return Err(UnknownCryptoError);
        }

        let msglen = ciphertext.len() - ABYTES;
        if dst_out.len() < msglen {
            return Err(UnknownCryptoError);
        }

        let mut block = [0u8; CHACHA_BLOCKSIZE];
        let ad = ad.unwrap_or(&[0u8; 0]);

        let macpos = TAG_SIZE + msglen;
        let nonce = self.get_nonce();

        block[0] = ciphertext[0];
        chacha20_xor_stream(&self.key, &nonce, 1, &mut block)?;
        let tag = StreamTag::try_from(block[0])?;
        block[0] = ciphertext[0];
        let mac = self.generate_auth_tag(ciphertext, ad, msglen, &block, TAG_SIZE)?;
        if !(mac == &ciphertext[macpos..macpos + mac.len()]) {
            return Err(UnknownCryptoError);
        }
        if msglen != 0 {
            chacha20_enc(
                &self.key,
                &nonce,
                2,
                &ciphertext[TAG_SIZE..(TAG_SIZE + msglen)],
                dst_out,
            )?;
        }
        self.advance_state(&mac, &tag)?;

        Ok(tag)
    }
}

#[cfg(test)]
mod public {
    #[cfg(feature = "safe_api")]
    use super::*;

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let secret_key = SecretKey::generate();
        let nonce = Nonce::generate();
        let initial_state = StreamXChaCha20Poly1305::new(&secret_key, &nonce);
        let debug = format!("{:?}", initial_state);
        let expected = "StreamXChaCha20Poly1305  { key: [***OMITTED***], counter: [***OMITTED***], inonce: [***OMITTED***]";
        assert_eq!(debug, expected);
    }

    #[cfg(feature = "safe_api")]
    mod proptest {
        use crate::errors::UnknownCryptoError;
        use crate::hazardous::aead::streaming::{
            Nonce, SecretKey, StreamTag, StreamXChaCha20Poly1305, ABYTES,
        };
        use crate::test_framework::aead_interface::*;
        use core::convert::TryFrom;

        fn seal(
            sk: &SecretKey,
            nonce: &Nonce,
            input: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            let mut state = StreamXChaCha20Poly1305::new(sk, nonce);
            state.seal_chunk(input, ad, output, StreamTag::Message)
        }

        fn open(
            sk: &SecretKey,
            nonce: &Nonce,
            input: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            let mut state = StreamXChaCha20Poly1305::new(sk, nonce);
            state.open_chunk(input, ad, output)?;

            Ok(())
        }

        #[quickcheck]
        fn prop_aead_interface(input: Vec<u8>, ad: Vec<u8>) -> bool {
            let secret_key = SecretKey::generate();
            let nonce = Nonce::generate();
            AeadTestRunner(seal, open, secret_key, nonce, &input, None, ABYTES, &ad);

            true
        }

        #[quickcheck]
        fn prop_same_input_twice_diff_output(input: Vec<u8>, ad: Vec<u8>) -> bool {
            let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::generate(), &Nonce::generate());

            let mut ct1 = vec![0u8; input.len() + ABYTES];
            let mut ct2 = ct1.clone();

            ctx.seal_chunk(&input, Some(&ad), &mut ct1, StreamTag::Message)
                .unwrap();
            ctx.seal_chunk(&input, Some(&ad), &mut ct2, StreamTag::Message)
                .unwrap();

            ct1 != ct2
        }

        #[quickcheck]
        fn prop_tag(byte: u8) -> bool {
            match byte {
                0u8 => StreamTag::try_from(byte).unwrap() == StreamTag::Message,
                1u8 => StreamTag::try_from(byte).unwrap() == StreamTag::Push,
                2u8 => StreamTag::try_from(byte).unwrap() == StreamTag::Rekey,
                3u8 => StreamTag::try_from(byte).unwrap() == StreamTag::Finish,
                _ => StreamTag::try_from(byte).is_err(),
            }
        }
    }
}

#[cfg(test)]
mod private {
    use super::*;

    mod test_padding {
        use super::*;
        #[test]
        fn test_length_padding() {
            assert_eq!(padding(0), 0);
            assert_eq!(padding(1), 15);
            assert_eq!(padding(2), 14);
            assert_eq!(padding(3), 13);
            assert_eq!(padding(4), 12);
            assert_eq!(padding(5), 11);
            assert_eq!(padding(6), 10);
            assert_eq!(padding(7), 9);
            assert_eq!(padding(8), 8);
            assert_eq!(padding(9), 7);
            assert_eq!(padding(10), 6);
            assert_eq!(padding(11), 5);
            assert_eq!(padding(12), 4);
            assert_eq!(padding(13), 3);
            assert_eq!(padding(14), 2);
            assert_eq!(padding(15), 1);
            assert_eq!(padding(16), 0);
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        // The usize that padding() returns should always
        // be what remains to make input a multiple of 16 in length.
        fn prop_padding_result(input: usize) -> bool {
            let rem = padding(input);

            // NOTE: It is possible to have an input size that will
            // have padding() return a remainder that cannot be added
            // to the original input size without overflowing its usize (tested on 64-bit).
            // This is okay, because nothing is added to the returned value of padding()
            // in generate_auth_tag. It's only ever added in this test. The remainder is still
            // valid regardless, which is also "proven" by the test below.
            // So to test the below assumption, we can only ever do so if it doesn't overflow,
            // hence the needed check.
            //
            // See also below test test_inputsize_79().
            //
            // (Trigger here with: size = 18446744073709551601)
            // (Trigger seal_chunk/open_chunk with input of size 79 (check usage of wrapping_sub))

            match input.checked_add(rem) {
                Some(res) => res % 16 == 0,
                None => true, // The case we cannot test
            }
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        // padding() should never return a usize above 15.
        // The usize must always be in range of 0..=15.
        fn prop_result_never_above_15(input: usize) -> bool {
            padding(input) < 16
        }
    }

    #[test]
    fn test_inputsize_79() {
        // Generated with libsodium
        let sk = [
            49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8, 101u8,
            102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8, 113u8,
            114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
        ];
        let nonce = [
            97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
            97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let input: [u8; 79] = [
            98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8,
            101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8,
            101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8,
            102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8,
            98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8,
            101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8, 101u8, 102u8, 98u8, 101u8,
            0u8,
        ];
        let output: [u8; 96] = [
            252u8, 178u8, 0u8, 210u8, 9u8, 149u8, 109u8, 242u8, 161u8, 71u8, 231u8, 3u8, 175u8,
            17u8, 24u8, 148u8, 40u8, 118u8, 80u8, 107u8, 96u8, 105u8, 191u8, 34u8, 86u8, 101u8,
            33u8, 53u8, 116u8, 51u8, 220u8, 199u8, 26u8, 140u8, 80u8, 251u8, 81u8, 125u8, 160u8,
            186u8, 197u8, 26u8, 72u8, 217u8, 22u8, 205u8, 150u8, 103u8, 233u8, 204u8, 79u8, 59u8,
            137u8, 18u8, 93u8, 25u8, 189u8, 131u8, 137u8, 231u8, 123u8, 56u8, 186u8, 215u8, 33u8,
            41u8, 241u8, 146u8, 248u8, 44u8, 253u8, 253u8, 177u8, 115u8, 51u8, 23u8, 166u8, 64u8,
            6u8, 213u8, 174u8, 254u8, 55u8, 101u8, 185u8, 178u8, 89u8, 121u8, 175u8, 221u8, 174u8,
            75u8, 188u8, 65u8, 41u8, 75u8,
        ];

        let secret_key = SecretKey::from_slice(&sk).unwrap();
        let nonce = Nonce::from_slice(&nonce).unwrap();

        let mut state = StreamXChaCha20Poly1305::new(&secret_key, &nonce);
        let mut dst_out = [0u8; 96];
        state
            .seal_chunk(&input, None, &mut dst_out, StreamTag::Message)
            .unwrap();
        assert_eq!(dst_out.as_ref(), output.as_ref());

        state = StreamXChaCha20Poly1305::new(&secret_key, &nonce);
        let mut dst_out_pt = [0u8; 79];
        state.open_chunk(&output, None, &mut dst_out_pt).unwrap();
        assert_eq!(dst_out_pt.as_ref(), input.as_ref());
    }

    // Test values were generated using libsodium. See /tests/test_generation/

    const KEY: [u8; 32] = [
        49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8, 101u8,
        102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8, 113u8, 114u8,
        115u8, 116u8, 117u8, 118u8, 0u8,
    ];
    const NONCE: [u8; 24] = [
        97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8,
        98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
    ];

    const DEFAULT_MSG: [u8; 51] = [
        68u8, 101u8, 102u8, 97u8, 117u8, 108u8, 116u8, 32u8, 109u8, 101u8, 115u8, 115u8, 97u8,
        103u8, 101u8, 32u8, 116u8, 111u8, 32u8, 116u8, 101u8, 115u8, 116u8, 32u8, 115u8, 116u8,
        114u8, 101u8, 97u8, 109u8, 105u8, 110u8, 103u8, 32u8, 65u8, 69u8, 65u8, 68u8, 32u8, 101u8,
        110u8, 99u8, 114u8, 121u8, 112u8, 116u8, 105u8, 111u8, 110u8, 46u8, 0u8,
    ];

    #[test]
    fn test_tag() {
        assert_eq!(StreamTag::Message.as_byte(), 0u8);
        assert_eq!(StreamTag::Push.as_byte(), 1u8);
        assert_eq!(StreamTag::Rekey.as_byte(), 2u8);
        assert_eq!(StreamTag::Finish.as_byte(), 3u8);
        assert!(StreamTag::try_from(4u8).is_err());
    }

    #[test]
    fn test_seal_open_with_explicit_rekey() {
        // Encrypt stream
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert_eq!(
            s.key,
            [
                23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
                116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
                219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
            ]
            .as_ref()
        );
        assert_eq!(
            s.get_nonce(),
            [1u8, 0u8, 0u8, 0u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,].as_ref()
        );

        // 1st StreamTag::Message
        let plaintext1: [u8; 6] = [116u8, 101u8, 115u8, 116u8, 49u8, 0u8];
        let mut out1 = [0u8; 6 + ABYTES];
        s.seal_chunk(&plaintext1, None, &mut out1, StreamTag::Message)
            .unwrap();
        assert_eq!(
            s.key,
            [
                23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
                116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
                219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
            ]
            .as_ref()
        );
        assert_eq!(
            s.get_nonce(),
            [2u8, 0u8, 0u8, 0u8, 88u8, 186u8, 23u8, 231u8, 10u8, 253u8, 79u8, 71u8,].as_ref()
        );
        assert_eq!(
            out1,
            [
                252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8,
                156u8, 45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
            ]
        );

        // 2nd StreamTag::Message
        let plaintext2: [u8; 20] = [
            116u8, 104u8, 105u8, 115u8, 32u8, 105u8, 115u8, 32u8, 108u8, 111u8, 110u8, 103u8,
            101u8, 114u8, 32u8, 116u8, 101u8, 120u8, 116u8, 0u8,
        ];
        let mut out2 = [0u8; 20 + ABYTES];
        s.seal_chunk(&plaintext2, None, &mut out2, StreamTag::Message)
            .unwrap();
        assert_eq!(
            s.key,
            [
                23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
                116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
                219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
            ]
            .as_ref()
        );
        assert_eq!(
            s.get_nonce(),
            [3u8, 0u8, 0u8, 0u8, 73u8, 199u8, 255u8, 159u8, 213u8, 205u8, 201u8, 51u8,].as_ref()
        );
        assert_eq!(
            out2.as_ref(),
            [
                243u8, 52u8, 124u8, 173u8, 133u8, 44u8, 99u8, 244u8, 250u8, 89u8, 101u8, 142u8,
                59u8, 49u8, 221u8, 52u8, 176u8, 214u8, 13u8, 247u8, 86u8, 17u8, 125u8, 232u8,
                120u8, 223u8, 48u8, 134u8, 116u8, 8u8, 207u8, 180u8, 241u8, 76u8, 26u8, 33u8,
                207u8,
            ]
            .as_ref()
        );

        // 3rd StreamTag::Message
        let plaintext3: [u8; 2] = [49u8, 0u8];
        let mut out3 = [0u8; 2 + ABYTES];
        s.seal_chunk(&plaintext3, None, &mut out3, StreamTag::Message)
            .unwrap();
        assert_eq!(
            s.key,
            [
                23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
                116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
                219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
            ]
            .as_ref()
        );
        assert_eq!(
            s.get_nonce(),
            [4u8, 0u8, 0u8, 0u8, 229u8, 134u8, 216u8, 143u8, 117u8, 43u8, 216u8, 142u8,].as_ref()
        );
        assert_eq!(
            out3.as_ref(),
            [
                237u8, 198u8, 240u8, 172u8, 65u8, 39u8, 16u8, 160u8, 230u8, 17u8, 189u8, 54u8,
                93u8, 173u8, 243u8, 103u8, 185u8, 53u8, 219u8,
            ]
            .as_ref()
        );

        // Explicit rekey
        s.rekey().unwrap();
        assert_eq!(
            s.key,
            [
                55u8, 213u8, 132u8, 57u8, 116u8, 28u8, 19u8, 214u8, 59u8, 159u8, 188u8, 185u8,
                201u8, 153u8, 70u8, 17u8, 149u8, 199u8, 55u8, 34u8, 164u8, 54u8, 200u8, 241u8,
                157u8, 71u8, 218u8, 62u8, 37u8, 37u8, 8u8, 126u8,
            ]
            .as_ref()
        );
        assert_eq!(
            s.get_nonce(),
            [1u8, 0u8, 0u8, 0u8, 250u8, 25u8, 191u8, 166u8, 103u8, 98u8, 187u8, 196u8,].as_ref()
        );

        // 4th StreamTag::Message
        let plaintext4: [u8; 23] = [
            102u8, 105u8, 114u8, 115u8, 116u8, 32u8, 116u8, 101u8, 120u8, 116u8, 32u8, 97u8, 102u8,
            116u8, 101u8, 114u8, 32u8, 114u8, 101u8, 107u8, 101u8, 121u8, 0u8,
        ];
        let mut out4 = [0u8; 23 + ABYTES];
        s.seal_chunk(&plaintext4, None, &mut out4, StreamTag::Message)
            .unwrap();
        assert_eq!(
            s.key,
            [
                55u8, 213u8, 132u8, 57u8, 116u8, 28u8, 19u8, 214u8, 59u8, 159u8, 188u8, 185u8,
                201u8, 153u8, 70u8, 17u8, 149u8, 199u8, 55u8, 34u8, 164u8, 54u8, 200u8, 241u8,
                157u8, 71u8, 218u8, 62u8, 37u8, 37u8, 8u8, 126u8,
            ]
            .as_ref()
        );
        assert_eq!(
            s.get_nonce(),
            [2u8, 0u8, 0u8, 0u8, 70u8, 193u8, 51u8, 16u8, 173u8, 151u8, 68u8, 48u8,].as_ref()
        );
        assert_eq!(
            out4.as_ref(),
            [
                210u8, 9u8, 37u8, 11u8, 182u8, 190u8, 88u8, 175u8, 0u8, 12u8, 125u8, 154u8, 63u8,
                104u8, 166u8, 255u8, 231u8, 12u8, 233u8, 57u8, 206u8, 99u8, 82u8, 23u8, 188u8,
                216u8, 140u8, 182u8, 202u8, 245u8, 255u8, 244u8, 104u8, 89u8, 216u8, 168u8, 68u8,
                130u8, 12u8, 80u8,
            ]
            .as_ref()
        );

        // 5th StreamTag::Message
        let plaintext5: [u8; 36] = [
            116u8, 104u8, 105u8, 115u8, 32u8, 105u8, 115u8, 32u8, 116u8, 104u8, 101u8, 32u8, 115u8,
            101u8, 99u8, 111u8, 110u8, 100u8, 32u8, 116u8, 101u8, 120u8, 116u8, 32u8, 97u8, 102u8,
            116u8, 101u8, 114u8, 32u8, 114u8, 101u8, 107u8, 101u8, 121u8, 0u8,
        ];
        let mut out5 = [0u8; 36 + ABYTES];
        s.seal_chunk(&plaintext5, None, &mut out5, StreamTag::Message)
            .unwrap();
        assert_eq!(
            s.key,
            [
                55u8, 213u8, 132u8, 57u8, 116u8, 28u8, 19u8, 214u8, 59u8, 159u8, 188u8, 185u8,
                201u8, 153u8, 70u8, 17u8, 149u8, 199u8, 55u8, 34u8, 164u8, 54u8, 200u8, 241u8,
                157u8, 71u8, 218u8, 62u8, 37u8, 37u8, 8u8, 126u8,
            ]
            .as_ref()
        );
        assert_eq!(
            s.get_nonce(),
            [3u8, 0u8, 0u8, 0u8, 119u8, 231u8, 54u8, 137u8, 64u8, 159u8, 87u8, 77u8,].as_ref()
        );
        assert_eq!(
            out5.as_ref(),
            [
                122u8, 17u8, 56u8, 176u8, 124u8, 172u8, 219u8, 248u8, 0u8, 37u8, 184u8, 242u8,
                65u8, 248u8, 69u8, 242u8, 158u8, 119u8, 20u8, 17u8, 225u8, 10u8, 107u8, 240u8,
                210u8, 134u8, 6u8, 182u8, 91u8, 243u8, 243u8, 20u8, 30u8, 205u8, 232u8, 167u8,
                247u8, 49u8, 38u8, 5u8, 153u8, 237u8, 8u8, 19u8, 125u8, 226u8, 190u8, 189u8, 167u8,
                33u8, 189u8, 74u8, 189u8,
            ]
            .as_ref()
        );

        // Decrypt stream
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));

        let mut plain_out1 = [0u8; 6];
        assert_eq!(
            s.open_chunk(&out1, None, &mut plain_out1).unwrap(),
            StreamTag::Message
        );
        assert_eq!(plain_out1.as_ref(), plaintext1.as_ref());

        let mut plain_out2 = [0u8; 20];
        assert_eq!(
            s.open_chunk(&out2, None, &mut plain_out2).unwrap(),
            StreamTag::Message
        );
        assert_eq!(plain_out2.as_ref(), plaintext2.as_ref());

        let mut plain_out3 = [0u8; 2];
        assert_eq!(
            s.open_chunk(&out3, None, &mut plain_out3).unwrap(),
            StreamTag::Message
        );
        assert_eq!(plain_out3.as_ref(), plaintext3.as_ref());

        s.rekey().unwrap();

        let mut plain_out4 = [0u8; 23];
        assert_eq!(
            s.open_chunk(&out4, None, &mut plain_out4).unwrap(),
            StreamTag::Message
        );
        assert_eq!(plain_out4.as_ref(), plaintext4.as_ref());

        let mut plain_out5 = [0u8; 36];
        assert_eq!(
            s.open_chunk(&out5, None, &mut plain_out5).unwrap(),
            StreamTag::Message
        );
        assert_eq!(plain_out5.as_ref(), plaintext5.as_ref());
    }

    #[test]
    fn test_reorder_or_drop_msg() {
        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let plaintext1 = [116u8, 101u8, 115u8, 116u8, 49u8, 0u8];
        let plaintext2 = [
            116u8, 104u8, 105u8, 115u8, 32u8, 105u8, 115u8, 32u8, 108u8, 111u8, 110u8, 103u8,
            101u8, 114u8, 32u8, 116u8, 101u8, 120u8, 116u8, 0u8,
        ];
        let cipher1 = [
            252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
            45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
        ];
        let cipher2 = [
            243u8, 52u8, 124u8, 173u8, 133u8, 44u8, 99u8, 244u8, 250u8, 89u8, 101u8, 142u8, 59u8,
            49u8, 221u8, 52u8, 176u8, 214u8, 13u8, 247u8, 86u8, 17u8, 125u8, 232u8, 120u8, 223u8,
            48u8, 134u8, 116u8, 8u8, 207u8, 180u8, 241u8, 76u8, 26u8, 33u8, 207u8,
        ];

        let cipher3 = [
            237u8, 198u8, 240u8, 172u8, 65u8, 39u8, 16u8, 160u8, 230u8, 17u8, 189u8, 54u8, 93u8,
            173u8, 243u8, 103u8, 185u8, 53u8, 219u8,
        ];
        let mut plain_out1 = [0u8; 23 - ABYTES];
        assert_eq!(
            ctx.open_chunk(&cipher1, None, &mut plain_out1).unwrap(),
            StreamTag::Message
        );
        assert_eq!(&plain_out1, &plaintext1);
        // Out of order decryption happens here
        let mut plain_out3 = [0u8; 19 - ABYTES];
        assert!(ctx.open_chunk(&cipher3, None, &mut plain_out3).is_err());

        let mut plain_out2 = [0u8; 37 - ABYTES];
        assert_eq!(
            ctx.open_chunk(&cipher2, None, &mut plain_out2).unwrap(),
            StreamTag::Message
        );
        assert_eq!(&plain_out2, &plaintext2);
    }

    #[test]
    fn test_err_on_diff_tag() {
        // Crate 4 different sealed chunks, sealed with the same input except for
        // the StreamTag.
        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let mut dst_out_msg = [0u8; 51 + ABYTES];
        ctx.seal_chunk(
            DEFAULT_MSG.as_ref(),
            None,
            &mut dst_out_msg,
            StreamTag::Message,
        )
        .unwrap();

        ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let mut dst_out_push = [0u8; 51 + ABYTES];
        ctx.seal_chunk(
            DEFAULT_MSG.as_ref(),
            None,
            &mut dst_out_push,
            StreamTag::Push,
        )
        .unwrap();

        ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let mut dst_out_rekey = [0u8; 51 + ABYTES];
        ctx.seal_chunk(
            DEFAULT_MSG.as_ref(),
            None,
            &mut dst_out_rekey,
            StreamTag::Rekey,
        )
        .unwrap();

        ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let mut dst_out_finish = [0u8; 51 + ABYTES];
        ctx.seal_chunk(
            DEFAULT_MSG.as_ref(),
            None,
            &mut dst_out_finish,
            StreamTag::Finish,
        )
        .unwrap();

        // Swap the StreamTags, which should decrypt successfully but fail authentication as
        // it does not match the Poly1305 Tag calculated.
        let mut dst_out_pt = [0u8; 51];

        ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert!(ctx.open_chunk(&dst_out_msg, None, &mut dst_out_pt).is_ok());

        dst_out_msg[0] = dst_out_push[0];
        ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert!(ctx.open_chunk(&dst_out_msg, None, &mut dst_out_pt).is_err());

        dst_out_msg[0] = dst_out_rekey[0];
        ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert!(ctx.open_chunk(&dst_out_msg, None, &mut dst_out_pt).is_err());

        dst_out_msg[0] = dst_out_finish[0];
        ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert!(ctx.open_chunk(&dst_out_msg, None, &mut dst_out_pt).is_err());
    }

    #[test]
    fn test_err_on_modified_message_tag() {
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let mut cipher1: [u8; 23] = [
            252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
            45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
        ];
        let mut plain_out1 = [0u8; 23 - ABYTES];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_ok());

        // Reset state
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        // Change tag to Push plaintext. Originally was Message and encrypted.
        cipher1[0] = StreamTag::Push.as_byte();
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_err());
    }

    #[test]
    fn test_err_on_diff_secret_key() {
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from(NONCE));
        let cipher1: [u8; 23] = [
            252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
            45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
        ];
        let mut plain_out1 = [0u8; 23 - ABYTES];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_err());
    }

    #[test]
    fn test_err_on_diff_nonce() {
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from([0u8; 24]));
        let cipher1: [u8; 23] = [
            252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
            45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
        ];
        let mut plain_out1 = [0u8; 23 - ABYTES];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_err());
    }

    #[test]
    fn test_err_on_modified_mac() {
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let mut cipher1: [u8; 23] = [
            252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
            45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
        ];
        let mut plain_out1 = [0u8; 23 - ABYTES];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_ok());

        // Reset state
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        // Change MAC
        let macpos = cipher1.len() - 1;
        cipher1[macpos] = 0b1010_1010 | cipher1[macpos];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_err());
    }

    #[test]
    fn test_err_on_modified_cipher() {
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        let mut cipher1: [u8; 23] = [
            252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
            45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
        ];
        let mut plain_out1 = [0u8; 23 - ABYTES];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_ok());

        // Reset state
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        // Change something in the ciphertext
        cipher1[5] = 0b1010_1010 | cipher1[5];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_err());
    }

    #[test]
    fn test_err_on_diff_ad() {
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        // This ciphertext was constructed without AD
        let cipher1: [u8; 23] = [
            252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
            45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
        ];
        let mut plain_out1 = [0u8; 23 - ABYTES];
        assert!(s.open_chunk(&cipher1, None, &mut plain_out1).is_ok());

        // Reset state
        let mut s = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert!(s
            .open_chunk(&cipher1, Some(&[1u8; 1]), &mut plain_out1)
            .is_err());
    }

    #[test]
    fn test_encrypting_same_message_different_output() {
        let input = [0u8, 1u8, 2u8, 3u8];
        let mut cipher = [0u8; 4 + ABYTES];
        let mut cipher2 = [0u8; 4 + ABYTES];
        let mut state_enc =
            StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from([0u8; 24]));
        state_enc
            .seal_chunk(&input, None, &mut cipher, StreamTag::Message)
            .unwrap();
        state_enc
            .seal_chunk(&input, None, &mut cipher2, StreamTag::Message)
            .unwrap();
        assert_ne!(cipher, cipher2);
    }

    #[test]
    fn test_encrypting_same_message_explicit_rekey() {
        let input = [0u8, 1u8, 2u8, 3u8];
        let mut cipher = [0u8; 4 + ABYTES];
        let mut cipher2 = [0u8; 4 + ABYTES];
        let mut state_enc =
            StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from([0u8; 24]));
        state_enc
            .seal_chunk(&input, None, &mut cipher, StreamTag::Message)
            .unwrap();
        let mut state_enc =
            StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from([0u8; 24]));
        state_enc.rekey().unwrap();
        state_enc
            .seal_chunk(&input, None, &mut cipher2, StreamTag::Message)
            .unwrap();
        assert_ne!(cipher, cipher2);
    }

    #[test]
    // This cannot be tested in AeadTestRunner as it assumes empty
    // ciphertext to be invalid.
    fn test_seal_empty_and_open() {
        let mut state_enc =
            StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from([0u8; 24]));
        let mut cipher = [0u8; ABYTES];
        state_enc
            .seal_chunk(&[0u8; 0], None, &mut cipher, StreamTag::Message)
            .unwrap();

        let mut state_dec =
            StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from([0u8; 24]));

        let mut out = [0u8; ABYTES];
        assert!(state_dec.open_chunk(&cipher, None, &mut out).is_ok());
    }

    #[test]
    // This cannot be tested in AeadTestRunner as it assumes empty
    // ciphertext to be invalid. This also tests that input to open_chunk
    // requires the tagsize only, and not tagsize + 1.
    fn test_seal_open_zero_length_both() {
        let mut state_enc =
            StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from([0u8; 24]));
        let mut out = [0u8; ABYTES];
        state_enc
            .seal_chunk(&[0u8; 0], None, &mut out, StreamTag::Message)
            .unwrap();
        let mut state_dec =
            StreamXChaCha20Poly1305::new(&SecretKey::from([0u8; 32]), &Nonce::from([0u8; 24]));
        let mut dst_out = [0u8; 0];
        // Only the attached tag is decrypted and authenticated. But it is
        // not placed in dst_out.
        assert!(state_dec.open_chunk(&out, None, &mut dst_out).is_ok());
        assert!(dst_out.is_empty());
        assert_eq!(dst_out, [0u8; 0]);
    }

    #[test]
    fn test_new_to_msg_with_tag_final() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let after_internal_key: [u8; 32] = [
            168u8, 19u8, 24u8, 25u8, 196u8, 239u8, 73u8, 251u8, 36u8, 135u8, 89u8, 117u8, 2u8,
            50u8, 208u8, 173u8, 177u8, 61u8, 147u8, 201u8, 97u8, 47u8, 74u8, 149u8, 21u8, 166u8,
            227u8, 53u8, 24u8, 101u8, 251u8, 201u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 149u8, 246u8, 165u8, 228u8, 252u8, 41u8, 183u8, 89u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            255u8, 148u8, 0u8, 209u8, 14u8, 130u8, 100u8, 227u8, 231u8, 72u8, 231u8, 21u8, 186u8,
            18u8, 26u8, 148u8, 110u8, 96u8, 90u8, 46u8, 114u8, 110u8, 169u8, 51u8, 16u8, 116u8,
            48u8, 34u8, 119u8, 48u8, 212u8, 203u8, 18u8, 137u8, 21u8, 223u8, 114u8, 94u8, 129u8,
            255u8, 198u8, 22u8, 78u8, 206u8, 9u8, 223u8, 135u8, 107u8, 224u8, 192u8, 4u8, 94u8,
            100u8, 12u8, 28u8, 232u8, 44u8, 133u8, 81u8, 145u8, 176u8, 153u8, 17u8, 215u8, 180u8,
            79u8, 24u8, 79u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert_eq!(ctx.key.unprotected_as_bytes(), before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Finish)
            .unwrap();

        assert_eq!(ctx.key.unprotected_as_bytes(), after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_new_to_msg_with_tag_rekey() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let after_internal_key: [u8; 32] = [
            39u8, 159u8, 44u8, 102u8, 206u8, 161u8, 116u8, 119u8, 163u8, 187u8, 45u8, 209u8, 172u8,
            224u8, 237u8, 93u8, 9u8, 197u8, 138u8, 242u8, 195u8, 183u8, 253u8, 169u8, 86u8, 46u8,
            161u8, 32u8, 71u8, 244u8, 51u8, 222u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 161u8, 222u8, 206u8, 42u8, 195u8, 117u8, 85u8, 88u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            254u8, 148u8, 0u8, 209u8, 14u8, 130u8, 100u8, 227u8, 231u8, 72u8, 231u8, 21u8, 186u8,
            18u8, 26u8, 148u8, 110u8, 96u8, 90u8, 46u8, 114u8, 110u8, 169u8, 51u8, 16u8, 116u8,
            48u8, 34u8, 119u8, 48u8, 212u8, 203u8, 18u8, 137u8, 21u8, 223u8, 114u8, 94u8, 129u8,
            255u8, 198u8, 22u8, 78u8, 206u8, 9u8, 223u8, 135u8, 107u8, 224u8, 192u8, 4u8, 94u8,
            187u8, 26u8, 216u8, 136u8, 169u8, 121u8, 52u8, 215u8, 102u8, 180u8, 177u8, 255u8, 69u8,
            135u8, 172u8, 22u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert_eq!(ctx.key.unprotected_as_bytes(), before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Rekey)
            .unwrap();

        assert_eq!(ctx.key.unprotected_as_bytes(), after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_new_to_msg_with_tag_final_twice() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let after_internal_key: [u8; 32] = [
            162u8, 54u8, 231u8, 162u8, 170u8, 199u8, 53u8, 228u8, 224u8, 121u8, 138u8, 154u8, 17u8,
            252u8, 83u8, 49u8, 52u8, 25u8, 105u8, 51u8, 112u8, 3u8, 62u8, 217u8, 163u8, 194u8,
            15u8, 113u8, 155u8, 17u8, 7u8, 250u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 107u8, 7u8, 226u8, 104u8, 227u8, 227u8, 7u8, 100u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            119u8, 255u8, 30u8, 46u8, 10u8, 174u8, 158u8, 45u8, 225u8, 116u8, 158u8, 172u8, 175u8,
            198u8, 241u8, 34u8, 87u8, 52u8, 80u8, 230u8, 175u8, 133u8, 217u8, 132u8, 169u8, 75u8,
            68u8, 249u8, 86u8, 87u8, 86u8, 68u8, 33u8, 250u8, 148u8, 117u8, 43u8, 10u8, 22u8,
            125u8, 198u8, 6u8, 231u8, 5u8, 86u8, 199u8, 29u8, 214u8, 215u8, 74u8, 71u8, 244u8,
            194u8, 50u8, 98u8, 209u8, 136u8, 235u8, 79u8, 113u8, 54u8, 101u8, 105u8, 14u8, 178u8,
            146u8, 23u8, 229u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert_eq!(ctx.key.unprotected_as_bytes(), before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Finish)
            .unwrap();
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Finish)
            .unwrap();

        assert_eq!(ctx.key.unprotected_as_bytes(), after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_new_to_msg_with_tag_rekey_twice() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let after_internal_key: [u8; 32] = [
            35u8, 207u8, 156u8, 185u8, 84u8, 18u8, 253u8, 160u8, 229u8, 242u8, 126u8, 247u8, 235u8,
            193u8, 36u8, 121u8, 42u8, 247u8, 85u8, 108u8, 107u8, 143u8, 210u8, 194u8, 109u8, 46u8,
            107u8, 47u8, 186u8, 127u8, 123u8, 46u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 198u8, 222u8, 225u8, 73u8, 93u8, 233u8, 75u8, 181u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            1u8, 171u8, 81u8, 78u8, 97u8, 128u8, 134u8, 65u8, 126u8, 237u8, 31u8, 59u8, 6u8, 76u8,
            85u8, 119u8, 69u8, 183u8, 129u8, 184u8, 101u8, 246u8, 151u8, 0u8, 92u8, 171u8, 38u8,
            164u8, 215u8, 120u8, 75u8, 169u8, 254u8, 207u8, 198u8, 138u8, 118u8, 68u8, 89u8, 231u8,
            38u8, 220u8, 26u8, 210u8, 220u8, 102u8, 8u8, 245u8, 205u8, 152u8, 39u8, 155u8, 36u8,
            115u8, 127u8, 79u8, 54u8, 246u8, 154u8, 2u8, 24u8, 208u8, 83u8, 232u8, 143u8, 234u8,
            51u8, 194u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert_eq!(ctx.key.unprotected_as_bytes(), before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Rekey)
            .unwrap();
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Rekey)
            .unwrap();

        assert_eq!(ctx.key.unprotected_as_bytes(), after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_new_to_msg_with_tag_push() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let after_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            2u8, 0u8, 0u8, 0u8, 118u8, 75u8, 245u8, 72u8, 68u8, 15u8, 117u8, 29u8,
        ];
        let after_internal_counter: [u8; 4] = [2u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            253u8, 148u8, 0u8, 209u8, 14u8, 130u8, 100u8, 227u8, 231u8, 72u8, 231u8, 21u8, 186u8,
            18u8, 26u8, 148u8, 110u8, 96u8, 90u8, 46u8, 114u8, 110u8, 169u8, 51u8, 16u8, 116u8,
            48u8, 34u8, 119u8, 48u8, 212u8, 203u8, 18u8, 137u8, 21u8, 223u8, 114u8, 94u8, 129u8,
            255u8, 198u8, 22u8, 78u8, 206u8, 9u8, 223u8, 135u8, 107u8, 224u8, 192u8, 4u8, 94u8,
            23u8, 41u8, 148u8, 41u8, 38u8, 110u8, 23u8, 29u8, 29u8, 207u8, 81u8, 40u8, 215u8,
            190u8, 64u8, 222u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        assert_eq!(ctx.key, before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce().as_ref(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Push)
            .unwrap();

        assert_eq!(ctx.key, after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce().as_ref(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_counter_overflow_with_tag_msg() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            255u8, 255u8, 255u8, 255u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [255u8, 255u8, 255u8, 255u8];
        let after_internal_key: [u8; 32] = [
            48u8, 109u8, 58u8, 2u8, 7u8, 92u8, 20u8, 239u8, 137u8, 218u8, 220u8, 62u8, 74u8, 47u8,
            118u8, 162u8, 61u8, 234u8, 35u8, 242u8, 40u8, 2u8, 243u8, 149u8, 188u8, 249u8, 180u8,
            242u8, 228u8, 139u8, 163u8, 76u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 36u8, 9u8, 22u8, 61u8, 226u8, 117u8, 46u8, 156u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            131u8, 93u8, 90u8, 220u8, 186u8, 163u8, 161u8, 113u8, 238u8, 31u8, 49u8, 63u8, 12u8,
            101u8, 64u8, 221u8, 255u8, 190u8, 206u8, 20u8, 155u8, 140u8, 72u8, 180u8, 4u8, 199u8,
            170u8, 178u8, 21u8, 212u8, 238u8, 60u8, 110u8, 233u8, 44u8, 24u8, 105u8, 216u8, 234u8,
            132u8, 103u8, 31u8, 222u8, 244u8, 214u8, 180u8, 224u8, 206u8, 148u8, 114u8, 100u8,
            161u8, 57u8, 6u8, 49u8, 199u8, 242u8, 58u8, 28u8, 253u8, 199u8, 16u8, 246u8, 86u8,
            116u8, 22u8, 66u8, 91u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        ctx.counter = u32::MAX;
        assert_eq!(ctx.key, before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Message)
            .unwrap();

        assert_eq!(ctx.key, after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_counter_overflow_with_tag_rekey() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            255u8, 255u8, 255u8, 255u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [255u8, 255u8, 255u8, 255u8];
        let after_internal_key: [u8; 32] = [
            115u8, 83u8, 132u8, 174u8, 130u8, 252u8, 214u8, 242u8, 239u8, 140u8, 231u8, 231u8,
            111u8, 228u8, 182u8, 88u8, 124u8, 109u8, 210u8, 61u8, 48u8, 22u8, 215u8, 232u8, 180u8,
            174u8, 180u8, 216u8, 174u8, 209u8, 222u8, 8u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 188u8, 188u8, 116u8, 239u8, 177u8, 113u8, 89u8, 218u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            129u8, 93u8, 90u8, 220u8, 186u8, 163u8, 161u8, 113u8, 238u8, 31u8, 49u8, 63u8, 12u8,
            101u8, 64u8, 221u8, 255u8, 190u8, 206u8, 20u8, 155u8, 140u8, 72u8, 180u8, 4u8, 199u8,
            170u8, 178u8, 21u8, 212u8, 238u8, 60u8, 110u8, 233u8, 44u8, 24u8, 105u8, 216u8, 234u8,
            132u8, 103u8, 31u8, 222u8, 244u8, 214u8, 180u8, 224u8, 206u8, 148u8, 114u8, 100u8,
            161u8, 107u8, 212u8, 93u8, 14u8, 123u8, 181u8, 233u8, 248u8, 139u8, 61u8, 100u8, 73u8,
            40u8, 14u8, 226u8, 118u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        ctx.counter = u32::MAX;
        assert_eq!(ctx.key.unprotected_as_bytes(), before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Rekey)
            .unwrap();

        assert_eq!(ctx.key.unprotected_as_bytes(), after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_counter_overflow_with_tag_final() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            255u8, 255u8, 255u8, 255u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [255u8, 255u8, 255u8, 255u8];
        let after_internal_key: [u8; 32] = [
            181u8, 99u8, 219u8, 38u8, 136u8, 29u8, 61u8, 72u8, 122u8, 0u8, 111u8, 182u8, 254u8,
            74u8, 225u8, 183u8, 250u8, 200u8, 34u8, 169u8, 252u8, 92u8, 107u8, 85u8, 144u8, 12u8,
            203u8, 19u8, 166u8, 41u8, 168u8, 26u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 230u8, 194u8, 178u8, 201u8, 13u8, 110u8, 57u8, 106u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            128u8, 93u8, 90u8, 220u8, 186u8, 163u8, 161u8, 113u8, 238u8, 31u8, 49u8, 63u8, 12u8,
            101u8, 64u8, 221u8, 255u8, 190u8, 206u8, 20u8, 155u8, 140u8, 72u8, 180u8, 4u8, 199u8,
            170u8, 178u8, 21u8, 212u8, 238u8, 60u8, 110u8, 233u8, 44u8, 24u8, 105u8, 216u8, 234u8,
            132u8, 103u8, 31u8, 222u8, 244u8, 214u8, 180u8, 224u8, 206u8, 148u8, 114u8, 100u8,
            161u8, 137u8, 59u8, 244u8, 49u8, 191u8, 114u8, 208u8, 246u8, 237u8, 83u8, 155u8, 66u8,
            2u8, 10u8, 178u8, 132u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        ctx.counter = u32::MAX;
        assert_eq!(ctx.key, before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Finish)
            .unwrap();

        assert_eq!(ctx.key, after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }

    #[test]
    fn test_counter_overflow_with_tag_push() {
        let before_internal_key: [u8; 32] = [
            23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8, 116u8,
            179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8, 219u8,
            33u8, 44u8, 68u8, 91u8, 135u8,
        ];
        let before_internal_nonce: [u8; 12] = [
            255u8, 255u8, 255u8, 255u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
        ];
        let before_internal_counter: [u8; 4] = [255u8, 255u8, 255u8, 255u8];
        let after_internal_key: [u8; 32] = [
            251u8, 165u8, 61u8, 114u8, 68u8, 126u8, 68u8, 202u8, 143u8, 101u8, 78u8, 242u8, 164u8,
            171u8, 209u8, 209u8, 227u8, 5u8, 181u8, 244u8, 141u8, 167u8, 137u8, 0u8, 228u8, 122u8,
            149u8, 109u8, 129u8, 240u8, 174u8, 128u8,
        ];
        let after_internal_nonce: [u8; 12] = [
            1u8, 0u8, 0u8, 0u8, 228u8, 204u8, 203u8, 245u8, 146u8, 107u8, 101u8, 124u8,
        ];
        let after_internal_counter: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
        let out: [u8; 68] = [
            130u8, 93u8, 90u8, 220u8, 186u8, 163u8, 161u8, 113u8, 238u8, 31u8, 49u8, 63u8, 12u8,
            101u8, 64u8, 221u8, 255u8, 190u8, 206u8, 20u8, 155u8, 140u8, 72u8, 180u8, 4u8, 199u8,
            170u8, 178u8, 21u8, 212u8, 238u8, 60u8, 110u8, 233u8, 44u8, 24u8, 105u8, 216u8, 234u8,
            132u8, 103u8, 31u8, 222u8, 244u8, 214u8, 180u8, 224u8, 206u8, 148u8, 114u8, 100u8,
            161u8, 82u8, 109u8, 199u8, 234u8, 54u8, 248u8, 2u8, 251u8, 41u8, 39u8, 45u8, 80u8,
            78u8, 18u8, 18u8, 105u8,
        ];

        let mut ctx = StreamXChaCha20Poly1305::new(&SecretKey::from(KEY), &Nonce::from(NONCE));
        ctx.counter = u32::MAX;
        assert_eq!(ctx.key, before_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), before_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(before_internal_counter));

        let mut actual = [0u8; 68];
        ctx.seal_chunk(DEFAULT_MSG.as_ref(), None, &mut actual, StreamTag::Push)
            .unwrap();

        assert_eq!(ctx.key, after_internal_key.as_ref());
        assert_eq!(ctx.get_nonce(), after_internal_nonce.as_ref());
        assert_eq!(ctx.counter, u32::from_le_bytes(after_internal_counter));
        assert_eq!(actual.as_ref(), out.as_ref());
    }
}
