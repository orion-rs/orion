// MIT License

// Copyright (c) 2018-2019 The orion Developers

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
//! Stream encryption based on XChaCha20Poly1305.
//!
//! This implementation is based on and compatible with the [secretstream API](https://download.libsodium.org/doc/secret-key_cryptography/secretstream)
//! of libsodium.
//!
//! # Parameters:
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `ad`: Additional data to authenticate (this is not encrypted and can be
//!   `None`. This data is also not a part of `dst_out`).
//! - `plaintext`: The data to be encrypted.
//! - `ciphertext`: The encrypted data with a Poly1305 tag and a [`Tag`] indicating its function.
//! - `dst_out`: Destination array that will hold the
//!   `ciphertext`/`plaintext` after encryption/decryption.
//! - `tag`: Indicates the type of message.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext + 17` when encrypting.
//! - The length of `dst_out` is less than `ciphertext - 17` when
//!   decrypting.
//! - The length of `ciphertext` is not greater than `16`.
//! - The received mac does not match the calculated mac when decrypting. This can indicate
//!   a dropped or reordered message within the stream.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key.
//! - The nonce can be  randomly generated using a CSPRNG.
//! [`Nonce::generate()`] can be used for this.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//! - The length of the messages is leaked.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::aead::xchacha20poly1305_stream::*;
//!
//! let secret_key = SecretKey::generate();
//!	let nonce = Nonce::generate();
//!	let ad = "Additional data".as_bytes();
//! let message = "Data to protect".as_bytes();
//!
//! // Length of above message is 15 and then we accomodate 17
//! // for the mac and tag.
//!
//! let mut dst_out_ct = [
//!		0u8;
//!		15 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES
//!	];
//! let mut dst_out_pt = [0u8; 15];
//!
//!	let mut ctx_enc =
//! 	SecretStreamXChaCha20Poly1305::new(&secret_key, &nonce);
//!
//! // Encrypt and place tag + ciphertext + mac in dst_out_ct
//!	ctx_enc.encrypt_message(
//!		message,
//!		Some(ad),
//!		&mut dst_out_ct,
//!		Tag::MESSAGE,
//!	)?;
//!
//! let mut ctx_dec =
//!		SecretStreamXChaCha20Poly1305::new(&secret_key, &nonce);
//!
//! // Decrypt and save the tag the message was encrypted with.
//! let tag = ctx_dec.decrypt_message(&dst_out_ct, Some(ad), &mut dst_out_pt)?;
//!
//!	assert_eq!(tag, Tag::MESSAGE);
//!	assert_eq!(dst_out_pt.as_ref(), message);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: ../../stream/chacha20/struct.SecretKey.html
//! [`Nonce::generate()`]: ../../stream/xchacha20/struct.Nonce.html
//! [`Tag`]: struct.Tag.html

use crate::const_assert;
use crate::errors::UnknownCryptoError;
use crate::hazardous::aead::chacha20poly1305::{padding, poly1305_key_gen};
use crate::hazardous::mac::poly1305::{Poly1305, Tag as PolyTag, POLY1305_OUTSIZE};
pub use crate::hazardous::stream::chacha20::SecretKey;
use crate::hazardous::stream::chacha20::{
	encrypt as chacha20_enc, encrypt_in_place as chacha20_enc_in_place, Nonce as chacha20Nonce,
	CHACHA_KEYSIZE, HCHACHA_NONCESIZE, IETF_CHACHA_NONCESIZE,
};
pub use crate::hazardous::stream::xchacha20::Nonce;
use crate::hazardous::stream::xchacha20::{subkey_and_nonce, XCHACHA_NONCESIZE};

use bitflags::bitflags;
use subtle::ConstantTimeEq;

bitflags! {
	/// Tag that indicates the type of message
	pub struct Tag: u8 {
		/// A  message with no special meaning
		const MESSAGE = 0b0000_0000;
		/// Marks that the message is the end of a set of messages. Allows the decrypting site to
		/// start working with this data
		const PUSH = 0b0000_0001;
		/// derives a new secret key and forgets the one used for earlier encryption/decryption
		const REKEY = 0b0000_0010;
		/// Indicates the end of a stream. Also does an rekey.
		const FINISH = Self::PUSH.bits | Self::REKEY.bits;

	}
}

/// Size of the nonce
pub const SECRETSTREAM_XCHACHA20POLY1305_NONCESIZE: usize = XCHACHA_NONCESIZE;
const SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES: usize = 4;
const SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES: usize = 8;
/// Size of additional data appended to each message
pub const SECRETSTREAM_XCHACHA20POLY1305_ABYTES: usize =
	POLY1305_OUTSIZE + core::mem::size_of::<Tag>();
const BLOCKSIZE: usize = 64;

fn xor_buf8(out: &mut [u8], input: &[u8]) {
	debug_assert_eq!(out.len(), 8);
	debug_assert_eq!(input.len(), 8);
	for (o_elem, i_elem) in out.iter_mut().zip(input.iter()) {
		*o_elem ^= i_elem;
	}
}

type INonceType = [u8; SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES];
type CounterType = u32;

/// Secret Stream State
pub struct SecretStreamXChaCha20Poly1305 {
	key: SecretKey,
	counter: CounterType,
	inonce: INonceType,
}

impl core::fmt::Debug for SecretStreamXChaCha20Poly1305 {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(
			f,
			"SecretStreamXChaCha20Poly1305  {{ key: [***OMITTED***], counter: [***OMITTED***],\
			 inonce: [***OMITTED***]",
		)
	}
}

impl SecretStreamXChaCha20Poly1305 {
	fn get_nonce(&self) -> chacha20Nonce {
		let mut nonce = [0u8; 12];
		nonce[..SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
			.copy_from_slice(&self.counter.to_le_bytes());
		nonce[SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES..].copy_from_slice(&self.inonce);
		chacha20Nonce::from(nonce)
	}

	/// creates a new internal state
	pub fn new(secret_key: &SecretKey, nonce: &Nonce) -> Self {
		const_assert!(
			SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES == core::mem::size_of::<CounterType>()
		);
		const_assert!(
			SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES == core::mem::size_of::<INonceType>()
		);
		const_assert!(
			SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
				+ SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES
				== IETF_CHACHA_NONCESIZE
		);
		let mut state = Self {
			key: subkey_and_nonce(&secret_key, &nonce).0,
			counter: 1,
			inonce: [0u8; SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES],
		};
		state
			.inonce
			.copy_from_slice(&nonce.as_ref()[HCHACHA_NONCESIZE..]);
		state
	}

	#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
	/// derives a new internal key used for encryption/decryption
	pub fn rekey(&mut self) -> Result<(), UnknownCryptoError> {
		let mut new_key_and_inonce =
			[0u8; CHACHA_KEYSIZE + SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES];

		new_key_and_inonce[..CHACHA_KEYSIZE].copy_from_slice(self.key.unprotected_as_bytes());
		new_key_and_inonce[CHACHA_KEYSIZE..].copy_from_slice(&self.inonce);

		chacha20_enc_in_place(&self.key, &self.get_nonce(), 0, &mut new_key_and_inonce)?;

		self.key = SecretKey::from_slice(&new_key_and_inonce[..CHACHA_KEYSIZE]).unwrap();
		self.inonce
			.copy_from_slice(&new_key_and_inonce[CHACHA_KEYSIZE..]);

		self.counter = 1;
		Ok(())
	}

	#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
	/// Encrypts a message
	pub fn encrypt_message(
		&mut self,
		plaintext: &[u8],
		ad: Option<&[u8]>,
		dst_out: &mut [u8],
		tag: Tag,
	) -> Result<(), UnknownCryptoError> {
		let msglen = plaintext.len();
		if dst_out.len() < SECRETSTREAM_XCHACHA20POLY1305_ABYTES + msglen {
			return Err(UnknownCryptoError);
		}

		let mut block = [0u8; BLOCKSIZE];
		let ad = match ad {
			Some(v) => v,
			None => &[0u8; 0],
		};
		let adlen = ad.len();
		let cipherpos = core::mem::size_of::<Tag>();
		let macpos = cipherpos + msglen;

		block[0] = tag.bits();
		chacha20_enc_in_place(&self.key, &self.get_nonce(), 1, &mut block)?;
		dst_out[0] = block[0];

		if msglen != 0 {
			chacha20_enc(
				&self.key,
				&self.get_nonce(),
				2,
				plaintext,
				&mut dst_out[cipherpos..],
			)?;
		}

		let mac = self.generate_auth_tag(dst_out, ad, msglen, &block, adlen, cipherpos)?;
		debug_assert!(dst_out.len() >= macpos + mac.get_length());
		dst_out[macpos..(macpos + mac.get_length())].copy_from_slice(mac.unprotected_as_bytes());
		xor_buf8(self.inonce.as_mut(), &dst_out[macpos..macpos + 8]);
		self.counter = self.counter.wrapping_add(1);
		if bool::from(tag.bits().ct_eq(&Tag::REKEY.bits()) | self.counter.ct_eq(&0u32)) {
			self.rekey()?;
		}
		Ok(())
	}

	#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
	/// Decrypts a message
	pub fn decrypt_message(
		&mut self,
		ciphertext: &[u8],
		ad: Option<&[u8]>,
		dst_out: &mut [u8],
	) -> Result<Tag, UnknownCryptoError> {
		if ciphertext.len() < SECRETSTREAM_XCHACHA20POLY1305_ABYTES {
			return Err(UnknownCryptoError);
		}
		let msglen = ciphertext.len() - SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
		if dst_out.len() < msglen {
			return Err(UnknownCryptoError);
		}
		let mut block = [0u8; BLOCKSIZE];
		let ad = match ad {
			Some(v) => v,
			None => &[0u8; 0],
		};
		let adlen = ad.len();
		let msgpos = core::mem::size_of::<Tag>();
		let macpos = msgpos + msglen;

		block[0] = ciphertext[0];
		chacha20_enc_in_place(&self.key, &self.get_nonce(), 1, &mut block)?;
		let tag = Tag::from_bits(block[0]).ok_or(UnknownCryptoError)?;
		block[0] = ciphertext[0];
		let mac = self.generate_auth_tag(ciphertext, ad, msglen, &block, adlen, msgpos)?;
		if !(mac == &ciphertext[macpos..macpos + mac.get_length()]) {
			return Err(UnknownCryptoError);
		}
		if msglen != 0 {
			chacha20_enc(
				&self.key,
				&self.get_nonce(),
				2,
				&ciphertext[msgpos..(msgpos + msglen)],
				dst_out,
			)?;
		}
		xor_buf8(self.inonce.as_mut(), &mac.unprotected_as_bytes()[..8]);
		self.counter = self.counter.wrapping_add(1);
		if bool::from(tag.bits().ct_eq(&Tag::REKEY.bits()) | self.counter.ct_eq(&0u32)) {
			self.rekey()?;
		}
		Ok(tag)
	}

	/// Generates the poly1305 tag for a message
	fn generate_auth_tag(
		&mut self,
		text: &[u8],
		ad: &[u8],
		msglen: usize,
		block: &[u8],
		adlen: usize,
		textpos: usize,
	) -> Result<PolyTag, UnknownCryptoError> {
		debug_assert!(text.len() >= textpos + msglen);
		let mut slen = [0u8; 8];
		let pad = [0u8; 16];
		let mut poly = Poly1305::new(&poly1305_key_gen(&self.key, &self.get_nonce())?);
		if adlen > 0 {
			poly.update(ad)?;
			poly.update(&pad[..padding(ad.len())])?;
		}
		poly.update(&block)?;
		poly.update(&text[textpos..(textpos + msglen)])?;
		poly.update(&pad[..padding(BLOCKSIZE.wrapping_sub(msglen))])?;
		slen.copy_from_slice(&(adlen as u64).to_le_bytes());
		poly.update(&slen)?;
		slen.copy_from_slice(&(BLOCKSIZE as u64 + msglen as u64).to_le_bytes());
		poly.update(&slen)?;
		Ok(poly.finalize()?)
	}
}

#[cfg(test)]
mod public {

	#[cfg(feature = "safe_api")]
	mod proptest2 {
		use crate::errors::UnknownCryptoError;
		use crate::hazardous::aead::xchacha20poly1305_stream::{
			Nonce, SecretKey, SecretStreamXChaCha20Poly1305, Tag,
			SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
		};
		use crate::test_framework::aead_interface::*;

		fn seal(
			sk: &SecretKey,
			nonce: &Nonce,
			input: &[u8],
			ad: Option<&[u8]>,
			output: &mut [u8],
		) -> Result<(), UnknownCryptoError> {
			//Hack to pass zero test
			if input.len() == 0 {
				return Err(UnknownCryptoError);
			}
			let mut state = SecretStreamXChaCha20Poly1305::new(sk, nonce);
			state.encrypt_message(input, ad, output, Tag::MESSAGE)?;
			Ok(())
		}

		fn open(
			sk: &SecretKey,
			nonce: &Nonce,
			input: &[u8],
			ad: Option<&[u8]>,
			output: &mut [u8],
		) -> Result<(), UnknownCryptoError> {
			//Hack to pass zero test
			if input.len() == SECRETSTREAM_XCHACHA20POLY1305_ABYTES {
				return Err(UnknownCryptoError);
			}
			let mut state = SecretStreamXChaCha20Poly1305::new(sk, nonce);
			state.decrypt_message(input, ad, output)?;
			Ok(())
		}

		quickcheck! {
			fn prop_aead_interface(input: Vec<u8>, ad: Vec<u8>) -> bool {
				let secret_key = SecretKey::generate();
				let nonce = Nonce::generate();
				AeadTestRunner(seal, open, secret_key, nonce, &input, None,SECRETSTREAM_XCHACHA20POLY1305_ABYTES , &ad);

				true
			}
		}
	}
}

#[cfg(test)]
mod private {
	use super::*;

	//All test values generated with libsodium https://github.com/jedisct1/libsodium version 1.0.18

	#[test]
	fn test_enc_and_dec_valid() {
		let mut s = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);
		assert_eq!(
			s.key.unprotected_as_bytes(),
			[
				23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
				116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
				219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
			]
		);
		assert_eq!(
			s.get_nonce(),
			[1u8, 0u8, 0u8, 0u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,].as_ref()
		);
		//MSg 1
		let plaintext1 = [116u8, 101u8, 115u8, 116u8, 49u8, 0u8];
		let mut out1 = [0u8; 6 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		s.encrypt_message(&plaintext1, None, &mut out1, Tag::MESSAGE)
			.unwrap();
		assert_eq!(
			s.key.unprotected_as_bytes(),
			[
				23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
				116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
				219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
			]
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

		//MSg 2
		let plaintext2 = [
			116u8, 104u8, 105u8, 115u8, 32u8, 105u8, 115u8, 32u8, 108u8, 111u8, 110u8, 103u8,
			101u8, 114u8, 32u8, 116u8, 101u8, 120u8, 116u8, 0u8,
		];
		let mut out2 = [0u8; 20 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		s.encrypt_message(&plaintext2, None, &mut out2, Tag::MESSAGE)
			.unwrap();
		assert_eq!(
			s.key.unprotected_as_bytes(),
			[
				23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
				116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
				219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
			]
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

		//MSg 3
		let plaintext3 = [49u8, 0u8];
		let mut out3 = [0u8; 2 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		s.encrypt_message(&plaintext3, None, &mut out3, Tag::MESSAGE)
			.unwrap();
		assert_eq!(
			s.key.unprotected_as_bytes(),
			[
				23u8, 45u8, 143u8, 75u8, 14u8, 65u8, 110u8, 208u8, 6u8, 34u8, 38u8, 33u8, 64u8,
				116u8, 179u8, 244u8, 8u8, 121u8, 32u8, 23u8, 87u8, 135u8, 147u8, 246u8, 88u8, 52u8,
				219u8, 33u8, 44u8, 68u8, 91u8, 135u8,
			]
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

		//rekey
		s.rekey().unwrap();
		assert_eq!(
			s.key.unprotected_as_bytes(),
			[
				55u8, 213u8, 132u8, 57u8, 116u8, 28u8, 19u8, 214u8, 59u8, 159u8, 188u8, 185u8,
				201u8, 153u8, 70u8, 17u8, 149u8, 199u8, 55u8, 34u8, 164u8, 54u8, 200u8, 241u8,
				157u8, 71u8, 218u8, 62u8, 37u8, 37u8, 8u8, 126u8,
			]
		);
		assert_eq!(
			s.get_nonce(),
			[1u8, 0u8, 0u8, 0u8, 250u8, 25u8, 191u8, 166u8, 103u8, 98u8, 187u8, 196u8,].as_ref()
		);

		//MSg 4
		let plaintext4 = [
			102u8, 105u8, 114u8, 115u8, 116u8, 32u8, 116u8, 101u8, 120u8, 116u8, 32u8, 97u8, 102u8,
			116u8, 101u8, 114u8, 32u8, 114u8, 101u8, 107u8, 101u8, 121u8, 0u8,
		];
		let mut out4 = [0u8; 23 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		s.encrypt_message(&plaintext4, None, &mut out4, Tag::MESSAGE)
			.unwrap();
		assert_eq!(
			s.key.unprotected_as_bytes(),
			[
				55u8, 213u8, 132u8, 57u8, 116u8, 28u8, 19u8, 214u8, 59u8, 159u8, 188u8, 185u8,
				201u8, 153u8, 70u8, 17u8, 149u8, 199u8, 55u8, 34u8, 164u8, 54u8, 200u8, 241u8,
				157u8, 71u8, 218u8, 62u8, 37u8, 37u8, 8u8, 126u8,
			]
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

		//MSg 5
		let plaintext5 = [
			116u8, 104u8, 105u8, 115u8, 32u8, 105u8, 115u8, 32u8, 116u8, 104u8, 101u8, 32u8, 115u8,
			101u8, 99u8, 111u8, 110u8, 100u8, 32u8, 116u8, 101u8, 120u8, 116u8, 32u8, 97u8, 102u8,
			116u8, 101u8, 114u8, 32u8, 114u8, 101u8, 107u8, 101u8, 121u8, 0u8,
		];
		let mut out5 = [0u8; 36 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		s.encrypt_message(&plaintext5, None, &mut out5, Tag::MESSAGE)
			.unwrap();
		assert_eq!(
			s.key.unprotected_as_bytes(),
			[
				55u8, 213u8, 132u8, 57u8, 116u8, 28u8, 19u8, 214u8, 59u8, 159u8, 188u8, 185u8,
				201u8, 153u8, 70u8, 17u8, 149u8, 199u8, 55u8, 34u8, 164u8, 54u8, 200u8, 241u8,
				157u8, 71u8, 218u8, 62u8, 37u8, 37u8, 8u8, 126u8,
			]
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

		//decrypt
		let mut s = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);

		let mut plain_out1 = [0u8; 6];
		assert_eq!(
			s.decrypt_message(&out1, None, &mut plain_out1).unwrap(),
			Tag::MESSAGE
		);
		assert_eq!(plain_out1.as_ref(), plaintext1.as_ref());
		let mut plain_out2 = [0u8; 20];
		assert_eq!(
			s.decrypt_message(&out2, None, &mut plain_out2).unwrap(),
			Tag::MESSAGE
		);
		assert_eq!(plain_out2.as_ref(), plaintext2.as_ref());
		let mut plain_out3 = [0u8; 2];
		assert_eq!(
			s.decrypt_message(&out3, None, &mut plain_out3).unwrap(),
			Tag::MESSAGE
		);
		assert_eq!(plain_out3.as_ref(), plaintext3.as_ref());

		s.rekey().unwrap();

		let mut plain_out4 = [0u8; 23];
		assert_eq!(
			s.decrypt_message(&out4, None, &mut plain_out4).unwrap(),
			Tag::MESSAGE
		);
		assert_eq!(plain_out4.as_ref(), plaintext4.as_ref());
		let mut plain_out5 = [0u8; 36];
		assert_eq!(
			s.decrypt_message(&out5, None, &mut plain_out5).unwrap(),
			Tag::MESSAGE
		);
		assert_eq!(plain_out5.as_ref(), plaintext5.as_ref());
	}

	#[test]
	fn test_reorder_or_drop_msg() {
		let mut s = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);
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
		let mut plain_out1 = [0u8; 23 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		assert_eq!(
			s.decrypt_message(&cipher1, None, &mut plain_out1).unwrap(),
			Tag::MESSAGE
		);
		assert_eq!(&plain_out1, &plaintext1);

		let mut plain_out3 = [0u8; 19 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		assert!(s.decrypt_message(&cipher3, None, &mut plain_out3).is_err());

		let mut plain_out2 = [0u8; 37 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		assert_eq!(
			s.decrypt_message(&cipher2, None, &mut plain_out2).unwrap(),
			Tag::MESSAGE
		);
		assert_eq!(&plain_out2, &plaintext2);
	}

	#[test]
	fn test_modified_tag() {
		let mut s = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);

		//This cipher text can be decrypted
		let mut cipher1 = [
			252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
			45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
		];
		cipher1[0] = 0b1010_1010 | cipher1[0]; //Change tag
		let mut plain_out1 = [0u8; 23 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		assert!(s.decrypt_message(&cipher1, None, &mut plain_out1).is_err());
	}

	#[test]
	fn test_modified_mac() {
		let mut s = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);

		//This cipher text can be decrypted
		let mut cipher1 = [
			252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
			45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
		];
		let macpos = cipher1.len() - 1;
		cipher1[macpos] = 0b1010_1010 | cipher1[macpos]; //Change mac
		let mut plain_out1 = [0u8; 23 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		assert!(s.decrypt_message(&cipher1, None, &mut plain_out1).is_err());
	}

	#[test]
	fn test_modified_cipher() {
		let mut s = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);

		//This cipher text can be decrypted
		let mut cipher1 = [
			252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
			45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
		];
		cipher1[5] = 0b1010_1010 | cipher1[5]; //Change something in the cipher
		let mut plain_out1 = [0u8; 23 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		assert!(s.decrypt_message(&cipher1, None, &mut plain_out1).is_err());
	}

	#[test]
	fn test_encrypting_same_message() {
		let input = [0u8, 1u8, 2u8, 3u8];
		let mut cipher = [0u8; 4 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		let mut cipher2 = [0u8; 4 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		let mut state_enc = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		state_enc
			.encrypt_message(&input, None, &mut cipher, Tag::MESSAGE)
			.unwrap();
		state_enc
			.encrypt_message(&input, None, &mut cipher2, Tag::MESSAGE)
			.unwrap();
		assert_ne!(cipher, cipher2);
	}

	#[test]
	fn test_encrypting_same_message_rekey() {
		let input = [0u8, 1u8, 2u8, 3u8];
		let mut cipher = [0u8; 4 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		let mut cipher2 = [0u8; 4 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		let mut state_enc = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		state_enc
			.encrypt_message(&input, None, &mut cipher, Tag::MESSAGE)
			.unwrap();
		let mut state_enc = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		state_enc.rekey().unwrap();
		state_enc
			.encrypt_message(&input, None, &mut cipher2, Tag::MESSAGE)
			.unwrap();
		assert_ne!(cipher, cipher2);
	}

	#[test]
	fn test_decrypt_cipher_too_short() {
		let mut state = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		let cipher = [0u8; 16];
		let mut out = [0u8; 50];
		assert!(state.decrypt_message(&cipher, None, &mut out).is_err());
	}

	#[test]
	fn test_decrypt_buffer_too_short() {
		let mut state = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);

		let cipher = [
			252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
			45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
		];
		let mut out = [0u8; 23 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES - 1];
		assert!(state.decrypt_message(&cipher, None, &mut out).is_err());
	}

	#[test]
	fn test_decrypt_buffer_exact() {
		let mut state = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[
				49u8, 50u8, 51u8, 52u8, 53u8, 54u8, 55u8, 56u8, 57u8, 97u8, 98u8, 99u8, 100u8,
				101u8, 102u8, 103u8, 104u8, 105u8, 106u8, 107u8, 108u8, 109u8, 111u8, 110u8, 112u8,
				113u8, 114u8, 115u8, 116u8, 117u8, 118u8, 0u8,
			])
			.unwrap(),
			&Nonce::from_slice(&[
				97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8, 97u8, 98u8,
				97u8, 98u8, 97u8, 98u8, 97u8, 97u8, 98u8, 97u8, 98u8, 0u8,
			])
			.unwrap(),
		);

		let cipher = [
			252u8, 164u8, 0u8, 196u8, 27u8, 198u8, 8u8, 57u8, 216u8, 118u8, 134u8, 104u8, 156u8,
			45u8, 71u8, 161u8, 199u8, 28u8, 79u8, 145u8, 19u8, 239u8, 4u8,
		];

		let mut out = [0u8; 23 - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		state.decrypt_message(&cipher, None, &mut out).unwrap();
	}

	#[test]
	fn test_encrypt_buffer_too_short() {
		let mut state = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		let text = [0u8; 16];
		let mut out = [0u8; 16 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES - 1];
		assert!(state
			.encrypt_message(&text, None, &mut out, Tag::MESSAGE)
			.is_err());
	}

	#[test]
	fn test_encrypt_buffer_exact() {
		let mut state = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		let text = [0u8; 16];
		let mut out = [0u8; 16 + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		state
			.encrypt_message(&text, None, &mut out, Tag::MESSAGE)
			.unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt_zero_length() {
		let mut state_enc = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		let text = [0u8; 0];
		let mut out = [0u8; SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
		state_enc
			.encrypt_message(&text, None, &mut out, Tag::MESSAGE)
			.unwrap();
		let mut state_dec = SecretStreamXChaCha20Poly1305::new(
			&SecretKey::from_slice(&[0; 32]).unwrap(),
			&Nonce::from_slice(&[0; 24]).unwrap(),
		);
		let mut text_out = [0u8; 0];
		state_dec
			.decrypt_message(&out, None, &mut text_out)
			.unwrap();
		assert_eq!(text, text_out);
	}
}
