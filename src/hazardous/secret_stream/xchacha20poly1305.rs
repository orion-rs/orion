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

// Based on the implementation used by libsodium
// https://download.libsodium.org/doc/secret-key_cryptography/secretstream
// https://github.com/jedisct1/libsodium/blob/stable/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c

use crate::const_assert;
use crate::errors::UnknownCryptoError;
use crate::hazardous::aead::chacha20poly1305::{padding, poly1305_key_gen};
use crate::hazardous::mac::poly1305::{Poly1305, Tag as PolyTag, POLY1305_OUTSIZE};
use crate::hazardous::stream::chacha20::{
	encrypt as chacha20_enc, encrypt_in_place as chacha20_enc_in_place, Nonce as chacha20Nonce,
	SecretKey as chacha20Key, CHACHA_KEYSIZE, HCHACHA_NONCESIZE, IETF_CHACHA_NONCESIZE,
};
use crate::hazardous::stream::xchacha20::subkey_and_nonce;
pub use crate::hazardous::stream::xchacha20::Nonce;

use bitflags::bitflags;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

//TODO Add more tests

bitflags! {
	/// Tag that indicates the type of message
	pub struct Tag: u8 {
		/// A simple message with no special meaning
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

/// Size of the header/nonce
pub const SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES: usize = 24;
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
	key: chacha20Key,
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
	pub fn new(key: chacha20Key, nonce: Nonce) -> Self {
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
			key: subkey_and_nonce(&key, &nonce).0,
			counter: 1,
			inonce: [0u8; SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES],
		};
		state
			.inonce
			.copy_from_slice(&nonce.as_ref()[HCHACHA_NONCESIZE..]);
		state
	}

	/// prepare a new push or pull operation
	pub fn init(&mut self, key: chacha20Key, nonce: Nonce) {
		*self = SecretStreamXChaCha20Poly1305::new(key, nonce);
	}

	#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
	/// derives a new secret key used for encryption/decryption
	pub fn rekey(&mut self) -> Result<(), UnknownCryptoError> {
		let mut new_key_and_inonce =
			[0u8; CHACHA_KEYSIZE + SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES];

		new_key_and_inonce[..CHACHA_KEYSIZE].copy_from_slice(self.key.unprotected_as_bytes());
		new_key_and_inonce[CHACHA_KEYSIZE..].copy_from_slice(&self.inonce);

		chacha20_enc_in_place(&self.key, &self.get_nonce(), 0, &mut new_key_and_inonce)?;

		self.key = chacha20Key::from_slice(&new_key_and_inonce[..CHACHA_KEYSIZE]).unwrap();
		self.inonce
			.copy_from_slice(&new_key_and_inonce[CHACHA_KEYSIZE..]);

		self.counter = 1;
		Ok(())
	}

	#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
	/// TODO: Doc
	/// //Ecryptes a message
	pub fn encrypt_message(
		&mut self,
		plaintext: &[u8],
		ad: &[u8],
		dst_out: &mut [u8],
		tag: Tag,
	) -> Result<(), UnknownCryptoError> {
		let msglen = plaintext.len();
		if dst_out.len() < SECRETSTREAM_XCHACHA20POLY1305_ABYTES + msglen {
			return Err(UnknownCryptoError);
		}

		let mut block = [0u8; BLOCKSIZE];
		let adlen = ad.len();
		let cipherpos = core::mem::size_of::<Tag>();
		let macpos = cipherpos + msglen;

		block[0] = tag.bits();
		chacha20_enc_in_place(&self.key, &self.get_nonce(), 1, &mut block)?;
		dst_out[0] = block[0];

		chacha20_enc(
			&self.key,
			&self.get_nonce(),
			2,
			plaintext,
			&mut dst_out[cipherpos..],
		)?;

		let mac = self
			.generate_auth_tag(dst_out, ad, msglen, &block, adlen, cipherpos)
			.unwrap();
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
	/// TODO: Doc
	/// Decryptes a message
	pub fn decrypt_message(
		&mut self,
		cipher: &[u8],
		ad: &[u8],
		plaintext_out: &mut [u8],
		tag_out: &mut Tag,
	) -> Result<(), UnknownCryptoError> {
		let msglen = cipher.len() - SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
		if cipher.len() < SECRETSTREAM_XCHACHA20POLY1305_ABYTES {
			return Err(UnknownCryptoError);
		}
		if plaintext_out.len() < msglen {
			return Err(UnknownCryptoError);
		}
		let mut block = [0u8; BLOCKSIZE];

		let adlen = ad.len();
		let msgpos = core::mem::size_of::<Tag>();
		let macpos = msgpos + msglen;

		block[0] = cipher[0];
		chacha20_enc_in_place(&self.key, &self.get_nonce(), 1, &mut block)?;
		let tag = Tag::from_bits(block[0]).ok_or(UnknownCryptoError)?;
		block[0] = cipher[0];
		let mut mac = self
			.generate_auth_tag(cipher, ad, msglen, &block, adlen, msgpos)
			.unwrap();
		if !(mac == &cipher[macpos..macpos + mac.get_length()]) {
			mac.zeroize();
			return Err(UnknownCryptoError);
		}
		chacha20_enc(
			&self.key,
			&self.get_nonce(),
			2,
			&cipher[msgpos..(msgpos + msglen)],
			plaintext_out,
		)?;
		xor_buf8(self.inonce.as_mut(), &mac.unprotected_as_bytes()[..8]);
		self.counter = self.counter.wrapping_add(1);
		if bool::from(tag.bits().ct_eq(&Tag::REKEY.bits()) | self.counter.ct_eq(&0u32)) {
			self.rekey()?;
		}
		*tag_out = tag;
		Ok(())
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

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use crate::hazardous::aead::chacha20poly1305::SecretKey;
		use crate::hazardous::secret_stream::xchacha20poly1305::{
			SecretStreamXChaCha20Poly1305, Tag, SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
		};
		use crate::hazardous::stream::xchacha20::Nonce;

		quickcheck! {
		fn prop_encrypting_and_decrypting_with_fixed_key(input: Vec<u8>) -> bool {
			if input.len() == 0 {
				return true;
			}
			let mut cipher =
				 vec![0u8; input.len() + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
			let mut msg =  vec![0u8; input.len()];
			let mut state_enc = SecretStreamXChaCha20Poly1305::new(
				SecretKey::from_slice(&[0; 32]).unwrap(),
				Nonce::from_slice(&[0; 24]).unwrap(),
			);
			state_enc
				.encrypt_message(
					input.as_slice(),
					&[0u8; 0],
					cipher.as_mut_slice(),
					Tag::MESSAGE,
				)
				.unwrap();

			let mut tag = Tag::empty();
			let mut state_dec = SecretStreamXChaCha20Poly1305::new(
				SecretKey::from_slice(&[0; 32]).unwrap(),
				Nonce::from_slice(&[0; 24]).unwrap(),
			);
			state_dec
				.decrypt_message(cipher.as_slice(), &[0u8; 0], msg.as_mut_slice(), &mut tag)
				.unwrap();
			(tag == Tag::MESSAGE) && (msg == input)
		}
		}

	}
}

#[cfg(test)]
mod private {
	extern crate hex;
	use self::hex::decode;
	use super::*;
	use hex::encode;

	//All test values generated with libsodium https://github.com/jedisct1/libsodium version 1.0.18

	#[test]
	fn test_push_with_zero_key_and_nonce() {
		let mut s = SecretStreamXChaCha20Poly1305 {
			key: chacha20Key::from([0u8; 32]),
			counter: 0,
			inonce: [0; 8],
		};
		let k = chacha20Key::from_slice(&[0; 32]).unwrap();
		s.init(k, Nonce::from_slice(&[0; 24]).unwrap());
		assert_eq!(
			encode(s.key.unprotected_as_bytes()),
			"1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586"
		);
		assert_eq!(encode(s.get_nonce().as_ref()), "010000000000000000000000");

		let plaintext = "1234";
		let mut out = [0u8; 21];
		s.encrypt_message(plaintext.as_bytes(), &[0u8; 0], &mut out, Tag::MESSAGE)
			.unwrap();
		assert_eq!(encode(&out), "5d1c4d54eb1738c2e8527f54f7b9bf46bcacc95f18");
		assert_eq!(
			encode(s.key.unprotected_as_bytes()),
			"1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586"
		);
		assert_eq!(encode(s.get_nonce().as_ref()), "020000001738c2e8527f54f7");
		//2
		s.encrypt_message(plaintext.as_bytes(), &[0u8; 0], &mut out, Tag::MESSAGE)
			.unwrap();
		assert_eq!(encode(&out), "6e76015272dc11c9539baae35a8be5e39f08df609d");
		assert_eq!(
			encode(s.key.unprotected_as_bytes()),
			"1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586"
		);
		assert_eq!(encode(s.get_nonce().as_ref()), "03000000cb290bbbc9d5b7ad");
		//3
		s.encrypt_message(plaintext.as_bytes(), &[0u8; 0], &mut out, Tag::MESSAGE)
			.unwrap();
		assert_eq!(encode(&out), "f9fde2c79b7a66073ac8a57d6d59d56225a3539bd9");
		assert_eq!(
			encode(s.key.unprotected_as_bytes()),
			"1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586"
		);
		assert_eq!(encode(s.get_nonce().as_ref()), "04000000b14f0c810170cac0");
		//4
		s.encrypt_message(plaintext.as_bytes(), &[0u8; 0], &mut out, Tag::MESSAGE)
			.unwrap();
		assert_eq!(encode(&out), "fac31dc872f09f95ae92fb1deed0371865c8eea4ca");
		assert_eq!(
			encode(s.key.unprotected_as_bytes()),
			"1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586"
		);
		assert_eq!(encode(s.get_nonce().as_ref()), "0500000041d0992f938bd72e");
	}

	#[test]
	fn test_decrypt() {
		let mut s = SecretStreamXChaCha20Poly1305 {
			key: chacha20Key::from([0u8; 32]),
			counter: 0,
			inonce: [0; 8],
		};
		let plaintext = "1234";
		let out = decode("5d1c4d54eb1738c2e8527f54f7b9bf46bcacc95f18").unwrap();
		s.init(
			chacha20Key::from_slice(&[0; 32]).unwrap(),
			Nonce::from_slice(&[0; 24]).unwrap(),
		);
		let mut plaintex_out = [0u8; 4];
		let mut tag_out = Tag::MESSAGE;
		s.decrypt_message(&out, &[0u8; 0], &mut plaintex_out, &mut tag_out)
			.unwrap();
		assert_eq!(plaintext.as_bytes(), plaintex_out);
	}

	#[test]
	fn test_rekey() {
		let mut s = SecretStreamXChaCha20Poly1305 {
			key: chacha20Key::from([0u8; 32]),
			counter: 0,
			inonce: [0; 8],
		};
		s.init(
			chacha20Key::from_slice(&[0; 32]).unwrap(),
			Nonce::from_slice(&[0; 24]).unwrap(),
		);
		s.rekey().unwrap();
		assert_eq!(
			encode(s.key.unprotected_as_bytes()),
			"99217472f2ff51598d4ea663ec55921afa989dbcaaecf003df3373219b910f80"
		);
		assert_eq!(encode(s.get_nonce().as_ref()), "01000000a4c0ddd43adf8183");
	}

}
