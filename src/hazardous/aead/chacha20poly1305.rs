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

//! # Parameters:
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `ad`: Additional data to authenticate (this is not encrypted and can be
//!   `None`).
//! - `ciphertext_with_tag`: The encrypted data with the corresponding 16 byte
//!   Poly1305 tag
//! appended to it.
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
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of `dst_out` is less than `plaintext + 16` when encrypting.
//! - The length of `dst_out` is less than `ciphertext_with_tag - 16` when
//!   decrypting.
//! - The length of `ciphertext_with_tag` is not greater than `16`.
//! - `plaintext` or `ciphertext_with_tag` are empty.
//! - `plaintext` or `ciphertext_with_tag - 16` are longer than (2^32)-2.
//! - The received tag does not match the calculated tag when decrypting.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - Only a nonce for XChaCha20Poly1305 is big enough to be randomly generated
//!   using a CSPRNG.
//! - To securely generate a strong key, use `SecretKey::generate()`.
//!
//! # Recommendation:
//! - It is recommended to use XChaCha20Poly1305 when possible.
//!
//! # Example:
//! ```
//! use orion::hazardous::aead;
//!
//! let secret_key = aead::chacha20poly1305::SecretKey::generate().unwrap();
//!
//! let nonce = aead::chacha20poly1305::Nonce::from_slice(&[
//! 	0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
//! 	])
//! .unwrap();
//! let ad = [
//! 	0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
//! 	];
//! let plaintext = b"\
//! Ladies and Gentlemen of the class of '99: If I could offer you o\
//! nly one tip for the future, sunscreen would be it.";
//!
//! // Length of above plaintext is 114 and then we accomodate 16 for the Poly1305
//! // tag.
//!
//! let mut dst_out_ct = [0u8; 114 + 16];
//! let mut dst_out_pt = [0u8; 114];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! aead::chacha20poly1305::seal(&secret_key, &nonce, plaintext, Some(&ad), &mut dst_out_ct)
//! 	.unwrap();
//! // Verify tag, if correct then decrypt and place plaintext in dst_out_pt
//! aead::chacha20poly1305::open(&secret_key, &nonce, &dst_out_ct, Some(&ad), &mut dst_out_pt)
//! 	.unwrap();
//!
//! assert_eq!(dst_out_pt.as_ref(), plaintext.as_ref());
//! ```
pub use crate::hazardous::stream::chacha20::{Nonce, SecretKey};
use crate::{
	errors::UnknownCryptoError,
	hazardous::{
		constants::{POLY1305_BLOCKSIZE, POLY1305_KEYSIZE},
		mac::poly1305::{self, OneTimeKey},
		stream::chacha20,
	},
	util,
};
use byteorder::{ByteOrder, LittleEndian};

#[must_use]
/// Poly1305 key generation using IETF ChaCha20.
fn poly1305_key_gen(key: &[u8], nonce: &[u8]) -> Result<OneTimeKey, UnknownCryptoError> {
	let one_time_key = OneTimeKey::from_slice(
		&chacha20::keystream_block(
			&SecretKey::from_slice(&key)?,
			&Nonce::from_slice(&nonce)?,
			0,
		)?[..POLY1305_KEYSIZE],
	)?;

	Ok(one_time_key)
}

#[must_use]
/// Padding size that gives the needed bytes to pad `input` to an integral
/// multiple of 16.
fn padding(input: &[u8]) -> usize {
	if input.len() % 16 != 0 {
		16 - (input.len() % 16)
	} else {
		0
	}
}

#[must_use]
/// Process data to be authenticated using a `Poly1305` struct initialized with
/// a one-time-key.
fn process_authentication(
	poly1305_state: &mut poly1305::Poly1305,
	ad: &[u8],
	buf: &[u8],
	buf_in_len: usize,
) -> Result<(), UnknownCryptoError> {
	if buf_in_len > buf.len() {
		return Err(UnknownCryptoError);
	}

	let mut padding_max = [0u8; 16];

	poly1305_state.update(ad)?;
	poly1305_state.update(&padding_max[..padding(ad)])?;
	poly1305_state.update(&buf[..buf_in_len])?;
	poly1305_state.update(&padding_max[..padding(&buf[..buf_in_len])])?;

	// Using the 16 bytes from padding template to store length information
	LittleEndian::write_u64(&mut padding_max[..8], ad.len() as u64);
	LittleEndian::write_u64(&mut padding_max[8..16], buf_in_len as u64);

	poly1305_state.update(&padding_max[..8])?;
	poly1305_state.update(&padding_max[8..16])?;

	Ok(())
}

#[must_use]
/// AEAD ChaCha20Poly1305 encryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn seal(
	secret_key: &SecretKey,
	nonce: &Nonce,
	plaintext: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	if dst_out.len() < plaintext.len() + POLY1305_BLOCKSIZE {
		return Err(UnknownCryptoError);
	}
	if plaintext.is_empty() {
		return Err(UnknownCryptoError);
	}

	let optional_ad = match ad {
		Some(ref n_val) => *n_val,
		None => &[0u8; 0],
	};

	let poly1305_key = poly1305_key_gen(&secret_key.unprotected_as_bytes(), &nonce.as_bytes())?;
	chacha20::encrypt(
		secret_key,
		nonce,
		1,
		plaintext,
		&mut dst_out[..plaintext.len()],
	)?;
	let mut poly1305_state = poly1305::init(&poly1305_key);

	process_authentication(&mut poly1305_state, &optional_ad, &dst_out, plaintext.len())?;
	dst_out[plaintext.len()..(plaintext.len() + POLY1305_BLOCKSIZE)]
		.copy_from_slice(&poly1305_state.finalize()?.unprotected_as_bytes());

	Ok(())
}

#[must_use]
/// AEAD ChaCha20Poly1305 decryption and authentication as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn open(
	secret_key: &SecretKey,
	nonce: &Nonce,
	ciphertext_with_tag: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	if ciphertext_with_tag.len() <= POLY1305_BLOCKSIZE {
		return Err(UnknownCryptoError);
	}
	if dst_out.len() < ciphertext_with_tag.len() - POLY1305_BLOCKSIZE {
		return Err(UnknownCryptoError);
	}

	let optional_ad = match ad {
		Some(ref n_val) => *n_val,
		None => &[0u8; 0],
	};

	let ciphertext_len = ciphertext_with_tag.len() - POLY1305_BLOCKSIZE;

	let poly1305_key = poly1305_key_gen(&secret_key.unprotected_as_bytes(), &nonce.as_bytes())?;
	let mut poly1305_state = poly1305::init(&poly1305_key);
	process_authentication(
		&mut poly1305_state,
		&optional_ad,
		ciphertext_with_tag,
		ciphertext_len,
	)?;

	util::secure_cmp(
		&poly1305_state.finalize()?.unprotected_as_bytes(),
		&ciphertext_with_tag[ciphertext_len..],
	)?;

	chacha20::decrypt(
		secret_key,
		nonce,
		1,
		&ciphertext_with_tag[..ciphertext_len],
		dst_out,
	)?;

	Ok(())
}

#[test]
fn length_padding_tests() {
	// Integral multiple of 16
	assert_eq!(padding(&[0u8; 16]), 0);
	assert_eq!(padding(&[0u8; 15]), 1);
	assert_eq!(padding(&[0u8; 32]), 0);
	assert_eq!(padding(&[0u8; 30]), 2);
}

#[test]
fn test_auth_process_with_above_length_index() {
	let poly1305_key = poly1305_key_gen(&[0u8; 32], &[0u8; 12]).unwrap();
	let mut poly1305_state = poly1305::init(&poly1305_key);

	assert!(process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 65).is_err());
}

#[test]
fn test_auth_process_ok_index_length() {
	let poly1305_key = poly1305_key_gen(&[0u8; 32], &[0u8; 12]).unwrap();
	let mut poly1305_state = poly1305::init(&poly1305_key);

	process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 64).unwrap();

	process_authentication(&mut poly1305_state, &[0u8; 0], &[0u8; 64], 0).unwrap();
}

#[test]
fn test_nonce_sizes() {
	assert!(Nonce::from_slice(&[0u8; 11]).is_err());
	assert!(Nonce::from_slice(&[0u8; 13]).is_err());
	assert!(Nonce::from_slice(&[0u8; 12]).is_ok());
}

#[test]
fn test_modified_tag_error() {
	let mut dst_out_ct = [0u8; 80]; // 64 + Poly1305TagLen
	let mut dst_out_pt = [0u8; 64];

	seal(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&[0u8; 64],
		None,
		&mut dst_out_ct,
	)
	.unwrap();
	// Modify the tags first byte
	dst_out_ct[65] ^= 1;
	assert!(open(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_ct,
		None,
		&mut dst_out_pt,
	)
	.is_err());
}

#[test]
fn test_bad_pt_ct_lengths() {
	let mut dst_out_ct_1 = [0u8; 79]; // 64 + Poly1305TagLen = 80
	let mut dst_out_ct_2 = [0u8; 80]; // 64 + Poly1305TagLen = 80

	let mut dst_out_pt_1 = [0u8; 63];
	let mut dst_out_pt_2 = [0u8; 64];

	assert!(seal(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_pt_2,
		Some(&[0u8; 5]),
		&mut dst_out_ct_1,
	)
	.is_err());

	seal(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_pt_2,
		Some(&[0u8; 5]),
		&mut dst_out_ct_2,
	)
	.unwrap();

	assert!(open(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_ct_2,
		Some(&[0u8; 5]),
		&mut dst_out_pt_1,
	)
	.is_err());

	open(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_ct_2,
		Some(&[0u8; 5]),
		&mut dst_out_pt_2,
	)
	.unwrap();
}

#[test]
fn test_bad_ct_length_and_empty_out_decrypt() {
	let dst_out_ct_1 = [0u8; POLY1305_BLOCKSIZE];
	let dst_out_ct_2 = [0u8; POLY1305_BLOCKSIZE - 1];
	let dst_out_ct_3 = [0u8; POLY1305_BLOCKSIZE + 1];

	let mut dst_out_pt_1 = [0u8; 64];
	let mut dst_out_pt_2 = [0u8; 0];

	assert!(open(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_ct_1,
		None,
		&mut dst_out_pt_1,
	)
	.is_err());

	assert!(open(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_ct_2,
		None,
		&mut dst_out_pt_1,
	)
	.is_err());

	assert!(open(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&dst_out_ct_3,
		None,
		&mut dst_out_pt_2,
	)
	.is_err());
}

#[test]
fn rfc_8439_test_poly1305_key_gen_1() {
	let key = [0u8; 32];
	let nonce = [
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	];
	let expected = [
		0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
		0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
		0x0d, 0xc7,
	];

	assert_eq!(
		poly1305_key_gen(&key, &nonce)
			.unwrap()
			.unprotected_as_bytes(),
		expected.as_ref()
	);
}

#[test]
fn rfc_8439_test_poly1305_key_gen_2() {
	let key = [
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01,
	];
	let nonce = [
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	];
	let expected = [
		0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74, 0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9, 0xe8,
		0x76, 0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87, 0xbc, 0x26, 0x66, 0xdd, 0xe3, 0xfb,
		0xb7, 0x39,
	];

	assert_eq!(
		poly1305_key_gen(&key, &nonce)
			.unwrap()
			.unprotected_as_bytes(),
		expected.as_ref()
	);
}

#[test]
fn rfc_8439_test_poly1305_key_gen_3() {
	let key = [
		0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5,
		0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70,
		0x75, 0xc0,
	];
	let nonce = [
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	];
	let expected = [
		0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9, 0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29, 0xf9,
		0x4b, 0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb, 0xdd, 0x59, 0xde, 0xaa, 0xd2, 0x33,
		0x10, 0xae,
	];

	assert_eq!(
		poly1305_key_gen(&key, &nonce)
			.unwrap()
			.unprotected_as_bytes(),
		expected.as_ref()
	);
}

#[test]
fn regression_detect_bigger_than_slice_bug() {
	let pt = [0x5B; 79];

	let mut dst_out_ct = [0u8; 79 + (POLY1305_BLOCKSIZE * 2)];

	seal(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&pt[..],
		None,
		&mut dst_out_ct,
	)
	.unwrap();

	// Verify that using a slice that is bigger than produces the exact same
	// output as using a slice that is the exact required length
	let mut dst_out_ct_2 = [0u8; 79 + POLY1305_BLOCKSIZE];

	seal(
		&SecretKey::from_slice(&[0u8; 32]).unwrap(),
		&Nonce::from_slice(&[0u8; 12]).unwrap(),
		&pt[..],
		None,
		&mut dst_out_ct_2,
	)
	.unwrap();

	assert!(dst_out_ct[..dst_out_ct_2.len()] == dst_out_ct_2[..]);
}
