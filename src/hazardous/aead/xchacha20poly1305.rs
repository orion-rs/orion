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
//!   `None`. This data is also not a part of `dst_out`).
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
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext + 16` when encrypting.
//! - The length of `dst_out` is less than `ciphertext_with_tag - 16` when
//!   decrypting.
//! - The length of `ciphertext_with_tag` is not greater than `16`.
//! - `plaintext` or `ciphertext_with_tag` are empty.
//! - The received tag does not match the calculated tag when decrypting.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^32-1 * 64 bytes of data are processed.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - Only a nonce for XChaCha20Poly1305 is big enough to be randomly generated
//!   using a CSPRNG.
//! [`Nonce::generate()`] can be used for this.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//!
//! # Recommendation:
//! - It is recommended to use XChaCha20Poly1305 when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::aead;
//!
//! let secret_key = aead::xchacha20poly1305::SecretKey::generate();
//! let nonce = aead::xchacha20poly1305::Nonce::generate();
//! let ad = "Additional data".as_bytes();
//! let message = "Data to protect".as_bytes();
//!
//! // Length of above message is 15 and then we accomodate 16 for the Poly1305
//! // tag.
//!
//! let mut dst_out_ct = [0u8; 15 + 16];
//! let mut dst_out_pt = [0u8; 15];
//! // Encrypt and place ciphertext + tag in dst_out_ct
//! aead::xchacha20poly1305::seal(&secret_key, &nonce, message, Some(&ad), &mut dst_out_ct)?;
//! // Verify tag, if correct then decrypt and place message in dst_out_pt
//! aead::xchacha20poly1305::open(&secret_key, &nonce, &dst_out_ct, Some(&ad), &mut dst_out_pt)?;
//!
//! assert_eq!(dst_out_pt.as_ref(), message.as_ref());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: ../../stream/chacha20/struct.SecretKey.html
//! [`Nonce::generate()`]: ../../stream/xchacha20/struct.Nonce.html
use crate::hazardous::stream::xchacha20::subkey_and_nonce;
pub use crate::hazardous::stream::{chacha20::SecretKey, xchacha20::Nonce};
use crate::{errors::UnknownCryptoError, hazardous::aead::chacha20poly1305};

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// AEAD XChaCha20Poly1305 encryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn seal(
	secret_key: &SecretKey,
	nonce: &Nonce,
	plaintext: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	let (subkey, ietf_nonce) = subkey_and_nonce(secret_key, nonce);

	chacha20poly1305::seal(&subkey, &ietf_nonce, plaintext, ad, dst_out)
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// AEAD XChaCha20Poly1305 decryption as specified in the [draft RFC](https://github.com/bikeshedders/xchacha-rfc).
pub fn open(
	secret_key: &SecretKey,
	nonce: &Nonce,
	ciphertext_with_tag: &[u8],
	ad: Option<&[u8]>,
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	let (subkey, ietf_nonce) = subkey_and_nonce(secret_key, nonce);

	chacha20poly1305::open(&subkey, &ietf_nonce, ciphertext_with_tag, ad, dst_out)
}

// Testing public functions in the module.
#[cfg(test)]
#[cfg(feature = "safe_api")]
mod public {
	use super::*;

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use super::*;
		use crate::hazardous::mac::poly1305::POLY1305_OUTSIZE;
		use crate::test_framework::aead_interface::*;

		quickcheck! {
			fn prop_aead_interface(input: Vec<u8>, ad: Vec<u8>) -> bool {
				let secret_key = SecretKey::generate();
				let nonce = Nonce::generate();
				AeadTestRunner(seal, open, secret_key, nonce, &input, None, POLY1305_OUTSIZE, &ad);

				true
			}
		}
	}
}
