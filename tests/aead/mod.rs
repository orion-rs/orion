// Copyright (c) 2018 brycx

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

pub mod boringssl_chacha20_poly1305;
pub mod boringssl_xchacha20_poly1305;
pub mod other_aead_xchacha20_poly1305;
pub mod rfc_aead_chacha20_poly1305;
pub mod wycheproof_chacha20_poly1305;

extern crate orion;
use self::{
	aead::{
		chacha20poly1305::{self, SecretKey},
		xchacha20poly1305,
	},
	orion::{
		errors::UnknownCryptoError,
		hazardous::{aead, constants},
	},
};

fn aead_test_runner(
	key: &[u8],
	nonce: &[u8],
	aad: &[u8],
	tag: &[u8],
	input: &[u8],
	output: &[u8],
) -> Result<(), UnknownCryptoError> {
	let mut dst_ct_out = vec![0u8; input.len() + 16];
	let mut dst_pt_out = vec![0u8; input.len()];

	// Make sure the boringssl parameters are acceptable
	if (key.len() != 32) || (tag.len() != 16) {
		// Should fail if key is of invalid length
		if key.len() != 32 {
			assert!(aead::chacha20poly1305::seal(
				&SecretKey::from_slice(&key).unwrap(),
				&chacha20poly1305::Nonce::from_slice(&nonce).unwrap(),
				input,
				Some(aad),
				&mut dst_ct_out,
			)
			.is_err());
		}
		return Ok(());
	}

	// Determine variant based on NONCE size
	if nonce.len() == constants::IETF_CHACHA_NONCESIZE {
		aead::chacha20poly1305::seal(
			&SecretKey::from_slice(&key).unwrap(),
			&chacha20poly1305::Nonce::from_slice(&nonce).unwrap(),
			input,
			Some(aad),
			&mut dst_ct_out,
		)
		.unwrap();
		aead::chacha20poly1305::open(
			&SecretKey::from_slice(&key).unwrap(),
			&chacha20poly1305::Nonce::from_slice(&nonce).unwrap(),
			&dst_ct_out,
			Some(aad),
			&mut dst_pt_out,
		)
		.unwrap();

		assert!(dst_ct_out[..input.len()].as_ref() == output);
		assert!(dst_ct_out[input.len()..].as_ref() == tag);
		assert!(dst_pt_out[..].as_ref() == input);

		Ok(())
	} else if nonce.len() == constants::XCHACHA_NONCESIZE {
		aead::xchacha20poly1305::seal(
			&SecretKey::from_slice(&key).unwrap(),
			&xchacha20poly1305::Nonce::from_slice(&nonce).unwrap(),
			input,
			Some(aad),
			&mut dst_ct_out,
		)
		.unwrap();

		aead::xchacha20poly1305::open(
			&SecretKey::from_slice(&key).unwrap(),
			&xchacha20poly1305::Nonce::from_slice(&nonce).unwrap(),
			&dst_ct_out,
			Some(aad),
			&mut dst_pt_out,
		)
		.unwrap();

		assert!(dst_ct_out[..input.len()].as_ref() == output);
		assert!(dst_ct_out[input.len()..].as_ref() == tag);
		assert!(dst_pt_out[..].as_ref() == input);

		Ok(())

	// If the nonce is not of valid legnth, check for expected fail
	} else {
		assert!(aead::chacha20poly1305::seal(
			&SecretKey::from_slice(&key).unwrap(),
			&chacha20poly1305::Nonce::from_slice(&nonce).unwrap(),
			input,
			Some(aad),
			&mut dst_ct_out,
		)
		.is_err());

		Ok(())
	}
}

fn wycheproof_test_runner(
	key: &[u8],
	nonce: &[u8],
	aad: &[u8],
	tag: &[u8],
	input: &[u8],
	output: &[u8],
	result: bool,
	tcid: u64,
) -> Result<(), UnknownCryptoError> {
	// Leave test vectors out that have empty input/output and are otherwise valid
	// since orion does not accept this. This will be test cases with "tcId" = 2, 3.
	if result {
		if input.is_empty() && output.is_empty() {
			return Ok(());
		}
	}

	let mut dst_ct_out = vec![0u8; input.len() + 16];
	let mut dst_pt_out = vec![0u8; input.len()];

	if result {
		aead::chacha20poly1305::seal(
			&SecretKey::from_slice(&key)?,
			&chacha20poly1305::Nonce::from_slice(&nonce)?,
			input,
			Some(aad),
			&mut dst_ct_out,
		)?;

		aead::chacha20poly1305::open(
			&SecretKey::from_slice(&key)?,
			&chacha20poly1305::Nonce::from_slice(&nonce)?,
			&dst_ct_out,
			Some(aad),
			&mut dst_pt_out,
		)?;

		assert!(dst_ct_out[..input.len()].as_ref() == output);
		assert!(dst_ct_out[input.len()..].as_ref() == tag);
		assert!(dst_pt_out[..].as_ref() == input);
	} else {
		let new_key = SecretKey::from_slice(&key);
		let new_nonce = chacha20poly1305::Nonce::from_slice(&nonce);

		// Detecting cases where there is invalid size of nonce and/or key
		if new_key.is_err() || new_nonce.is_err() {
			return Ok(());
		}

		let encryption = aead::chacha20poly1305::seal(
			&new_key.unwrap(),
			&new_nonce.unwrap(),
			input,
			Some(aad),
			&mut dst_ct_out,
		);
		// Because of the early return, there is no need to check for invalid size of
		// nonce and/or key
		let decryption = aead::chacha20poly1305::open(
			&SecretKey::from_slice(&key)?,
			&chacha20poly1305::Nonce::from_slice(&nonce)?,
			&dst_ct_out,
			Some(aad),
			&mut dst_pt_out,
		);

		// Test case results may be invalid, but this does not mean both seal() and
		// open() fails. We use a match arm to allow failure combinations, with
		// possible successfull calls, but never a combination of two successfull
		// calls where the output matches the expected values.
		match (encryption, decryption) {
			(Ok(_), Err(_)) => (),
			(Err(_), Ok(_)) => (),
			(Err(_), Err(_)) => (),
			(Ok(_), Ok(_)) => {
				let is_ct_same = dst_ct_out[..input.len()].as_ref() == output;
				let is_tag_same = dst_ct_out[input.len()..].as_ref() == tag;
				let is_decrypted_same = dst_pt_out[..].as_ref() == input;
				// In this case a test vector reported as invalid by Wycheproof would be
				// accepted by orion.
				if is_ct_same && is_decrypted_same && is_tag_same {
					panic!("Unallowed test result! {:?}", tcid);
				}
			}
		}
	}

	Ok(())
}
