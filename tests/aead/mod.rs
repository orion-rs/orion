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
extern crate ring;
use self::{
	aead::{
		chacha20poly1305::{self, SecretKey},
		xchacha20poly1305,
	},
	orion::hazardous::{aead, constants},
	ring::error,
};

fn aead_test_runner(
	key: &[u8],
	nonce: &[u8],
	aad: &[u8],
	tag: &[u8],
	input: &[u8],
	output: &[u8],
) -> Result<(), error::Unspecified> {
	let mut dst_ct_out = vec![0u8; input.len() + 16];
	let mut dst_pt_out = vec![0u8; input.len()];

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
	}

	if nonce.len() == constants::XCHACHA_NONCESIZE {
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
	}

	assert!(dst_ct_out[..input.len()].as_ref() == output);
	assert!(dst_ct_out[input.len()..].as_ref() == tag);
	assert!(dst_pt_out[..].as_ref() == input);

	Ok(())
}

/// Wycheproof only runs against ChaCha20Poly1305. So we don't need to check for
/// variants and we must be able to detect the test cases that have been marked
/// #[should_panic] in the Wycheproof test module.
fn wycheproof_test_runner(
	key: &[u8],
	nonce: &[u8],
	aad: &[u8],
	tag: &[u8],
	input: &[u8],
	output: &[u8],
) -> Result<(), error::Unspecified> {
	let mut dst_ct_out = vec![0u8; input.len() + 16];
	let mut dst_pt_out = vec![0u8; input.len()];

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
}
