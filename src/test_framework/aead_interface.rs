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

#![allow(non_snake_case)]
#[cfg(feature = "safe_api")]
use crate::errors::UnknownCryptoError;

#[cfg(feature = "safe_api")]
///
pub fn AeadTestRunner<Sealer, Opener, Key, Nonce>(
	sealer: Sealer,
	opener: Opener,
	key: Key,
	nonce: Nonce,
	input: &[u8],
	expected_with_tag: Option<&[u8]>,
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
	Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	// Skip tests that require non-empty input.
	// The tests that check for behavior in empty and non-empty
	// input, do not take an input parameter for that reason.
	if !input.is_empty() {
		seal_dst_out_length(&sealer, &key, &nonce, input, tag_size, aad);
		open_dst_out_length(&sealer, &opener, &key, &nonce, input, tag_size, aad);
		seal_open_same_plaintext(&sealer, &opener, &key, &nonce, input, tag_size, aad);
		open_modified_tag_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
		open_modified_ciphertext_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
		if let Some(expected_with_tag_result) = expected_with_tag {
			seal_open_equals_expected(
				&sealer,
				&opener,
				&key,
				&nonce,
				&input,
				expected_with_tag_result,
				tag_size,
				aad,
			);
		}
	}
	seal_plaintext_length(&sealer, &key, &nonce, tag_size, aad);
	open_ciphertext_with_tag_length(&sealer, &opener, &key, &nonce, tag_size, aad);
}

#[cfg(feature = "safe_api")]
/// Related bug: https://github.com/brycx/orion/issues/52
fn seal_dst_out_length<Sealer, Key, Nonce>(
	sealer: &Sealer,
	key: &Key,
	nonce: &Nonce,
	input: &[u8],
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	assert!(!input.is_empty());
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let mut dst_out_ct = vec![0u8; input.len() + tag_size];
	assert!(sealer(&key, &nonce, input, default_aad, &mut dst_out_ct).is_ok());

	let mut dst_out_ct_more = vec![0u8; input.len() + (tag_size + 1)];
	// Related bug: #52
	assert!(sealer(&key, &nonce, input, default_aad, &mut dst_out_ct_more).is_ok());

	let mut dst_out_ct_more_double = vec![0u8; input.len() + (tag_size * 2)];
	// Related bug: #52
	assert!(sealer(
		&key,
		&nonce,
		input,
		default_aad,
		&mut dst_out_ct_more_double
	)
	.is_ok());

	let mut dst_out_ct_less = vec![0u8; input.len() + (tag_size - 1)];
	assert!(sealer(&key, &nonce, input, default_aad, &mut dst_out_ct_less).is_err());
}

#[cfg(feature = "safe_api")]
/// Related bug: https://github.com/brycx/orion/issues/52
fn seal_plaintext_length<Sealer, Key, Nonce>(
	sealer: &Sealer,
	key: &Key,
	nonce: &Nonce,
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let input_0 = vec![0u8; 0];
	let mut dst_out_ct_0 = vec![0u8; input_0.len() + tag_size];
	assert!(sealer(&key, &nonce, &input_0, default_aad, &mut dst_out_ct_0).is_err());

	let input_1 = vec![0u8; 1];
	let mut dst_out_ct_1 = vec![0u8; input_1.len() + tag_size];
	assert!(sealer(&key, &nonce, &input_1, default_aad, &mut dst_out_ct_1).is_ok());

	let input_128 = vec![0u8; 128];
	let mut dst_out_ct_128 = vec![0u8; input_128.len() + tag_size];
	assert!(sealer(&key, &nonce, &input_128, default_aad, &mut dst_out_ct_128).is_ok());
}

#[cfg(feature = "safe_api")]
/// Related bug: https://github.com/brycx/orion/issues/52
fn open_dst_out_length<Sealer, Opener, Key, Nonce>(
	sealer: &Sealer,
	opener: &Opener,
	key: &Key,
	nonce: &Nonce,
	input: &[u8],
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
	Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	assert!(!input.is_empty());
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let mut dst_out_ct = vec![0u8; input.len() + tag_size];
	sealer(&key, &nonce, input, default_aad, &mut dst_out_ct).unwrap();

	let mut dst_out_pt = vec![0u8; input.len()];
	assert!(opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_ok());

	let mut dst_out_pt_0 = [0u8; 0];
	assert!(opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt_0).is_err());

	let mut dst_out_pt_less = vec![0u8; input.len() - 1];
	assert!(opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt_less).is_err());

	let mut dst_out_pt_more = vec![0u8; input.len() + 1];
	assert!(opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt_more).is_ok());
}

#[cfg(feature = "safe_api")]
fn open_ciphertext_with_tag_length<Sealer, Opener, Key, Nonce>(
	sealer: &Sealer,
	opener: &Opener,
	key: &Key,
	nonce: &Nonce,
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
	Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let mut dst_out_pt = vec![0u8; 64];
	// Empty input
	assert!(opener(&key, &nonce, &[0u8; 0], default_aad, &mut dst_out_pt).is_err());

	assert!(opener(
		&key,
		&nonce,
		&vec![0u8; tag_size], // Only tagsize, must be at least + 1.
		default_aad,
		&mut dst_out_pt
	)
	.is_err());

	assert!(opener(
		&key,
		&nonce,
		&vec![0u8; tag_size - 1],
		default_aad,
		&mut dst_out_pt
	)
	.is_err());

	let mut dst_out_ct = vec![0u8; dst_out_pt.len() + tag_size];
	sealer(
		&key,
		&nonce,
		&vec![0u8; tag_size + 1],
		default_aad,
		&mut dst_out_ct,
	)
	.unwrap();

	assert!(opener(
		&key,
		&nonce,
		&dst_out_ct[..(tag_size + 1) + tag_size],
		default_aad,
		&mut dst_out_pt
	)
	.is_ok());
}

#[cfg(feature = "safe_api")]
/// Test that sealing and opening produces the correct plaintext.
fn seal_open_same_plaintext<Sealer, Opener, Key, Nonce>(
	sealer: &Sealer,
	opener: &Opener,
	key: &Key,
	nonce: &Nonce,
	input: &[u8],
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
	Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	assert!(!input.is_empty());
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let mut dst_out_ct = vec![0u8; input.len() + tag_size];
	sealer(&key, &nonce, input, default_aad, &mut dst_out_ct).unwrap();

	let mut dst_out_pt = input.to_vec();
	opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt).unwrap();

	assert_eq!(input, &dst_out_pt[..]);
}

#[cfg(feature = "safe_api")]
/// Test that sealing and opening produces the expected ciphertext/plaintext.
fn seal_open_equals_expected<Sealer, Opener, Key, Nonce>(
	sealer: &Sealer,
	opener: &Opener,
	key: &Key,
	nonce: &Nonce,
	input: &[u8],
	expected_with_tag: &[u8],
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
	Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	assert!(!input.is_empty());
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let mut dst_out_ct = vec![0u8; input.len() + tag_size];
	sealer(&key, &nonce, input, default_aad, &mut dst_out_ct).unwrap();
	assert_eq!(expected_with_tag, &dst_out_ct[..]);

	let mut dst_out_pt = input.to_vec();
	opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt).unwrap();
	assert_eq!(input, &dst_out_pt[..]);
}

#[cfg(feature = "safe_api")]
/// When opening sealed data with a modified tag, an error should be returned.
fn open_modified_tag_err<Sealer, Opener, Key, Nonce>(
	sealer: &Sealer,
	opener: &Opener,
	key: &Key,
	nonce: &Nonce,
	input: &[u8],
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
	Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	assert!(!input.is_empty());
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let mut dst_out_ct = vec![0u8; input.len() + tag_size];
	sealer(&key, &nonce, input, default_aad, &mut dst_out_ct).unwrap();
	// Modify the first byte of the authentication tag.
	dst_out_ct[input.len() + 1] ^= 1;

	let mut dst_out_pt = input.to_vec();
	assert!(opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_err());
}

#[cfg(feature = "safe_api")]
/// When opening sealed data with a modified ciphertext, an error should be returned.
fn open_modified_ciphertext_err<Sealer, Opener, Key, Nonce>(
	sealer: &Sealer,
	opener: &Opener,
	key: &Key,
	nonce: &Nonce,
	input: &[u8],
	tag_size: usize,
	aad: &[u8],
) where
	Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
	Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
	assert!(!input.is_empty());
	let default_aad = if aad.is_empty() { None } else { Some(aad) };

	let mut dst_out_ct = vec![0u8; input.len() + tag_size];
	sealer(&key, &nonce, input, default_aad, &mut dst_out_ct).unwrap();
	// Modify the first byte of the ciphertext.
	dst_out_ct[0] ^= 1;

	let mut dst_out_pt = input.to_vec();
	assert!(opener(&key, &nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_err());
}
