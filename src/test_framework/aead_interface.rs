// MIT License

// Copyright (c) 2019-2025 The orion Developers

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

#[cfg(test)]
#[cfg(feature = "safe_api")]
use crate::test_framework::streamcipher_interface::TestingRandom;

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "safe_api")]
/// Test runner for AEADs.
pub fn AeadTestRunner<Sealer, Opener, Key, Nonce>(
    sealer: Sealer,
    opener: Opener,
    key: Key,
    nonce: Nonce,
    input: &[u8],
    expected_ct_with_tag: Option<&[u8]>,
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    seal_dst_out_length(&sealer, &key, &nonce, input, tag_size, aad);
    open_dst_out_length(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    open_modified_tag_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    open_modified_ciphertext_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    open_modified_aad_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    none_or_empty_some_aad_same_result(&sealer, &opener, &key, &nonce, input, tag_size);
    seal_open_equals_expected(
        &sealer,
        &opener,
        &key,
        &nonce,
        input,
        expected_ct_with_tag,
        tag_size,
        aad,
    );
    seal_plaintext_length(&sealer, &key, &nonce, tag_size, aad);
    open_ciphertext_with_tag_length(&sealer, &opener, &key, &nonce, tag_size, aad);
}

#[cfg(feature = "safe_api")]
/// Related bug: <https://github.com/orion-rs/orion/issues/52>
/// Test dst_out mutable array sizes when using seal().
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
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct).is_ok());

    let mut dst_out_ct_more = vec![0u8; input.len() + (tag_size + 1)];
    // Related bug: #52
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct_more).is_ok());

    let mut dst_out_ct_more_double = vec![0u8; input.len() + (tag_size * 2)];
    // Related bug: #52
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct_more_double).is_ok());

    let mut dst_out_ct_less = vec![0u8; input.len() + (tag_size - 1)];
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct_less).is_err());
}

#[cfg(feature = "safe_api")]
/// Related bug: <https://github.com/orion-rs/orion/issues/52>
/// Test input sizes when using seal().
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
    assert!(sealer(key, nonce, &input_0, default_aad, &mut dst_out_ct_0).is_ok());

    let input_1 = vec![0u8; 1];
    let mut dst_out_ct_1 = vec![0u8; input_1.len() + tag_size];
    assert!(sealer(key, nonce, &input_1, default_aad, &mut dst_out_ct_1).is_ok());

    let input_128 = vec![0u8; 128];
    let mut dst_out_ct_128 = vec![0u8; input_128.len() + tag_size];
    assert!(sealer(key, nonce, &input_128, default_aad, &mut dst_out_ct_128).is_ok());
}

#[cfg(feature = "safe_api")]
/// Related bug: <https://github.com/orion-rs/orion/issues/52>
/// Test dst_out mutable array sizes when using open().
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
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();

    let mut dst_out_pt = vec![0u8; input.len()];
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_ok());

    let mut dst_out_pt_0 = [0u8; 0];
    let empty_out_res = opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt_0);
    if input.is_empty() {
        assert!(empty_out_res.is_ok());
    } else {
        assert!(empty_out_res.is_err());
    }

    if !input.is_empty() {
        let mut dst_out_pt_less = vec![0u8; input.len() - 1];
        assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt_less).is_err());
    }

    let mut dst_out_pt_more = vec![0u8; input.len() + 1];
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt_more).is_ok());
}

#[cfg(feature = "safe_api")]
/// Test input sizes when using open().
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
    let mut dst_out_pt = vec![0u8; tag_size];

    assert!(opener(key, nonce, &[0u8; 0], default_aad, &mut dst_out_pt).is_err());

    assert!(opener(
        key,
        nonce,
        &vec![0u8; tag_size - 1],
        default_aad,
        &mut dst_out_pt
    )
    .is_err());

    let mut dst_out_ct = vec![0u8; tag_size];
    sealer(key, nonce, &[0u8; 0], default_aad, &mut dst_out_ct).unwrap();

    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_ok());
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "safe_api")]
/// Test that sealing and opening produces the expected ciphertext.
fn seal_open_equals_expected<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    expected_ct_with_tag: Option<&[u8]>,
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();
    if let Some(expected) = expected_ct_with_tag {
        assert_eq!(expected, &dst_out_ct[..]);
    }

    let mut dst_out_pt = input.to_vec();
    opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).unwrap();
    assert_eq!(input, &dst_out_pt[..]);
    if let Some(expected) = expected_ct_with_tag {
        opener(key, nonce, expected, default_aad, &mut dst_out_pt).unwrap();
        assert_eq!(input, &dst_out_pt[..]);
    }
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
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();
    // Modify the first byte of the authentication tag.
    dst_out_ct[input.len() + 1] ^= 1;

    let mut dst_out_pt = input.to_vec();
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_err());
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
    let mut input = input;
    if input.is_empty() {
        input = &[0u8; 1];
    }
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();
    // Modify the first byte of the ciphertext.
    dst_out_ct[0] ^= 1;

    let mut dst_out_pt = input.to_vec();
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_err());
}

#[cfg(feature = "safe_api")]
/// When opening sealed data with modified aad, an error should be returned.
fn open_modified_aad_err<Sealer, Opener, Key, Nonce>(
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
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();

    let mut dst_out_pt = input.to_vec();
    assert!(opener(key, nonce, &dst_out_ct, Some(b"BAD AAD"), &mut dst_out_pt).is_err());
}

#[cfg(feature = "safe_api")]
/// Using None or Some with empty slice should produce the exact same result.
fn none_or_empty_some_aad_same_result<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    tag_size: usize,
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let mut dst_out_ct_none = vec![0u8; input.len() + tag_size];
    let mut dst_out_ct_some_empty = vec![0u8; input.len() + tag_size];

    sealer(key, nonce, input, None, &mut dst_out_ct_none).unwrap();
    sealer(
        key,
        nonce,
        input,
        Some(&[0u8; 0]),
        &mut dst_out_ct_some_empty,
    )
    .unwrap();

    assert_eq!(dst_out_ct_none, dst_out_ct_some_empty);

    let mut dst_out_pt = vec![0u8; input.len()];
    assert!(opener(
        key,
        nonce,
        &dst_out_ct_none,
        Some(&[0u8; 0]),
        &mut dst_out_pt
    )
    .is_ok());
    assert!(opener(key, nonce, &dst_out_ct_some_empty, None, &mut dst_out_pt).is_ok());
}

#[cfg(test)]
#[cfg(feature = "safe_api")]
/// Test that sealing and opening with different secret-key/nonce yields an error.
pub fn test_diff_params_err<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    input: &[u8],
    tag_size: usize,
) where
    Key: TestingRandom + PartialEq<Key>,
    Nonce: TestingRandom + PartialEq<Nonce>,
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let sk1 = Key::gen();
    let sk2 = Key::gen();
    assert!(sk1 != sk2);

    let n1 = Nonce::gen();
    let n2 = Nonce::gen();
    assert!(n1 != n2);

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    let mut dst_out_pt = vec![0u8; input.len()];

    // Different secret key
    sealer(&sk1, &n1, input, None, &mut dst_out_ct).unwrap();
    assert!(opener(&sk2, &n1, &dst_out_ct, None, &mut dst_out_pt).is_err());

    // Different nonce
    sealer(&sk1, &n1, input, None, &mut dst_out_ct).unwrap();
    assert!(opener(&sk1, &n2, &dst_out_ct, None, &mut dst_out_pt).is_err());
}
