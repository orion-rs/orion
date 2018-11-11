// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

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
use self::aead::chacha20poly1305::SecretKey;
use self::orion::hazardous::aead;
use self::orion::hazardous::constants;
use self::ring::error;

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
        assert!(
            aead::chacha20poly1305::encrypt(
                SecretKey::from_slice(key).unwrap(),
                nonce,
                input,
                aad,
                &mut dst_ct_out
            ).is_ok()
        );
        assert!(
            aead::chacha20poly1305::decrypt(
                SecretKey::from_slice(key).unwrap(),
                nonce,
                &dst_ct_out,
                aad,
                &mut dst_pt_out
            ).is_ok()
        );
    }

    if nonce.len() == constants::XCHACHA_NONCESIZE {
        assert!(
            aead::xchacha20poly1305::encrypt(
                SecretKey::from_slice(key).unwrap(),
                nonce,
                input,
                aad,
                &mut dst_ct_out
            ).is_ok()
        );

        assert!(
            aead::xchacha20poly1305::decrypt(
                SecretKey::from_slice(key).unwrap(),
                nonce,
                &dst_ct_out,
                aad,
                &mut dst_pt_out
            ).is_ok()
        );
    }

    assert!(dst_ct_out[..input.len()].as_ref() == output);
    assert!(dst_ct_out[input.len()..].as_ref() == tag);
    assert!(dst_pt_out[..].as_ref() == input);

    Ok(())
}
