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

pub mod other_chacha20;
pub mod other_hchacha20;
pub mod rfc_chacha20;
pub mod rfc_xchacha20;

extern crate hex;
extern crate orion;

use self::hex::decode;
use self::orion::hazardous::constants;
use self::orion::hazardous::stream::chacha20;
use self::orion::hazardous::stream::xchacha20;

pub fn chacha_test_runner(
    key: &[u8],
    nonce: &[u8],
    init_block_count: u32,
    pt: &mut [u8],
    ct: &mut [u8],
) {
    let original_pt = pt.to_vec();
    let original_ct = ct.to_vec();

    // Selecting variant based on nonce size
    if nonce.len() == constants::IETF_CHACHA_NONCESIZE {
        chacha20::encrypt(&key, &nonce, init_block_count, &original_pt, ct).unwrap();
        chacha20::decrypt(&key, &nonce, init_block_count, &original_ct, pt).unwrap();
    }
    if nonce.len() == constants::XCHACHA_NONCESIZE {
        xchacha20::encrypt(&key, &nonce, init_block_count, &original_pt, ct).unwrap();
        xchacha20::decrypt(&key, &nonce, init_block_count, &original_ct, pt).unwrap();
    }

    assert!(&original_pt == &pt);
    assert!(&original_ct == &ct);
}

pub fn hchacha_test_runner(key: &str, nonce: &str, output_expected: &str) {
    let actual: [u8; 32] =
        chacha20::hchacha20(&decode(key).unwrap(), &decode(nonce).unwrap()).unwrap();

    assert_eq!(&actual, &decode(output_expected).unwrap()[..]);
}
