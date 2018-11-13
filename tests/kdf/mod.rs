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

pub mod custom_hkdf;
pub mod custom_pbkdf2;
pub mod other_hkdf;

extern crate orion;
use self::orion::hazardous::kdf::hkdf::*;
use self::orion::hazardous::mac::hmac;

pub fn hkdf_test_runner(
    excp_prk: Option<&[u8]>,
    excp_okm: &[u8],
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm_out: &mut [u8],
) -> bool {
    let actual_prk = extract(&Salt::from_slice(&salt), &ikm);

    if excp_prk.is_some() {
        assert!(actual_prk == hmac::Mac::from_slice(excp_prk.unwrap()).unwrap());
    }

    expand(&actual_prk, Some(&info), okm_out).unwrap();

    let mut okm_one_shot_dst = okm_out.to_vec();
    derive_key(&Salt::from_slice(&salt), ikm, Some(&info), &mut okm_one_shot_dst).unwrap();

    ((okm_out == excp_okm) == (okm_one_shot_dst == excp_okm))
}
