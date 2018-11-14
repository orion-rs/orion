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

pub mod nist_hmac;
pub mod other_poly1305;
pub mod rfc_hmac;
pub mod rfc_poly1305;

extern crate orion;
extern crate ring;

use self::orion::hazardous::mac::hmac;
use self::orion::hazardous::mac::poly1305;
use self::poly1305::OneTimeKey;
use self::poly1305::Tag;
use self::ring::error;

fn hmac_test_runner(
    secret_key: &[u8],
    data: &[u8],
    expected: &[u8],
    trunc: Option<usize>,
) -> Result<(), error::Unspecified> {
    let mut mac = hmac::init(&hmac::SecretKey::from_slice(secret_key));
    mac.update(data).unwrap();

    let res = mac.finalize().unwrap();
    let len = match trunc {
        Some(ref length) => *length,
        None => 64,
    };

    assert_eq!(
        res.unsafe_as_bytes()[..len].as_ref(),
        expected[..len].as_ref()
    );
    // If the MACs are modified, then they should not be equal to the expected
    let mut bad_res = res.unsafe_as_bytes()[..len].to_vec();
    bad_res[0] ^= 1;
    assert_ne!(&bad_res[..len], expected);

    Ok(())
}

fn poly1305_test_runner(key: &[u8], input: &[u8], output: &[u8]) -> Result<(), error::Unspecified> {
    let mut state = poly1305::init(&OneTimeKey::from_slice(key).unwrap()).unwrap();
    state.update(input).unwrap();

    let tag_stream = state.finalize().unwrap();
    let tag_one_shot = poly1305::poly1305(&OneTimeKey::from_slice(key).unwrap(), input).unwrap();

    assert!(tag_stream == Tag::from_slice(&output).unwrap());
    assert!(tag_one_shot == Tag::from_slice(&output).unwrap());
    assert!(poly1305::verify(
        &Tag::from_slice(&output).unwrap(),
        &OneTimeKey::from_slice(key).unwrap(),
        input
    )
    .unwrap());

    // If the MACs are modified, then they should not be equal to the expected
    let mut bad_tag = tag_stream.unsafe_as_bytes();
    bad_tag[0] ^= 1;
    assert!(Tag::from_slice(&bad_tag).unwrap() != Tag::from_slice(&output).unwrap());

    Ok(())
}
