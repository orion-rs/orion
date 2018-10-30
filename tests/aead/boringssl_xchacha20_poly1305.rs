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

// Testing against BoringSSL test vectors from October 6th 2018

/*
Some BoringSSL test vectors have been excluded form the original file. orion does not support
empty input/output so any such test cases are not run through here either.
*/

#[cfg(test)]
mod boringssl_aead_xchacha20_poly1305 {

    extern crate orion;
    extern crate ring;

    use self::orion::hazardous::aead;
    use self::ring::{error, test};

    fn xchacha20_poly1305_test_runner(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
        input: &[u8],
        output: &[u8],
    ) -> Result<(), error::Unspecified> {
        let mut dst_ct_out = vec![0u8; input.len() + 16];
        let mut dst_pt_out = vec![0u8; input.len()];

        assert!(
            aead::xchacha20_poly1305_encrypt(key, nonce, input, aad, &mut dst_ct_out).is_ok()
        );
        assert!(dst_ct_out[..input.len()].as_ref() == output);
        assert!(dst_ct_out[input.len()..].as_ref() == tag);

        assert!(
            aead::xchacha20_poly1305_decrypt(key, nonce, &dst_ct_out, aad, &mut dst_pt_out)
                .is_ok()
        );
        assert!(dst_pt_out[..].as_ref() == input);

        Ok(())
    }

    #[test]
    fn boringssl_xchacha20_poly1305() {
        test::from_file(
            "tests/test_data/boringssl_xchacha20_poly1305_tests_fmt.txt",
            |section, test_case| {
                assert_eq!(section, "");
                let key = test_case.consume_bytes("KEY");
                let nonce = test_case.consume_bytes("NONCE");
                let input = test_case.consume_bytes("IN");
                let aad = test_case.consume_bytes("AD");
                let output = test_case.consume_bytes("CT");
                let tag = test_case.consume_bytes("TAG");

                // orion doesn't support empty input/output
                if input.is_empty() || output.is_empty() {
                    Ok(())
                } else {
                    xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output)
                }
            },
        );
    }
}
