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
Some BoringSSL test vectors have been excluded form the original file. These include the first,
which is a RFC 7539 that is already tested in `rfc_aead_chacha20_poly1305.rs` and the tag-truncated
test vectors. Also, orion does not support empty input/output so any such test cases are not run
through here either.
*/

#[cfg(test)]
mod boringssl_aead_chacha20_poly1305 {

    extern crate ring;
    use self::ring::test;
    use aead::aead_test_runner as chacha20_poly1305_test_runner;

    #[test]
    fn boringssl_chacha20_poly1305() {
        test::from_file(
            "tests/test_data/boringssl_chacha20_poly1305_fmt.txt",
            |section, test_case| {
                assert_eq!(section, "");
                let key = test_case.consume_bytes("KEY");
                let nonce = test_case.consume_bytes("NONCE");
                let input = test_case.consume_bytes("IN");
                let aad = test_case.consume_bytes("AD");
                let output = test_case.consume_bytes("CT");
                let tag = test_case.consume_bytes("TAG");

                // orion doesn't support empty input/output
                if input.is_empty() && output.is_empty() {
                    Ok(())
                } else {
                    chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output)
                }
            },
        );
    }
}
