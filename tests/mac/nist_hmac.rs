// Copyright 2015-2016 Brian Smith.
// Copyright (c) 2018 brycx
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Testing against NIST CAVP HMACVS test vectors
extern crate ring;

use self::ring::test;
use mac::hmac_test_runner;

#[test]
fn nist_hmac() {
    test::from_file("tests/test_data/HMAC_fmt.rsp", |section, test_case| {
        assert_eq!(section, "");
        let digest_alg = test_case.consume_string("HMAC");
        let key_value = test_case.consume_bytes("Key");
        let input = test_case.consume_bytes("Input");
        let output = test_case.consume_bytes("Output");
        // Only run if SHA512
        let run: bool = match digest_alg.as_ref() {
            "SHA256" => false,
            "SHA384" => false,
            "SHA512" => true,
            _ => panic!("option not found"),
        };

        if run {
            hmac_test_runner(&key_value[..], &input[..], &output[..], None)
        } else {
            Ok(())
        }
    });
}
