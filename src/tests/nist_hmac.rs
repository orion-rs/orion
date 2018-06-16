// Copyright 2015-2016 Brian Smith.
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
use self::ring::{test, error};
use core::options::ShaVariantOption;
use hmac::Hmac;

fn hmac_test_runner(option: ShaVariantOption, key: &[u8], input: &[u8], output: &[u8], is_ok: bool)
                    -> Result<(), error::Unspecified> {

    let hmac = Hmac { secret_key: key.to_vec(), data: input.to_vec(), sha2: option };

    let digest = hmac.finalize();

    assert_eq!(is_ok, digest == output);

    // To conform with the Result construction of compare functions
    match is_ok {
        true => {
            assert_eq!(is_ok, hmac.verify(output).unwrap());
        },
        false => {
            assert!(hmac.verify(output).is_err());
        }
    }

    Ok(())

}

#[test]
fn hmac_tests() {
    test::from_file("src/tests/test_data/HMAC_fmt.rsp", |section, test_case| {
        assert_eq!(section, "");
        let digest_alg = test_case.consume_string("HMAC");
        let key_value = test_case.consume_bytes("Key");
        let mut input = test_case.consume_bytes("Input");
        let output = test_case.consume_bytes("Output");


        let alg = match digest_alg.as_ref() {
            "SHA256" => ShaVariantOption::SHA256,
            "SHA384" => ShaVariantOption::SHA384,
            "SHA512" => ShaVariantOption::SHA512,
            _ => panic!("option not found"),
        };

        hmac_test_runner(alg, &key_value[..], &input[..], &output[..], true)?;

        // Tamper with the input and check that verification fails
        if input.is_empty() {
            input.push(0);
        } else {
            input[0] ^= 1;
        }

        hmac_test_runner(alg, &key_value[..], &input[..], &output[..], false)
    });
}
