// Testing against BoringSSL test vector from [boringssl](https://boringssl.googlesource.com/boringssl/+/master/crypto/poly1305/poly1305_tests.txt).
// Pulled at commit (master): 0f5ecd3a854546d943104e1f7421e489b7f4d5aa

use crate::mac::poly1305_test_runner;
use crate::TestCaseReader;

#[test]
fn test_boringssl_poly1305() {
    let boringssl_poly1305_fields: Vec<String> = vec!["Key".into(), "Input".into(), "MAC".into()];
    let mut boringssl_poly1305_reader = TestCaseReader::new(
        "./tests/test_data/third_party/google/boringssl/boringssl_poly1305_tests.txt",
        boringssl_poly1305_fields,
        "=",
    );

    let mut test_case = boringssl_poly1305_reader.next();
    while test_case.is_some() {
        let mut tc = test_case.unwrap();

        let key: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Key"));
        let input: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Input"));
        let expected_output: Vec<u8> = TestCaseReader::default_parse(tc.get_data("MAC"));

        if key.is_empty() {
            tc.outcome = false;
        }
        if expected_output.is_empty() {
            tc.outcome = false;
        }

        poly1305_test_runner(&key[..], &input[..], &expected_output[..]);

        // Read the next one
        test_case = boringssl_poly1305_reader.next();
    }
}
