extern crate orion;

use self::orion::hazardous::{
    mac::poly1305::POLY1305_OUTSIZE,
    stream::{
        chacha20::{CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE},
        xchacha20::XCHACHA_NONCESIZE,
    },
};
use crate::aead::wycheproof_test_runner;
use crate::TestCaseReader;

/// BoringSSLs ChaCha20Poly1305 and XChaCha20Poly1305 share the same format
/// so the fields and separator remain the same.
fn boringssl_runner(path: &str, is_ietf: bool) {
    let boringssl_fields: Vec<String> = vec![
        "KEY".into(),
        "NONCE".into(),
        "IN".into(),
        "AD".into(),
        "CT".into(),
        "TAG".into(),
    ];

    let mut boringssl_reader = TestCaseReader::new(path, boringssl_fields, ":");

    let mut test_case = boringssl_reader.next();
    while test_case.is_some() {
        let mut tc = test_case.unwrap();

        let key: Vec<u8> = TestCaseReader::default_parse(tc.get_data("KEY"));
        let nonce: Vec<u8> = TestCaseReader::default_parse(tc.get_data("NONCE"));
        let input: Vec<u8> = TestCaseReader::default_parse(tc.get_data("IN"));
        let ad: Vec<u8> = TestCaseReader::default_parse(tc.get_data("AD"));
        let expected_output: Vec<u8> = TestCaseReader::default_parse(tc.get_data("CT"));
        let tag: Vec<u8> = TestCaseReader::default_parse(tc.get_data("TAG"));

        // Sanity check to make we actually got any values
        assert!(!key.is_empty());
        assert!(!nonce.is_empty());
        assert!(!tag.is_empty());

        if key.len() != CHACHA_KEYSIZE {
            tc.outcome = false;
        }
        if is_ietf && (nonce.len() != IETF_CHACHA_NONCESIZE) {
            tc.outcome = false;
        }
        if !is_ietf && (nonce.len() != XCHACHA_NONCESIZE) {
            tc.outcome = false;
        }
        if tag.len() != POLY1305_OUTSIZE {
            tc.outcome = false;
        }

        assert!(wycheproof_test_runner(
            &key[..],
            &nonce[..],
            &ad[..],
            &tag[..],
            &input[..],
            &expected_output[..],
            tc.outcome,
            tc.test_case_number,
            is_ietf,
        )
        .is_ok());

        // Read the next one
        test_case = boringssl_reader.next();
    }
}

#[test]
fn test_chacha20poly1305() {
    boringssl_runner(
        "./tests/test_data/third_party/google/boringssl/boringssl_chacha20_poly1305.txt",
        true,
    );
}

#[test]
fn test_xchacha20poly1305() {
    boringssl_runner(
        "./tests/test_data/third_party/google/boringssl/boringssl_xchacha20_poly1305.txt",
        false,
    );
}
