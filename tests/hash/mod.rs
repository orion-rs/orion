pub mod blake2b_kat;
pub mod other_blake2b;
pub mod sha256_nist_cavp;
pub mod sha384_nist_cavp;
pub mod sha512_nist_cavp;

use crate::TestCaseReader;
use orion::hazardous::hash::{blake2, sha2::sha256, sha2::sha384, sha2::sha512};
use orion::hazardous::mac;

fn blake2b_test_runner(input: &[u8], key: &[u8], output: &[u8]) {
    // Only make SecretKey if test case key value is not empty.
    if key.is_empty() {
        let mut state = blake2::blake2b::Blake2b::new(output.len()).unwrap();
        state.update(input).unwrap();
        let digest = state.finalize().unwrap();
        assert_eq!(digest.len(), output.len());
        assert_eq!(digest.as_ref(), &output[..]);
    } else {
        let secret_key = mac::blake2b::SecretKey::from_slice(key).unwrap();
        let mut state = mac::blake2b::Blake2b::new(&secret_key, output.len()).unwrap();
        state.update(input).unwrap();
        let tag = state.finalize().unwrap();
        assert_eq!(tag.len(), output.len());
        assert_eq!(tag.unprotected_as_bytes(), &output[..]);
    }
}

fn sha512_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha512::Sha512::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha512::Sha512::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha256_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha256::Sha256::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha256::Sha256::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha384_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha384::Sha384::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha384::Sha384::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

/// NISTs SHA256/384/512 Long/Short share the same format,
/// so fields and separator remain the same.
fn nist_cavp_runner(path: &str) {
    let nist_cavp_fields: Vec<String> = vec!["Len".into(), "Msg".into(), "MD".into()];
    let mut nist_cavp_reader = TestCaseReader::new(path, nist_cavp_fields, "=");

    let mut test_case = nist_cavp_reader.next();
    // Check that we actually ran any of the SHA2 test runners.
    let mut ran_any_runner = false;
    while test_case.is_some() {
        let tc = test_case.unwrap();

        let input: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Msg"));
        let expected_output: Vec<u8> = TestCaseReader::default_parse(tc.get_data("MD"));

        if path.contains("SHA256") {
            sha256_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }
        if path.contains("SHA384") {
            sha384_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }
        if path.contains("SHA512") {
            sha512_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }

        assert!(ran_any_runner);
        // Read the next one
        test_case = nist_cavp_reader.next();
    }
}
