pub mod blake2b_kat;
pub mod other_blake2b;
pub mod sha512_nist_cavp;

use orion::hazardous::hash::{blake2b, sha512, sha256};
use crate::TestCaseReader;

fn blake2b_test_runner(input: &[u8], key: &[u8], output: &[u8]) {
    // Only make SecretKey if test case key value is not empty.
    let mut state = if key.is_empty() {
        blake2b::Blake2b::new(None, output.len()).unwrap()
    } else {
        let secret_key = blake2b::SecretKey::from_slice(key).unwrap();
        blake2b::Blake2b::new(Some(&secret_key), output.len()).unwrap()
    };

    state.update(input).unwrap();
    let digest = state.finalize().unwrap();
    assert!(digest.len() == output.len());
    assert!(digest.as_ref() == &output[..]);
}

fn sha512_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha512::Sha512::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha512::Sha512::digest(data).unwrap();

    assert!(digest.as_ref() == digest_one_shot.as_ref());
    assert!(digest.as_ref() == output);
}

// TODO: Refactor
fn sha256_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha256::Sha256::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha256::Sha256::digest(data).unwrap();

    assert!(digest.as_ref() == digest_one_shot.as_ref());
    assert!(digest.as_ref() == output);
}

/// NISTs SHA256/512 Long/Short share the same format,
/// so fields and separator remain the same.
fn nist_cavp_runner(path: &str) {
    let nist_cavp_fields: Vec<String> = vec!["Len".into(), "Msg".into(), "MD".into()];
    let mut nist_cavp_reader = TestCaseReader::new(path, nist_cavp_fields, "=");

    let mut test_case = nist_cavp_reader.next();
    while test_case.is_some() {
        let tc = test_case.unwrap();

        let input: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Msg"));
        let expected_output: Vec<u8> = TestCaseReader::default_parse(tc.get_data("MD"));

        if path.contains("SHA256") {
            sha256_test_runner(&input[..], &expected_output[..]);
        }
        if path.contains("SHA512") {
            sha512_test_runner(&input[..], &expected_output[..]);
        }

        // Read the next one
        test_case = nist_cavp_reader.next();
    }
}