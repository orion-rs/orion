pub mod blake2b_kat;
pub mod other_blake2b;
pub mod sha256_nist_cavp;
pub mod sha384_nist_cavp;
pub mod sha3_224_nist_cavp;
pub mod sha3_256_nist_cavp;
pub mod sha3_384_nist_cavp;
pub mod sha3_512_nist_cavp;
pub mod sha512_nist_cavp;
pub mod shake128_nist_cavp;
pub mod shake256_nist_cavp;

use crate::TestCaseReader;
use orion::hazardous::hash::{blake2, sha2, sha3};
use orion::hazardous::mac;

fn blake2b_test_runner(input: &[u8], key: &[u8], output: &[u8]) {
    // Only make SecretKey if test case key value is not empty.
    if key.is_empty() {
        let mut state = blake2::blake2b::Blake2b::new(output.len()).unwrap();
        state.update(input).unwrap();
        let digest = state.finalize().unwrap();
        assert_eq!(digest.len(), output.len());
        assert_eq!(digest.as_ref(), output);
    } else {
        let secret_key = mac::blake2b::SecretKey::from_slice(key).unwrap();
        let mut state = mac::blake2b::Blake2b::new(&secret_key, output.len()).unwrap();
        state.update(input).unwrap();
        let tag = state.finalize().unwrap();
        assert_eq!(tag.len(), output.len());
        assert_eq!(tag.unprotected_as_bytes(), output);
    }
}

fn sha512_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha2::sha512::Sha512::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha2::sha512::Sha512::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha256_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha2::sha256::Sha256::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha2::sha256::Sha256::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha384_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha2::sha384::Sha384::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha2::sha384::Sha384::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha3_224_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha3::sha3_224::Sha3_224::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha3::sha3_224::Sha3_224::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha3_256_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha3::sha3_256::Sha3_256::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha3::sha3_256::Sha3_256::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha3_384_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha3::sha3_384::Sha3_384::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha3::sha3_384::Sha3_384::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn sha3_512_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha3::sha3_512::Sha3_512::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha3::sha3_512::Sha3_512::digest(data).unwrap();

    assert_eq!(digest.as_ref(), digest_one_shot.as_ref());
    assert_eq!(digest.as_ref(), output);
}

fn shake128_test_runner(data: &[u8], output: &[u8]) {
    let rate: usize = 168;

    let mut state = sha3::shake128::Shake128::new();
    state.absorb(data).unwrap();

    let mut digest = vec![0u8; output.len()];
    for rate_chunk in digest.chunks_mut(rate) {
        if rate_chunk.len() == rate {
            state.squeeze(rate_chunk).unwrap();
        } else {
            let mut rate_block = [0u8; 168];
            state.squeeze(&mut rate_block).unwrap();

            rate_chunk.copy_from_slice(&rate_block[..rate_chunk.len()]);
        }
    }

    assert_eq!(digest.as_slice(), output);
}

fn shake256_test_runner(data: &[u8], output: &[u8]) {
    let rate: usize = 136;

    let mut state = sha3::shake256::Shake256::new();
    state.absorb(data).unwrap();

    let mut digest = vec![0u8; output.len()];
    for rate_chunk in digest.chunks_mut(rate) {
        if rate_chunk.len() == rate {
            state.squeeze(rate_chunk).unwrap();
        } else {
            let mut rate_block = [0u8; 136];
            state.squeeze(&mut rate_block).unwrap();

            rate_chunk.copy_from_slice(&rate_block[..rate_chunk.len()]);
        }
    }

    assert_eq!(digest.as_slice(), output);
}

/// NISTs SHA2/SHA3 Long/Short share the same format,
/// so fields and separator remain the same.
fn sha_nist_cavp_runner(path: &str) {
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
        if path.contains("SHA3_224") {
            sha3_224_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }
        if path.contains("SHA3_256") {
            sha3_256_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }
        if path.contains("SHA3_384") {
            sha3_384_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }
        if path.contains("SHA3_512") {
            sha3_512_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }

        assert!(ran_any_runner);
        // Read the next one
        test_case = nist_cavp_reader.next();
    }
}

fn shake_nist_cavp_runner(path: &str) {
    let nist_cavp_fields: Vec<String> = vec!["Msg".into(), "Output".into()];
    let mut nist_cavp_reader = TestCaseReader::new(path, nist_cavp_fields, "=");

    let mut test_case = nist_cavp_reader.next();
    // Check that we actually ran any of the SHAKE test runners.
    let mut ran_any_runner = false;
    while test_case.is_some() {
        let tc = test_case.unwrap();

        let input: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Msg"));
        let expected_output: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Output"));

        if path.contains("SHAKE128") {
            shake128_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }
        if path.contains("SHAKE256") {
            dbg!(&tc);

            shake256_test_runner(&input[..], &expected_output[..]);
            ran_any_runner = true;
        }

        assert!(ran_any_runner);
        // Read the next one
        test_case = nist_cavp_reader.next();
    }
}
