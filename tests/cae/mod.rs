use crate::aead::wycheproof_aead::WycheproofAeadTests;
use hex::decode;
use orion::hazardous::cae::{
    chacha20poly1305blake2b::{self, SecretKey},
    xchacha20poly1305blake2b,
};
use std::{fs::File, io::BufReader};
mod ctx_test_vectors;
use crate::cae::ctx_test_vectors::custom_ctx_runner;

/// This test runner tests that CTX variants of ChaCha20Poly1305 XChaCha20Poly1305
/// (with BLAKE2b) produce the same ciphertext as the non-CTX variants of them.
/// Since CTX does not modify how the ciphertext is produced.
fn wycheproof_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: WycheproofAeadTests = serde_json::from_reader(reader).unwrap();

    let is_ietf = match tests.algorithm.as_str() {
        "CHACHA20-POLY1305" => true,
        "XCHACHA20-POLY1305" => false,
        _ => panic!("Unexpected name for Wycheproof algorithm"),
    };

    for test_group in tests.testGroups.iter() {
        for test in test_group.tests.iter() {
            match test.result.as_str() {
                "valid" => true,
                // The only thing we want to test for CTX is that it still produces
                // ciphertexts matching the underlying AE. Therefor, invalid test cases
                // are of no interest here.
                "invalid" => continue,
                _ => panic!("Unexpected test outcome for Wycheproof test"),
            };

            let input = &decode(&test.msg).unwrap();
            let output = &decode(&test.ct).unwrap();
            let key = SecretKey::from_slice(&decode(&test.key).unwrap()).unwrap();
            let aad = &decode(&test.aad).unwrap();

            let mut dst_ct_out = vec![0u8; input.len() + 32];

            if is_ietf {
                let nonce =
                    chacha20poly1305blake2b::Nonce::from_slice(&decode(&test.iv).unwrap()).unwrap();
                chacha20poly1305blake2b::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)
                    .unwrap();
            } else {
                let nonce = xchacha20poly1305blake2b::Nonce::from_slice(&decode(&test.iv).unwrap())
                    .unwrap();
                xchacha20poly1305blake2b::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)
                    .unwrap();
            }

            assert_eq!(dst_ct_out[..input.len()].as_ref(), output);
        }
    }
}

#[test]
fn test_ctx_equivalence_ctx_chacha20() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_chacha20_poly1305_test.json",
    );
}

#[test]
fn test_ctx_equivalence_ctx_xchacha20() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_xchacha20_poly1305_test.json",
    );
}

#[test]
fn test_ctx_custom_chacha20() {
    custom_ctx_runner("./tests/test_data/experimental/ctx_chacha20_poly1305_blake2b_256.json");
}

#[test]
fn test_ctx_custom_xchacha20() {
    custom_ctx_runner("./tests/test_data/experimental/ctx_xchacha20_poly1305_blake2b_256.json");
}
