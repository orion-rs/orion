// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/2196000605e45d91097147c9c71f26b72af58003

use hex::decode;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WycheproofHkdfTests {
    algorithm: String,
    numberOfTests: u64,
    testGroups: Vec<HkdfTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct HkdfTestGroup {
    keySize: u64,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    comment: String,
    ikm: String,
    salt: String,
    info: String,
    size: usize,
    okm: String,
    result: String,
    flags: Vec<String>,
}

fn wycheproof_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: WycheproofHkdfTests = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        for test in test_group.tests.iter() {
            let should_test_pass: bool = match test.result.as_str() {
                "valid" => true,
                "invalid" => false,
                _ => panic!("Unexpected test outcome for Wycheproof test"),
            };

            dbg!(&test);

            if tests.algorithm.contains("SHA-256") {
                super::hkdf256_test_runner(
                    None,
                    &decode(&test.okm).unwrap(),
                    &decode(&test.salt).unwrap(),
                    &decode(&test.ikm).unwrap(),
                    &decode(&test.info).unwrap(),
                    test.size,
                    should_test_pass,
                );

                tests_run += 1;
            }
            if tests.algorithm.contains("SHA-384") {
                super::hkdf384_test_runner(
                    None,
                    &decode(&test.okm).unwrap(),
                    &decode(&test.salt).unwrap(),
                    &decode(&test.ikm).unwrap(),
                    &decode(&test.info).unwrap(),
                    test.size,
                    should_test_pass,
                );

                tests_run += 1;
            }
            if tests.algorithm.contains("SHA-512") {
                super::hkdf512_test_runner(
                    None,
                    &decode(&test.okm).unwrap(),
                    &decode(&test.salt).unwrap(),
                    &decode(&test.ikm).unwrap(),
                    &decode(&test.info).unwrap(),
                    test.size,
                    should_test_pass,
                );

                tests_run += 1;
            }
        }
    }

    assert_eq!(tests_run, tests.numberOfTests);
}

#[test]
fn test_wycheproof_hkdf_256() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_hkdf_sha256_test.json",
    );
}
#[test]
fn test_wycheproof_hkdf_384() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_hkdf_sha384_test.json",
    );
}
#[test]
fn test_wycheproof_hkdf_512() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_hkdf_sha512_test.json",
    );
}
