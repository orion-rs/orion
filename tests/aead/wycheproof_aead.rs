// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/2196000605e45d91097147c9c71f26b72af58003

use hex::decode;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WycheproofAeadTests {
    algorithm: String,
    numberOfTests: u64,
    testGroups: Vec<AeadTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AeadTestGroup {
    ivSize: u64,
    keySize: u64,
    tagSize: u64,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
    flags: Vec<String>,
}

fn wycheproof_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: WycheproofAeadTests = serde_json::from_reader(reader).unwrap();

    let is_ietf = match tests.algorithm.as_str() {
        "CHACHA20-POLY1305" => true,
        "XCHACHA20-POLY1305" => false,
        _ => panic!("Unexpected name for Wycheproof algorithm"),
    };

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        for test in test_group.tests.iter() {
            let should_test_pass: bool = match test.result.as_str() {
                "valid" => true,
                "invalid" => false,
                _ => panic!("Unexpected test outcome for Wycheproof test"),
            };

            assert!(super::wycheproof_test_runner(
                &decode(&test.key).unwrap(),
                &decode(&test.iv).unwrap(),
                &decode(&test.aad).unwrap(),
                &decode(&test.tag).unwrap(),
                &decode(&test.msg).unwrap(),
                &decode(&test.ct).unwrap(),
                should_test_pass,
                test.tcId,
                is_ietf,
            )
            .is_ok());

            tests_run += 1;
        }
    }

    assert_eq!(tests_run, tests.numberOfTests);
}

#[test]
fn test_wycheproof_chacha20_poly1305() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_chacha20_poly1305_test.json",
    );
}

#[test]
fn test_wycheproof_xchacha20_poly1305() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_xchacha20_poly1305_test.json",
    );
}
