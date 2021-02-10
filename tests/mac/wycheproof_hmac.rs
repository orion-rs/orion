// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/2196000605e45d91097147c9c71f26b72af58003

use hex::decode;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WycheproofHmacTests {
    algorithm: String,
    numberOfTests: u64,
    testGroups: Vec<HmacTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct HmacTestGroup {
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
    msg: String,
    tag: String,
    result: String,
    flags: Vec<String>,
}

fn wycheproof_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: WycheproofHmacTests = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        for test in test_group.tests.iter() {
            let should_test_pass: bool = match test.result.as_str() {
                "valid" => true,
                "invalid" => false,
                _ => panic!("Unexpected test outcome for Wycheproof test"),
            };

            if path.contains("sha256") {
                super::hmac256_test_runner(
                    &decode(&test.tag).unwrap(),
                    &decode(&test.key).unwrap(),
                    &decode(&test.msg).unwrap(),
                    Some((test_group.tagSize / 8) as usize),
                    should_test_pass,
                );

                tests_run += 1;
            }
            if path.contains("sha384") {
                super::hmac384_test_runner(
                    &decode(&test.tag).unwrap(),
                    &decode(&test.key).unwrap(),
                    &decode(&test.msg).unwrap(),
                    Some((test_group.tagSize / 8) as usize),
                    should_test_pass,
                );

                tests_run += 1;
            }
            if path.contains("sha512") {
                super::hmac512_test_runner(
                    &decode(&test.tag).unwrap(),
                    &decode(&test.key).unwrap(),
                    &decode(&test.msg).unwrap(),
                    Some((test_group.tagSize / 8) as usize),
                    should_test_pass,
                );

                tests_run += 1;
            }
        }
    }

    assert_eq!(tests_run, tests.numberOfTests);
}

#[test]
fn test_wycheproof_hmac_256() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_hmac_sha256_test.json",
    );
}

#[test]
fn test_wycheproof_hmac_384() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_hmac_sha384_test.json",
    );
}

#[test]
fn test_wycheproof_hmac_512() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_hmac_sha512_test.json",
    );
}
