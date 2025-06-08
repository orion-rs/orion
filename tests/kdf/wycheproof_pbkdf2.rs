// Testing against C2SP Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/C2SP/wycheproof/commit/99ad8dabdbd3859633fd45f2eef9872acd25cb63

use hex::decode;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WycheproofPbkdf2Tests {
    algorithm: String,

    #[serde(skip)]
    #[allow(dead_code)]
    schema: String,

    #[serde(skip)]
    #[allow(dead_code)]
    generatorVersion: String,

    numberOfTests: u32,

    #[serde(skip)]
    #[allow(dead_code)]
    header: Vec<String>,

    #[serde(skip)]
    #[allow(dead_code)]
    notes: Vec<String>,

    testGroups: Vec<Pbkdf2TestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Pbkdf2TestGroup {
    #[serde(rename(deserialize = "type"))]
    testType: String,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    comment: String,
    flags: Vec<String>,
    password: String,
    salt: String,
    iterationCount: usize,
    dkLen: usize,
    dk: String,
    result: String,
}

fn wycheproof_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: WycheproofPbkdf2Tests = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        for test in test_group.tests.iter() {
            let should_test_pass: bool = match test.result.as_str() {
                "valid" => true,
                "invalid" => false, // NOTE: There don't actually seem to be any of these in the files.
                _ => panic!("Unexpected test outcome for Wycheproof test"),
            };

            dbg!(&test);

            if tests.algorithm.contains("PBKDF2-HMACSHA256") {
                super::pbkdf2_256_test_runner(
                    &decode(&test.dk).unwrap(),
                    &decode(&test.password).unwrap(),
                    &decode(&test.salt).unwrap(),
                    test.iterationCount,
                    test.dkLen,
                    should_test_pass,
                );

                tests_run += 1;
            }
            if tests.algorithm.contains("PBKDF2-HMACSHA384") {
                super::pbkdf2_384_test_runner(
                    &decode(&test.dk).unwrap(),
                    &decode(&test.password).unwrap(),
                    &decode(&test.salt).unwrap(),
                    test.iterationCount,
                    test.dkLen,
                    should_test_pass,
                );

                tests_run += 1;
            }
            if tests.algorithm.contains("PBKDF2-HMACSHA512") {
                super::pbkdf2_512_test_runner(
                    &decode(&test.dk).unwrap(),
                    &decode(&test.password).unwrap(),
                    &decode(&test.salt).unwrap(),
                    test.iterationCount,
                    test.dkLen,
                    should_test_pass,
                );

                tests_run += 1;
            }
        }
    }

    assert_eq!(tests_run, tests.numberOfTests);
}

#[test]
fn test_wycheproof_pbkdf2_256() {
    wycheproof_runner("./tests/test_data/third_party/c2sp_wycheproof/pbkdf2_hmacsha256_test.json");
}
#[test]
fn test_wycheproof_pbkdf2_384() {
    wycheproof_runner("./tests/test_data/third_party/c2sp_wycheproof/pbkdf2_hmacsha384_test.json");
}
#[test]
fn test_wycheproof_pbkdf2_512() {
    wycheproof_runner("./tests/test_data/third_party/c2sp_wycheproof/pbkdf2_hmacsha512_test.json");
}
