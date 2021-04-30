// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/2196000605e45d91097147c9c71f26b72af58003
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WycheproofX25519Tests {
    algorithm: String,
    generatorVersion: String,
    numberOfTests: u64,
    header: Vec<String>,
    #[serde(skip)]
    notes: Vec<String>,
    schema: String,
    testGroups: Vec<X25519TestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct X25519TestGroup {
    curve: String,
    // NOTE: Reserved keyword
    #[serde(rename(deserialize = "type"))]
    #[serde(rename(serialize = "type"))]
    t_type: String,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    comment: String,
    public: String,
    private: String,
    shared: String,
    result: String,
    flags: Vec<String>,
}

fn wycheproof_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: WycheproofX25519Tests = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        for test in test_group.tests.iter() {
            let mut should_test_pass: bool = match test.result.as_str() {
                "valid" => true,
                "acceptable" => true, // NOTE: We handle special cases after this
                _ => false,           // NOTE: expected unreachable
            };

            // TODO: Are these the only ones we want to reject? Should align with the RFC.
            if test.flags.contains(&"ZeroSharedSecret".to_string()) {
                should_test_pass = false;
            }

            let mut k = [0u8; 32];
            let mut u = [0u8; 32];
            let mut er = [0u8; 32];
            hex::decode_to_slice(&test.private, &mut k).unwrap();
            hex::decode_to_slice(&test.public, &mut u).unwrap();
            hex::decode_to_slice(&test.shared, &mut er).unwrap();

            super::x25519_test_runner(&er, &k, &u, should_test_pass);

            tests_run += 1;
        }
    }

    assert_eq!(tests_run, tests.numberOfTests);
}

#[test]
fn test_wycheproof_x25519() {
    wycheproof_runner(
        "./tests/test_data/third_party/google/wycheproof/wycheproof_x25519_test.json",
    );
}
