// Test vector generated with the Python cryptography.io package.

use hex::decode;
use orion::hazardous::kdf::scrypt::*;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestCase {
    variant: String,
    n: u32,
    r: u32,
    p: u32,
    tag_length: u32,
    password: String,
    salt: String,
    tag: String,
    phc: String,
}

fn run_tests_from_json(path_to_vectors: &str) {
    let file = File::open(path_to_vectors).unwrap();
    let reader = BufReader::new(file);
    let tests: Vec<TestCase> = serde_json::from_reader(reader).unwrap();

    for test in tests {
        let mut dst_out = vec![0u8; test.tag_length as usize];
        let passwd = if !test.password.is_empty() {
            decode(&test.password).unwrap()
        } else {
            vec![]
        };
        let salt = if !test.salt.is_empty() {
            decode(&test.salt).unwrap()
        } else {
            vec![]
        };
        let expacted_result = decode(&test.tag).unwrap();

        // PasswordHash figures out the variant itself
        let phc = PasswordHash::try_from(test.phc.as_bytes())
            .expect("failed to parse test vector PHC string");
        let cost = CostParams::new(test.n, test.r, test.p).unwrap();

        match test.variant.as_str() {
            "scrypt" => {
                assert!(
                    Scrypt::verify(&expacted_result, &passwd, &salt, &cost, &mut dst_out).is_ok()
                );
                let rt =
                    Scrypt::derive_key_encoded(&passwd, &salt, &cost, test.tag_length as usize)
                        .unwrap();
                assert_eq!(rt.unprotected_as_ref(), test.phc.as_bytes());
                assert_eq!(rt.unprotected_as_str(), test.phc.as_str());
                assert!(Scrypt::verify_encoded(&phc, &passwd,).is_ok());
            }
            _ => (),
        }
    }
}

#[test]
fn test_pycryptography() {
    run_tests_from_json("./tests/test_data/third_party/custom/python_cryptography_scrypt.json");
}
