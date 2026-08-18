// Test vector generated with the Python cryptography.io package.

use hex::decode;
use orion::hazardous::kdf::{argon2i, argon2id};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestCase {
    variant: String,
    version: u32,
    memory: u32,
    passes: u32,
    parallelism: u32,
    tag_length: u32,
    password: String,
    salt: String,
    secret: String,
    associated_data: String,
    tag: String,
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
        let secret = if !test.secret.is_empty() {
            decode(&test.secret).unwrap()
        } else {
            vec![]
        };
        let ad = if !test.associated_data.is_empty() {
            decode(&test.associated_data).unwrap()
        } else {
            vec![]
        };
        let expacted_result = decode(&test.tag).unwrap();

        match test.variant.as_str() {
            "argon2i" => {
                assert!(
                    argon2i::verify(
                        &expacted_result,
                        &passwd,
                        &salt,
                        test.passes,
                        test.memory,
                        test.parallelism,
                        Some(&secret),
                        Some(&ad),
                        &mut dst_out
                    )
                    .is_ok()
                );
            }
            "argon2id" => {
                assert!(
                    argon2id::verify(
                        &expacted_result,
                        &passwd,
                        &salt,
                        test.passes,
                        test.memory,
                        test.parallelism,
                        Some(&secret),
                        Some(&ad),
                        &mut dst_out
                    )
                    .is_ok()
                );
            }
            _ => (),
        }
    }
}

#[test]
fn test_pynacl() {
    run_tests_from_json("./tests/test_data/third_party/custom/python_cryptography_argon2.json");
}
