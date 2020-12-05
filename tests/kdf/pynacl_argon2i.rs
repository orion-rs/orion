// Testing against PyNaCl test vectors
// Latest commit when these test vectors were pulled: https://github.com/pyca/pynacl/commit/d28395dafd1b87f377299a8646551a454759e161
// The generated test vectors have been generated the 24th January 2020.

use hex::decode;
use orion::hazardous::kdf::argon2i;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestCase {
    passwd: String,
    mode: String,
    dgst_len: usize,
    iters: u32,
    salt: String,
    pwhash: String,
    maxmem: u32,
}

fn run_tests_from_json(path_to_vectors: &str) {
    let file = File::open(path_to_vectors).unwrap();
    let reader = BufReader::new(file);
    let tests: Vec<TestCase> = serde_json::from_reader(reader).unwrap();

    for test in tests {
        let mut dst_out = vec![0u8; test.dgst_len as usize];

        assert!(argon2i::verify(
            &decode(&test.pwhash).unwrap(),
            test.passwd.as_bytes(),
            test.salt.as_bytes(),
            test.iters,
            test.maxmem,
            None,
            None,
            &mut dst_out
        )
        .is_ok());
    }
}

#[test]
fn test_pynacl() {
    run_tests_from_json("./tests/test_data/third_party/pynacl/pynacl_raw_argon2i_hashes.json");
}
