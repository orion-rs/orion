// Testing against PyNaCl test vectors
// Latest commit when these test vectors were pulled: https://github.com/pyca/pynacl/commit/d28395dafd1b87f377299a8646551a454759e161
// The generated test vectors have been generated the 24th January 2020.
extern crate hex;
extern crate orion;
extern crate serde_json;

use self::hex::decode;

use self::serde_json::{Deserializer, Value};
use std::{fs::File, io::BufReader};

use orion::hazardous::kdf::argon2;

fn run_tests_from_json(path_to_vectors: &str) {
    let file = File::open(path_to_vectors).unwrap();
    let reader = BufReader::new(file);
    let stream = Deserializer::from_reader(reader).into_iter::<Value>();

    for test_file in stream {
        for test_groups in test_file.unwrap().as_array() {
            for test_case in test_groups {
                let password = test_case
                    .get("passwd")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .as_bytes();
                let outsize = test_case.get("dgst_len").unwrap().as_u64().unwrap();
                let salt = test_case.get("salt").unwrap().as_str().unwrap().as_bytes();
                let iterations = test_case.get("iters").unwrap().as_u64().unwrap();
                let expected_hash =
                    decode(test_case.get("pwhash").unwrap().as_str().unwrap()).unwrap();
                let memory = test_case.get("maxmem").unwrap().as_u64().unwrap();

                let mut dst_out = vec![0u8; outsize as usize];
                assert!(argon2::verify(
                    &expected_hash[..],
                    password,
                    salt,
                    iterations as u32,
                    memory as u32,
                    None,
                    None,
                    &mut dst_out
                )
                .is_ok());
            }
        }
    }
}

#[test]
fn test_pynacl() {
    run_tests_from_json("./tests/test_data/original/pynacl_raw_argon2i_hashes.json");
}
