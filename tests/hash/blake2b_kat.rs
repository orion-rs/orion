extern crate hex;
extern crate serde_json;

use self::hex::decode;
use super::*;

use self::serde_json::{Deserializer, Value};
use std::{fs::File, io::BufReader};

#[test]
fn test_blake2b_kat() {
    let file = File::open("./tests/test_data/third_party/blake2-kat.json").unwrap();
    let reader = BufReader::new(file);
    let stream = Deserializer::from_reader(reader).into_iter::<Value>();

    for test_collection in stream {
        for test_object in test_collection.unwrap().as_array() {
            for test_case in test_object {
                // Only test BLAKE2b test vectors
                if test_case.get("hash").unwrap() == "blake2b" {
                    blake2b_test_runner(
                        &decode(test_case.get("in").unwrap().as_str().unwrap()).unwrap(),
                        &decode(test_case.get("key").unwrap().as_str().unwrap()).unwrap(),
                        &decode(test_case.get("out").unwrap().as_str().unwrap()).unwrap(),
                    )
                }
            }
        }
    }
}
