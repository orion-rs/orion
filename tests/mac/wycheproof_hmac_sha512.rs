// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/2196000605e45d91097147c9c71f26b72af58003
extern crate hex;
extern crate serde_json;

use self::hex::decode;

use self::serde_json::{Deserializer, Value};
use crate::mac::hmac_test_runner;
use std::{fs::File, io::BufReader};

fn wycheproof_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let stream = Deserializer::from_reader(reader).into_iter::<Value>();

    for test_file in stream {
        for test_groups in test_file.unwrap().get("testGroups") {
            for test_group_collection in test_groups.as_array() {
                for test_group in test_group_collection {
                    let tag_len = test_group.get("tagSize").unwrap().as_u64().unwrap();
                    for test_vectors in test_group.get("tests").unwrap().as_array() {
                        for test_case in test_vectors {
                            let key =
                                decode(test_case.get("key").unwrap().as_str().unwrap()).unwrap();
                            let msg =
                                decode(test_case.get("msg").unwrap().as_str().unwrap()).unwrap();
                            let tag =
                                decode(test_case.get("tag").unwrap().as_str().unwrap()).unwrap();
                            let result: bool =
                                match test_case.get("result").unwrap().as_str().unwrap() {
                                    "valid" => true,
                                    "invalid" => false,
                                    _ => panic!("Unrecognized result detected!"),
                                };
                            let tcid = test_case.get("tcId").unwrap().as_u64().unwrap();
                            println!("tcId: {}, len: {}", tcid, tag_len);

                            hmac_test_runner(
                                &tag[..],
                                &key[..],
                                &msg[..],
                                Some(tag_len as usize / 8), /* Wychproof sets tag length in bits, we need bytes */
                                result,
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_wycheproof_hmac() {
    wycheproof_runner("./tests/test_data/original/wycheproof_hmac_sha512_test.json");
}
