// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/2196000605e45d91097147c9c71f26b72af58003
extern crate hex;
extern crate serde_json;

use self::hex::decode;

use self::serde_json::{Deserializer, Value};
use crate::kdf::wycheproof_hkdf_test_runner;
use std::{fs::File, io::BufReader};

fn wycheproof_runner(path: &str) {
	let file = File::open(path).unwrap();
	let reader = BufReader::new(file);
	let stream = Deserializer::from_reader(reader).into_iter::<Value>();

	for test_file in stream {
		for test_groups in test_file.unwrap().get("testGroups") {
			for test_group_collection in test_groups.as_array() {
				for test_group in test_group_collection {
					for test_vectors in test_group.get("tests").unwrap().as_array() {
						for test_case in test_vectors {
							let ikm =
								decode(test_case.get("ikm").unwrap().as_str().unwrap()).unwrap();
							let salt =
								decode(test_case.get("salt").unwrap().as_str().unwrap()).unwrap();
							let info =
								decode(test_case.get("info").unwrap().as_str().unwrap()).unwrap();
							let okm_len = test_case.get("size").unwrap().as_u64().unwrap();
							let okm =
								decode(test_case.get("okm").unwrap().as_str().unwrap()).unwrap();
							let result: bool =
								match test_case.get("result").unwrap().as_str().unwrap() {
									"valid" => true,
									"invalid" => false,
									_ => panic!("Unrecognized result detected!"),
								};
							let tcid = test_case.get("tcId").unwrap().as_u64().unwrap();
							println!("tcId: {}, okm_len: {}", tcid, okm_len);

							wycheproof_hkdf_test_runner(
								&okm[..],
								&salt[..],
								&ikm[..],
								&info[..],
								okm_len as usize,
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
fn test_wycheproof_hkdf() {
	wycheproof_runner("./tests/test_data/original/wycheproof_hkdf_sha512_test.json");
}
