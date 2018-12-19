// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/8f2cba4d3fe693aa312fed6939ef5454952d830d
extern crate hex;
extern crate serde;
extern crate serde_json;

use self::hex::decode;

use self::serde_json::{Deserializer, Value};
use crate::aead::wycheproof_test_runner as chacha20_poly1305_test_runner;
use std::{fs::File, io::BufReader};

#[test]
fn test_wycheproof() {
	let file = File::open("./tests/test_data/original/Wycheproof_ChaCha20_Poly1305.json").unwrap();
	let reader = BufReader::new(file);
	let stream = Deserializer::from_reader(reader).into_iter::<Value>();

	for test_file in stream {
		for test_groups in test_file.unwrap().get("testGroups") {
			for test_group_collection in test_groups.as_array() {
				for test_group in test_group_collection {
					for test_vectors in test_group.get("tests").unwrap().as_array() {
						for test_case in test_vectors {
							let key =
								decode(test_case.get("key").unwrap().as_str().unwrap()).unwrap();
							let iv =
								decode(test_case.get("iv").unwrap().as_str().unwrap()).unwrap();
							let aad =
								decode(test_case.get("aad").unwrap().as_str().unwrap()).unwrap();
							let msg =
								decode(test_case.get("msg").unwrap().as_str().unwrap()).unwrap();
							let ct =
								decode(test_case.get("ct").unwrap().as_str().unwrap()).unwrap();
							let tag =
								decode(test_case.get("tag").unwrap().as_str().unwrap()).unwrap();
							let result: bool =
								match test_case.get("result").unwrap().as_str().unwrap() {
									"valid" => true,
									"invalid" => false,
									_ => panic!("Unrecognized result detected!"),
								};
							let tcid = test_case.get("tcId").unwrap().as_u64().unwrap();

							chacha20_poly1305_test_runner(
								&key, &iv, &aad, &tag, &msg, &ct, result, tcid,
							)
							.unwrap();
						}
					}
				}
			}
		}
	}
}
