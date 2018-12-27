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

extern crate hex;
extern crate serde_json;

use self::hex::decode;
use super::*;

use self::serde_json::{Deserializer, Value};
use std::{fs::File, io::BufReader};

#[test]
fn test_blake2b_kat() {
	let file = File::open("./tests/test_data/original/blake2-kat.json").unwrap();
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
